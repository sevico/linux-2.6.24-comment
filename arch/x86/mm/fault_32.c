/*
 *  linux/arch/i386/mm/fault.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/vt_kern.h>		/* For unblank_screen() */
#include <linux/highmem.h>
#include <linux/bootmem.h>		/* for max_low_pfn */
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/kdebug.h>
#include <linux/kprobes.h>

#include <asm/system.h>
#include <asm/desc.h>
#include <asm/segment.h>

extern void die(const char *,struct pt_regs *,long);

#ifdef CONFIG_KPROBES
static inline int notify_page_fault(struct pt_regs *regs)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (!user_mode_vm(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, 14))
			ret = 1;
		preempt_enable();
	}

	return ret;
}
#else
static inline int notify_page_fault(struct pt_regs *regs)
{
	return 0;
}
#endif

/*
 * Return EIP plus the CS segment base.  The segment limit is also
 * adjusted, clamped to the kernel/user address space (whichever is
 * appropriate), and returned in *eip_limit.
 *
 * The segment is checked, because it might have been changed by another
 * task between the original faulting instruction and here.
 *
 * If CS is no longer a valid code segment, or if EIP is beyond the
 * limit, or if it is a kernel address when CS is not a kernel segment,
 * then the returned value will be greater than *eip_limit.
 * 
 * This is slow, but is very rarely executed.
 */
static inline unsigned long get_segment_eip(struct pt_regs *regs,
					    unsigned long *eip_limit)
{
	unsigned long eip = regs->eip;
	unsigned seg = regs->xcs & 0xffff;
	u32 seg_ar, seg_limit, base, *desc;

	/* Unlikely, but must come before segment checks. */
	if (unlikely(regs->eflags & VM_MASK)) {
		base = seg << 4;
		*eip_limit = base + 0xffff;
		return base + (eip & 0xffff);
	}

	/* The standard kernel/user address space limit. */
	*eip_limit = user_mode(regs) ? USER_DS.seg : KERNEL_DS.seg;
	
	/* By far the most common cases. */
	if (likely(SEGMENT_IS_FLAT_CODE(seg)))
		return eip;

	/* Check the segment exists, is within the current LDT/GDT size,
	   that kernel/user (ring 0..3) has the appropriate privilege,
	   that it's a code segment, and get the limit. */
	__asm__ ("larl %3,%0; lsll %3,%1"
		 : "=&r" (seg_ar), "=r" (seg_limit) : "0" (0), "rm" (seg));
	if ((~seg_ar & 0x9800) || eip > seg_limit) {
		*eip_limit = 0;
		return 1;	 /* So that returned eip > *eip_limit. */
	}

	/* Get the GDT/LDT descriptor base. 
	   When you look for races in this code remember that
	   LDT and other horrors are only used in user space. */
	if (seg & (1<<2)) {
		/* Must lock the LDT while reading it. */
		mutex_lock(&current->mm->context.lock);
		desc = current->mm->context.ldt;
		desc = (void *)desc + (seg & ~7);
	} else {
		/* Must disable preemption while reading the GDT. */
 		desc = (u32 *)get_cpu_gdt_table(get_cpu());
		desc = (void *)desc + (seg & ~7);
	}

	/* Decode the code segment base from the descriptor */
	base = get_desc_base((unsigned long *)desc);

	if (seg & (1<<2)) { 
		mutex_unlock(&current->mm->context.lock);
	} else
		put_cpu();

	/* Adjust EIP and segment limit, and clamp at the kernel limit.
	   It's legitimate for segments to wrap at 0xffffffff. */
	seg_limit += base;
	if (seg_limit < *eip_limit && seg_limit >= base)
		*eip_limit = seg_limit;
	return eip + base;
}

/* 
 * Sometimes AMD Athlon/Opteron CPUs report invalid exceptions on prefetch.
 * Check that here and ignore it.
 */
static int __is_prefetch(struct pt_regs *regs, unsigned long addr)
{ 
	unsigned long limit;
	unsigned char *instr = (unsigned char *)get_segment_eip (regs, &limit);
	int scan_more = 1;
	int prefetch = 0; 
	int i;

	for (i = 0; scan_more && i < 15; i++) { 
		unsigned char opcode;
		unsigned char instr_hi;
		unsigned char instr_lo;

		if (instr > (unsigned char *)limit)
			break;
		if (probe_kernel_address(instr, opcode))
			break; 

		instr_hi = opcode & 0xf0; 
		instr_lo = opcode & 0x0f; 
		instr++;

		switch (instr_hi) { 
		case 0x20:
		case 0x30:
			/* Values 0x26,0x2E,0x36,0x3E are valid x86 prefixes. */
			scan_more = ((instr_lo & 7) == 0x6);
			break;
			
		case 0x60:
			/* 0x64 thru 0x67 are valid prefixes in all modes. */
			scan_more = (instr_lo & 0xC) == 0x4;
			break;		
		case 0xF0:
			/* 0xF0, 0xF2, and 0xF3 are valid prefixes */
			scan_more = !instr_lo || (instr_lo>>1) == 1;
			break;			
		case 0x00:
			/* Prefetch instruction is 0x0F0D or 0x0F18 */
			scan_more = 0;
			if (instr > (unsigned char *)limit)
				break;
			if (probe_kernel_address(instr, opcode))
				break;
			prefetch = (instr_lo == 0xF) &&
				(opcode == 0x0D || opcode == 0x18);
			break;			
		default:
			scan_more = 0;
			break;
		} 
	}
	return prefetch;
}

static inline int is_prefetch(struct pt_regs *regs, unsigned long addr,
			      unsigned long error_code)
{
	if (unlikely(boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
		     boot_cpu_data.x86 >= 6)) {
		/* Catch an obscure case of prefetch inside an NX page. */
		if (nx_enabled && (error_code & 16))
			return 0;
		return __is_prefetch(regs, addr);
	}
	return 0;
} 

static noinline void force_sig_info_fault(int si_signo, int si_code,
	unsigned long address, struct task_struct *tsk)
{
	siginfo_t info;

	info.si_signo = si_signo;
	info.si_errno = 0;
	info.si_code = si_code;
	info.si_addr = (void __user *)address;
	force_sig_info(si_signo, &info, tsk);
}

fastcall void do_invalid_op(struct pt_regs *, unsigned long);

static inline pmd_t *vmalloc_sync_one(pgd_t *pgd, unsigned long address)
{
	unsigned index = pgd_index(address);
	pgd_t *pgd_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;

	pgd += index;
	/**
		 * 把主内核页全局目录的线性地址赋给pgd_k
		 */
	pgd_k = init_mm.pgd + index;
/**
		 * pgd_k对应的主内核页全局目录项为空。说明不是非连续内存区产生的错误。
		 * 因为非连续内存区产生的缺页仅仅是没有页表项，而不会缺少目录项。
		 */
	if (!pgd_present(*pgd_k))
		return NULL;

	/*
	 * set_pgd(pgd, *pgd_k); here would be useless on PAE
	 * and redundant with the set_pmd() on non-PAE. As would
	 * set_pud.
	 */
	/**
		 * 检查了全局目录项，还必须检查主内核页上级目录项和中间目录项。
		 * 如果它们中有一个为空，也转到no_context
		 */
	pud = pud_offset(pgd, address);
	pud_k = pud_offset(pgd_k, address);
	if (!pud_present(*pud_k))
		return NULL;
	/*直接用，没有分配，因为共享了内核主页表的PMD*/
	pmd = pmd_offset(pud, address);
	pmd_k = pmd_offset(pud_k, address);
	if (!pmd_present(*pmd_k))
		return NULL;
	if (!pmd_present(*pmd)) {
		/*这里共享了内核主页表的PT，因为PMD,PUD都是共享的，所以vmalloc只可能是因为pgd中的present没有置位引发的*/
		set_pmd(pmd, *pmd_k);
		arch_flush_lazy_mmu_mode();
	} else
		BUG_ON(pmd_page(*pmd) != pmd_page(*pmd_k));
	return pmd_k;
}

/*
 * Handle a fault on the vmalloc or module mapping area
 *
 * This assumes no large pages in there.
 */
static inline int vmalloc_fault(unsigned long address)
{
	unsigned long pgd_paddr;
	pmd_t *pmd_k;
	pte_t *pte_k;
	/*
	 * Synchronize this task's top level page-table
	 * with the 'reference' page table.
	 *
	 * Do _not_ use "current" here. We might be inside
	 * an interrupt in the middle of a task switch..
	 */
	/**
		 * 把cr3中当前进程页全局目录的物理地址赋给局部变量pgd_paddr。
		 * 注：内核不使用current->mm->pgd导出当前进程的页全局目录地址。因为这种缺页可能在任何时刻发生，甚至在进程切换期间发生。
		 */
	pgd_paddr = read_cr3();
	pmd_k = vmalloc_sync_one(__va(pgd_paddr), address);
	if (!pmd_k)
		return -1;
	pte_k = pte_offset_kernel(pmd_k, address);
	if (!pte_present(*pte_k))
		return -1;
	return 0;
}

int show_unhandled_signals = 1;

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * error_code:
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 *	bit 3 == 1 means use of reserved bit detected
 *	bit 4 == 1 means fault was an instruction fetch
 * 这个函数处理页面错误. 它确定地址和问题, 然后把错误传递给一个合适的程序.
 *
 * error_code:
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 * 
 * 错误代码:
 *  bit 0 == 0 表示未找到页面, 1 表示保护错误
 *  bit 1 == 0 表示读取, 1 表示写入
 *  bit 2 == 0 表示内核, 1 表示用户模式
 */
// 处理页面错误异常(缺页中断)
// struct pt_regs *regs 出现异常时 CPU 各个寄存器值的副本
// error_code           指明映射失败原因
/**
 * 缺页中断服务程序。
 * regs-发生异常时寄存器的值
 * error_code-当异常发生时，控制单元压入栈中的错误代码。
 *			  当第0位被清0时，则异常是由一个不存在的页所引起的。否则是由无效的访问权限引起的。
 *			  如果第1位被清0，则异常由读访问或者执行访问所引起，如果被设置，则异常由写访问引起。
 *			  如果第2位被清0，则异常发生在内核态，否则异常发生在用户态。
 */
fastcall void __kprobes do_page_fault(struct pt_regs *regs,
				      unsigned long error_code)
{
	// 当前出现异常进程的 task_struct
	struct task_struct *tsk;
	// 当前出现异常进程用户空间 mm_struct
	struct mm_struct *mm;
	// 当前出现异常进程的出错区间
	struct vm_area_struct * vma;
	// 当前出现异常进程访问的出错地址
	unsigned long address;
	int write, si_code;
	int fault;

	/*
	 * We can fault from pretty much anywhere, with unknown IRQ state.
	 */
	trace_hardirqs_fixup();

	/* get the address */
	/* 获取出错地址 */
	/**
	 * 读取引起异常的线性地址。CPU控制单元把这个值存放在cr2控制寄存器中。
	 */
	address = read_cr2();
	//得到当前进程的描述符和内存地址描述
	tsk = current;

	si_code = SEGV_MAPERR;

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 *
	 * This verifies that the fault happens in kernel space
	 * (error_code & 4) == 0, and that the fault was not a
	 * protection error (error_code & 9) == 0.
	 */
	/**
	 * 根据异常地址，判断是访问内核态地址还是用户态地址发生了异常。
	 * 这并不代表异常发生在用户态还是内核态。
	*/
	if (unlikely(address >= TASK_SIZE)) {
		/*
         * !(第0，3位 = 1，由无效的访问权限引起的； 第2位==1，异常发生在用户态。) ==> 内核态访问了一个不存在的页框
         */
		/**
			 * 内核态访问了一个不存在的页框，这可能是由于内核态访问非连续内存区而引起的。
			 * 注:vmalloc可能打乱了内核页表，而进程切换后，并没有随着修改这些页表项。这可能会引起异常，而这种异常其实不是程序逻辑错误。
		*/
		//发生在核心态，且异常不是由保护错误触发时，内核使用vmalloc_fault同步页表（从init的页表复制相关的项到当前页表
		if (!(error_code & 0x0000000d) && vmalloc_fault(address) >= 0)
			return;
		if (notify_page_fault(regs))
			return;
		/*
		 * Don't take the mm semaphore here. If we fixup a prefetch
		 * fault we could otherwise deadlock.
		 */
		//如果异常是在中断期间或内核线程过程中触发，也没有自身的上下文因而也没有独立的mm_struct实列，则跳转
		goto bad_area_nosemaphore;
	}

	if (notify_page_fault(regs))
		return;

	/* It's safe to allow irq's after cr2 has been saved and the vmalloc
	   fault has been handled. */
	/**
	 * 只在保存了cr2就可以打开中断了。
	 * 如果中断发生前是允许中断的，或者运行在虚拟8086模式，就打开中断。
	 */
	if (regs->eflags & (X86_EFLAGS_IF|VM_MASK))
		local_irq_enable();
	// 获取 mm_struct
	mm = tsk->mm;

	/*
	 * If we're in an interrupt, have no user context or are running in an
	 * atomic region then we must not take the fault..
	 * 如果我们处于中断或没有用户上下文环境的情况下, 我们绝不能处理这种错误
	 */
	// in_atomic() 返回非零, 说明映射失败发生在某个中断/异常处理程序中, 与当前出现异常进程无关.
	//mm 为空, 说明当前出现异常进程的映射还没有建立, 与该进程无关. 说明映射发生在某个 in_interrupt() 程序无法检测的某个中断/异常处理程序中.
	/**
	 * 内核是否在执行一些关键例程，或者是内核线程出错了。
	 * in_atomic表示内核现在禁止抢占，一般是中断处理程序、可延迟函数、临界区或内核线程中。
	 * 一般来说，这些程序不会去访问用户空间地址。因为访问这些地址总是可能造成导致阻塞。
	 * 而这些地方是不允许阻塞的。
	 * 总之，问题有点严重。
	 */
	if (in_atomic() || !mm)
		goto bad_area_nosemaphore;

	/* When running in the kernel we expect faults to occur only to
	 * addresses in user space.  All other faults represent errors in the
	 * kernel and should generate an OOPS.  Unfortunately, in the case of an
	 * erroneous fault occurring in a code path which already holds mmap_sem
	 * we will deadlock attempting to validate the fault against the
	 * address space.  Luckily the kernel only validly references user
	 * space from well defined areas of code, which are listed in the
	 * exceptions table.
	 *
	 * As the vast majority of faults will be valid we will only perform
	 * the source reference check when there is a possibility of a deadlock.
	 * Attempt to lock the address space, if we cannot we then validate the
	 * source.  If this is invalid we can skip the address space check,
	 * thus avoiding the deadlock.
	 */
	// 信号量, 锁住 mm_struct 及其下属的 vm_area_struct, 防止其他进程打扰.
	/**
	 * 缺页没有发生在中断处理程序、可延迟函数、临界区、内核线程中
	 * 那么，就需要检查进程所拥有的线性区，以决定引起缺页的线性地址是否包含在进程的地址空间中
	 * 为此，必须获得进程的mmap_sem读写信号量。
	 */

	/**
	 * 既然不是内核BUG，也不是硬件故障，那么缺页发生时，当前进程就还没有为写而获得信号量mmap_sem.
	 * 但是为了稳妥起见，还是调用down_read_trylock确保mmap_sem没有被其他地方占用。
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		/**
		 * 一般不会运行到这里来。
		 * 运行到这里表示:信号被关闭了。
		 */
		if ((error_code & 4) == 0 &&
		    !search_exception_tables(regs->eip))/* 第2位被清0，则异常发生在内核态; 且在异常处理表中又没有对应的处理函数。*/
		    /**
		     * 内核态异常，在异常处理表中又没有对应的处理函数。
		     * 转到bad_area_nosemaphore，它会再检查一下：是否是使用作为系统调用参数被传递给内核的线性地址。
		     * 请回想一下,access_ok只是作了简单的检查，并不确保线性地址空间真的存在（只要是用户态地址就行了）
		     * 也就是说：用户态程序在调用系统调用的时候，可能传递了一个非法的用户态地址给内核。
		     * 而内核试图读写这个地址的时候，就出错了
		     * 的确，这里就会处理这个情况。
		     */
			goto bad_area_nosemaphore;
			/**
		 * 否则，不是内核异常或者严重的硬件故障。并且信号量被其他线程占用了，等待其他线程释放信号量后继续。
		 */
		down_read(&mm->mmap_sem);
	}
	// 查找当前出现异常进程区间中第一个结束地址大于出错地址的区间
	/**
	 * 运行到此，就已经获得了mmap_sem信号量。
	 * 可以放心的操作mm了。
	 * 现在开始搜索出错地址所在的线性区。
	 */
	vma = find_vma(mm, address);
	// 用户程序越界访问系统空间	
	/**
	 * 如果vma为空，说明在出错地址后面没有线性区了，说明错误的地址肯定是无效的。
	 */ 
	if (!vma)
		goto bad_area;
	// vma->vm_struct <= address 说明 address 在这个区间中
	/**
	 * vma在address后面，并且它的起始地址在address前面，说明线性区包含了这个地址。
	 * 谢天谢地，这很可能不是真的错误，可能是COW机制起作用了，也可能是需要调页了。
	 */
	if (vma->vm_start <= address)
		goto good_area;
	// 虚拟地址处于用户空间, 但是不在任何一个 vm_area_struct 之中
	// VM_GROWSDOWN 表示当前 vma 处于栈区
	// 紧邻其上的不是一个栈区区间, 当前的空间没有建立映射或映射已经被销毁
	/**
	 * 运行到此，说明地址并不在线性区中。
	 * 但是我们还要再判断一下，有可能是push指令引起的异常。和vma==NULL还不太一样。
	 * 直接转到bad_area是不正确的。
	 */
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	// 内存映射的空洞紧邻其上的是一个栈区区间
	// 处于用户模式
	/**
	 * 运行到此，说明address地址后面的vma有VM_GROWSDOWN标志，表示它是一个堆栈区
	 * 请注意，如果是内核态访问用户态的堆栈空间，就应该直接扩展堆栈，而不判断if (address + 32 < regs->esp)
	 * 注意，如果是内核态在访问用户态堆栈空间，没有32的距离限制，都应该expand_stack
	 */
	if (error_code & 4) {
		/*
		 * Accessing the stack below %esp is always a bug.
		 * The large cushion allows instructions like enter
		 * and pusha to work.  ("enter $65535,$31" pushes
		 * 32 pointers and then decrements %esp by 65535.)
		 * 访问 %esp 所指向的栈顶之下的空间总是一个 bug.
		 * 由于一些指令(如 pusha)会使 %esp 做递减, 并在更下面的位置,
		 * 所以会 "+ 32"
		 */
		// 在参数入栈时一次入栈最多通过 pusha 入栈 32 个字节
		// 所以如果访问的位置超出 32 个字节说明访问的页面出错异常不是堆栈扩展造成的
		if (address + 65536 + 32 * sizeof(unsigned long) < regs->esp)
			goto bad_area;
	}
	// 本次页面出错异常是堆栈扩展造成的
	// 扩展堆栈: expand_stack 建立页面映射并扩展栈区
	/**
	 * 线程堆栈空间不足，就扩展一下，一般会成功的，不会运行到bad_area.
	 * 注意:如果异常发生在内核态，说明内核正在访问用户态的栈，就直接扩展用户栈。
	 * 注意这里只是扩展了vma，但是并没有分配新的也
	 */
	if (expand_stack(vma, address))
		goto bad_area;
/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 * 对于这次内存访问, 我们有一个好的 vm_area_struct, 因此我们可以处理它..
 */
	/**
 * 处理地址空间内的错误地址。其实可能并不是错误地址。
 */
good_area:
	si_code = SEGV_ACCERR;
	write = 0;
	switch (error_code & 3) {/* 错误是由写访问引起的 */ /*★*/
	/* 出错指令为读操作, 物理页面在内存中 */
	default: /* 3: write, present */
			 /* fall through */
	/* 出错指令为写操作, 物理页面不在内存中 */
	/**
		 * 写访问出错。
		 */
	case 2:  /* write, not present *//*异常由由一个不存在的页, 写访问引起。*/
		// 检查当前 vma 是否可写
			/**
			 * 但是线性区不允许写，难道是想写只读数据区或者代码段？？？
			 * 注意，当errcode==3也会到这里
			 */
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
		/**
			 * 线性区可写，但是此时发生了写访问错误。
			 * 说明可以启动写时复制或请求调页了。将write++其实就是将它置1
			 */
		write++;
		break;
	/* 出错指令为读操作, 物理页面在内存中 */
		/**
		 * 没有读权限？？
		 * 可能是由于进程试图访问一个有特权的页框。
		 */
	case 1: /* read, present *//*异常由无效的访问权限, 读访问或者执行访问所引起*/
		goto bad_area;
	/* 出错指令为读操作, 物理页面不在内存中 */
		/**
		 * 要读的页不存在，检查是否真的可读或者可执行
		 */
	case 0: /* read, not present *//*异常由一个不存在的页, 读访问或者执行访问所引起*/
		/**
			 * 要读的页不存在，也不允许读和执行，那也是一种错误
			 */
		if (!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE)))
			goto bad_area;
		/**
			 * 运行到这里，说明要读的页不存在，但是线性区允许读，说明是需要调页了。
			 */
	}
	/**
 * 幸免于难，可能不是真正的错误。
 * 呵呵，找块毛巾擦擦汗。
 */
 survive:
	 /*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 * 如果因为任何原因我们无法处理错误, 请确保我们优雅的退出, 而不是无休止的重复处理错误
	 */
	 //真正处理出错的内存页，创建页表
 /**
	 * 线性区的访问权限与引起异常的类型相匹配，调用handle_mm_fault分配一个新页框。
	 * handle_mm_fault中会处理请求调页和写时复制两种机制。
	 */
	 fault = handle_mm_fault(mm, vma, address, write);
	 //返回值VM_FAULT_MINOR:数据已经在内存中,VM_FAULT_MAJOR:数据需要从块设备读取
	 if (unlikely(fault & VM_FAULT_ERROR))
	 {
	 	/**
		 * VM_FAULT_OOM表示没有足够的内存
		 * 如果不是init进程，就杀死它，否则就调度其他进程运行，等待内存被释放出来。
		 */
		 if (fault & VM_FAULT_OOM)
			 goto out_of_memory;
			/**
		 * VM_FAULT_SIGBUS表示其他错误。
		 * do_sigbus会向进程发送SIGBUS信号。
		 *//*不正常*/
		 else if (fault & VM_FAULT_SIGBUS)
			 goto do_sigbus;
		 BUG();
	}
	/**
		 * VM_FAULT_MAJOR表示阻塞了当前进程，即主缺页。
		 * 很可能是由于当用磁盘上的数据填充所分配的页框时花费了时间。
		 */
	if (fault & VM_FAULT_MAJOR)
		tsk->maj_flt++;
	else
		//没有阻塞当前进程，即次缺页/*正常*/
		tsk->min_flt++;

	/*
	 * Did it hit the DOS screen memory VA from vm86 mode?
	 */
	// 处理与 VM86 模式及 VGA 的图像存储区相关的特殊情况
	if (regs->eflags & VM_MASK) {
		unsigned long bit = (address - 0xA0000) >> PAGE_SHIFT;
		if (bit < 32)
			tsk->thread.screen_bitmap |= 1 << bit;
	}
	up_read(&mm->mmap_sem);
	return;

 /*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 * 尝试访问的内存不在内存映射(vm_area_struct)之中
 * 首先检查当前出现异常进程属于用户还是内核, 然后修复..
 */
	/**
 * 处理地址空间以外的错误地址。
 * 当要访问的地址不在进程的地址空间内时，执行到此。
 */
 bad_area:
	 // 对于 mm_struct 及其下属 vm_area_struct 的使用完成, 信号量解锁
	 up_read(&mm->mmap_sem);
/**
 * 用户态程序访问了内核态地址，或者访问了没有权限的页框。
 * 或者是内核态线程出错了，也或者是当前有很紧要的操作
 * 总之，运行到这里可不是什么好事。
 */
 bad_area_nosemaphore:
	 /* User mode accesses just cause a SIGSEGV */
	 // 用户模式
 /**
	 * 第2位 == 1, 异常发生在用户态。
	 * 发生在用户态的错误地址。
	 * 就发生一个SIGSEGV信号给current进程，并结束函数。
	 */
	 if (error_code & 4)
	 {
		 /*
		 * It's possible to have interrupts off here.
		 */
		 local_irq_enable();

		 /* 
		 * Valid to do another page fault here because this one came 
		 * from user space.
		 */
		 if (is_prefetch(regs, address, error_code))
			 return;

		 if (show_unhandled_signals && unhandled_signal(tsk, SIGSEGV) &&
			 printk_ratelimit())
		 {
			 printk("%s%s[%d]: segfault at %08lx eip %08lx "
					"esp %08lx error %lx\n",
					task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
					tsk->comm, task_pid_nr(tsk), address, regs->eip,
					regs->esp, error_code);
		 }
		 // 设置当前出现异常进程的 task_struct
		 tsk->thread.cr2 = address;
		 /* Kernel addresses are always protection faults */
		 tsk->thread.error_code = error_code | (address >= TASK_SIZE);
		 tsk->thread.trap_no = 14;
		 // 向当前出现异常进程发送一个强制 SIGSEGV 信号, 产生 Segment Fault
		 /**
		 * force_sig_info确信进程不忽略或阻塞SIGSEGV信号
		 * SEGV_MAPERR或SEGV_ACCERR已经被设置在info.si_code中。
		 */
		 force_sig_info_fault(SIGSEGV, si_code, address, tsk);
		 return;
	 }
	 /*从这里往下，异常发生在内核态*/
#ifdef CONFIG_X86_F00F_BUG
	/*
	 * Pentium F0 0F C7 C8 bug workaround.
	 */
	if (boot_cpu_data.f00f_bug) {
		unsigned long nr;
		
		nr = (address - idt_descr.address) >> 3;

		if (nr == 6) {
			do_invalid_op(regs, 0);
			return;
		}
	}
#endif
	/**
	 * 异常发生在内核态。
	 */
no_context:
	/* Are we prepared to handle this kernel fault?  */
/**
	 * 异常的引起是因为把某个线性地址作为系统调用的参数传递给内核。
	 * 调用fixup_exception判断这种情况，如果是这样的话，那谢天谢地，还有修复的可能。
	 * 典型的：fixup_exception可能会向进程发送SIGSEGV信号或者用一个适当的出错码终止系统调用处理程序。
	 */
	if (fixup_exception(regs))
		return;

	/* 
	 * Valid to do another page fault here, because if this fault
	 * had been triggered by is_prefetch fixup_exception would have 
	 * handled it.
	 */
 	if (is_prefetch(regs, address, error_code))
 		return;

/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice.
 */

	bust_spinlocks(1);

	if (oops_may_print()) {
		__typeof__(pte_val(__pte(0))) page;

#ifdef CONFIG_X86_PAE
		if (error_code & 16) {
			pte_t *pte = lookup_address(address);

			if (pte && pte_present(*pte) && !pte_exec_kernel(*pte))
				printk(KERN_CRIT "kernel tried to execute "
					"NX-protected page - exploit attempt? "
					"(uid: %d)\n", current->uid);
		}
#endif
		/**
	 * 但愿程序不要运行到这里来，著名的oops出现了^-^
	 * 不过oops算什么呢，真正的内核高手在等着解决这些错误呢
	 */
		if (address < PAGE_SIZE)
			printk(KERN_ALERT "BUG: unable to handle kernel NULL "
					"pointer dereference");
		else
			printk(KERN_ALERT "BUG: unable to handle kernel paging"
					" request");
		printk(" at virtual address %08lx\n",address);
		printk(KERN_ALERT "printing eip: %08lx ", regs->eip);

		page = read_cr3();
		page = ((__typeof__(page) *) __va(page))[address >> PGDIR_SHIFT];
#ifdef CONFIG_X86_PAE
		printk("*pdpt = %016Lx ", page);
		if ((page >> PAGE_SHIFT) < max_low_pfn
		    && page & _PAGE_PRESENT) {
			page &= PAGE_MASK;
			page = ((__typeof__(page) *) __va(page))[(address >> PMD_SHIFT)
			                                         & (PTRS_PER_PMD - 1)];
			printk(KERN_CONT "*pde = %016Lx ", page);
			page &= ~_PAGE_NX;
		}
#else
		printk("*pde = %08lx ", page);
#endif

		/*
		 * We must not directly access the pte in the highpte
		 * case if the page table is located in highmem.
		 * And let's rather not kmap-atomic the pte, just in case
		 * it's allocated already.
		 */
		if ((page >> PAGE_SHIFT) < max_low_pfn
		    && (page & _PAGE_PRESENT)
		    && !(page & _PAGE_PSE)) {
			page &= PAGE_MASK;
			page = ((__typeof__(page) *) __va(page))[(address >> PAGE_SHIFT)
			                                         & (PTRS_PER_PTE - 1)];
			printk("*pte = %0*Lx ", sizeof(page)*2, (u64)page);
		}

		printk("\n");
	}

	tsk->thread.cr2 = address;
	tsk->thread.trap_no = 14;
	tsk->thread.error_code = error_code;
	die("Oops", regs, error_code);/*★*/
	bust_spinlocks(0);
	do_exit(SIGKILL);

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
	/**
 * 缺页了，但是没有内存了，就杀死进程（init除外）
 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (is_global_init(tsk)) {/*如果是init, 则调度其他进行*/
		yield();
		down_read(&mm->mmap_sem);
		goto survive;
	}
	printk("VM: killing process %s\n", tsk->comm);
	if (error_code & 4)
		do_group_exit(SIGKILL);
	goto no_context;
/**
 * 缺页了，但是分配页时出现了错误，就向进程发送SIGBUS信号。
 */
do_sigbus:
	up_read(&mm->mmap_sem);

	/* Kernel mode? Handle exceptions or die */
	if (!(error_code & 4))
		goto no_context;

	/* User space => ok to do another page fault */
	if (is_prefetch(regs, address, error_code))
		return;

	tsk->thread.cr2 = address;
	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 14;
	force_sig_info_fault(SIGBUS, BUS_ADRERR, address, tsk);
}

void vmalloc_sync_all(void)
{
	/*
	 * Note that races in the updates of insync and start aren't
	 * problematic: insync can only get set bits added, and updates to
	 * start are only improving performance (without affecting correctness
	 * if undone).
	 */
	static DECLARE_BITMAP(insync, PTRS_PER_PGD);
	static unsigned long start = TASK_SIZE;
	unsigned long address;

	if (SHARED_KERNEL_PMD)
		return;

	BUILD_BUG_ON(TASK_SIZE & ~PGDIR_MASK);
	for (address = start; address >= TASK_SIZE; address += PGDIR_SIZE) {
		if (!test_bit(pgd_index(address), insync)) {
			unsigned long flags;
			struct page *page;

			spin_lock_irqsave(&pgd_lock, flags);
			for (page = pgd_list; page; page =
					(struct page *)page->index)
				if (!vmalloc_sync_one(page_address(page),
								address)) {
					BUG_ON(page != pgd_list);
					break;
				}
			spin_unlock_irqrestore(&pgd_lock, flags);
			if (!page)
				set_bit(pgd_index(address), insync);
		}
		if (address == start && test_bit(pgd_index(address), insync))
			start = address + PGDIR_SIZE;
	}
}
