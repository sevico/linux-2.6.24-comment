/*
 *	Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 *
 * This file contains the lowest level x86-specific interrupt
 * entry, irq-stacks and irq statistics code. All the remaining
 * irq logic is done by the generic kernel/irq/ code and
 * by the x86-specific irq controller code. (e.g. i8259.c and
 * io_apic.c.)
 */

#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/delay.h>

#include <asm/apic.h>
#include <asm/uaccess.h>

DEFINE_PER_CPU_SHARED_ALIGNED(irq_cpustat_t, irq_stat);
EXPORT_PER_CPU_SYMBOL(irq_stat);

DEFINE_PER_CPU(struct pt_regs *, irq_regs);
EXPORT_PER_CPU_SYMBOL(irq_regs);

/*
 * 'what should we do if we get a hw irq event on an illegal vector'.
 * each architecture has to answer this themselves.
 */
void ack_bad_irq(unsigned int irq)
{
	printk(KERN_ERR "unexpected IRQ trap at vector %02x\n", irq);

#ifdef CONFIG_X86_LOCAL_APIC
	/*
	 * Currently unexpected vectors happen only on SMP and APIC.
	 * We _must_ ack these because every local APIC has only N
	 * irq slots per priority level, and a 'hanging, unacked' IRQ
	 * holds up an irq slot - in excessive cases (when multiple
	 * unexpected vectors occur) that might lock up the APIC
	 * completely.
	 * But only ack when the APIC is enabled -AK
	 */
	if (cpu_has_apic)
		ack_APIC_irq();
#endif
}

#ifdef CONFIG_4KSTACKS
/*
 * per-CPU IRQ handling contexts (thread information and stack)
 */
union irq_ctx {
	struct thread_info      tinfo;
	u32                     stack[THREAD_SIZE/sizeof(u32)];
};

static union irq_ctx *hardirq_ctx[NR_CPUS] __read_mostly;
static union irq_ctx *softirq_ctx[NR_CPUS] __read_mostly;
#endif

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
fastcall unsigned int do_IRQ(struct pt_regs *regs)
{	
	struct pt_regs *old_regs;
	/* high bit used in ret_from_ code */
	//获取中断向量号
	//压入堆栈的 irq 取反得到起始 irq，注意是从0开始的，0~31的中断向量
	//是 CPU 内部保留的，从31开始，这个向量的作用是找到合适的中断入口程序，
	//不要把这个irq和中断向量号混淆
	int irq = ~regs->orig_eax;
	//找到 irq_desc结构
	struct irq_desc *desc = irq_desc + irq;
#ifdef CONFIG_4KSTACKS
	union irq_ctx *curctx, *irqctx;
	u32 *isp;
#endif

	if (unlikely((unsigned)irq >= NR_IRQS)) {
		printk(KERN_EMERG "%s: cannot handle IRQ %d\n",
					__FUNCTION__, irq);
		BUG();
	}

	old_regs = set_irq_regs(regs);
	//进入中断上下文
	irq_enter();
#ifdef CONFIG_DEBUG_STACKOVERFLOW
	/* Debugging check for stack overflow: is there less than 1KB free? */
	{
		long esp;

		__asm__ __volatile__("andl %%esp,%0" :
					"=r" (esp) : "0" (THREAD_SIZE - 1));
		if (unlikely(esp < (sizeof(struct thread_info) + STACK_WARN))) {
			printk("do_IRQ: stack overflow: %ld\n",
				esp - sizeof(struct thread_info));
			dump_stack();
		}
	}
#endif
/*CONFIG_4KSTACKS: 如果thread_union大小为4KB*/

#ifdef CONFIG_4KSTACKS
	/**
	 * 如果中断栈使用不同的的栈,就需要切换栈.
	 */
	/*
	 * 执行current_thread_info 以获取与内核栈相连的thread_info描述符的地址保存到curctx
	 */
	curctx = (union irq_ctx *) current_thread_info();
	/*
	 * 硬中断请求栈地址保存到irqctx
	 */
	irqctx = hardirq_ctx[smp_processor_id()];

	/*
	 * this is where we switch to the IRQ stack. However, if we are
	 * already using the IRQ stack (because we interrupted a hardirq
	 * handler) we can't do that and just have to keep using the
	 * current stack (which is the irq stack already after all)
	 */
	/**
	 * 当前在使用内核栈,而不是硬中断请求栈.就需要切换栈
	 * 
	 * curctx 和irqctx 相等，说明内核已经在使用硬件中断请求栈，
	 * 这种情况发生在内核处理另外一个中断时又产生了中断请求的时候
	 * 不相等就要切换内核栈
	 */
	if (curctx != irqctx) {
		int arg1, arg2, ebx;

		/* build the stack frame on the IRQ stack */
		isp = (u32*) ((char*)irqctx + sizeof(*irqctx));
		/**
		 * 保存当前进程描述符指针
		 */
		irqctx->tinfo.task = curctx->tinfo.task;
		/**
		 * 把esp栈指针寄存器的当前值存入irqctx的thread_info(内核oops时使用)
		 * current_stack_pointer 用来在C 中获得当前的栈指针
		 */
		irqctx->tinfo.previous_esp = current_stack_pointer;

		/*
		 * Copy the softirq bits in preempt_count so that the
		 * softirq checks work in the hardirq context.
		 */
		irqctx->tinfo.preempt_count =
			(irqctx->tinfo.preempt_count & ~SOFTIRQ_MASK) |
			(curctx->tinfo.preempt_count & SOFTIRQ_MASK);
			/**
		 * 将中断请求栈的栈顶装入esp,isp即为中断栈顶
		 * 调用完__do_IRQ后,从ebx中恢复esp
		 */
		asm volatile(
			"       xchgl  %%ebx,%%esp      \n"
			"       call   *%%edi           \n"
			"       movl   %%ebx,%%esp      \n"
			: "=a" (arg1), "=d" (arg2), "=b" (ebx)
			:  "0" (irq),   "1" (desc),  "2" (isp),
			   "D" (desc->handle_irq)
			: "memory", "cc"
		);
	} else/* 否则,发生了中断嵌套,不用切换 */
#endif
//调用该IRQ的公共处理程序对中断进行处理
		desc->handle_irq(irq, desc);
//推出中断上下文
		/**
	 * 递减中断计数器并检查是否有可延迟函数
	 */
	irq_exit();
	set_irq_regs(old_regs);
	/**
	 * 结束后,会返回ret_from_intr函数. 
	 */
	return 1;
}

#ifdef CONFIG_4KSTACKS

static char softirq_stack[NR_CPUS * THREAD_SIZE]
		__attribute__((__section__(".bss.page_aligned")));

static char hardirq_stack[NR_CPUS * THREAD_SIZE]
		__attribute__((__section__(".bss.page_aligned")));

/*
 * allocate per-cpu stacks for hardirq and for softirq processing
 */
void irq_ctx_init(int cpu)
{
	union irq_ctx *irqctx;

	if (hardirq_ctx[cpu])
		return;

	irqctx = (union irq_ctx*) &hardirq_stack[cpu*THREAD_SIZE];
	irqctx->tinfo.task              = NULL;
	irqctx->tinfo.exec_domain       = NULL;
	irqctx->tinfo.cpu               = cpu;
	irqctx->tinfo.preempt_count     = HARDIRQ_OFFSET;
	irqctx->tinfo.addr_limit        = MAKE_MM_SEG(0);

	hardirq_ctx[cpu] = irqctx;

	irqctx = (union irq_ctx*) &softirq_stack[cpu*THREAD_SIZE];
	irqctx->tinfo.task              = NULL;
	irqctx->tinfo.exec_domain       = NULL;
	irqctx->tinfo.cpu               = cpu;
	irqctx->tinfo.preempt_count     = 0;
	irqctx->tinfo.addr_limit        = MAKE_MM_SEG(0);

	softirq_ctx[cpu] = irqctx;

	printk("CPU %u irqstacks, hard=%p soft=%p\n",
		cpu,hardirq_ctx[cpu],softirq_ctx[cpu]);
}

void irq_ctx_exit(int cpu)
{
	hardirq_ctx[cpu] = NULL;
}

extern asmlinkage void __do_softirq(void);

asmlinkage void do_softirq(void)
{
	unsigned long flags;
	struct thread_info *curctx;
	union irq_ctx *irqctx;
	u32 *isp;

	if (in_interrupt())
		return;

	local_irq_save(flags);

	if (local_softirq_pending()) {
		curctx = current_thread_info();
		irqctx = softirq_ctx[smp_processor_id()];
		irqctx->tinfo.task = curctx->task;
		irqctx->tinfo.previous_esp = current_stack_pointer;

		/* build the stack frame on the softirq stack */
		isp = (u32*) ((char*)irqctx + sizeof(*irqctx));

		asm volatile(
			"       xchgl   %%ebx,%%esp     \n"
			"       call    __do_softirq    \n"
			"       movl    %%ebx,%%esp     \n"
			: "=b"(isp)
			: "0"(isp)
			: "memory", "cc", "edx", "ecx", "eax"
		);
		/*
		 * Shouldnt happen, we returned above if in_interrupt():
	 	 */
		WARN_ON_ONCE(softirq_count());
	}

	local_irq_restore(flags);
}
#endif

/*
 * Interrupt statistics:
 */

atomic_t irq_err_count;

/*
 * /proc/interrupts printing:
 */

int show_interrupts(struct seq_file *p, void *v)
{
	int i = *(loff_t *) v, j;
	struct irqaction * action;
	unsigned long flags;

	if (i == 0) {
		seq_printf(p, "           ");
		for_each_online_cpu(j)
			seq_printf(p, "CPU%-8d",j);
		seq_putc(p, '\n');
	}

	if (i < NR_IRQS) {
		unsigned any_count = 0;

		spin_lock_irqsave(&irq_desc[i].lock, flags);
#ifndef CONFIG_SMP
		any_count = kstat_irqs(i);
#else
		for_each_online_cpu(j)
			any_count |= kstat_cpu(j).irqs[i];
#endif
		action = irq_desc[i].action;
		if (!action && !any_count)
			goto skip;
		seq_printf(p, "%3d: ",i);
#ifndef CONFIG_SMP
		seq_printf(p, "%10u ", kstat_irqs(i));
#else
		for_each_online_cpu(j)
			seq_printf(p, "%10u ", kstat_cpu(j).irqs[i]);
#endif
		seq_printf(p, " %8s", irq_desc[i].chip->name);
		seq_printf(p, "-%-8s", irq_desc[i].name);

		if (action) {
			seq_printf(p, "  %s", action->name);
			while ((action = action->next) != NULL)
				seq_printf(p, ", %s", action->name);
		}

		seq_putc(p, '\n');
skip:
		spin_unlock_irqrestore(&irq_desc[i].lock, flags);
	} else if (i == NR_IRQS) {
		seq_printf(p, "NMI: ");
		for_each_online_cpu(j)
			seq_printf(p, "%10u ", nmi_count(j));
		seq_printf(p, "  Non-maskable interrupts\n");
#ifdef CONFIG_X86_LOCAL_APIC
		seq_printf(p, "LOC: ");
		for_each_online_cpu(j)
			seq_printf(p, "%10u ",
				per_cpu(irq_stat,j).apic_timer_irqs);
		seq_printf(p, "  Local timer interrupts\n");
#endif
#ifdef CONFIG_SMP
		seq_printf(p, "RES: ");
		for_each_online_cpu(j)
			seq_printf(p, "%10u ",
				per_cpu(irq_stat,j).irq_resched_count);
		seq_printf(p, "  Rescheduling interrupts\n");
		seq_printf(p, "CAL: ");
		for_each_online_cpu(j)
			seq_printf(p, "%10u ",
				per_cpu(irq_stat,j).irq_call_count);
		seq_printf(p, "  function call interrupts\n");
		seq_printf(p, "TLB: ");
		for_each_online_cpu(j)
			seq_printf(p, "%10u ",
				per_cpu(irq_stat,j).irq_tlb_count);
		seq_printf(p, "  TLB shootdowns\n");
#endif
		seq_printf(p, "TRM: ");
		for_each_online_cpu(j)
			seq_printf(p, "%10u ",
				per_cpu(irq_stat,j).irq_thermal_count);
		seq_printf(p, "  Thermal event interrupts\n");
		seq_printf(p, "SPU: ");
		for_each_online_cpu(j)
			seq_printf(p, "%10u ",
				per_cpu(irq_stat,j).irq_spurious_count);
		seq_printf(p, "  Spurious interrupts\n");
		seq_printf(p, "ERR: %10u\n", atomic_read(&irq_err_count));
#if defined(CONFIG_X86_IO_APIC)
		seq_printf(p, "MIS: %10u\n", atomic_read(&irq_mis_count));
#endif
	}
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
#include <mach_apic.h>

void fixup_irqs(cpumask_t map)
{
	unsigned int irq;
	static int warned;

	for (irq = 0; irq < NR_IRQS; irq++) {
		cpumask_t mask;
		if (irq == 2)
			continue;

		cpus_and(mask, irq_desc[irq].affinity, map);
		if (any_online_cpu(mask) == NR_CPUS) {
			printk("Breaking affinity for irq %i\n", irq);
			mask = map;
		}
		if (irq_desc[irq].chip->set_affinity)
			irq_desc[irq].chip->set_affinity(irq, mask);
		else if (irq_desc[irq].action && !(warned++))
			printk("Cannot set affinity for irq %i\n", irq);
	}

#if 0
	barrier();
	/* Ingo Molnar says: "after the IO-APIC masks have been redirected
	   [note the nop - the interrupt-enable boundary on x86 is two
	   instructions from sti] - to flush out pending hardirqs and
	   IPIs. After this point nothing is supposed to reach this CPU." */
	__asm__ __volatile__("sti; nop; cli");
	barrier();
#else
	/* That doesn't seem sufficient.  Give it 1ms. */
	local_irq_enable();
	mdelay(1);
	local_irq_disable();
#endif
}
#endif

