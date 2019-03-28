/*
 *  linux/arch/arm/mm/mmap.c
 */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/shm.h>
#include <linux/sched.h>
#include <asm/system.h>

#define COLOUR_ALIGN(addr,pgoff)		\
	((((addr)+SHMLBA-1)&~(SHMLBA-1)) +	\
	 (((pgoff)<<PAGE_SHIFT) & (SHMLBA-1)))

/*
 * We need to ensure that shared mappings are correctly aligned to
 * avoid aliasing issues with VIPT caches.  We need to ensure that
 * a specific page of an object is always mapped at a multiple of
 * SHMLBA bytes.
 *
 * We unconditionally provide this function for all cases, however
 * in the VIVT case, we optimise out the alignment rules.
 */
/**
 * 分配从低端地址向高端地址移动的线性区(如堆而不是栈)
 */
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;
#ifdef CONFIG_CPU_V6
	unsigned int cache_type;
	int do_align = 0, aliasing = 0;

	/*
	 * We only need to do colour alignment if either the I or D
	 * caches alias.  This is indicated by bits 9 and 21 of the
	 * cache type register.
	 */
	cache_type = read_cpuid(CPUID_CACHETYPE);
	if (cache_type != read_cpuid(CPUID_ID)) {
		aliasing = (cache_type | cache_type >> 12) & (1 << 11);
		if (aliasing)
			do_align = filp || flags & MAP_SHARED;
	}
#else
#define do_align 0
#define aliasing 0
#endif

	/*
	 * We enforce the MAP_FIXED case.
	 */
	if (flags & MAP_FIXED) {
		if (aliasing && flags & MAP_SHARED && addr & (SHMLBA - 1))
			return -EINVAL;
		return addr;
	}
	/**
	 * 当然了，只要是普通进程地址，就不能超过TASK_SIZE(一般就是3G)
	 */
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (addr) {
		/**
		 * 如果地址不是0，就从addr处开始分配
		 * 当然，需要将addr按4K取整
		 */
		if (do_align)
			addr = COLOUR_ALIGN(addr, pgoff);
		else
			addr = PAGE_ALIGN(addr);

		vma = find_vma(mm, addr);
		/**
		 * TASK_SIZE - len >= addr而不是addr + len <= TASK_SIZE
		 */
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;/* 没有被映射，这块区间可以使用。 */
	}
	if (len > mm->cached_hole_size) {
		/**
	 * 如果addr==0或者前面的搜索失败
	 * 从free_area_cache开始搜索，这个值初始为用户态空间的1/3处（即1G处），它也是为正文段、数据段、BSS段保留的
	 */
	        start_addr = addr = mm->free_area_cache;
	} else {
	        start_addr = addr = TASK_UNMAPPED_BASE;
	        mm->cached_hole_size = 0;
	}

full_search:
	if (do_align)
		addr = COLOUR_ALIGN(addr, pgoff);
	else
		addr = PAGE_ALIGN(addr);

	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			/**
			 * 没有找到，从TASK_UNMAPPED_BASE(1G)处开始找
			 * 第二次再从1G开始搜索的时候，start_addr = TASK_UNMAPPED_BASE，就会直接返回错误 -ENOMEM
			 */
			if (start_addr != TASK_UNMAPPED_BASE) {
				start_addr = addr = TASK_UNMAPPED_BASE;
				mm->cached_hole_size = 0;
				goto full_search;
			}
			return -ENOMEM;
		}
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
			/**
			 * 找到了，记下本次找到的地方，下次从addr+len处开始找
			 */
			mm->free_area_cache = addr + len;
			return addr;
		}
		if (addr + mm->cached_hole_size < vma->vm_start)
		        mm->cached_hole_size = vma->vm_start - addr;
		addr = vma->vm_end;
		if (do_align)
			addr = COLOUR_ALIGN(addr, pgoff);
	}
}


/*
 * You really shouldn't be using read() or write() on /dev/mem.  This
 * might go away in the future.
 */
int valid_phys_addr_range(unsigned long addr, size_t size)
{
	if (addr + size > __pa(high_memory))
		return 0;

	return 1;
}

/*
 * We don't use supersection mappings for mmap() on /dev/mem, which
 * means that we can't map the memory area above the 4G barrier into
 * userspace.
 */
int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
	return !(pfn + (size >> PAGE_SHIFT) > 0x00100000);
}
