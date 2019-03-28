#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/auxvec.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/prio_tree.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <asm/page.h>
#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct address_space;

#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
typedef atomic_long_t mm_counter_t;
#else  /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */
typedef unsigned long mm_counter_t;
#endif /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 */
struct page {
//页面标识
	/**
	 * 一组标志，也对页框所在的管理区进行编号
	 * 在不支持NUMA的机器上，flags中字段中管理索引占两位，节点索引占一位。
	 * 在支持NUMA的32位机器上，flags中管理索引占用两位。节点数目占6位。
	 * 在支持NUMA的64位机器上，64位的flags字段中，管理区索引占用两位，节点数目占用10位。
	 */
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
//引用次数
	/**
	 * 页框的引用计数。当小于0表示没有人使用。
	 * Page_count返回_count+1表示正在使用的人数。
	 */
	atomic_t _count;		/* Usage count, see below. */
	/**
	 * 页框中的页表项数目（没有则为-1）
	 *		-1:		表示没有页表项引用该页框。
	 *		0:		表明页是非共享的。
	 *		>0:		表示而是共享的。
	 */
	union {
		//映射计数器
		atomic_t _mapcount;	/* Count of ptes mapped in mms,
					 * to show when page is mapped
					 * & limit reverse map searches.
					 */
		unsigned int inuse;	/* SLUB: Nr of objects 用于slub*/
	};
	union {
	    struct {
	    	/**
	 * 可用于正在使用页的内核成分（如在缓冲页的情况下，它是一个缓冲器头指针。）
	 * 如果页是空闲的，则该字段由伙伴系统使用。
	 * 当用于伙伴系统时，如果该页是一个2^k的空闲页块的第一个页，那么它的值就是k.
	 * 这样，伙伴系统可以查找相邻的伙伴，以确定是否可以将空闲块合并成2^(k+1)大小的空闲块。
	 */
		unsigned long private;		/* Mapping-private opaque data:
					 	 * usually used for buffer_heads
						 * if PagePrivate set; used for
						 * swp_entry_t if PageSwapCache;
						 * indicates order in the buddy
						 * system if PG_buddy is set.
						 */
		//文件缓存空间
	    	/**
	 * 当页被插入页高速缓存时使用或者当页属于匿名页时使用）。
	 * 		如果mapping字段为空，则该页属于交换高速缓存(swap cache)。
	 *		如果mapping字段不为空，且最低位为1，表示该页为匿名页。同时该字段中存放的是指向anon_vma描述符的指针。
	 *		如果mapping字段不为空，且最低位为0，表示该页为映射页。同时该字段指向对应文件的address_space对象。
	 */
		struct address_space *mapping;	/* If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
	    };
#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
	    spinlock_t ptl;
#endif
	    struct kmem_cache *slab;	/* SLUB: Pointer to slab */
	    struct page *first_page;	/* Compound tail pages */
	};
	union {
		/**
	 * 作为不同的含义被几种内核成分使用。
	 * 在页磁盘映象或匿名区中表示存放在页框中的数据的位置。
	 * 或者它存放在一个换出页标志符。
	 * 表示所有者的地址空间中以页大小为单位的偏移量，
	 * 也就是磁盘映像中页中数据的位置
	 * page->index是区域内的页索引或是页的线性地址除以PAGE_SIZE
	 * 
	 * liufeng: 
	 * 不是页内偏移量，而是该页面相对于文件起始位置，以页面为大小的偏移量
	 * 如果减去vma->vm_pgoff，就表示该页面的虚拟地址相对于vma起始地址，以页面为大小的偏移量
	 */
		pgoff_t index;		/* Our offset within mapping. */
		void *freelist;		/* SLUB: freelist req. slab lock */
	};
	/**
	 * 包含页的最近最少使用的双向链表的指针。
	 */
	struct list_head lru;		/* Pageout list, eg. active_list
					 * protected by zone->lru_lock !
					 */
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	/**
	 * 如果进行了内存映射，就是内核虚拟地址。对存在高端内存的系统来说有意义。
	 * 否则是NULL
	 */
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
};

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
/**
 * 线性区描述符。
 */
struct vm_area_struct {
	/**
	 * 指向线性区所在的内存描述符。
	 */
	struct mm_struct * vm_mm;	/* The address space we belong to. */
	/**
	 * 线性区内的第一个线性地址。
	 */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	/**
	 * 线性区之后的第一个线性地址。
	 */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	/**
	 * 进程链表中的下一个线性区。
	 */
	struct vm_area_struct *vm_next;
	/**
	 * 线性区中页框的访问许可权。
	 */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/**
	 * 线性区的标志。
	 */
	unsigned long vm_flags;		/* Flags, listed below. */
	/**
	 * 用于红黑树的数据。
	 */
	struct rb_node vm_rb;

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap prio tree, or
	 * linkage to the list of like vmas hanging off its node, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	/**
	 * 链接到反映射所使用的数据结构。
	 */
	union {
		/**
		 * 如果在优先搜索树中，存在两个节点的基索引、堆索引、大小索引完全相同，那么这些相同的节点会被链接到一个链表，而vm_set就是这个链表的元素。
		 */
		struct {
			struct list_head list;
			void *parent;	/* aligns with prio_tree_node parent */
			struct vm_area_struct *head;
		} vm_set;
		/**
		 * 如果是文件映射，那么prio_tree_node用于将线性区插入到优先搜索树中。作为搜索树的一个节点。
		 */
		struct raw_prio_tree_node prio_tree_node;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	/**
	 * 指向匿名线性区链表的指针(参见"映射页的反映射")。
	 * 页框结构有一个anon_vma指针，指向该页的第一个线性区，随后的线性区通过此字段链接起来。
	 * 通过此字段，可以将线性区链接到此链表中。
	 */
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	/**
	 * 指向anon_vma数据结构的指针(参见"映射页的反映射")。此指针也存放在页结构的mapping字段中。
	 */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	/**
	 * 指向线性区的方法。
	 */
	struct vm_operations_struct * vm_ops;

	/* Information about our backing store: */
	/**
	 * 在映射文件中的偏移量(以页为单位)。对匿名页，它等于0或vm_start/PAGE_SIZE
	 */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
	/**
	 * 指向映射文件的文件对象(如果有的话)
	 */
	struct file * vm_file;		/* File we map to (can be NULL). */
	/**
	 * 指向内存区的私有数据。
	 */
	void * vm_private_data;		/* was vm_pte (shared mem) */
	/**
	 * 释放非线性文件内存映射中的一个线性地址区间时使用。
	 */
	unsigned long vm_truncate_count;/* truncate_count or restart_addr */

#ifndef CONFIG_MMU
	atomic_t vm_usage;		/* refcount (VMAs shared if !MMU) */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
};
/**
 * 内存描述符。task_struct的mm字段指向它。
 * 它包含了进程地址空间有关的全部信息。
 */
struct mm_struct {
	/**
	 * 指向线性区对象的链表头。
	 */
	struct vm_area_struct * mmap;		/* list of VMAs */
	/**
	 * 指向线性区对象的红-黑树的根
	 */
	struct rb_root mm_rb;
	/**
	 * 指向最后一个引用的线性区对象。
	 */
	struct vm_area_struct * mmap_cache;	/* last find_vma result */
	/**
	 * 在进程地址空间中搜索有效线性地址区的方法。
	 */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
	/**
	 * 释放线性地址区间时调用的方法。
	 */
	void (*unmap_area) (struct mm_struct *mm, unsigned long addr);
	/**
	 * 标识第一个分配的匿名线性区或文件内存映射的线性地址。
	 */
	unsigned long mmap_base;		/* base of mmap area */
	unsigned long task_size;		/* size of task vm space */
	unsigned long cached_hole_size; 	/* if non-zero, the largest hole below free_area_cache */
	/**
	 * 内核从这个地址开始搜索进程地址空间中线性地址的空间区间。
	 */
	unsigned long free_area_cache;		/* first hole of size cached_hole_size or larger */
	//进程页目录
	pgd_t * pgd;
	/**
	 * 次使用计数器。存放共享mm_struct数据结构的轻量级进程的个数。
	 */
	atomic_t mm_users;			/* How many users with user space? */
	/**
	 * 主使用计数器。每当mm_count递减时，内核都要检查它是否变为0,如果是，就要解除这个内存描述符。
	 */
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	/**
	 * 线性区的个数。
	 */
	int map_count;				/* number of VMAs */
	/**
	 * 内存描述符的读写信号量。
	 * 由于描述符可能在几个轻量级进程间共享，通过这个信号量可以避免竞争条件。
	 */
	struct rw_semaphore mmap_sem;
	/**
	 * 线性区和页表的自旋锁。
	 */
	spinlock_t page_table_lock;		/* Protects page tables and some counters */
	/**
	 * 指向内存描述符链表中的相邻元素。
	 */
	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	/**
	 * 进程所拥有的最大页框数。
	 */
	mm_counter_t _file_rss;
	/**
	 * 进程线性区中的最大页数。
	 */
	mm_counter_t _anon_rss;

	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	unsigned long hiwater_vm;	/* High-water virtual memory usage */
	//进程的执行文件镜像
	/**
	 * exec_vm-可执行内存映射的页数。
	 * stack_vm-用户态堆栈中的页数。
	 * reserved_vm-在保留区中的页数或在特殊线性区中的页数。
	 * def_flags-线性区默认的访问标志。
	 * nr_ptes-this进程的页表数。
	 */
	/**
	 * rss-分配给进程的页框总数
	 * anon_rss-分配给匿名内存映射的页框数。s
	 * total_vm-进程地址空间的大小(页框数)
	 * locked_vm-锁住而不能换出的页的个数。
	 * shared_vm-共享文件内存映射中的页数。
	 */
	unsigned long total_vm, locked_vm, shared_vm, exec_vm;
	unsigned long stack_vm, reserved_vm, def_flags, nr_ptes;
	/**
	 * start_code-可执行代码的起始地址。
	 * end_code-可执行代码的最后地址。
	 * start_data-已初始化数据的起始地址。
	 * end_data--已初始化数据的结束地址。
	 */
	unsigned long start_code, end_code, start_data, end_data;
	/**
	 * start_brk-堆的超始地址。
	 * brk-堆的当前最后地址。
	 * start_stack-用户态堆栈的起始地址。
	 */
	unsigned long start_brk, brk, start_stack;
	/**
	 * arg_start-命令行参数的起始地址。
	 * arg_end-命令行参数的结束地址。
	 * env_start-环境变量的起始地址。
	 * env_end-环境变量的结束地址。
	 */
	unsigned long arg_start, arg_end, env_start, env_end;
	/**
	 * 开始执行elf程序时使用。
	 */
	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */
	/**
	 * 懒惰TLB交换的位掩码。
	 */
	cpumask_t cpu_vm_mask;

	/* Architecture-specific MM context */
	/**
	 * 特殊体系结构信息的表。
	 * 如80X86平台上的LDT地址。
	 */
	mm_context_t context;

	/* Swap token stuff */
	/*
	 * Last value of global fault stamp as seen by this process.
	 * In other words, this value gives an indication of how long
	 * it has been since this task got the token.
	 * Look at mm/thrash.c
	 */
	unsigned int faultstamp;
	unsigned int token_priority;
	unsigned int last_interval;

	unsigned long flags; /* Must use atomic bitops to access the bits */

	/* coredumping support */
	/**
	 * 正在把进程地址空间的内容卸载到转储文件中的轻量级进程的数量。
	 */
	int core_waiters;
	/**
	 * core_startup_done-指向创建内存转储文件时的补充原语。
	 * core_done-创建内存转储文件时使用的补充原语。
	 */
	struct completion *core_startup_done, core_done;

	/* aio bits */
	/**
	 * 用于保护异步IO上下文链表的锁。
	 */
	rwlock_t		ioctx_list_lock;
	/**
	 * 异步IO上下文链表。
	 * 一个应用可以创建多个AIO环境，一个给定进程的所有的kioctx描述符存放在一个单向链表中，该链表位于ioctx_list字段
	 */
	struct kioctx		*ioctx_list;
};

#endif /* _LINUX_MM_TYPES_H */
