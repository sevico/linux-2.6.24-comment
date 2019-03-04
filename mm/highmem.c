/*
 * High memory handling common code and variables.
 *
 * (C) 1999 Andrea Arcangeli, SuSE GmbH, andrea@suse.de
 *          Gerhard Wichert, Siemens AG, Gerhard.Wichert@pdb.siemens.de
 *
 *
 * Redesigned the x86 32-bit VM architecture to deal with
 * 64-bit physical space. With current x86 CPUs this
 * means up to 64 Gigabytes physical RAM.
 *
 * Rewrote high memory support to move the page cache into
 * high memory. Implemented permanent (schedulable) kmaps
 * based on Linus' idea.
 *
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <linux/blktrace_api.h>
#include <asm/tlbflush.h>

/*
 * Virtual_count is not a pure "count".
 *  0 means that it is not mapped, and has not been mapped
 *    since a TLB flush - it is usable.
 *  1 means that there are no users, but it has been mapped
 *    since the last TLB flush - so we can't use it.
 *  n means that there are (n-1) current users of it.
 */
#ifdef CONFIG_HIGHMEM

unsigned long totalhigh_pages __read_mostly;

unsigned int nr_free_highpages (void)
{
	pg_data_t *pgdat;
	unsigned int pages = 0;

	for_each_online_pgdat(pgdat) {
		pages += zone_page_state(&pgdat->node_zones[ZONE_HIGHMEM],
			NR_FREE_PAGES);
		if (zone_movable_is_highmem())
			pages += zone_page_state(
					&pgdat->node_zones[ZONE_MOVABLE],
					NR_FREE_PAGES);
	}

	return pages;
}
/**
 * Pkmap_count数组包含LAST_PKMAP个计数器，pkmap_page_table页表中每一项都有一个。
 * 它记录了永久内核映射使用了哪些页表项。
 * 它的值可能为：
 *	0：对应的页表项没有映射任何高端内存页框，并且是可用的。
 *	1：对应页表项没有映射任何高端内存，但是它仍然不可用。因为自从它最后一次使用以来，相应的TLB表还没有被刷新。
 *	>1：相应的页表项映射了一个高端内存页框。并且正好有n-1个内核正在使用这个页框。
 */
static int pkmap_count[LAST_PKMAP];
static unsigned int last_pkmap_nr;
static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(kmap_lock);
/**
 * 用于建立永久内核映射的页表。
 * 这样，内核可以长期映射高端内存到内核地址空间中。
 * 页表中的表项数由LAST_PKMAP宏产生，取决于是否打开PAE，它的值可能是512或者1024，
 * 这样可能映射2MB或4MB的永久内核映射。
 */
pte_t * pkmap_page_table;

static DECLARE_WAIT_QUEUE_HEAD(pkmap_map_wait);

static void flush_all_zero_pkmaps(void)
{
	int i;

	flush_cache_kmaps();

	for (i = 0; i < LAST_PKMAP; i++) {
		struct page *page;

		/*
		 * zero means we don't have anything to do,
		 * >1 means that it is still in use. Only
		 * a count of 1 means that it is free but
		 * needs to be unmapped
		 */
		if (pkmap_count[i] != 1)
			continue;
		pkmap_count[i] = 0;

		/* sanity check */
		BUG_ON(pte_none(pkmap_page_table[i]));

		/*
		 * Don't need an atomic fetch-and-clear op here;
		 * no-one has the page mapped, and cannot get at
		 * its virtual address (and hence PTE) without first
		 * getting the kmap_lock (which is held here).
		 * So no dangers, even with speculative execution.
		 */
		page = pte_page(pkmap_page_table[i]);
		pte_clear(&init_mm, (unsigned long)page_address(page),
			  &pkmap_page_table[i]);

		set_page_address(page, NULL);
	}
	flush_tlb_kernel_range(PKMAP_ADDR(0), PKMAP_ADDR(LAST_PKMAP));
}

/* Flush all unused kmap mappings in order to remove stray
   mappings. */
void kmap_flush_unused(void)
{
	spin_lock(&kmap_lock);
	flush_all_zero_pkmaps();
	spin_unlock(&kmap_lock);
}
/**
 * 为建立永久内核映射建立初始映射.
 */
static inline unsigned long map_new_virtual(struct page *page)
{
	unsigned long vaddr;
	int count;

start:
	count = LAST_PKMAP;
	/* Find an empty entry */
	/**
	 * 扫描pkmap_count中的所有计数器值,直到找到一个空值.
	 */
	for (;;) {
		/**
		 * 从上次结束的地方开始搜索.
		 */
		last_pkmap_nr = (last_pkmap_nr + 1) & LAST_PKMAP_MASK;
		/**
		 * 搜索到最后一位了.在从0开始搜索前,刷新计数为1的项.
		 * 当计数值为1表示页表项可用,但是对应的TLB还没有刷新.
		 */
		if (!last_pkmap_nr) {
			flush_all_zero_pkmaps();
			count = LAST_PKMAP;
		}
		/**
		 * 找到计数为0的页表项,表示该页空闲且可用.
		 */
		if (!pkmap_count[last_pkmap_nr])
			break;	/* Found a usable entry */
		/**
		 * count是允许的搜索次数.如果还允许继续搜索下一个页表项.则继续,否则表示没有空闲项,退出.
		 */
		if (--count)
			continue;

		/*
		 * Sleep for somebody else to unmap their entries
		 */
		/**
		 * 运行到这里,表示没有找到空闲页表项.先睡眠一下.
		 * 等待其他线程释放页表项,然后唤醒本线程.
		 */
		{
			DECLARE_WAITQUEUE(wait, current);

			__set_current_state(TASK_UNINTERRUPTIBLE);
			/**
			 * 将当前线程挂到pkmap_map_wait等待队列上.
			 */
			add_wait_queue(&pkmap_map_wait, &wait);
			spin_unlock(&kmap_lock);
			schedule();
			remove_wait_queue(&pkmap_map_wait, &wait);
			spin_lock(&kmap_lock);

			/* Somebody else might have mapped it while we slept */
			/**
			 * 在当前线程等待的过程中,其他线程可能已经将页面进行了映射.
			 * 检测一下,如果已经映射了,就退出.
			 * 注意,这里没有对kmap_lock进行解锁操作.关于kmap_lock锁的操作,需要结合kmap_high来分析.
			 * 总的原则是:进入本函数时保证关锁,然后在本句前面关锁,本句后面解锁.
			 * 在函数返回后,锁仍然是关的.则外层解锁.
			 * 即使在本函数中循环也是这样.
			 * 内核就是这么乱,看久了就习惯了.不过你目前可能必须得学着适应这种代码.
			 */
			if (page_address(page))
				return (unsigned long)page_address(page);

			/* Re-start */
			goto start;
		}
	}
	/**
	 * 不管何种路径运行到这里来,kmap_lock都是锁着的.
	 * 并且last_pkmap_nr对应的是一个空闲且可用的表项.
	 */
	vaddr = PKMAP_ADDR(last_pkmap_nr);
	/**
	 * 设置页表属性,建立虚拟地址和物理地址之间的映射.
	 */
	set_pte_at(&init_mm, vaddr,
		   &(pkmap_page_table[last_pkmap_nr]), mk_pte(page, kmap_prot));
	/**
	 * 1表示相应的项可用,但是TLB需要刷新.
	 * 但是我们这里明明建立了映射,为什么还是可用的呢,其他地方不会将占用么?
	 * 其实不用担心,因为返回kmap_high后,kmap_high函数会将它再加1.
	 */
	pkmap_count[last_pkmap_nr] = 1;
	set_page_address(page, (void *)vaddr);

	return vaddr;
}
/**
 * 为高端内存建立永久内核映射。
 */
void fastcall *kmap_high(struct page *page)
{
	unsigned long vaddr;

	/*
	 * For highmem pages, we can't trust "virtual" until
	 * after we have the lock.
	 *
	 * We cannot call this from interrupts, as it may block
	 */
	/**
	 * 这个函数不会在中断中调用，也不能在中断中调用。
	 * 所以，在这里只需要获取自旋锁就行了。
	 */
	spin_lock(&kmap_lock);
	/**
	 * page_address有检查页框是否被映射的作用。
	 */
	vaddr = (unsigned long)page_address(page);
	/**
	 * 没有被映射，就调用map_new_virtual把页框的物理地址插入到pkmap_page_table的一个项中。
	 * 并在page_address_htable散列表中加入一个元素。
	 */
	if (!vaddr)
		vaddr = map_new_virtual(page);
	/**
	 * 使页框的线性地址所对应的计数器加1.
	 */
	pkmap_count[PKMAP_NR(vaddr)]++;
	/**
	 * 初次映射时,map_new_virtual中会将计数置为1,上一句再加1.
	 * 多次映射时,计数值会再加1.
	 * 总之,计数值决不会小于2.
	 */
	BUG_ON(pkmap_count[PKMAP_NR(vaddr)] < 2);
	/**
	 * 释放自旋锁.
	 */
	spin_unlock(&kmap_lock);
	return (void*) vaddr;
}

EXPORT_SYMBOL(kmap_high);
/**
 * 解除高端内存的永久内核映射
 */
void fastcall kunmap_high(struct page *page)
{
	unsigned long vaddr;
	unsigned long nr;
	int need_wakeup;

	spin_lock(&kmap_lock);
	/**
	 * 得到物理页对应的虚拟地址。
	 */
	vaddr = (unsigned long)page_address(page);
	/**
	 * vaddr会==0，可能是内存越界等严重故障了吧。
	 * BUG一下
	 */
	BUG_ON(!vaddr);
	/**
	 * 根据虚拟地址，找到页表项在pkmap_count中的序号。
	 */
	nr = PKMAP_NR(vaddr);

	/*
	 * A count must never go down to zero
	 * without a TLB flush!
	 */
	need_wakeup = 0;
	switch (--pkmap_count[nr]) {
	case 0:
		BUG();/* 一定是逻辑错误了，多次调用了unmap */
	case 1:
		/*
		 * Avoid an unnecessary wake_up() function call.
		 * The common case is pkmap_count[] == 1, but
		 * no waiters.
		 * The tasks queued in the wait-queue are guarded
		 * by both the lock in the wait-queue-head and by
		 * the kmap_lock.  As the kmap_lock is held here,
		 * no need for the wait-queue-head's lock.  Simply
		 * test if the queue is empty.
		 */
	/**
		 * 页表项可用了。need_wakeup会唤醒等待队列上阻塞的线程。
		 */
		need_wakeup = waitqueue_active(&pkmap_map_wait);
	}
	spin_unlock(&kmap_lock);

	/* do wake-up, if needed, race-free outside of the spin lock */
	/**
	 * 有等待线程，唤醒它。
	 */
	if (need_wakeup)
		wake_up(&pkmap_map_wait);
}

EXPORT_SYMBOL(kunmap_high);
#endif

#if defined(HASHED_PAGE_VIRTUAL)

#define PA_HASH_ORDER	7

/*
 * Describes one page->virtual association
 */
struct page_address_map {
	struct page *page;
	void *virtual;
	struct list_head list;
};

/*
 * page_address_map freelist, allocated from page_address_maps.
 */
static struct list_head page_address_pool;	/* freelist */
static spinlock_t pool_lock;			/* protects page_address_pool */

/*
 * Hash table bucket
 */
/**
 * 本散列表记录了高端内存页框与永久内核映射映射包含的线性地址。
 */
static struct page_address_slot {
	//典型的list_head嵌入链表结构。实际上每个节点是page_address_map
	struct list_head lh;			/* List of page_address_maps */
	spinlock_t lock;			/* Protect this bucket's list */
} ____cacheline_aligned_in_smp page_address_htable[1<<PA_HASH_ORDER];

static struct page_address_slot *page_slot(struct page *page)
{
	return &page_address_htable[hash_ptr(page, PA_HASH_ORDER)];
}
/**
 * page_address返回页框对应的线性地址。
 */
void *page_address(struct page *page)
{
	unsigned long flags;
	void *ret;
	struct page_address_slot *pas;
	/**
	 * 如果页框不在高端内存中(PG_highmem标志为0)，则线性地址总是存在的。
	 * 并且通过计算页框下标，然后将其转换成物理地址，最后根据物理地址得到线性地址。
	 */
	if (!PageHighMem(page))
		/**
		 * 本句等价于__va((unsigned long)(page - mem_map) << 12)
		 */
		return lowmem_page_address(page);
	/**
	 * 否则页框在高端内存中(PG_highmem标志为1)，则到page_address_htable散列表中查找。
	 */
	pas = page_slot(page);
	ret = NULL;
	spin_lock_irqsave(&pas->lock, flags);
	if (!list_empty(&pas->lh)) {
		struct page_address_map *pam;

		list_for_each_entry(pam, &pas->lh, list) {
			/**
			 * 在page_address_htable中找到，返回对应的物理地址。
			 */
			if (pam->page == page) {
				ret = pam->virtual;
				goto done;
			}
		}
	}
done:
/**
	 * 没有在page_address_htable中找到，返回默认值NULL。
	 */
	spin_unlock_irqrestore(&pas->lock, flags);
	return ret;
}

EXPORT_SYMBOL(page_address);

void set_page_address(struct page *page, void *virtual)
{
	unsigned long flags;
	struct page_address_slot *pas;
	struct page_address_map *pam;

	BUG_ON(!PageHighMem(page));

	pas = page_slot(page);
	if (virtual) {		/* Add */
		BUG_ON(list_empty(&page_address_pool));

		spin_lock_irqsave(&pool_lock, flags);
		pam = list_entry(page_address_pool.next,
				struct page_address_map, list);
		list_del(&pam->list);
		spin_unlock_irqrestore(&pool_lock, flags);

		pam->page = page;
		pam->virtual = virtual;

		spin_lock_irqsave(&pas->lock, flags);
		list_add_tail(&pam->list, &pas->lh);
		spin_unlock_irqrestore(&pas->lock, flags);
	} else {		/* Remove */
		spin_lock_irqsave(&pas->lock, flags);
		list_for_each_entry(pam, &pas->lh, list) {
			if (pam->page == page) {
				list_del(&pam->list);
				spin_unlock_irqrestore(&pas->lock, flags);
				spin_lock_irqsave(&pool_lock, flags);
				list_add_tail(&pam->list, &page_address_pool);
				spin_unlock_irqrestore(&pool_lock, flags);
				goto done;
			}
		}
		spin_unlock_irqrestore(&pas->lock, flags);
	}
done:
	return;
}

static struct page_address_map page_address_maps[LAST_PKMAP];

void __init page_address_init(void)
{
	int i;

	INIT_LIST_HEAD(&page_address_pool);
	for (i = 0; i < ARRAY_SIZE(page_address_maps); i++)
		list_add(&page_address_maps[i].list, &page_address_pool);
	for (i = 0; i < ARRAY_SIZE(page_address_htable); i++) {
		INIT_LIST_HEAD(&page_address_htable[i].lh);
		spin_lock_init(&page_address_htable[i].lock);
	}
	spin_lock_init(&pool_lock);
}

#endif	/* defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL) */
