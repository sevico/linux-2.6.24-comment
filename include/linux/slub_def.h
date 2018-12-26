#ifndef _LINUX_SLUB_DEF_H
#define _LINUX_SLUB_DEF_H

/*
 * SLUB : A Slab allocator without object queues.
 *
 * (C) 2007 SGI, Christoph Lameter <clameter@sgi.com>
 */
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/workqueue.h>
#include <linux/kobject.h>

struct kmem_cache_cpu {
//空闲对象队列的指针，即第一个空闲对象的指针
	void **freelist;
//	slab的第一个物理页框描述符，保存slab的元数据
	struct page *page;
//处理器所在NUMA节点号
	int node;
//在空闲对象中，存放下一个空闲对象指针的偏移	
	unsigned int offset;
//对象实际大小，与kmem_cache结构objsize字段一致
	unsigned int objsize;
};

struct kmem_cache_node {
	//保护本数据结构的自旋锁	
	spinlock_t list_lock;	/* Protect partial list and nr_partial */
	//本节点半满slab的数目
	unsigned long nr_partial;
	//	本节点slab的总数
	atomic_long_t nr_slabs;
	//半满slab 的链表头
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	struct list_head full;
#endif
};

/*
 * Slab cache management.
 */
struct kmem_cache {
	/* Used for retriving partial slabs etc */
	//描述缓冲区属性的一组标志
	unsigned long flags;
	//分配给对象的内存大小，包含对象元数据，例如空闲链表指针，因此可能大于对象的实际大小
	int size;		/* The size of an object including meta data */
	//对象的实际大小，不包含对象元数据
	int objsize;		/* The size of an object without meta data */
	//空闲对象指针在对象中的偏移值
	int offset;		/* Free pointer offset. */
	//表示一个slab需要2^order个物理页框，用于伙伴系统	
	int order;

	/*
	 * Avoid an extra cache line for UP, SMP and for the node local to
	 * struct kmem_cache.
	 */
	 //	创建缓冲区的NUMA节点，其中包括后备半满缓冲池
	struct kmem_cache_node local_node;

	/* Allocation and freeing of slabs */
	//一个slab中的对象总个数	
	int objects;		/* Number of objects in slab */
	//引用计数计数器。当新创建的缓冲区可以与已有缓冲区合并时，增加原有缓冲区引用计数。
	int refcount;		/* Refcount for slab cache destroy */
	//创建slab时，用于初始化每个对象的构造函数
	void (*ctor)(struct kmem_cache *, void *);
	//对象元数据在对象中的偏移	
	int inuse;		/* Offset to metadata */
	//对齐要求
	int align;		/* Alignment */
	//缓冲区名字
	const char *name;	/* Name (only for display!) */
	//包含所有缓冲区描述结构的双向循环队列，队列头为 slab_caches
	struct list_head list;	/* List of slab caches */
#ifdef CONFIG_SLUB_DEBUG
	struct kobject kobj;	/* For sysfs */
#endif

#ifdef CONFIG_NUMA
	//防磁片的调节值，该值越小，越倾向于从本节点中分配对象	
	int defrag_ratio;
//所有可用的NUMA节点，这些节点中的后备半满slab均可以用于本缓冲区内存分配
	struct kmem_cache_node *node[MAX_NUMNODES];
#endif
#ifdef CONFIG_SMP
//为每个处理器创建的缓存slab数据结构，以加快每个CPU上的分配速度，降低锁竞争
	struct kmem_cache_cpu *cpu_slab[NR_CPUS];
#else
	struct kmem_cache_cpu cpu_slab;
#endif
};

/*
 * Kmalloc subsystem.
 */
#if defined(ARCH_KMALLOC_MINALIGN) && ARCH_KMALLOC_MINALIGN > 8
#define KMALLOC_MIN_SIZE ARCH_KMALLOC_MINALIGN
#else
#define KMALLOC_MIN_SIZE 8
#endif

#define KMALLOC_SHIFT_LOW ilog2(KMALLOC_MIN_SIZE)

/*
 * We keep the general caches in an array of slab caches that are used for
 * 2^x bytes of allocations.
 */
extern struct kmem_cache kmalloc_caches[PAGE_SHIFT];

/*
 * Sorry that the following has to be that ugly but some versions of GCC
 * have trouble with constant propagation and loops.
 */
static __always_inline int kmalloc_index(size_t size)
{
	if (!size)
		return 0;

	if (size <= KMALLOC_MIN_SIZE)
		return KMALLOC_SHIFT_LOW;

	if (size > 64 && size <= 96)
		return 1;
	if (size > 128 && size <= 192)
		return 2;
	if (size <=          8) return 3;
	if (size <=         16) return 4;
	if (size <=         32) return 5;
	if (size <=         64) return 6;
	if (size <=        128) return 7;
	if (size <=        256) return 8;
	if (size <=        512) return 9;
	if (size <=       1024) return 10;
	if (size <=   2 * 1024) return 11;
/*
 * The following is only needed to support architectures with a larger page
 * size than 4k.
 */
	if (size <=   4 * 1024) return 12;
	if (size <=   8 * 1024) return 13;
	if (size <=  16 * 1024) return 14;
	if (size <=  32 * 1024) return 15;
	if (size <=  64 * 1024) return 16;
	if (size <= 128 * 1024) return 17;
	if (size <= 256 * 1024) return 18;
	if (size <= 512 * 1024) return 19;
	if (size <= 1024 * 1024) return 20;
	if (size <=  2 * 1024 * 1024) return 21;
	return -1;

/*
 * What we really wanted to do and cannot do because of compiler issues is:
 *	int i;
 *	for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++)
 *		if (size <= (1 << i))
 *			return i;
 */
}

/*
 * Find the slab cache for a given combination of allocation flags and size.
 *
 * This ought to end up with a global pointer to the right cache
 * in kmalloc_caches.
 */
static __always_inline struct kmem_cache *kmalloc_slab(size_t size)
{
	int index = kmalloc_index(size);

	if (index == 0)
		return NULL;

	return &kmalloc_caches[index];
}

#ifdef CONFIG_ZONE_DMA
#define SLUB_DMA __GFP_DMA
#else
/* Disable DMA functionality */
#define SLUB_DMA (__force gfp_t)0
#endif

void *kmem_cache_alloc(struct kmem_cache *, gfp_t);
void *__kmalloc(size_t size, gfp_t flags);

static __always_inline void *kmalloc(size_t size, gfp_t flags)
{
	if (__builtin_constant_p(size)) {
		if (size > PAGE_SIZE / 2)
			return (void *)__get_free_pages(flags | __GFP_COMP,
							get_order(size));

		if (!(flags & SLUB_DMA)) {
			struct kmem_cache *s = kmalloc_slab(size);

			if (!s)
				return ZERO_SIZE_PTR;

			return kmem_cache_alloc(s, flags);
		}
	}
	return __kmalloc(size, flags);
}

#ifdef CONFIG_NUMA
void *__kmalloc_node(size_t size, gfp_t flags, int node);
void *kmem_cache_alloc_node(struct kmem_cache *, gfp_t flags, int node);

static __always_inline void *kmalloc_node(size_t size, gfp_t flags, int node)
{
	if (__builtin_constant_p(size) &&
		size <= PAGE_SIZE / 2 && !(flags & SLUB_DMA)) {
			struct kmem_cache *s = kmalloc_slab(size);

		if (!s)
			return ZERO_SIZE_PTR;

		return kmem_cache_alloc_node(s, flags, node);
	}
	return __kmalloc_node(size, flags, node);
}
#endif

#endif /* _LINUX_SLUB_DEF_H */
