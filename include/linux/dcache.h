#ifndef __LINUX_DCACHE_H
#define __LINUX_DCACHE_H

#ifdef __KERNEL__

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>

struct nameidata;
struct vfsmount;

/*
 * linux/include/linux/dcache.h
 *
 * Dirent cache data structures
 *
 * (C) Copyright 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

#define IS_ROOT(x) ((x) == (x)->d_parent)

/*
 * "quick string" -- eases parameter passing, but more importantly
 * saves "metadata" about the string (ie length and the hash).
 *
 * hash comes first so it snuggles against d_parent in the
 * dentry.
 */
struct qstr {
	unsigned int hash;
	unsigned int len;
	const unsigned char *name;
};

struct dentry_stat_t {
	int nr_dentry;
	int nr_unused;
	int age_limit;          /* age in seconds */
	int want_pages;         /* pages requested by system */
	int dummy[2];
};
extern struct dentry_stat_t dentry_stat;

/* Name hashing routines. Initial hash value */
/* Hash courtesy of the R5 hash in reiserfs modulo sign bits */
#define init_name_hash()		0

/* partial hash update function. Assume roughly 4 bits per character */
static inline unsigned long
partial_name_hash(unsigned long c, unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/*
 * Finally: cut down the number of bits to a int value (and try to avoid
 * losing bits)
 */
static inline unsigned long end_name_hash(unsigned long hash)
{
	return (unsigned int) hash;
}

/* Compute the hash for a name string. */
static inline unsigned int
full_name_hash(const unsigned char *name, unsigned int len)
{
	unsigned long hash = init_name_hash();
	while (len--)
		hash = partial_name_hash(*name++, hash);
	return end_name_hash(hash);
}

struct dcookie_struct;

#define DNAME_INLINE_LEN_MIN 36

struct dentry {
	/* 目录项对象引用计数器 */
	atomic_t d_count;
	/* 目录项高速缓存标志:空闲状态，未使用状态，正在使用状态，负状态(如孤儿节点) 
	目录项对应的目录项缓存标志，可以取DCACHE_UNSHARED、DCACHE_REFERENCED等，在include/linux/dcache.h文件中定义
	*/
	unsigned int d_flags;		/* protected by d_lock */
	/* 保护目录项对象的自旋锁 */
	spinlock_t d_lock;		/* per dentry lock */
	/* 与文件名关联的索引节点*/
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	/*
	 * The next three fields are touched by __d_lookup.  Place them here
	 * so they all fit in a cache line.
	 */
	 /* 指向散列表表项链表的指针
	 因为内核中的dentry有很多，所以使用了dentry_hashtable(定义在文件
fs/dcache.c)对其进行管理,dentry_hashtable是由list_head组成的链表
一个dentry一经创建，就会通过它的d_hash挂入dentry_hashtable中对应
哈希值的链表里
	 */
	struct hlist_node d_hash;	/* lookup hash list */
	/* 父目录的目录项对象 */
	struct dentry *d_parent;	/* parent directory */
	/* 文件名 */
	struct qstr d_name;
	/* 用于未使用目录项链表的指针	
	最近未使用的目录项的链表，LRU即为Least Recently Used的缩写
	*/
	struct list_head d_lru;		/* LRU list */
	/*
	 * d_child and d_rcu can share memory	 
	 旧版本中，struct dentry的大小为128字节，为cache line的整数倍，但是RCU
	 机制应用后，即d_rcu字段增加之后，dentry结构的大小变成了136字节
	 (128+8,struct rcu_head中只包含两个指针，大小为8字节），这就影响了
	 目录项的存取效率。所以从2.6.15内核开始，使用union组织d_child和d_rcu,
	 使它们两个共享内存，将dentry结构的大小恢复到128字节。d_rcu只在d_free
	 中有用到，当dfree()被调用的时候，d_child为空且不会再被用到，所以可以使
	 它们两个共用内存
	 */
	union {
	 /* 对目录而言，用于同一父目录中的目录项链表的指针	 
	 对于目录而言，它通过d_child加入到父日录的d_subdirs链表中
	 */
		struct list_head d_child;	/* child of parent list */
	 /* 回收目录项对象时，由RCU描述符使用 */
	 	struct rcu_head d_rcu;
	} d_u;
	/* 对目录而言，d_subdirs是它的子目录dentry链表的头 */
	struct list_head d_subdirs;	/* our children */
	 /* 用于与同一索引节点（别名）相关的目录项链表的指针
	 一个有效的dentry，必然与一个inode相关联，可是，一个inode却可能对应着
多个dentry，这是因为一个文件可以被链接（link）到其他文件。所以，在inode中
有个链表i_dentry，与该inode相关联的所有目录项都通过其dentry结构中的
d_alias字段挂入该inode的i_dentry链表中
	 */
	struct list_head d_alias;	/* inode alias list */
	  /* 由d_revalidate方法使用
	  重新变为有效的时间。比如对于NFS，如果一个操作成功，就说明相关dentry是
	  有效的，就需要更新它的dtime
	  */
	unsigned long d_time;		/* used by d_revalidate */
	  /* 目录项方法
	  目录项函数集, 主要包含对子dentry的查询操作. 由文件系统类型确定
	  */
	struct dentry_operations *d_op;
	   /* 文件的超级块对象 */
	struct super_block *d_sb;	/* The root of the dentry tree */
	   /* 依赖于文件系统的数据 在sysfs中指向sysfs_dirent*/
	void *d_fsdata;			/* fs-specific data */
#ifdef CONFIG_PROFILING
	struct dcookie_struct *d_cookie; /* cookie, if any 指向内核配置文件使用的数据结构的指针*/
#endif
	int d_mounted;/* 对目录而言，用于记录安装该目录项的文件系统数的计数器 */
	/* 存放短文件名的空间	
	存放短的文件名，如果文件名长度超过DNAME_INLINE_LEN_MIN-1则使用
	kmalloc为文件名分配存储空间
	*/
	unsigned char d_iname[DNAME_INLINE_LEN_MIN];	/* small names */
};

/*
 * dentry->d_lock spinlock nesting subclasses:
 *
 * 0: normal
 * 1: nested
 */
enum dentry_d_lock_class
{
	DENTRY_D_LOCK_NORMAL, /* implicitly used by plain spin_lock() APIs. */
	DENTRY_D_LOCK_NESTED
};

struct dentry_operations {
	/* 在把目录项对象转换为一个文件路径名之前，判定该目录项对象是否仍然有效。
	  * 缺省的VFS函数什么也不做，而网络文件系统可以指定自己的函数。	
	用于判断dentry是否有效，当VFS从dcache中使用一个dentry时被调用
	如果一个文件系统相信dcache中的所有dentry总是有效的，它可以不提供这个
	函数。返回值为0表示dentry无效，大于0,意味着dentry有效
	*/
	int (*d_revalidate)(struct dentry *, struct nameidata *);
	 /* 生成一个散列值；这是用于目录项散列表的、特定干具体文件系统的散列函数。
	  * 参数dentry标识包含路径分量的目录。参数name指向一个结构，
	  * 该结构包含要查找的路径名分量以及由散列函数生成的散列值。
	为dentry生成hash值，当VFS添加dentry到hash表时被调用
	*/
	int (*d_hash) (struct dentry *, struct qstr *);
	/* 比较两个文件名。name1应该属于dir所指的目录。
  * 缺省的VFS函数是常用的字符串匹配函数。
  * 不过，每个文件系统可用自己的方式实现这一方法。
  * 例如，MS.DOS文件系统不区分大写和小写字母。 */
	int (*d_compare) (struct dentry *, struct qstr *, struct qstr *);
	/* 当对目录项对象的最后一个引用被删除（d_count变为“0”）时，
  * 调用该方法。缺省的VFS函数什么也不做。
	此时在dcache中dentry仍然是有效的
*/
	int (*d_delete)(struct dentry *);
	 /* 当要释放一个目录项对象时（放入slab分配器），调用该方法。
  * 缺省的VFS函数什么也不做。 */
	void (*d_release)(struct dentry *);
	/* 当一个目录项对象变为“负”状态（即丢弃它的索引节点）时，调用该方法。
  * 缺省的VFS函数调用iput()释放索引节点对象。 */
	void (*d_iput)(struct dentry *, struct inode *);
	//需要生成dentry的路径名（pathname）时被调用
	char *(*d_dname)(struct dentry *, char *, int);
};

/* the dentry parameter passed to d_hash and d_compare is the parent
 * directory of the entries to be compared. It is used in case these
 * functions need any directory specific information for determining
 * equivalency classes.  Using the dentry itself might not work, as it
 * might be a negative dentry which has no information associated with
 * it */

/*
locking rules:
		big lock	dcache_lock	d_lock   may block
d_revalidate:	no		no		no       yes
d_hash		no		no		no       yes
d_compare:	no		yes		yes      no
d_delete:	no		yes		no       no
d_release:	no		no		no       yes
d_iput:		no		no		no       yes
 */

/* d_flags entries */
#define DCACHE_AUTOFS_PENDING 0x0001    /* autofs: "under construction" */
#define DCACHE_NFSFS_RENAMED  0x0002    /* this dentry has been "silly
					 * renamed" and has to be
					 * deleted on the last dput()
					 */
#define	DCACHE_DISCONNECTED 0x0004
     /* This dentry is possibly not currently connected to the dcache tree,
      * in which case its parent will either be itself, or will have this
      * flag as well.  nfsd will not use a dentry with this bit set, but will
      * first endeavour to clear the bit either by discovering that it is
      * connected, or by performing lookup operations.   Any filesystem which
      * supports nfsd_operations MUST have a lookup function which, if it finds
      * a directory inode with a DCACHE_DISCONNECTED dentry, will d_move
      * that dentry into place and return that dentry rather than the passed one,
      * typically using d_splice_alias.
      */

#define DCACHE_REFERENCED	0x0008  /* Recently used, don't discard. */
#define DCACHE_UNHASHED		0x0010	

#define DCACHE_INOTIFY_PARENT_WATCHED	0x0020 /* Parent inode is watched */

extern spinlock_t dcache_lock;
extern seqlock_t rename_lock;

/**
 * d_drop - drop a dentry
 * @dentry: dentry to drop
 *
 * d_drop() unhashes the entry from the parent dentry hashes, so that it won't
 * be found through a VFS lookup any more. Note that this is different from
 * deleting the dentry - d_delete will try to mark the dentry negative if
 * possible, giving a successful _negative_ lookup, while d_drop will
 * just make the cache lookup fail.
 *
 * d_drop() is used mainly for stuff that wants to invalidate a dentry for some
 * reason (NFS timeouts or autofs deletes).
 *
 * __d_drop requires dentry->d_lock.
 */

static inline void __d_drop(struct dentry *dentry)
{
	if (!(dentry->d_flags & DCACHE_UNHASHED)) {
		dentry->d_flags |= DCACHE_UNHASHED;
		hlist_del_rcu(&dentry->d_hash);
	}
}

static inline void d_drop(struct dentry *dentry)
{
	spin_lock(&dcache_lock);
	spin_lock(&dentry->d_lock);
 	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
}

static inline int dname_external(struct dentry *dentry)
{
	return dentry->d_name.name != dentry->d_iname;
}

/*
 * These are the low-level FS interfaces to the dcache..
 */
extern void d_instantiate(struct dentry *, struct inode *);
extern struct dentry * d_instantiate_unique(struct dentry *, struct inode *);
extern struct dentry * d_materialise_unique(struct dentry *, struct inode *);
extern void d_delete(struct dentry *);

/* allocate/de-allocate */
extern struct dentry * d_alloc(struct dentry *, const struct qstr *);
extern struct dentry * d_alloc_anon(struct inode *);
extern struct dentry * d_splice_alias(struct inode *, struct dentry *);
extern void shrink_dcache_sb(struct super_block *);
extern void shrink_dcache_parent(struct dentry *);
extern void shrink_dcache_for_umount(struct super_block *);
extern int d_invalidate(struct dentry *);

/* only used at mount-time */
extern struct dentry * d_alloc_root(struct inode *);

/* <clickety>-<click> the ramfs-type tree */
extern void d_genocide(struct dentry *);

extern struct dentry *d_find_alias(struct inode *);
extern void d_prune_aliases(struct inode *);

/* test whether we have any submounts in a subdir tree */
extern int have_submounts(struct dentry *);

/*
 * This adds the entry to the hash queues.
 */
extern void d_rehash(struct dentry *);

/**
 * d_add - add dentry to hash queues
 * @entry: dentry to add
 * @inode: The inode to attach to this dentry
 *
 * This adds the entry to the hash queues and initializes @inode.
 * The entry was actually filled in earlier during d_alloc().
 */
 
static inline void d_add(struct dentry *entry, struct inode *inode)
{
	d_instantiate(entry, inode);
	d_rehash(entry);
}

/**
 * d_add_unique - add dentry to hash queues without aliasing
 * @entry: dentry to add
 * @inode: The inode to attach to this dentry
 *
 * This adds the entry to the hash queues and initializes @inode.
 * The entry was actually filled in earlier during d_alloc().
 */
static inline struct dentry *d_add_unique(struct dentry *entry, struct inode *inode)
{
	struct dentry *res;

	res = d_instantiate_unique(entry, inode);
	d_rehash(res != NULL ? res : entry);
	return res;
}

/* used for rename() and baskets */
extern void d_move(struct dentry *, struct dentry *);

/* appendix may either be NULL or be used for transname suffixes */
extern struct dentry * d_lookup(struct dentry *, struct qstr *);
extern struct dentry * __d_lookup(struct dentry *, struct qstr *);
extern struct dentry * d_hash_and_lookup(struct dentry *, struct qstr *);

/* validate "insecure" dentry pointer */
extern int d_validate(struct dentry *, struct dentry *);

/*
 * helper function for dentry_operations.d_dname() members
 */
extern char *dynamic_dname(struct dentry *, char *, int, const char *, ...);

extern char * d_path(struct dentry *, struct vfsmount *, char *, int);
  
/* Allocation counts.. */

/**
 *	dget, dget_locked	-	get a reference to a dentry
 *	@dentry: dentry to get a reference to
 *
 *	Given a dentry or %NULL pointer increment the reference count
 *	if appropriate and return the dentry. A dentry will not be 
 *	destroyed when it has references. dget() should never be
 *	called for dentries with zero reference counter. For these cases
 *	(preferably none, functions in dcache.c are sufficient for normal
 *	needs and they take necessary precautions) you should hold dcache_lock
 *	and call dget_locked() instead of dget().
 */
 
static inline struct dentry *dget(struct dentry *dentry)
{
	if (dentry) {
		//这里可知，对于dentry引用计数为0的dentry决不能使用
		//dget，而应使用dget_locked。因为：引用一个d_count＝0的dentry对象，将使该dentry对象从unused状态
		//转变为inuse状态，该dentry状态也必须从LRU链表中脱离，而在操作dcache链表时是必须先持有自旋锁
		//dcache_lock的。函数dget()并不对调用者由任何调用假设，相反，dget_locked()函数则假定调用者在调
		//用它之前已经持有自旋锁dentry_lock。
		BUG_ON(!atomic_read(&dentry->d_count));
		atomic_inc(&dentry->d_count);
	}
	return dentry;
}

extern struct dentry * dget_locked(struct dentry *);

/**
 *	d_unhashed -	is dentry hashed
 *	@dentry: entry to check
 *
 *	Returns true if the dentry passed is not currently hashed.
 */
 
static inline int d_unhashed(struct dentry *dentry)
{
	return (dentry->d_flags & DCACHE_UNHASHED);
}

static inline struct dentry *dget_parent(struct dentry *dentry)
{
	struct dentry *ret;

	spin_lock(&dentry->d_lock);
	ret = dget(dentry->d_parent);
	spin_unlock(&dentry->d_lock);
	return ret;
}

extern void dput(struct dentry *);

static inline int d_mountpoint(struct dentry *dentry)
{
	return dentry->d_mounted;
}

extern struct vfsmount *lookup_mnt(struct vfsmount *, struct dentry *);
extern struct vfsmount *__lookup_mnt(struct vfsmount *, struct dentry *, int);
extern struct dentry *lookup_create(struct nameidata *nd, int is_dir);

extern int sysctl_vfs_cache_pressure;

#endif /* __KERNEL__ */

#endif	/* __LINUX_DCACHE_H */
