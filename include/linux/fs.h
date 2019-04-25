#ifndef _LINUX_FS_H
#define _LINUX_FS_H

/*
 * This file has definitions for some important file table
 * structures etc.
 */

#include <linux/limits.h>
#include <linux/ioctl.h>

/*
 * It's silly to have NR_OPEN bigger than NR_FILE, but you can change
 * the file limit at runtime and only root can increase the per-process
 * nr_file rlimit, so it's safe to set up a ridiculously high absolute
 * upper limit on files-per-process.
 *
 * Some programs (notably those using select()) may have to be 
 * recompiled to take full advantage of the new limits..  
 */

/* Fixed constants first: */
#undef NR_OPEN
#define NR_OPEN (1024*1024)	/* Absolute upper limit on fd num */
#define INR_OPEN 1024		/* Initial setting for nfile rlimits */

#define BLOCK_SIZE_BITS 10
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)

#define SEEK_SET	0	/* seek relative to beginning of file */
#define SEEK_CUR	1	/* seek relative to current file position */
#define SEEK_END	2	/* seek relative to end of file */
#define SEEK_MAX	SEEK_END

/* And dynamically-tunable limits and defaults: */
struct files_stat_struct {
	int nr_files;		/* read only */
	int nr_free_files;	/* read only */
	int max_files;		/* tunable */
};
extern struct files_stat_struct files_stat;
extern int get_max_files(void);

struct inodes_stat_t {
	int nr_inodes;
	int nr_unused;
	int dummy[5];		/* padding for sysctl ABI compatibility */
};
extern struct inodes_stat_t inodes_stat;

extern int leases_enable, lease_break_time;

#ifdef CONFIG_DNOTIFY
extern int dir_notify_enable;
#endif

#define NR_FILE  8192	/* this can well be larger on a larger system */

#define MAY_EXEC 1
#define MAY_WRITE 2
#define MAY_READ 4
#define MAY_APPEND 8

#define FMODE_READ 1
#define FMODE_WRITE 2

/* Internal kernel extensions */
#define FMODE_LSEEK	4
#define FMODE_PREAD	8
#define FMODE_PWRITE	FMODE_PREAD	/* These go hand in hand */

/* File is being opened for execution. Primary users of this flag are
   distributed filesystems that can use it to achieve correct ETXTBUSY
   behavior for cross-node execution/opening_for_writing of files */
#define FMODE_EXEC	16

#define RW_MASK		1
#define RWA_MASK	2
#define READ 0
#define WRITE 1
#define READA 2		/* read-ahead  - don't block if no resources */
#define SWRITE 3	/* for ll_rw_block() - wait for buffer lock */
#define READ_SYNC	(READ | (1 << BIO_RW_SYNC))
#define READ_META	(READ | (1 << BIO_RW_META))
#define WRITE_SYNC	(WRITE | (1 << BIO_RW_SYNC))
#define WRITE_BARRIER	((1 << BIO_RW) | (1 << BIO_RW_BARRIER))

#define SEL_IN		1
#define SEL_OUT		2
#define SEL_EX		4

/* public flags for file_system_type */
#define FS_REQUIRES_DEV 1 
#define FS_BINARY_MOUNTDATA 2
#define FS_HAS_SUBTYPE 4
#define FS_REVAL_DOT	16384	/* Check the paths ".", ".." for staleness */
#define FS_RENAME_DOES_D_MOVE	32768	/* FS will handle d_move()
					 * during rename() internally.
					 */

/*
 * These are the fs-independent mount-flags: up to 32 flags are supported
 */
#define MS_RDONLY	 1	/* Mount read-only */
#define MS_NOSUID	 2	/* Ignore suid and sgid bits */
#define MS_NODEV	 4	/* Disallow access to device special files */
#define MS_NOEXEC	 8	/* Disallow program execution */
#define MS_SYNCHRONOUS	16	/* Writes are synced at once */
#define MS_REMOUNT	32	/* Alter flags of a mounted FS */
#define MS_MANDLOCK	64	/* Allow mandatory locks on an FS */
#define MS_DIRSYNC	128	/* Directory modifications are synchronous */
#define MS_NOATIME	1024	/* Do not update access times. */
#define MS_NODIRATIME	2048	/* Do not update directory access times */
#define MS_BIND		4096
#define MS_MOVE		8192
#define MS_REC		16384
#define MS_VERBOSE	32768	/* War is peace. Verbosity is silence.
				   MS_VERBOSE is deprecated. */
#define MS_SILENT	32768
#define MS_POSIXACL	(1<<16)	/* VFS does not apply the umask */
#define MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define MS_PRIVATE	(1<<18)	/* change to private */
#define MS_SLAVE	(1<<19)	/* change to slave */
#define MS_SHARED	(1<<20)	/* change to shared */
#define MS_RELATIME	(1<<21)	/* Update atime relative to mtime/ctime. */
#define MS_KERNMOUNT	(1<<22) /* this is a kern_mount call */
#define MS_ACTIVE	(1<<30)
#define MS_NOUSER	(1<<31)

/*
 * Superblock flags that can be altered by MS_REMOUNT
 */
#define MS_RMT_MASK	(MS_RDONLY|MS_SYNCHRONOUS|MS_MANDLOCK)

/*
 * Old magic mount flag and mask
 */
#define MS_MGC_VAL 0xC0ED0000
#define MS_MGC_MSK 0xffff0000

/* Inode flags - they have nothing to superblock flags now */

#define S_SYNC		1	/* Writes are synced at once */
#define S_NOATIME	2	/* Do not update access times */
#define S_APPEND	4	/* Append-only file */
#define S_IMMUTABLE	8	/* Immutable file */
#define S_DEAD		16	/* removed, but still open directory */
#define S_NOQUOTA	32	/* Inode is not counted to quota */
#define S_DIRSYNC	64	/* Directory modifications are synchronous */
#define S_NOCMTIME	128	/* Do not update file c/mtime */
#define S_SWAPFILE	256	/* Do not truncate: swapon got its bmaps */
#define S_PRIVATE	512	/* Inode is fs-internal */

/*
 * Note that nosuid etc flags are inode-specific: setting some file-system
 * flags just means all the inodes inherit those flags by default. It might be
 * possible to override it selectively if you really wanted to with some
 * ioctl() that is not currently implemented.
 *
 * Exception: MS_RDONLY is always applied to the entire file system.
 *
 * Unfortunately, it is possible to change a filesystems flags with it mounted
 * with files in use.  This means that all of the inodes will not have their
 * i_flags updated.  Hence, i_flags no longer inherit the superblock mount
 * flags, so these have to be checked separately. -- rmk@arm.uk.linux.org
 */
#define __IS_FLG(inode,flg) ((inode)->i_sb->s_flags & (flg))

#define IS_RDONLY(inode) ((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SYNC(inode)		(__IS_FLG(inode, MS_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, MS_SYNCHRONOUS|MS_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_MANDLOCK(inode)	__IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode)   __IS_FLG(inode, MS_RDONLY|MS_NOATIME)

#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_POSIXACL(inode)	__IS_FLG(inode, MS_POSIXACL)

#define IS_DEADDIR(inode)	((inode)->i_flags & S_DEAD)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)

/* the read-only stuff doesn't really belong here, but any other place is
   probably as bad and I don't want to create yet another include file. */

#define BLKROSET   _IO(0x12,93)	/* set device read-only (0 = read-write) */
#define BLKROGET   _IO(0x12,94)	/* get read-only status (0 = read_write) */
#define BLKRRPART  _IO(0x12,95)	/* re-read partition table */
#define BLKGETSIZE _IO(0x12,96)	/* return device size /512 (long *arg) */
#define BLKFLSBUF  _IO(0x12,97)	/* flush buffer cache */
#define BLKRASET   _IO(0x12,98)	/* set read ahead for block device */
#define BLKRAGET   _IO(0x12,99)	/* get current read ahead setting */
#define BLKFRASET  _IO(0x12,100)/* set filesystem (mm/filemap.c) read-ahead */
#define BLKFRAGET  _IO(0x12,101)/* get filesystem (mm/filemap.c) read-ahead */
#define BLKSECTSET _IO(0x12,102)/* set max sectors per request (ll_rw_blk.c) */
#define BLKSECTGET _IO(0x12,103)/* get max sectors per request (ll_rw_blk.c) */
#define BLKSSZGET  _IO(0x12,104)/* get block device sector size */
#if 0
#define BLKPG      _IO(0x12,105)/* See blkpg.h */

/* Some people are morons.  Do not use sizeof! */

#define BLKELVGET  _IOR(0x12,106,size_t)/* elevator get */
#define BLKELVSET  _IOW(0x12,107,size_t)/* elevator set */
/* This was here just to show that the number is taken -
   probably all these _IO(0x12,*) ioctls should be moved to blkpg.h. */
#endif
/* A jump here: 108-111 have been used for various private purposes. */
#define BLKBSZGET  _IOR(0x12,112,size_t)
#define BLKBSZSET  _IOW(0x12,113,size_t)
#define BLKGETSIZE64 _IOR(0x12,114,size_t)	/* return device size in bytes (u64 *arg) */
#define BLKTRACESETUP _IOWR(0x12,115,struct blk_user_trace_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)

#define BMAP_IOCTL 1		/* obsolete - kept for compatibility */
#define FIBMAP	   _IO(0x00,1)	/* bmap access */
#define FIGETBSZ   _IO(0x00,2)	/* get the block size used for bmap */

#define	FS_IOC_GETFLAGS			_IOR('f', 1, long)
#define	FS_IOC_SETFLAGS			_IOW('f', 2, long)
#define	FS_IOC_GETVERSION		_IOR('v', 1, long)
#define	FS_IOC_SETVERSION		_IOW('v', 2, long)
#define FS_IOC32_GETFLAGS		_IOR('f', 1, int)
#define FS_IOC32_SETFLAGS		_IOW('f', 2, int)
#define FS_IOC32_GETVERSION		_IOR('v', 1, int)
#define FS_IOC32_SETVERSION		_IOW('v', 2, int)

/*
 * Inode flags (FS_IOC_GETFLAGS / FS_IOC_SETFLAGS)
 */
#define	FS_SECRM_FL			0x00000001 /* Secure deletion */
#define	FS_UNRM_FL			0x00000002 /* Undelete */
#define	FS_COMPR_FL			0x00000004 /* Compress file */
#define FS_SYNC_FL			0x00000008 /* Synchronous updates */
#define FS_IMMUTABLE_FL			0x00000010 /* Immutable file */
#define FS_APPEND_FL			0x00000020 /* writes to file may only append */
#define FS_NODUMP_FL			0x00000040 /* do not dump file */
#define FS_NOATIME_FL			0x00000080 /* do not update atime */
/* Reserved for compression usage... */
#define FS_DIRTY_FL			0x00000100
#define FS_COMPRBLK_FL			0x00000200 /* One or more compressed clusters */
#define FS_NOCOMP_FL			0x00000400 /* Don't compress */
#define FS_ECOMPR_FL			0x00000800 /* Compression error */
/* End compression flags --- maybe not all used */
#define FS_BTREE_FL			0x00001000 /* btree format dir */
#define FS_INDEX_FL			0x00001000 /* hash-indexed directory */
#define FS_IMAGIC_FL			0x00002000 /* AFS directory */
#define FS_JOURNAL_DATA_FL		0x00004000 /* Reserved for ext3 */
#define FS_NOTAIL_FL			0x00008000 /* file tail should not be merged */
#define FS_DIRSYNC_FL			0x00010000 /* dirsync behaviour (directories only) */
#define FS_TOPDIR_FL			0x00020000 /* Top of directory hierarchies*/
#define FS_EXTENT_FL			0x00080000 /* Extents */
#define FS_DIRECTIO_FL			0x00100000 /* Use direct i/o */
#define FS_RESERVED_FL			0x80000000 /* reserved for ext2 lib */

#define FS_FL_USER_VISIBLE		0x0003DFFF /* User visible flags */
#define FS_FL_USER_MODIFIABLE		0x000380FF /* User modifiable flags */


#define SYNC_FILE_RANGE_WAIT_BEFORE	1
#define SYNC_FILE_RANGE_WRITE		2
#define SYNC_FILE_RANGE_WAIT_AFTER	4

#ifdef __KERNEL__

#include <linux/linkage.h>
#include <linux/wait.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/cache.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/radix-tree.h>
#include <linux/prio_tree.h>
#include <linux/init.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/capability.h>

#include <asm/atomic.h>
#include <asm/semaphore.h>
#include <asm/byteorder.h>

struct export_operations;
struct hd_geometry;
struct iovec;
struct nameidata;
struct kiocb;
struct pipe_inode_info;
struct poll_table_struct;
struct kstatfs;
struct vm_area_struct;
struct vfsmount;

extern void __init inode_init(void);
extern void __init inode_init_early(void);
extern void __init mnt_init(void);
extern void __init files_init(unsigned long);

struct buffer_head;
typedef int (get_block_t)(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create);
typedef void (dio_iodone_t)(struct kiocb *iocb, loff_t offset,
			ssize_t bytes, void *private);

/*
 * Attribute flags.  These should be or-ed together to figure out what
 * has been changed!
 */
#define ATTR_MODE	1
#define ATTR_UID	2
#define ATTR_GID	4
#define ATTR_SIZE	8
#define ATTR_ATIME	16
#define ATTR_MTIME	32
#define ATTR_CTIME	64
#define ATTR_ATIME_SET	128
#define ATTR_MTIME_SET	256
#define ATTR_FORCE	512	/* Not a change, but a change it */
#define ATTR_ATTR_FLAG	1024
#define ATTR_KILL_SUID	2048
#define ATTR_KILL_SGID	4096
#define ATTR_FILE	8192
#define ATTR_KILL_PRIV	16384
#define ATTR_OPEN	32768	/* Truncating from open(O_TRUNC) */

/*
 * This is the Inode Attributes structure, used for notify_change().  It
 * uses the above definitions as flags, to know which values have changed.
 * Also, in this manner, a Filesystem can look at only the values it cares
 * about.  Basically, these are the attributes that the VFS layer can
 * request to change from the FS layer.
 *
 * Derek Atkins <warlord@MIT.EDU> 94-10-20
 */
struct iattr {
	unsigned int	ia_valid;
	umode_t		ia_mode;
	uid_t		ia_uid;
	gid_t		ia_gid;
	loff_t		ia_size;
	struct timespec	ia_atime;
	struct timespec	ia_mtime;
	struct timespec	ia_ctime;

	/*
	 * Not an attribute, but an auxilary info for filesystems wanting to
	 * implement an ftruncate() like method.  NOTE: filesystem should
	 * check for (ia_valid & ATTR_FILE), and not for (ia_file != NULL).
	 */
	struct file	*ia_file;
};

/*
 * Includes for diskquotas.
 */
#include <linux/quota.h>

/** 
 * enum positive_aop_returns - aop return codes with specific semantics
 *
 * @AOP_WRITEPAGE_ACTIVATE: Informs the caller that page writeback has
 * 			    completed, that the page is still locked, and
 * 			    should be considered active.  The VM uses this hint
 * 			    to return the page to the active list -- it won't
 * 			    be a candidate for writeback again in the near
 * 			    future.  Other callers must be careful to unlock
 * 			    the page if they get this return.  Returned by
 * 			    writepage(); 
 *
 * @AOP_TRUNCATED_PAGE: The AOP method that was handed a locked page has
 *  			unlocked it and the page might have been truncated.
 *  			The caller should back up to acquiring a new page and
 *  			trying again.  The aop will be taking reasonable
 *  			precautions not to livelock.  If the caller held a page
 *  			reference, it should drop it before retrying.  Returned
 *  			by readpage().
 *
 * address_space_operation functions return these large constants to indicate
 * special semantics to the caller.  These are much larger than the bytes in a
 * page to allow for functions that return the number of bytes operated on in a
 * given page.
 */

enum positive_aop_returns {
	AOP_WRITEPAGE_ACTIVATE	= 0x80000,
	AOP_TRUNCATED_PAGE	= 0x80001,
};

#define AOP_FLAG_UNINTERRUPTIBLE	0x0001 /* will not do a short write */
#define AOP_FLAG_CONT_EXPAND		0x0002 /* called from cont_expand */

/*
 * oh the beauties of C type declarations.
 */
struct page;
struct address_space;
struct writeback_control;

struct iov_iter {
	const struct iovec *iov;
	unsigned long nr_segs;
	size_t iov_offset;
	size_t count;
};

size_t iov_iter_copy_from_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes);
size_t iov_iter_copy_from_user(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes);
void iov_iter_advance(struct iov_iter *i, size_t bytes);
int iov_iter_fault_in_readable(struct iov_iter *i, size_t bytes);
size_t iov_iter_single_seg_count(struct iov_iter *i);

static inline void iov_iter_init(struct iov_iter *i,
			const struct iovec *iov, unsigned long nr_segs,
			size_t count, size_t written)
{
	i->iov = iov;
	i->nr_segs = nr_segs;
	i->iov_offset = 0;
	i->count = count + written;

	iov_iter_advance(i, written);
}

static inline size_t iov_iter_count(struct iov_iter *i)
{
	return i->count;
}


struct address_space_operations {
	int (*writepage)(struct page *page, struct writeback_control *wbc);
	int (*readpage)(struct file *, struct page *);
	void (*sync_page)(struct page *);

	/* Write back some dirty pages from this mapping. */
	int (*writepages)(struct address_space *, struct writeback_control *);

	/* Set a page dirty.  Return true if this dirtied it */
	int (*set_page_dirty)(struct page *page);

	int (*readpages)(struct file *filp, struct address_space *mapping,
			struct list_head *pages, unsigned nr_pages);

	/*
	 * ext3 requires that a successful prepare_write() call be followed
	 * by a commit_write() call - they must be balanced
	 */
	int (*prepare_write)(struct file *, struct page *, unsigned, unsigned);
	int (*commit_write)(struct file *, struct page *, unsigned, unsigned);

	int (*write_begin)(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata);
	int (*write_end)(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata);

	/* Unfortunately this kludge is needed for FIBMAP. Don't use it */
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidatepage) (struct page *, unsigned long);
	int (*releasepage) (struct page *, gfp_t);
	ssize_t (*direct_IO)(int, struct kiocb *, const struct iovec *iov,
			loff_t offset, unsigned long nr_segs);
	struct page* (*get_xip_page)(struct address_space *, sector_t,
			int);
	/* migrate the contents of a page to the specified target */
	int (*migratepage) (struct address_space *,
			struct page *, struct page *);
	int (*launder_page) (struct page *);
};

/*
 * pagecache_write_begin/pagecache_write_end must be used by general code
 * to write into the pagecache.
 */
int pagecache_write_begin(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata);

int pagecache_write_end(struct file *, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata);

struct backing_dev_info;
struct address_space {
	struct inode		*host;		/* owner: inode, block_device */
	struct radix_tree_root	page_tree;	/* radix tree of all pages */
	rwlock_t		tree_lock;	/* and rwlock protecting it(page_tree) */
	unsigned int		i_mmap_writable;/* count VM_SHARED mappings */
	struct prio_tree_root	i_mmap;		/* tree of private and shared mappings */
	struct list_head	i_mmap_nonlinear;/*list VM_NONLINEAR mappings */
	spinlock_t		i_mmap_lock;	/* protect tree, count, list */
	unsigned int		truncate_count;	/* Cover race condition with truncate */
	unsigned long		nrpages;	/* number of total pages */
	pgoff_t			writeback_index;/* writeback starts here */
	const struct address_space_operations *a_ops;	/* methods */
	unsigned long		flags;		/* error bits/gfp mask */
	struct backing_dev_info *backing_dev_info; /* device readahead, etc */
	spinlock_t		private_lock;	/* for use by the address_space */
	struct list_head	private_list;	/* ditto */
	struct address_space	*assoc_mapping;	/* ditto 关联缓存 */
} __attribute__((aligned(sizeof(long))));
	/*
	 * On most architectures that alignment is already the case; but
	 * must be enforced here for CRIS, to let the least signficant bit
	 * of struct page's "mapping" pointer be used for PAGE_MAPPING_ANON.
	 */
/**
 * 一个块设备驱动程序可以处理几个块设备.
 * 例如：一个IDE驱动程序可以处理几个IDE磁盘。其中的每个都是一个单独的块设备。
 * 并且，每个磁盘都可以被分区。每个分区又可以被看成是一个逻辑设备。
 * 每个块设备都都是由block_device定义的。
 */

struct block_device {
	/**
	 * 块设备的主设备号和次设备号
	 */
	dev_t			bd_dev;  /* not a kdev_t - it's a search key */
		/**
	 * 指向bdev文件系统中块设备对应的文件索引结点的指针。
	 */
	struct inode *		bd_inode;	/* will die */
	/**
	 * 计数器，统计设备已经被打开了多少次
	 */
	int			bd_openers;
	/**
	 * 保护块设备打开和关闭的信号量。
	 */
	struct mutex		bd_mutex;	/* open/close mutex */
	/**
	 * 禁止在块设备上进行新安装(mount)的信号量。
	 */
	struct semaphore	bd_mount_sem;
	/**
	 * 已打开的块设备文件的索引结点链表的首部。
	 */
	struct list_head	bd_inodes;
	/**
	 * 块设备描述符的当前所有者
	 */
	void *			bd_holder;
	/**
	 * 计数器，统计对bd_holder字段多次设置的次数。
	 */
	int			bd_holders;
#ifdef CONFIG_SYSFS
	struct list_head	bd_holder_list;
#endif
	/**
		 * 如果设备是一个分区。则指向整个磁盘的块设备描述符。
		 * 否则，指向该块设备描述符
	*/

	struct block_device *	bd_contains;
	/**
		 * 块大小 
	*/
	unsigned		bd_block_size;
	/**
	 * 指向分区描述符的指针（如果块设备不是分区，则为NULL）
	 */
	struct hd_struct *	bd_part;
	/* number of times partitions within this device have been opened. */
	/**
	 * 计数器，统计包含在块设备中的分区已经被打开了多少次
	 */
	unsigned		bd_part_count;
	/**
	 * 当需要读块设备的分区表时设置的标志
	 */
	int			bd_invalidated;
	/**
	 * 指向块设备中基本磁盘的gendisk结构的指针
	 */
	struct gendisk *	bd_disk;
	/**
	 * 用于块设备描述符链表的指针
	 */
	//用于跟踪记录系统中所有可用的block_device实例。该链表的表头为全局变量all_bdevs
	struct list_head	bd_list;
	/**
	 * 指向块设备的专门描述符（通常为NULL）
	 */
	struct backing_dev_info *bd_inode_backing_dev_info;
	/*
	 * Private data.  You must have bd_claim'ed the block_device
	 * to use this.  NOTE:  bd_claim allows an owner to claim
	 * the same device multiple times, the owner must take special
	 * care to not mess up bd_private for that case.
	 */
	 /**
	 * 块设备持有者的私有数据指针
	 */
	unsigned long		bd_private;
};

/*
 * Radix-tree tags, for tagging dirty and writeback pages within the pagecache
 * radix trees
 */
#define PAGECACHE_TAG_DIRTY	0
#define PAGECACHE_TAG_WRITEBACK	1

int mapping_tagged(struct address_space *mapping, int tag);

/*
 * Might pages of this file be mapped into userspace?
 */
static inline int mapping_mapped(struct address_space *mapping)
{
	return	!prio_tree_empty(&mapping->i_mmap) ||
		!list_empty(&mapping->i_mmap_nonlinear);
}

/*
 * Might pages of this file have been modified in userspace?
 * Note that i_mmap_writable counts all VM_SHARED vmas: do_mmap_pgoff
 * marks vma as VM_SHARED if it is shared, and the file was opened for
 * writing i.e. vma may be mprotected writable even if now readonly.
 */
static inline int mapping_writably_mapped(struct address_space *mapping)
{
	return mapping->i_mmap_writable != 0;
}

/*
 * Use sequence counter to get consistent i_size on 32-bit processors.
 */
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
#include <linux/seqlock.h>
#define __NEED_I_SIZE_ORDERED
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#else
#define i_size_ordered_init(inode) do { } while (0)
#endif

struct inode {
	/* 用于散列链表的指针
	共有4个管理inode的链表。
(1)inode_unused，用于将目前还没使用的inode链接起来。
(2)inode_in_use，用于将目前正在使用的inode链接起来。Inode_unused
与inode_in_use都是定义在include/linux/write_back.h文件中的
全局变量。
(3）超级块对象的s_dirty字段，用于将所有的脏inode链接在一起。
(4）所有正在使用中的inode都可以从inode_in_use中找到，但是因为系统中
的inode有许多，所以查找的效率并不高。因此每个使用中的inode都会计算
出其hash值，这些hash值有可能会重复，i_hash则将具有同样hash值的

多个inode链接起来。
	*/
	struct hlist_node	i_hash;
	/* 用于描述索引节点当前状态的链表的指针
	通过此字段将队列链入不同状态的链表中
	*/
	struct list_head	i_list;
	/* 用于超级块的索引节点链表的指针
	super_block->s_inodes
	*/
	struct list_head	i_sb_list;
	/* 引用索引节点的目录项对象链表的头 */
	struct list_head	i_dentry;
	/* 索引节点号 由超级块对象和这个序号可以找到inode*/
	unsigned long		i_ino;
	/* 引用计数器 */
	atomic_t		i_count;
	/* 硬链接数目 */
	unsigned int		i_nlink;
	/* 所有者标识符 */
	uid_t			i_uid;
	/* 所有者组标识符 */
	gid_t			i_gid;
	/* 实设备标识符 */
	dev_t			i_rdev;
	/* 版本号（每次修改后自动递增） */
	unsigned long		i_version;
	/* 文件的字节数 */
	loff_t			i_size;
#ifdef __NEED_I_SIZE_ORDERED
	seqcount_t		i_size_seqcount;
#endif
	/* 上次访问文件的时间 */
	struct timespec		i_atime;
	/* 上次写文件的时间 */
	struct timespec		i_mtime;
	/* 上次修改索引节点的时间 */
	struct timespec		i_ctime;
	/* 块的大小，以bit为单位 */
	unsigned int		i_blkbits;
	/* 文件的块数 */
	blkcnt_t		i_blocks;
	/* 文件中最后一个块的字节数 */
	unsigned short          i_bytes;
	/* 文件类型与访问权限 */
	umode_t			i_mode;
	/* 保护索引节点一些字段的自旋锁：i_blocks, i_bytes, maybe i_size */
	spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
	/* 索引节点信号量 */
	struct mutex		i_mutex;
	/* 在直接I/O文件操作中避免出现竞争条件的读/写信号量
	保护一个inode上的I/O操作不会被另一个打断
	*/
	struct rw_semaphore	i_alloc_sem;
	/* 索引节点的操作
	索引节点函数集, 主要包含对子inode的创建, 删除等操作
	*/
	const struct inode_operations	*i_op;
	/* 缺省文件操作：former->i_op->default_file_ops */
	const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
	/* 指向超级块对象的指针 */
	struct super_block	*i_sb;
	/* 指向文件锁链表的指针 */
	struct file_lock	*i_flock;
	/* 指向缓存address_space对象的指针
	address_Space并不代表某个地址空间，而是用于描述页高速缓存中的页面的一个文件对应一个address_space,
	一个address_space与一个偏移量能够确定一个页高速缓存中的页面。i_mapping通常指向i_data，
	不过二者是有区别的，i_mapping表示应该向谁请求页面，i_data表示被该inode读写的页面
	*/
	struct address_space	*i_mapping;
	/* 嵌入在inode中的文件的address_space对象 */
	struct address_space	i_data;
#ifdef CONFIG_QUOTA
	/* 索引节点磁盘限额
	inode的磁盘限额。磁盘限额管理分为两种，一种是block的限额；另一种是
	inode的限额，将与磁盘限额有关的操作函数放在struct super_block里是
	因为一个文件系统会使用相同的限额管理方式，而从一个inode又都可以通过
	i_sb字段获得该inode的超级块。MAXQUOTAS值为2，分别对应了两种限额管理
	方式，一种是user限额，另一种是group限额
	*/
	struct dquot		*i_dquot[MAXQUOTAS];
#endif
	/* 用于具体的字符或块设备索引节点链表的指针	
	共用同一个驱动程序的设备形成的链表。比如对于字符设备，在其open时，会
	根据i_rdev字段查找到相应的驱动程序，并使i_cdev字段指向找到的cdev,
	然后将inode添加到struct cdev中list字段形成的链表里
	*/
	struct list_head	i_devices;
	union {
		/* 如果文件是一个管道则使用它 */
		struct pipe_inode_info	*i_pipe;
		/* 指向块设备驱动程序的指针 */
		struct block_device	*i_bdev;
		/* 指向字符设备驱动程序的指针 */
		struct cdev		*i_cdev;
	};
	/* 拥有一组次设备号的设备文件的索引
	i_cindex表示该设备文件在共用同一驱动程序的多个设备（主设备号相同，次设备号不同）之中的索引
	*/
	int			i_cindex;
	/* 索引节点版本号（由某些文件系统使用）
	inode实例数目
	*/
	__u32			i_generation;

#ifdef CONFIG_DNOTIFY
	/* 目录通知事件的位掩码 */
	unsigned long		i_dnotify_mask; /* Directory notify events */
	/* 用于目录通知 */
	struct dnotify_struct	*i_dnotify; /* for directory notifications */
#endif

#ifdef CONFIG_INOTIFY
//被监控目标上的watch(监控)链表
	struct list_head	inotify_watches; /* watches on this inode */
//保护watch链表的互斥锁
	struct mutex		inotify_mutex;	/* protects the watches list */
#endif
	/* 索引节点的状态标志 I_NEW,I_LOCK,I_FREEING */
	unsigned long		i_state;
	/* 索引节点的弄脏时间（以jiffy为单位） */
	unsigned long		dirtied_when;	/* jiffies of first dirtying */
	/* 文件系统的安装标志 ,S_SYNC,S_NOATIME,S_DIRSYNC*/
	unsigned int		i_flags;
	/* 用于写进程的引用计数器 */
	atomic_t		i_writecount;
#ifdef CONFIG_SECURITY
	/* 指向索引节点安全结构的指针(struct inode_security_struct) */
	void			*i_security;
#endif
	/* 指向私有数据的指针 */
	void			*i_private; /* fs or device private pointer */
};

/*
 * inode->i_mutex nesting subclasses for the lock validator:
 *
 * 0: the object of the current VFS operation
 * 1: parent
 * 2: child/target
 * 3: quota file
 *
 * The locking order between these classes is
 * parent -> child -> normal -> xattr -> quota
 */
enum inode_i_mutex_lock_class
{
	I_MUTEX_NORMAL,
	I_MUTEX_PARENT,
	I_MUTEX_CHILD,
	I_MUTEX_XATTR,
	I_MUTEX_QUOTA
};

extern void inode_double_lock(struct inode *inode1, struct inode *inode2);
extern void inode_double_unlock(struct inode *inode1, struct inode *inode2);

/*
 * NOTE: in a 32bit arch with a preemptable kernel and
 * an UP compile the i_size_read/write must be atomic
 * with respect to the local cpu (unlike with preempt disabled),
 * but they don't need to be atomic with respect to other cpus like in
 * true SMP (so they need either to either locally disable irq around
 * the read or for example on x86 they can be still implemented as a
 * cmpxchg8b without the need of the lock prefix). For SMP compiles
 * and 64bit archs it makes no difference if preempt is enabled or not.
 */
static inline loff_t i_size_read(const struct inode *inode)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	loff_t i_size;
	unsigned int seq;

	do {
		seq = read_seqcount_begin(&inode->i_size_seqcount);
		i_size = inode->i_size;
	} while (read_seqcount_retry(&inode->i_size_seqcount, seq));
	return i_size;
#elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPT)
	loff_t i_size;

	preempt_disable();
	i_size = inode->i_size;
	preempt_enable();
	return i_size;
#else
	return inode->i_size;
#endif
}

/*
 * NOTE: unlike i_size_read(), i_size_write() does need locking around it
 * (normally i_mutex), otherwise on 32bit/SMP an update of i_size_seqcount
 * can be lost, resulting in subsequent i_size_read() calls spinning forever.
 */
static inline void i_size_write(struct inode *inode, loff_t i_size)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	write_seqcount_begin(&inode->i_size_seqcount);
	inode->i_size = i_size;
	write_seqcount_end(&inode->i_size_seqcount);
#elif BITS_PER_LONG==32 && defined(CONFIG_PREEMPT)
	preempt_disable();
	inode->i_size = i_size;
	preempt_enable();
#else
	inode->i_size = i_size;
#endif
}

static inline unsigned iminor(const struct inode *inode)
{
	return MINOR(inode->i_rdev);
}

static inline unsigned imajor(const struct inode *inode)
{
	return MAJOR(inode->i_rdev);
}

extern struct block_device *I_BDEV(struct inode *inode);

struct fown_struct {
	rwlock_t lock;          /* protects pid, uid, euid fields */
	struct pid *pid;	/* pid or -pgrp where SIGIO should be sent */
	enum pid_type pid_type;	/* Kind of process group SIGIO should be sent to */
	uid_t uid, euid;	/* uid/euid of process setting the owner */
	int signum;		/* posix.1b rt signal to be delivered on IO */
};

/*
 * Track a single file's readahead state
 */
struct file_ra_state {
	pgoff_t start;			/* where readahead started */
	unsigned int size;		/* # of readahead pages */
	unsigned int async_size;	/* do asynchronous readahead when
					   there are only # of pages ahead */

	unsigned int ra_pages;		/* Maximum readahead window */
	int mmap_miss;			/* Cache miss stat for mmap accesses */
	loff_t prev_pos;		/* Cache last read() position */
};

/*
 * Check if @index falls in the readahead windows.
 */
static inline int ra_has_index(struct file_ra_state *ra, pgoff_t index)
{
	return (index >= ra->start &&
		index <  ra->start + ra->size);
}

struct file {
	/*
	 * fu_list becomes invalid after file_free is called and queued via
	 * fu_rcuhead for RCU freeing
	 */
	 //fu_list 链接在 super_block->s_files中
	union {
	//file链表，一个文件系统的所有已打开文件都通过fu_list挂入该文件系统超级块的s_files链表中
		struct list_head	fu_list;
	//保护file的RCU
		struct rcu_head 	fu_rcuhead;
	} f_u;  /* 用于通用文件对象链表的指针 */
	struct path		f_path;
	//与该文件相关的dentry
#define f_dentry	f_path.dentry
//该文件所在文件系统的安装点,和f_dentry一起可以得到该文件在系统中的绝对路径
#define f_vfsmnt	f_path.mnt
	/* 指向文件操作表的指针 */
	const struct file_operations	*f_op;
	/* 文件对象的引用计数器 */
	atomic_t		f_count;
	 /* 当打开文件时所指定的标志 */
	unsigned int 		f_flags;
	  /* 进程的访问模式 */
	mode_t			f_mode;
	  /* 当前的文件位移量（文件指针） */
	loff_t			f_pos;
	  /* 通过信号进行I/O事件通知的数据 */	
	/*fowner记录了一个进程ID和某些事件发生（比如文件有新数据可用）时发送给该
	进程的信号*/
	struct fown_struct	f_owner;
	  /* 用户的UID、GID */
	unsigned int		f_uid, f_gid;
	   /* 文件预读状态 */
	struct file_ra_state	f_ra;
	/* 版本号，每次使用后自动递增
	当文件的f_pos改变时，f_version递增
	*/
	u64			f_version;
#ifdef CONFIG_SECURITY
	/* 指向文件对象的安全结构的指针	
	指向文件安全数据结构（struct fiie_security_struct）的指针
	*/
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others
	用于存放一些供文件系统或驱动程序使用的私有数据
	*/
	void			*private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file 
指向特定文件系统或设备驱动程序所需的数据的指针
*/
	struct list_head	f_ep_links; /* 文件的事件轮询等待者链表的头 */
	spinlock_t		f_ep_lock; /* 保护f_ep_links链表的自旋锁 */
#endif /* #ifdef CONFIG_EPOLL */
//该文件对应的address_space，参看struct inode的i_mapping字段
	struct address_space	*f_mapping; /* 指向文件地址空间对象的指针 */
};
//保护超级块的s_files链表免受多处理器系统上的同时访问
extern spinlock_t files_lock;
#define file_list_lock() spin_lock(&files_lock);
#define file_list_unlock() spin_unlock(&files_lock);

#define get_file(x)	atomic_inc(&(x)->f_count)
#define file_count(x)	atomic_read(&(x)->f_count)

#define	MAX_NON_LFS	((1UL<<31) - 1)

/* Page cache limit. The filesystems should put that into their s_maxbytes 
   limits, otherwise bad things can happen in VM. */ 
#if BITS_PER_LONG==32
#define MAX_LFS_FILESIZE	(((u64)PAGE_CACHE_SIZE << (BITS_PER_LONG-1))-1) 
#elif BITS_PER_LONG==64
#define MAX_LFS_FILESIZE 	0x7fffffffffffffffUL
#endif

#define FL_POSIX	1
#define FL_FLOCK	2
#define FL_ACCESS	8	/* not trying to lock, just looking */
#define FL_EXISTS	16	/* when unlocking, test for existence */
#define FL_LEASE	32	/* lease held on this file */
#define FL_CLOSE	64	/* unlock on close */
#define FL_SLEEP	128	/* A blocking lock */

/*
 * The POSIX file lock owner is determined by
 * the "struct files_struct" in the thread group
 * (or NULL for no owner - BSD locks).
 *
 * Lockd stuffs a "host" pointer into this.
 */
typedef struct files_struct *fl_owner_t;

struct file_lock_operations {
	void (*fl_insert)(struct file_lock *);	/* lock insertion callback */
	void (*fl_remove)(struct file_lock *);	/* lock removal callback */
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};

struct lock_manager_operations {
	int (*fl_compare_owner)(struct file_lock *, struct file_lock *);
	void (*fl_notify)(struct file_lock *);	/* unblock callback */
	int (*fl_grant)(struct file_lock *, struct file_lock *, int);
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
	void (*fl_break)(struct file_lock *);
	int (*fl_mylease)(struct file_lock *, struct file_lock *);
	int (*fl_change)(struct file_lock **, int);
};

/* that will die - we need it for nfs_lock_info */
#include <linux/nfs_fs_i.h>

struct file_lock {
	struct file_lock *fl_next;	/* singly linked list for this inode  */
	struct list_head fl_link;	/* doubly linked list of all locks */
	struct list_head fl_block;	/* circular list of blocked processes */
	fl_owner_t fl_owner;
	unsigned int fl_pid;
	wait_queue_head_t fl_wait;
	struct file *fl_file;
	unsigned char fl_flags;
	unsigned char fl_type;
	loff_t fl_start;
	loff_t fl_end;

	struct fasync_struct *	fl_fasync; /* for lease break notifications */
	unsigned long fl_break_time;	/* for nonblocking lease breaks */

	struct file_lock_operations *fl_ops;	/* Callbacks for filesystems */
	struct lock_manager_operations *fl_lmops;	/* Callbacks for lockmanagers */
	union {
		struct nfs_lock_info	nfs_fl;
		struct nfs4_lock_info	nfs4_fl;
		struct {
			struct list_head link;	/* link in AFS vnode's pending_locks list */
			int state;		/* state of grant or error if -ve */
		} afs;
	} fl_u;
};

/* The following constant reflects the upper bound of the file/locking space */
#ifndef OFFSET_MAX
#define INT_LIMIT(x)	(~((x)1 << (sizeof(x)*8 - 1)))
#define OFFSET_MAX	INT_LIMIT(loff_t)
#define OFFT_OFFSET_MAX	INT_LIMIT(off_t)
#endif

#include <linux/fcntl.h>

extern int fcntl_getlk(struct file *, struct flock __user *);
extern int fcntl_setlk(unsigned int, struct file *, unsigned int,
			struct flock __user *);

#if BITS_PER_LONG == 32
extern int fcntl_getlk64(struct file *, struct flock64 __user *);
extern int fcntl_setlk64(unsigned int, struct file *, unsigned int,
			struct flock64 __user *);
#endif

extern void send_sigio(struct fown_struct *fown, int fd, int band);
extern int fcntl_setlease(unsigned int fd, struct file *filp, long arg);
extern int fcntl_getlease(struct file *filp);

/* fs/sync.c */
extern int do_sync_mapping_range(struct address_space *mapping, loff_t offset,
			loff_t endbyte, unsigned int flags);

/* fs/locks.c */
extern void locks_init_lock(struct file_lock *);
extern void locks_copy_lock(struct file_lock *, struct file_lock *);
extern void locks_remove_posix(struct file *, fl_owner_t);
extern void locks_remove_flock(struct file *);
extern void posix_test_lock(struct file *, struct file_lock *);
extern int posix_lock_file(struct file *, struct file_lock *, struct file_lock *);
extern int posix_lock_file_wait(struct file *, struct file_lock *);
extern int posix_unblock_lock(struct file *, struct file_lock *);
extern int vfs_test_lock(struct file *, struct file_lock *);
extern int vfs_lock_file(struct file *, unsigned int, struct file_lock *, struct file_lock *);
extern int vfs_cancel_lock(struct file *filp, struct file_lock *fl);
extern int flock_lock_file_wait(struct file *filp, struct file_lock *fl);
extern int __break_lease(struct inode *inode, unsigned int flags);
extern void lease_get_mtime(struct inode *, struct timespec *time);
extern int generic_setlease(struct file *, long, struct file_lock **);
extern int vfs_setlease(struct file *, long, struct file_lock **);
extern int lease_modify(struct file_lock **, int);
extern int lock_may_read(struct inode *, loff_t start, unsigned long count);
extern int lock_may_write(struct inode *, loff_t start, unsigned long count);
extern struct seq_operations locks_seq_operations;

struct fasync_struct {
	int	magic;
	int	fa_fd;
	struct	fasync_struct	*fa_next; /* singly linked list */
	struct	file 		*fa_file;
};

#define FASYNC_MAGIC 0x4601

/* SMP safe fasync helpers: */
extern int fasync_helper(int, struct file *, int, struct fasync_struct **);
/* can be called from interrupts */
extern void kill_fasync(struct fasync_struct **, int, int);
/* only for net: no internal synchronization */
extern void __kill_fasync(struct fasync_struct *, int, int);

extern int __f_setown(struct file *filp, struct pid *, enum pid_type, int force);
extern int f_setown(struct file *filp, unsigned long arg, int force);
extern void f_delown(struct file *filp);
extern pid_t f_getown(struct file *filp);
extern int send_sigurg(struct fown_struct *fown);

/*
 *	Umount options
 */

#define MNT_FORCE	0x00000001	/* Attempt to forcibily umount */
#define MNT_DETACH	0x00000002	/* Just detach from the tree */
#define MNT_EXPIRE	0x00000004	/* Mark for expiry */

extern struct list_head super_blocks;
extern spinlock_t sb_lock;

#define sb_entry(list)	list_entry((list), struct super_block, s_list)
#define S_BIAS (1<<30)
struct super_block {
	/* 指向超级块链表的指针 */
		//每一个分区都有一个超级块，所有超级块用s_list连接
	//用以形成超级块链表
	struct list_head	s_list;		/* Keep this first */
	 /* 设备标识符 */
	//超级块所属文件系统所在的设备标识符
	dev_t			s_dev;		/* search index; _not_ kdev_t */
	 /* 以字节为单位的块大小 */
	unsigned long		s_blocksize;
	  /* 以位为单位的块大小(对数) */
	//一个块需要几个bit来表示，如果一个块是1024字节，那么s_blocksize_bits就是10
	unsigned char		s_blocksize_bits;
	   /* 修改（脏）标志 */
	unsigned char		s_dirt;
	   /* 文件的最长长度 */
	unsigned long long	s_maxbytes;	/* Max file size */
	   /* 文件系统类型 */
	struct file_system_type	*s_type;
	   /* 超级块方法 */
	const struct super_operations	*s_op;
	   /* 磁盘限额处理方法 文件系统可以提供自己的磁盘限额处理方法，也可以使用VFS提供了的通用方法*/
	struct dquot_operations	*dq_op;
	   /* 磁盘限额管理方法 来自用户空间的请求*/
 	struct quotactl_ops	*s_qcop;
	    /* 网络文件系统使用的输出操作 导出的方法（从NFS服务器共享文件又称导出目录)*/
	const struct export_operations *s_export_op;
		/* 安装标志 我们使用一个文件系统时，首先要进行mount操作，在mount的时候
		还需要给它参数，比如mount成只读或可擦写等，这些参数就是记录在s_flags*/
	unsigned long		s_flags;
		/* 文件系统的魔数 */
	unsigned long		s_magic;
		 /* 文件系统根目录的目录项对象 */
	struct dentry		*s_root;
		  /* 卸载所用的信号量 */
	struct rw_semaphore	s_umount;
		  /* 用于超级块同步 */
	struct mutex		s_lock;
		   /* 超级快引用计数器 */
	int			s_count;
		    /* 表示对超级块的索引节点进行同步的标志 */
	int			s_syncing;
			/* 对超级块的已安装文件系统进行同步的标志 */
	int			s_need_sync_fs;
	/* 超级快次级引用计数器 */
	atomic_t		s_active;
#ifdef CONFIG_SECURITY
	/* 指向超级块安全数据结构的指针 */
	void                    *s_security;
#endif
	/* 指向超级块扩展属性结构的指针 */
	struct xattr_handler	**s_xattr;
	/* 所有索引节点的链表头 */
	struct list_head	s_inodes;	/* all inodes */
	/*
	脏inode的链表。一个文件系统里有许多的inode，有的inode内容会被更改，
	此时就称其为dirty inode，所有的dirty inode都会被记录，以便在适当的时候写入磁盘
	*/
	struct list_head	s_dirty;	/* dirty inodes */
	/* 等待被写入磁盘的索引节点的链表 */
	struct list_head	s_io;		/* parked for writeback */
	struct list_head	s_more_io;	/* parked for more writeback */
	/* 用于处理远程网络文件系统的匿名目录项的链表 */
	struct hlist_head	s_anon;		/* anonymous dentries for (nfs) exporting */
	 /* 文件对象的链表 */
	struct list_head	s_files;
	/* 指向块设备驱动程序描述符的指针 */
	struct block_device	*s_bdev;
	//类似s_bdev,指向超级块被安装的MTD设备
	struct mtd_info		*s_mtd;
	 /* 用于给定文件系统类型的超级块对象链表的指针 */
	//同一种文件系统类型的超级块通过s_instances链接
	struct list_head	s_instances;
	 /* 磁盘限额信息 */
	struct quota_info	s_dquot;	/* Diskquota specific options */
	/* 冻结文件系统时使用的标志（强制置于一致状态） */
	int			s_frozen;
	/* 进程挂起的等待队列，直到文件系统被解冻 */
	wait_queue_head_t	s_wait_unfrozen;
	/* 包含超级块的块设备名称 */
	//文件系统名称，比如对于sysfs，s_id为“sysfs”
	char s_id[32];				/* Informational name */
	/* 指向特定文件系统的超级块信息的指针 */
	void 			*s_fs_info;	/* Filesystem private info */

	/*
	 * The next field is for VFS *only*. No filesystems have any business
	 * even looking at it. You had been warned.
	 */
	  /* 当VFS通过目录重命名文件时使用的信号量 */
	struct mutex s_vfs_rename_mutex;	/* Kludge */

	/* Granularity of c/m/atime in ns.
	   Cannot be worse than a second
	   时间戳的粒度（纳秒级）
	   */
	u32		   s_time_gran;

	/*
	 * Filesystem subtype.  If non-empty the filesystem type field
	 * in /proc/mounts will be "type.subtype"
	 */
	char *s_subtype;
};

extern struct timespec current_fs_time(struct super_block *sb);

/*
 * Snapshotting support.
 */
enum {
	SB_UNFROZEN = 0,
	SB_FREEZE_WRITE	= 1,
	SB_FREEZE_TRANS = 2,
};

#define vfs_check_frozen(sb, level) \
	wait_event((sb)->s_wait_unfrozen, ((sb)->s_frozen < (level)))

#define get_fs_excl() atomic_inc(&current->fs_excl)
#define put_fs_excl() atomic_dec(&current->fs_excl)
#define has_fs_excl() atomic_read(&current->fs_excl)

#define is_owner_or_cap(inode)	\
	((current->fsuid == (inode)->i_uid) || capable(CAP_FOWNER))

/* not quite ready to be deprecated, but... */
extern void lock_super(struct super_block *);
extern void unlock_super(struct super_block *);

/*
 * VFS helper functions..
 */
extern int vfs_permission(struct nameidata *, int);
extern int vfs_create(struct inode *, struct dentry *, int, struct nameidata *);
extern int vfs_mkdir(struct inode *, struct dentry *, int);
extern int vfs_mknod(struct inode *, struct dentry *, int, dev_t);
extern int vfs_symlink(struct inode *, struct dentry *, const char *, int);
extern int vfs_link(struct dentry *, struct inode *, struct dentry *);
extern int vfs_rmdir(struct inode *, struct dentry *);
extern int vfs_unlink(struct inode *, struct dentry *);
extern int vfs_rename(struct inode *, struct dentry *, struct inode *, struct dentry *);

/*
 * VFS dentry helper functions.
 */
extern void dentry_unhash(struct dentry *dentry);

/*
 * VFS file helper functions.
 */
extern int file_permission(struct file *, int);

/*
 * File types
 *
 * NOTE! These match bits 12..15 of stat.st_mode
 * (ie "(i_mode >> 12) & 15").
 */
#define DT_UNKNOWN	0
#define DT_FIFO		1
#define DT_CHR		2
#define DT_DIR		4
#define DT_BLK		6
#define DT_REG		8
#define DT_LNK		10
#define DT_SOCK		12
#define DT_WHT		14

#define OSYNC_METADATA	(1<<0)
#define OSYNC_DATA	(1<<1)
#define OSYNC_INODE	(1<<2)
int generic_osync_inode(struct inode *, struct address_space *, int);

/*
 * This is the "filldir" function type, used by readdir() to let
 * the kernel specify what kind of dirent layout it wants to have.
 * This allows the kernel to read directories into kernel space or
 * to have different dirent layouts depending on the binary type.
 */
typedef int (*filldir_t)(void *, const char *, int, loff_t, u64, unsigned);

struct block_device_operations {
	int (*open) (struct inode *, struct file *);//打开文件
	int (*release) (struct inode *, struct file *);//关闭文件
	int (*ioctl) (struct inode *, struct file *, unsigned, unsigned long);//向块设备发送特殊命令
	long (*unlocked_ioctl) (struct file *, unsigned, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned, unsigned long);
	int (*direct_access) (struct block_device *, sector_t, unsigned long *);
	int (*media_changed) (struct gendisk *);//检查存储介质是否已经改变
	int (*revalidate_disk) (struct gendisk *);//让设备重新生效
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	struct module *owner;
};

/*
 * "descriptor" for what we're up to with a read.
 * This allows us to use the same read code yet
 * have multiple different users of the data that
 * we read from a file.
 *
 * The simplest case just copies the data to user
 * mode.
 */
 /**
 * 与每个用户态读缓冲区相关的文件读操作的状态。
 */
typedef struct {
	/**
	* 已经拷贝到用户态缓冲区的字节数
	*/

	size_t written;
	/**
	 * 待传送的字节数
	 */
	size_t count;
	/**
	 * 在用户态缓冲区中的当前位置
	 */
	union {
		char __user * buf;
		void *data;
	} arg;
		/**
	 * 读操作的错误码。0表示无错误。
	 */
	int error;
} read_descriptor_t;

typedef int (*read_actor_t)(read_descriptor_t *, struct page *, unsigned long, unsigned long);

/* These macros are for out of kernel modules to test that
 * the kernel supports the unlocked_ioctl and compat_ioctl
 * fields in struct file_operations. */
#define HAVE_COMPAT_IOCTL 1
#define HAVE_UNLOCKED_IOCTL 1

/*
 * NOTE:
 * read, write, poll, fsync, readv, writev, unlocked_ioctl and compat_ioctl
 * can be called without the big kernel lock held in all filesystems.
 */
struct file_operations {
	/* 指向一个模块的拥有者，该字段主要应用于那些有模块产生的文件系统 */
	struct module *owner;
	 /* 更新文件指针。
		设定从文件的哪个位置开始读写，由系统调用llseek()调用
		*/
	loff_t (*llseek) (struct file *, loff_t, int);
	/* 从文件的*offset处开始读出count个字节；然后增加*offset的值（一般与文件指针对应）	
	从文件的指定位置（第四个参数为offset)读取指定的字节(第三个参数)到指定的buf
	（第二个参数）中，同时要更新文件的f_pos由系统调用read调用
	*/
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	/**
		 * 向设备发送数据。如果没有这个函数，write系统调用会向程序返回一个-EINVAL。如果返回值非负，则表示成功写入的字节数。
		 从给定的buf（第二个参数）中取出指定长度（第三个参数）的数据，写入文件的		 
		 指定位置（第四个参数为文件的offset)，由系统调用write()调用
		 */
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	/* 启动一个异步I/O操作，从文件的pos处开始读出len个字节的数据并将它们放入buf中 
  * （引入它是为了支持io_submit()系统调用）。 */
	/*以异步的方式从文件中读取数据，由系统调用aio_read调用，aio是"asynchronous I/O”
	的缩写*/
	ssize_t (*aio_read) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
	/**
	 * 初始化设备上的异步写入操作。	 
	 以异步的方式向文件中写数据，由系统调用aio_write()调用
	 */
	ssize_t (*aio_write) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
	/**
	 * 对于设备文件来说，这个字段应该为NULL。它仅用于读取目录，只对文件系统有用。
	 * filldir_t用于提取目录项的各个字段。
	 */
	int (*readdir) (struct file *, void *, filldir_t);
		/**
	 * POLL方法是poll、epoll和select这三个系统调用的后端实现。这三个系统调用可用来查询某个或多个文件描述符上的读取或写入是否会被阻塞。
	 * poll方法应该返回一个位掩码，用来指出非阻塞的读取或写入是否可能。并且也会向内核提供将调用进程置于休眠状态直到IO变为可能时的信息。
	 * 如果驱动程序将POLL方法定义为NULL，则设备会被认为既可读也可写，并且不会阻塞。	 
	 检查指定文件上是否有操作发生，如果没有则休眠，直到该文件上有操作发生，由系统调用poll
	 */
	unsigned int (*poll) (struct file *, struct poll_table_struct *);
		/**
	 * 系统调用ioctl提供了一种执行设备特殊命令的方法(如格式化软盘的某个磁道，这既不是读也不是写操作)。
	 * 另外，内核还能识别一部分ioctl命令，而不必调用fops表中的ioctl。如果设备不提供ioctl入口点，则对于任何内核未预先定义的请求，ioctl系统调用将返回错误(-ENOTYY)
	 用于向设备发送command，由系统调用ioctl。这个函数要做的事情很简单，只是根据command的值，进行适当的操作
	 */
	int (*ioctl) (struct inode *, struct file *, unsigned int, unsigned long);
		/**
	 * 与ioctl类似，但是不获取大内核锁。
	 */
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
		/**
	 * 64位内核使用该方法实现32位系统调用。
	 考虑这样的场景：用户应用是32位的而内核和硬件架构都是64位的。这种情况下，
应用调用ioctl()时，内核里必须有进行32位到64位转化的机制。compat_ioctl()
即是用于64位的内核执行来自32位应用的ioctl()
	 */
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	/**
	 * 请求将设备内存映射到进程地址空间。如果设备没有实现这个方法，那么mmap系统调用将返回-ENODEV。	 
	 将指定的文件映射到指定的地址空间上，由系统调用mmap()调用
	 */
	int (*mmap) (struct file *, struct vm_area_struct *);
		/**
	 * 尽管这始终是对设备文件执行的第一个操作，然而却并不要求驱动程序一定要声明一个相应的方法。
	 * 如果这个入口为NULL，设备的打开操作永远成功，但系统不会通知驱动程序。	 
	 创建新的文件对象，并将它和相应的inode关联起来，由系统调用open调用
	 */
	int (*open) (struct inode *, struct file *);
	/**
	 * 对flush操作的调用发生在进程关闭设备文件描述符副本的时候，它应该执行(并等待)设备上尚未完结的操作。
	 * 请不要将它同用户程序使用的fsync操作相混淆。目前，flush仅仅用于少数几个驱动程序。比如，SCSI磁带驱动程序用它来确保设备被关闭之前所有的数据都被写入磁带中。
	 * 如果flush被置为NULL，内核将简单地忽略用户应用程序的请求。
	 */
	 /*当己打开的文件引用计数减少时（系统调用close被调用），该函数会被调用。
它的作用根据具体文件系统而定*/
	int (*flush) (struct file *, fl_owner_t id);
	/**
	 * 当file结构被释放时，将调用这个操作。与open相似，也可以将release设置为NULL。	 
	 释放文件对象，当已打开文件的引用计数变为0时，该函数会被调用
	 */
	int (*release) (struct inode *, struct file *);
	/**
	 * 该方法是fsync系统调用的后端实现。用户调用它来刷新待处理的数据。如果驱动程序没有实现这一方法，fsync系统调用将返回-EINVAL。
	 将文件所有被缓存的数据写入磁盘，由系统调用fsync和fdatasync调用,
	 fdatasync()只会影响文件的数据部分，fsync则还会同步更新文件的属性
	 */
	int (*fsync) (struct file *, struct dentry *, int datasync);
	/**
	 * 这是fsync的异步版本。
	 */
	int (*aio_fsync) (struct kiocb *, int datasync);
	/**
	 * 这个操作用来通知设备其FASYNC标志发生了变化。异步通知是比较高级的话题，如果设备不支持异步通知，该字段可以是NULL。
	 */
	 //打开或关闭异步I/O的通知信号
	int (*fasync) (int, struct file *, int);
	/**
	 * LOCK方法用于实现文件锁定，锁定是常规文件不可缺少的特性。但是设备驱动程序几乎从来不会实现这个方法。
	 */
	 //用以对文件加锁
	int (*lock) (struct file *, int, struct file_lock *);
	/**
	 * sendpage是sendfile系统调用的另一半。它由内核调用以将数据发送到对应的文件。每次一个数据页。
	 * 设备驱动程序通常也不需要实现sendfile。	 
	 用来从一个文件向另一个文件发送数据，一次一页地将数据从文件传送到页高速缓存中的页
	 */
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
	/**
	 * 在进程的地址空间中找到一个合适的位置，以便将底层设备中的内存段映射到该位置。
	 * 该任务通常由内存管理代码完成，但该方法的存在可允许驱动程序强制满足特定设备需要的任何对齐要求。大部分驱动程序可设置该方法为NULL。
	 在进程的地址空间中找到一个未使用的地址范围来映射文件
	 */
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	/**
	 * 该方法允许模块检查传递给fcntl调用的标志。当前只适用于NFS
	 */	 
	/*使用系统调用fcntl()设置文件的的状态标志（F_SETFL命令）时，调用
	check_flaqs(）进行附加的检查*/
	int (*check_flags)(int);
	/**
	 * 当应用程序使用fcntl来请求目录改变通知时，该方法将被调用。该方法仅对文件系统有用，驱动程序不必实现dir_notify。
	 * 当前适用于CIFS。
	 */
	 //使用系统调用fcntl()请求目录改变通知（F_NOTIFY）时，调用dir_noify
	int (*dir_notify)(struct file *filp, unsigned long arg);
	/**
	 * 用于定制flock系统调用的行为。当进程试图对文件加锁时，回调此函数。由系统调用flock调用
	 */
	int (*flock) (struct file *, int, struct file_lock *);
	//从一个管道移动数据到一个文件，由系统调用spIice调用
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	//从一个文件移动数据到一个管道，由系统调用splice调用
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	/*
	为一个已打开的文件设置一个租约(lease)，文件租约提供当一个进程试图打开或
	读写文件内容时，拥有文件租约的进程将会被通知的机制
	*/
	int (*setlease)(struct file *, long, struct file_lock **);
};

struct inode_operations {
	/* 在某一目录下，为与目录项对象相关的普通文件创建一个新的磁盘索引节点。
	在打开一个新文件时，内核必须为这个文件创建一个inode，因为一个文件一定是
	位于某个目录下面，vFs就通过该目录inode的i_op调用create()完成新inode
	的创建工作。传递的第一个参数就是该目录的inode，第二个参数是要打开的新文件
	的dentry，第三个参数是对该文件的访问权限。对于普通的文件，不可能会调用到
	它的crea七e()，因为它不是目录，没办法在它底下产生一个inode。对于目录，
	则必须提供create()，不然没有办法在其底下产生子目录或文件
	*/
	int (*create) (struct inode *,struct dentry *,int, struct nameidata *);
	/* 为包含在一个目录项对象中的文件名对应的索引节点查找目录。	
	在指定的日录中寻找inode。与create()一样，lookup(）也是由日录的inode
	所应该提供的。比如对于文件/home/test/test.c，如果要打开该文件，首先就要找
	到它的inode，那么内核是如果找到它的inode呢？首先会调用根目录inode
	的i_op一＞lookup(）找到home的dentry，然后调用home目录inode的
	i_op一＞lookup(）找到test的dentry，接着再调用test目录inode的
	i_op->lookup(）找到test.c的dentry，从这个dentry自然就可以获得
	test.c的inode
	*/
	struct dentry * (*lookup) (struct inode *,struct dentry *, struct nameidata *);
	 /* 创建一个新的名为new_dentry的硬链接，它指向dir目录下名为old_dentry的文件。 */
	/*
	创建硬链接（hard link)，日录的inode应该提供这个函数。硬链接和原始文件
	必须位于同一个文件系统，它们共享同一个inode，原始文件被删除后，因为硬链接
	仍然存在，所以该文件仍然存在，可以通过硬链接去读取它，只有当其所有的硬链接
	都被删除，即它的引用计数为0时（每添加一个硬链接引用计数加1，删除一个硬链接
	计数器减1)，该文件才会被删除。系统调用link()可以用来创建硬链接，它会调用
	i_op->link(）完成这个工作，传递的第一个参数为原始文件的dentry，第二个参数
	为所产生的link所在目录的inode，第三个参数为硬链接文件的dentry
	*/
	int (*link) (struct dentry *,struct inode *,struct dentry *);
	  /* 从一个目录中删除目录项对象所指定文件的硬链接。	  
	  从一个日录中删除指定文件的硬链接，日录的inode应该提供这个函数。硬链接引用
	  的是文件的物理数据，而符号链接引用的则是文件在文件系统中的位置，如果原始文件
	  被删除，它所有的符号连接也会被破坏。系统调用unlink()可以用来删除文件，它会
	  去调用i_op->unlink()，传递的第一个参数为硬链接所在目录的inode，第二个参
	  数为要删除文件的dentry，它至少会把指定文件的引用计数减1
	  */
	int (*unlink) (struct inode *,struct dentry *);
	  /* 在某个目录下，为与目录项对象相关的符号链接创建一个新的索引节点。	  
	  创建符号连接，目录的inode应该提供这个函数。它会被系统调用symlink()调用，
	  第一个参数为符号连接所在日录的inode，第一二个参数为所创建的符号连接本身的
	  dentry，第三个参数则指定了符号链接的内容，通常是一个路径名称
	  */
	int (*symlink) (struct inode *,struct dentry *,const char *);
	  /* 在某个目录下，为与目录项对象相关的目录创建一个新的索引节点。
	  创建新目录,会被系统调用mkdir()调用，第一个参数表示要产生的目录所在的目录
	  第二个参数指的是要产生的目录，第三个参数则是目录的权限。在代表目录的inode
	  里，i_nlink字段表示目录中有几个文件或子目录，所以目录刚被创建时，它的
	  i_nlink为2，有两个子目录“.”和“..”
	  */
	int (*mkdir) (struct inode *,struct dentry *,int);
	  /**
	 * 移除目录。
	 */
	int (*rmdir) (struct inode *,struct dentry *);
	  	/**
	 * 为特定设备文件创建一个索引节点。	 
	 创建特殊文件（设备文件、管道、套接字等），会被系统调用mknod()调用。它会在
	 第一个参数指定的目录下产生一个inode，初始模式由第三个参数指定，如果要产生
	 的文件是设备文件，那么第四个参数就是该设备的标识符
	 */
	int (*mknod) (struct inode *,struct dentry *,int,dev_t);
		 /* 将old_dir目录下由old_entry标识的文件移到new_dir目录下。
  * 新文件名包含在new_dentry指向的目录项对象中。
将旧目录（第一个参数）下的源文件（第二个参数）移动到新目录（第三个参数）,
并更改为目标文件（第四个参数），旧目录inode的i_nlink应该减1，新目录inode
的i_nlink应该加1

*/
	int (*rename) (struct inode *old_dir, struct dentry *old_entry,
			struct inode *new_dir, struct dentry *new_dentry);
	/* 将目录项所指定的符号链接中对应的文件路径名拷贝到buffer所指定的用户态内存区。	
	当inode是一个符号链接时，它需要提供这个函数。readlink(）读取指定符号连接
	（第一个参数）的数据到特定的缓冲区（第二个参数），读取数据的最大长度不超过第
	三个参数指定的长度
	*/
	int (*readlink) (struct dentry *, char __user *,int);
	 /* 解析索引节点对象所指定的符号链接；如果该符号链接是一个相对路径名，
  * 则从第二个参数所指定的目录开始进行查找。
一个符号链接查找它指向的索引节点，与readlink()一样，如果inode是一个
符号链接时，它需要提供这个函数。比如当我们读取符号连接a时，如果a指向文件
/home/tmp/test.c，那么我们事实上会读到文件/home/tmp/test.c，这个解析
符号链接的工作就由follow_link(）完成。Follow_link()返回一个可以传递给
Put_link(）的指针

*/
	void * (*follow_link) (struct dentry *, struct nameidata *);
	/* 释放由follow_link方法分配的用于解析符号链接的所有临时数据结构。 */
	void (*put_link) (struct dentry *, struct nameidata *, void *);
	 /* 修改与索引节点相关的文件长度。在调用该方法之前，
  * 必须将inode对象的i_size字段设置为需要的新长度值。 */
	void (*truncate) (struct inode *);
	/* 检查是否允许对与索引节点所指的文件进行指定模式的访问。 */
	int (*permission) (struct inode *, int, struct nameidata *);
		/**
	 * 修改文件属性。
	 */
	int (*setattr) (struct dentry *, struct iattr *);
		/* 由一些文件系统用于读取索引节点属性。获取inode属性 */
	int (*getattr) (struct vfsmount *mnt, struct dentry *, struct kstat *);
		/* 为索引节点设置“扩展属性”（扩展属性存放在任何索引节点之外的磁盘块中）。		
		为指定的文件（第一个参数）设置特定的扩展属性。扩展属性（xattr）允许用户将
		文件与未被文件系统所解释的信息关联起来，与之相对应的是经过文件系统严格定义的
		正规文件属性，比如文件创建和修改的事件等。扩展文件属性的典型应用包括文件作者、
		文件编码等。每个扩展属性由一个名字和与之相关联的数据组成
		*/
	int (*setxattr) (struct dentry *, const char *,const void *,size_t,int);
	 /* 获取索引节点的扩展属性。 */
	ssize_t (*getxattr) (struct dentry *, const char *, void *, size_t);
	/* 获取扩展属性名称的整个链表。
	列出指定文件的所有扩展属性
	*/
	ssize_t (*listxattr) (struct dentry *, char *, size_t);
	/**
	 * 删除索引节点的扩展属性。
	 */
	int (*removexattr) (struct dentry *, const char *);
	//截去文件中一个连续的区域(指定范围的block)
	void (*truncate_range)(struct inode *, loff_t, loff_t);
	//为文件预分配磁盘空间，可参看http://lwn.net/Articles/226710/
	long (*fallocate)(struct inode *inode, int mode, loff_t offset,
			  loff_t len);
};

struct seq_file;

ssize_t rw_copy_check_uvector(int type, const struct iovec __user * uvector,
				unsigned long nr_segs, unsigned long fast_segs,
				struct iovec *fast_pointer,
				struct iovec **ret_pointer);

extern ssize_t vfs_read(struct file *, char __user *, size_t, loff_t *);
extern ssize_t vfs_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t vfs_readv(struct file *, const struct iovec __user *,
		unsigned long, loff_t *);
extern ssize_t vfs_writev(struct file *, const struct iovec __user *,
		unsigned long, loff_t *);

/*
 * NOTE: write_inode, delete_inode, clear_inode, put_inode can be called
 * without the big kernel lock held in all filesystems.
 */
struct super_operations {
	/* 为索引节点对象分配空间，包括具体文件系统的数据所需要的空间。 */
//创建和初始化一个新的索引节点对象
   	struct inode *(*alloc_inode)(struct super_block *sb);
	/* 撤销索引节点对象，包括具体文件系统的数据。 */
		//释放inode 结构
	void (*destroy_inode)(struct inode *);
	/* 用磁盘上的数据填充以参数传递过来的索引节点对象的字段；
	   索引节点对象的i_ino字段标识从磁盘上要读取的具体文件系统的索引节点。
	   读取一个inode，并使用它填充参数指向的inode。只会被iget()调用，通常不会
	直接调用read_inode()，而是调用iget()返回所要的inode。那么read_inode
	又是如何知道读取哪一个ioode？在read_inode被调用前，VFS会先在inode
	对象中填入一些信息，比如i_ino。字段，以便readinode能够获悉需要读取哪一个inode
	   */
		//从磁盘上读取指定的inode 结构，并初始化inode 结构
	//inode 号由该结构的 i_ino成员指定
	void (*read_inode) (struct inode *);
    /* 当索引节点标记为修改（脏）时调用。
  * 像ReiserFS和Ext3这样的文件系统用它来更新磁盘上的文件系统日志。*/
		//当inode被修改后调用
   	void (*dirty_inode) (struct inode *);
	/* 用通过传递参数指定的索引节点对象的内容更新一个文件系统的索引节点。
  * 索引节点对象的i_ino字段标识所涉及磁盘上文件系统的索引节点。
  * flag参数表示I/O操作是否应当同步。*/
	int (*write_inode) (struct inode *, int);
	 /* 释放索引节点时调用（减少该节点引用计数器值）以执行具体文件系统操作。*/
	/*
释放inode时调用。与read_inode(）相对应，基本上调用一次read_inode()
就需要调用一次put_inode(）。put_inode(）只会被iput(）调用，iput()
减少inode的引用计数，当该inode的引用计数减少到0时，就会调用ipu_final()
将其释放
*/
	void (*put_inode) (struct inode *);
	  /* 在即将撤消索引节点时调用——也就是说，
  * 当最后一个用户释放该索引节点时；
  * 实现该方法的文件系统通常使用generic_drop_inode()函数。
  * 该函数从VFS数据结构中移走对索引节点的每一个引用，
  * 如果索引节点不再出现在任何目录中，
  * 则调用超级块方法delete_inode将它从文件系统中删除。只会被iput_final调用*/
	//当inode 的引用计数为0时，用来删除 inode在内存中的结构
	void (*drop_inode) (struct inode *);
	 /* 在必须撤消索引节点时调用。删除内存中的VFS索引节点和磁盘上的文件数据及元数据。	
	释放内存中的inode，并且将其从磁盘上删除。inode的引用计数为0时，它所占用
	的内存会被释放，如果此时它的硬链接个数（inode->1nlink）也为0，就会调用
	delete_inode(）将其从磁盘上删除
	*/
	//删除 inode，包括内存中的 inode结构和磁盘上的结构
	void (*delete_inode) (struct inode *);
	  /* 释放通过传递的参数指定的超级块对象（因为相应的文件系统被卸载）。*/
		//释放超级块
	void (*put_super) (struct super_block *);
	  /* 用指定对象的内容更新文件系统的超级块。
	 	将超级块写回磁盘，更新磁盘上的超级块。Write_super最后应该将s_dirt
设为0,表示这个超级块不再是脏的。另外，write_super(）应该要检查文件系统
是否被mounte成只读（检查s_flags是否设置了MS_RDONLY标志），如果是的话
就不需要做什么工作了
	 	*/
	 	//在磁盘上写入超级块
	void (*write_super) (struct super_block *);
	  /* 在清除文件系统来更新磁盘上的具体文件系统数据结构时调用（由日志文件系统使用）。*/
		//把文件写入磁盘时，更新文件系统的特定结构
	int (*sync_fs)(struct super_block *sb, int wait);
	 /* 阻塞对文件系统的修改并用指定对象的内容更新超级块。
  * 当文件系统被冻结时调用该方法，例如，由逻辑卷管理器驱动程序（LVM）调用。*/
	void (*write_super_lockfs) (struct super_block *);
	 /* 取消由write_super_lockfs()超级块方法实现的对文件系统更新的阻塞，锁定。*/
	void (*unlockfs) (struct super_block *);
	  /* 将文件系统的统计信息返回，填写在buf缓冲区中。*/
		//获取文件系统信息
	int (*statfs) (struct dentry *, struct kstatfs *);
	 /* 用新的选项重新安装文件系统（当某个安装选项必须被修改时被调用
	使用新的选项重新mount文件系统。当一个文件系统已经被mount之后，如果我们
希望改变之前mount时设定的参数，可以重新执行“mount”命令，并在其-o参数
后添加remount。基本上，remount所造成的参数改变，VFS会帮我们做好，只是
为了怕参数的改变会对文件系统本身造成行为上的改变，所以此时会调用
Remount_fs()告诉文件系统用户要改变mount的参数，如果该文件系统有需要，可以在remount_fs中做适当的处理。
	*/
	//重新挂载这个设备，通常在 shell中运行 mount命令
	//并指定remount属性时会调用该函数
	int (*remount_fs) (struct super_block *, int *, char *);
	 /* 当撤消磁盘索引节点执行具体文件系统操作时调用。只会被VFS提供的clear_inode调用*/
	void (*clear_inode) (struct inode *);
	  /* 中断一个安装操作，因为相应的卸载操作已经开始（只在网络文件系统中使用）。*/
	void (*umount_begin) (struct vfsmount *, int);
	 /* 用来显示特定文件系统的选项。*/
		//获取文件系统属性
	int (*show_options)(struct seq_file *, struct vfsmount *);
	/* 用来显示特定文件系统的状态。显示文件系统安装点的统计信息*/
	int (*show_stats)(struct seq_file *, struct vfsmount *);
#ifdef CONFIG_QUOTA
	 /* 限额系统使用该方法从文件中读取数据，该文件详细说明了所在文件系统的限制。*/
	ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
	/* 限额系统使用该方法将数据写入文件中，该文件详细说明了所在文件系统的限制。*/
	ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
#endif
};

/*
 * Inode state bits.  Protected by inode_lock.
 *
 * Three bits determine the dirty state of the inode, I_DIRTY_SYNC,
 * I_DIRTY_DATASYNC and I_DIRTY_PAGES.
 *
 * Four bits define the lifetime of an inode.  Initially, inodes are I_NEW,
 * until that flag is cleared.  I_WILL_FREE, I_FREEING and I_CLEAR are set at
 * various stages of removing an inode.
 *
 * Two bits are used for locking and completion notification, I_LOCK and I_SYNC.
 *
 * I_DIRTY_SYNC		Inode itself is dirty.
 * I_DIRTY_DATASYNC	Data-related inode changes pending
 * I_DIRTY_PAGES	Inode has dirty pages.  Inode itself may be clean.
 * I_NEW		get_new_inode() sets i_state to I_LOCK|I_NEW.  Both
 *			are cleared by unlock_new_inode(), called from iget().
 * I_WILL_FREE		Must be set when calling write_inode_now() if i_count
 *			is zero.  I_FREEING must be set when I_WILL_FREE is
 *			cleared.
 * I_FREEING		Set when inode is about to be freed but still has dirty
 *			pages or buffers attached or the inode itself is still
 *			dirty.
 * I_CLEAR		Set by clear_inode().  In this state the inode is clean
 *			and can be destroyed.
 *
 *			Inodes that are I_WILL_FREE, I_FREEING or I_CLEAR are
 *			prohibited for many purposes.  iget() must wait for
 *			the inode to be completely released, then create it
 *			anew.  Other functions will just ignore such inodes,
 *			if appropriate.  I_LOCK is used for waiting.
 *
 * I_LOCK		Serves as both a mutex and completion notification.
 *			New inodes set I_LOCK.  If two processes both create
 *			the same inode, one of them will release its inode and
 *			wait for I_LOCK to be released before returning.
 *			Inodes in I_WILL_FREE, I_FREEING or I_CLEAR state can
 *			also cause waiting on I_LOCK, without I_LOCK actually
 *			being set.  find_inode() uses this to prevent returning
 *			nearly-dead inodes.
 * I_SYNC		Similar to I_LOCK, but limited in scope to writeback
 *			of inode dirty data.  Having a seperate lock for this
 *			purpose reduces latency and prevents some filesystem-
 *			specific deadlocks.
 *
 * Q: Why does I_DIRTY_DATASYNC exist?  It appears as if it could be replaced
 *    by (I_DIRTY_SYNC|I_DIRTY_PAGES).
 * Q: What is the difference between I_WILL_FREE and I_FREEING?
 * Q: igrab() only checks on (I_FREEING|I_WILL_FREE).  Should it also check on
 *    I_CLEAR?  If not, why?
 */
#define I_DIRTY_SYNC		1
#define I_DIRTY_DATASYNC	2
#define I_DIRTY_PAGES		4
#define I_NEW			8
#define I_WILL_FREE		16
#define I_FREEING		32
#define I_CLEAR			64
#define __I_LOCK		7
#define I_LOCK			(1 << __I_LOCK)
#define __I_SYNC		8
#define I_SYNC			(1 << __I_SYNC)

#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)

extern void __mark_inode_dirty(struct inode *, int);
static inline void mark_inode_dirty(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY);
}

static inline void mark_inode_dirty_sync(struct inode *inode)
{
	__mark_inode_dirty(inode, I_DIRTY_SYNC);
}

/**
 * inc_nlink - directly increment an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  Currently,
 * it is only here for parity with dec_nlink().
 */
static inline void inc_nlink(struct inode *inode)
{
	inode->i_nlink++;
}

static inline void inode_inc_link_count(struct inode *inode)
{
	inc_nlink(inode);
	mark_inode_dirty(inode);
}

/**
 * drop_nlink - directly drop an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  In cases
 * where we are attempting to track writes to the
 * filesystem, a decrement to zero means an imminent
 * write when the file is truncated and actually unlinked
 * on the filesystem.
 */
static inline void drop_nlink(struct inode *inode)
{
	inode->i_nlink--;
}

/**
 * clear_nlink - directly zero an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  See
 * drop_nlink() for why we care about i_nlink hitting zero.
 */
static inline void clear_nlink(struct inode *inode)
{
	inode->i_nlink = 0;
}

static inline void inode_dec_link_count(struct inode *inode)
{
	drop_nlink(inode);
	mark_inode_dirty(inode);
}

extern void touch_atime(struct vfsmount *mnt, struct dentry *dentry);
static inline void file_accessed(struct file *file)
{
	if (!(file->f_flags & O_NOATIME))
		touch_atime(file->f_path.mnt, file->f_path.dentry);
}

int sync_inode(struct inode *inode, struct writeback_control *wbc);

struct file_system_type {
	//文件系统的名字，不能为NULL，否则无法使用mount命令进行安装
	const char *name;
	/*	
	文件系统类型标志的bitmap，相关标志定义在include/linux/fs.h文件中：
	FS_REQUIRES_DEV：表示该文件系统建立在实际的物理磁盘之上(proc文件系统	只存在于内存),比如Ext2、MINIX等。	
	FS_BINARY_MOUNTDATA：告诉selinux(Security-Enhanced Linux）代码
	mount的数据是二进制的，不能被标准的选项解析器（option parser）处理。在coda、SMBFS、NFS等文件系统中有使用。
	FS_HAS_SUBTYPE：表示该文件系统有子类型，FUSE中有使用，主要是为了解决
基于FUSE的文件系统的描述问题而引入。从内核的角度看，FUSE相关的仅有两种文
件系统类型―FUSE和FUSEBLK，但从用户的角度看，有很多种文件系统类型，他们
并不关心这些文件系统类型是否是基于FUSE的。旧的描述方式在mount·些这样的
文件系统时会产生问题，因此内核引入了子文件系统类型，使用type.subtype的方
式描述一个基于FUSE的文件系统。
	FS_REVAL_DOT：告诉vFS使“.”、“..”等路径重新生效（revalidate)，因
	为它们可能已经无效（stale）了。NFS中有使用。	
	FS_RENAME_DOES_D_MOVE：表示具体的文件系统将在rename期间处理
	dmove。在NFS、OCFS2中有使用。
	*/
	int fs_flags;
	/*	
	在安装文件系统时，会调用get_sb从磁盘中获取超级块。这个函数必须提供，
	它主要是通过调用get_sb_bdev(),get_sb_single(),get_sb_nodev等函数完成工作
	*/
		//超级块初始化函数指针
	int (*get_sb) (struct file_system_type *, int,
		       const char *, void *, struct vfsmount *);
	//卸载文件系统时，会调用kill_sb进行一些清理工作。这个函数必须提供，它主要
	//是通过kill_block_super,kill_anon_super,kill_litter_super等函数完成工作
	//释放超级块函数指针
	void (*kill_sb) (struct super_block *);
	//指向拥有这个结构的模块，如果一个文件系统被编译进内核，则该字段为NULL
	struct module *owner;
	/*
	形成文件系统类型链表。在fs/filesystem.c文件中定义了一个全局变量
file_systems，它就是所有己注册（注意不是已安装）的文件系统类型链表的头。
register_filesystem通过next字段将一个文件系统类型添加到这个链表里，
unregister_filesystem(）将一个文件系统类型从这个链表里删除。
	*/
	struct file_system_type * next;
	//同一种文件类型的超级块形成一个链表，fs_supers是这个链表的头
	struct list_head fs_supers;
	/*
	如果编译内核时没有配置CONFIG_LOCKDEP选项，s_lock_key和s_umount_key将不占用内存空间
	*/
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;

	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key i_mutex_dir_key;
	struct lock_class_key i_alloc_sem_key;
};

extern int get_sb_bdev(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data,
	int (*fill_super)(struct super_block *, void *, int),
	struct vfsmount *mnt);
extern int get_sb_single(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int),
	struct vfsmount *mnt);
extern int get_sb_nodev(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int),
	struct vfsmount *mnt);
void generic_shutdown_super(struct super_block *sb);
void kill_block_super(struct super_block *sb);
void kill_anon_super(struct super_block *sb);
void kill_litter_super(struct super_block *sb);
void deactivate_super(struct super_block *sb);
int set_anon_super(struct super_block *s, void *data);
struct super_block *sget(struct file_system_type *type,
			int (*test)(struct super_block *,void *),
			int (*set)(struct super_block *,void *),
			void *data);
extern int get_sb_pseudo(struct file_system_type *, char *,
	const struct super_operations *ops, unsigned long,
	struct vfsmount *mnt);
extern int simple_set_mnt(struct vfsmount *mnt, struct super_block *sb);
int __put_super(struct super_block *sb);
int __put_super_and_need_restart(struct super_block *sb);
void unnamed_dev_init(void);

/* Alas, no aliases. Too much hassle with bringing module.h everywhere */
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)

extern int register_filesystem(struct file_system_type *);
extern int unregister_filesystem(struct file_system_type *);
extern struct vfsmount *kern_mount_data(struct file_system_type *, void *data);
#define kern_mount(type) kern_mount_data(type, NULL)
extern int may_umount_tree(struct vfsmount *);
extern int may_umount(struct vfsmount *);
extern void umount_tree(struct vfsmount *, int, struct list_head *);
extern void release_mounts(struct list_head *);
extern long do_mount(char *, char *, char *, unsigned long, void *);
extern struct vfsmount *copy_tree(struct vfsmount *, struct dentry *, int);
extern void mnt_set_mountpoint(struct vfsmount *, struct dentry *,
				  struct vfsmount *);
extern struct vfsmount *collect_mounts(struct vfsmount *, struct dentry *);
extern void drop_collected_mounts(struct vfsmount *);

extern int vfs_statfs(struct dentry *, struct kstatfs *);

/* /sys/fs */
extern struct kset fs_subsys;

#define FLOCK_VERIFY_READ  1
#define FLOCK_VERIFY_WRITE 2

extern int locks_mandatory_locked(struct inode *);
extern int locks_mandatory_area(int, struct inode *, struct file *, loff_t, size_t);

/*
 * Candidates for mandatory locking have the setgid bit set
 * but no group execute bit -  an otherwise meaningless combination.
 */

static inline int __mandatory_lock(struct inode *ino)
{
	return (ino->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID;
}

/*
 * ... and these candidates should be on MS_MANDLOCK mounted fs,
 * otherwise these will be advisory locks
 */

static inline int mandatory_lock(struct inode *ino)
{
	return IS_MANDLOCK(ino) && __mandatory_lock(ino);
}

static inline int locks_verify_locked(struct inode *inode)
{
	if (mandatory_lock(inode))
		return locks_mandatory_locked(inode);
	return 0;
}

extern int rw_verify_area(int, struct file *, loff_t *, size_t);

static inline int locks_verify_truncate(struct inode *inode,
				    struct file *filp,
				    loff_t size)
{
	if (inode->i_flock && mandatory_lock(inode))
		return locks_mandatory_area(
			FLOCK_VERIFY_WRITE, inode, filp,
			size < inode->i_size ? size : inode->i_size,
			(size < inode->i_size ? inode->i_size - size
			 : size - inode->i_size)
		);
	return 0;
}

static inline int break_lease(struct inode *inode, unsigned int mode)
{
	if (inode->i_flock)
		return __break_lease(inode, mode);
	return 0;
}

/* fs/open.c */

extern int do_truncate(struct dentry *, loff_t start, unsigned int time_attrs,
		       struct file *filp);
extern long do_sys_open(int dfd, const char __user *filename, int flags,
			int mode);
extern struct file *filp_open(const char *, int, int);
extern struct file * dentry_open(struct dentry *, struct vfsmount *, int);
extern int filp_close(struct file *, fl_owner_t id);
extern char * getname(const char __user *);

/* fs/dcache.c */
extern void __init vfs_caches_init_early(void);
extern void __init vfs_caches_init(unsigned long);

extern struct kmem_cache *names_cachep;

#define __getname()	kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define __putname(name) kmem_cache_free(names_cachep, (void *)(name))
#ifndef CONFIG_AUDITSYSCALL
#define putname(name)   __putname(name)
#else
extern void putname(const char *name);
#endif

#ifdef CONFIG_BLOCK
extern int register_blkdev(unsigned int, const char *);
extern void unregister_blkdev(unsigned int, const char *);
extern struct block_device *bdget(dev_t);
extern void bd_set_size(struct block_device *, loff_t size);
extern void bd_forget(struct inode *inode);
extern void bdput(struct block_device *);
extern struct block_device *open_by_devnum(dev_t, unsigned);
extern const struct address_space_operations def_blk_aops;
#else
static inline void bd_forget(struct inode *inode) {}
#endif
extern const struct file_operations def_blk_fops;
extern const struct file_operations def_chr_fops;
extern const struct file_operations bad_sock_fops;
extern const struct file_operations def_fifo_fops;
#ifdef CONFIG_BLOCK
extern int ioctl_by_bdev(struct block_device *, unsigned, unsigned long);
extern int blkdev_ioctl(struct inode *, struct file *, unsigned, unsigned long);
extern int blkdev_driver_ioctl(struct inode *inode, struct file *file,
			       struct gendisk *disk, unsigned cmd,
			       unsigned long arg);
extern long compat_blkdev_ioctl(struct file *, unsigned, unsigned long);
extern int blkdev_get(struct block_device *, mode_t, unsigned);
extern int blkdev_put(struct block_device *);
extern int bd_claim(struct block_device *, void *);
extern void bd_release(struct block_device *);
#ifdef CONFIG_SYSFS
extern int bd_claim_by_disk(struct block_device *, void *, struct gendisk *);
extern void bd_release_from_disk(struct block_device *, struct gendisk *);
#else
#define bd_claim_by_disk(bdev, holder, disk)	bd_claim(bdev, holder)
#define bd_release_from_disk(bdev, disk)	bd_release(bdev)
#endif
#endif

/* fs/char_dev.c */
#define CHRDEV_MAJOR_HASH_SIZE	255
extern int alloc_chrdev_region(dev_t *, unsigned, unsigned, const char *);
extern int register_chrdev_region(dev_t, unsigned, const char *);
extern int register_chrdev(unsigned int, const char *,
			   const struct file_operations *);
extern void unregister_chrdev(unsigned int, const char *);
extern void unregister_chrdev_region(dev_t, unsigned);
extern int chrdev_open(struct inode *, struct file *);
extern void chrdev_show(struct seq_file *,off_t);

/* fs/block_dev.c */
#define BDEVNAME_SIZE	32	/* Largest string for a blockdev identifier */

#ifdef CONFIG_BLOCK
#define BLKDEV_MAJOR_HASH_SIZE	255
extern const char *__bdevname(dev_t, char *buffer);
extern const char *bdevname(struct block_device *bdev, char *buffer);
extern struct block_device *lookup_bdev(const char *);
extern struct block_device *open_bdev_excl(const char *, int, void *);
extern void close_bdev_excl(struct block_device *);
extern void blkdev_show(struct seq_file *,off_t);
#else
#define BLKDEV_MAJOR_HASH_SIZE	0
#endif

extern void init_special_inode(struct inode *, umode_t, dev_t);

/* Invalid inode operations -- fs/bad_inode.c */
extern void make_bad_inode(struct inode *);
extern int is_bad_inode(struct inode *);

extern const struct file_operations read_fifo_fops;
extern const struct file_operations write_fifo_fops;
extern const struct file_operations rdwr_fifo_fops;

extern int fs_may_remount_ro(struct super_block *);

#ifdef CONFIG_BLOCK
/*
 * return READ, READA, or WRITE
 */
#define bio_rw(bio)		((bio)->bi_rw & (RW_MASK | RWA_MASK))

/*
 * return data direction, READ or WRITE
 */
#define bio_data_dir(bio)	((bio)->bi_rw & 1)

extern int check_disk_change(struct block_device *);
extern int __invalidate_device(struct block_device *);
extern int invalidate_partition(struct gendisk *, int);
#endif
extern int invalidate_inodes(struct super_block *);
unsigned long __invalidate_mapping_pages(struct address_space *mapping,
					pgoff_t start, pgoff_t end,
					bool be_atomic);
unsigned long invalidate_mapping_pages(struct address_space *mapping,
					pgoff_t start, pgoff_t end);

static inline unsigned long __deprecated
invalidate_inode_pages(struct address_space *mapping)
{
	return invalidate_mapping_pages(mapping, 0, ~0UL);
}

static inline void invalidate_remote_inode(struct inode *inode)
{
	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	    S_ISLNK(inode->i_mode))
		invalidate_mapping_pages(inode->i_mapping, 0, -1);
}
extern int invalidate_inode_pages2(struct address_space *mapping);
extern int invalidate_inode_pages2_range(struct address_space *mapping,
					 pgoff_t start, pgoff_t end);
extern int write_inode_now(struct inode *, int);
extern int filemap_fdatawrite(struct address_space *);
extern int filemap_flush(struct address_space *);
extern int filemap_fdatawait(struct address_space *);
extern int filemap_write_and_wait(struct address_space *mapping);
extern int filemap_write_and_wait_range(struct address_space *mapping,
				        loff_t lstart, loff_t lend);
extern int wait_on_page_writeback_range(struct address_space *mapping,
				pgoff_t start, pgoff_t end);
extern int __filemap_fdatawrite_range(struct address_space *mapping,
				loff_t start, loff_t end, int sync_mode);

extern long do_fsync(struct file *file, int datasync);
extern void sync_supers(void);
extern void sync_filesystems(int wait);
extern void __fsync_super(struct super_block *sb);
extern void emergency_sync(void);
extern void emergency_remount(void);
extern int do_remount_sb(struct super_block *sb, int flags,
			 void *data, int force);
#ifdef CONFIG_BLOCK
extern sector_t bmap(struct inode *, sector_t);
#endif
extern int notify_change(struct dentry *, struct iattr *);
extern int permission(struct inode *, int, struct nameidata *);
extern int generic_permission(struct inode *, int,
		int (*check_acl)(struct inode *, int));

extern int get_write_access(struct inode *);
extern int deny_write_access(struct file *);
static inline void put_write_access(struct inode * inode)
{
	atomic_dec(&inode->i_writecount);
}
static inline void allow_write_access(struct file *file)
{
	if (file)
		atomic_inc(&file->f_path.dentry->d_inode->i_writecount);
}
extern int do_pipe(int *);
extern struct file *create_read_pipe(struct file *f);
extern struct file *create_write_pipe(void);
extern void free_write_pipe(struct file *);

extern int open_namei(int dfd, const char *, int, int, struct nameidata *);
extern int may_open(struct nameidata *, int, int);

extern int kernel_read(struct file *, unsigned long, char *, unsigned long);
extern struct file * open_exec(const char *);
 
/* fs/dcache.c -- generic fs support functions */
extern int is_subdir(struct dentry *, struct dentry *);
extern ino_t find_inode_number(struct dentry *, struct qstr *);

#include <linux/err.h>

/* needed for stackable file system support */
extern loff_t default_llseek(struct file *file, loff_t offset, int origin);

extern loff_t vfs_llseek(struct file *file, loff_t offset, int origin);

extern void inode_init_once(struct inode *);
extern void iput(struct inode *);
extern struct inode * igrab(struct inode *);
extern ino_t iunique(struct super_block *, ino_t);
extern int inode_needs_sync(struct inode *inode);
extern void generic_delete_inode(struct inode *inode);
extern void generic_drop_inode(struct inode *inode);

extern struct inode *ilookup5_nowait(struct super_block *sb,
		unsigned long hashval, int (*test)(struct inode *, void *),
		void *data);
extern struct inode *ilookup5(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data);
extern struct inode *ilookup(struct super_block *sb, unsigned long ino);

extern struct inode * iget5_locked(struct super_block *, unsigned long, int (*test)(struct inode *, void *), int (*set)(struct inode *, void *), void *);
extern struct inode * iget_locked(struct super_block *, unsigned long);
extern void unlock_new_inode(struct inode *);

static inline struct inode *iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode = iget_locked(sb, ino);
	
	if (inode && (inode->i_state & I_NEW)) {
		sb->s_op->read_inode(inode);
		unlock_new_inode(inode);
	}

	return inode;
}

extern void __iget(struct inode * inode);
extern void clear_inode(struct inode *);
extern void destroy_inode(struct inode *);
extern struct inode *new_inode(struct super_block *);
extern int __remove_suid(struct dentry *, int);
extern int should_remove_suid(struct dentry *);
extern int remove_suid(struct dentry *);

extern void __insert_inode_hash(struct inode *, unsigned long hashval);
extern void remove_inode_hash(struct inode *);
static inline void insert_inode_hash(struct inode *inode) {
	__insert_inode_hash(inode, inode->i_ino);
}

extern struct file * get_empty_filp(void);
extern void file_move(struct file *f, struct list_head *list);
extern void file_kill(struct file *f);
#ifdef CONFIG_BLOCK
struct bio;
extern void submit_bio(int, struct bio *);
extern int bdev_read_only(struct block_device *);
#endif
extern int set_blocksize(struct block_device *, int);
extern int sb_set_blocksize(struct super_block *, int);
extern int sb_min_blocksize(struct super_block *, int);
extern int sb_has_dirty_inodes(struct super_block *);

extern int generic_file_mmap(struct file *, struct vm_area_struct *);
extern int generic_file_readonly_mmap(struct file *, struct vm_area_struct *);
extern int file_read_actor(read_descriptor_t * desc, struct page *page, unsigned long offset, unsigned long size);
int generic_write_checks(struct file *file, loff_t *pos, size_t *count, int isblk);
extern ssize_t generic_file_aio_read(struct kiocb *, const struct iovec *, unsigned long, loff_t);
extern ssize_t generic_file_aio_write(struct kiocb *, const struct iovec *, unsigned long, loff_t);
extern ssize_t generic_file_aio_write_nolock(struct kiocb *, const struct iovec *,
		unsigned long, loff_t);
extern ssize_t generic_file_direct_write(struct kiocb *, const struct iovec *,
		unsigned long *, loff_t, loff_t *, size_t, size_t);
extern ssize_t generic_file_buffered_write(struct kiocb *, const struct iovec *,
		unsigned long, loff_t, loff_t *, size_t, ssize_t);
extern ssize_t do_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos);
extern ssize_t do_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos);
extern void do_generic_mapping_read(struct address_space *mapping,
				    struct file_ra_state *, struct file *,
				    loff_t *, read_descriptor_t *, read_actor_t);
extern int generic_segment_checks(const struct iovec *iov,
		unsigned long *nr_segs, size_t *count, int access_flags);

/* fs/splice.c */
extern ssize_t generic_file_splice_read(struct file *, loff_t *,
		struct pipe_inode_info *, size_t, unsigned int);
extern ssize_t generic_file_splice_write(struct pipe_inode_info *,
		struct file *, loff_t *, size_t, unsigned int);
extern ssize_t generic_file_splice_write_nolock(struct pipe_inode_info *,
		struct file *, loff_t *, size_t, unsigned int);
extern ssize_t generic_splice_sendpage(struct pipe_inode_info *pipe,
		struct file *out, loff_t *, size_t len, unsigned int flags);
extern long do_splice_direct(struct file *in, loff_t *ppos, struct file *out,
		size_t len, unsigned int flags);

extern void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping);
extern loff_t no_llseek(struct file *file, loff_t offset, int origin);
extern loff_t generic_file_llseek(struct file *file, loff_t offset, int origin);
extern loff_t remote_llseek(struct file *file, loff_t offset, int origin);
extern int generic_file_open(struct inode * inode, struct file * filp);
extern int nonseekable_open(struct inode * inode, struct file * filp);

#ifdef CONFIG_FS_XIP
extern ssize_t xip_file_read(struct file *filp, char __user *buf, size_t len,
			     loff_t *ppos);
extern int xip_file_mmap(struct file * file, struct vm_area_struct * vma);
extern ssize_t xip_file_write(struct file *filp, const char __user *buf,
			      size_t len, loff_t *ppos);
extern int xip_truncate_page(struct address_space *mapping, loff_t from);
#else
static inline int xip_truncate_page(struct address_space *mapping, loff_t from)
{
	return 0;
}
#endif

static inline void do_generic_file_read(struct file * filp, loff_t *ppos,
					read_descriptor_t * desc,
					read_actor_t actor)
{
	do_generic_mapping_read(filp->f_mapping,
				&filp->f_ra,
				filp,
				ppos,
				desc,
				actor);
}

#ifdef CONFIG_BLOCK
ssize_t __blockdev_direct_IO(int rw, struct kiocb *iocb, struct inode *inode,
	struct block_device *bdev, const struct iovec *iov, loff_t offset,
	unsigned long nr_segs, get_block_t get_block, dio_iodone_t end_io,
	int lock_type);

enum {
	DIO_LOCKING = 1, /* need locking between buffered and direct access */
	DIO_NO_LOCKING,  /* bdev; no locking at all between buffered/direct */
	DIO_OWN_LOCKING, /* filesystem locks buffered and direct internally */
};

static inline ssize_t blockdev_direct_IO(int rw, struct kiocb *iocb,
	struct inode *inode, struct block_device *bdev, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs, get_block_t get_block,
	dio_iodone_t end_io)
{
	return __blockdev_direct_IO(rw, iocb, inode, bdev, iov, offset,
				nr_segs, get_block, end_io, DIO_LOCKING);
}

static inline ssize_t blockdev_direct_IO_no_locking(int rw, struct kiocb *iocb,
	struct inode *inode, struct block_device *bdev, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs, get_block_t get_block,
	dio_iodone_t end_io)
{
	return __blockdev_direct_IO(rw, iocb, inode, bdev, iov, offset,
				nr_segs, get_block, end_io, DIO_NO_LOCKING);
}

static inline ssize_t blockdev_direct_IO_own_locking(int rw, struct kiocb *iocb,
	struct inode *inode, struct block_device *bdev, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs, get_block_t get_block,
	dio_iodone_t end_io)
{
	return __blockdev_direct_IO(rw, iocb, inode, bdev, iov, offset,
				nr_segs, get_block, end_io, DIO_OWN_LOCKING);
}
#endif

extern const struct file_operations generic_ro_fops;

#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))

extern int vfs_readlink(struct dentry *, char __user *, int, const char *);
extern int vfs_follow_link(struct nameidata *, const char *);
extern int page_readlink(struct dentry *, char __user *, int);
extern void *page_follow_link_light(struct dentry *, struct nameidata *);
extern void page_put_link(struct dentry *, struct nameidata *, void *);
extern int __page_symlink(struct inode *inode, const char *symname, int len,
		gfp_t gfp_mask);
extern int page_symlink(struct inode *inode, const char *symname, int len);
extern const struct inode_operations page_symlink_inode_operations;
extern int generic_readlink(struct dentry *, char __user *, int);
extern void generic_fillattr(struct inode *, struct kstat *);
extern int vfs_getattr(struct vfsmount *, struct dentry *, struct kstat *);
void inode_add_bytes(struct inode *inode, loff_t bytes);
void inode_sub_bytes(struct inode *inode, loff_t bytes);
loff_t inode_get_bytes(struct inode *inode);
void inode_set_bytes(struct inode *inode, loff_t bytes);

extern int vfs_readdir(struct file *, filldir_t, void *);

extern int vfs_stat(char __user *, struct kstat *);
extern int vfs_lstat(char __user *, struct kstat *);
extern int vfs_stat_fd(int dfd, char __user *, struct kstat *);
extern int vfs_lstat_fd(int dfd, char __user *, struct kstat *);
extern int vfs_fstat(unsigned int, struct kstat *);

extern int vfs_ioctl(struct file *, unsigned int, unsigned int, unsigned long);

extern void get_filesystem(struct file_system_type *fs);
extern void put_filesystem(struct file_system_type *fs);
extern struct file_system_type *get_fs_type(const char *name);
extern struct super_block *get_super(struct block_device *);
extern struct super_block *user_get_super(dev_t);
extern void drop_super(struct super_block *sb);

extern int dcache_dir_open(struct inode *, struct file *);
extern int dcache_dir_close(struct inode *, struct file *);
extern loff_t dcache_dir_lseek(struct file *, loff_t, int);
extern int dcache_readdir(struct file *, void *, filldir_t);
extern int simple_getattr(struct vfsmount *, struct dentry *, struct kstat *);
extern int simple_statfs(struct dentry *, struct kstatfs *);
extern int simple_link(struct dentry *, struct inode *, struct dentry *);
extern int simple_unlink(struct inode *, struct dentry *);
extern int simple_rmdir(struct inode *, struct dentry *);
extern int simple_rename(struct inode *, struct dentry *, struct inode *, struct dentry *);
extern int simple_sync_file(struct file *, struct dentry *, int);
extern int simple_empty(struct dentry *);
extern int simple_readpage(struct file *file, struct page *page);
extern int simple_prepare_write(struct file *file, struct page *page,
			unsigned offset, unsigned to);
extern int simple_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata);
extern int simple_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata);

extern struct dentry *simple_lookup(struct inode *, struct dentry *, struct nameidata *);
extern ssize_t generic_read_dir(struct file *, char __user *, size_t, loff_t *);
extern const struct file_operations simple_dir_operations;
extern const struct inode_operations simple_dir_inode_operations;
struct tree_descr { char *name; const struct file_operations *ops; int mode; };
struct dentry *d_alloc_name(struct dentry *, const char *);
extern int simple_fill_super(struct super_block *, int, struct tree_descr *);
extern int simple_pin_fs(struct file_system_type *, struct vfsmount **mount, int *count);
extern void simple_release_fs(struct vfsmount **mount, int *count);

extern ssize_t simple_read_from_buffer(void __user *, size_t, loff_t *, const void *, size_t);

#ifdef CONFIG_MIGRATION
extern int buffer_migrate_page(struct address_space *,
				struct page *, struct page *);
#else
#define buffer_migrate_page NULL
#endif

extern int inode_change_ok(struct inode *, struct iattr *);
extern int __must_check inode_setattr(struct inode *, struct iattr *);

extern void file_update_time(struct file *file);

static inline ino_t parent_ino(struct dentry *dentry)
{
	ino_t res;

	spin_lock(&dentry->d_lock);
	res = dentry->d_parent->d_inode->i_ino;
	spin_unlock(&dentry->d_lock);
	return res;
}

/* kernel/fork.c */
extern int unshare_files(void);

/* Transaction based IO helpers */

/*
 * An argresp is stored in an allocated page and holds the
 * size of the argument or response, along with its content
 */
struct simple_transaction_argresp {
	ssize_t size;
	char data[0];
};

#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))

char *simple_transaction_get(struct file *file, const char __user *buf,
				size_t size);
ssize_t simple_transaction_read(struct file *file, char __user *buf,
				size_t size, loff_t *pos);
int simple_transaction_release(struct inode *inode, struct file *file);

static inline void simple_transaction_set(struct file *file, size_t n)
{
	struct simple_transaction_argresp *ar = file->private_data;

	BUG_ON(n > SIMPLE_TRANSACTION_LIMIT);

	/*
	 * The barrier ensures that ar->size will really remain zero until
	 * ar->data is ready for reading.
	 */
	smp_mb();
	ar->size = n;
}

/*
 * simple attribute files
 *
 * These attributes behave similar to those in sysfs:
 *
 * Writing to an attribute immediately sets a value, an open file can be
 * written to multiple times.
 *
 * Reading from an attribute creates a buffer from the value that might get
 * read with multiple read calls. When the attribute has been read
 * completely, no further read calls are possible until the file is opened
 * again.
 *
 * All attributes contain a text representation of a numeric value
 * that are accessed with the get() and set() functions.
 */
#define DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_close,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
};

static inline void __attribute__((format(printf, 1, 2)))
__simple_attr_check_format(const char *fmt, ...)
{
	/* don't do anything, just let the compiler check the arguments; */
}

int simple_attr_open(struct inode *inode, struct file *file,
		     u64 (*get)(void *), void (*set)(void *, u64),
		     const char *fmt);
int simple_attr_close(struct inode *inode, struct file *file);
ssize_t simple_attr_read(struct file *file, char __user *buf,
			 size_t len, loff_t *ppos);
ssize_t simple_attr_write(struct file *file, const char __user *buf,
			  size_t len, loff_t *ppos);


#ifdef CONFIG_SECURITY
static inline char *alloc_secdata(void)
{
	return (char *)get_zeroed_page(GFP_KERNEL);
}

static inline void free_secdata(void *secdata)
{
	free_page((unsigned long)secdata);
}
#else
static inline char *alloc_secdata(void)
{
	return (char *)1;
}

static inline void free_secdata(void *secdata)
{ }
#endif	/* CONFIG_SECURITY */

struct ctl_table;
int proc_nr_files(struct ctl_table *table, int write, struct file *filp,
		  void __user *buffer, size_t *lenp, loff_t *ppos);


#endif /* __KERNEL__ */
#endif /* _LINUX_FS_H */
