/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 * Version: $Id: mount.h,v 2.0 1996/11/17 16:48:14 mvw Exp mvw $
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H
#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;

#define MNT_NOSUID	0x01
#define MNT_NODEV	0x02
#define MNT_NOEXEC	0x04
#define MNT_NOATIME	0x08
#define MNT_NODIRATIME	0x10
#define MNT_RELATIME	0x20

#define MNT_SHRINKABLE	0x100

#define MNT_SHARED	0x1000	/* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE	0x2000	/* if the vfsmount is a unbindable mount */
#define MNT_PNODE_MASK	0x3000	/* propagation flag mask */

struct vfsmount {
	/**
		vfsmount实例的地址和相关的dentry对象的地址用来计算散列和
		 * 用于散列表链表的指针。
		 内核使用了mount_hashtable（定义在文件fs/namespace.c）对vfsmount结构
进行管理，mount_hashtable是由list_head组成的链表。一个vfsmount一经
创建，就会通过它的mnt_hash挂入mount_hashtable中对应哈希值的链表里
	*/
	struct list_head mnt_hash;
	/**
	 * 指向父文件系统，这个文件系统安装在其上。
	 */
	struct vfsmount *mnt_parent;	/* fs we are mounted on */
	/**
	 * 安装点目录节点。
	 安装点的dentry,mnt_mountpoint和mnt_parent分别是父文件系统的dentry和vfsmount
	 */
	struct dentry *mnt_mountpoint;	/* dentry of mountpoint */
	/**
	 * 指向这个文件系统根目录的dentry。
	 */
	struct dentry *mnt_root;	/* root of the mounted tree */
	/**
	 * 该文件系统的超级块对象。
	 */
	struct super_block *mnt_sb;	/* pointer to superblock */
	/**
	 * 子挂载点链表表头	 
	 mnt_mounts是子文件系统链表的头，同一父文件系统的所有文件系统通过
	 mnt_child形成一个链表。比如，系统的文件系统是Ext3，在/mnt/hda、
	 /mnt/usb目录下分别安装了文件系统a、b，这样系统就为新安装的a、b分配
	 vfsmount结构，并将它们的mnt_parent指向该Ext3文件系统的vfsmount结构，
	 a和b通过mnt_child挂入该Ext3文件系统的mnt_mounts链表。next_mnt()
	 实现了对mount树的遍历
	 */
	struct list_head mnt_mounts;	/* list of children, anchored here */
	/**
	 * 已安装文件系统链表头。通过此字段将其加入父文件系统的mnt_mounts链表中。
	 */
	struct list_head mnt_child;	/* and going through their mnt_child */
	/**
	 * mount标志	 
	 mount时指定的标志，可用的标志定义在include/linux/mount.h文件
	 */
	int mnt_flags;
	/* 4 bytes hole on 64bits arches */
	/**
	 * 设备文件名。	 
	 设备的文件名，用于文件/proc/mounts（包含了所有已经安装的文件系统）
	 */
	char *mnt_devname;		/* Name of device e.g. /dev/dsk/hda1 */
	//所有己安装的文件系统的vfsmount通过mnt_list链接在一起
	//一个命名空间的所有装载的文件系统都保存在namespace->list链表中。使用vfsmount的mnt_list成员作为链表元素
	struct list_head mnt_list;
	/**
	 * 如果文件系统标记为过期，就设置这个标志。
	 */
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	//以下4个字段用于实现Shared subtree
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct vfsmount *mnt_master;	/* slave is on master->mnt_slave_list */
	//所在的namespace
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	/*
	 * We put mnt_count & mnt_expiry_mark at the end of struct vfsmount
	 * to let these frequently modified fields in a separate cache line
	 * (so that reads of mnt_flags wont ping-pong on SMP machines)
	 */
	 /**
	 * 引用计数器，禁止文件系统被卸载。
	 */
	atomic_t mnt_count;
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
};

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

extern void mntput_no_expire(struct vfsmount *mnt);
extern void mnt_pin(struct vfsmount *mnt);
extern void mnt_unpin(struct vfsmount *mnt);

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		mnt->mnt_expiry_mark = 0;
		mntput_no_expire(mnt);
	}
}

extern void free_vfsmnt(struct vfsmount *mnt);
extern struct vfsmount *alloc_vfsmnt(const char *name);
extern struct vfsmount *do_kern_mount(const char *fstype, int flags,
				      const char *name, void *data);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);

struct nameidata;

extern int do_add_mount(struct vfsmount *newmnt, struct nameidata *nd,
			int mnt_flags, struct list_head *fslist);

extern void mark_mounts_for_expiry(struct list_head *mounts);
extern void shrink_submounts(struct vfsmount *mountpoint, struct list_head *mounts);

extern spinlock_t vfsmount_lock;
extern dev_t name_to_dev_t(char *name);

#endif
#endif /* _LINUX_MOUNT_H */
