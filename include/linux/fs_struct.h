#ifndef _LINUX_FS_STRUCT_H
#define _LINUX_FS_STRUCT_H

struct dentry;
struct vfsmount;

struct fs_struct {
	//引用计数
	atomic_t count;
	//保护该结构的锁
	rwlock_t lock;
	int umask;
	/*
	root指向进程的根目录，pwd指向进程的当前工作目录，它们不一定位于同一文件
	系统中，比如，进程的根目录通常是安装于/目录的文件系统，而当前工作目录则可能
	是安装于/mnt/fat目录的FAT文件系统。
	系统调用chroot()可以改变进程的根目录，子进程将继承新的根目录。比如使用
chroot()修改根目录为/mnt，那么接下来进程的所有操作都将在/mnt目录下面，
无法访问更上一层的目录，此时如果查看与该进程相对应的目录/proc/{PID}/中的
root文件，会发现它指向了/mnt目录

	*/
	struct dentry * root, * pwd, * altroot;
	//rootmnt对应进程根目录的安装点，pwdmnt对应进程当前工作目录的安装点
	struct vfsmount * rootmnt, * pwdmnt, * altrootmnt;
};

#define INIT_FS {				\
	.count		= ATOMIC_INIT(1),	\
	.lock		= RW_LOCK_UNLOCKED,	\
	.umask		= 0022, \
}

extern struct kmem_cache *fs_cachep;

extern void exit_fs(struct task_struct *);
extern void set_fs_altroot(void);
extern void set_fs_root(struct fs_struct *, struct vfsmount *, struct dentry *);
extern void set_fs_pwd(struct fs_struct *, struct vfsmount *, struct dentry *);
extern struct fs_struct *copy_fs_struct(struct fs_struct *);
extern void put_fs_struct(struct fs_struct *);

#endif /* _LINUX_FS_STRUCT_H */
