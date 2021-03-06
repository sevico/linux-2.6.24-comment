/*
 *  linux/kernel/fork.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also entry.S and others).
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()'
 */

#include <linux/slab.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/mnt_namespace.h>
#include <linux/personality.h>
#include <linux/mempolicy.h>
#include <linux/sem.h>
#include <linux/file.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/jiffies.h>
#include <linux/futex.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/rcupdate.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/profile.h>
#include <linux/rmap.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/freezer.h>
#include <linux/delayacct.h>
#include <linux/taskstats_kern.h>
#include <linux/random.h>
#include <linux/tty.h>
#include <linux/proc_fs.h>

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

/*
 * Protected counters by write_lock_irq(&tasklist_lock)
 */
unsigned long total_forks;	/* Handle normal Linux uptimes. */
int nr_threads; 		/* The idle threads do not count.. */

int max_threads;		/* tunable limit on nr_threads */

DEFINE_PER_CPU(unsigned long, process_counts) = 0;

__cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */

int nr_processes(void)
{
	int cpu;
	int total = 0;

	for_each_online_cpu(cpu)
		total += per_cpu(process_counts, cpu);

	return total;
}

#ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR
# define alloc_task_struct()	kmem_cache_alloc(task_struct_cachep, GFP_KERNEL)
# define free_task_struct(tsk)	kmem_cache_free(task_struct_cachep, (tsk))
static struct kmem_cache *task_struct_cachep;
#endif

/* SLAB cache for signal_struct structures (tsk->signal) */
static struct kmem_cache *signal_cachep;

/* SLAB cache for sighand_struct structures (tsk->sighand) */
struct kmem_cache *sighand_cachep;

/* SLAB cache for files_struct structures (tsk->files) */
struct kmem_cache *files_cachep;

/* SLAB cache for fs_struct structures (tsk->fs) */
struct kmem_cache *fs_cachep;

/* SLAB cache for vm_area_struct structures */
struct kmem_cache *vm_area_cachep;

/* SLAB cache for mm_struct structures (tsk->mm) */
static struct kmem_cache *mm_cachep;

void free_task(struct task_struct *tsk)
{
	prop_local_destroy_single(&tsk->dirties);
	free_thread_info(tsk->stack);
	rt_mutex_debug_task_free(tsk);
	free_task_struct(tsk);
}
EXPORT_SYMBOL(free_task);

void __put_task_struct(struct task_struct *tsk)
{
	WARN_ON(!tsk->exit_state);
	WARN_ON(atomic_read(&tsk->usage));
	WARN_ON(tsk == current);

	security_task_free(tsk);
	free_uid(tsk->user);
	put_group_info(tsk->group_info);
	delayacct_tsk_free(tsk);

	if (!profile_handoff_task(tsk))
		free_task(tsk);
}

void __init fork_init(unsigned long mempages)
{
#ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR
#ifndef ARCH_MIN_TASKALIGN
#define ARCH_MIN_TASKALIGN	L1_CACHE_BYTES
#endif
	/* create a slab on which task_structs can be allocated */
	task_struct_cachep =
		kmem_cache_create("task_struct", sizeof(struct task_struct),
			ARCH_MIN_TASKALIGN, SLAB_PANIC, NULL);
#endif

	/*
	 * The default maximum number of threads is set to a safe
	 * value: the thread structures can take up at most half
	 * of memory.
	 */
	max_threads = mempages / (8 * THREAD_SIZE / PAGE_SIZE);

	/*
	 * we need to allow at least 20 threads to boot a system
	 */
	if(max_threads < 20)
		max_threads = 20;

	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;
	init_task.signal->rlim[RLIMIT_SIGPENDING] =
		init_task.signal->rlim[RLIMIT_NPROC];
}

static struct task_struct *dup_task_struct(struct task_struct *orig)
{
	struct task_struct *tsk;
	struct thread_info *ti;
	int err;

	prepare_to_copy(orig);

	tsk = alloc_task_struct();
	if (!tsk)
		return NULL;

	ti = alloc_thread_info(tsk);
	if (!ti) {
		free_task_struct(tsk);
		return NULL;
	}

	*tsk = *orig;
	tsk->stack = ti;

	err = prop_local_init_single(&tsk->dirties);
	if (err) {
		free_thread_info(ti);
		free_task_struct(tsk);
		return NULL;
	}

	setup_thread_stack(tsk, orig);

#ifdef CONFIG_CC_STACKPROTECTOR
	tsk->stack_canary = get_random_int();
#endif

	/* One for us, one for whoever does the "release_task()" (usually parent) */
	atomic_set(&tsk->usage,2);
	atomic_set(&tsk->fs_excl, 0);
#ifdef CONFIG_BLK_DEV_IO_TRACE
	tsk->btrace_seq = 0;
#endif
	tsk->splice_pipe = NULL;
	return tsk;
}

#ifdef CONFIG_MMU
static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
{
	struct vm_area_struct *mpnt, *tmp, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int retval;
	unsigned long charge;
	struct mempolicy *pol;

	down_write(&oldmm->mmap_sem);
	flush_cache_dup_mm(oldmm);
	/*
	 * Not linked in yet - no deadlock potential:
	 */
	down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING);

	mm->locked_vm = 0;
	mm->mmap = NULL;
	mm->mmap_cache = NULL;
	mm->free_area_cache = oldmm->mmap_base;
	mm->cached_hole_size = ~0UL;
	mm->map_count = 0;
	cpus_clear(mm->cpu_vm_mask);
	mm->mm_rb = RB_ROOT;
	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;
	//处理每一个vm_area_struct结构
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct file *file;
		//不需要复制
		if (mpnt->vm_flags & VM_DONTCOPY) {
			long pages = vma_pages(mpnt);
			mm->total_vm -= pages;
			vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,
								-pages);
			continue;
		}
		charge = 0;
		//需要安全计数检查
		if (mpnt->vm_flags & VM_ACCOUNT) {
			unsigned int len = (mpnt->vm_end - mpnt->vm_start) >> PAGE_SHIFT;
			if (security_vm_enough_memory(len))
				goto fail_nomem;
			charge = len;
		}
		//为子进程分配新的vm_area_struct结构
		tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
		if (!tmp)
			goto fail_nomem;
		//整个结构复制
		*tmp = *mpnt;
		pol = mpol_copy(vma_policy(mpnt));
		retval = PTR_ERR(pol);
		if (IS_ERR(pol))
			goto fail_nomem_policy;
		vma_set_policy(tmp, pol);
		tmp->vm_flags &= ~VM_LOCKED;
		tmp->vm_mm = mm;
		tmp->vm_next = NULL;
		anon_vma_link(tmp);
		file = tmp->vm_file;
		//如果这片内存对应的是一个文件映射，则设置文件相关信息，增加文件的引用计数等
		if (file) {
			struct inode *inode = file->f_path.dentry->d_inode;
			get_file(file);
			if (tmp->vm_flags & VM_DENYWRITE)
				atomic_dec(&inode->i_writecount);

			/* insert tmp into the share list, just after mpnt */
			spin_lock(&file->f_mapping->i_mmap_lock);
			tmp->vm_truncate_count = mpnt->vm_truncate_count;
			flush_dcache_mmap_lock(file->f_mapping);
			vma_prio_tree_add(tmp, mpnt);
			flush_dcache_mmap_unlock(file->f_mapping);
			spin_unlock(&file->f_mapping->i_mmap_lock);
		}

		/*
		 * Link in the new vma and copy the page table entries.
		 */
		//把新的vm_area_struct结构添加到子进程
		*pprev = tmp;
		pprev = &tmp->vm_next;
		//添加到红黑树
		__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

		mm->map_count++;
		//分配设置页表，并不需要分配物理页面
		retval = copy_page_range(mm, oldmm, mpnt);

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto out;
	}
	/* a new mm has just been created */
	arch_dup_mmap(oldmm, mm);
	retval = 0;
out:
	up_write(&mm->mmap_sem);
	flush_tlb_mm(oldmm);
	up_write(&oldmm->mmap_sem);
	return retval;
fail_nomem_policy:
	kmem_cache_free(vm_area_cachep, tmp);
fail_nomem:
	retval = -ENOMEM;
	vm_unacct_memory(charge);
	goto out;
}

static inline int mm_alloc_pgd(struct mm_struct * mm)
{
	mm->pgd = pgd_alloc(mm);
	if (unlikely(!mm->pgd))
		return -ENOMEM;
	return 0;
}

static inline void mm_free_pgd(struct mm_struct * mm)
{
	pgd_free(mm->pgd);
}
#else
#define dup_mmap(mm, oldmm)	(0)
#define mm_alloc_pgd(mm)	(0)
#define mm_free_pgd(mm)
#endif /* CONFIG_MMU */

__cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock);

#define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL))
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))

#include <linux/init_task.h>

static struct mm_struct * mm_init(struct mm_struct * mm)
{
	atomic_set(&mm->mm_users, 1);
	atomic_set(&mm->mm_count, 1);
	init_rwsem(&mm->mmap_sem);
	INIT_LIST_HEAD(&mm->mmlist);
	mm->flags = (current->mm) ? current->mm->flags
				  : MMF_DUMP_FILTER_DEFAULT;
	mm->core_waiters = 0;
	mm->nr_ptes = 0;
	set_mm_counter(mm, file_rss, 0);
	set_mm_counter(mm, anon_rss, 0);
	spin_lock_init(&mm->page_table_lock);
	rwlock_init(&mm->ioctx_list_lock);
	mm->ioctx_list = NULL;
	mm->free_area_cache = TASK_UNMAPPED_BASE;
	mm->cached_hole_size = ~0UL;

	if (likely(!mm_alloc_pgd(mm))) {
		mm->def_flags = 0;
		return mm;
	}
	free_mm(mm);
	return NULL;
}

/*
 * Allocate and initialize an mm_struct.
 */
struct mm_struct * mm_alloc(void)
{
	struct mm_struct * mm;

	mm = allocate_mm();
	if (mm) {
		memset(mm, 0, sizeof(*mm));
		mm = mm_init(mm);
	}
	return mm;
}

/*
 * Called when the last reference to the mm
 * is dropped: either by a lazy thread or by
 * mmput. Free the page directory and the mm.
 */
void fastcall __mmdrop(struct mm_struct *mm)
{
	BUG_ON(mm == &init_mm);
	mm_free_pgd(mm);
	destroy_context(mm);
	free_mm(mm);
}

/*
 * Decrement the use count and release all resources for an mm.
 */
void mmput(struct mm_struct *mm)
{
	might_sleep();

	if (atomic_dec_and_test(&mm->mm_users)) {
		exit_aio(mm);
		exit_mmap(mm);
		if (!list_empty(&mm->mmlist)) {
			spin_lock(&mmlist_lock);
			list_del(&mm->mmlist);
			spin_unlock(&mmlist_lock);
		}
		put_swap_token(mm);
		mmdrop(mm);
	}
}
EXPORT_SYMBOL_GPL(mmput);

/**
 * get_task_mm - acquire a reference to the task's mm
 *
 * Returns %NULL if the task has no mm.  Checks PF_BORROWED_MM (meaning
 * this kernel workthread has transiently adopted a user mm with use_mm,
 * to do its AIO) is not set and if so returns a reference to it, after
 * bumping up the use count.  User must release the mm via mmput()
 * after use.  Typically used by /proc and ptrace.
 */
struct mm_struct *get_task_mm(struct task_struct *task)
{
	struct mm_struct *mm;

	task_lock(task);
	mm = task->mm;
	if (mm) {
		if (task->flags & PF_BORROWED_MM)
			mm = NULL;
		else
			atomic_inc(&mm->mm_users);
	}
	task_unlock(task);
	return mm;
}
EXPORT_SYMBOL_GPL(get_task_mm);

/* Please note the differences between mmput and mm_release.
 * mmput is called whenever we stop holding onto a mm_struct,
 * error success whatever.
 *
 * mm_release is called after a mm_struct has been removed
 * from the current process.
 *
 * This difference is important for error handling, when we
 * only half set up a mm_struct for a new process and need to restore
 * the old one.  Because we mmput the new mm_struct before
 * restoring the old one. . .
 * Eric Biederman 10 January 1998
 */
void mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
	struct completion *vfork_done = tsk->vfork_done;

	/* Get rid of any cached register state */
	deactivate_mm(tsk, mm);

	/* notify parent sleeping on vfork() */
	if (vfork_done) {
		tsk->vfork_done = NULL;
		complete(vfork_done);
	}

	/*
	 * If we're exiting normally, clear a user-space tid field if
	 * requested.  We leave this alone when dying by signal, to leave
	 * the value intact in a core dump, and to save the unnecessary
	 * trouble otherwise.  Userland only wants this done for a sys_exit.
	 */
	if (tsk->clear_child_tid
	    && !(tsk->flags & PF_SIGNALED)
	    && atomic_read(&mm->mm_users) > 1) {
		u32 __user * tidptr = tsk->clear_child_tid;
		tsk->clear_child_tid = NULL;

		/*
		 * We don't check the error code - if userspace has
		 * not set up a proper pointer then tough luck.
		 */
		put_user(0, tidptr);
		sys_futex(tidptr, FUTEX_WAKE, 1, NULL, NULL, 0);
	}
}

/*
 * Allocate a new mm structure and copy contents from the
 * mm structure of the passed in task structure.
 */
static struct mm_struct *dup_mm(struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm = current->mm;
	int err;

	if (!oldmm)
		return NULL;
	//分配mm_struct 结构
	mm = allocate_mm();
	if (!mm)
		goto fail_nomem;
	//复制 mm_struct 结构
	memcpy(mm, oldmm, sizeof(*mm));

	/* Initializing for Swap token stuff */
	mm->token_priority = 0;
	mm->last_interval = 0;
	//初始化，同时分配页表
	if (!mm_init(mm))
		goto fail_nomem;

	if (init_new_context(tsk, mm))
		goto fail_nocontext;
	//拷贝 vm_area_struct结构
	err = dup_mmap(mm, oldmm);
	if (err)
		goto free_pt;

	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;

	return mm;

free_pt:
	mmput(mm);

fail_nomem:
	return NULL;

fail_nocontext:
	/*
	 * If init_new_context() failed, we cannot use mmput() to free the mm
	 * because it calls destroy_context()
	 */
	mm_free_pgd(mm);
	free_mm(mm);
	return NULL;
}

static int copy_mm(unsigned long clone_flags, struct task_struct * tsk)
{
	struct mm_struct * mm, *oldmm;
	int retval;

	tsk->min_flt = tsk->maj_flt = 0;
	tsk->nvcsw = tsk->nivcsw = 0;

	tsk->mm = NULL;
	tsk->active_mm = NULL;

	/*
	 * Are we cloning a kernel thread?
	 *
	 * We need to steal a active VM for that..
	 */
	oldmm = current->mm;
	if (!oldmm)
		return 0;
	//如果要共享mm，则增加父进程 mm的引用计数，同时把设置mm 为 current->mm
	if (clone_flags & CLONE_VM) {
		atomic_inc(&oldmm->mm_users);
		mm = oldmm;
		goto good_mm;
	}

	retval = -ENOMEM;
	mm = dup_mm(tsk);
	if (!mm)
		goto fail_nomem;

good_mm:
	/* Initializing for Swap token stuff */
	mm->token_priority = 0;
	mm->last_interval = 0;

	tsk->mm = mm;
	tsk->active_mm = mm;
	return 0;

fail_nomem:
	return retval;
}

static struct fs_struct *__copy_fs_struct(struct fs_struct *old)
{
	struct fs_struct *fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	/* We don't need to lock fs - think why ;-) */
	if (fs) {
		atomic_set(&fs->count, 1);
		rwlock_init(&fs->lock);
		fs->umask = old->umask;
		read_lock(&old->lock);
		fs->rootmnt = mntget(old->rootmnt);
		fs->root = dget(old->root);
		fs->pwdmnt = mntget(old->pwdmnt);
		fs->pwd = dget(old->pwd);
		if (old->altroot) {
			fs->altrootmnt = mntget(old->altrootmnt);
			fs->altroot = dget(old->altroot);
		} else {
			fs->altrootmnt = NULL;
			fs->altroot = NULL;
		}
		read_unlock(&old->lock);
	}
	return fs;
}

struct fs_struct *copy_fs_struct(struct fs_struct *old)
{
	return __copy_fs_struct(old);
}

EXPORT_SYMBOL_GPL(copy_fs_struct);

static int copy_fs(unsigned long clone_flags, struct task_struct *tsk)
{
	if (clone_flags & CLONE_FS) {
		atomic_inc(&current->fs->count);
		return 0;
	}
	tsk->fs = __copy_fs_struct(current->fs);
	if (!tsk->fs)
		return -ENOMEM;
	return 0;
}

static int count_open_files(struct fdtable *fdt)
{
	int size = fdt->max_fds;
	int i;

	/* Find the last open fd */
	for (i = size/(8*sizeof(long)); i > 0; ) {
		if (fdt->open_fds->fds_bits[--i])
			break;
	}
	i = (i+1) * 8 * sizeof(long);
	return i;
}

static struct files_struct *alloc_files(void)
{
	struct files_struct *newf;
	struct fdtable *fdt;

	newf = kmem_cache_alloc(files_cachep, GFP_KERNEL);
	if (!newf)
		goto out;

	atomic_set(&newf->count, 1);

	spin_lock_init(&newf->file_lock);
	newf->next_fd = 0;
	fdt = &newf->fdtab;
	fdt->max_fds = NR_OPEN_DEFAULT;
	fdt->close_on_exec = (fd_set *)&newf->close_on_exec_init;
	fdt->open_fds = (fd_set *)&newf->open_fds_init;
	fdt->fd = &newf->fd_array[0];
	INIT_RCU_HEAD(&fdt->rcu);
	fdt->next = NULL;
	rcu_assign_pointer(newf->fdt, fdt);
out:
	return newf;
}

/*
 * Allocate a new files structure and copy contents from the
 * passed in files structure.
 * errorp will be valid only when the returned files_struct is NULL.
 */
static struct files_struct *dup_fd(struct files_struct *oldf, int *errorp)
{
	struct files_struct *newf;
	struct file **old_fds, **new_fds;
	int open_files, size, i;
	struct fdtable *old_fdt, *new_fdt;

	*errorp = -ENOMEM;
	newf = alloc_files();
	if (!newf)
		goto out;

	spin_lock(&oldf->file_lock);
	old_fdt = files_fdtable(oldf);
	new_fdt = files_fdtable(newf);
	open_files = count_open_files(old_fdt);

	/*
	 * Check whether we need to allocate a larger fd array and fd set.
	 * Note: we're not a clone task, so the open count won't change.
	 */
	if (open_files > new_fdt->max_fds) {
		new_fdt->max_fds = 0;
		spin_unlock(&oldf->file_lock);
		spin_lock(&newf->file_lock);
		*errorp = expand_files(newf, open_files-1);
		spin_unlock(&newf->file_lock);
		if (*errorp < 0)
			goto out_release;
		new_fdt = files_fdtable(newf);
		/*
		 * Reacquire the oldf lock and a pointer to its fd table
		 * who knows it may have a new bigger fd table. We need
		 * the latest pointer.
		 */
		spin_lock(&oldf->file_lock);
		old_fdt = files_fdtable(oldf);
	}

	old_fds = old_fdt->fd;
	new_fds = new_fdt->fd;

	memcpy(new_fdt->open_fds->fds_bits,
		old_fdt->open_fds->fds_bits, open_files/8);
	memcpy(new_fdt->close_on_exec->fds_bits,
		old_fdt->close_on_exec->fds_bits, open_files/8);

	for (i = open_files; i != 0; i--) {
		struct file *f = *old_fds++;
		if (f) {
			get_file(f);
		} else {
			/*
			 * The fd may be claimed in the fd bitmap but not yet
			 * instantiated in the files array if a sibling thread
			 * is partway through open().  So make sure that this
			 * fd is available to the new process.
			 */
			FD_CLR(open_files - i, new_fdt->open_fds);
		}
		rcu_assign_pointer(*new_fds++, f);
	}
	spin_unlock(&oldf->file_lock);

	/* compute the remainder to be cleared */
	size = (new_fdt->max_fds - open_files) * sizeof(struct file *);

	/* This is long word aligned thus could use a optimized version */
	memset(new_fds, 0, size);

	if (new_fdt->max_fds > open_files) {
		int left = (new_fdt->max_fds-open_files)/8;
		int start = open_files / (8 * sizeof(unsigned long));

		memset(&new_fdt->open_fds->fds_bits[start], 0, left);
		memset(&new_fdt->close_on_exec->fds_bits[start], 0, left);
	}

	return newf;

out_release:
	kmem_cache_free(files_cachep, newf);
out:
	return NULL;
}

static int copy_files(unsigned long clone_flags, struct task_struct * tsk)
{
	struct files_struct *oldf, *newf;
	int error = 0;

	/*
	 * A background process may not have any files ...
	 */
	oldf = current->files;
	if (!oldf)
		goto out;

	if (clone_flags & CLONE_FILES) {
		atomic_inc(&oldf->count);
		goto out;
	}

	/*
	 * Note: we may be using current for both targets (See exec.c)
	 * This works because we cache current->files (old) as oldf. Don't
	 * break this.
	 */
	tsk->files = NULL;
	newf = dup_fd(oldf, &error);
	if (!newf)
		goto out;

	tsk->files = newf;
	error = 0;
out:
	return error;
}

/*
 *	Helper to unshare the files of the current task.
 *	We don't want to expose copy_files internals to
 *	the exec layer of the kernel.
 */

int unshare_files(void)
{
	struct files_struct *files  = current->files;
	int rc;

	BUG_ON(!files);

	/* This can race but the race causes us to copy when we don't
	   need to and drop the copy */
	if(atomic_read(&files->count) == 1)
	{
		atomic_inc(&files->count);
		return 0;
	}
	rc = copy_files(0, current);
	if(rc)
		current->files = files;
	return rc;
}

EXPORT_SYMBOL(unshare_files);

static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)
{
	struct sighand_struct *sig;

	if (clone_flags & (CLONE_SIGHAND | CLONE_THREAD)) {
		atomic_inc(&current->sighand->count);
		return 0;
	}
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
	rcu_assign_pointer(tsk->sighand, sig);
	if (!sig)
		return -ENOMEM;
	atomic_set(&sig->count, 1);
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));
	return 0;
}

void __cleanup_sighand(struct sighand_struct *sighand)
{
	if (atomic_dec_and_test(&sighand->count))
		kmem_cache_free(sighand_cachep, sighand);
}

static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)
{
	struct signal_struct *sig;
	int ret;

	if (clone_flags & CLONE_THREAD) {
		atomic_inc(&current->signal->count);
		atomic_inc(&current->signal->live);
		return 0;
	}
	sig = kmem_cache_alloc(signal_cachep, GFP_KERNEL);
	tsk->signal = sig;
	if (!sig)
		return -ENOMEM;

	ret = copy_thread_group_keys(tsk);
	if (ret < 0) {
		kmem_cache_free(signal_cachep, sig);
		return ret;
	}

	atomic_set(&sig->count, 1);
	atomic_set(&sig->live, 1);
	init_waitqueue_head(&sig->wait_chldexit);
	sig->flags = 0;
	sig->group_exit_code = 0;
	sig->group_exit_task = NULL;
	sig->group_stop_count = 0;
	sig->curr_target = NULL;
	init_sigpending(&sig->shared_pending);
	INIT_LIST_HEAD(&sig->posix_timers);

	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sig->it_real_incr.tv64 = 0;
	sig->real_timer.function = it_real_fn;
	sig->tsk = tsk;

	sig->it_virt_expires = cputime_zero;
	sig->it_virt_incr = cputime_zero;
	sig->it_prof_expires = cputime_zero;
	sig->it_prof_incr = cputime_zero;

	sig->leader = 0;	/* session leadership doesn't inherit */
	sig->tty_old_pgrp = NULL;

	sig->utime = sig->stime = sig->cutime = sig->cstime = cputime_zero;
	sig->gtime = cputime_zero;
	sig->cgtime = cputime_zero;
	sig->nvcsw = sig->nivcsw = sig->cnvcsw = sig->cnivcsw = 0;
	sig->min_flt = sig->maj_flt = sig->cmin_flt = sig->cmaj_flt = 0;
	sig->inblock = sig->oublock = sig->cinblock = sig->coublock = 0;
	sig->sum_sched_runtime = 0;
	INIT_LIST_HEAD(&sig->cpu_timers[0]);
	INIT_LIST_HEAD(&sig->cpu_timers[1]);
	INIT_LIST_HEAD(&sig->cpu_timers[2]);
	taskstats_tgid_init(sig);

	task_lock(current->group_leader);
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);
	task_unlock(current->group_leader);

	if (sig->rlim[RLIMIT_CPU].rlim_cur != RLIM_INFINITY) {
		/*
		 * New sole thread in the process gets an expiry time
		 * of the whole CPU time limit.
		 */
		tsk->it_prof_expires =
			secs_to_cputime(sig->rlim[RLIMIT_CPU].rlim_cur);
	}
	acct_init_pacct(&sig->pacct);

	tty_audit_fork(sig);

	return 0;
}

void __cleanup_signal(struct signal_struct *sig)
{
	exit_thread_group_keys(sig);
	kmem_cache_free(signal_cachep, sig);
}

static void cleanup_signal(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;

	atomic_dec(&sig->live);

	if (atomic_dec_and_test(&sig->count))
		__cleanup_signal(sig);
}

static void copy_flags(unsigned long clone_flags, struct task_struct *p)
{
	unsigned long new_flags = p->flags;

	new_flags &= ~PF_SUPERPRIV;
	new_flags |= PF_FORKNOEXEC;
	if (!(clone_flags & CLONE_PTRACE))
		p->ptrace = 0;
	p->flags = new_flags;
	clear_freeze_flag(p);
}

asmlinkage long sys_set_tid_address(int __user *tidptr)
{
	current->clear_child_tid = tidptr;

	return task_pid_vnr(current);
}

static void rt_mutex_init_task(struct task_struct *p)
{
	spin_lock_init(&p->pi_lock);
#ifdef CONFIG_RT_MUTEXES
	plist_head_init(&p->pi_waiters, &p->pi_lock);
	p->pi_blocked_on = NULL;
#endif
}

/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
/**
 * 创建进程描述符以及子进程执行所需要的所有其他数据结构
 * 它的参数与do_fork相同。外加子进程的PID。
 */
static struct task_struct *copy_process(unsigned long clone_flags,
					unsigned long stack_start,
					struct pt_regs *regs,
					unsigned long stack_size,
					int __user *child_tidptr,
					struct pid *pid)
{
	int retval;
	struct task_struct *p;
	int cgroup_callbacks_done = 0;
	//标志检查
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
		return ERR_PTR(-EINVAL);

	/*
	 * Thread groups must share signals as well, and detached threads
	 * can only be started up within the thread group.
	 */
	/**
	 * CLONE_THREAD标志被设置，并且CLONE_SIGHAND没有设置。
	 * (同一线程组中的轻量级进程必须共享信号)
	 */
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);

	/*
	 * Shared signal handlers imply shared VM. By way of the above,
	 * thread groups also imply shared VM. Blocking this case allows
	 * for various simplifications in other code.
	 */
	/**
	 * CLONE_SIGHAND被设置，但是CLONE_VM没有设置。
	 * (共享信号处理程序的轻量级进程也必须共享内存描述符)
	 */
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);
	//安全检查框架，利用它可以在进程建立前检查是否允许检查，利用这个开发框架
	//可以开发出进程监控。默认调用dummy_task_create函数，它什么也不做
	/**
	 * 通过调用security_task_create以及稍后调用security_task_alloc执行所有附加的安全检查。
	 * LINUX2.6提供扩展安全性的钩子函数，与传统unix相比，它具有更加强壮的安全模型。
	 */
	retval = security_task_create(clone_flags);
	if (retval)
		goto fork_out;

	retval = -ENOMEM;
	//为子进程分配一个 task_struct 和内核态堆栈，把父进程的task_struct结构
	//复制到子进程，同时设置内核态堆栈中的 thread_info结构
	p = dup_task_struct(current);
	if (!p)
		goto fork_out;

	rt_mutex_init_task(p);

#ifdef CONFIG_TRACE_IRQFLAGS
	DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled);
	DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);
#endif
	//检查进程的资源限制
	/**
	 * 检查存放在current->sigal->rlim[RLIMIT_NPROC].rlim_cur中的限制值，是否小于或者等于用户所拥有的进程数。
	 * 如果是，则返回错误码。当然，有root权限除外。
	 * p->user表示进程的拥有者，p->user->processes表示进程拥有者当前进程数
	 * xie.baoyou注：此处比较是用>=而不是>
	 */
	retval = -EAGAIN;
	if (atomic_read(&p->user->processes) >=
			p->signal->rlim[RLIMIT_NPROC].rlim_cur) {
		/**
		 * 当然，用户有root权限就另当别论了
		 */
		if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_RESOURCE) &&
		    p->user != current->nsproxy->user_ns->root_user)
			goto bad_fork_free;
	}
/*
	进程描述符中包含有一个user_struct结构指针user，一个用户的多个进程可以通过
	该指针共享该用户的资源信息，因为创建了新的进程，所以必须更新该用户的
	user_struct结构，累加相应的计数器
*/
	/**
	 * 递增user结构的使用计数器
	 */
	atomic_inc(&p->user->__count);
	/**
	 * 增加用户拥有的进程计数。
	 */
	atomic_inc(&p->user->processes);
	get_group_info(p->group_info);

	/*
	 * If multiple threads are within copy_process(), then this check
	 * triggers too late. This doesn't hurt, the check is only there
	 * to stop root fork bombs.
	 */
	/**
	 * 检查系统中的进程数量（nr_threads）是否超过max_threads
	 * max_threads的缺省值是由系统内存容量决定的。总的原则是：所有的thread_info描述符和内核栈所占用的空间
	 * 不能超过物理内存的1/8。不过，系统管理可以通过写/proc/sys/kernel/thread-max文件来改变这个值。
	 */
	if (nr_threads >= max_threads)
		goto bad_fork_cleanup_count;
	/**
	 * 如果新进程的执行域和可招待格式的内核函数都包含在内核中模块中，
	 * 就递增它们的使用计数器。
	 */
	if (!try_module_get(task_thread_info(p)->exec_domain->module))
		goto bad_fork_cleanup_count;

	if (p->binfmt && !try_module_get(p->binfmt->module))
		goto bad_fork_cleanup_put_domain;
	/**
	 * 设置几个与进程状态相关的关键字段。
	 */

	/**
	 * did_exec是进程发出的execve系统调用的次数，初始为0
	 */
	p->did_exec = 0;
	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */
	//拷贝 clone_flags 到子进程的task_struct
	/**
	 * 更新从父进程复制到tsk_flags字段中的一些标志。
	 * 首先清除PF_SUPERPRIV。该标志表示进程是否使用了某种超级用户权限。
	 * 然后设置PF_FORKNOEXEC标志。它表示子进程还没有发出execve系统调用。
	 */
	copy_flags(clone_flags, p);
	/**
	 * 初始化子进程描述符中的list_head数据结构和自旋锁。
	 * 并为挂起信号，定时器及时间统计表相关的几个字段赋初值。
	 */
	INIT_LIST_HEAD(&p->children);
	INIT_LIST_HEAD(&p->sibling);
	p->vfork_done = NULL;
	spin_lock_init(&p->alloc_lock);

	clear_tsk_thread_flag(p, TIF_SIGPENDING);
	init_sigpending(&p->pending);

	p->utime = cputime_zero;
	p->stime = cputime_zero;
	p->gtime = cputime_zero;
	p->utimescaled = cputime_zero;
	p->stimescaled = cputime_zero;
	p->prev_utime = cputime_zero;
	p->prev_stime = cputime_zero;

#ifdef CONFIG_TASK_XACCT
	p->rchar = 0;		/* I/O counter: bytes read */
	p->wchar = 0;		/* I/O counter: bytes written */
	p->syscr = 0;		/* I/O counter: read syscalls */
	p->syscw = 0;		/* I/O counter: write syscalls */
#endif
	task_io_accounting_init(p);
	acct_clear_integrals(p);

	p->it_virt_expires = cputime_zero;
	p->it_prof_expires = cputime_zero;
	p->it_sched_expires = 0;
	INIT_LIST_HEAD(&p->cpu_timers[0]);
	INIT_LIST_HEAD(&p->cpu_timers[1]);
	INIT_LIST_HEAD(&p->cpu_timers[2]);
	/**
	 * 把大内核锁计数器初始化为-1
	 */
	p->lock_depth = -1;		/* -1 = no lock */
	do_posix_clock_monotonic_gettime(&p->start_time);
	p->real_start_time = p->start_time;
	monotonic_to_bootbased(&p->real_start_time);
#ifdef CONFIG_SECURITY
	p->security = NULL;
#endif
	p->io_context = NULL;
	p->audit_context = NULL;
	cgroup_fork(p);
#ifdef CONFIG_NUMA
 	p->mempolicy = mpol_copy(p->mempolicy);
 	if (IS_ERR(p->mempolicy)) {
 		retval = PTR_ERR(p->mempolicy);
 		p->mempolicy = NULL;
 		goto bad_fork_cleanup_cgroup;
 	}
	mpol_fix_fork_child_flag(p);
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	p->irq_events = 0;
#ifdef __ARCH_WANT_INTERRUPTS_ON_CTXSW
	p->hardirqs_enabled = 1;
#else
	p->hardirqs_enabled = 0;
#endif
	p->hardirq_enable_ip = 0;
	p->hardirq_enable_event = 0;
	p->hardirq_disable_ip = _THIS_IP_;
	p->hardirq_disable_event = 0;
	p->softirqs_enabled = 1;
	p->softirq_enable_ip = _THIS_IP_;
	p->softirq_enable_event = 0;
	p->softirq_disable_ip = 0;
	p->softirq_disable_event = 0;
	p->hardirq_context = 0;
	p->softirq_context = 0;
#endif
#ifdef CONFIG_LOCKDEP
	p->lockdep_depth = 0; /* no locks held yet */
	p->curr_chain_key = 0;
	p->lockdep_recursion = 0;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	p->blocked_on = NULL; /* not blocked yet */
#endif

	/* Perform scheduler related setup. Assign this task to a CPU. */
	/**
	 * 调用sched_fork完成对新进程调度程序数据结构的初始化。
	 * 该函数把新进程的状态置为TASK_RUNNING，并把thread_info结构的preempt_count字段设置为1，
	 * 从而禁止抢占。
	 */
	sched_fork(p, clone_flags);
	//安全检查框架，默认什么也不做
	if ((retval = security_task_alloc(p)))
		goto bad_fork_cleanup_policy;
	if ((retval = audit_alloc(p)))
		goto bad_fork_cleanup_security;
	/* copy all the process information */
	//下面根据 clone_flags 复制父进程的资源到子进程，对于 clone_flags 指定的共享资源，
	//则仅仅设置子进程的相关指针，并增加资源数据结构的引用计数
	/**
	 * copy_semundo，copy_files，copy_fs，copy_sighand，copy_signal
	 * copy_mm，copy_keys，copy_namespace创建新的数据结构，并把父进程相应数据结构的值复制到新数据结构中。
	 * 除非clone_flags参数指出它们有不同的值。
	 */
	if ((retval = copy_semundo(clone_flags, p)))
		goto bad_fork_cleanup_audit;
	if ((retval = copy_files(clone_flags, p)))
		goto bad_fork_cleanup_semundo;
	if ((retval = copy_fs(clone_flags, p)))
		goto bad_fork_cleanup_files;
	if ((retval = copy_sighand(clone_flags, p)))
		goto bad_fork_cleanup_fs;
	if ((retval = copy_signal(clone_flags, p)))
		goto bad_fork_cleanup_sighand;
	if ((retval = copy_mm(clone_flags, p)))
		goto bad_fork_cleanup_signal;
	if ((retval = copy_keys(clone_flags, p)))
		goto bad_fork_cleanup_mm;
	if ((retval = copy_namespaces(clone_flags, p)))
		goto bad_fork_cleanup_keys;
	//复制父进程的内核态堆栈到子进程
	/**
	 * 调用copy_thread，用发出clone系统调用时CPU寄存器的值（它们保存在父进程的内核栈中）
	 * 来初始化子进程的内核栈。不过，copy_thread把eax寄存器对应字段的值（这是fork和clone系统调用在子进程中的返回值）
	 * 强行置为0。子进程描述符的thread.esp字段初始化为子进程内核栈的基地址。ret_from_fork的地址存放在thread.eip中。
	 * 如果父进程使用IO权限位图。则子进程获取该位图的一个拷贝。
	 * 最后，如果CLONE_SETTLS标志被置位，则子进程获取由CLONE系统调用的参数tls指向的用户态数据结构所表示的TLS段。
	 */
	retval = copy_thread(0, clone_flags, stack_start, stack_size, p, regs);
	if (retval)
		goto bad_fork_cleanup_namespaces;
	//分配 pid 结构
	if (pid != &init_struct_pid) {
		retval = -ENOMEM;
		pid = alloc_pid(task_active_pid_ns(p));
		if (!pid)
			goto bad_fork_cleanup_namespaces;

		if (clone_flags & CLONE_NEWPID) {
			retval = pid_ns_prepare_proc(task_active_pid_ns(p));
			if (retval < 0)
				goto bad_fork_free_pid;
		}
	}

	p->pid = pid_nr(pid);
	p->tgid = p->pid;
	//如果建立的是轻权进程，那么父子进程在同一个线程组中，就设置子进程的 tgid
	if (clone_flags & CLONE_THREAD)
		p->tgid = current->tgid;
	/**
	 * 如果clone_flags参数的值被置为CLONE_CHILD_SETTID或CLONE_CHILD_CLEARTID
	 * 就把child_tidptr参数的值分别复制到set_child_tid或clear_child_tid字段。
	 * 这些标志说明：必须改变子进程用户态地址空间的child_tidptr所指向的变量的值
	 * 不过实际的写操作要稍后再执行。
	 */
	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;
	/*
	 * Clear TID on mm_release()?
	 */
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr: NULL;
#ifdef CONFIG_FUTEX
	p->robust_list = NULL;
#ifdef CONFIG_COMPAT
	p->compat_robust_list = NULL;
#endif
	INIT_LIST_HEAD(&p->pi_state_list);
	p->pi_state_cache = NULL;
#endif
	/*
	 * sigaltstack should be cleared when sharing the same VM
	 */
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
		p->sas_ss_sp = p->sas_ss_size = 0;

	/*
	 * Syscall tracing should be turned off in the child regardless
	 * of CLONE_PTRACE.
	 */
	/**
	 * 清除TIF_SYSCALL_TRACE标志。使ret_from_fork函数不会把系统调用结束的消息通知给调试进程。
	 * 也不应该通知给调试进程，因为子进程并没有调用fork.
	 */
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);
#ifdef TIF_SYSCALL_EMU
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);
#endif

	/* Our parent execution domain becomes current domain
	   These must match for thread signalling to apply */
	p->parent_exec_id = p->self_exec_id;

	/* ok, now we should be set up.. */
	//父进程是否要求子进程退出时发送信号
	/**
	 * 用clone_flags参数低位的信号数据编码统建始化tsk_exit_signal字段。
	 * 如CLONE_THREAD标志被置位，就把exit_signal字段初始化为-1。
	 * 这样做是因为：当创建线程时，即使被创建的线程死亡，都不应该给领头进程的父进程发送信号。
	 * 而应该是领头进程死亡后，才向其领头进程的父进程发送信号。
	 */
	p->exit_signal = (clone_flags & CLONE_THREAD) ? -1 : (clone_flags & CSIGNAL);
	p->pdeath_signal = 0;
	//子进程默认的退出状态
	p->exit_state = 0;

	/*
	 * Ok, make it visible to the rest of the system.
	 * We dont wake it up yet.
	 */
	p->group_leader = p;
	INIT_LIST_HEAD(&p->thread_group);
	INIT_LIST_HEAD(&p->ptrace_children);
	INIT_LIST_HEAD(&p->ptrace_list);

	/* Now that the task is set up, run cgroup callbacks if
	 * necessary. We need to run them before the task is visible
	 * on the tasklist. */
	cgroup_fork_callbacks(p);
	cgroup_callbacks_done = 1;

	/* Need tasklist lock for parent etc handling! */
	write_lock_irq(&tasklist_lock);

	/* for sys_ioprio_set(IOPRIO_WHO_PGRP) */
	p->ioprio = current->ioprio;

	/*
	 * The task hasn't been attached yet, so its cpus_allowed mask will
	 * not be changed, nor will its assigned CPU.
	 *
	 * The cpus_allowed mask of the parent may have changed after it was
	 * copied first time - so re-copy it here, then check the child's CPU
	 * to ensure it is on a valid CPU (and if not, just force it back to
	 * parent's CPU). This avoids alot of nasty races.
	 */
	/**
	 * 初始化子线程的cpu字段。
	 */
	p->cpus_allowed = current->cpus_allowed;
	if (unlikely(!cpu_isset(task_cpu(p), p->cpus_allowed) ||
			!cpu_online(task_cpu(p))))
		set_task_cpu(p, smp_processor_id());

	/* CLONE_PARENT re-uses the old parent */
	/**
	 * 初始化表示亲子关系的字段，如果CLONE_PARENT或者CLONE_THREAD被设置了
	 * 就用current->real_parent初始化，否则，当前进程就是初创建进程的父进程。
	 */
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD))
	//把子进程的 real_parent 设置为父进程的 real_parent
		p->real_parent = current->real_parent;
	else
		p->real_parent = current;
	p->parent = p->real_parent;

	spin_lock(&current->sighand->siglock);

	/*
	 * Process group and session signals need to be delivered to just the
	 * parent before the fork or both the parent and the child after the
	 * fork. Restart if a signal comes in before we add the new process to
	 * it's process group.
	 * A fatal signal pending means that current will exit, so the new
	 * thread can't slip out of an OOM kill (or normal SIGKILL).
 	 */
	recalc_sigpending();
	if (signal_pending(current)) {
		spin_unlock(&current->sighand->siglock);
		write_unlock_irq(&tasklist_lock);
		retval = -ERESTARTNOINTR;
		goto bad_fork_free_pid;
	}

	if (clone_flags & CLONE_THREAD) {
		p->group_leader = current->group_leader;
		list_add_tail_rcu(&p->thread_group, &p->group_leader->thread_group);

		if (!cputime_eq(current->signal->it_virt_expires,
				cputime_zero) ||
		    !cputime_eq(current->signal->it_prof_expires,
				cputime_zero) ||
		    current->signal->rlim[RLIMIT_CPU].rlim_cur != RLIM_INFINITY ||
		    !list_empty(&current->signal->cpu_timers[0]) ||
		    !list_empty(&current->signal->cpu_timers[1]) ||
		    !list_empty(&current->signal->cpu_timers[2])) {
			/*
			 * Have child wake up on its first tick to check
			 * for process CPU timers.
			 */
			p->it_prof_expires = jiffies_to_cputime(1);
		}
	}

	if (likely(p->pid)) {
		//把子进程添加到父进程的子进程链表中，这样组成了兄弟进程链表
		add_parent(p);
		//如果父进程是调试器，那么设置子进程的 parent 指针为调试器的父进程
		/**
	 * PT_PTRACED表示子进程必须被跟踪，就把current->parent赋给tsk->parent，并将子进程插入调试程序的跟踪链表中。
	 */
		if (unlikely(p->ptrace & PT_PTRACED))
			__ptrace_link(p, current->parent);
		/**
	 * 如果子进程是线程组的领头进程(CLONE_THREAD标志被清0)
	 */
		if (thread_group_leader(p)) {
			if (clone_flags & CLONE_NEWPID)
				p->nsproxy->pid_ns->child_reaper = p;

			p->signal->tty = current->signal->tty;
			set_task_pgrp(p, task_pgrp_nr(current));
			set_task_session(p, task_session_nr(current));
			/**
		 * 将进程插入相应的散列表。
		 */
			attach_pid(p, PIDTYPE_PGID, task_pgrp(current));
			attach_pid(p, PIDTYPE_SID, task_session(current));
			list_add_tail_rcu(&p->tasks, &init_task.tasks);
			__get_cpu_var(process_counts)++;
		}
		/**
	 * 把新进程描述符的PID插入pidhash散列表中。
	 */
		attach_pid(p, PIDTYPE_PID, pid);
		/**
	 * 计数
	 */
		nr_threads++;
	}

	total_forks++;
	spin_unlock(&current->sighand->siglock);
	write_unlock_irq(&tasklist_lock);
	proc_fork_connector(p);
	cgroup_post_fork(p);
	return p;
//出错退出
bad_fork_free_pid:
	if (pid != &init_struct_pid)
		free_pid(pid);
bad_fork_cleanup_namespaces:
	exit_task_namespaces(p);
bad_fork_cleanup_keys:
	exit_keys(p);
bad_fork_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
bad_fork_cleanup_signal:
	cleanup_signal(p);
bad_fork_cleanup_sighand:
	__cleanup_sighand(p->sighand);
bad_fork_cleanup_fs:
	exit_fs(p); /* blocking */
bad_fork_cleanup_files:
	exit_files(p); /* blocking */
bad_fork_cleanup_semundo:
	exit_sem(p);
bad_fork_cleanup_audit:
	audit_free(p);
bad_fork_cleanup_security:
	security_task_free(p);
bad_fork_cleanup_policy:
#ifdef CONFIG_NUMA
	mpol_free(p->mempolicy);
bad_fork_cleanup_cgroup:
#endif
	cgroup_exit(p, cgroup_callbacks_done);
	delayacct_tsk_free(p);
	if (p->binfmt)
		module_put(p->binfmt->module);
bad_fork_cleanup_put_domain:
	module_put(task_thread_info(p)->exec_domain->module);
bad_fork_cleanup_count:
	put_group_info(p->group_info);
	atomic_dec(&p->user->processes);
	free_uid(p->user);
bad_fork_free:
	free_task(p);
fork_out:
	return ERR_PTR(retval);
}

noinline struct pt_regs * __devinit __attribute__((weak)) idle_regs(struct pt_regs *regs)
{
	memset(regs, 0, sizeof(struct pt_regs));
	return regs;
}

struct task_struct * __cpuinit fork_idle(int cpu)
{
	struct task_struct *task;
	struct pt_regs regs;

	task = copy_process(CLONE_VM, 0, idle_regs(&regs), 0, NULL,
				&init_struct_pid);
	if (!IS_ERR(task))
		init_idle(task, cpu);

	return task;
}

static int fork_traceflag(unsigned clone_flags)
{
	if (clone_flags & CLONE_UNTRACED)
		return 0;
	else if (clone_flags & CLONE_VFORK) {
		if (current->ptrace & PT_TRACE_VFORK)
			return PTRACE_EVENT_VFORK;
	} else if ((clone_flags & CSIGNAL) != SIGCHLD) {
		if (current->ptrace & PT_TRACE_CLONE)
			return PTRACE_EVENT_CLONE;
	} else if (current->ptrace & PT_TRACE_FORK)
		return PTRACE_EVENT_FORK;

	return 0;
}

/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 */
 /*
 	参数clone_flags由两部分组成，最低的一个字节为信号掩码，用于指定子进程退出时向父进
 	程发出的信号。通过sys_fork()和sys_vfork()的定义可以看到，在fork和vfork中这个
 	信号就是SIGCHLD，而clone则可以由用户自己定义。而第二部分，即剩余的字节是表示资源
 	和特性的标志位。对于fork第二部分为全0,对于vfork则为CLONE_VFORK|CLONE_VM,至于clone则是由用户自己来定义
 */
/**
 * 负责处理clone,fork,vfork系统调用。
 * clone_flags-与clone的flag参数相同
 * stack_start-与clone的child_stack相同
 * regs-指向通用寄存器的值。是在从用户态切换到内核态时被保存到内核态堆栈中的。
 * stack_size-未使用,总是为0
 * parent_tidptr,child_tidptr-clone中对应参数ptid,ctid相同
 */
long do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      struct pt_regs *regs,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr)
{
//定义一个进程描述符
	struct task_struct *p;
	int trace = 0;
	long nr;
	//current是父进程，如果该进程被跟踪，那么当调试器要求跟踪每一个子进程时
	//创建出来的子进程也处于跟踪状态
	/**
	 * 如果父进程正在被跟踪,就检查debugger程序是否想跟踪子进程.并且子进程不是内核进程(CLONE_UNTRACED未设置)
	 * 那么就设置CLONE_PTRACE标志.
	 */
	if (unlikely(current->ptrace)) {
		trace = fork_traceflag (clone_flags);
		if (trace)
			clone_flags |= CLONE_PTRACE;
	}
//调用copy_process完成具体的复制工作
//分配子进程task_struct结构，并复制父进程资源
	p = copy_process(clone_flags, stack_start, regs, stack_size,
			child_tidptr, NULL);
	/*
	 * Do this prior waking up the new thread - the thread pointer
	 * might get invalid after that point, if the thread exits quickly.
	 */
	 /*
	 调用COPY_Process()后，如果没有指定CLONESTOPPED,就会调用
	 wake_up_new_task()将新进程添加到可运行队列之中：如果父了进程运行在同一
	 CPU之上，且没有设置CLONE_VM标志（意味着将会用到写时复制），则把了进程添
	 加到父进程的前面，确保子进程先于父进程运行，这样，如果子进程被创建后立即调用
	 exec()，将会避免由写时复制引起的一系列不必要的页面复制。
	 */
	if (!IS_ERR(p)) {
		struct completion vfork;

		/*
		 * this is enough to call pid_nr_ns here, but this if
		 * improves optimisation of regular fork()
		 */
		//这是为进程 pid namespace 设置的，不同的 namespace 中
		//可以建立相同的 pid 进程
		nr = (clone_flags & CLONE_NEWPID) ?
			task_pid_nr_ns(p, current->nsproxy->pid_ns) :
				task_pid_vnr(p);
		//把进程 ID 传递到 parent_tidptr 指针指定的用户空间
		if (clone_flags & CLONE_PARENT_SETTID)
			put_user(nr, parent_tidptr);
		//如果设置了CLONE_VFORK标志，则把父进程添加到等待队列并挂起
		//CLONE_VFORK要求父进程进入子进程，现在初始化一个等待对象
		if (clone_flags & CLONE_VFORK) {
			p->vfork_done = &vfork;
			init_completion(&vfork);
		}
		//如果被调试，或者设置了CLONE_STOPPED标志，则向进程发送SIGSTOP信号
		if ((p->ptrace & PT_PTRACED) || (clone_flags & CLONE_STOPPED)) {
			/*
			 * We'll start up with an immediate SIGSTOP.
			 */
			sigaddset(&p->pending.signal, SIGSTOP);
			set_tsk_thread_flag(p, TIF_SIGPENDING);
		}
		//如果没有设置CLONE_STOPPED标志，就把进程加入就绪队列
		if (!(clone_flags & CLONE_STOPPED))
			wake_up_new_task(p, clone_flags);
		else/*如果CLONE_STOPPED标志被设置，就把子进程设置为TASK_STOPPED状态。*/
			p->state = TASK_STOPPED;
		//如果被调试，就发送SIGTRAP信号
		/**
		 * 如果进程正被跟踪,则把子进程的PID插入到父进程的ptrace_message,并调用ptrace_notify
		 * ptrace_notify使当前进程停止运行,并向当前进程的父进程发送SIGCHLD信号.子进程的祖父进程是跟踪父进程的debugger进程.
		 * dubugger进程可以通过ptrace_message获得被创建子进程的PID.
		 */
		if (unlikely (trace)) {
			current->ptrace_message = nr;
			ptrace_notify ((trace << 8) | SIGTRAP);
		}
		/**
		 * 如果设置了CLONE_VFORK,就把父进程插入等待队列,并挂起父进程直到子进程结束或者执行了新的程序.
		 */
		if (clone_flags & CLONE_VFORK) {
			freezer_do_not_count();
			//当前进程进入之前初始化好的等待队列
			wait_for_completion(&vfork);
			freezer_count();
			if (unlikely (current->ptrace & PT_TRACE_VFORK_DONE)) {
				current->ptrace_message = nr;
				ptrace_notify ((PTRACE_EVENT_VFORK_DONE << 8) | SIGTRAP);
			}
		}
	} else {
		nr = PTR_ERR(p);
	}
	return nr;
}

#ifndef ARCH_MIN_MMSTRUCT_ALIGN
#define ARCH_MIN_MMSTRUCT_ALIGN 0
#endif

static void sighand_ctor(struct kmem_cache *cachep, void *data)
{
	struct sighand_struct *sighand = data;

	spin_lock_init(&sighand->siglock);
	init_waitqueue_head(&sighand->signalfd_wqh);
}

void __init proc_caches_init(void)
{
	sighand_cachep = kmem_cache_create("sighand_cache",
			sizeof(struct sighand_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_DESTROY_BY_RCU,
			sighand_ctor);
	signal_cachep = kmem_cache_create("signal_cache",
			sizeof(struct signal_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
	files_cachep = kmem_cache_create("files_cache",
			sizeof(struct files_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
	fs_cachep = kmem_cache_create("fs_cache",
			sizeof(struct fs_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
	vm_area_cachep = kmem_cache_create("vm_area_struct",
			sizeof(struct vm_area_struct), 0,
			SLAB_PANIC, NULL);
	mm_cachep = kmem_cache_create("mm_struct",
			sizeof(struct mm_struct), ARCH_MIN_MMSTRUCT_ALIGN,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
}

/*
 * Check constraints on flags passed to the unshare system call and
 * force unsharing of additional process context as appropriate.
 */
static void check_unshare_flags(unsigned long *flags_ptr)
{
	/*
	 * If unsharing a thread from a thread group, must also
	 * unshare vm.
	 */
	if (*flags_ptr & CLONE_THREAD)
		*flags_ptr |= CLONE_VM;

	/*
	 * If unsharing vm, must also unshare signal handlers.
	 */
	if (*flags_ptr & CLONE_VM)
		*flags_ptr |= CLONE_SIGHAND;

	/*
	 * If unsharing signal handlers and the task was created
	 * using CLONE_THREAD, then must unshare the thread
	 */
	if ((*flags_ptr & CLONE_SIGHAND) &&
	    (atomic_read(&current->signal->count) > 1))
		*flags_ptr |= CLONE_THREAD;

	/*
	 * If unsharing namespace, must also unshare filesystem information.
	 */
	if (*flags_ptr & CLONE_NEWNS)
		*flags_ptr |= CLONE_FS;
}

/*
 * Unsharing of tasks created with CLONE_THREAD is not supported yet
 */
static int unshare_thread(unsigned long unshare_flags)
{
	if (unshare_flags & CLONE_THREAD)
		return -EINVAL;

	return 0;
}

/*
 * Unshare the filesystem structure if it is being shared
 */
static int unshare_fs(unsigned long unshare_flags, struct fs_struct **new_fsp)
{
	struct fs_struct *fs = current->fs;

	if ((unshare_flags & CLONE_FS) &&
	    (fs && atomic_read(&fs->count) > 1)) {
		*new_fsp = __copy_fs_struct(current->fs);
		if (!*new_fsp)
			return -ENOMEM;
	}

	return 0;
}

/*
 * Unsharing of sighand is not supported yet
 */
static int unshare_sighand(unsigned long unshare_flags, struct sighand_struct **new_sighp)
{
	struct sighand_struct *sigh = current->sighand;

	if ((unshare_flags & CLONE_SIGHAND) && atomic_read(&sigh->count) > 1)
		return -EINVAL;
	else
		return 0;
}

/*
 * Unshare vm if it is being shared
 */
static int unshare_vm(unsigned long unshare_flags, struct mm_struct **new_mmp)
{
	struct mm_struct *mm = current->mm;

	if ((unshare_flags & CLONE_VM) &&
	    (mm && atomic_read(&mm->mm_users) > 1)) {
		return -EINVAL;
	}

	return 0;
}

/*
 * Unshare file descriptor table if it is being shared
 */
static int unshare_fd(unsigned long unshare_flags, struct files_struct **new_fdp)
{
	struct files_struct *fd = current->files;
	int error = 0;

	if ((unshare_flags & CLONE_FILES) &&
	    (fd && atomic_read(&fd->count) > 1)) {
		*new_fdp = dup_fd(fd, &error);
		if (!*new_fdp)
			return error;
	}

	return 0;
}

/*
 * Unsharing of semundo for tasks created with CLONE_SYSVSEM is not
 * supported yet
 */
static int unshare_semundo(unsigned long unshare_flags, struct sem_undo_list **new_ulistp)
{
	if (unshare_flags & CLONE_SYSVSEM)
		return -EINVAL;

	return 0;
}

/*
 * unshare allows a process to 'unshare' part of the process
 * context which was originally shared using clone.  copy_*
 * functions used by do_fork() cannot be used here directly
 * because they modify an inactive task_struct that is being
 * constructed. Here we are modifying the current, active,
 * task_struct.
 */
asmlinkage long sys_unshare(unsigned long unshare_flags)
{
	int err = 0;
	struct fs_struct *fs, *new_fs = NULL;
	struct sighand_struct *new_sigh = NULL;
	struct mm_struct *mm, *new_mm = NULL, *active_mm = NULL;
	struct files_struct *fd, *new_fd = NULL;
	struct sem_undo_list *new_ulist = NULL;
	struct nsproxy *new_nsproxy = NULL;

	check_unshare_flags(&unshare_flags);

	/* Return -EINVAL for all unsupported flags */
	err = -EINVAL;
	if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND|
				CLONE_VM|CLONE_FILES|CLONE_SYSVSEM|
				CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|
				CLONE_NEWNET))
		goto bad_unshare_out;

	if ((err = unshare_thread(unshare_flags)))
		goto bad_unshare_out;
	if ((err = unshare_fs(unshare_flags, &new_fs)))
		goto bad_unshare_cleanup_thread;
	if ((err = unshare_sighand(unshare_flags, &new_sigh)))
		goto bad_unshare_cleanup_fs;
	if ((err = unshare_vm(unshare_flags, &new_mm)))
		goto bad_unshare_cleanup_sigh;
	if ((err = unshare_fd(unshare_flags, &new_fd)))
		goto bad_unshare_cleanup_vm;
	if ((err = unshare_semundo(unshare_flags, &new_ulist)))
		goto bad_unshare_cleanup_fd;
	if ((err = unshare_nsproxy_namespaces(unshare_flags, &new_nsproxy,
			new_fs)))
		goto bad_unshare_cleanup_semundo;

	if (new_fs ||  new_mm || new_fd || new_ulist || new_nsproxy) {

		if (new_nsproxy) {
			switch_task_namespaces(current, new_nsproxy);
			new_nsproxy = NULL;
		}

		task_lock(current);

		if (new_fs) {
			fs = current->fs;
			current->fs = new_fs;
			new_fs = fs;
		}

		if (new_mm) {
			mm = current->mm;
			active_mm = current->active_mm;
			current->mm = new_mm;
			current->active_mm = new_mm;
			activate_mm(active_mm, new_mm);
			new_mm = mm;
		}

		if (new_fd) {
			fd = current->files;
			current->files = new_fd;
			new_fd = fd;
		}

		task_unlock(current);
	}

	if (new_nsproxy)
		put_nsproxy(new_nsproxy);

bad_unshare_cleanup_semundo:
bad_unshare_cleanup_fd:
	if (new_fd)
		put_files_struct(new_fd);

bad_unshare_cleanup_vm:
	if (new_mm)
		mmput(new_mm);

bad_unshare_cleanup_sigh:
	if (new_sigh)
		if (atomic_dec_and_test(&new_sigh->count))
			kmem_cache_free(sighand_cachep, new_sigh);

bad_unshare_cleanup_fs:
	if (new_fs)
		put_fs_struct(new_fs);

bad_unshare_cleanup_thread:
bad_unshare_out:
	return err;
}
