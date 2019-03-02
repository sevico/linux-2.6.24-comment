/*
 *  linux/kernel/exit.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/tty.h>
#include <linux/mnt_namespace.h>
#include <linux/key.h>
#include <linux/security.h>
#include <linux/cpu.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/profile.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/freezer.h>
#include <linux/cgroup.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/posix-timers.h>
#include <linux/cn_proc.h>
#include <linux/mutex.h>
#include <linux/futex.h>
#include <linux/compat.h>
#include <linux/pipe_fs_i.h>
#include <linux/audit.h> /* for audit_free() */
#include <linux/resource.h>
#include <linux/blkdev.h>
#include <linux/task_io_accounting_ops.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>

extern void sem_exit (void);

static void exit_mm(struct task_struct * tsk);

static void __unhash_process(struct task_struct *p)
{
	nr_threads--;
	detach_pid(p, PIDTYPE_PID);
	if (thread_group_leader(p)) {
		detach_pid(p, PIDTYPE_PGID);
		detach_pid(p, PIDTYPE_SID);

		list_del_rcu(&p->tasks);
		__get_cpu_var(process_counts)--;
	}
	list_del_rcu(&p->thread_group);
	remove_parent(p);
}

/*
 * This function expects the tasklist_lock write-locked.
 */
static void __exit_signal(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	struct sighand_struct *sighand;

	BUG_ON(!sig);
	BUG_ON(!atomic_read(&sig->count));

	rcu_read_lock();
	sighand = rcu_dereference(tsk->sighand);
	spin_lock(&sighand->siglock);

	posix_cpu_timers_exit(tsk);
	if (atomic_dec_and_test(&sig->count))
		posix_cpu_timers_exit_group(tsk);
	else {
		/*
		 * If there is any task waiting for the group exit
		 * then notify it:
		 */
		if (sig->group_exit_task && atomic_read(&sig->count) == sig->notify_count)
			wake_up_process(sig->group_exit_task);

		if (tsk == sig->curr_target)
			sig->curr_target = next_thread(tsk);
		/*
		 * Accumulate here the counters for all threads but the
		 * group leader as they die, so they can be added into
		 * the process-wide totals when those are taken.
		 * The group leader stays around as a zombie as long
		 * as there are other threads.  When it gets reaped,
		 * the exit.c code will add its counts into these totals.
		 * We won't ever get here for the group leader, since it
		 * will have been the last reference on the signal_struct.
		 */
		sig->utime = cputime_add(sig->utime, tsk->utime);
		sig->stime = cputime_add(sig->stime, tsk->stime);
		sig->gtime = cputime_add(sig->gtime, tsk->gtime);
		sig->min_flt += tsk->min_flt;
		sig->maj_flt += tsk->maj_flt;
		sig->nvcsw += tsk->nvcsw;
		sig->nivcsw += tsk->nivcsw;
		sig->inblock += task_io_get_inblock(tsk);
		sig->oublock += task_io_get_oublock(tsk);
		sig->sum_sched_runtime += tsk->se.sum_exec_runtime;
		sig = NULL; /* Marker for below. */
	}
	/**
	 * __unhash_process将进程从各种hash表中摘除。它执行:
	 *    变量nr_threads减1
	 *    两次调用detach_pid，分别从PIDTYPE_PID和PIDTYPE_TGID类型的PID散列表中删除进程描述符。
	 *    如果进程是线程组的领头进程，那么再调用两次detach_pid，从PIDTYPE_PGID和PIDTYPE_SID类型的散列表中删除进程描述符。
	 *    用宏REMOVE_LINKS从进程链表中解除进程描述符的链接。
	 */
	__unhash_process(tsk);

	tsk->signal = NULL;
	tsk->sighand = NULL;
	spin_unlock(&sighand->siglock);
	rcu_read_unlock();
	/**
	 * 删除信号处理函数。
	 */
	__cleanup_sighand(sighand);
	clear_tsk_thread_flag(tsk,TIF_SIGPENDING);
	flush_sigqueue(&tsk->pending);
	if (sig) {
		flush_sigqueue(&sig->shared_pending);
		taskstats_tgid_free(sig);
		__cleanup_signal(sig);
	}
}

static void delayed_put_task_struct(struct rcu_head *rhp)
{
	/**
	 * 递减进程描述符的使用计数器。如果计数器变成0,则终止所有残留的对进程的引用。
	 *     递减进程所有者的user_struct数据结构的使用计数器。如果计数为0，就释放该结构。
	 *     释放进程描述符以及thread_info描述符和内核态堆栈所占用的内存区域。
	 		rcu机制
	 */
	put_task_struct(container_of(rhp, struct task_struct, rcu));
}
/**
 * 释放进程描述符。如果进程已经是僵死状态，就会回收它占用的RAM。
 */
void release_task(struct task_struct * p)
{
	struct task_struct *leader;
	int zap_leader;
repeat:
	/**
	 * 递减进程拥有者的进程个数。
	 */
	atomic_dec(&p->user->processes);
	proc_flush_task(p);
	write_lock_irq(&tasklist_lock);
	/**
	 * 如果进程正被跟踪，函数将它从调试程序的ptrace_children链表中删除，并让该进程重新属于初始的父进程。
	 */
	ptrace_unlink(p);
	BUG_ON(!list_empty(&p->ptrace_list) || !list_empty(&p->ptrace_children));
	/**
	 * 删除所有的挂起信号并释放进程的signal_struct描述符。
	 * 如果该描述符不再被其他的轻量级进程使用，函数进一步删除这个数据结构。
	 * 它还会调用exit_itimers，删除所有POSIX时间间隔定时器。?
	 */
	__exit_signal(p);

	/*
	 * If we are the last non-leader member of the thread
	 * group, and the leader is zombie, then notify the
	 * group leader's parent process. (if it wants notification.)
	 */
	zap_leader = 0;
	leader = p->group_leader;	
	/**
	 * 如果进程不是线程组的领头进程，领头进程处于僵死状态，并且进程是线程组的最后一个成员。
	 */
	if (leader != p && thread_group_empty(leader) && leader->exit_state == EXIT_ZOMBIE) {
		BUG_ON(leader->exit_signal == -1);
		/**
		 * 向领头进程的父进程发送一个信号，通知它:进程已经死亡。
		 */
		do_notify_parent(leader, leader->exit_signal);
		/*
		 * If we were the last child thread and the leader has
		 * exited already, and the leader's parent ignores SIGCHLD,
		 * then we are the one who should release the leader.
		 *
		 * do_notify_parent() will have marked it self-reaping in
		 * that case.
		 */
		zap_leader = (leader->exit_signal == -1);
	}

	write_unlock_irq(&tasklist_lock);
	release_thread(p);
	call_rcu(&p->rcu, delayed_put_task_struct);

	p = leader;
	if (unlikely(zap_leader))
		goto repeat;
}

/*
 * This checks not only the pgrp, but falls back on the pid if no
 * satisfactory pgrp is found. I dunno - gdb doesn't work correctly
 * without this...
 *
 * The caller must hold rcu lock or the tasklist lock.
 */
struct pid *session_of_pgrp(struct pid *pgrp)
{
	struct task_struct *p;
	struct pid *sid = NULL;

	p = pid_task(pgrp, PIDTYPE_PGID);
	if (p == NULL)
		p = pid_task(pgrp, PIDTYPE_PID);
	if (p != NULL)
		sid = task_session(p);

	return sid;
}

/*
 * Determine if a process group is "orphaned", according to the POSIX
 * definition in 2.2.2.52.  Orphaned process groups are not to be affected
 * by terminal-generated stop signals.  Newly orphaned process groups are
 * to receive a SIGHUP and a SIGCONT.
 *
 * "I ask you, have you ever known what it is to be an orphan?"
 */
static int will_become_orphaned_pgrp(struct pid *pgrp, struct task_struct *ignored_task)
{
	struct task_struct *p;
	int ret = 1;

	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		if (p == ignored_task
				|| p->exit_state
				|| is_global_init(p->real_parent))
			continue;
		if (task_pgrp(p->real_parent) != pgrp &&
		    task_session(p->real_parent) == task_session(p)) {
			ret = 0;
			break;
		}
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);
	return ret;	/* (sighing) "Often!" */
}

int is_current_pgrp_orphaned(void)
{
	int retval;

	read_lock(&tasklist_lock);
	retval = will_become_orphaned_pgrp(task_pgrp(current), NULL);
	read_unlock(&tasklist_lock);

	return retval;
}

static int has_stopped_jobs(struct pid *pgrp)
{
	int retval = 0;
	struct task_struct *p;

	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		if (p->state != TASK_STOPPED)
			continue;
		retval = 1;
		break;
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);
	return retval;
}

/**
 * reparent_to_kthreadd - Reparent the calling kernel thread to kthreadd
 *
 * If a kernel thread is launched as a result of a system call, or if
 * it ever exits, it should generally reparent itself to kthreadd so it
 * isn't in the way of other processes and is correctly cleaned up on exit.
 *
 * The various task state such as scheduling policy and priority may have
 * been inherited from a user process, so we reset them to sane values here.
 *
 * NOTE that reparent_to_kthreadd() gives the caller full capabilities.
 */
static void reparent_to_kthreadd(void)
{
	write_lock_irq(&tasklist_lock);

	ptrace_unlink(current);
	/* Reparent to init */
	remove_parent(current);
	current->real_parent = current->parent = kthreadd_task;
	add_parent(current);

	/* Set the exit signal to SIGCHLD so we signal init on exit */
	current->exit_signal = SIGCHLD;

	if (task_nice(current) < 0)
		set_user_nice(current, 0);
	/* cpus_allowed? */
	/* rt_priority? */
	/* signals? */
	security_task_reparent_to_init(current);
	memcpy(current->signal->rlim, init_task.signal->rlim,
	       sizeof(current->signal->rlim));
	atomic_inc(&(INIT_USER->__count));
	write_unlock_irq(&tasklist_lock);
	switch_uid(INIT_USER);
}

void __set_special_pids(pid_t session, pid_t pgrp)
{
	struct task_struct *curr = current->group_leader;

	if (task_session_nr(curr) != session) {
		detach_pid(curr, PIDTYPE_SID);
		set_task_session(curr, session);
		attach_pid(curr, PIDTYPE_SID, find_pid(session));
	}
	if (task_pgrp_nr(curr) != pgrp) {
		detach_pid(curr, PIDTYPE_PGID);
		set_task_pgrp(curr, pgrp);
		attach_pid(curr, PIDTYPE_PGID, find_pid(pgrp));
	}
}

static void set_special_pids(pid_t session, pid_t pgrp)
{
	write_lock_irq(&tasklist_lock);
	__set_special_pids(session, pgrp);
	write_unlock_irq(&tasklist_lock);
}

/*
 * Let kernel threads use this to say that they
 * allow a certain signal (since daemonize() will
 * have disabled all of them by default).
 */
int allow_signal(int sig)
{
	if (!valid_signal(sig) || sig < 1)
		return -EINVAL;

	spin_lock_irq(&current->sighand->siglock);
	sigdelset(&current->blocked, sig);
	if (!current->mm) {
		/* Kernel threads handle their own signals.
		   Let the signal code know it'll be handled, so
		   that they don't get converted to SIGKILL or
		   just silently dropped */
		current->sighand->action[(sig)-1].sa.sa_handler = (void __user *)2;
	}
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
	return 0;
}

EXPORT_SYMBOL(allow_signal);

int disallow_signal(int sig)
{
	if (!valid_signal(sig) || sig < 1)
		return -EINVAL;

	spin_lock_irq(&current->sighand->siglock);
	current->sighand->action[(sig)-1].sa.sa_handler = SIG_IGN;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
	return 0;
}

EXPORT_SYMBOL(disallow_signal);

/*
 *	Put all the gunge required to become a kernel thread without
 *	attached user resources in one place where it belongs.
 */

void daemonize(const char *name, ...)
{
	va_list args;
	struct fs_struct *fs;
	sigset_t blocked;

	va_start(args, name);
	vsnprintf(current->comm, sizeof(current->comm), name, args);
	va_end(args);

	/*
	 * If we were started as result of loading a module, close all of the
	 * user space pages.  We don't need them, and if we didn't close them
	 * they would be locked into memory.
	 */
	exit_mm(current);
	/*
	 * We don't want to have TIF_FREEZE set if the system-wide hibernation
	 * or suspend transition begins right now.
	 */
	current->flags |= PF_NOFREEZE;

	set_special_pids(1, 1);
	proc_clear_tty(current);

	/* Block and flush all signals */
	sigfillset(&blocked);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	flush_signals(current);

	/* Become as one with the init task */

	exit_fs(current);	/* current->fs->count--; */
	fs = init_task.fs;
	current->fs = fs;
	atomic_inc(&fs->count);

	if (current->nsproxy != init_task.nsproxy) {
		get_nsproxy(init_task.nsproxy);
		switch_task_namespaces(current, init_task.nsproxy);
	}

	exit_files(current);
	current->files = init_task.files;
	atomic_inc(&current->files->count);

	reparent_to_kthreadd();
}

EXPORT_SYMBOL(daemonize);

static void close_files(struct files_struct * files)
{
	int i, j;
	struct fdtable *fdt;

	j = 0;

	/*
	 * It is safe to dereference the fd table without RCU or
	 * ->file_lock because this is the last reference to the
	 * files structure.
	 */
	fdt = files_fdtable(files);
	for (;;) {
		unsigned long set;
		i = j * __NFDBITS;
		if (i >= fdt->max_fds)
			break;
		set = fdt->open_fds->fds_bits[j++];
		while (set) {
			if (set & 1) {
				struct file * file = xchg(&fdt->fd[i], NULL);
				if (file) {
					filp_close(file, files);
					cond_resched();
				}
			}
			i++;
			set >>= 1;
		}
	}
}

struct files_struct *get_files_struct(struct task_struct *task)
{
	struct files_struct *files;

	task_lock(task);
	files = task->files;
	if (files)
		atomic_inc(&files->count);
	task_unlock(task);

	return files;
}

void fastcall put_files_struct(struct files_struct *files)
{
	struct fdtable *fdt;

	if (atomic_dec_and_test(&files->count)) {
		close_files(files);
		/*
		 * Free the fd and fdset arrays if we expanded them.
		 * If the fdtable was embedded, pass files for freeing
		 * at the end of the RCU grace period. Otherwise,
		 * you can free files immediately.
		 */
		fdt = files_fdtable(files);
		if (fdt != &files->fdtab)
			kmem_cache_free(files_cachep, files);
		free_fdtable(fdt);
	}
}

EXPORT_SYMBOL(put_files_struct);

void reset_files_struct(struct task_struct *tsk, struct files_struct *files)
{
	struct files_struct *old;

	old = tsk->files;
	task_lock(tsk);
	tsk->files = files;
	task_unlock(tsk);
	put_files_struct(old);
}
EXPORT_SYMBOL(reset_files_struct);

static void __exit_files(struct task_struct *tsk)
{
	struct files_struct * files = tsk->files;

	if (files) {
		task_lock(tsk);
		tsk->files = NULL;
		task_unlock(tsk);
		put_files_struct(files);
	}
}

void exit_files(struct task_struct *tsk)
{
	__exit_files(tsk);
}

static void __put_fs_struct(struct fs_struct *fs)
{
	/* No need to hold fs->lock if we are killing it */
	if (atomic_dec_and_test(&fs->count)) {
		dput(fs->root);
		mntput(fs->rootmnt);
		dput(fs->pwd);
		mntput(fs->pwdmnt);
		if (fs->altroot) {
			dput(fs->altroot);
			mntput(fs->altrootmnt);
		}
		kmem_cache_free(fs_cachep, fs);
	}
}

void put_fs_struct(struct fs_struct *fs)
{
	__put_fs_struct(fs);
}

static void __exit_fs(struct task_struct *tsk)
{
	struct fs_struct * fs = tsk->fs;

	if (fs) {
		task_lock(tsk);
		tsk->fs = NULL;
		task_unlock(tsk);
		__put_fs_struct(fs);
	}
}

void exit_fs(struct task_struct *tsk)
{
	__exit_fs(tsk);
}

EXPORT_SYMBOL_GPL(exit_fs);

/*
 * Turn us into a lazy TLB process if we
 * aren't already..
 */
static void exit_mm(struct task_struct * tsk)
{
	struct mm_struct *mm = tsk->mm;

	mm_release(tsk, mm);
	if (!mm)
		return;
	/*
	 * Serialize with any possible pending coredump.
	 * We must hold mmap_sem around checking core_waiters
	 * and clearing tsk->mm.  The core-inducing thread
	 * will increment core_waiters for each thread in the
	 * group with ->mm != NULL.
	 */
	down_read(&mm->mmap_sem);
	if (mm->core_waiters) {
		up_read(&mm->mmap_sem);
		down_write(&mm->mmap_sem);
		if (!--mm->core_waiters)
			complete(mm->core_startup_done);
		up_write(&mm->mmap_sem);

		wait_for_completion(&mm->core_done);
		down_read(&mm->mmap_sem);
	}
	atomic_inc(&mm->mm_count);
	BUG_ON(mm != tsk->active_mm);
	/* more a memory barrier than a real lock */
	task_lock(tsk);
	tsk->mm = NULL;
	up_read(&mm->mmap_sem);
	enter_lazy_tlb(mm, current);
	/* We don't want this task to be frozen prematurely */
	clear_freeze_flag(tsk);
	task_unlock(tsk);
	mmput(mm);
}

static void
reparent_thread(struct task_struct *p, struct task_struct *father, int traced)
{
	if (p->pdeath_signal)
		/* We already hold the tasklist_lock here.  */
		group_send_sig_info(p->pdeath_signal, SEND_SIG_NOINFO, p);

	/* Move the child from its dying parent to the new one.  */
	if (unlikely(traced)) {
		/* Preserve ptrace links if someone else is tracing this child.  */
		list_del_init(&p->ptrace_list);
		if (p->parent != p->real_parent)
			list_add(&p->ptrace_list, &p->real_parent->ptrace_children);
	} else {
		/* If this child is being traced, then we're the one tracing it
		 * anyway, so let go of it.
		 */
		p->ptrace = 0;
		remove_parent(p);
		p->parent = p->real_parent;
		add_parent(p);

		if (p->state == TASK_TRACED) {
			/*
			 * If it was at a trace stop, turn it into
			 * a normal stop since it's no longer being
			 * traced.
			 */
			ptrace_untrace(p);
		}
	}

	/* If this is a threaded reparent there is no need to
	 * notify anyone anything has happened.
	 */
	if (p->real_parent->group_leader == father->group_leader)
		return;

	/* We don't want people slaying init.  */
	if (p->exit_signal != -1)
		p->exit_signal = SIGCHLD;

	/* If we'd notified the old parent about this child's death,
	 * also notify the new parent.
	 */
	if (!traced && p->exit_state == EXIT_ZOMBIE &&
	    p->exit_signal != -1 && thread_group_empty(p))
		do_notify_parent(p, p->exit_signal);

	/*
	 * process group orphan check
	 * Case ii: Our child is in a different pgrp
	 * than we are, and it was the only connection
	 * outside, so the child pgrp is now orphaned.
	 */
	if ((task_pgrp(p) != task_pgrp(father)) &&
	    (task_session(p) == task_session(father))) {
		struct pid *pgrp = task_pgrp(p);

		if (will_become_orphaned_pgrp(pgrp, NULL) &&
		    has_stopped_jobs(pgrp)) {
			__kill_pgrp_info(SIGHUP, SEND_SIG_PRIV, pgrp);
			__kill_pgrp_info(SIGCONT, SEND_SIG_PRIV, pgrp);
		}
	}
}

/*
 * When we die, we re-parent all our children.
 * Try to give them to another thread in our thread
 * group, and if no such member exists, give it to
 * the child reaper process (ie "init") in our pid
 * space.
 */
static void forget_original_parent(struct task_struct *father)
{
	//参数 father就是当前要退出的进程
	struct task_struct *p, *n, *reaper = father;
	struct list_head ptrace_dead;

	INIT_LIST_HEAD(&ptrace_dead);

	write_lock_irq(&tasklist_lock);
	//reaper就是选定的“继父”，首先在该进程组中寻找一个标志不为PF_EXITING的进程
	//作为“继父”。如果reaper==father,则说明进程组中的所有进程都遍历完了，还没有
	//找到一个满足条件的“继父”，于是就调用task_child_reaper函数获取默认继父
	//通常这个“继父”就是init 进程
	do {
		reaper = next_thread(reaper);
		if (reaper == father) {
			reaper = task_child_reaper(father);
			break;
		}
	} while (reaper->flags & PF_EXITING);

	/*
	 * There are only two places where our children can be:
	 *
	 * - in our child list
	 * - in our ptraced child list
	 *
	 * Search them and reparent children.
	 */
	//根据子进程中的兄弟进程链表处理当前进程的所有子进程
	list_for_each_entry_safe(p, n, &father->children, sibling) {
		int ptrace;

		ptrace = p->ptrace;

		/* if father isn't the real parent, then ptrace must be enabled */
		BUG_ON(father != p->real_parent && !ptrace);
		//如果子进程的real_parent指向当前进程，说明当前进程是真正的父进程
		//那么直接调整子进程的real_parent为它的“继父”
		if (father == p->real_parent) {
			/* reparent with a reaper, real father it's us */
			p->real_parent = reaper;
			reparent_thread(p, father, 0);
		} else {
			/* reparent ptraced task to its real parent
			如果子进程的real_parent不是当前进程，那么说明当前进程是一个调试器
			(调试器作为一个临时的父进程)，而子进程处于被调试状态，现在调试器要退出
			了，所以调整子进程的 parent指向它的real_parent。如果子进程也要退出，
			就向它真正的父进程发送信号
			 */
			__ptrace_unlink (p);
			if (p->exit_state == EXIT_ZOMBIE && p->exit_signal != -1 &&
			    thread_group_empty(p))
				do_notify_parent(p, p->exit_signal);
		}

		/*
		 * if the ptraced child is a zombie with exit_signal == -1
		 * we must collect it before we exit, or it will remain
		 * zombie forever since we prevented it from self-reap itself
		 * while it was being traced by us, to be able to see it in wait4.
		 */
		if (unlikely(ptrace && p->exit_state == EXIT_ZOMBIE && p->exit_signal == -1))
			list_add(&p->ptrace_list, &ptrace_dead);
	}
	//如果当前进程要退出，有些子进程正在被调试，这些被调试的子进程的real_parent
	//指向自己，而 parent指向调试器，现在调整它们的 real_parent指向“继父”进程
	list_for_each_entry_safe(p, n, &father->ptrace_children, ptrace_list) {
		p->real_parent = reaper;
		reparent_thread(p, father, 1);
	}

	write_unlock_irq(&tasklist_lock);
	BUG_ON(!list_empty(&father->children));
	BUG_ON(!list_empty(&father->ptrace_children));

	list_for_each_entry_safe(p, n, &ptrace_dead, ptrace_list) {
		list_del_init(&p->ptrace_list);
		release_task(p);
	}

}

/*
 * Send signals to all our closest relatives so that they know
 * to properly mourn us..
 */
static void exit_notify(struct task_struct *tsk)
{
	int state;
	struct task_struct *t;
	struct pid *pgrp;
	//当进程退出时，如果有一个信号未处理，那么需要查看当前进程是否在某个进程组中
	//如果是就需要唤醒进程组中的其他进程，“委托”它来处理这个信号。什么时候会出现这
	//种情况呢？例如：当前进程在执行do_exit过程中，产生了一个中断，而在中断处理
	//过程中，向该进程发送了一个信号，当中断返回再次调度该进程时，就出现了这种情况
	if (signal_pending(tsk) && !(tsk->signal->flags & SIGNAL_GROUP_EXIT)
	    && !thread_group_empty(tsk)) {
		/*
		 * This occurs when there was a race between our exit
		 * syscall and a group signal choosing us as the one to
		 * wake up.  It could be that we are the only thread
		 * alerted to check for pending signals, but another thread
		 * should be woken now to take the signal since we will not.
		 * Now we'll wake all the threads in the group just to make
		 * sure someone gets all the pending signals.
		 */
		spin_lock_irq(&tsk->sighand->siglock);
		for (t = next_thread(tsk); t != tsk; t = next_thread(t))
			if (!signal_pending(t) && !(t->flags & PF_EXITING))
				recalc_sigpending_and_wake(t);
		spin_unlock_irq(&tsk->sighand->siglock);
	}

	/*
	 * This does two things:
	 *
  	 * A.  Make init inherit all the child processes
	 * B.  Check to see if any process groups have become orphaned
	 *	as a result of our exiting, and if they have any stopped
	 *	jobs, send them a SIGHUP and then a SIGCONT.  (POSIX 3.2.2.2)
	 */
	//调整亲缘关系的相关链表
	forget_original_parent(tsk);
	exit_task_namespaces(tsk);

	write_lock_irq(&tasklist_lock);
	/*
	 * Check to see if any process groups have become orphaned
	 * as a result of our exiting, and if they have any stopped
	 * jobs, send them a SIGHUP and then a SIGCONT.  (POSIX 3.2.2.2)
	 *
	 * Case i: Our father is in a different pgrp than we are
	 * and we were the only connection outside, so our pgrp
	 * is about to become orphaned.
	 */
	t = tsk->real_parent;

	pgrp = task_pgrp(tsk);
	if ((task_pgrp(t) != pgrp) &&
	    (task_session(t) == task_session(tsk)) &&
	    will_become_orphaned_pgrp(pgrp, tsk) &&
	    has_stopped_jobs(pgrp)) {
		__kill_pgrp_info(SIGHUP, SEND_SIG_PRIV, pgrp);
		__kill_pgrp_info(SIGCONT, SEND_SIG_PRIV, pgrp);
	}

	/* Let father know we died
	 *
	 * Thread signals are configurable, but you aren't going to use
	 * that to send signals to arbitary processes.
	 * That stops right now.
	 *
	 * If the parent exec id doesn't match the exec id we saved
	 * when we started then we know the parent has changed security
	 * domain.
	 *
	 * If our self_exec id doesn't match our parent_exec_id then
	 * we have changed execution domain as these two values started
	 * the same after a fork.
	 */
	if (tsk->exit_signal != SIGCHLD && tsk->exit_signal != -1 &&
	    ( tsk->parent_exec_id != t->self_exec_id  ||
	      tsk->self_exec_id != tsk->parent_exec_id)
	    && !capable(CAP_KILL))
		tsk->exit_signal = SIGCHLD;


	/* If something other than our normal parent is ptracing us, then
	 * send it a SIGCHLD instead of honoring exit_signal.  exit_signal
	 * only has special meaning to our real parent.
	 * 向父进程发送信号，exit_signal是进程结束时需要向父进程发送的信号，
	 * 如果是-1，表示没有进程指定该进程结束时要发送什么信号，那么就发送
	 * 默认SIGCHLD，如果当前进程在一个进程组中，则要等进程组中最后一个进程退出时，
	 * 才发送该信号
	 */
	if (tsk->exit_signal != -1 && thread_group_empty(tsk)) {
		int signal = tsk->parent == tsk->real_parent ? tsk->exit_signal : SIGCHLD;
		do_notify_parent(tsk, signal);
	} else if (tsk->ptrace) {
		do_notify_parent(tsk, SIGCHLD);
	}

	state = EXIT_ZOMBIE;
	//-1说明退出时必须向父进程发送信号
	if (tsk->exit_signal == -1 && likely(!tsk->ptrace))
		state = EXIT_DEAD;
	tsk->exit_state = state;
	//唤醒在该进程上等待的进程
	if (thread_group_leader(tsk) &&
	    tsk->signal->notify_count < 0 &&
	    tsk->signal->group_exit_task)
		wake_up_process(tsk->signal->group_exit_task);

	write_unlock_irq(&tasklist_lock);

	/* If the process is dead, release it - nobody will wait for it */
	if (state == EXIT_DEAD)
		release_task(tsk);
}

#ifdef CONFIG_DEBUG_STACK_USAGE
static void check_stack_usage(void)
{
	static DEFINE_SPINLOCK(low_water_lock);
	static int lowest_to_date = THREAD_SIZE;
	unsigned long *n = end_of_stack(current);
	unsigned long free;

	while (*n == 0)
		n++;
	free = (unsigned long)n - (unsigned long)end_of_stack(current);

	if (free >= lowest_to_date)
		return;

	spin_lock(&low_water_lock);
	if (free < lowest_to_date) {
		printk(KERN_WARNING "%s used greatest stack depth: %lu bytes "
				"left\n",
				current->comm, free);
		lowest_to_date = free;
	}
	spin_unlock(&low_water_lock);
}
#else
static inline void check_stack_usage(void) {}
#endif

static inline void exit_child_reaper(struct task_struct *tsk)
{
	if (likely(tsk->group_leader != task_child_reaper(tsk)))
		return;

	if (tsk->nsproxy->pid_ns == &init_pid_ns)
		panic("Attempted to kill init!");

	/*
	 * @tsk is the last thread in the 'cgroup-init' and is exiting.
	 * Terminate all remaining processes in the namespace and reap them
	 * before exiting @tsk.
	 *
	 * Note that @tsk (last thread of cgroup-init) may not necessarily
	 * be the child-reaper (i.e main thread of cgroup-init) of the
	 * namespace i.e the child_reaper may have already exited.
	 *
	 * Even after a child_reaper exits, we let it inherit orphaned children,
	 * because, pid_ns->child_reaper remains valid as long as there is
	 * at least one living sub-thread in the cgroup init.

	 * This living sub-thread of the cgroup-init will be notified when
	 * a child inherited by the 'child-reaper' exits (do_notify_parent()
	 * uses __group_send_sig_info()). Further, when reaping child processes,
	 * do_wait() iterates over children of all living sub threads.

	 * i.e even though 'child_reaper' thread is listed as the parent of the
	 * orphaned children, any living sub-thread in the cgroup-init can
	 * perform the role of the child_reaper.
	 */
	zap_pid_ns_processes(tsk->nsproxy->pid_ns);
}
/**
 * 所有进程的终止都是本函数处理的。
 * 它从内核数据结构中删除对终止进程的大部分引用（注：不是全部，进程描述符就不是）
 * 它接受进程的终止代码作为参数。
 */
fastcall NORET_TYPE void do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

	profile_task_exit(tsk);

	WARN_ON(atomic_read(&tsk->fs_excl));
	//中断环境不允许退出
	if (unlikely(in_interrupt()))
		panic("Aiee, killing interrupt handler!");
	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");
	//如果一个被调试的进程退出，就向父进程(调试器)发送信号
	if (unlikely(current->ptrace & PT_TRACE_EXIT)) {
		current->ptrace_message = code;
		ptrace_notify((PTRACE_EVENT_EXIT << 8) | SIGTRAP);
	}

	/*
	 * We're taking recursive faults here in do_exit. Safest is to just
	 * leave this task alone and wait for reboot.
	 */
	//如果当前进程已经是退出状态，那么说明它已经调用过exit 一次了
	//着一定是出问题了
	if (unlikely(tsk->flags & PF_EXITING)) {
		printk(KERN_ALERT
			"Fixing recursive fault but reboot is needed!\n");
		/*
		 * We can do this unlocked here. The futex code uses
		 * this flag just to verify whether the pi state
		 * cleanup has been done or not. In the worst case it
		 * loops once more. We pretend that the cleanup was
		 * done as there is no way to return. Either the
		 * OWNER_DIED bit is set by now or we push the blocked
		 * task into the wait for ever nirwana as well.
		 */
		/**
	 * PF_EXITING表示进程的状态：正在被删除。
	 */
		tsk->flags |= PF_EXITPIDONE;
		if (tsk->io_context)
			exit_io_context();
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
	}

	tsk->flags |= PF_EXITING;
	/*
	 * tsk->flags are checked in the futex code to protect against
	 * an exiting task cleaning up the robust pi futexes.
	 */
	smp_mb();
	spin_unlock_wait(&tsk->pi_lock);

	if (unlikely(in_atomic()))
		printk(KERN_INFO "note: %s[%d] exited with preempt_count %d\n",
				current->comm, task_pid_nr(current),
				preempt_count());

	acct_update_integrals(tsk);
	if (tsk->mm) {
		update_hiwater_rss(tsk->mm);
		update_hiwater_vm(tsk->mm);
	}
	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead) {
		exit_child_reaper(tsk);
		hrtimer_cancel(&tsk->signal->real_timer);
		exit_itimers(tsk->signal);
	}
	acct_collect(code, group_dead);
#ifdef CONFIG_FUTEX
	if (unlikely(tsk->robust_list))
		exit_robust_list(tsk);
#ifdef CONFIG_COMPAT
	if (unlikely(tsk->compat_robust_list))
		compat_exit_robust_list(tsk);
#endif
#endif
	if (group_dead)
		tty_audit_exit();
	if (unlikely(tsk->audit_context))
		audit_free(tsk);
	//设置进程退出码
	tsk->exit_code = code;
	taskstats_exit(tsk, group_dead);
	/**
	 * exit_mm从进程描述符中分离出分页相关的描述符。
	 * 如果没有其他进程共享这些数据结构，就删除这些数据结构。
	 */
	exit_mm(tsk);

	if (group_dead)
		acct_process();
	/**
	 * exit_sem从进程描述符中分离出信号量相关的描述符
	 */
	exit_sem(tsk);
	/**
	 * __exit_files从进程描述符中分离出文件系统相关的描述符
	 */
	__exit_files(tsk);
	/**
	 * __exit_fs从进程描述符中分离出打开文件描述符相关的描述符
	 */
	__exit_fs(tsk);
	check_stack_usage();
	//进程的thread_struct 结构
	/**
	 * exit_thread从进程描述符中分离出IO权限位图相关的描述符
	 */
	exit_thread();
	cgroup_exit(tsk, 1);
	exit_keys(tsk);

	if (group_dead && tsk->signal->leader)
		disassociate_ctty(1);
	/**
	 * 如果实现了被杀死进程的执行域和可执行格式的内核函数在内核模块中
	 * 就递减它们的值。
	 * 注：这应该是为了防止意外的卸载模块。
	 */
	module_put(task_thread_info(tsk)->exec_domain->module);
	if (tsk->binfmt)
		module_put(tsk->binfmt->module);
	//销毁进程在proc 文件系统中的信息
	proc_exit_connector(tsk);
	//从进程的亲缘关系的链表中解除当前进程，并发送信号到父进程
	exit_notify(tsk);
#ifdef CONFIG_NUMA
	mpol_free(tsk->mempolicy);
	tsk->mempolicy = NULL;
#endif
#ifdef CONFIG_FUTEX
	/*
	 * This must happen late, after the PID is not
	 * hashed anymore:
	 */
	if (unlikely(!list_empty(&tsk->pi_state_list)))
		exit_pi_state_list(tsk);
	if (unlikely(current->pi_state_cache))
		kfree(current->pi_state_cache);
#endif
	/*
	 * Make sure we are holding no locks:
	 */
	debug_check_no_locks_held(tsk);
	/*
	 * We can do this unlocked here. The futex code uses this flag
	 * just to verify whether the pi state cleanup has been done
	 * or not. In the worst case it loops once more.
	 */
	tsk->flags |= PF_EXITPIDONE;

	if (tsk->io_context)
		exit_io_context();

	if (tsk->splice_pipe)
		__free_pipe_info(tsk->splice_pipe);

	preempt_disable();
	/* causes final put_task_struct in finish_task_switch(). */
	tsk->state = TASK_DEAD;
/**
	 * 完了，让其他线程运行吧
	 * 因为schedule会忽略处于EXIT_ZOMBIE状态的进程，所以进程现在是不会再运行了。
	 */
	schedule();
	/**
	 * 当然，谁还会让死掉的进程继续运行，说明内核一定是错了
	 * 注：难道schedule被谁改了，没有判断EXIT_ZOMBIE？？？
	 */
	BUG();
	/* Avoid "noreturn function does return".  */
	/**
	 * 仅仅为了防止编译器报警告信息而已，仅此而已。
	 */
	for (;;)
		cpu_relax();	/* For when BUG is null */
}

EXPORT_SYMBOL_GPL(do_exit);

NORET_TYPE void complete_and_exit(struct completion *comp, long code)
{
	if (comp)
		complete(comp);

	do_exit(code);
}

EXPORT_SYMBOL(complete_and_exit);

asmlinkage long sys_exit(int error_code)
{
	do_exit((error_code&0xff)<<8);
}

/*
 * Take down every thread in the group.  This is called by fatal signals
 * as well as by sys_exit_group (below).
 */
/**
 * 杀死属于current线程组的所有进程.它接受进程终止代码作为参数.
 * 这个参数可能是系统调用exit_group()指定的一个值,也可能是内核提供的一个错误代号.
 */
NORET_TYPE void
do_group_exit(int exit_code)
{
	BUG_ON(exit_code & 0x80); /* core dumps don't get here */
	/**
	 * 检查进程的SIGNAL_GROUP_EXIT,如果不为0,说明内核已经开始为线程组执行退出的过程.
	 */
	if (current->signal->flags & SIGNAL_GROUP_EXIT)
		exit_code = current->signal->group_exit_code;
	else if (!thread_group_empty(current)) {
		/**
		 * 设置进程的SIGNAL_GROUP_EXIT标志,并把终止代号放在sig->group_exit_code
		 */
		struct signal_struct *const sig = current->signal;
		struct sighand_struct *const sighand = current->sighand;
		spin_lock_irq(&sighand->siglock);
		if (sig->flags & SIGNAL_GROUP_EXIT)
			/* Another thread got here before we took the lock.  */
			exit_code = sig->group_exit_code;
		else {
			sig->group_exit_code = exit_code;
			/**
			 * zap_other_threads杀死线程组中的其他线程.
			 * 它扫描PIDTYPE_TGID类型的散列表中的每个PID链表,向表中其他进程发送SIGKILL信号.
			 */
			zap_other_threads(current);
		}
		spin_unlock_irq(&sighand->siglock);
	}
	/**
	 * 杀死当前进程,此过程不再返回.
	 */
	do_exit(exit_code);
	/* NOTREACHED */
}

/*
 * this kills every thread in the thread group. Note that any externally
 * wait4()-ing process will get the correct exit code - even if this
 * thread is not the thread group leader.
 */
asmlinkage void sys_exit_group(int error_code)
{
	do_group_exit((error_code & 0xff) << 8);
}

static int eligible_child(pid_t pid, int options, struct task_struct *p)
{
	int err;
	struct pid_namespace *ns;
	//根据PID判断是不是我们要wait的子进程
	//pid >0:等待的子程程的进程号等于pid
　　 //pid = 0:等待进程组号等于当前进程组号的所有子进程
　　 //pid < -1 :等待任何进程组号等于pid绝对值的子进程
　　 //pid == -1 :等待任何子进程
	ns = current->nsproxy->pid_ns;
	if (pid > 0) {
		if (task_pid_nr_ns(p, ns) != pid)
			return 0;
	} else if (!pid) {
		if (task_pgrp_nr_ns(p, ns) != task_pgrp_vnr(current))
			return 0;
	} else if (pid != -1) {
		if (task_pgrp_nr_ns(p, ns) != -pid)
			return 0;
	}

	/*
	 * Do not consider detached threads that are
	 * not ptraced:
	 */
	//如果子进程exit_signal ==-1且没有被跟踪.那不会对子进程进行回收
	if (p->exit_signal == -1 && !p->ptrace)
		return 0;

	/* Wait for all children (clone and not) if __WALL is set;
	 * otherwise, wait for clone children *only* if __WCLONE is
	 * set; otherwise, wait for non-clone children *only*.  (Note:
	 * A "clone" child here is one that reports to its parent
	 * using a signal other than SIGCHLD.) */
	if (((p->exit_signal != SIGCHLD) ^ ((options & __WCLONE) != 0))
	    && !(options & __WALL))
		return 0;
	/*
	 * Do not consider thread group leaders that are
	 * in a non-empty thread group:
	 */
	//如果子进程是进程组leader,且进程组不为空
	if (delay_group_leader(p))
		return 2;

	err = security_task_wait(p);
	if (err)
		return err;

	return 1;
}

static int wait_noreap_copyout(struct task_struct *p, pid_t pid, uid_t uid,
			       int why, int status,
			       struct siginfo __user *infop,
			       struct rusage __user *rusagep)
{
	int retval = rusagep ? getrusage(p, RUSAGE_BOTH, rusagep) : 0;

	put_task_struct(p);
	if (!retval)
		retval = put_user(SIGCHLD, &infop->si_signo);
	if (!retval)
		retval = put_user(0, &infop->si_errno);
	if (!retval)
		retval = put_user((short)why, &infop->si_code);
	if (!retval)
		retval = put_user(pid, &infop->si_pid);
	if (!retval)
		retval = put_user(uid, &infop->si_uid);
	if (!retval)
		retval = put_user(status, &infop->si_status);
	if (!retval)
		retval = pid;
	return retval;
}

/*
 * Handle sys_wait4 work for one task in state EXIT_ZOMBIE.  We hold
 * read_lock(&tasklist_lock) on entry.  If we return zero, we still hold
 * the lock and this task is uninteresting.  If we return nonzero, we have
 * released the lock and the system call should return.
 */
static int wait_task_zombie(struct task_struct *p, int noreap,
			    struct siginfo __user *infop,
			    int __user *stat_addr, struct rusage __user *ru)
{
	unsigned long state;
	int retval, status, traced;
	struct pid_namespace *ns;

	ns = current->nsproxy->pid_ns;
	//WNOWAIT被设置.不需要释放子进程的资源,只要取相关信息即可
	if (unlikely(noreap)) {
		pid_t pid = task_pid_nr_ns(p, ns);
		uid_t uid = p->uid;
		int exit_code = p->exit_code;
		int why, status;
		//子进程不为EXIT_ZOMBIE .异常退出
		if (unlikely(p->exit_state != EXIT_ZOMBIE))
			return 0;
		//没有退出信号具没有被跟踪.退出
		if (unlikely(p->exit_signal == -1 && p->ptrace == 0))
			return 0;
		//增加引用计数
		get_task_struct(p);
		read_unlock(&tasklist_lock);
		if ((exit_code & 0x7f) == 0) {
			why = CLD_EXITED;
			status = exit_code >> 8;
		} else {
			why = (exit_code & 0x80) ? CLD_DUMPED : CLD_KILLED;
			status = exit_code & 0x7f;
		}
		//取相关信息
		return wait_noreap_copyout(p, pid, uid, why,
					   status, infop, ru);
	}

	/*
	 * Try to move the task's state to DEAD
	 * only one thread is allowed to do this:
	 */
	//将子进程状态设为EXIT_DEAD状态
	state = xchg(&p->exit_state, EXIT_DEAD);
	//如果子进程不为EXIT_ZOMBIE状态,异常退出
	if (state != EXIT_ZOMBIE) {
		BUG_ON(state != EXIT_DEAD);
		return 0;
	}

	/* traced means p->ptrace, but not vice versa */
	//没有退出信号,且没有被跟踪
	traced = (p->real_parent != p->parent);

	if (likely(!traced)) {
		struct signal_struct *psig;
		struct signal_struct *sig;

		/*
		 * The resource counters for the group leader are in its
		 * own task_struct.  Those for dead threads in the group
		 * are in its signal_struct, as are those for the child
		 * processes it has previously reaped.  All these
		 * accumulate in the parent's signal_struct c* fields.
		 *
		 * We don't bother to take a lock here to protect these
		 * p->signal fields, because they are only touched by
		 * __exit_signal, which runs with tasklist_lock
		 * write-locked anyway, and so is excluded here.  We do
		 * need to protect the access to p->parent->signal fields,
		 * as other threads in the parent group can be right
		 * here reaping other children at the same time.
		 */
		//更新父进程的一些统计信息
		spin_lock_irq(&p->parent->sighand->siglock);
		psig = p->parent->signal;
		sig = p->signal;
		psig->cutime =
			cputime_add(psig->cutime,
			cputime_add(p->utime,
			cputime_add(sig->utime,
				    sig->cutime)));
		psig->cstime =
			cputime_add(psig->cstime,
			cputime_add(p->stime,
			cputime_add(sig->stime,
				    sig->cstime)));
		psig->cgtime =
			cputime_add(psig->cgtime,
			cputime_add(p->gtime,
			cputime_add(sig->gtime,
				    sig->cgtime)));
		psig->cmin_flt +=
			p->min_flt + sig->min_flt + sig->cmin_flt;
		psig->cmaj_flt +=
			p->maj_flt + sig->maj_flt + sig->cmaj_flt;
		psig->cnvcsw +=
			p->nvcsw + sig->nvcsw + sig->cnvcsw;
		psig->cnivcsw +=
			p->nivcsw + sig->nivcsw + sig->cnivcsw;
		psig->cinblock +=
			task_io_get_inblock(p) +
			sig->inblock + sig->cinblock;
		psig->coublock +=
			task_io_get_oublock(p) +
			sig->oublock + sig->coublock;
		spin_unlock_irq(&p->parent->sighand->siglock);
	}

	/*
	 * Now we are sure this task is interesting, and no other
	 * thread can reap it because we set its state to EXIT_DEAD.
	 */
	//取得相关的退出信息
	read_unlock(&tasklist_lock);

	retval = ru ? getrusage(p, RUSAGE_BOTH, ru) : 0;
	status = (p->signal->flags & SIGNAL_GROUP_EXIT)
		? p->signal->group_exit_code : p->exit_code;
	if (!retval && stat_addr)
		retval = put_user(status, stat_addr);
	if (!retval && infop)
		retval = put_user(SIGCHLD, &infop->si_signo);
	if (!retval && infop)
		retval = put_user(0, &infop->si_errno);
	if (!retval && infop) {
		int why;

		if ((status & 0x7f) == 0) {
			why = CLD_EXITED;
			status >>= 8;
		} else {
			why = (status & 0x80) ? CLD_DUMPED : CLD_KILLED;
			status &= 0x7f;
		}
		retval = put_user((short)why, &infop->si_code);
		if (!retval)
			retval = put_user(status, &infop->si_status);
	}
	if (!retval && infop)
		retval = put_user(task_pid_nr_ns(p, ns), &infop->si_pid);
	if (!retval && infop)
		retval = put_user(p->uid, &infop->si_uid);
	if (!retval)
		retval = task_pid_nr_ns(p, ns);
	//当前进程不是生父进程.则说明进程是被跟踪出去了
　　 // TODO:子进程exit退出的时候,只会向其当前父进程发送信号的哦^_^
	if (traced) {
		write_lock_irq(&tasklist_lock);
		/* We dropped tasklist, ptracer could die and untrace */
		//将进程从跟踪链表中脱落,并设置父进程为生父进程
		ptrace_unlink(p);
		/*
		 * If this is not a detached task, notify the parent.
		 * If it's still not detached after that, don't release
		 * it now.
		 */
		//如果允许发送信息,则给生父进程发送相关信号
		if (p->exit_signal != -1) {
			do_notify_parent(p, p->exit_signal);
			if (p->exit_signal != -1) {
				p->exit_state = EXIT_ZOMBIE;
				p = NULL;
			}
		}
		write_unlock_irq(&tasklist_lock);
	}
	//释放子进程的剩余资源
	if (p != NULL)
		release_task(p);

	return retval;
}

/*
 * Handle sys_wait4 work for one task in state TASK_STOPPED.  We hold
 * read_lock(&tasklist_lock) on entry.  If we return zero, we still hold
 * the lock and this task is uninteresting.  If we return nonzero, we have
 * released the lock and the system call should return.
 */
static int wait_task_stopped(struct task_struct *p, int delayed_group_leader,
			     int noreap, struct siginfo __user *infop,
			     int __user *stat_addr, struct rusage __user *ru)
{
	int retval, exit_code;
	pid_t pid;
	//进程退出状态码为零.没有相关退出信息
	if (!p->exit_code)
		return 0;
	if (delayed_group_leader && !(p->ptrace & PT_PTRACED) &&
	    p->signal->group_stop_count > 0)
		/*
		 * A group stop is in progress and this is the group leader.
		 * We won't report until all threads have stopped.
		 */
		return 0;

	/*
	 * Now we are pretty sure this task is interesting.
	 * Make sure it doesn't get reaped out from under us while we
	 * give up the lock and then examine it below.  We don't want to
	 * keep holding onto the tasklist_lock while we call getrusage and
	 * possibly take page faults for user memory.
	 */
	pid = task_pid_nr_ns(p, current->nsproxy->pid_ns);
	//正在取task里面的信息,为了防止意外释放,先增加它的引用计数
	get_task_struct(p);
	read_unlock(&tasklist_lock);
	//如果WNOWAIT 被定义
	if (unlikely(noreap)) {
		uid_t uid = p->uid;
		int why = (p->ptrace & PT_PTRACED) ? CLD_TRAPPED : CLD_STOPPED;

		exit_code = p->exit_code;
		//退出状态码为零,但是过程已经处于退出状态中(僵尸或者是死进程)
		if (unlikely(!exit_code) || unlikely(p->exit_state))
			goto bail_ref;
		//把子进程的各项信息保存起来
		//返回值是退出子进程的PID
		return wait_noreap_copyout(p, pid, uid,
					   why, exit_code,
					   infop, ru);
	}

	write_lock_irq(&tasklist_lock);

	/*
	 * This uses xchg to be atomic with the thread resuming and setting
	 * it.  It must also be done with the write lock held to prevent a
	 * race with the EXIT_ZOMBIE case.
	 */
	//如果子进程没有退出.只要取子进程的退出信息,再清除子进程的退出信息即可
	//
	exit_code = xchg(&p->exit_code, 0);
	if (unlikely(p->exit_state)) {
		/*
		 * The task resumed and then died.  Let the next iteration
		 * catch it in EXIT_ZOMBIE.  Note that exit_code might
		 * already be zero here if it resumed and did _exit(0).
		 * The task itself is dead and won't touch exit_code again;
		 * other processors in this function are locked out.
		 */
		p->exit_code = exit_code;
		exit_code = 0;
	}
	if (unlikely(exit_code == 0)) {
		/*
		 * Another thread in this function got to it first, or it
		 * resumed, or it resumed and then died.
		 */
		write_unlock_irq(&tasklist_lock);
bail_ref:
		put_task_struct(p);
		/*
		 * We are returning to the wait loop without having successfully
		 * removed the process and having released the lock. We cannot
		 * continue, since the "p" task pointer is potentially stale.
		 *
		 * Return -EAGAIN, and do_wait() will restart the loop from the
		 * beginning. Do _not_ re-acquire the lock.
		 */
		return -EAGAIN;
	}

	/* move to end of parent's list to avoid starvation */
	//将子进程加到父进程子链表的末尾
	remove_parent(p);
	add_parent(p);

	write_unlock_irq(&tasklist_lock);
	//收集相关的信息
	retval = ru ? getrusage(p, RUSAGE_BOTH, ru) : 0;
	if (!retval && stat_addr)
		retval = put_user((exit_code << 8) | 0x7f, stat_addr);
	if (!retval && infop)
		retval = put_user(SIGCHLD, &infop->si_signo);
	if (!retval && infop)
		retval = put_user(0, &infop->si_errno);
	if (!retval && infop)
		retval = put_user((short)((p->ptrace & PT_PTRACED)
					  ? CLD_TRAPPED : CLD_STOPPED),
				  &infop->si_code);
	if (!retval && infop)
		retval = put_user(exit_code, &infop->si_status);
	if (!retval && infop)
		retval = put_user(pid, &infop->si_pid);
	if (!retval && infop)
		retval = put_user(p->uid, &infop->si_uid);
	if (!retval)
		retval = pid;
	//减少task的引用计数
	put_task_struct(p);

	BUG_ON(!retval);
	return retval;
}

/*
 * Handle do_wait work for one task in a live, non-stopped state.
 * read_lock(&tasklist_lock) on entry.  If we return zero, we still hold
 * the lock and this task is uninteresting.  If we return nonzero, we have
 * released the lock and the system call should return.
 */
static int wait_task_continued(struct task_struct *p, int noreap,
			       struct siginfo __user *infop,
			       int __user *stat_addr, struct rusage __user *ru)
{
	int retval;
	pid_t pid;
	uid_t uid;
	struct pid_namespace *ns;

	if (!(p->signal->flags & SIGNAL_STOP_CONTINUED))
		return 0;

	spin_lock_irq(&p->sighand->siglock);
	/* Re-check with the lock held.  */
	if (!(p->signal->flags & SIGNAL_STOP_CONTINUED)) {
		spin_unlock_irq(&p->sighand->siglock);
		return 0;
	}
	if (!noreap)
		p->signal->flags &= ~SIGNAL_STOP_CONTINUED;
	spin_unlock_irq(&p->sighand->siglock);

	ns = current->nsproxy->pid_ns;
	pid = task_pid_nr_ns(p, ns);
	uid = p->uid;
	get_task_struct(p);
	read_unlock(&tasklist_lock);

	if (!infop) {
		retval = ru ? getrusage(p, RUSAGE_BOTH, ru) : 0;
		put_task_struct(p);
		if (!retval && stat_addr)
			retval = put_user(0xffff, stat_addr);
		if (!retval)
			retval = task_pid_nr_ns(p, ns);
	} else {
		retval = wait_noreap_copyout(p, pid, uid,
					     CLD_CONTINUED, SIGCONT,
					     infop, ru);
		BUG_ON(retval == 0);
	}

	return retval;
}


static inline int my_ptrace_child(struct task_struct *p)
{
	if (!(p->ptrace & PT_PTRACED))
		return 0;
	if (!(p->ptrace & PT_ATTACHED))
		return 1;
	/*
	 * This child was PTRACE_ATTACH'd.  We should be seeing it only if
	 * we are the attacher.  If we are the real parent, this is a race
	 * inside ptrace_attach.  It is waiting for the tasklist_lock,
	 * which we have to switch the parent links, but has already set
	 * the flags in p->ptrace.
	 */
	return (p->parent != p->real_parent);
}

static long do_wait(pid_t pid, int options, struct siginfo __user *infop,
		    int __user *stat_addr, struct rusage __user *ru)
{
	//初始化一个等待队列
	DECLARE_WAITQUEUE(wait, current);
	struct task_struct *tsk;
	int flag, retval;
	int allowed, denied;
	//把等待队列wait添加到wait_childexit 链表上，do_notify_parent
	//函数根据这个链表找到等待的父进程
	add_wait_queue(&current->signal->wait_chldexit,&wait);
repeat:
	/*
	 * We will set this flag if we see any child that might later
	 * match our criteria, even if we are not able to reap it yet.
	 * 当flag 被设置时，说明找到了由 pid指定的子进程，但是这些子进程的当前
	 * 状态，可能不满足退出条件，所以在下面“schedule();”，当前进程需要让出
	 * CPU，知道子进程退出
	 */
	flag = 0;
	allowed = denied = 0;
	//把当前进程设置为可中断等待状态
	current->state = TASK_INTERRUPTIBLE;
	read_lock(&tasklist_lock);
	tsk = current;
	//如果当前进程是一个轻权进程，那么需要在进程组每一个进程的子进程链表
	//中寻找 pid指定的进程。也就是说，要寻找的不仅仅是“自己的儿子”，还包括
	//“自己兄弟的儿子”，这个 do-while 循环就处理进程组的这种情况
	do {
		struct task_struct *p;
		int ret;
		//当前进程可能有多个子进程，在这些子进程中寻找 pid指定的子进程
		//例如当 pid 为-1时，就要循环处理每一个子进程
		list_for_each_entry(p, &tsk->children, sibling) {
			//判断是否是我们要wait 的子进程
			ret = eligible_child(pid, options, p);
			if (!ret)
				continue;

			if (unlikely(ret < 0)) {
				denied = ret;
				continue;
			}
			allowed = 1;

			switch (p->state) {
			//子进程为TASK_TRACED.即处于跟踪状态。则取子进程的相关信息
			case TASK_TRACED:
				/*
				 * When we hit the race with PTRACE_ATTACH,
				 * we will not report this child.  But the
				 * race means it has not yet been moved to
				 * our ptrace_children list, so we need to
				 * set the flag here to avoid a spurious ECHILD
				 * when the race happens with the only child.
				 * 要等待的子进程处于被调试状态，此时子进程的信号将发给
				 * 调试器进程，如果当前进程就是调试器，则my_ptrace_child
				 * 返回1，如果当前进程不是调试器进程就不能进行处理。于是就像代码
				 * 注释中说的 FALLTHROUGH，继续向下执行
				 */
				flag = 1;
				//判断是否是被父进程跟踪的子进程
				//如果是则返回1..不是返回0
				if (!my_ptrace_child(p))
					continue;
				/*FALLTHROUGH*/
			case TASK_STOPPED:
				/*
				 * It's stopped now, so it might later
				 * continue, exit, or stop again.
				 */
				//WUNTRACED:子进程是停止的,也马上返回
				//没有定义WUNTRACED 参数.继续遍历子进程
　　　　　　　　　 /*从此看出.生父进程是不会处理STOP状态的子进程的.只有
　　　　　　　　　 发起跟踪的进程才会
　　　　　　　　　 　*/
				//如果当前进程没有指定WUNTRACED选项，或者子进程不是被当前进程
				//调试的进程，就不处理。可以看出只有调试器才会
				//等待TASK_STOPPED状态的子进程
				flag = 1;
				if (!(options & WUNTRACED) &&
				    !my_ptrace_child(p))
					continue;
				//WNOWAIT:不会将zombie子进程的退出状态撤销
				//下次调用wait系列函数的时候还可以继续获得这个退出状态
				//子进程已经满足条件，从子进程获取必要的信息，如果成功，
				//当前进程就可以跳转到end处直接返回了
				retval = wait_task_stopped(p, ret == 2,
							   (options & WNOWAIT),
							   infop,
							   stat_addr, ru);
				//重试
				if (retval == -EAGAIN)
					goto repeat;
				//成功，父进程可以返回了
				if (retval != 0) /* He released the lock.  */
					goto end;
				break;
			default:
			// case EXIT_DEAD:
				//不需要处理DEAD状态
				//如果子进程的退出状态处于EXIT_DEAD这个进程早已退出，不需要处理
				//因此寻找下一个子进程(主要是为了处理像 pid 为-1这种情况)
				if (p->exit_state == EXIT_DEAD)
					continue;
			// case EXIT_ZOMBIE:
				//子进程为僵尸状态
				//如果子进程的退出状态为EXIT_ZOMBIE，那么说明它正在等待调用wait
				//的父进程来“收拾残局”，那么就省事了，直接获取信息然后返回
				if (p->exit_state == EXIT_ZOMBIE) {
					/*
					 * Eligible but we cannot release
					 * it yet:
					 */
					/*
					由于wait_task_zombie会调用release_task释放某些资源，但是
					如果 pid 为-1，并且子进程p 是一个进程组中的 Group Leader进程，
					而且这个进程组中还有其他进程，这样虽然wait 条件可能会满足，但是
					却不能释放这些资源，这种情况下eligible_child返回2，从而
					跳转到check_continued执行
					 */
					if (ret == 2)
						goto check_continued;
					if (!likely(options & WEXITED))
						continue;
					//从子进程中获取信息，如果成功从end处返回
					retval = wait_task_zombie(
						p, (options & WNOWAIT),
						infop, stat_addr, ru);
					/* He released the lock.  */
					if (retval != 0)
						goto end;
					break;
				}
check_continued:
				/*
				 * It's running now, so it might later
				 * exit, stop, or stop and then continue.
				 */
				flag = 1;
				if (!unlikely(options & WCONTINUED))
					continue;
				//从子进程中获取信息，如果成功从end处返回
				//不会调用release_task释放子进程的相关资源
				retval = wait_task_continued(
					p, (options & WNOWAIT),
					infop, stat_addr, ru);
				if (retval != 0) /* He released the lock.  */
					goto end;
				//如果执行check_continued处这里，说明pid等于-1
				//而当前子进程不满足条件，那么继续处理其他子进程
				break;
			}
		}
		//遍历被跟踪出去的子进程
		//从这里可以看出.如果一个子进程被跟踪出去了.那么子进程的退出
		//操作并不是由生父进程进行了
		/*
		如果当前进程建立了一个子进程，之后某个调试器附加到这个子进程上，
		这样子进程处于被调试状态，这时子进程就临时地变成了调试器的“儿子”，
		但是同时子进程被链接到当前进程的 ptrace_children 链表中。
		如果在第 41 行对子进程链表都遍历完了(flag=0 说明在list_for_each_entry循环中，
		在子进程链表中，没有一个满足条件的子进程）还没有找到合适的子进程，
		那么需要考虑查看 ptrace_listchildren 链表上是否有合适的进程
		 */
		if (!flag) {
			list_for_each_entry(p, &tsk->ptrace_children,
					    ptrace_list) {
				if (!eligible_child(pid, options, p))
					continue;
				flag = 1;
				break;
			}
		}
		//__WNOTHREAD标志表示不需要到进程组中的其他进程寻找 pid 指定的进程
		if (options & __WNOTHREAD)
			break;
		//也有可能是进程中的线程在wait其fork出来的子进程
		tsk = next_thread(tsk);
		BUG_ON(tsk->signal != current->signal);
	} while (tsk != current);

	read_unlock(&tasklist_lock);
	/*
	如果上面的 do-while 循环结束，运行到这里，并且 flag 不为 0, 
	说明当前进程存在由 pid 指定的子进程，但是子进程的当前状态却不是当前进程（父进程）所期待的状态，
	所以当前进程可能要被阻塞了，直到子进程进入这种状态。
	 */
	if (flag) {
		retval = 0;
		//如果定义了WHNOHANG:马上退出
		if (options & WNOHANG)
			goto end;
		retval = -ERESTARTSYS;
		/*
		再次检査当前进程是否有信号，这期间子进程可能进入了所期待的状态，
		那么就不需要让出 CPU 了。例如：当前进程执行到if (flag)，
		某个中断把子进程唤醒，并且 CPU 调度子进程运行，子进程退出，
		当再次调度到当前进程从if (flag)继续执行时，条件就满足了。
		 */
		if (signal_pending(current))
			goto end;
		/*
		让出 CPU，此时其他进程开始执行，当有信号时，例如子进程退出发送信号给父进程，当前进程将被唤醒，
		继续执行，转到 repeat 处重新检査，并从子进程中获取状态，如果成功，就从 end 处返回了。
		 */
		schedule();
		goto repeat;
	}
	retval = -ECHILD;
	if (unlikely(denied) && !allowed)
		retval = denied;
end:
	//将进程设为运行状态,从等待队列中移除
	current->state = TASK_RUNNING;
	remove_wait_queue(&current->signal->wait_chldexit,&wait);
	//复制信息到用户空间
	if (infop) {
		if (retval > 0)
		retval = 0;
		else {
			/*
			 * For a WNOHANG return, clear out all the fields
			 * we would set so the user can easily tell the
			 * difference.
			 */
			if (!retval)
				retval = put_user(0, &infop->si_signo);
			if (!retval)
				retval = put_user(0, &infop->si_errno);
			if (!retval)
				retval = put_user(0, &infop->si_code);
			if (!retval)
				retval = put_user(0, &infop->si_pid);
			if (!retval)
				retval = put_user(0, &infop->si_uid);
			if (!retval)
				retval = put_user(0, &infop->si_status);
		}
	}
	return retval;
}

asmlinkage long sys_waitid(int which, pid_t pid,
			   struct siginfo __user *infop, int options,
			   struct rusage __user *ru)
{
	long ret;

	if (options & ~(WNOHANG|WNOWAIT|WEXITED|WSTOPPED|WCONTINUED))
		return -EINVAL;
	if (!(options & (WEXITED|WSTOPPED|WCONTINUED)))
		return -EINVAL;

	switch (which) {
	case P_ALL:
		pid = -1;
		break;
	case P_PID:
		if (pid <= 0)
			return -EINVAL;
		break;
	case P_PGID:
		if (pid <= 0)
			return -EINVAL;
		pid = -pid;
		break;
	default:
		return -EINVAL;
	}

	ret = do_wait(pid, options, infop, NULL, ru);

	/* avoid REGPARM breakage on x86: */
	prevent_tail_call(ret);
	return ret;
}

asmlinkage long sys_wait4(pid_t pid, int __user *stat_addr,
			  int options, struct rusage __user *ru)
{
	long ret;
	//options的标志为须为WNOHANG…__WALL的组合，否则会出错
	//相关标志的作用在do_wait()中再进行分析
	if (options & ~(WNOHANG|WUNTRACED|WCONTINUED|
			__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;
	ret = do_wait(pid, options | WEXITED, NULL, stat_addr, ru);

	/* avoid REGPARM breakage on x86: */
	prevent_tail_call(ret);
	return ret;
}

#ifdef __ARCH_WANT_SYS_WAITPID

/*
 * sys_waitpid() remains for compatibility. waitpid() should be
 * implemented by calling sys_wait4() from libc.a.
 */
asmlinkage long sys_waitpid(pid_t pid, int __user *stat_addr, int options)
{
	return sys_wait4(pid, stat_addr, options, NULL);
}

#endif
