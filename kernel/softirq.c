/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 * Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#include <linux/tick.h>

#include <asm/irq.h>
/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
     by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
     execution. Hence, we get something sort of weak cpu binding.
     Though it is still not clear, will it result in better locality
     or will not.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
     any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
     it is logically serialized per device, but this serialization
     is invisible to common code.
   - Tasklets: serialized wrt itself.
 */

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS] ____cacheline_aligned;
EXPORT_SYMBOL(irq_stat);
#endif
/**
 * 所有的软中断，目前使用了前六个。数组的下标就是软中断的优先级。
 * 下标越低，优先级越高。
 */
static struct softirq_action softirq_vec[32] __cacheline_aligned_in_smp;

static DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
/*
 * 唤醒本地CPU的ksoftirqd内核线程
 */
static inline void wakeup_softirqd(void)
{
	/* Interrupts are disabled: no need to stop preemption */
	struct task_struct *tsk = __get_cpu_var(ksoftirqd);

	if (tsk && tsk->state != TASK_RUNNING)
		wake_up_process(tsk);
}

/*
 * This one is for softirq.c-internal use,
 * where hardirqs are disabled legitimately:
 */
#ifdef CONFIG_TRACE_IRQFLAGS
static void __local_bh_disable(unsigned long ip)
{
	unsigned long flags;

	WARN_ON_ONCE(in_irq());

	raw_local_irq_save(flags);
	add_preempt_count(SOFTIRQ_OFFSET);
	/*
	 * Were softirqs turned off above:
	 */
	if (softirq_count() == SOFTIRQ_OFFSET)
		trace_softirqs_off(ip);
	raw_local_irq_restore(flags);
}
#else /* !CONFIG_TRACE_IRQFLAGS */
static inline void __local_bh_disable(unsigned long ip)
{
	add_preempt_count(SOFTIRQ_OFFSET);
	barrier();
}
#endif /* CONFIG_TRACE_IRQFLAGS */

void local_bh_disable(void)
{
	__local_bh_disable((unsigned long)__builtin_return_address(0));
}

EXPORT_SYMBOL(local_bh_disable);

void __local_bh_enable(void)
{
	WARN_ON_ONCE(in_irq());

	/*
	 * softirqs should never be enabled by __local_bh_enable(),
	 * it always nests inside local_bh_enable() sections:
	 */
	WARN_ON_ONCE(softirq_count() == SOFTIRQ_OFFSET);

	sub_preempt_count(SOFTIRQ_OFFSET);
}
EXPORT_SYMBOL_GPL(__local_bh_enable);

/*
 * Special-case - softirqs can safely be enabled in
 * cond_resched_softirq(), or by __do_softirq(),
 * without processing still-pending softirqs:
 */
void _local_bh_enable(void)
{
	WARN_ON_ONCE(in_irq());
	WARN_ON_ONCE(!irqs_disabled());

	if (softirq_count() == SOFTIRQ_OFFSET)
		trace_softirqs_on((unsigned long)__builtin_return_address(0));
	sub_preempt_count(SOFTIRQ_OFFSET);
}

EXPORT_SYMBOL(_local_bh_enable);

void local_bh_enable(void)
{
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned long flags;

	WARN_ON_ONCE(in_irq());
#endif
	WARN_ON_ONCE(irqs_disabled());

#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_save(flags);
#endif
	/*
	 * Are softirqs going to be turned on now:
	 */
	if (softirq_count() == SOFTIRQ_OFFSET)
		trace_softirqs_on((unsigned long)__builtin_return_address(0));
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
 	 */
 	sub_preempt_count(SOFTIRQ_OFFSET - 1);

	if (unlikely(!in_interrupt() && local_softirq_pending()))
		do_softirq();

	dec_preempt_count();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_restore(flags);
#endif
	preempt_check_resched();
}
EXPORT_SYMBOL(local_bh_enable);

void local_bh_enable_ip(unsigned long ip)
{
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned long flags;

	WARN_ON_ONCE(in_irq());

	local_irq_save(flags);
#endif
	/*
	 * Are softirqs going to be turned on now:
	 */
	if (softirq_count() == SOFTIRQ_OFFSET)
		trace_softirqs_on(ip);
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
 	 */
 	sub_preempt_count(SOFTIRQ_OFFSET - 1);

	if (unlikely(!in_interrupt() && local_softirq_pending()))
		do_softirq();

	dec_preempt_count();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_restore(flags);
#endif
	preempt_check_resched();
}
EXPORT_SYMBOL(local_bh_enable_ip);

/*
 * We restart softirq processing MAX_SOFTIRQ_RESTART times,
 * and we fall back to softirqd after that.
 *
 * This number has been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_RESTART 10

asmlinkage void __do_softirq(void)
{
	struct softirq_action *h;
	__u32 pending;
	int max_restart = MAX_SOFTIRQ_RESTART;
	int cpu;
	// 获取irq_stat[cpu].__softirq_pending的值
	pending = local_softirq_pending();
	account_system_vtime(current);

	__local_bh_disable((unsigned long)__builtin_return_address(0));
	trace_softirq_enter();

	cpu = smp_processor_id();
restart:
	/* Reset the pending bitmask before enabling irqs */
// 重置irq_stat[cpu].__softirq_pending的值为0，并开启软中断
	set_softirq_pending(0);

	local_irq_enable();
	//获取软中断向量数据softirq_vec
	h = softirq_vec;
	//在一个while循环中，对于每一个未处理的软中断，执行softirq_vec中相对应的action处理函数
	do {
		if (pending & 1) {
			h->action(h);
			rcu_bh_qsctr_inc(cpu);
		}
		h++;
		pending >>= 1;
	} while (pending);
	//关闭中断，重新读取irq_stat[cpu].__softirq_pending的值，若该值不为0则
	local_irq_disable();

	pending = local_softirq_pending();
	//在重复执行的次数没有超过MAX_SOFTIRQ_RESTART，且irq_stat[cpu].__softirq_pending的值不为0
	//时，重新执行上述的操作
	if (pending && --max_restart)
		goto restart;
	// 若已超过MAX_SOFTIRQ_RESTART，则调用wakeup_softirqd，唤醒软中断守护进程，由软中断守护进程继续处理
	if (pending)
		wakeup_softirqd();

	trace_softirq_exit();

	account_system_vtime(current);
	_local_bh_enable();
}

#ifndef __ARCH_HAS_DO_SOFTIRQ

asmlinkage void do_softirq(void)
{
	__u32 pending;
	unsigned long flags;
	/**
	 * 如果in_interrupt返回真，说明系统要么是处于中断中，要么是禁用了软中断。
	 * 请注意in_interrupt()的实现代码：preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK)
	 * 它判断当前是否在硬件中断中，或者是否在软中断中。
	 */
	if (in_interrupt())
		return;
	/**
	 * 在此时需要关闭中断，因为接下来我们需要将判断是否有挂起的软中断
	 * 如果不在关中断的情况下访问这个标志，那么，这个标志就可能被中断程序修改。
	 * 从另一个方面来说，我们还会在后面切换堆栈，这也需要在关中断中进行。
	 * 开中断的时机在__do_softirq中。当然，本函数结束时，也会恢复中断标志。
	 */
	local_irq_save(flags);

	pending = local_softirq_pending();
	/* 有挂起的软中断 */
	if (pending)
		__do_softirq();

	local_irq_restore(flags);
}

#endif

/*
 * Enter an interrupt context.
 */
void irq_enter(void)
{
	__irq_enter();
#ifdef CONFIG_NO_HZ
	if (idle_cpu(smp_processor_id()))
		tick_nohz_update_jiffies();
#endif
}

#ifdef __ARCH_IRQ_EXIT_IRQS_DISABLED
# define invoke_softirq()	__do_softirq()
#else
# define invoke_softirq()	do_softirq()
#endif

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
	account_system_vtime(current);
	trace_hardirq_exit();
	sub_preempt_count(IRQ_EXIT_OFFSET);
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();

#ifdef CONFIG_NO_HZ
	/* Make sure that timer wheel updates are propagated */
	if (!in_interrupt() && idle_cpu(smp_processor_id()) && !need_resched())
		tick_nohz_stop_sched_tick();
#endif
	preempt_enable_no_resched();
}

/*
 * This function must run with irqs disabled!
 */
inline fastcall void raise_softirq_irqoff(unsigned int nr)
{
	/**
	 * 标记nr对应的软中断为挂起状态。
	 */
	__raise_softirq_irqoff(nr);

	/*
	 * If we're in an interrupt or softirq, we're done
	 * (this also catches softirq-disabled code). We will
	 * actually run the softirq once we return from
	 * the irq or softirq.
	 *
	 * Otherwise we wake up ksoftirqd to make sure we
	 * schedule the softirq soon.
	 */
	/**
	 * in_interrupt是判断是否在中断上下文中。
	 * 程序在中断上下文中，表示：要么当前禁用了软中断，要么处在硬中断嵌套中，此时都不用唤醒ksoftirqd内核线程。
	 */
	if (!in_interrupt())
		wakeup_softirqd();
}
/**
 * 激活软中断
 * nr-要激活的软中断下标
 */
void fastcall raise_softirq(unsigned int nr)
{
	unsigned long flags;
	/**
	 * 禁用本地CPU中断。
	 */
	local_irq_save(flags);
	/**
	 * raise_softirq_irqoff是本函数的执行体，不过它是在关中断下运行。
	 */
	raise_softirq_irqoff(nr);
	/**
	 * 打开本地中断
	 */
	local_irq_restore(flags);
}
/**
 * 初始化软中断
 * nr-软中断下标
 * action-软中断处理函数
 * data-软中断处理函数的参数。执行处理函数时，将它回传给软中断。
*/
void open_softirq(int nr, void (*action)(struct softirq_action*), void *data)
{
	softirq_vec[nr].data = data;
	softirq_vec[nr].action = action;
}

/* Tasklets */
struct tasklet_head
{
	struct tasklet_struct *list;
};

/* Some compilers disobey section attribute on statics when not
   initialized -- RR */
static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec) = { NULL };
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec) = { NULL };

void fastcall __tasklet_schedule(struct tasklet_struct *t)
{
	unsigned long flags;
	/**
	 * 首先禁止本地中断。
	 */
	local_irq_save(flags);
	/**
	 * 将tasklet挂到tasklet_vec[n]链表的头。
	 */
	t->next = __get_cpu_var(tasklet_vec).list;
	__get_cpu_var(tasklet_vec).list = t;
	/**
	 * raise_softirq_irqoff激活TASKLET_SOFTIRQ软中断。
	 * 它与raise_soft相似，但是它假设已经关本地中断了。
	 */
	raise_softirq_irqotasklet_actionff(TASKLET_SOFTIRQ);
	/**
	 * 恢复IF标志。
	 */
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_schedule);

void fastcall __tasklet_hi_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = __get_cpu_var(tasklet_hi_vec).list;
	__get_cpu_var(tasklet_hi_vec).list = t;
	raise_softirq_irqoff(HI_SOFTIRQ);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_hi_schedule);

static void tasklet_action(struct softirq_action *a)
{
	struct tasklet_struct *list;
	// 关闭软中断，获取运行CPU所对应的tasklet链表的表头，然后将表头置为NULL，再启中断
	local_irq_disable();
	list = __get_cpu_var(tasklet_vec).list;
	__get_cpu_var(tasklet_vec).list = NULL;
	local_irq_enable();
	//遍历tasklet链表，每次遍历均执行如下操作：
	while (list) {
		//获取tasklet链表的一个tasklet变量
		struct tasklet_struct *t = list;

		list = list->next;
		//保证某一时刻，最多只有一个 CPU 执行同一个 tasklet 函数
		//对该tasklet执行加锁操作，即置位TASKLET_STATE_RUN
		if (tasklet_trylock(t)) {
			//判断当前tasklet是否使能，若已使能，则执行以下操作
			if (!atomic_read(&t->count)) {
				// tasklet的当前状态若为TASKLET_STATE_SCHED，则清空该位
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				//调用该tasklet的回调处理函数
				t->func(t->data);
				// 解锁该tasklet，重新while循环
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}
		//若未使能，则执行以下操作
		//关闭中断
		
		local_irq_disable();
		//将该tasklet重新加入到链表tasklet_vec
		t->next = __get_cpu_var(tasklet_vec).list;
		__get_cpu_var(tasklet_vec).list = t;
		//开启软中断TASKLET_SOFTIRQ，在 下一次处理该软中断时，再处理该tasklet
		__raise_softirq_irqoff(TASKLET_SOFTIRQ);
		//开启中断
		local_irq_enable();
	}
}

static void tasklet_hi_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __get_cpu_var(tasklet_hi_vec).list;
	__get_cpu_var(tasklet_hi_vec).list = NULL;
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = __get_cpu_var(tasklet_hi_vec).list;
		__get_cpu_var(tasklet_hi_vec).list = t;
		__raise_softirq_irqoff(HI_SOFTIRQ);
		local_irq_enable();
	}
}


void tasklet_init(struct tasklet_struct *t,
		  void (*func)(unsigned long), unsigned long data)
{
	t->next = NULL;
	t->state = 0;
	atomic_set(&t->count, 0);
	t->func = func;
	t->data = data;
}

EXPORT_SYMBOL(tasklet_init);
/*确保了 tasklet 不会被再次调度来运行，通常当一个设备正被关闭或者模块卸载时被调用。如果 tasklet 正在运行, 这个函数等待直到它执行完毕。若 tasklet 重新调度它自己，则必须阻止在调用 tasklet_kill 前它重新调度它自己，如同使用 del_timer_sync*/

void tasklet_kill(struct tasklet_struct *t)
{
	if (in_interrupt())
		printk("Attempt to kill tasklet from interrupt\n");

	while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		do
			yield();
		while (test_bit(TASKLET_STATE_SCHED, &t->state));
	}
	tasklet_unlock_wait(t);
	clear_bit(TASKLET_STATE_SCHED, &t->state);
}

EXPORT_SYMBOL(tasklet_kill);

void __init softirq_init(void)
{
	open_softirq(TASKLET_SOFTIRQ, tasklet_action, NULL);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action, NULL);
}

static int ksoftirqd(void * __bind_cpu)
{
	//把ksoftirqd内核线程的状态设置为TASK_INTERRUPTIBLE
	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		preempt_disable();
		//如果没有软件中断需要处理，则调用schedule()主动让出 CPU
		if (!local_softirq_pending()) {
			preempt_enable_no_resched();
			schedule();
			preempt_disable();
		}
		//当需要时，ksoftirqd 被唤醒，并继续执行到这里，现在把状态设置为TASK_RUNNING
		__set_current_state(TASK_RUNNING);

		while (local_softirq_pending()) {
			/* Preempt disable stops cpu going offline.
			   If already offline, we'll be on wrong CPU:
			   don't process */
			   //CPU 热插拔支持
			if (cpu_is_offline((long)__bind_cpu))
				goto wait_to_die;
			//处理软件中断
			/**
			 * 回想一下，do_softirq会设置软中断计数标志，而ininterrupt会根据这个标志返回是否处于中断上下文。
			 * 其实，现在我们是在线程上下文执行do_softirq。
			 * 所以说，ininterrupt有点名不符实。
			 * liufeng: 线程上线问就不会发现有软中断计数器的增加?
			 */
			do_softirq();
			preempt_enable_no_resched();
			/**
			 * 增加一个调度点，仅此而已。
			 */
			cond_resched();
			/**
			 * 现在是增加抢占计数，而不是软中断计数。
			 * 增加软中断计数，防止软中断重入是在do_softirq中。
			 */
			preempt_disable();
		}
		preempt_enable();
		//处理结束，把状态设置为TASK_INTERRUPTIBLE
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;

wait_to_die:
	preempt_enable();
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * tasklet_kill_immediate is called to remove a tasklet which can already be
 * scheduled for execution on @cpu.
 *
 * Unlike tasklet_kill, this function removes the tasklet
 * _immediately_, even if the tasklet is in TASKLET_STATE_SCHED state.
 *
 * When this function is called, @cpu must be in the CPU_DEAD state.
 */
void tasklet_kill_immediate(struct tasklet_struct *t, unsigned int cpu)
{
	struct tasklet_struct **i;

	BUG_ON(cpu_online(cpu));
	BUG_ON(test_bit(TASKLET_STATE_RUN, &t->state));

	if (!test_bit(TASKLET_STATE_SCHED, &t->state))
		return;

	/* CPU is dead, so no lock needed. */
	for (i = &per_cpu(tasklet_vec, cpu).list; *i; i = &(*i)->next) {
		if (*i == t) {
			*i = t->next;
			return;
		}
	}
	BUG();
}

static void takeover_tasklets(unsigned int cpu)
{
	struct tasklet_struct **i;

	/* CPU is dead, so no lock needed. */
	local_irq_disable();

	/* Find end, append list for that CPU. */
	for (i = &__get_cpu_var(tasklet_vec).list; *i; i = &(*i)->next);
	*i = per_cpu(tasklet_vec, cpu).list;
	per_cpu(tasklet_vec, cpu).list = NULL;
	raise_softirq_irqoff(TASKLET_SOFTIRQ);

	for (i = &__get_cpu_var(tasklet_hi_vec).list; *i; i = &(*i)->next);
	*i = per_cpu(tasklet_hi_vec, cpu).list;
	per_cpu(tasklet_hi_vec, cpu).list = NULL;
	raise_softirq_irqoff(HI_SOFTIRQ);

	local_irq_enable();
}
#endif /* CONFIG_HOTPLUG_CPU */

static int __cpuinit cpu_callback(struct notifier_block *nfb,
				  unsigned long action,
				  void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	struct task_struct *p;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		p = kthread_create(ksoftirqd, hcpu, "ksoftirqd/%d", hotcpu);
		if (IS_ERR(p)) {
			printk("ksoftirqd for %i failed\n", hotcpu);
			return NOTIFY_BAD;
		}
		kthread_bind(p, hotcpu);
  		per_cpu(ksoftirqd, hotcpu) = p;
 		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		wake_up_process(per_cpu(ksoftirqd, hotcpu));
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		if (!per_cpu(ksoftirqd, hotcpu))
			break;
		/* Unbind so it can run.  Fall thru. */
		kthread_bind(per_cpu(ksoftirqd, hotcpu),
			     any_online_cpu(cpu_online_map));
	case CPU_DEAD:
	case CPU_DEAD_FROZEN: {
		struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };

		p = per_cpu(ksoftirqd, hotcpu);
		per_cpu(ksoftirqd, hotcpu) = NULL;
		sched_setscheduler(p, SCHED_FIFO, &param);
		kthread_stop(p);
		takeover_tasklets(hotcpu);
		break;
	}
#endif /* CONFIG_HOTPLUG_CPU */
 	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpu_nfb = {
	.notifier_call = cpu_callback
};

__init int spawn_ksoftirqd(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	int err = cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);

	BUG_ON(err == NOTIFY_BAD);
	cpu_callback(&cpu_nfb, CPU_ONLINE, cpu);
	register_cpu_notifier(&cpu_nfb);
	return 0;
}

#ifdef CONFIG_SMP
/*
 * Call a function on all processors
 */
int on_each_cpu(void (*func) (void *info), void *info, int retry, int wait)
{
	int ret = 0;

	preempt_disable();
	ret = smp_call_function(func, info, retry, wait);
	local_irq_disable();
	func(info);
	local_irq_enable();
	preempt_enable();
	return ret;
}
EXPORT_SYMBOL(on_each_cpu);
#endif
