#ifndef __NET_FIB_RULES_H
#define __NET_FIB_RULES_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/fib_rules.h>
#include <net/flow.h>
#include <net/rtnetlink.h>

struct fib_rule
{
	struct list_head	list;//队列头，用来链入路由规则函数的队列中
	atomic_t		refcnt;  //计数器
	int			ifindex;  //网络设备ID
	char			ifname[IFNAMSIZ];  //用于保存网络设备名称
	u32			mark; //用于过滤作用
	u32			mark_mask;  //掩码
	u32			pref; //优先级
	u32			flags;  //标志位
	u32			table;  //路由函数表id
	u8			action;  //动作标识
	u32			target;
	struct fib_rule *	ctarget;  //当前规则
	struct rcu_head		rcu;
};

struct fib_lookup_arg
{
	void			*lookup_ptr;
	void			*result;
	struct fib_rule		*rule;
};
//路由规则函数表的结构定义
struct fib_rules_ops
{
	int			family; //协议族id
	struct list_head	list;  //队列头
	int			rule_size;  //规则结构长度
	int			addr_size; //地址长度
	int			unresolved_rules;
	int			nr_goto_rules;
	//动作函数指针
	int			(*action)(struct fib_rule *,
					  struct flowi *, int,
					  struct fib_lookup_arg *);
	//匹配函数指针
	int			(*match)(struct fib_rule *,
					 struct flowi *, int);
	//配置函数指针
	int			(*configure)(struct fib_rule *,
					     struct sk_buff *,
					     struct nlmsghdr *,
					     struct fib_rule_hdr *,
					     struct nlattr **);
	//对比函数指针
	int			(*compare)(struct fib_rule *,
					   struct fib_rule_hdr *,
					   struct nlattr **);
	//填充函数指针
	int			(*fill)(struct fib_rule *, struct sk_buff *,
					struct nlmsghdr *,
					struct fib_rule_hdr *);
	//查找优先级函数指针
	u32			(*default_pref)(void);
	//统计负载数据能力函数指针
	size_t			(*nlmsg_payload)(struct fib_rule *);

	/* Called after modifications to the rules set, must flush
	 * the route cache if one exists. */
	 //修改规则后，必须刷新缓存的函数指针
	void			(*flush_cache)(void);

	int			nlgroup; //路由netlink的组划分标识
	const struct nla_policy	*policy; //netlink的属性优先级
	//路由规则队列
	struct list_head	rules_list;
	struct module		*owner;
};

#define FRA_GENERIC_POLICY \
	[FRA_IFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_PRIORITY]	= { .type = NLA_U32 }, \
	[FRA_FWMARK]	= { .type = NLA_U32 }, \
	[FRA_FWMASK]	= { .type = NLA_U32 }, \
	[FRA_TABLE]     = { .type = NLA_U32 }, \
	[FRA_GOTO]	= { .type = NLA_U32 }

static inline void fib_rule_get(struct fib_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static inline void fib_rule_put_rcu(struct rcu_head *head)
{
	struct fib_rule *rule = container_of(head, struct fib_rule, rcu);
	kfree(rule);
}

static inline void fib_rule_put(struct fib_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt))
		call_rcu(&rule->rcu, fib_rule_put_rcu);
}

static inline u32 frh_get_table(struct fib_rule_hdr *frh, struct nlattr **nla)
{
	if (nla[FRA_TABLE])
		return nla_get_u32(nla[FRA_TABLE]);
	return frh->table;
}

extern int			fib_rules_register(struct fib_rules_ops *);
extern int			fib_rules_unregister(struct fib_rules_ops *);

extern int			fib_rules_lookup(struct fib_rules_ops *,
						 struct flowi *, int flags,
						 struct fib_lookup_arg *);
extern int			fib_default_rule_add(struct fib_rules_ops *,
						     u32 pref, u32 table,
						     u32 flags);
#endif
