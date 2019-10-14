/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: policy rules.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * 		Thomas Graf <tgraf@suug.ch>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Fixes:
 * 		Rani Assaf	:	local_rule cannot be deleted
 *		Marc Boucher	:	routing by fwmark
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/ip_fib.h>
#include <net/fib_rules.h>

static struct fib_rules_ops fib4_rules_ops;

struct fib4_rule
{
	struct fib_rule		common;
	u8			dst_len;
	u8			src_len;
	u8			tos;
	__be32			src;
	__be32			srcmask;
	__be32			dst;
	__be32			dstmask;
#ifdef CONFIG_NET_CLS_ROUTE
	u32			tclassid;
#endif
};

#ifdef CONFIG_NET_CLS_ROUTE
u32 fib_rules_tclass(struct fib_result *res)
{
	return res->r ? ((struct fib4_rule *) res->r)->tclassid : 0;
}
#endif

int fib_lookup(struct flowi *flp, struct fib_result *res)
{
	struct fib_lookup_arg arg = {
		.result = res,
	};
	int err;

	err = fib_rules_lookup(&fib4_rules_ops, flp, 0, &arg);
	res->r = arg.rule;

	return err;
}
/*
功能:ipv4的fib rule 的操作函数action
1.根据rule的action规则决定后续操作，对于支持策略路由而言，我们建立fib rule的
   action均是FR_ACT_TO_TBL，而对于FR_ACT_UNREACHABLE、FR_ACT_PROHIBIT、FR_ACT_BLACKHOLE等均是
   返回相应的失败码。而对于FR_ACT_TO_TBL，则需要进一步进行路由项的查找
2.对于FR_ACT_TO_TBL，则根据fib_rule->table的table id值，调用函数fib_get_table获取相应的路由
   表，接着就是调用路由表的查找路由函数tb_lookup进行路由项的查找，对于ipv4
   其路由表的tb_lookup即为函数fn_hash_lookup
*/

static int fib4_rule_action(struct fib_rule *rule, struct flowi *flp,
			    int flags, struct fib_lookup_arg *arg)
{
	int err = -EAGAIN;
	struct fib_table *tbl;

	switch (rule->action) {
	case FR_ACT_TO_TBL:
		break;

	case FR_ACT_UNREACHABLE:
		err = -ENETUNREACH;
		goto errout;

	case FR_ACT_PROHIBIT:
		err = -EACCES;
		goto errout;

	case FR_ACT_BLACKHOLE:
	default:
		err = -EINVAL;
		goto errout;
	}

	if ((tbl = fib_get_table(rule->table)) == NULL)
		goto errout;

	err = tbl->tb_lookup(tbl, flp, (struct fib_result *) arg->result);
	if (err > 0)
		err = -EAGAIN;
errout:
	return err;
}


void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	if (res->r && res->r->action == FR_ACT_TO_TBL &&
	    FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK) {
		struct fib_table *tb;
		if ((tb = fib_get_table(res->r->table)) != NULL)
			tb->tb_select_default(tb, flp, res);
	}
}
/*
这个函数主要是对源ip地址、目的ip地址以及tos的匹配操作。
(fib rule的添加类似于如下命令:
# ip rule add fwmark 0x4/0x40004 from  192.168.1.1/32 to 192.168.33.9/24 tos 10 iif br0 table 231)
*/
static int fib4_rule_match(struct fib_rule *rule, struct flowi *fl, int flags)
{
	struct fib4_rule *r = (struct fib4_rule *) rule;
	__be32 daddr = fl->fl4_dst;
	__be32 saddr = fl->fl4_src;

	if (((saddr ^ r->src) & r->srcmask) ||
	    ((daddr ^ r->dst) & r->dstmask))
		return 0;

	if (r->tos && (r->tos != fl->fl4_tos))
		return 0;

	return 1;
}
//从0开始到RT_TABLE_MAX为止，找到第一个没有创建路由表的id后，
// 即调用fib_new_table创建此id对应的路由表，并返回路由表的首地址；
//若从0开始到RT_TABLE_MAX的id，都有创建相应的路由表了，则程序返回NULL
static struct fib_table *fib_empty_table(void)
{
	u32 id;

	for (id = 1; id <= RT_TABLE_MAX; id++)
		if (fib_get_table(id) == NULL)
			return fib_new_table(id);
	return NULL;
}

static const struct nla_policy fib4_rule_policy[FRA_MAX+1] = {
	FRA_GENERIC_POLICY,
	[FRA_FLOW]	= { .type = NLA_U32 },
};
//当新增加一个ipv4 的fib rule 规则时，就会调用该函数，对
//新创建的struct fib4_rule类型的变量进行初始化操作，即根据
//应用层传递的配置参数，设置struct fib4_rule类型的变量的
//源ip地址、源ip的掩码值、目的ip地址、目的ip的掩码值、路由表id、tos等
static int fib4_rule_configure(struct fib_rule *rule, struct sk_buff *skb,
			       struct nlmsghdr *nlh, struct fib_rule_hdr *frh,
			       struct nlattr **tb)
{
	int err = -EINVAL;
	struct fib4_rule *rule4 = (struct fib4_rule *) rule;

	if (frh->tos & ~IPTOS_TOS_MASK)
		goto errout;

	if (rule->table == RT_TABLE_UNSPEC) {
		if (rule->action == FR_ACT_TO_TBL) {
			struct fib_table *table;
			/*
若应用层没有设置路由表的id，则调用fib_empty_table创建
一个新的路由表，并将新创建的路由表的id传递
给rule->table
(使用如下命令，即会使系统创建一个新的路由表
# ip rule add from 192.168.192.1 table 0)
*/
			table = fib_empty_table();
			if (table == NULL) {
				err = -ENOBUFS;
				goto errout;
			}

			rule->table = table->tb_id;
		}
	}

	if (frh->src_len)
		rule4->src = nla_get_be32(tb[FRA_SRC]);

	if (frh->dst_len)
		rule4->dst = nla_get_be32(tb[FRA_DST]);

#ifdef CONFIG_NET_CLS_ROUTE
	if (tb[FRA_FLOW])
		rule4->tclassid = nla_get_u32(tb[FRA_FLOW]);
#endif

	rule4->src_len = frh->src_len;
	rule4->srcmask = inet_make_mask(rule4->src_len);
	rule4->dst_len = frh->dst_len;
	rule4->dstmask = inet_make_mask(rule4->dst_len);
	rule4->tos = frh->tos;

	err = 0;
errout:
	return err;
}

static int fib4_rule_compare(struct fib_rule *rule, struct fib_rule_hdr *frh,
			     struct nlattr **tb)
{
	struct fib4_rule *rule4 = (struct fib4_rule *) rule;

	if (frh->src_len && (rule4->src_len != frh->src_len))
		return 0;

	if (frh->dst_len && (rule4->dst_len != frh->dst_len))
		return 0;

	if (frh->tos && (rule4->tos != frh->tos))
		return 0;

#ifdef CONFIG_NET_CLS_ROUTE
	if (tb[FRA_FLOW] && (rule4->tclassid != nla_get_u32(tb[FRA_FLOW])))
		return 0;
#endif

	if (frh->src_len && (rule4->src != nla_get_be32(tb[FRA_SRC])))
		return 0;

	if (frh->dst_len && (rule4->dst != nla_get_be32(tb[FRA_DST])))
		return 0;

	return 1;
}

static int fib4_rule_fill(struct fib_rule *rule, struct sk_buff *skb,
			  struct nlmsghdr *nlh, struct fib_rule_hdr *frh)
{
	struct fib4_rule *rule4 = (struct fib4_rule *) rule;

	frh->family = AF_INET;
	frh->dst_len = rule4->dst_len;
	frh->src_len = rule4->src_len;
	frh->tos = rule4->tos;

	if (rule4->dst_len)
		NLA_PUT_BE32(skb, FRA_DST, rule4->dst);

	if (rule4->src_len)
		NLA_PUT_BE32(skb, FRA_SRC, rule4->src);

#ifdef CONFIG_NET_CLS_ROUTE
	if (rule4->tclassid)
		NLA_PUT_U32(skb, FRA_FLOW, rule4->tclassid);
#endif
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

static u32 fib4_rule_default_pref(void)
{
	struct list_head *pos;
	struct fib_rule *rule;

	if (!list_empty(&fib4_rules_ops.rules_list)) {
		pos = fib4_rules_ops.rules_list.next;
		if (pos->next != &fib4_rules_ops.rules_list) {
			rule = list_entry(pos->next, struct fib_rule, list);
			if (rule->pref)
				return rule->pref - 1;
		}
	}

	return 0;
}

static size_t fib4_rule_nlmsg_payload(struct fib_rule *rule)
{
	return nla_total_size(4) /* dst */
	       + nla_total_size(4) /* src */
	       + nla_total_size(4); /* flow */
}

static void fib4_rule_flush_cache(void)
{
	rt_cache_flush(-1);
}

static struct fib_rules_ops fib4_rules_ops = {
	.family		= AF_INET,
	.rule_size	= sizeof(struct fib4_rule),
	.addr_size	= sizeof(u32),
	.action		= fib4_rule_action,
	.match		= fib4_rule_match,
	.configure	= fib4_rule_configure,
	.compare	= fib4_rule_compare,
	.fill		= fib4_rule_fill,
	.default_pref	= fib4_rule_default_pref,
	.nlmsg_payload	= fib4_rule_nlmsg_payload,
	.flush_cache	= fib4_rule_flush_cache,
	.nlgroup	= RTNLGRP_IPV4_RULE,
	.policy		= fib4_rule_policy,
	.rules_list	= LIST_HEAD_INIT(fib4_rules_ops.rules_list),
	.owner		= THIS_MODULE,
};

static int __init fib_default_rules_init(void)
{
	int err;

	err = fib_default_rule_add(&fib4_rules_ops, 0,
				   RT_TABLE_LOCAL, FIB_RULE_PERMANENT);
	if (err < 0)
		return err;
	err = fib_default_rule_add(&fib4_rules_ops, 0x7FFE,
				   RT_TABLE_MAIN, 0);
	if (err < 0)
		return err;
	err = fib_default_rule_add(&fib4_rules_ops, 0x7FFF,
				   RT_TABLE_DEFAULT, 0);
	if (err < 0)
		return err;
	return 0;
}

void __init fib4_rules_init(void)
{
	BUG_ON(fib_default_rules_init());
	fib_rules_register(&fib4_rules_ops);
}
