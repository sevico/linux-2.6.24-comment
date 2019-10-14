/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

struct fib_config {
	u8			fc_dst_len;  //地址长度
	u8			fc_tos;  //服务类型TOS
	u8			fc_protocol;  //路由协议
	u8			fc_scope;  //路由范围
	u8			fc_type;  //路由类型
	/* 3 bytes unused */
	u32			fc_table;  //路由函数表 路由表id
	__be32			fc_dst;  //路由目标地址
	__be32			fc_gw;  //网关
	int			fc_oif;  //网络设备ID
	u32			fc_flags;  //路由标志位
	u32			fc_priority;  //路由优先级
	__be32			fc_prefsrc;  //指定的IP地址
	struct nlattr		*fc_mx;  //指向netlink属性队列
	struct rtnexthop	*fc_mp;  //配置的跳转结构队列
	int			fc_mx_len;  //全部netlink属性队列长度
	int			fc_mp_len;  //全部配置跳转结构的总长度
	u32			fc_flow;  //基于策略路由的分类标签
	u32			fc_nlflags;  //netlink的标志位
	struct nl_info		fc_nlinfo;  //netlink的信息结构
 };

struct fib_info;

struct fib_nh {
	//指向网络设备结构
	struct net_device	*nh_dev;
	//链入到路由设备队列的哈希节点
	struct hlist_node	nh_hash;
	 //指向包含这个跳转的路由信息结构(fib_info)
	struct fib_info		*nh_parent;
	 //跳转标志位
	unsigned		nh_flags;
	 //路由跳转的范围，以此确定下一个跳转
	unsigned char		nh_scope;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	//跳转压力
	int			nh_weight;
	//跳转能力
	int			nh_power;
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	__u32			nh_tclassid;
#endif
	//发送设备的ID
	int			nh_oif;
	//网关的IP地址
	__be32			nh_gw;
};

/*
 * This structure contains data shared by many of routes.
 */

struct fib_info {
//通过fib_hash和fib_lhash链入到两个哈希表中
	//通过fib_hash将fib_info实例插入到fib_info_hash散列表中
	struct hlist_node	fib_hash;
//将fib_info实例插入到fib_info_laddrhash散列表中.在路由表项有一个首选源地址时,才将fib_info结构插入到fib_info_laddrhash
	struct hlist_node	fib_lhash;
//持有该fib_info实例引用的fib_node数据结构的数目
	int			fib_treeref;//路由信息结构的使用计数器
	//由于路由查找成功而持有的引用计数
	atomic_t		fib_clntref;  //是否释放路由信息结构的计数器
	int			fib_dead;  //标志着路由是否被删除了
	//当前使用的唯一标志是RTNH_F_DEAD,表示吓一跳无效.在支持多路径条件下使用
	unsigned		fib_flags;  //标志位
	int			fib_protocol;  //安装路由协议
	__be32			fib_prefsrc;  //指定的源IP地址，源地址是与目标地址组成一个路由
	u32			fib_priority;  //路由的优先级
	u32			fib_metrics[RTAX_MAX];  //用来保存负载值
#define fib_mtu fib_metrics[RTAX_MTU-1]  //MTU值
#define fib_window fib_metrics[RTAX_WINDOW-1]  //窗口值
#define fib_rtt fib_metrics[RTAX_RTT-1]  //RTT值
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]  //对外公开的MSS值
	int			fib_nhs;  //跳转结构fib_nh的长度
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			fib_power;  //支持路径时使用
#endif
	struct fib_nh		fib_nh[0]; //下一个跳转结构
#define fib_dev		fib_nh[0].nh_dev
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

/*
路由查找结果相关的结构体
*/

struct fib_result {
	/*掩码长度*/
	unsigned char	prefixlen;
	/*fib_info变量中的下一跳网关变量的index，根据该index值与struct fib_info结构
类型的变量，就能够找到struct fib_nh结构的变量，从而就能够获取下一跳
网关相关的属性*/
	unsigned char	nh_sel;
	/*路由项的类型:为RTN_MULTICAST、RTN_UNICAST、RTN_BROADCAST等*/
	unsigned char	type;	
	/*路由项的scope:取值为RT_SCOPE_UNIVERSE、RT_SCOPE_LINK等*/
	unsigned char	scope;
	/*指向关联的struct fib_info结构类型的变量*/
	struct fib_info *fi;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	/*指向关联的fib_rule结构的变量，用于策略路由*/
	struct fib_rule	*r;
#endif
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;      
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])
#define FIB_RES_RESET(res)	((res).nh_sel = 0)

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])
#define FIB_RES_RESET(res)

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

struct fib_table {  //路由函数表结构定义
	struct hlist_node tb_hlist;  //哈希节点
	u32		tb_id;  //标识符
	unsigned	tb_stamp;  //时间戳
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);
	int		(*tb_insert)(struct fib_table *, struct fib_config *);
	int		(*tb_delete)(struct fib_table *, struct fib_config *);
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);
	/*清空路由表的规则*/
	int		(*tb_flush)(struct fib_table *table);
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);
	/*可变长数组，主要是用来指向掩码相关的hash数组*/
	unsigned char	tb_data[0];
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

extern struct fib_table *ip_fib_local_table;
extern struct fib_table *ip_fib_main_table;

static inline struct fib_table *fib_get_table(u32 id)
{
	if (id != RT_TABLE_LOCAL)
		return ip_fib_main_table;
	return ip_fib_local_table;
}

static inline struct fib_table *fib_new_table(u32 id)
{
	return fib_get_table(id);
}

static inline int fib_lookup(const struct flowi *flp, struct fib_result *res)
{
	if (ip_fib_local_table->tb_lookup(ip_fib_local_table, flp, res) &&
	    ip_fib_main_table->tb_lookup(ip_fib_main_table, flp, res))
		return -ENETUNREACH;
	return 0;
}

static inline void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	if (FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
		ip_fib_main_table->tb_select_default(ip_fib_main_table, flp, res);
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
extern void __init fib4_rules_init(void);

#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif

#define ip_fib_local_table fib_get_table(RT_TABLE_LOCAL)
#define ip_fib_main_table fib_get_table(RT_TABLE_MAIN)

extern int fib_lookup(struct flowi *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(u32 id);
extern struct fib_table *fib_get_table(u32 id);
extern void fib_select_default(const struct flowi *flp, struct fib_result *res);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern const struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			       struct net_device *dev, __be32 *spec_dst, u32 *itag);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

struct rtentry;

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down(__be32 local, struct net_device *dev, int force);
extern int fib_sync_up(struct net_device *dev);
extern __be32  __fib_res_prefsrc(struct fib_result *res);

/* Exported by fib_hash.c */
extern struct fib_table *fib_hash_init(u32 id);

static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = fib_rules_tclass(res);
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#ifdef CONFIG_PROC_FS
extern int  fib_proc_init(void);
extern void fib_proc_exit(void);
#endif

#endif  /* _NET_FIB_H */
