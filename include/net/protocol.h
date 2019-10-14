/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the protocol dispatcher.
 *
 * Version:	@(#)protocol.h	1.0.2	05/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Changes:
 *		Alan Cox	:	Added a name field and a frag handler
 *					field for later.
 *		Alan Cox	:	Cleaned up, and sorted types.
 *		Pedro Roque	:	inet6 protocols
 */
 
#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <linux/in6.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

#define MAX_INET_PROTOS	256		/* Must be a power of 2		*/


/* This is used to register protocols. */
//管理第四层接收数据包的方法
/*
定义了协议族中支持的传输层协议以及传输层的报文接受例程。
此结构是网络层和传输层之间的桥梁，当网络层数据包从网络层流向传输层
的时候，会调用此结构中的传输层协议数据报接受处理函数。
*/
struct net_protocol {
//传输层协议数据报接受处理函数指针
	int			(*handler)(struct sk_buff *skb);
	void			(*err_handler)(struct sk_buff *skb, u32 info);
	int			(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff	       *(*gso_segment)(struct sk_buff *skb,
					       int features);
	int			no_policy;
};

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
struct inet6_protocol 
{
	int	(*handler)(struct sk_buff *skb);

	void	(*err_handler)(struct sk_buff *skb,
			       struct inet6_skb_parm *opt,
			       int type, int code, int offset,
			       __be32 info);

	int	(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff *(*gso_segment)(struct sk_buff *skb,
				       int features);

	unsigned int	flags;	/* INET6_PROTO_xxx */
};

#define INET6_PROTO_NOPOLICY	0x1
#define INET6_PROTO_FINAL	0x2
/* This should be set for any extension header which is compatible with GSO. */
#define INET6_PROTO_GSO_EXTHDR	0x4
#endif

/* This is used to register socket interfaces for IP protocols.  */
//把INET套接字协议族操作集与传输层协议操作集关联起来
struct inet_protosw {
//用于初始化时在散列表中将type值相同的inet_protosw结构实例连接成链表。
	struct list_head list;

        /* These two fields form the lookup key.  */
	//标识套接口类型，对于Internet协议族共有三种类型：SOCK_STREAM、SOCK_DGRAM、SOCK_RAW，与应用程序层创建套接口函数
	//二个参数type取值恰好对应
	unsigned short	 type;	   /* This is the 2nd argument to socket(2). */
	//标识协议族中四层的协议号，Internet协议族中的值包括IPPROTO_TCP、IPPROTO_UDP等
	unsigned short	 protocol; /* This is the L4 protocol number.  */
	//套接口网络层接口。TCP为tcp_prot；UDP为udp_prot；原始套接口为raw_prot
	struct proto	 *prot;
	//套接口传输层接口。TCP为inet_stream_ops；UDP为inet_dgram_ops；原始套接口为inet_sockraw_ops
	const struct proto_ops *ops;
  
	int              capability; /* Which (if any) capability do
				      * we need to use this socket
				      * interface?
                                      */
	char             no_check;   /* checksum on rcv/xmit/none? */
	unsigned char	 flags;      /* See INET_PROTOSW_* below.  */
};
#define INET_PROTOSW_REUSE 0x01	     /* Are ports automatically reusable? */
#define INET_PROTOSW_PERMANENT 0x02  /* Permanent protocols are unremovable. */
#define INET_PROTOSW_ICSK      0x04  /* Is this an inet_connection_sock? */

extern struct net_protocol *inet_protocol_base;
extern struct net_protocol *inet_protos[MAX_INET_PROTOS];

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern struct inet6_protocol *inet6_protos[MAX_INET_PROTOS];
#endif

extern int	inet_add_protocol(struct net_protocol *prot, unsigned char num);
extern int	inet_del_protocol(struct net_protocol *prot, unsigned char num);
extern void	inet_register_protosw(struct inet_protosw *p);
extern void	inet_unregister_protosw(struct inet_protosw *p);

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern int	inet6_add_protocol(struct inet6_protocol *prot, unsigned char num);
extern int	inet6_del_protocol(struct inet6_protocol *prot, unsigned char num);
extern void	inet6_register_protosw(struct inet_protosw *p);
extern void	inet6_unregister_protosw(struct inet_protosw *p);
#endif

#endif	/* _PROTOCOL_H */
