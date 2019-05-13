/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The User Datagram Protocol (UDP).
 *
 * Version:	$Id: udp.c,v 1.102 2002/02/01 22:01:04 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 * Fixes:
 *		Alan Cox	:	verify_area() calls
 *		Alan Cox	: 	stopped close while in use off icmp
 *					messages. Not a fix but a botch that
 *					for udp at least is 'valid'.
 *		Alan Cox	:	Fixed icmp handling properly
 *		Alan Cox	: 	Correct error for oversized datagrams
 *		Alan Cox	:	Tidied select() semantics.
 *		Alan Cox	:	udp_err() fixed properly, also now
 *					select and read wake correctly on errors
 *		Alan Cox	:	udp_send verify_area moved to avoid mem leak
 *		Alan Cox	:	UDP can count its memory
 *		Alan Cox	:	send to an unknown connection causes
 *					an ECONNREFUSED off the icmp, but
 *					does NOT close.
 *		Alan Cox	:	Switched to new sk_buff handlers. No more backlog!
 *		Alan Cox	:	Using generic datagram code. Even smaller and the PEEK
 *					bug no longer crashes it.
 *		Fred Van Kempen	: 	Net2e support for sk->broadcast.
 *		Alan Cox	:	Uses skb_free_datagram
 *		Alan Cox	:	Added get/set sockopt support.
 *		Alan Cox	:	Broadcasting without option set returns EACCES.
 *		Alan Cox	:	No wakeup calls. Instead we now use the callbacks.
 *		Alan Cox	:	Use ip_tos and ip_ttl
 *		Alan Cox	:	SNMP Mibs
 *		Alan Cox	:	MSG_DONTROUTE, and 0.0.0.0 support.
 *		Matt Dillon	:	UDP length checks.
 *		Alan Cox	:	Smarter af_inet used properly.
 *		Alan Cox	:	Use new kernel side addressing.
 *		Alan Cox	:	Incorrect return on truncated datagram receive.
 *	Arnt Gulbrandsen 	:	New udp_send and stuff
 *		Alan Cox	:	Cache last socket
 *		Alan Cox	:	Route cache
 *		Jon Peatfield	:	Minor efficiency fix to sendto().
 *		Mike Shaver	:	RFC1122 checks.
 *		Alan Cox	:	Nonblocking error fix.
 *	Willy Konynenberg	:	Transparent proxying support.
 *		Mike McLagan	:	Routing by source
 *		David S. Miller	:	New socket lookup architecture.
 *					Last socket cache retained as it
 *					does have a high hit rate.
 *		Olaf Kirch	:	Don't linearise iovec on sendmsg.
 *		Andi Kleen	:	Some cleanups, cache destination entry
 *					for connect.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Melvin Smith	:	Check msg_name not msg_namelen in sendto(),
 *					return ENOTCONN for unconnected sockets (POSIX)
 *		Janos Farkas	:	don't deliver multi/broadcasts to a different
 *					bound-to-device socket
 *	Hirokazu Takahashi	:	HW checksumming for outgoing UDP
 *					datagrams.
 *	Hirokazu Takahashi	:	sendfile() on UDP works now.
 *		Arnaldo C. Melo :	convert /proc/net/udp to seq_file
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov:		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 *	Derek Atkins <derek@ihtfp.com>: Add Encapulation Support
 *	James Chapman		:	Add L2TP encapsulation type.
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include "udp_impl.h"

/*
 *	Snmp MIB for the UDP layer
 */

DEFINE_SNMP_STAT(struct udp_mib, udp_statistics) __read_mostly;

struct hlist_head udp_hash[UDP_HTABLE_SIZE];
DEFINE_RWLOCK(udp_hash_lock);

static inline int __udp_lib_lport_inuse(__u16 num,
					const struct hlist_head udptable[])
{
	struct sock *sk;
	struct hlist_node *node;

	sk_for_each(sk, node, &udptable[num & (UDP_HTABLE_SIZE - 1)])
		if (sk->sk_hash == num)
			return 1;
	return 0;
}

/**
 *  __udp_lib_get_port  -  UDP/-Lite port lookup for IPv4 and IPv6
 *
 *  @sk:          socket struct in question
 *  @snum:        port number to look up
 *  @udptable:    hash list table, must be of UDP_HTABLE_SIZE
 *  @saddr_comp:  AF-dependent comparison of bound local IP addresses
 */
int __udp_lib_get_port(struct sock *sk, unsigned short snum,
		       struct hlist_head udptable[],
		       int (*saddr_comp)(const struct sock *sk1,
					 const struct sock *sk2 )    )
{
	struct hlist_node *node;
	struct hlist_head *head;
	struct sock *sk2;
	int    error = 1;

	write_lock_bh(&udp_hash_lock);

	if (!snum) {
		int i, low, high, remaining;
		unsigned rover, best, best_size_so_far;

		inet_get_local_port_range(&low, &high);
		remaining = (high - low) + 1;

		best_size_so_far = UINT_MAX;
		best = rover = net_random() % remaining + low;

		/* 1st pass: look for empty (or shortest) hash chain */
		for (i = 0; i < UDP_HTABLE_SIZE; i++) {
			int size = 0;

			head = &udptable[rover & (UDP_HTABLE_SIZE - 1)];
			if (hlist_empty(head))
				goto gotit;

			sk_for_each(sk2, node, head) {
				if (++size >= best_size_so_far)
					goto next;
			}
			best_size_so_far = size;
			best = rover;
		next:
			/* fold back if end of range */
			if (++rover > high)
				rover = low + ((rover - low)
					       & (UDP_HTABLE_SIZE - 1));


		}

		/* 2nd pass: find hole in shortest hash chain */
		rover = best;
		for (i = 0; i < (1 << 16) / UDP_HTABLE_SIZE; i++) {
			if (! __udp_lib_lport_inuse(rover, udptable))
				goto gotit;
			rover += UDP_HTABLE_SIZE;
			if (rover > high)
				rover = low + ((rover - low)
					       & (UDP_HTABLE_SIZE - 1));
		}


		/* All ports in use! */
		goto fail;

gotit:
		snum = rover;
	} else {
		head = &udptable[snum & (UDP_HTABLE_SIZE - 1)];

		sk_for_each(sk2, node, head)
			if (sk2->sk_hash == snum                             &&
			    sk2 != sk                                        &&
			    (!sk2->sk_reuse        || !sk->sk_reuse)         &&
			    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if
			     || sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
			    (*saddr_comp)(sk, sk2)                             )
				goto fail;
	}

	inet_sk(sk)->num = snum;
	sk->sk_hash = snum;
	if (sk_unhashed(sk)) {
		head = &udptable[snum & (UDP_HTABLE_SIZE - 1)];
		sk_add_node(sk, head);
		sock_prot_inc_use(sk->sk_prot);
	}
	error = 0;
fail:
	write_unlock_bh(&udp_hash_lock);
	return error;
}

int udp_get_port(struct sock *sk, unsigned short snum,
			int (*scmp)(const struct sock *, const struct sock *))
{
	return  __udp_lib_get_port(sk, snum, udp_hash, scmp);
}

int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
{
	struct inet_sock *inet1 = inet_sk(sk1), *inet2 = inet_sk(sk2);

	return 	( !ipv6_only_sock(sk2)  &&
		  (!inet1->rcv_saddr || !inet2->rcv_saddr ||
		   inet1->rcv_saddr == inet2->rcv_saddr      ));
}

static inline int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
	return udp_get_port(sk, snum, ipv4_rcv_saddr_equal);
}

/* UDP is nearly always wildcards out the wazoo, it makes no sense to try
 * harder than this. -DaveM
 */
static struct sock *__udp4_lib_lookup(__be32 saddr, __be16 sport,
				      __be32 daddr, __be16 dport,
				      int dif, struct hlist_head udptable[])
{
	struct sock *sk, *result = NULL;
	struct hlist_node *node;
	unsigned short hnum = ntohs(dport);
	int badness = -1;

	read_lock(&udp_hash_lock);
	sk_for_each(sk, node, &udptable[hnum & (UDP_HTABLE_SIZE - 1)]) {
		struct inet_sock *inet = inet_sk(sk);

		if (sk->sk_hash == hnum && !ipv6_only_sock(sk)) {
			int score = (sk->sk_family == PF_INET ? 1 : 0);
			if (inet->rcv_saddr) {
				if (inet->rcv_saddr != daddr)
					continue;
				score+=2;
			}
			if (inet->daddr) {
				if (inet->daddr != saddr)
					continue;
				score+=2;
			}
			if (inet->dport) {
				if (inet->dport != sport)
					continue;
				score+=2;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score+=2;
			}
			if (score == 9) {
				result = sk;
				break;
			} else if (score > badness) {
				result = sk;
				badness = score;
			}
		}
	}
	if (result)
		sock_hold(result);
	read_unlock(&udp_hash_lock);
	return result;
}

static inline struct sock *udp_v4_mcast_next(struct sock *sk,
					     __be16 loc_port, __be32 loc_addr,
					     __be16 rmt_port, __be32 rmt_addr,
					     int dif)
{
	struct hlist_node *node;
	struct sock *s = sk;
	unsigned short hnum = ntohs(loc_port);

	sk_for_each_from(s, node) {
		struct inet_sock *inet = inet_sk(s);

		if (s->sk_hash != hnum					||
		    (inet->daddr && inet->daddr != rmt_addr)		||
		    (inet->dport != rmt_port && inet->dport)		||
		    (inet->rcv_saddr && inet->rcv_saddr != loc_addr)	||
		    ipv6_only_sock(s)					||
		    (s->sk_bound_dev_if && s->sk_bound_dev_if != dif))
			continue;
		if (!ip_mc_sf_allow(s, loc_addr, rmt_addr, dif))
			continue;
		goto found;
	}
	s = NULL;
found:
	return s;
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition.  If err < 0 then the socket should
 * be closed and the error returned to the user.  If err > 0
 * it's just the icmp type << 8 | icmp code.
 * Header points to the ip header of the error packet. We move
 * on past this. Then (as it used to claim before adjustment)
 * header points to the first 8 bytes of the udp header.  We need
 * to find the appropriate port.
 */

void __udp4_lib_err(struct sk_buff *skb, u32 info, struct hlist_head udptable[])
{
	struct inet_sock *inet;
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct udphdr *uh = (struct udphdr*)(skb->data+(iph->ihl<<2));
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	struct sock *sk;
	int harderr;
	int err;

	sk = __udp4_lib_lookup(iph->daddr, uh->dest, iph->saddr, uh->source,
			       skb->dev->ifindex, udptable		    );
	if (sk == NULL) {
		ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
		return;	/* No socket for error */
	}

	err = 0;
	harderr = 0;
	inet = inet_sk(sk);

	switch (type) {
	default:
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	case ICMP_SOURCE_QUENCH:
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		harderr = 1;
		break;
	case ICMP_DEST_UNREACH:
		if (code == ICMP_FRAG_NEEDED) { /* Path MTU discovery */
			if (inet->pmtudisc != IP_PMTUDISC_DONT) {
				err = EMSGSIZE;
				harderr = 1;
				break;
			}
			goto out;
		}
		err = EHOSTUNREACH;
		if (code <= NR_ICMP_UNREACH) {
			harderr = icmp_err_convert[code].fatal;
			err = icmp_err_convert[code].errno;
		}
		break;
	}

	/*
	 *      RFC1122: OK.  Passes ICMP errors back to application, as per
	 *	4.1.3.3.
	 */
	if (!inet->recverr) {
		if (!harderr || sk->sk_state != TCP_ESTABLISHED)
			goto out;
	} else {
		ip_icmp_error(sk, skb, err, uh->dest, info, (u8*)(uh+1));
	}
	sk->sk_err = err;
	sk->sk_error_report(sk);
out:
	sock_put(sk);
}

void udp_err(struct sk_buff *skb, u32 info)
{
	return __udp4_lib_err(skb, info, udp_hash);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void udp_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip_flush_pending_frames(sk);
	}
}

/**
 * 	udp4_hwcsum_outgoing  -  handle outgoing HW checksumming
 * 	@sk: 	socket we are sending on
 * 	@skb: 	sk_buff containing the filled-in UDP header
 * 	        (checksum field must be zeroed out)
 */
static void udp4_hwcsum_outgoing(struct sock *sk, struct sk_buff *skb,
				 __be32 src, __be32 dst, int len      )
{
	unsigned int offset;
	struct udphdr *uh = udp_hdr(skb);
	__wsum csum = 0;

	if (skb_queue_len(&sk->sk_write_queue) == 1) {
		/*
		 * Only one fragment on the socket.
		 */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, 0);
	} else {
		/*
		 * HW-checksum won't work as there are two or more
		 * fragments on the socket so that all csums of sk_buffs
		 * should be together
		 */
		offset = skb_transport_offset(skb);
		skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);

		skb->ip_summed = CHECKSUM_NONE;

		skb_queue_walk(&sk->sk_write_queue, skb) {
			csum = csum_add(csum, skb->csum);
		}

		uh->check = csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}

/*
 * Push out all pending data as one UDP datagram. Socket is locked.
 */
 //如注释：该函数会将当前所有pending的数据包作为一个UDP数据报发送出去
static int udp_push_pending_frames(struct sock *sk)
{
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi *fl = &inet->cork.fl;
	struct sk_buff *skb;
	struct udphdr *uh;
	int err = 0;
	__wsum csum = 0;

	/* Grab the skbuff where UDP header space exists. */
	//获取发送队列中第一个SKB的指针，注意是获取，并不会将该skb从发送队列上摘除
	//发送队列中此时可能有多个skb，每个skb携带的数据为一个MTU大小，这是由前面的
	//ip_append_data()处理好的，方面IP层的后续处理
	if ((skb = skb_peek(&sk->sk_write_queue)) == NULL)
		goto out;

	/*
	 * Create a UDP header
	 */
	 //组装UDP首部各个字段
	uh = udp_hdr(skb);
	uh->source = fl->fl_ip_sport;
	uh->dest = fl->fl_ip_dport;
	uh->len = htons(up->len);
	uh->check = 0;
	//计算数据包的校验和
	if (up->pcflag)  				 /*     UDP-Lite      */
		csum  = udplite_csum_outgoing(sk, skb);

	else if (sk->sk_no_check == UDP_CSUM_NOXMIT) {   /* UDP csum disabled */

		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */

		udp4_hwcsum_outgoing(sk, skb, fl->fl4_src,fl->fl4_dst, up->len);
		goto send;

	} else						 /*   `normal' UDP    */
		csum = udp_csum_outgoing(sk, skb);

	/* add protocol-dependent pseudo-header */
	//伪首部校验和计算
	uh->check = csum_tcpudp_magic(fl->fl4_src, fl->fl4_dst, up->len,
				      sk->sk_protocol, csum             );
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	//调用IP协议的push()函数将数据包组织成一个IP报文发送出去。这些数据包虽然可能会由多个片段组成，
		//而且每个片段都达到了MTU大小，但是它们公用一个ipid，表明它们属于同一个IP报文，只是分段了而已
		//该函数在IP协议的发送部分再分析

	err = ip_push_pending_frames(sk);
out:
	//无论成功与否，发送队列中不再有数据，所以清空len和pending标记
	up->len = 0;
	up->pending = 0;
	if (!err)
		UDP_INC_STATS_USER(UDP_MIB_OUTDATAGRAMS, up->pcflag);
	return err;
}

int udp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_udplite = up->pcflag;
	//corkreq表示是否需要等待其它数据，将这些报文组合成一个UDP报文
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	//UDP首部长度字段只有16bit，所以一个数据包大小不能超过0xFFFF
	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */
	//UDP不支持带外数据，所以不能设置MSG_OOB
	if (msg->msg_flags&MSG_OOB)	/* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;
	//pending标记和前面说的MSG_MORE标记有关。当设置MSG_MORE标记的数据到达时，UDP会将待
	//发送的数据暂存到发送队列中，这些数据就处于pending状态，等应用指定要发送数据时，会将
	//数据发送给IP，然后清空发送队列，这时退出pending状态。
	if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		/*
		 * 再判断一次是因为了lock_sock()可能会导致进程休眠。内核中有许多地方使用这样的方式编程。
		 * 因为大部分情况下pending标记是没有的，这样的话就不会进入到这里，这种编程方式就可以省掉
		 * 一个lock_sock(比较复杂、耗时)电泳，仅当设置了pending后，才加锁并再检查一次，这样就
		 * 能在大部分情况下不用锁，少数情况下加锁，这种方法是内核中常用的提升效率的策略。
		 */
		if (likely(up->pending)) {
			//pengding的值只能是0或者AF_INET
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			//因为已经有挂起的数据，所以可以不用再次进行地址、路由的选择，直接跳转到do_append_data
			//处追加数据即可。因为如果有pending标记，下面需要做的工作在处理第一个数据包时已经处理过了
			goto do_append_data;
		}
		release_sock(sk);
	}
	//ulen表示要发送的UDP报文长度，这里在数据长度的基础上再加上UDP首部长度8个字节
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address.
	 */
	 //下面这段逻辑是确定目的端IP地址和端口号

	//msg_name不为空，表示调用系统调用时用户空间程序指定了目的端地址信息，这种
	//情况下校验指定参数并设置地址族、目的地址和目的端口
	if (msg->msg_name) {
		//目的地址长度必须是IPv4地址
		struct sockaddr_in * usin = (struct sockaddr_in*)msg->msg_name;
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		//地址族必须是AF_INET或者AF_UNSPEC
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}
		//目的IP和目的端口
		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		//目的端口不能为0
		if (dport == 0)
			return -EINVAL;
	} else {
	//调用发送相关系统调用时没有指定目的地址情况处理
	//如果在该UDP套接字上没有执行过connect()系统调用，所以内核不知道要将该数据包发给谁，
		//这种情况返回需要建立连接的错误码
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		//应用程序有调用过connect()，这种情况下目的端地址信息会被保存在inet_sock结构中
		daddr = inet->daddr;
		dport = inet->dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		 //由于已经连接过，所以连接标记置1
		connected = 1;
	}
	ipc.addr = inet->saddr;

	ipc.oif = sk->sk_bound_dev_if;
	//如果发送数据时指定了控制信息(sendmsg()系统调用)，用的比较少，先忽略
	if (msg->msg_controllen) {
		err = ip_cmsg_send(msg, &ipc);
		if (err)
			return err;
		if (ipc.opt)
			free = 1;
		connected = 0;
	}
	if (!ipc.opt)
		ipc.opt = inet->opt;

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;
	//源路由选项相关处理，先忽略
	if (ipc.opt && ipc.opt->srr) {
		if (!daddr)
			return -EINVAL;
		faddr = ipc.opt->faddr;
		connected = 0;
	}
	tos = RT_TOS(inet->tos);
	/*
	 * 如果设置了SOCK_LOCALROUTE或者发送时设置了MSG_DONTROUTE标记，再或者IP选项中存在严格源站选路
	 * 选项，则说明目的地址或下一跳必然位于本地子网中。此时需要设置tos中的RTO_ONLINK标记，表示
	 * 后续查找路由时与目的地直连。
	 */
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}
	//多播地址处理，忽略
	if (MULTICAST(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	}
	//对于已经连接的情况，之前一定已经查询过路由了，这里需要检查该路由是否依然有效
	if (connected)
		rt = (struct rtable*)sk_dst_check(sk, 0);
	//如果需要，这里查询路由表
	if (rt == NULL) {
		//查询条件有：输出设备接口、源和目的IP、TOS、源和目的端口
		struct flowi fl = { .oif = ipc.oif,
				    .nl_u = { .ip4_u =
					      { .daddr = faddr,
						.saddr = saddr,
						.tos = tos } },
				    .proto = sk->sk_protocol,
				    .uli_u = { .ports =
					       { .sport = inet->sport,
						 .dport = dport } } };
		security_sk_classify_flow(sk, &fl);
		//查询路由表
		err = ip_route_output_flow(&rt, &fl, sk, 1);
		//路由查询失败、发送失败
		if (err) {
			if (err == -ENETUNREACH)
				IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		//路由结果为广播但是该socket不允许广播，发送失败
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		//如果是已连接套接字，那么将路由信息设置到套接字，下次检查即可，不用重复查询，见上文
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->u.dst));
	}
	//MSG_CONFIRM表示该报文要求接收端的数据链路层进行确认，用的很少，忽略
	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	saddr = rt->rt_src;
	if (!ipc.addr)
		daddr = ipc.addr = rt->rt_dst;

	lock_sock(sk);
	//这种情况不应该出现
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	 //将一些重要信息暂存到inet->cork中，以备可能存在的后续发送过程使用
	inet->cork.fl.fl4_dst = daddr;
	inet->cork.fl.fl_ip_dport = dport;
	inet->cork.fl.fl4_src = saddr;
	inet->cork.fl.fl_ip_sport = inet->sport;
	//下面就要将待发送数据放入发送队列了，先设置pending标记
	up->pending = AF_INET;

do_append_data:
	//up->len变量记录了当前该传输控制块上已经pending的字节数，这里将ulen累加到该变量上
	up->len += ulen;
	//根据是否为UDPlite选用不同的拷贝函数，这两个协议公用一套函数，但是因为校验和计算方法
	//有差别，而且可能需要在拷贝过程中顺便计算校验和(这样可以避免再次遍历数据)，所以这里需要区分
	getfrag  =  is_udplite ?  udplite_getfrag : ip_generic_getfrag;
	//ip_append_data()很重要，而且足够复杂，它属于IP提供给上层协议使用的一个发送接口，目前
	//主要有UDP和raw套接字使用，该函数后面会单独分析，这里只需要知道如下几点：
	//1. 该函数将要发送的数据按照MTU大小分割成若干个方便IP处理的片段，每个片段一个skb；并且这些
	//   skb会放入到套接字的发送缓冲区中；
	//2. 该函数只是组织数据包，并不执行发送动作，如果需要发送，需要由调用者主动调用ip_push_frames()
	//3. 处理成功返回0，失败返回错误码
	err = ip_append_data(sk, getfrag, msg->msg_iov, ulen,
			sizeof(struct udphdr), &ipc, rt,
			corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	//数据包处理失败，将所有数据包清空，见下文
	if (err)
		udp_flush_pending_frames(sk);
	//数据包处理没有问题，并且没有启用MSG_MORE特性，那么直接将发送队列中的数据发送给IP。
	//对于大多数应用都是走了该分支，即一次写操作对应一个UDP数据包，这种UDP套接字相当于
	//没有发送缓冲区
	else if (!corkreq)
		err = udp_push_pending_frames(sk);
	//这种情况不大可能发生，除非应用程序指定要发送的数据长度为0
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		up->pending = 0;
	release_sock(sk);

out:
	//释放对路由缓存的引用
	ip_rt_put(rt);
	if (free)
		kfree(ipc.opt);
	//处理过程没有错误，返回已发送的字节数
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS_USER(UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

do_confirm:
	//确认处理，用的很少，忽
	dst_confirm(&rt->u.dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}

int udp_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	struct udp_sock *up = udp_sk(sk);
	int ret;

	if (!up->pending) {
		struct msghdr msg = {	.msg_flags = flags|MSG_MORE };

		/* Call udp_sendmsg to specify destination address which
		 * sendpage interface can't pass.
		 * This will succeed only when the socket is connected.
		 */
		ret = udp_sendmsg(NULL, sk, &msg, 0);
		if (ret < 0)
			return ret;
	}

	lock_sock(sk);

	if (unlikely(!up->pending)) {
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 3\n");
		return -EINVAL;
	}

	ret = ip_append_page(sk, page, offset, size, flags);
	if (ret == -EOPNOTSUPP) {
		release_sock(sk);
		return sock_no_sendpage(sk->sk_socket, page, offset,
					size, flags);
	}
	if (ret < 0) {
		udp_flush_pending_frames(sk);
		goto out;
	}

	up->len += size;
	if (!(up->corkflag || (flags&MSG_MORE)))
		ret = udp_push_pending_frames(sk);
	if (!ret)
		ret = size;
out:
	release_sock(sk);
	return ret;
}

/*
 *	IOCTL requests applicable to the UDP protocol
 */

int udp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	{
		int amount = atomic_read(&sk->sk_wmem_alloc);
		return put_user(amount, (int __user *)arg);
	}

	case SIOCINQ:
	{
		struct sk_buff *skb;
		unsigned long amount;

		amount = 0;
		spin_lock_bh(&sk->sk_receive_queue.lock);
		skb = skb_peek(&sk->sk_receive_queue);
		if (skb != NULL) {
			/*
			 * We will only return the amount
			 * of this packet since that is all
			 * that will be read.
			 */
			amount = skb->len - sizeof(struct udphdr);
		}
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		return put_user(amount, (int __user *)arg);
	}

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

/*
 * 	This should be easy, if there is something there we
 * 	return it, otherwise we block.
 */

int udp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int noblock, int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int err;
	int is_udplite = IS_UDPLITE(sk);

	/*
	 *	Check any passed addresses
	 */
	if (addr_len)
		*addr_len=sizeof(*sin);

	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len);

try_again:
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	ulen = skb->len - sizeof(struct udphdr);
	copied = len;
	if (copied > ulen)
		copied = ulen;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	/*
	 * If checksum is needed at all, try to do it while copying the
	 * data.  If the data is truncated, or if we only want a partial
	 * coverage checksum (UDP-Lite), do it before the copy.
	 */

	if (copied < ulen || UDP_SKB_CB(skb)->partial_cov) {
		if (udp_lib_checksum_complete(skb))
			goto csum_copy_err;
	}

	if (skb_csum_unnecessary(skb))
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr),
					      msg->msg_iov, copied       );
	else {
		err = skb_copy_and_csum_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov);

		if (err == -EINVAL)
			goto csum_copy_err;
	}

	if (err)
		goto out_free;

	sock_recv_timestamp(msg, sk, skb);

	/* Copy the address. */
	if (sin)
	{
		sin->sin_family = AF_INET;
		sin->sin_port = udp_hdr(skb)->source;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	}
	if (inet->cmsg_flags)
		ip_cmsg_recv(msg, skb);

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

out_free:
	skb_free_datagram(sk, skb);
out:
	return err;

csum_copy_err:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, is_udplite);

	skb_kill_datagram(sk, skb, flags);

	if (noblock)
		return -EAGAIN;
	goto try_again;
}


int udp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	/*
	 *	1003.1g - break association.
	 */

	sk->sk_state = TCP_CLOSE;
	inet->daddr = 0;
	inet->dport = 0;
	sk->sk_bound_dev_if = 0;
	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
		sk->sk_prot->unhash(sk);
		inet->sport = 0;
	}
	sk_dst_reset(sk);
	return 0;
}

/* returns:
 *  -1: error
 *   0: success
 *  >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
int udp_queue_rcv_skb(struct sock * sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;

	/*
	 *	Charge it to the socket, dropping if the queue is full.
	 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

	if (up->encap_type) {
		/*
		 * This is an encapsulation socket so pass the skb to
		 * the socket's udp_encap_rcv() hook. Otherwise, just
		 * fall through and pass this up the UDP socket.
		 * up->encap_rcv() returns the following value:
		 * =0 if skb was successfully passed to the encap
		 *    handler or was discarded by it.
		 * >0 if skb should be passed on to UDP.
		 * <0 if skb should be resubmitted as proto -N
		 */

		/* if we're overly short, let UDP handle it */
		if (skb->len > sizeof(struct udphdr) &&
		    up->encap_rcv != NULL) {
			int ret;

			ret = (*up->encap_rcv)(sk, skb);
			if (ret <= 0) {
				UDP_INC_STATS_BH(UDP_MIB_INDATAGRAMS, up->pcflag);
				return -ret;
			}
		}

		/* FALLTHROUGH -- it's a UDP Packet */
	}

	/*
	 * 	UDP-Lite specific tests, ignored on UDP sockets
	 */
	if ((up->pcflag & UDPLITE_RECV_CC)  &&  UDP_SKB_CB(skb)->partial_cov) {

		/*
		 * MIB statistics other than incrementing the error count are
		 * disabled for the following two types of errors: these depend
		 * on the application settings, not on the functioning of the
		 * protocol stack as such.
		 *
		 * RFC 3828 here recommends (sec 3.3): "There should also be a
		 * way ... to ... at least let the receiving application block
		 * delivery of packets with coverage values less than a value
		 * provided by the application."
		 */
		if (up->pcrlen == 0) {          /* full coverage was set  */
			LIMIT_NETDEBUG(KERN_WARNING "UDPLITE: partial coverage "
				"%d while full coverage %d requested\n",
				UDP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		/* The next case involves violating the min. coverage requested
		 * by the receiver. This is subtle: if receiver wants x and x is
		 * greater than the buffersize/MTU then receiver will complain
		 * that it wants x while sender emits packets of smaller size y.
		 * Therefore the above ...()->partial_cov statement is essential.
		 */
		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			LIMIT_NETDEBUG(KERN_WARNING
				"UDPLITE: coverage %d too small, need min %d\n",
				UDP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	if (sk->sk_filter) {
		if (udp_lib_checksum_complete(skb))
			goto drop;
	}

	if ((rc = sock_queue_rcv_skb(sk,skb)) < 0) {
		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS_BH(UDP_MIB_RCVBUFERRORS, up->pcflag);
		goto drop;
	}

	UDP_INC_STATS_BH(UDP_MIB_INDATAGRAMS, up->pcflag);
	return 0;

drop:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, up->pcflag);
	kfree_skb(skb);
	return -1;
}

/*
 *	Multicasts and broadcasts go to each listener.
 *
 *	Note: called only from the BH handler context,
 *	so we don't need to lock the hashes.
 */
static int __udp4_lib_mcast_deliver(struct sk_buff *skb,
				    struct udphdr  *uh,
				    __be32 saddr, __be32 daddr,
				    struct hlist_head udptable[])
{
	struct sock *sk;
	int dif;

	read_lock(&udp_hash_lock);
	sk = sk_head(&udptable[ntohs(uh->dest) & (UDP_HTABLE_SIZE - 1)]);
	dif = skb->dev->ifindex;
	sk = udp_v4_mcast_next(sk, uh->dest, daddr, uh->source, saddr, dif);
	if (sk) {
		struct sock *sknext = NULL;

		do {
			struct sk_buff *skb1 = skb;

			sknext = udp_v4_mcast_next(sk_next(sk), uh->dest, daddr,
						   uh->source, saddr, dif);
			if (sknext)
				skb1 = skb_clone(skb, GFP_ATOMIC);

			if (skb1) {
				int ret = udp_queue_rcv_skb(sk, skb1);
				if (ret > 0)
					/* we should probably re-process instead
					 * of dropping packets here. */
					kfree_skb(skb1);
			}
			sk = sknext;
		} while (sknext);
	} else
		kfree_skb(skb);
	read_unlock(&udp_hash_lock);
	return 0;
}

/* Initialize UDP checksum. If exited with zero value (success),
 * CHECKSUM_UNNECESSARY means, that no more checks are required.
 * Otherwise, csum completion requires chacksumming packet body,
 * including udp header and folding it to skb->csum.
 */
static inline int udp4_csum_init(struct sk_buff *skb, struct udphdr *uh,
				 int proto)
{
	const struct iphdr *iph;
	int err;

	UDP_SKB_CB(skb)->partial_cov = 0;
	UDP_SKB_CB(skb)->cscov = skb->len;

	if (proto == IPPROTO_UDPLITE) {
		err = udplite_checksum_init(skb, uh);
		if (err)
			return err;
	}

	iph = ip_hdr(skb);
	if (uh->check == 0) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
	       if (!csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len,
				      proto, skb->csum))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (!skb_csum_unnecessary(skb))
		skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
					       skb->len, proto, 0);
	/* Probably, we should checksum udp header (it should be in cache
	 * in any case) and data in tiny packets (< rx copybreak).
	 */

	return 0;
}

/*
 *	All we need to do is get the socket, and then do a checksum.
 */

int __udp4_lib_rcv(struct sk_buff *skb, struct hlist_head udptable[],
		   int proto)
{
	struct sock *sk;
	struct udphdr *uh = udp_hdr(skb);
	unsigned short ulen;
	struct rtable *rt = (struct rtable*)skb->dst;
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;

	/*
	 *  Validate the packet.
	 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;		/* No space for header. */

	ulen = ntohs(uh->len);
	if (ulen > skb->len)
		goto short_packet;

	if (proto == IPPROTO_UDP) {
		/* UDP validates ulen. */
		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
			goto short_packet;
		uh = udp_hdr(skb);
	}

	if (udp4_csum_init(skb, uh, proto))
		goto csum_error;

	if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
		return __udp4_lib_mcast_deliver(skb, uh, saddr, daddr, udptable);

	sk = __udp4_lib_lookup(saddr, uh->source, daddr, uh->dest,
			       inet_iif(skb), udptable);

	if (sk != NULL) {
		int ret = udp_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
			return -ret;
		return 0;
	}

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	if (udp_lib_checksum_complete(skb))
		goto csum_error;

	UDP_INC_STATS_BH(UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
	 * Hmm.  We got an UDP packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb);
	return 0;

short_packet:
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: short packet: From %u.%u.%u.%u:%u %d/%d to %u.%u.%u.%u:%u\n",
		       proto == IPPROTO_UDPLITE ? "-Lite" : "",
		       NIPQUAD(saddr),
		       ntohs(uh->source),
		       ulen,
		       skb->len,
		       NIPQUAD(daddr),
		       ntohs(uh->dest));
	goto drop;

csum_error:
	/*
	 * RFC1122: OK.  Discards the bad packet silently (as far as
	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
	 */
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: bad checksum. From %d.%d.%d.%d:%d to %d.%d.%d.%d:%d ulen %d\n",
		       proto == IPPROTO_UDPLITE ? "-Lite" : "",
		       NIPQUAD(saddr),
		       ntohs(uh->source),
		       NIPQUAD(daddr),
		       ntohs(uh->dest),
		       ulen);
drop:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
	kfree_skb(skb);
	return 0;
}

int udp_rcv(struct sk_buff *skb)
{
	return __udp4_lib_rcv(skb, udp_hash, IPPROTO_UDP);
}

int udp_destroy_sock(struct sock *sk)
{
	lock_sock(sk);
	udp_flush_pending_frames(sk);
	release_sock(sk);
	return 0;
}

/*
 *	Socket option code for UDP
 */
int udp_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int optlen,
		       int (*push_pending_frames)(struct sock *))
{
	struct udp_sock *up = udp_sk(sk);
	int val;
	int err = 0;

	if (optlen<sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	switch (optname) {
	case UDP_CORK:
		if (val != 0) {
			up->corkflag = 1;
		} else {
			up->corkflag = 0;
			lock_sock(sk);
			(*push_pending_frames)(sk);
			release_sock(sk);
		}
		break;

	case UDP_ENCAP:
		switch (val) {
		case 0:
		case UDP_ENCAP_ESPINUDP:
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			up->encap_rcv = xfrm4_udp_encap_rcv;
			/* FALLTHROUGH */
		case UDP_ENCAP_L2TPINUDP:
			up->encap_type = val;
			break;
		default:
			err = -ENOPROTOOPT;
			break;
		}
		break;

	/*
	 * 	UDP-Lite's partial checksum coverage (RFC 3828).
	 */
	/* The sender sets actual checksum coverage length via this option.
	 * The case coverage > packet length is handled by send module. */
	case UDPLITE_SEND_CSCOV:
		if (!up->pcflag)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Illegal coverage: use default (8) */
			val = 8;
		up->pcslen = val;
		up->pcflag |= UDPLITE_SEND_CC;
		break;

	/* The receiver specifies a minimum checksum coverage value. To make
	 * sense, this should be set to at least 8 (as done below). If zero is
	 * used, this again means full checksum coverage.                     */
	case UDPLITE_RECV_CSCOV:
		if (!up->pcflag)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Avoid silly minimal values.       */
			val = 8;
		up->pcrlen = val;
		up->pcflag |= UDPLITE_RECV_CC;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	return err;
}

int udp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return ip_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
}
#endif

int udp_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val, len;

	if (get_user(len,optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case UDP_CORK:
		val = up->corkflag;
		break;

	case UDP_ENCAP:
		val = up->encap_type;
		break;

	/* The following two cannot be changed on UDP sockets, the return is
	 * always 0 (which corresponds to the full checksum coverage of UDP). */
	case UDPLITE_SEND_CSCOV:
		val = up->pcslen;
		break;

	case UDPLITE_RECV_CSCOV:
		val = up->pcrlen;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val,len))
		return -EFAULT;
	return 0;
}

int udp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ip_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return compat_ip_getsockopt(sk, level, optname, optval, optlen);
}
#endif
/**
 * 	udp_poll - wait for a UDP event.
 *	@file - file struct
 *	@sock - socket
 *	@wait - poll table
 *
 *	This is same as datagram poll, except for the special case of
 *	blocking sockets. If application is using a blocking fd
 *	and a packet with checksum error is in the queue;
 *	then it could get return from select indicating data available
 *	but then block when reading it. Add special case code
 *	to work around these arguably broken applications.
 */
unsigned int udp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask = datagram_poll(file, sock, wait);
	struct sock *sk = sock->sk;
	int 	is_lite = IS_UDPLITE(sk);

	/* Check for false positives due to checksum errors */
	if ( (mask & POLLRDNORM) &&
	     !(file->f_flags & O_NONBLOCK) &&
	     !(sk->sk_shutdown & RCV_SHUTDOWN)){
		struct sk_buff_head *rcvq = &sk->sk_receive_queue;
		struct sk_buff *skb;

		spin_lock_bh(&rcvq->lock);
		while ((skb = skb_peek(rcvq)) != NULL &&
		       udp_lib_checksum_complete(skb)) {
			UDP_INC_STATS_BH(UDP_MIB_INERRORS, is_lite);
			__skb_unlink(skb, rcvq);
			kfree_skb(skb);
		}
		spin_unlock_bh(&rcvq->lock);

		/* nothing to see, move along */
		if (skb == NULL)
			mask &= ~(POLLIN | POLLRDNORM);
	}

	return mask;

}

DEFINE_PROTO_INUSE(udp)

struct proto udp_prot = {
	.name		   = "UDP",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = udp_sendmsg,
	.recvmsg	   = udp_recvmsg,
	.sendpage	   = udp_sendpage,
	.backlog_rcv	   = udp_queue_rcv_skb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.get_port	   = udp_v4_get_port,
	.obj_size	   = sizeof(struct udp_sock),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
	REF_PROTO_INUSE(udp)
};

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

static struct sock *udp_get_first(struct seq_file *seq)
{
	struct sock *sk;
	struct udp_iter_state *state = seq->private;

	for (state->bucket = 0; state->bucket < UDP_HTABLE_SIZE; ++state->bucket) {
		struct hlist_node *node;
		sk_for_each(sk, node, state->hashtable + state->bucket) {
			if (sk->sk_family == state->family)
				goto found;
		}
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *udp_get_next(struct seq_file *seq, struct sock *sk)
{
	struct udp_iter_state *state = seq->private;

	do {
		sk = sk_next(sk);
try_again:
		;
	} while (sk && sk->sk_family != state->family);

	if (!sk && ++state->bucket < UDP_HTABLE_SIZE) {
		sk = sk_head(state->hashtable + state->bucket);
		goto try_again;
	}
	return sk;
}

static struct sock *udp_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = udp_get_first(seq);

	if (sk)
		while (pos && (sk = udp_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

static void *udp_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock(&udp_hash_lock);
	return *pos ? udp_get_idx(seq, *pos-1) : (void *)1;
}

static void *udp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == (void *)1)
		sk = udp_get_idx(seq, 0);
	else
		sk = udp_get_next(seq, v);

	++*pos;
	return sk;
}

static void udp_seq_stop(struct seq_file *seq, void *v)
{
	read_unlock(&udp_hash_lock);
}

static int udp_seq_open(struct inode *inode, struct file *file)
{
	struct udp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	int rc = -ENOMEM;
	struct udp_iter_state *s = kzalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		goto out;
	s->family		= afinfo->family;
	s->hashtable		= afinfo->hashtable;
	s->seq_ops.start	= udp_seq_start;
	s->seq_ops.next		= udp_seq_next;
	s->seq_ops.show		= afinfo->seq_show;
	s->seq_ops.stop		= udp_seq_stop;

	rc = seq_open(file, &s->seq_ops);
	if (rc)
		goto out_kfree;

	seq	     = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}

/* ------------------------------------------------------------------------ */
int udp_proc_register(struct udp_seq_afinfo *afinfo)
{
	struct proc_dir_entry *p;
	int rc = 0;

	if (!afinfo)
		return -EINVAL;
	afinfo->seq_fops->owner		= afinfo->owner;
	afinfo->seq_fops->open		= udp_seq_open;
	afinfo->seq_fops->read		= seq_read;
	afinfo->seq_fops->llseek	= seq_lseek;
	afinfo->seq_fops->release	= seq_release_private;

	p = proc_net_fops_create(&init_net, afinfo->name, S_IRUGO, afinfo->seq_fops);
	if (p)
		p->data = afinfo;
	else
		rc = -ENOMEM;
	return rc;
}

void udp_proc_unregister(struct udp_seq_afinfo *afinfo)
{
	if (!afinfo)
		return;
	proc_net_remove(&init_net, afinfo->name);
	memset(afinfo->seq_fops, 0, sizeof(*afinfo->seq_fops));
}

/* ------------------------------------------------------------------------ */
static void udp4_format_sock(struct sock *sp, char *tmpbuf, int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->daddr;
	__be32 src  = inet->rcv_saddr;
	__u16 destp	  = ntohs(inet->dport);
	__u16 srcp	  = ntohs(inet->sport);

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %p",
		bucket, src, srcp, dest, destp, sp->sk_state,
		atomic_read(&sp->sk_wmem_alloc),
		atomic_read(&sp->sk_rmem_alloc),
		0, 0L, 0, sock_i_uid(sp), 0, sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp);
}

int udp4_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
	else {
		char tmpbuf[129];
		struct udp_iter_state *state = seq->private;

		udp4_format_sock(v, tmpbuf, state->bucket);
		seq_printf(seq, "%-127s\n", tmpbuf);
	}
	return 0;
}

/* ------------------------------------------------------------------------ */
static struct file_operations udp4_seq_fops;
static struct udp_seq_afinfo udp4_seq_afinfo = {
	.owner		= THIS_MODULE,
	.name		= "udp",
	.family		= AF_INET,
	.hashtable	= udp_hash,
	.seq_show	= udp4_seq_show,
	.seq_fops	= &udp4_seq_fops,
};

int __init udp4_proc_init(void)
{
	return udp_proc_register(&udp4_seq_afinfo);
}

void udp4_proc_exit(void)
{
	udp_proc_unregister(&udp4_seq_afinfo);
}
#endif /* CONFIG_PROC_FS */

EXPORT_SYMBOL(udp_disconnect);
EXPORT_SYMBOL(udp_hash);
EXPORT_SYMBOL(udp_hash_lock);
EXPORT_SYMBOL(udp_ioctl);
EXPORT_SYMBOL(udp_get_port);
EXPORT_SYMBOL(udp_prot);
EXPORT_SYMBOL(udp_sendmsg);
EXPORT_SYMBOL(udp_lib_getsockopt);
EXPORT_SYMBOL(udp_lib_setsockopt);
EXPORT_SYMBOL(udp_poll);

#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL(udp_proc_register);
EXPORT_SYMBOL(udp_proc_unregister);
#endif
