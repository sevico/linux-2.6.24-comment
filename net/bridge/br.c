/*
 *	Generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br.c,v 1.47 2001/12/24 00:56:41 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/llc.h>
#include <net/llc.h>

#include "br_private.h"

int (*br_should_route_hook)(struct sk_buff *skb);

static struct llc_sap *br_stp_sap;

static int __init br_init(void)
{
	int err;

	br_stp_sap = llc_sap_open(LLC_SAP_BSPAN, br_stp_rcv);
	if (!br_stp_sap) {
		printk(KERN_ERR "bridge: can't register sap for STP\n");
		return -EADDRINUSE;
	}
	//调用br_fdb_init进行CAM表的初始化
	err = br_fdb_init();
	if (err)
		goto err_out;
	//调用函数br_netfilter_init，注册网络防火墙相关的钩子函数，主要是实现ebtables相关的功能
	err = br_netfilter_init();
	if (err)
		goto err_out1;
	//调用函数register_netdevice_notifier，向通知链中注册网桥感兴趣的信息
	err = register_netdevice_notifier(&br_device_notifier);
	if (err)
		goto err_out2;
	//调用函数br_netlink_init，进行netlink的初始化
	err = br_netlink_init();
	if (err)
		goto err_out3;
	//调用brioctl_set，设置网桥相关的ioctl回调函数br_ioctl_deviceless_stub
	brioctl_set(br_ioctl_deviceless_stub);
	//设置br_handle_frame_hook的回调函数
	br_handle_frame_hook = br_handle_frame;

	br_fdb_get_hook = br_fdb_get;
	br_fdb_put_hook = br_fdb_put;

	return 0;
err_out3:
	unregister_netdevice_notifier(&br_device_notifier);
err_out2:
	br_netfilter_fini();
err_out1:
	br_fdb_fini();
err_out:
	llc_sap_put(br_stp_sap);
	return err;
}

static void __exit br_deinit(void)
{
	rcu_assign_pointer(br_stp_sap->rcv_func, NULL);

	br_netlink_fini();
	br_netfilter_fini();
	unregister_netdevice_notifier(&br_device_notifier);
	brioctl_set(NULL);

	br_cleanup_bridges();

	synchronize_net();

	llc_sap_put(br_stp_sap);
	br_fdb_get_hook = NULL;
	br_fdb_put_hook = NULL;

	br_handle_frame_hook = NULL;
	br_fdb_fini();
}

EXPORT_SYMBOL(br_should_route_hook);

module_init(br_init)
module_exit(br_deinit)
MODULE_LICENSE("GPL");
MODULE_VERSION(BR_VERSION);
