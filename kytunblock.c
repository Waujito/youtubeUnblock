#include "nf_wrapper.h"
#ifndef KERNEL_SPACE
#error "You are trying to compile the kernel module not in the kernel space"
#endif
// Kernel module for youtubeUnblock.
// Make with make kmake && sudo iptables -t mangle -D OUTPUT 1 && sudo make kreload && sudo iptables -t mangle -I OUTPUT -p tcp -j YTUNBLOCK
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/socket.h>
#include <linux/net.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include "mangle.h"
#include "config.h"
#include "utils.h"
#include "logging.h"
#include "kmod_utils.h"

MODULE_LICENSE("GPL");
MODULE_VERSION("0.3.2");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtube unblock");

static NF_CALLBACK(ykb_nf_hook, skb) {
	int ret;

	if ((skb->mark & config.mark) == config.mark) 
		goto accept;
	
	if (skb->head == NULL) 
		goto accept;
	
	if (skb->len > MAX_PACKET_SIZE)
		goto accept;

	ret = skb_linearize(skb);
	if (ret < 0) {
		lgerror("Cannot linearize", ret);
		goto accept;
	}

	int vrd = process_packet(skb->data, skb->len);

	switch(vrd) {
		case PKT_ACCEPT:
			goto accept;
		case PKT_DROP:
			goto drop;
	}

accept:
	return NF_ACCEPT;
drop:
	kfree_skb(skb);
	return NF_STOLEN;
}


static struct nf_hook_ops ykb_nf_reg __read_mostly = {
	.hook		= ykb_nf_hook,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_POST_ROUTING,
	.priority	= NF_IP_PRI_MANGLE,
};

static struct nf_hook_ops ykb6_nf_reg __read_mostly = {
	.hook		= ykb_nf_hook,
	.pf		= NFPROTO_IPV6,
	.hooknum	= NF_INET_POST_ROUTING,
	.priority	= NF_IP6_PRI_MANGLE,
};

static int __init ykb_init(void) {
	int ret = 0;

	ret = open_raw_socket();
	if (ret < 0) goto err;


	if (config.use_ipv6) {
		ret = open_raw6_socket();
		if (ret < 0) goto close_rawsocket;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		struct net *n;
		for_each_net(n) {
			ret = nf_register_net_hook(n, &ykb6_nf_reg);
			if (ret < 0) 
				lgerror("bad rat",ret);
		}
#else
		nf_register_hook(&ykb6_nf_reg);
#endif
	}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	struct net *n;

	for_each_net(n) {
		ret = nf_register_net_hook(n, &ykb_nf_reg);
		if (ret < 0) 
			lgerror("bad rat",ret);
	}
#else
	nf_register_hook(&ykb_nf_reg);
#endif

	pr_info("youtubeUnblock kernel module started.\n");
	return 0;

close_rawsocket:
	close_raw_socket();
err:
	return ret;
}

static void __exit ykb_destroy(void) {
	if (config.use_ipv6) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		struct net *n;
		for_each_net(n)
			nf_unregister_net_hook(n, &ykb6_nf_reg);
#else
		nf_unregister_hook(&ykb6_nf_reg);
#endif
		close_raw6_socket();
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	struct net *n;
	for_each_net(n)
		nf_unregister_net_hook(n, &ykb_nf_reg);
#else
	nf_unregister_hook(&ykb_nf_reg);
#endif

	close_raw_socket();
	pr_info("youtubeUnblock kernel module destroyed.\n");
}

module_init(ykb_init);
module_exit(ykb_destroy);
