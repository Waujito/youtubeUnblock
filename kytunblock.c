#ifndef KERNEL_SPACE
#error "You are trying to compile the kernel module not in the kernel space"
#endif
// Kernel module for youtubeUnblock.
// Make with make kmake && sudo iptables -t mangle -D OUTPUT 1 && sudo make kreload && sudo iptables -t mangle -I OUTPUT -p tcp -j YTUNBLOCK
#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include "mangle.h"
#include "config.h"
#include "raw_replacements.h"
#include "utils.h"
#include "logging.h"
#include "kmod_utils.h"

struct config_t config = {
	.threads = THREADS_NUM,
	.frag_sni_reverse = 1,
	.frag_sni_faked = 0,
	.fragmentation_strategy = FRAGMENTATION_STRATEGY,
	.faking_strategy = FAKING_STRATEGY,
	.faking_ttl = FAKE_TTL,
	.fake_sni = 1,
	.fake_sni_seq_len = 1,
	.frag_middle_sni = 1,
	.frag_sni_pos = 1,
	.use_ipv6 = 1,
	.fakeseq_offset = 10000,
	.mark = DEFAULT_RAWSOCKET_MARK,
	.synfake = 0,
	.synfake_len = 0,

	.sni_detection = SNI_DETECTION_PARSE,

#ifdef SEG2_DELAY
	.seg2_delay = SEG2_DELAY,
#else
	.seg2_delay = 0,
#endif

#ifdef USE_GSO
	.use_gso = 1,
#else
	.use_gso = false,
#endif

#ifdef DEBUG
	.verbose = 2,
#else
	.verbose = 0,
#endif

	.domains_str = defaul_snistr,
	.domains_strlen = sizeof(defaul_snistr),

	.queue_start_num = DEFAULT_QUEUE_NUM,
	.fake_sni_pkt = fake_sni_old,
	.fake_sni_pkt_sz = sizeof(fake_sni_old) - 1, // - 1 for null-terminator
};

MODULE_LICENSE("GPL");
MODULE_VERSION("0.3.2");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtube unblock");


static unsigned int ykb_nf_hook(void *priv, 
			struct sk_buff *skb, 
			const struct nf_hook_state *state) {
	if ((skb->mark & config.mark) == config.mark) 
		goto accept_no_free;
	
	if (skb->head == NULL) 
		goto accept_no_free;
	
	uint32_t buflen = skb->len;
	if (buflen > MAX_PACKET_SIZE)
		goto accept_no_free;

	NETBUF_ALLOC(buf, buflen);
	if (!NETBUF_CHECK(buf))
		goto accept_no_free;

	if (skb_copy_bits(skb, 0, buf, buflen) < 0) {
		pr_err("Unable copy bits\n");
		goto accept;
	}

	int vrd = process_packet(buf, buflen);

	switch(vrd) {
		case PKT_ACCEPT:
			goto accept;
		case PKT_DROP:
			goto drop;
	}

accept:
	NETBUF_FREE(buf);
accept_no_free:
	return NF_ACCEPT;
drop:
	NETBUF_FREE(buf);
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
