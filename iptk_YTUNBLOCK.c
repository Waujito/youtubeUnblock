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
#include <linux/netfilter/x_tables.h>
#include "ipt_YTUNBLOCK.h"

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

static unsigned int ykb_tg(struct sk_buff *skb, const struct xt_action_param *par) 
{
	if ((skb->mark & config.mark) == config.mark) 
		return XT_CONTINUE;
	
	if (skb->head == NULL) return XT_CONTINUE;
	
	uint32_t buflen = skb->len;
	if (buflen > MAX_PACKET_SIZE)
		goto accept;

	NETBUF_ALLOC(buf, buflen);
	if (!NETBUF_CHECK(buf))
		goto no_free;

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
no_free:
	return XT_CONTINUE;
drop:
	NETBUF_FREE(buf);
	kfree_skb(skb);
	return NF_STOLEN;
}

static int ykb_chk(const struct xt_tgchk_param *par) {
	return 0;
}


static struct xt_target ykb_tg_reg __read_mostly = {
	.name		= "YTUNBLOCK",
	.target		= ykb_tg,
	.table		= "mangle",
	.hooks		= (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_FORWARD), 
	.targetsize	= sizeof(struct xt_ytunblock_tginfo),
	.family		= NFPROTO_IPV4,
	.checkentry	= ykb_chk,
	.me		= THIS_MODULE,
};

static struct xt_target ykb6_tg_reg __read_mostly = {
	.name		= "YTUNBLOCK",
	.target		= ykb_tg,
	.table		= "mangle",
	.hooks		= (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_FORWARD), 
	.targetsize	= sizeof(struct xt_ytunblock_tginfo),
	.family		= NFPROTO_IPV6,
	.checkentry	= ykb_chk,
	.me		= THIS_MODULE,
};

static int __init ykb_init(void) {
	int ret = 0;

	ret = open_raw_socket();
	if (ret < 0) goto err;

	if (config.use_ipv6) {
		ret = open_raw6_socket();
		if (ret < 0) goto close_rawsocket;

		ret = xt_register_target(&ykb6_tg_reg);
		if (ret < 0) goto close_raw6socket;
	}

	ret = xt_register_target(&ykb_tg_reg);
	if (ret < 0) goto close_xt6_target;

	pr_info("youtubeUnblock kernel module started.\n");
	return 0;

close_xt6_target:
	if (config.use_ipv6) xt_unregister_target(&ykb6_tg_reg);
close_raw6socket:
	if (config.use_ipv6) close_raw6_socket();
close_rawsocket:
	close_raw_socket();
err:
	return ret;
}

static void __exit ykb_destroy(void) {
	xt_unregister_target(&ykb_tg_reg);
	if (config.use_ipv6) xt_unregister_target(&ykb6_tg_reg);
	if (config.use_ipv6) close_raw6_socket();
	close_raw_socket();
	pr_info("youtubeUnblock kernel module destroyed.\n");
}

module_init(ykb_init);
module_exit(ykb_destroy);
