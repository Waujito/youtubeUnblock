// Kernel module for youtubeUnblock.
#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/netfilter/x_tables.h>
#include "ipt_YTUNBLOCK.h"
#include "mangle.h"

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtube unblock");


static int rsfd;
static struct socket *rawsocket;
DEFINE_MUTEX(rslock);

static int open_raw_socket(void) {
	int ret = 0;
	ret = sock_create(AF_INET, SOCK_RAW, IPPROTO_RAW, &rawsocket);

	if (ret < 0) {
		pr_alert("Unable to create raw socket\n");
		goto err;
	}

	sockptr_t optval = {
		.kernel = NULL,
		.is_kernel = 1
	};

	int mark = RAWSOCKET_MARK;
	optval.kernel = &mark;
	ret = sock_setsockopt(rawsocket, SOL_SOCKET, SO_MARK, optval, sizeof(mark));
	if (ret < 0)
	{
		pr_alert("setsockopt(SO_MARK, %d) failed\n", mark);
		goto err;
	}
	int one = 1;
	optval.kernel = &one;

	// ret = sock_setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, optval, sizeof(one));
	// if (ret < 0)
	// {
	// 	pr_alert("setsockopt(IP_HDRINCL, 1) failed\n");
	// 	goto err;
	// }

	return 0;
err:
	return ret;
}

static void close_raw_socket(void) {
	sock_release(rawsocket);
}

static unsigned int ykb_tg(struct sk_buff *skb, const struct xt_action_param *par) 
{
	if (skb->head == NULL) return XT_CONTINUE;
	const __u8 *rawdata = skb->head + skb->network_header;
	const __u32 rawsize = skb->len;
	struct iphdr *iph = ip_hdr(skb);
	
	pr_info("Lengths: %d %d %d %d\n", skb->len, skb->mac_len, skb->hdr_len, skb->data_len);
	pr_info("Lengths: %d %d\n", skb->network_header == skb->mac_len, skb->hdr_len == iph->ihl * 4);

	return XT_CONTINUE;
}

static int ykb_chk(const struct xt_tgchk_param *par) {
	pr_info("Checkentry\n");
	return 0;
}


static struct xt_target ykb_tg_reg __read_mostly = {
	.name		= "YTUNBLOCK",
	.target		= ykb_tg,
	.table		= "mangle",
	.hooks		= (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_FORWARD), 
	.targetsize	= sizeof(struct xt_ytunblock_tginfo),
	.proto		= IPPROTO_TCP,
	.family		= NFPROTO_IPV4,
	.checkentry	= ykb_chk,
	.me		= THIS_MODULE,
};

static int __init ykb_init(void) {
	int ret = 0;

	ret = open_raw_socket();
	if (ret < 0) goto err;

	ret = xt_register_target(&ykb_tg_reg);
	if (ret < 0) goto close_rawsocket;

	pr_info("youtubeUnblock kernel module started.\n");
	return 0;
close_rawsocket:
	close_raw_socket();
err:
	return ret;
}

static void __exit ykb_destroy(void) {
	xt_unregister_target(&ykb_tg_reg);
	close_raw_socket();
	pr_info("youtubeUnblock kernel module destroyed.\n");
}

module_init(ykb_init);
module_exit(ykb_destroy);
