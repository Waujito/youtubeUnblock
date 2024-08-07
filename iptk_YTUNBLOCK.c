#define _GNU_SOURCE
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
		goto sr_err;
	}
	int one = 1;
	optval.kernel = &one;

	return 0;
sr_err:
	sock_release(rawsocket);
err:
	return ret;
}

static void close_raw_socket(void) {
	sock_release(rawsocket);
}

#define AVAILABLE_MTU 1384

static int send_raw_socket(const uint8_t *pkt, uint32_t pktlen) {
	
	if (pktlen > AVAILABLE_MTU) {
		pr_warn("The packet is too big and may cause issues!");

		__u32 buff1_size = pktlen;
		__u32 buff2_size = pktlen;
		__u8 *buff1 = kmalloc(pktlen, GFP_ATOMIC);
		if (buff1 == NULL) return -1;
		__u8 *buff2 = kmalloc(pktlen, GFP_ATOMIC);
		if (buff2 == NULL) {
			kfree(buff1);
			return -1;
		}

		int ret;

#if defined(USE_TCP_SEGMENTATION) || defined(RAWSOCK_TCP_FSTRAT)
		if ((ret = tcp4_frag(pkt, pktlen, AVAILABLE_MTU-128, 
			buff1, &buff1_size, buff2, &buff2_size)) < 0)
			return ret;
#elif defined(USE_IP_FRAGMENTATION) || defined(RAWSOCK_IP_FSTRAT)
		if ((ret = ip4_frag(pkt, pktlen, AVAILABLE_MTU-128, 
			buff1, &buff1_size, buff2, &buff2_size)) < 0)
			return ret;
#else
		pr_warn("send_raw_socket: Packet is too big but fragmentation is disabled! "
			"Pass -DRAWSOCK_TCP_FSTRAT or -DRAWSOCK_IP_FSTRAT as CFLAGS "
			"To enable it only for raw socket\n");
		return -EINVAL;
#endif

		int sent = 0;
		ret = send_raw_socket(buff1, buff1_size);

		if (ret >= 0) sent += ret;
		else {
			kfree(buff1);
			kfree(buff2);
			return ret;
		}

		kfree(buff1);

		ret = send_raw_socket(buff2, buff2_size);
		if (ret >= 0) sent += ret;
		else {
			kfree(buff2);
			return ret;
		}

		kfree(buff2);

		return sent;
	}

	struct iphdr *iph;

	int ret;
	if ((ret = ip4_payload_split(
	(uint8_t *)pkt, pktlen, &iph, NULL, NULL, NULL)) < 0) {
		return ret;
	}

	struct sockaddr_in daddr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = {
			.s_addr = iph->daddr
		}
	};

	struct msghdr msg;
	struct kvec iov;
	iov.iov_base = (__u8 *)pkt;
	iov.iov_len = pktlen;
	iov_iter_kvec(&msg.msg_iter, READ, &iov, 1, 1);

	msg.msg_flags = 0;
	msg.msg_name = &daddr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	mutex_lock(&rslock);
	ret = kernel_sendmsg(rawsocket, &msg, &iov, 1, pktlen);
	mutex_unlock(&rslock);

	return ret;
}
static unsigned int ykb_tg(struct sk_buff *skb, const struct xt_action_param *par) 
{
	if ((skb->mark & RAWSOCKET_MARK) == RAWSOCKET_MARK) 
		return XT_CONTINUE;
	
	if (skb->head == NULL) return XT_CONTINUE;
	
	// TODO: Mallocs are bad!
	uint32_t buflen = skb->len;
	__u8 *buf = kmalloc(skb->len, GFP_ATOMIC);
	if (buf == NULL) {
		pr_err("Cannot alloc enough buffer space");
		goto accept;
	}
	if (skb_copy_bits(skb, 0, buf, skb->len) < 0) {
		pr_err("Unable copy bits\n");
		goto ac_fkb;
	}
	struct iphdr *iph;
	uint32_t iph_len;
	struct tcphdr *tcph;
	uint32_t tcph_len;
	__u8 *payload;
	uint32_t plen;

	int ret = tcp4_payload_split(buf, buflen, &iph, &iph_len, 
		    &tcph, &tcph_len, &payload, &plen);

	if (ret < 0) 
		goto ac_fkb;

	struct verdict vrd = analyze_tls_data(payload, plen);

	if (vrd.gvideo_hello) {
		int ret;
		pr_info("Googlevideo detected\n");

		ip4_set_checksum(iph);
		tcp4_set_checksum(tcph, iph);

		uint32_t f1len = skb->len;
		uint32_t f2len = skb->len;
		__u8 *frag1 = kmalloc(f1len, GFP_ATOMIC);
		if (!frag1) {
			pr_err("Cannot alloc enough gv frag1 buffer space");
			goto ac_fkb;
		}
		__u8 *frag2 = kmalloc(f2len, GFP_ATOMIC);
		if (!frag2) {
			pr_err("Cannot alloc enough gv frag1 buffer space");
			kfree(frag1);
			goto ac_fkb;
		}


#ifdef FAKE_SNI
		uint32_t fksn_len = FAKE_SNI_MAXLEN;
		__u8 *fksn_buf = kmalloc(fksn_len, GFP_ATOMIC);
		if (!fksn_buf) {
			pr_err("Cannot alloc enough gksn buffer space");
			goto fallback;
		}
		
		ret = gen_fake_sni(iph, tcph, fksn_buf, &fksn_len);
		if (ret < 0) {
			pr_err("Cannot alloc enough gksn buffer space");
			goto fksn_fb;
		}
#endif

#if defined(USE_TCP_SEGMENTATION)
		size_t ipd_offset = vrd.sni_offset;
		size_t mid_offset = ipd_offset + vrd.sni_len / 2;


		if ((ret = tcp4_frag(buf, skb->len, 
			 mid_offset, frag1, &f1len, frag2, &f2len)) < 0) {
			pr_err("tcp4_frag: %d", ret);
			goto fksn_fb;
		}
#elif defined(USE_IP_FRAGMENTATION)
		size_t ipd_offset = tcph_len + vrd.sni_offset;
		size_t mid_offset = ipd_offset + vrd.sni_len / 2;
		mid_offset += 8 - mid_offset % 8;

		if ((ret = ip4_frag(buf, skb->len, 
			 mid_offset, frag1, &f1len, frag2, &f2len)) < 0) {
			pr_err("ip4_frag: %d", ret);
			goto fksn_fb;
		}
#endif

#ifdef FAKE_SNI
		ret = send_raw_socket(fksn_buf, fksn_len);
		if (ret < 0) {
			pr_err("fksn_send: %d", ret);
			goto fksn_fb;
		}
#endif

#if defined(USE_NO_FRAGMENTATION)
#ifdef SEG2_DELAY
#error "SEG2_DELAY is incompatible with NO FRAGMENTATION"
#endif
		ret = send_raw_socket(buf, buflen);
		if (ret < 0) {
			pr_err("nofrag_send: %d", ret);
		}
		goto fksn_fb;
#endif

		ret = send_raw_socket(frag2, f2len);
		if (ret < 0) {
			pr_err("raw frag2 send: %d", ret);
			goto fksn_fb;
		}

#ifdef SEG2_DELAY
#error "Seg2 delay is unsupported yet for kmod"
#else
		ret = send_raw_socket(frag1, f1len);
		if (ret < 0) {
			pr_err("raw frag1 send: %d", ret);
			goto fksn_fb;
		}
#endif

fksn_fb:
#ifdef FAKE_SNI
		kfree(fksn_buf);
#endif 
fallback:
#ifndef SEG2_DELAY
		kfree(frag1);
#endif
		kfree(frag2);
		kfree(buf);
		kfree_skb(skb);
		return NF_STOLEN;
	}
ac_fkb:
	kfree(buf);
accept:
	return XT_CONTINUE;
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
