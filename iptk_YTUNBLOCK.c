//
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

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtube unblock");

#define USE_TCP_SEGMENTATION

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

	// ret = sock_setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, optval, sizeof(one));
	// if (ret < 0)
	// {
	// 	pr_alert("setsockopt(IP_HDRINCL, 1) failed\n");
	// 	goto err;
	// }

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
		pr_alert("The packet is too big!");
		return -ENOMEM;
#ifdef DEBUG
		printf("Split packet!\n");
#endif

		__u32 buff1_size = pktlen;
		__u32 buff2_size = pktlen;
		__u8 *buff1 = kmalloc(pktlen, GFP_KERNEL);
		if (buff1 == NULL) return -1;
		__u8 *buff2 = kmalloc(pktlen, GFP_KERNEL);
		if (buff2 == NULL) {
			kfree(buff1);
			return -1;
		}

		int ret;

#ifdef USE_TCP_SEGMENTATION
		if ((ret = tcp4_frag(pkt, pktlen, AVAILABLE_MTU-128, 
			buff1, &buff1_size, buff2, &buff2_size)) < 0)
			return ret;
#else
		if ((ret = ip4_frag(pkt, pktlen, AVAILABLE_MTU-128, 
			buff1, &buff1_size, buff2, &buff2_size)) < 0)
			return ret;

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

	// TODO: Implement packet send via kernel 
	//https://stackoverflow.com/questions/25958715/linux-kernel-module-how-to-reinject-packets-the-kernel-considers-as-nf-stolen
	//https://stackoverflow.com/questions/15934513/cannot-send-out-packets-by-dev-queue-xmit
	//https://stackoverflow.com/questions/66846959/send-packet-in-linux-kernel
	return 0;
/*
	struct iphdr *iph;

	int ret;
	if ((ret = ip4_payload_split(
	(uint8_t *)pkt, pktlen, &iph, NULL, NULL, NULL)) < 0) {
		return ret;
	}

	int sin_port = 0;

	struct tcphdr *tcph;
	if (tcp4_payload_split((uint8_t *)pkt, pktlen, NULL, NULL, &tcph, NULL, NULL, NULL) == 0)
		sin_port = tcph->dest;

	struct sockaddr_in daddr = {
		.sin_family = AF_INET,
		.sin_port = sin_port,
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
	msg.msg_name = (struct sockaddr *)&daddr;
	msg.msg_namelen = sizeof(daddr);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	mutex_lock(&rslock);
	// ret = sock_sendmsg(rawsocket, &msg);
	ret = kernel_sendmsg(rawsocket, &msg, &iov, 1, 1);
	mutex_unlock(&rslock);

	pr_info("%d\n", ret);

	return ret;
*/
}
static unsigned int ykb_tg(struct sk_buff *skb, const struct xt_action_param *par) 
{
	if (skb->head == NULL) return XT_CONTINUE;
	struct iphdr *iph = ip_hdr(skb);
	if (iph == NULL) {
		pr_alert("iph is NULL!\n");
		goto accept;
	}
	__u32 iph_len = iph->ihl * 4;

	struct tcphdr *tcph = tcp_hdr(skb);
	if (tcph == NULL) {
		pr_alert("tcph is NULL!\n");
		goto accept;
	}
	__u32 tcph_len = tcp_hdrlen(skb);

	// Mallocs are bad!
	__u8 *buf = kmalloc(skb->len, GFP_KERNEL);
	if (buf == NULL) {
		pr_alert("Cannot alloc enough buffer");
		goto accept;
	}
	if (skb_copy_bits(skb, 0, buf, skb->len) < 0) {
		pr_alert("Unable copy bits\n");
		goto ac_fkb;
	}

	const __u8 *payload = buf + iph_len + tcph_len;
	__u32 plen = skb->len - iph_len - tcph_len;

	struct verdict vrd = analyze_tls_data(payload, plen);

	if (vrd.gvideo_hello) {
		pr_alert("Googlevideo detected!\n");
		uint32_t f1len = skb->len;
		uint32_t f2len = skb->len;
		__u8 *frag1 = kmalloc(f1len, GFP_KERNEL);
		__u8 *frag2 = kmalloc(f2len, GFP_KERNEL);

#ifdef USE_TCP_SEGMENTATION
		size_t ipd_offset = vrd.sni_offset;
		size_t mid_offset = ipd_offset + vrd.sni_len / 2;


		int ret;
		if ((ret = tcp4_frag(buf, skb->len, 
			 mid_offset, frag1, &f1len, frag2, &f2len)) < 0) {
			pr_err("tcp4_frag");
		}

		if ((ret = send_raw_socket(frag2, f2len) < 0) || 
			(ret = send_raw_socket(frag1, f1len) < 0)) {
			pr_err("raw frags send");
			goto fallback;
		}
			
#else
// TODO: Implement ip fragmentation
/*
		// TODO: Implement compute of tcp checksum
		// GSO may turn kernel to not compute the tcp checksum.
		// Also it will never be meaningless to ensure the 
		// checksum is right.
		// nfq_tcp_compute_checksum_ipv4(tcph, ip_header);

		size_t ipd_offset = ((char *)data - (char *)tcph) + vrd.sni_offset;
		size_t mid_offset = ipd_offset + vrd.sni_len / 2;
		mid_offset += 8 - mid_offset % 8;

		if ((errno = ip4_frag(raw_payload, raw_payload_len, 
			 mid_offset, frag1, &f1len, frag2, &f2len)) < 0) {
			errno *= -1;
			perror("ip4_frag");
			goto fallback;
		}

		if ((send_raw_socket(frag2, f2len) < 0) || 
			(send_raw_socket(frag1, f1len) < 0)) {
			perror("raw frags send");
		}
*/
#endif

fallback:
		kfree(frag1);
		kfree(frag2);
		kfree(buf);
		return XT_CONTINUE;
		// return NF_DROP;
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
