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
#include "utils.h"
#include "logging.h"

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

static struct socket *rawsocket;
DEFINE_MUTEX(rslock);

static struct socket *raw6socket;
DEFINE_MUTEX(rs6lock);

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

	int mark = config.mark;
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

static int send_raw_ipv4(const uint8_t *pkt, uint32_t pktlen) {
	int ret = 0;
	if (pktlen > AVAILABLE_MTU) return -ENOMEM;

	struct iphdr *iph;

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

static int open_raw6_socket(void) {
	int ret = 0;
	ret = sock_create(AF_INET6, SOCK_RAW, IPPROTO_RAW, &raw6socket);

	if (ret < 0) {
		pr_alert("Unable to create raw socket\n");
		goto err;
	}

	sockptr_t optval = {
		.kernel = NULL,
		.is_kernel = 1
	};

	int mark = config.mark;
	optval.kernel = &mark;
	ret = sock_setsockopt(raw6socket, SOL_SOCKET, SO_MARK, optval, sizeof(mark));
	if (ret < 0)
	{
		pr_alert("setsockopt(SO_MARK, %d) failed\n", mark);
		goto sr_err;
	}
	int one = 1;
	optval.kernel = &one;

	return 0;
sr_err:
	sock_release(raw6socket);
err:
	return ret;
}

static void close_raw6_socket(void) {
	sock_release(raw6socket);
}

static int send_raw_ipv6(const uint8_t *pkt, uint32_t pktlen) {
	int ret = 0;
	if (pktlen > AVAILABLE_MTU) return -ENOMEM;

	struct ip6_hdr *iph;

	if ((ret = ip6_payload_split(
	(uint8_t *)pkt, pktlen, &iph, NULL, NULL, NULL)) < 0) {
		return ret;
	}

	struct sockaddr_in6 daddr = {
		.sin6_family = AF_INET6,
		/* Always 0 for raw socket */
		.sin6_port = 0,
		.sin6_addr = iph->ip6_dst
	};

	struct msghdr msg;
	struct kvec iov;
	iov.iov_base = (__u8 *)pkt;
	iov.iov_len = pktlen;
	iov_iter_kvec(&msg.msg_iter, READ, &iov, 1, 1);

	msg.msg_flags = 0;
	msg.msg_name = &daddr;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	mutex_lock(&rs6lock);
	ret = kernel_sendmsg(raw6socket, &msg, &iov, 1, pktlen);
	mutex_unlock(&rs6lock);

	return ret;
}

static int send_raw_socket(const uint8_t *pkt, uint32_t pktlen) {
	int ret;

	if (pktlen > AVAILABLE_MTU) {
		pr_warn("The packet is too big and may cause issues!");

		NETBUF_ALLOC(buff1, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(buff1)) {
			lgerror("Allocation error", -ENOMEM);
			return -ENOMEM;
		}
		NETBUF_ALLOC(buff2, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(buff2)) {
			lgerror("Allocation error", -ENOMEM);
			NETBUF_FREE(buff2);
			return -ENOMEM;
		}
		uint32_t buff1_size = MAX_PACKET_SIZE;
		uint32_t buff2_size = MAX_PACKET_SIZE;

		switch (config.fragmentation_strategy) {
			case FRAG_STRAT_TCP:
				if ((ret = tcp_frag(pkt, pktlen, AVAILABLE_MTU-128,
					buff1, &buff1_size, buff2, &buff2_size)) < 0) {

					goto erret_lc;
				}
				break;
			case FRAG_STRAT_IP:
				if ((ret = ip4_frag(pkt, pktlen, AVAILABLE_MTU-128,
					buff1, &buff1_size, buff2, &buff2_size)) < 0) {

					goto erret_lc;
				}
				break;
			default:
				pr_warn("send_raw_socket: Packet is too big but fragmentation is disabled!");
				ret = -EINVAL;
				goto erret_lc;
		}

		int sent = 0;
		ret = send_raw_socket(buff1, buff1_size);

		if (ret >= 0) sent += ret;
		else {
			goto erret_lc;
		}

		ret = send_raw_socket(buff2, buff2_size);
		if (ret >= 0) sent += ret;
		else {
			goto erret_lc;
		}

		NETBUF_FREE(buff1);
		NETBUF_FREE(buff2);
		return sent;
erret_lc:
		NETBUF_FREE(buff1);
		NETBUF_FREE(buff2);
		return ret;
	}
	
	int ipvx = netproto_version(pkt, pktlen);

	if (ipvx == IP4VERSION) 
		return send_raw_ipv4(pkt, pktlen);

	else if (ipvx == IP6VERSION) 
		return send_raw_ipv6(pkt, pktlen);

	printf("proto version %d is unsupported\n", ipvx);
	return -EINVAL;
}

static void delay_packet_send(const unsigned char *data, unsigned int data_len, unsigned int delay_ms) {
	pr_warn("delay_packet_send won't work on current youtubeUnblock version");
	send_raw_socket(data, data_len);
}

struct instance_config_t instance_config = {
	.send_raw_packet = send_raw_socket,
	.send_delayed_packet = delay_packet_send,
};

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
	.proto		= IPPROTO_TCP,
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
	.proto		= IPPROTO_TCP,
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
