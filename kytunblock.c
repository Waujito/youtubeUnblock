#ifndef KERNEL_SPACE
#error "You are trying to compile the kernel module not in the kernel space"
#endif

// Kernel module for youtubeUnblock.
// Build with make kmake 
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include "mangle.h"
#include "config.h"
#include "utils.h"
#include "logging.h"

MODULE_LICENSE("GPL");
MODULE_VERSION("0.3.2");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtubeUnblock");

static struct socket *rawsocket;

static struct socket *raw6socket;

static int open_raw_socket(void) {
	int ret = 0;
	ret = sock_create(AF_INET, SOCK_RAW, IPPROTO_RAW, &rawsocket);

	if (ret < 0) {
		pr_alert("Unable to create raw socket\n");
		goto err;
	}

	// That's funny, but this is how it is done in the kernel
	// https://elixir.bootlin.com/linux/v3.17.7/source/net/core/sock.c#L916
	rawsocket->sk->sk_mark=config.mark;

	return 0;

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

	memset(&msg, 0, sizeof(msg));

	iov.iov_base = (__u8 *)pkt;
	iov.iov_len = pktlen;

	msg.msg_flags = 0;
	msg.msg_name = &daddr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;


	ret = kernel_sendmsg(rawsocket, &msg, &iov, 1, pktlen);

	return ret;
}

static int open_raw6_socket(void) {
	int ret = 0;
	ret = sock_create(AF_INET6, SOCK_RAW, IPPROTO_RAW, &raw6socket);

	if (ret < 0) {
		pr_alert("Unable to create raw socket\n");
		goto err;
	}

	// That's funny, but this is how it is done in the kernel
	// https://elixir.bootlin.com/linux/v3.17.7/source/net/core/sock.c#L916
	raw6socket->sk->sk_mark=config.mark;

	return 0;

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

	struct kvec iov;
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	iov.iov_base = (__u8 *)pkt;
	iov.iov_len = pktlen;

	msg.msg_flags = 0;
	msg.msg_name = &daddr;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	ret = kernel_sendmsg(raw6socket, &msg, &iov, 1, pktlen);

	return ret;
}

static int send_raw_socket(const uint8_t *pkt, uint32_t pktlen) {
	int ret;

	if (pktlen > AVAILABLE_MTU) {
		lgdebug("The packet is too big and may cause issues!");

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
				pr_info("send_raw_socket: Packet is too big but fragmentation is disabled!");
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
	pr_info("delay_packet_send won't work on current youtubeUnblock version");
	send_raw_socket(data, data_len);
}

struct instance_config_t instance_config = {
	.send_raw_packet = send_raw_socket,
	.send_delayed_packet = delay_packet_send,
};


/* If this is a Red Hat-based kernel (Red Hat, CentOS, Fedora, etc)... */
#ifdef RHEL_RELEASE_CODE

#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		const struct nf_hook_state *state) \

#elif RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#else

#error "Sorry; this version of RHEL is not supported because it's kind of old."

#endif /* RHEL_RELEASE_CODE >= x */


/* If this NOT a RedHat-based kernel (Ubuntu, Debian, SuSE, etc)... */
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		void *priv, \
		struct sk_buff *skb, \
		const struct nf_hook_state *state)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct nf_hook_state *state)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		unsigned int hooknum, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#else
#error "Linux < 3.0 isn't supported at all."

#endif /* LINUX_VERSION_CODE > n */

#endif /* RHEL or not RHEL */



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
