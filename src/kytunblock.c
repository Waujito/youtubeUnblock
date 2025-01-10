/*
  youtubeUnblock - https://github.com/Waujito/youtubeUnblock

  Copyright (C) 2024-2025 Vadim Vetrov <vetrovvd@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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

#ifdef IS_ENABLED
#if !(IS_ENABLED(CONFIG_NF_CONNTRACK))
#define NO_CONNTRACK
#endif /* IS CONNTRACK ENABLED */
#endif /* ifdef IS_ENABLED */

#ifndef NO_CONNTRACK
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#endif

#include "mangle.h"
#include "config.h"
#include "utils.h"
#include "logging.h"
#include "args.h"

#if defined(PKG_VERSION)
MODULE_VERSION(PKG_VERSION);
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtubeUnblock");

static struct socket *rawsocket;
static struct socket *raw6socket;

DEFINE_SPINLOCK(hot_config_spinlock);
DEFINE_MUTEX(config_free_mutex);
atomic_t hot_config_counter = ATOMIC_INIT(0);
// boolean flag for hot config replacement
// if 1, youtubeUnblock should stop processing
atomic_t hot_config_rep = ATOMIC_INIT(0);

static int open_raw_socket(void) {
	int ret = 0;
	ret = sock_create(AF_INET, SOCK_RAW, IPPROTO_RAW, &rawsocket);

	if (ret < 0) {
		lgerror(ret, "Unable to create raw socket\n");
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

static int send_raw_ipv4(const uint8_t *pkt, size_t pktlen) {
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

	msg.msg_flags = MSG_DONTWAIT;
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
		lgerror(ret, "Unable to create raw socket\n");
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

static int send_raw_ipv6(const uint8_t *pkt, size_t pktlen) {
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

	msg.msg_flags = MSG_DONTWAIT;
	msg.msg_name = &daddr;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	ret = kernel_sendmsg(raw6socket, &msg, &iov, 1, pktlen);

	return ret;
}

static int send_raw_socket(const uint8_t *pkt, size_t pktlen) {
	int ret;

	if (pktlen > AVAILABLE_MTU) {
		lgtrace("Split packet!");

		size_t buff1_size = pktlen;
		uint8_t *buff1 = malloc(buff1_size);
		if (buff1 == NULL) {
			lgerror(-ENOMEM, "Allocation error");
			return -ENOMEM;
		}
		size_t buff2_size = pktlen;
		uint8_t *buff2 = malloc(buff2_size);
		if (buff2 == NULL) {
			lgerror(-ENOMEM, "Allocation error");
			free(buff1);
			return -ENOMEM;
		}

		if ((ret = tcp_frag(pkt, pktlen, AVAILABLE_MTU-128,
			buff1, &buff1_size, buff2, &buff2_size)) < 0) {

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

		free(buff1);
		free(buff2);
		return sent;
erret_lc:
		free(buff1);
		free(buff2);
		return ret;
	}
	
	int ipvx = netproto_version(pkt, pktlen);

	if (ipvx == IP4VERSION) {
		ret = send_raw_ipv4(pkt, pktlen);
	} else if (ipvx == IP6VERSION) {
		ret = send_raw_ipv6(pkt, pktlen);
	} else {
		printf("proto version %d is unsupported\n", ipvx);
		return -EINVAL;
	}

	lgtrace_addp("raw_sock_send: %d", ret);
	return ret;
}

static int delay_packet_send(const unsigned char *data, size_t data_len, unsigned int delay_ms) {
	lginfo("delay_packet_send won't work on current youtubeUnblock version");
	return send_raw_socket(data, data_len);
}

struct instance_config_t instance_config = {
	.send_raw_packet = send_raw_socket,
	.send_delayed_packet = delay_packet_send,
};

static int conntrack_parse(const struct sk_buff *skb, 
			  struct ytb_conntrack *yct) {
#ifndef NO_CONNTRACK

	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	const struct nf_conn_counter *counters;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	const struct nf_conn_acct *acct;
	acct = nf_conn_acct_find(ct);
	if (!acct)
		return -1;
	counters = acct->counter;
#else 
	counters = nf_conn_acct_find(ct);
	if (!counters)
		return -1;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
	yct->orig_packets = atomic64_read(&counters[IP_CT_DIR_ORIGINAL].packets);
	yct->orig_bytes = atomic64_read(&counters[IP_CT_DIR_ORIGINAL].bytes);
	yct->repl_packets = atomic64_read(&counters[IP_CT_DIR_REPLY].packets);
	yct->repl_bytes = atomic64_read(&counters[IP_CT_DIR_REPLY].bytes);
#else 
	yct->orig_packets = counters[IP_CT_DIR_ORIGINAL].packets;
	yct->orig_bytes = counters[IP_CT_DIR_ORIGINAL].bytes;
	yct->repl_packets = counters[IP_CT_DIR_REPLY].packets;
	yct->repl_bytes = counters[IP_CT_DIR_REPLY].bytes;
#endif
	yct_set_mask_attr(YCTATTR_ORIG_PACKETS, yct);
	yct_set_mask_attr(YCTATTR_ORIG_BYTES, yct);
	yct_set_mask_attr(YCTATTR_REPL_PACKETS, yct);
	yct_set_mask_attr(YCTATTR_REPL_BYTES, yct);

#if defined(CONFIG_NF_CONNTRACK_MARK)
	yct->connmark = READ_ONCE(ct->mark);
	yct_set_mask_attr(YCTATTR_CONNMARK, yct);
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	yct->id = nf_ct_get_id(ct);
	yct_set_mask_attr(YCTATTR_CONNID, yct);
#endif

#endif /* NO_CONNTRACK */

	return 0;
}

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
	struct packet_data pd = {0};
	uint8_t *data_buf = NULL;
	int nf_verdict = NF_ACCEPT;

	spin_lock(&hot_config_spinlock);
	// if set flag to disable processing, 
	// explicitly accept all packets
	if (atomic_read(&hot_config_rep)) {
		spin_unlock(&hot_config_spinlock);
		return NF_ACCEPT;
	} else {
		atomic_inc(&hot_config_counter);
	}
	spin_unlock(&hot_config_spinlock);

	if ((skb->mark & config.mark) == config.mark)  {
		goto send_verdict;
	}
	
	if (skb->head == NULL) {
		goto send_verdict;
	}
	
	if (skb->len >= MAX_PACKET_SIZE) {
		goto send_verdict;
	}

	ret = conntrack_parse(skb, &pd.yct);
	if (ret < 0) {
		lgtrace("[TRACE] conntrack_parse error code\n");
	}

	if (config.connbytes_limit != 0 && yct_is_mask_attr(YCTATTR_ORIG_PACKETS, &pd.yct) && pd.yct.orig_packets > config.connbytes_limit)
		goto send_verdict;


	if (skb_is_nonlinear(skb)) {
		data_buf = kmalloc(skb->len, GFP_KERNEL);
		if (data_buf == NULL) {
			lgerror(-ENOMEM, "Cannot allocate packet buffer");
		}
		ret = skb_copy_bits(skb, 0, data_buf, skb->len);
		if (ret) {
			lgerror(ret, "Cannot copy bits");
			goto send_verdict;
		}

		pd.payload = data_buf;	
	} else {
		pd.payload = skb->data;
	}

	pd.payload_len = skb->len;

	int vrd = process_packet(&pd);

	switch(vrd) {
		case PKT_ACCEPT:
			nf_verdict = NF_ACCEPT;
			break;
		case PKT_DROP:
			nf_verdict = NF_STOLEN;
			kfree_skb(skb);
			break;
	}

send_verdict:
	kfree(data_buf);
	atomic_dec(&hot_config_counter);
	return nf_verdict;
}

static struct nf_hook_ops ykb_hook_ops[] = {
{
	.hook		= ykb_nf_hook,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_POST_ROUTING,
	.priority	= NF_IP_PRI_MANGLE,
}
#ifndef NO_IPV6
,{
	.hook		= ykb_nf_hook,
	.pf		= NFPROTO_IPV6,
	.hooknum	= NF_INET_POST_ROUTING,
	.priority	= NF_IP6_PRI_MANGLE,
}
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
static int ykb_net_init(struct net *net)
{
	return nf_register_net_hooks(net, ykb_hook_ops, sizeof(ykb_hook_ops));
}

static void ykb_net_exit(struct net *net)
{
	nf_unregister_net_hooks(net, ykb_hook_ops, sizeof(ykb_hook_ops));
}

static struct pernet_operations ykb_pernet_ops = {
	.init = ykb_net_init,
	.exit = ykb_net_exit
};
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0) */

static int __init ykb_init(void) {
	int ret;

#ifdef NO_CONNTRACK
	lgwarning("Conntrack is disabled.");
#endif
#ifdef NO_IPV6
	lgwarning("IPv6 is disabled.");
#endif
	
	ret = init_config(&config);
	if (ret < 0) goto err;

	ret = open_raw_socket();
	if (ret < 0) {
		lgerror(ret, "ipv4 rawsocket initialization failed!");
		goto err;
	}

#ifndef NO_IPV6
	ret = open_raw6_socket();
	if (ret < 0) {
		lgerror(ret, "ipv6 rawsocket initialization failed!");
		goto err_close4_sock;
	}
#endif /* NO_IPV6 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	ret = register_pernet_subsys(&ykb_pernet_ops);
#else
	ret = nf_register_hooks(ykb_hook_ops, sizeof(ykb_hook_ops));
#endif

	if (ret < 0)
		goto err_close_sock;


	lginfo("youtubeUnblock kernel module started.\n");
	return 0;

err_close_sock:
#ifndef NO_IPV6
	close_raw6_socket();
#endif
err_close4_sock:
	close_raw_socket();
err:
	return ret;
}

static void __exit ykb_destroy(void) {
	mutex_lock(&config_free_mutex);
	// acquire all locks.
	spin_lock(&hot_config_spinlock);
	// lock netfilter youtubeUnblock
	atomic_set(&hot_config_rep, 1);
	spin_unlock(&hot_config_spinlock);

	// wait until all 
	// netfilter callbacks keep running
	while (atomic_read(&hot_config_counter) > 0) {}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	unregister_pernet_subsys(&ykb_pernet_ops);
#else
	nf_unregister_hooks(ykb_hook_ops, sizeof(ykb_hook_ops));
#endif


#ifndef NO_IPV6
	close_raw6_socket();
#endif

	close_raw_socket();
	free_config(config);
	lginfo("youtubeUnblock kernel module destroyed.\n");
}

module_init(ykb_init);
module_exit(ykb_destroy);
