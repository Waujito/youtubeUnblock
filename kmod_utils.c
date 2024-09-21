#ifndef KERNEL_SPACE
#error "You are trying to compile the kernel module not in the kernel space"
#endif
#include "kmod_utils.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>

#include "config.h"
#include "utils.h"
#include "logging.h"

static struct socket *rawsocket;

static struct socket *raw6socket;


int open_raw_socket(void) {
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

void close_raw_socket(void) {
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

int open_raw6_socket(void) {
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

void close_raw6_socket(void) {
	sock_release(raw6socket);
}

int send_raw_ipv6(const uint8_t *pkt, uint32_t pktlen) {
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

int send_raw_socket(const uint8_t *pkt, uint32_t pktlen) {
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

void delay_packet_send(const unsigned char *data, unsigned int data_len, unsigned int delay_ms) {
	pr_info("delay_packet_send won't work on current youtubeUnblock version");
	send_raw_socket(data, data_len);
}

struct instance_config_t instance_config = {
	.send_raw_packet = send_raw_socket,
	.send_delayed_packet = delay_packet_send,
};
