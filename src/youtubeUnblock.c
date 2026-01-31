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

#define _GNU_SOURCE
#ifndef __linux__
#error "The package is linux only!"
#endif

#ifdef KERNEL_SPACE
#error "The build aims to the kernel, not userspace"
#endif

#include <stdio.h>
#include <stdlib.h>

/* Warning is ok, use this for Entware */
#include <libnetfilter_queue/linux_nfnetlink_queue.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/pktbuff.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <pthread.h>
#include <sys/socket.h>
#include <signal.h>

#include "config.h"
#include "dpi.h"
#include "args.h"
#include "utils.h"
#include "logging.h"

pthread_mutex_t rawsocket_lock;
int rawsocket = -2;

pthread_mutex_t raw6socket_lock;
int raw6socket = -2;

static struct config_t *cur_config = NULL;

static int open_socket(struct mnl_socket **_nl) {
	assert (_nl);

	struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);

	if (nl == NULL) {
		lgerror(-errno, "mnl_socket_open");
		return -1;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		lgerror(-errno, "mnl_socket_bind");
		mnl_socket_close(nl);
		return -1;
	}

	*_nl = nl;

	return 0;
}


static int close_socket(struct mnl_socket **nl) {
	assert (nl);

	if (*nl && mnl_socket_close(*nl) < 0) {
		lgerror(-errno, "mnl_socket_close");
		return -1;
	}

	*nl = NULL;

	return 0;
}

static int open_raw_socket(void) {
	if (rawsocket != -2) {
		errno = EALREADY;
		lgerror(-errno, "Raw socket is already opened");
		return -1;
	}
	
	rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rawsocket == -1) {
		lgerror(-errno, "Unable to create raw socket");
		return -1;
	}

	int mark = cur_config->mark;
	if (setsockopt(rawsocket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
	{
		lgerror(-errno, "setsockopt(SO_MARK, %d) failed", mark);
		return -1;
	}

	int mst = pthread_mutex_init(&rawsocket_lock, NULL);
	if (mst) {
		lgerror(-errno, "Mutex err: %d", mst);
		close(rawsocket);
		errno = mst;

		return -1;
	}


	return rawsocket;
}

static int close_raw_socket(void) {
	if (rawsocket < 0) {
		errno = EALREADY;
		lgerror(-errno, "Raw socket is not set");
		return -1;
	}

	if (close(rawsocket)) {
		lgerror(-errno, "Unable to close raw socket");
		pthread_mutex_destroy(&rawsocket_lock);
		return -1;
	}

	pthread_mutex_destroy(&rawsocket_lock);

	rawsocket = -2;
	return 0;
}

static int open_raw6_socket(void) {
	if (raw6socket != -2) {
		errno = EALREADY;
		lgerror(-errno, "Raw socket is already opened");
		return -1;
	}
	
	raw6socket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (rawsocket == -1) {
		lgerror(-errno, "Unable to create raw socket");
		return -1;
	}

	int mark = cur_config->mark;
	if (setsockopt(raw6socket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
	{
		lgerror(-errno, "setsockopt(SO_MARK, %d) failed", mark);
		return -1;
	}

	int mst = pthread_mutex_init(&raw6socket_lock, NULL);
	if (mst) {
		lgerror(-errno, "Mutex err: %d", mst);
		close(raw6socket);

		return -1;
	}


	return raw6socket;
}

static int close_raw6_socket(void) {
	if (raw6socket < 0) {
		errno = EALREADY;
		lgerror(-errno, "Raw socket is not set");
		return -1;
	}

	if (close(raw6socket)) {
		lgerror(-errno, "Unable to close raw socket");
		pthread_mutex_destroy(&rawsocket_lock);
		return -1;
	}

	pthread_mutex_destroy(&raw6socket_lock);

	raw6socket = -2;
	return 0;
}

static int send_raw_ipv4(const uint8_t *pkt, size_t pktlen) {
	int ret;
	if (pktlen > AVAILABLE_MTU) return -ENOMEM;

	struct iphdr *iph;

	if ((ret = ip4_payload_split(
	(uint8_t *)pkt, pktlen, &iph, NULL, NULL, NULL)) < 0) {
		errno = -ret;
		return ret;
	}

	struct sockaddr_in daddr = {
		.sin_family = AF_INET,
		/* Always 0 for raw socket */
		.sin_port = 0,
		.sin_addr = {
			.s_addr = iph->daddr
		}
	};

	if (cur_config->threads != 1)
		pthread_mutex_lock(&rawsocket_lock);

	int sent = sendto(rawsocket, 
	    pkt, pktlen, 0, 
	    (struct sockaddr *)&daddr, sizeof(daddr));

	if (cur_config->threads != 1)
		pthread_mutex_unlock(&rawsocket_lock);

	/* The function will return -errno on error as well as errno value set itself */
	if (sent < 0) sent = -errno;

	return sent;
}

static int send_raw_ipv6(const uint8_t *pkt, size_t pktlen) {
	int ret;
	if (pktlen > AVAILABLE_MTU) return -ENOMEM;

	struct ip6_hdr *iph;

	if ((ret = ip6_payload_split(
	(uint8_t *)pkt, pktlen, &iph, NULL, NULL, NULL)) < 0) {
		errno = -ret;
		return ret;
	}

	struct sockaddr_in6 daddr = {
		.sin6_family = AF_INET6,
		/* Always 0 for raw socket */
		.sin6_port = 0,
		.sin6_addr = iph->ip6_dst
	};

	if (cur_config->threads != 1)
		pthread_mutex_lock(&rawsocket_lock);

	int sent = sendto(raw6socket, 
	    pkt, pktlen, 0, 
	    (struct sockaddr *)&daddr, sizeof(daddr));

	lgtrace_addp("rawsocket sent %d", sent);

	if (cur_config->threads != 1)
		pthread_mutex_unlock(&rawsocket_lock);

	/* The function will return -errno on error as well as errno value set itself */
	if (sent < 0) sent = -errno;

	return sent;
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
	
	++global_stats.sent_counter;
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

/*
 * libnetfilter_conntrack
 * (C) 2005-2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Vyatta Inc. <http://www.vyatta.com>
 */

enum ctattr_counters {
	CTA_COUNTERS_UNSPEC,
	CTA_COUNTERS_PACKETS,		/* 64bit counters */
	CTA_COUNTERS_BYTES,		/* 64bit counters */
	CTA_COUNTERS32_PACKETS,		/* old 32bit counters, unused */
	CTA_COUNTERS32_BYTES,		/* old 32bit counters, unused */
	CTA_COUNTERS_PAD,
	__CTA_COUNTERS_MAX
};
#define CTA_COUNTERS_MAX (__CTA_COUNTERS_MAX - 1)

enum ctattr_type {
	CTA_UNSPEC,
	CTA_TUPLE_ORIG,
	CTA_TUPLE_REPLY,
	CTA_STATUS,
	CTA_PROTOINFO,
	CTA_HELP,
	CTA_NAT_SRC,
#define CTA_NAT	CTA_NAT_SRC	/* backwards compatibility */
	CTA_TIMEOUT,
	CTA_MARK,
	CTA_COUNTERS_ORIG,
	CTA_COUNTERS_REPLY,
	CTA_USE,
	CTA_ID,
	CTA_NAT_DST,
	CTA_TUPLE_MASTER,
	CTA_SEQ_ADJ_ORIG,
	CTA_NAT_SEQ_ADJ_ORIG	= CTA_SEQ_ADJ_ORIG,
	CTA_SEQ_ADJ_REPLY,
	CTA_NAT_SEQ_ADJ_REPLY	= CTA_SEQ_ADJ_REPLY,
	CTA_SECMARK,		/* obsolete */
	CTA_ZONE,
	CTA_SECCTX,
	CTA_TIMESTAMP,
	CTA_MARK_MASK,
	CTA_LABELS,
	CTA_LABELS_MASK,
	CTA_SYNPROXY,
	CTA_FILTER,
	CTA_STATUS_MASK,
	__CTA_MAX
};
#define CTA_MAX (__CTA_MAX - 1)

enum {
	__DIR_ORIG,
	__DIR_REPL
};

static int yct_parse_counters_attr_cb(const struct nlattr *attr,
				      void *data) {
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_COUNTERS_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTA_COUNTERS_PACKETS:
	case CTA_COUNTERS_BYTES:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			return MNL_CB_ERROR;
		break;
	case CTA_COUNTERS32_PACKETS:
	case CTA_COUNTERS32_BYTES:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int yct_parse_counters(const struct nlattr *attr,
			      struct ytb_conntrack *yct, int dir) {
	struct nlattr *tb[CTA_COUNTERS_MAX+1] = {0};

	if (mnl_attr_parse_nested(attr, yct_parse_counters_attr_cb, tb) < 0)
		return -1;

	if (tb[CTA_COUNTERS_PACKETS] || tb[CTA_COUNTERS32_PACKETS]) {
		uint64_t packets_counter;
		if (tb[CTA_COUNTERS32_PACKETS]) {
			packets_counter =
			ntohl(mnl_attr_get_u32(tb[CTA_COUNTERS32_PACKETS]));
		}
		if (tb[CTA_COUNTERS_PACKETS]) {
			packets_counter =
			be64toh(mnl_attr_get_u64(tb[CTA_COUNTERS_PACKETS]));
		}
		switch(dir) {
		case __DIR_ORIG:
			yct->orig_packets = packets_counter;
			yct_set_mask_attr(YCTATTR_ORIG_PACKETS, yct);
			break;
		case __DIR_REPL:
			yct->repl_packets = packets_counter;
			yct_set_mask_attr(YCTATTR_REPL_PACKETS, yct);
			break;
		}
	}
	if (tb[CTA_COUNTERS_BYTES] || tb[CTA_COUNTERS32_BYTES]) {
		uint64_t bytes_counter;
		if (tb[CTA_COUNTERS32_BYTES]) {
			bytes_counter =
			ntohl(mnl_attr_get_u32(tb[CTA_COUNTERS32_BYTES]));
		}
		if (tb[CTA_COUNTERS_BYTES]) {
			bytes_counter =
			be64toh(mnl_attr_get_u64(tb[CTA_COUNTERS_BYTES]));
		}

		switch(dir) {
		case __DIR_ORIG:
			yct->orig_bytes = bytes_counter;
			yct_set_mask_attr(YCTATTR_ORIG_BYTES, yct);
			break;
		case __DIR_REPL:
			yct->repl_bytes = bytes_counter;
			yct_set_mask_attr(YCTATTR_REPL_BYTES, yct);
			break;
		}
	}

	return 0;
}

static int yct_parse_conntrack_attr_cb(const struct nlattr *attr,
				       void *data) {
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTA_TUPLE_ORIG:
	case CTA_TUPLE_REPLY:
	case CTA_TUPLE_MASTER:
	case CTA_NAT_SEQ_ADJ_ORIG:
	case CTA_NAT_SEQ_ADJ_REPLY:
	case CTA_PROTOINFO:
	case CTA_COUNTERS_ORIG:
	case CTA_COUNTERS_REPLY:
	case CTA_HELP:
	case CTA_SECCTX:
	case CTA_TIMESTAMP:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			return MNL_CB_ERROR;
		break;
	case CTA_STATUS:
	case CTA_TIMEOUT:
	case CTA_MARK:
	case CTA_SECMARK:
	case CTA_USE:
	case CTA_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case CTA_ZONE:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			return MNL_CB_ERROR;
		break;
	case CTA_NAT_SRC:
	case CTA_NAT_DST:
		/* deprecated */
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int yct_payload_parse(const void *payload,
			     size_t payload_len, uint16_t l3num,
			     struct ytb_conntrack *yct) {
	struct nlattr *tb[CTA_MAX+1] = {0};

	if (mnl_attr_parse_payload(payload, payload_len,
				   yct_parse_conntrack_attr_cb, tb) < 0)
		return -1;

	if (tb[CTA_MARK]) {
		yct->connmark = ntohl(mnl_attr_get_u32(tb[CTA_MARK]));
		yct_set_mask_attr(YCTATTR_CONNMARK, yct);
	}


	if (tb[CTA_COUNTERS_ORIG]) {
		if (yct_parse_counters(tb[CTA_COUNTERS_ORIG],
					yct, __DIR_ORIG) < 0)
			return -1;
	}

	if (tb[CTA_ID]) {
		yct->id = ntohl(mnl_attr_get_u32(tb[CTA_ID]));
		yct_set_mask_attr(YCTATTR_CONNID, yct);
	}

	if (tb[CTA_COUNTERS_REPLY]) {
		if (yct_parse_counters(tb[CTA_COUNTERS_REPLY],
					yct, __DIR_REPL) < 0)
			return -1;
	}

	return 0;
}


// Per-queue data. Passed to queue_cb.
struct queue_data {
	struct mnl_socket **_nl;
	int queue_num;
};

/**
 * Used to accept unsupported packets (GSOs)
 */
static int fallback_accept_packet(uint32_t id, struct queue_data qdata) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *verdnlh;
        verdnlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, qdata.queue_num);
        nfq_nlmsg_verdict_put(verdnlh, id, NF_ACCEPT);

        if (mnl_socket_sendto(*qdata._nl, verdnlh, verdnlh->nlmsg_len) < 0) {
                lgerror(-errno, "mnl_socket_send");
                return MNL_CB_ERROR;
        }

        return MNL_CB_OK;
}


struct dps_t {
	uint8_t *pkt;
	size_t pktlen;
	// Time for the packet in milliseconds
	uint32_t timer;
};
// Note that the thread will automatically release dps_t and pkt_buff
void *delay_packet_send_fn(void *data) {
	struct dps_t *dpdt = data;

	uint8_t *pkt = dpdt->pkt;
	size_t pktlen = dpdt->pktlen;

	usleep(dpdt->timer * 1000);
	int ret = send_raw_socket(pkt, pktlen);
	if (ret < 0) {
		errno = -ret;
		lgerror(-errno, "send delayed raw packet");
	}

	free(pkt);
	free(dpdt);
	return NULL;
}

int delay_packet_send(const unsigned char *data, size_t data_len, unsigned int delay_ms) {
	int ret;

	struct dps_t *dpdt = malloc(sizeof(struct dps_t));
	if (dpdt == NULL) {
		return -ENOMEM;
	}
	*dpdt = (struct dps_t){0};

	dpdt->pkt = malloc(data_len);
	if (dpdt->pkt == NULL) {
		free(dpdt);
		return -ENOMEM;
	}
	memcpy(dpdt->pkt, data, data_len);

	dpdt->pktlen = data_len;
	dpdt->timer = delay_ms;
	pthread_t thr = {0};
	ret = pthread_create(&thr, NULL, delay_packet_send_fn, dpdt);
	if (ret != 0) {
		free(dpdt->pkt);
		free(dpdt);
		return -ret;
	}

	ret = pthread_detach(thr);

	lgtrace_addp("Scheduled packet send after %d ms", delay_ms);

	return 0;
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	
	struct queue_data *qdata = data;

	struct nfqnl_msg_packet_hdr *ph = NULL;
        struct nlattr *attr[NFQA_MAX+1] = {0};
	struct packet_data packet = {0};
	struct ytb_conntrack *yct = &packet.yct;
	struct nfgenmsg *nfg;
	struct nlmsghdr *verdnlh;
	int ret;
	uint16_t l3num;	
	uint32_t id;

	++global_stats.all_packet_counter;

        if (nfq_nlmsg_parse(nlh, attr) < 0) {
                lgerror(-errno, "Attr parse");
                return MNL_CB_ERROR;
        }
 
        if (attr[NFQA_PACKET_HDR] == NULL) {
		errno = ENODATA;
                lgerror(-errno, "Metaheader not set");
                return MNL_CB_ERROR;
        }

	nfg = mnl_nlmsg_get_payload(nlh);
	l3num = nfg->nfgen_family;

        ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

        id = ntohl(ph->packet_id);

        packet.payload_len = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
        packet.payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

	if (attr[NFQA_CAP_LEN] != NULL &&
		ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN])) != packet.payload_len) {
		lgerr("The packet was truncated! Skip!");
		return fallback_accept_packet(id, *qdata);
	}

	if (attr[NFQA_MARK] != NULL) {
		// Skip packets sent by rawsocket to escape infinity loop.
		if (CHECK_BITFIELD(ntohl(mnl_attr_get_u32(attr[NFQA_MARK])),
				cur_config->mark)) {
			return fallback_accept_packet(id, *qdata);
		}
	}

	if (attr[NFQA_CT] != NULL) {
		ret = yct_payload_parse(
			mnl_attr_get_payload(attr[NFQA_CT]),
			mnl_attr_get_payload_len(attr[NFQA_CT]),
			l3num, yct);
		if (ret < 0) {
			lgerror(ret, "Cannot parse CT");

			goto ct_out;
		}
	
		lgtrace("[CONNTRACK TRACE] orig_packets=%lu repl_packets=%lu orig_bytes=%lu repl_bytes=%lu connmark=%d id=%ud\n", yct->orig_packets, yct->repl_packets, yct->orig_bytes, yct->repl_bytes, yct->connmark, yct->id);

	}

ct_out:
	verdnlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, qdata->queue_num);

	ret = process_packet(cur_config, &packet);

	++global_stats.packet_counter;

	switch (ret) {
		case PKT_DROP:
			++global_stats.target_counter;
			nfq_nlmsg_verdict_put(verdnlh, id, NF_DROP);
			break;
		default:
			nfq_nlmsg_verdict_put(verdnlh, id, NF_ACCEPT);
			break;
	}

        if (mnl_socket_sendto(*qdata->_nl, verdnlh, verdnlh->nlmsg_len) < 0) {
                lgerror(-errno, "mnl_socket_send");
                return MNL_CB_ERROR;
        }
	
	return MNL_CB_OK;
}

#define BUF_SIZE (0xffff + (MNL_SOCKET_BUFFER_SIZE / 2))

int init_queue(int queue_num) {
	struct mnl_socket *nl;

	if (open_socket(&nl)) {
		lgerror(-errno, "Unable to open socket");
		return -1;
	}

	uint32_t portid = mnl_socket_get_portid(nl);

	struct nlmsghdr *nlh;
	char *buf = malloc(BUF_SIZE);
	if (buf == NULL) {
		lgerror(-ENOMEM, "Allocation error");
		goto die_alloc;
	}

	/* Support for kernels versions < 3.8 */
	// Obsolete and ignored in kernel version 3.8
	// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0360ae412d09bc6f4864c801effcb20bfd84520e

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, PF_INET, NFQNL_CFG_CMD_PF_UNBIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		lgerror(-errno, "mnl_socket_send");
		goto die;
	}

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, PF_INET, NFQNL_CFG_CMD_PF_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		lgerror(-errno, "mnl_socket_send");
		goto die;
	}

	if (cur_config->use_ipv6) {
		nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_cmd(nlh, PF_INET6, NFQNL_CFG_CMD_PF_UNBIND);

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			lgerror(-errno, "mnl_socket_send");
			goto die;
		}

		nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
		nfq_nlmsg_cfg_put_cmd(nlh, PF_INET6, NFQNL_CFG_CMD_PF_BIND);

		if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
			lgerror(-errno, "mnl_socket_send");
			goto die;
		}
	}
	/* End of support for kernel versions < 3.8 */

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		lgerror(-errno, "mnl_socket_send");
		goto die;
	}

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

	unsigned int cfg_flags = NFQA_CFG_F_GSO | NFQA_CFG_F_CONNTRACK | NFQA_CFG_F_FAIL_OPEN;
	unsigned int cfg_mask = 0;

	if (cur_config->use_gso) {
		cfg_mask |= NFQA_CFG_F_GSO;
	}
	if (cur_config->use_conntrack) {
		cfg_mask |= NFQA_CFG_F_CONNTRACK;
	}
	cfg_mask |= NFQA_CFG_F_FAIL_OPEN;

	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(cfg_flags));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(cfg_mask));


	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		lgerror(-errno, "mnl_socket_send");
		goto die;
	}


	/* ENOBUFS is signalled to userspace when packets were lost
          * on kernel side.  In most cases, userspace isn't interested
          * in this information, so turn it off.
          */
	int ret = 1;
	mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

	struct queue_data qdata = {
		._nl = &nl,
		.queue_num = queue_num
	};

	lginfo("Queue %d started", qdata.queue_num);

	while (1) {
		ret = mnl_socket_recvfrom(nl, buf, BUF_SIZE);
		if (ret == -1) {
			lgerror(-errno, "mnl_socket_recvfrom");
			goto die;
		}

		ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, &qdata);
		if (ret < 0) {
			lgerror(ret, "mnl_cb_run");
			if (ret == -EPERM) {
				lgerr("Probably another instance of youtubeUnblock with the same queue number is running");
			} else {
				lgerr("Make sure the nfnetlink_queue kernel module is loaded");
			}
			goto die;
		}
	}


	free(buf);
	close_socket(&nl);
	return 0;

die:
	free(buf);
die_alloc:
	close_socket(&nl);
	return -1;
}

// Per-queue config. Used to initialize a queue. Passed to wrapper
struct queue_conf {
	uint16_t i;
	int queue_num;
};

struct queue_res {
	int status;
};
static struct queue_res defqres = {0};

static struct queue_res threads_reses[MAX_THREADS];

void *init_queue_wrapper(void *qdconf) {
	struct queue_conf *qconf = qdconf;
	struct queue_res *thres = threads_reses + qconf->i;
	
	thres->status = init_queue(qconf->queue_num);

	lgerror(thres->status, "Thread %d exited with status %d", qconf->i, thres->status);

	return thres;
}

struct instance_config_t instance_config = {
	.send_raw_packet = send_raw_socket,
	.send_delayed_packet = delay_packet_send,
};

void sigint_handler(int s) {
	lginfo("youtubeUnblock stats: catched %ld packets, "
		"processed %ld packets, "
		"targetted %ld packets, sent over socket %ld packets",
		global_stats.all_packet_counter, global_stats.packet_counter, 
		global_stats.target_counter, global_stats.sent_counter);

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
	int ret;
	struct config_t config;

	if ((ret = yparse_args(&config, argc, argv)) != 0) {
		if (ret < 0) {
			lgerror(-errno, "Unable to parse args");
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	print_version();
	print_welcome(&config);

	parse_global_lgconf(&config);
	cur_config = &config;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	if (open_raw_socket() < 0) {
		lgerror(-errno, "Unable to open raw socket");
		exit(EXIT_FAILURE);
	}

	if (config.use_ipv6) {
		if (open_raw6_socket() < 0) {
			lgerror(-errno, "Unable to open raw socket for ipv6");
			close_raw_socket();
			exit(EXIT_FAILURE);
		}
	}

	if (config.daemonize) {
		daemon(0, config.noclose);
	}

	struct queue_res *qres = &defqres;

	if (config.threads == 1) {
		struct queue_conf tconf = {
			.i = 0,
			.queue_num = config.queue_start_num
		};

		qres = init_queue_wrapper(&tconf);
	} else {
		lginfo("%d threads wil be used", config.threads);

		struct queue_conf thread_confs[MAX_THREADS];
		pthread_t threads[MAX_THREADS];
		for (int i = 0; i < config.threads; i++) {
			struct queue_conf *tconf = thread_confs + i;
			pthread_t *thr = threads + i;

			tconf->queue_num = config.queue_start_num + i;
			tconf->i = i;

			pthread_create(thr, NULL, init_queue_wrapper, tconf);
		}

		void *res;
		for (int i = 0; i < config.threads; i++) {
			pthread_join(threads[i], &res);

			qres = res;
		}
	}

	close_raw_socket();
	if (config.use_ipv6)
		close_raw6_socket();

	return -qres->status;
}

