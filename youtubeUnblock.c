#define _GNU_SOURCE
#ifndef __linux__
#error "The package is linux only!"
#endif

#ifdef KERNEL_SPACE
#error "The build aims to the kernel, not userspace"
#endif

#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <stdio.h>
#include <stdlib.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/pktbuff.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/netfilter.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#include <pthread.h>
#include "mangle.h"

#ifndef NOUSE_GSO
#define USE_GSO
#endif

#ifndef USE_IP_FRAGMENTATION
#define USE_TCP_SEGMENTATION
#endif

#define RAWSOCKET_MARK 0xfc70
#define MAX_THREADS 16

#ifndef THREADS_NUM
#define THREADS_NUM 1
#endif

#if THREADS_NUM > MAX_THREADS
#error "Too much threads"
#endif


static struct {
	uint32_t queue_start_num;
	int rawsocket;
	pthread_mutex_t rawsocket_lock;
	int threads;
} config = {
	.rawsocket = -2,
	.threads=THREADS_NUM
};

static int parse_args(int argc, const char *argv[]) {
	int err;
	char *end;

	if (argc != 2) {
		errno = EINVAL;
		goto errormsg_help;
	}

	uint32_t queue_num = strtoul(argv[1], &end, 10);
	if (errno != 0 || *end != '\0') goto errormsg_help;

	config.queue_start_num = queue_num;
	return 0;

errormsg_help:
	err = errno;
	printf("Usage: %s [queue_num]\n", argv[0]);
	errno = err;
	if (errno == 0) errno = EINVAL;

	return -1;
}

static int open_socket(struct mnl_socket **_nl) {
	struct mnl_socket *nl = NULL;
	nl = mnl_socket_open(NETLINK_NETFILTER);

	if (nl == NULL) {
		perror("mnl_socket_open");
		return -1;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		mnl_socket_close(nl);
		return -1;
	}

	*_nl = nl;

	return 0;
}


static int close_socket(struct mnl_socket **_nl) {
	struct mnl_socket *nl = *_nl;
	if (nl == NULL) return 1;
	if (mnl_socket_close(nl) < 0) {
		perror("mnl_socket_close");
		return -1;
	}

	*_nl = NULL;

	return 0;
}

static int open_raw_socket(void) {
	if (config.rawsocket != -2) {
		errno = EALREADY;
		perror("Raw socket is already opened");
		return -1;
	}
	
	config.rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (config.rawsocket == -1) {
		perror("Unable to create raw socket");
		return -1;
	}

	int one = 1;
	const int *val = &one;
	if (setsockopt(config.rawsocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		fprintf(stderr, "setsockopt(IP_HDRINCL, 1) failed\n");
		return -1;
	}

	int mark = RAWSOCKET_MARK;
	if (setsockopt(config.rawsocket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
	{
		fprintf(stderr, "setsockopt(SO_MARK, %d) failed\n", mark);
		return -1;
	}

	int mst = pthread_mutex_init(&config.rawsocket_lock, NULL);
	if (mst) {
		fprintf(stderr, "Mutex err: %d\n", mst);
		close(config.rawsocket);
		errno = mst;

		return -1;
	}


	return config.rawsocket;
}

static int close_raw_socket(void) {
	if (config.rawsocket < 0) {
		errno = EALREADY;
		perror("Raw socket is not set");
		return -1;
	}

	if (close(config.rawsocket)) {
		perror("Unable to close raw socket");
		pthread_mutex_destroy(&config.rawsocket_lock);
		return -1;
	}

	pthread_mutex_destroy(&config.rawsocket_lock);

	config.rawsocket = -2;
	return 0;
}


#define AVAILABLE_MTU 1384

static int send_raw_socket(const uint8_t *pkt, uint32_t pktlen) {
	if (pktlen > AVAILABLE_MTU) {
#ifdef DEBUG
		printf("Split packet!\n");
#endif

		uint8_t buff1[MNL_SOCKET_BUFFER_SIZE];
		uint32_t buff1_size = MNL_SOCKET_BUFFER_SIZE;
		uint8_t buff2[MNL_SOCKET_BUFFER_SIZE];
		uint32_t buff2_size = MNL_SOCKET_BUFFER_SIZE;

#ifdef USE_TCP_SEGMENTATION
		if ((errno = tcp4_frag(pkt, pktlen, AVAILABLE_MTU-128, 
			buff1, &buff1_size, buff2, &buff2_size)) < 0)
			return -1;
#else
		if ((errno = ip4_frag(pkt, pktlen, AVAILABLE_MTU-128, 
			buff1, &buff1_size, buff2, &buff2_size)) < 0)
			return -1;

#endif

		int sent = 0;
		int status = send_raw_socket(buff1, buff1_size);

		if (status >= 0) sent += status;
		else {
			return status;
		}

		status = send_raw_socket(buff2, buff2_size);
		if (status >= 0) sent += status;
		else {
			return status;
		}

		return sent;
	}


	struct iphdr *iph;

	if ((errno = ip4_payload_split(
	(uint8_t *)pkt, pktlen, &iph, NULL, NULL, NULL)) < 0) {
		errno *= -1;
		return -1;
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

	pthread_mutex_lock(&config.rawsocket_lock);

	int sent = sendto(config.rawsocket, 
	    pkt, pktlen, 0, 
	    (struct sockaddr *)&daddr, sizeof(daddr));

	pthread_mutex_unlock(&config.rawsocket_lock);

	return sent;
}

struct packet_data {
	uint32_t id;
	uint16_t hw_proto;
	uint8_t hook;
	
	void *payload;
	uint16_t payload_len;
};


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
                perror("mnl_socket_send");
                return MNL_CB_ERROR;
        }

        return MNL_CB_OK;
}

static int process_packet(const struct packet_data packet, struct queue_data qdata) {

	char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *verdnlh;

#ifdef DEBUG_LOGGING
        printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u)\n",
	       packet.id, packet.hw_proto, packet.hook, packet.payload_len);
#endif

	if (packet.hw_proto != ETH_P_IP) {
		return fallback_accept_packet(packet.id, qdata);
	}

	const int family = AF_INET;
	const uint8_t *raw_payload = packet.payload;
	size_t raw_payload_len = packet.payload_len;

	if (raw_payload == NULL) return MNL_CB_ERROR;

	const struct iphdr *ip_header = (const void *)raw_payload;

	if (ip_header->version != IPPROTO_IPIP || ip_header->protocol != IPPROTO_TCP) 
		goto fallback;

	int iph_len = ip_header->ihl * 4;

	const struct tcphdr *tcph = (const void *)(raw_payload + iph_len);
	if ((const uint8_t *)tcph + 20 > raw_payload + raw_payload_len) {
		printf("LZ\n");
		goto fallback;
	}

	int tcph_len = tcph->doff * 4;
	if ((const uint8_t *)tcph + tcph_len > raw_payload + raw_payload_len) {
		printf("LZ\n");
		goto fallback;
	}

	int data_len = ntohs(ip_header->tot_len) - iph_len - tcph_len;
	const uint8_t *data = (const uint8_t *)(raw_payload + iph_len + tcph_len);

	struct verdict vrd = analyze_tls_data(data, data_len);

	verdnlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, qdata.queue_num);
        nfq_nlmsg_verdict_put(verdnlh, packet.id, NF_ACCEPT);

	if (vrd.gvideo_hello) {
#ifdef DEBUG
		printf("Google video!\n");
#endif

		if (data_len > 1480) {
#ifdef DEBUG
			fprintf(stderr, "WARNING! Google video packet is too big and may cause issues!\n");
#endif
		}
		
		uint8_t frag1[MNL_SOCKET_BUFFER_SIZE];
		uint8_t frag2[MNL_SOCKET_BUFFER_SIZE];
		uint32_t f1len = MNL_SOCKET_BUFFER_SIZE;
		uint32_t f2len = MNL_SOCKET_BUFFER_SIZE;
		nfq_nlmsg_verdict_put(verdnlh, packet.id, NF_DROP);


#ifdef USE_TCP_SEGMENTATION
		size_t ipd_offset = vrd.sni_offset;
		size_t mid_offset = ipd_offset + vrd.sni_len / 2;

		if ((errno = tcp4_frag(raw_payload, raw_payload_len, 
			 mid_offset, frag1, &f1len, frag2, &f2len)) < 0) {
			errno *= -1;
			perror("tcp4_frag");
			goto fallback;
		}

		if ((send_raw_socket(frag2, f2len) < 0) || 
			(send_raw_socket(frag1, f1len) < 0)) {
			perror("raw frags send");
		}

#else
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

#endif

	}


/*       
	if (pktb_mangled(pktb)) {
#ifdef DEBUG
		printf("Mangled!\n");
#endif
		nfq_nlmsg_verdict_put_pkt(
			verdnlh, pktb_data(pktb), pktb_len(pktb));
	}
*/

        if (mnl_socket_sendto(*qdata._nl, verdnlh, verdnlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
		
		goto error;
        }
 
        return MNL_CB_OK;

fallback:
	return fallback_accept_packet(packet.id, qdata);
error:
	return MNL_CB_ERROR;
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
	
	struct queue_data *qdata = data;

	struct nfqnl_msg_packet_hdr *ph = NULL;
        struct nlattr *attr[NFQA_MAX+1] = {0};
	struct packet_data packet = {0};

        if (nfq_nlmsg_parse(nlh, attr) < 0) {
                perror("Attr parse");
                return MNL_CB_ERROR;
        }
 
        if (attr[NFQA_PACKET_HDR] == NULL) {
		errno = ENODATA;
                perror("Metaheader not set");
                return MNL_CB_ERROR;
        }

        ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

        packet.id = ntohl(ph->packet_id);
	packet.hw_proto = ntohs(ph->hw_protocol);
	packet.hook = ph->hook;
        packet.payload_len = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
        packet.payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

	if (attr[NFQA_CAP_LEN] != NULL && ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN])) != packet.payload_len) {
		fprintf(stderr, "The packet was truncated! Skip!\n");
		return fallback_accept_packet(packet.id, *qdata);
	}

	if (attr[NFQA_MARK] != NULL) {
		// Skip packets sent by rawsocket to escape infinity loop.
		if (ntohl(mnl_attr_get_u32(attr[NFQA_MARK])) == 
			RAWSOCKET_MARK) {
			return fallback_accept_packet(packet.id, *qdata);
		}
	}


	return process_packet(packet, *qdata);
}

#define BUF_SIZE (0xffff + (MNL_SOCKET_BUFFER_SIZE / 2))

int init_queue(int queue_num) {
	struct mnl_socket *nl;

	if (open_socket(&nl)) {
		perror("Unable to open socket");
		return -1;
	}

	uint32_t portid = mnl_socket_get_portid(nl);

	struct nlmsghdr *nlh;
	char buf[BUF_SIZE];

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		goto die;
	}

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

#ifdef USE_GSO
        mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
        mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
#endif

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
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

	printf("Queue %d started!\n", qdata.queue_num);

	while (1) {
		ret = mnl_socket_recvfrom(nl, buf, BUF_SIZE);
		if (ret == -1) {
			perror("mnl_socket_recvfrom");
			continue;
		}

		ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, &qdata);
		if (ret < 0) {
			perror("mnl_cb_run");
		}
	}


	close_socket(&nl);
	return 0;

die:
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

static struct queue_res threads_reses[MAX_THREADS];

void *init_queue_wrapper(void *qdconf) {
	struct queue_conf *qconf = qdconf;
	struct queue_res *thres = threads_reses + qconf->i;
	
	thres->status = init_queue(qconf->queue_num);

	fprintf(stderr, "Thread %d exited with status %d\n", qconf->i, thres->status);

	return thres;
}

int main(int argc, const char *argv[]) {
	if (parse_args(argc, argv)) {
		perror("Unable to parse args");
		exit(EXIT_FAILURE);
	}

#ifdef USE_TCP_SEGMENTATION
	printf("Using TCP segmentation!\n");
#else 
	printf("Using IP fragmentation!\n");
#endif 

#ifdef USE_GSO
	printf("GSO is enabled!\n");
#endif

	if (open_raw_socket() < 0) {
		perror("Unable to open raw socket");
		exit(EXIT_FAILURE);
	}

#if THREADS_NUM == 1
	struct queue_conf tconf = {
		.i = 0,
		.queue_num = config.queue_start_num
	};

	struct queue_res *qres = init_queue_wrapper(&tconf);
#else
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

		struct queue_res *qres = res;
	}
#endif

	if (close_raw_socket() < 0) {
		perror("Unable to close raw socket");
		exit(EXIT_FAILURE);
	}

	return qres->status;
}

