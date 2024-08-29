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

#include "config.h"
#include "mangle.h"
#include "args.h"
#include "utils.h"
#include "logging.h"

pthread_mutex_t rawsocket_lock;
int rawsocket = -2;

pthread_mutex_t raw6socket_lock;
int raw6socket = -2;

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
	if (rawsocket != -2) {
		errno = EALREADY;
		perror("Raw socket is already opened");
		return -1;
	}
	
	rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rawsocket == -1) {
		perror("Unable to create raw socket");
		return -1;
	}

	int mark = config.mark;
	if (setsockopt(rawsocket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
	{
		fprintf(stderr, "setsockopt(SO_MARK, %d) failed\n", mark);
		return -1;
	}

	int mst = pthread_mutex_init(&rawsocket_lock, NULL);
	if (mst) {
		fprintf(stderr, "Mutex err: %d\n", mst);
		close(rawsocket);
		errno = mst;

		return -1;
	}


	return rawsocket;
}

static int close_raw_socket(void) {
	if (rawsocket < 0) {
		errno = EALREADY;
		perror("Raw socket is not set");
		return -1;
	}

	if (close(rawsocket)) {
		perror("Unable to close raw socket");
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
		perror("Raw socket is already opened");
		return -1;
	}
	
	raw6socket = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (rawsocket == -1) {
		perror("Unable to create raw socket");
		return -1;
	}

	int mark = config.mark;
	if (setsockopt(raw6socket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
	{
		fprintf(stderr, "setsockopt(SO_MARK, %d) failed\n", mark);
		return -1;
	}

	int mst = pthread_mutex_init(&raw6socket_lock, NULL);
	if (mst) {
		fprintf(stderr, "Mutex err: %d\n", mst);
		close(raw6socket);
		errno = mst;

		return -1;
	}


	return raw6socket;
}

static int close_raw6_socket(void) {
	if (raw6socket < 0) {
		errno = EALREADY;
		perror("Raw socket is not set");
		return -1;
	}

	if (close(raw6socket)) {
		perror("Unable to close raw socket");
		pthread_mutex_destroy(&rawsocket_lock);
		return -1;
	}

	pthread_mutex_destroy(&raw6socket_lock);

	raw6socket = -2;
	return 0;
}

static int send_raw_ipv4(const uint8_t *pkt, uint32_t pktlen) {
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

	if (config.threads != 1)
		pthread_mutex_lock(&rawsocket_lock);

	int sent = sendto(rawsocket, 
	    pkt, pktlen, 0, 
	    (struct sockaddr *)&daddr, sizeof(daddr));

	if (config.threads != 1)
		pthread_mutex_unlock(&rawsocket_lock);

	/* The function will return -errno on error as well as errno value set itself */
	if (sent < 0) sent = -errno;

	return sent;
}

static int send_raw_ipv6(const uint8_t *pkt, uint32_t pktlen) {
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

	tcp6_set_checksum((void *)(uint8_t *)pkt + sizeof(struct ip6_hdr), (void *)pkt);


	if (config.threads != 1)
		pthread_mutex_lock(&rawsocket_lock);

	int sent = sendto(raw6socket, 
	    pkt, pktlen, 0, 
	    (struct sockaddr *)&daddr, sizeof(daddr));

	lgtrace_addp("rawsocket sent %d", sent);

	if (config.threads != 1)
		pthread_mutex_unlock(&rawsocket_lock);

	/* The function will return -errno on error as well as errno value set itself */
	if (sent < 0) sent = -errno;

	return sent;
}

static int send_raw_socket(const uint8_t *pkt, uint32_t pktlen) {
	int ret;

	if (pktlen > AVAILABLE_MTU) {
		if (config.verbose)
			printf("Split packet!\n");

		uint8_t buff1[MNL_SOCKET_BUFFER_SIZE];
		uint32_t buff1_size = MNL_SOCKET_BUFFER_SIZE;
		uint8_t buff2[MNL_SOCKET_BUFFER_SIZE];
		uint32_t buff2_size = MNL_SOCKET_BUFFER_SIZE;

		switch (config.fragmentation_strategy) {
			case FRAG_STRAT_TCP:
				if ((ret = tcp_frag(pkt, pktlen, AVAILABLE_MTU-128,
					buff1, &buff1_size, buff2, &buff2_size)) < 0) {

					errno = -ret;
					return ret;
				}
				break;
			case FRAG_STRAT_IP:
				if ((ret = ip4_frag(pkt, pktlen, AVAILABLE_MTU-128,
					buff1, &buff1_size, buff2, &buff2_size)) < 0) {

					errno = -ret;
					return ret;
				}
				break;
			default:
				errno = EINVAL;
				printf("send_raw_socket: Packet is too big but fragmentation is disabled!\n");
				return -EINVAL;
		}

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
	
	int ipvx = netproto_version(pkt, pktlen);

	if (ipvx == IP4VERSION) 
		return send_raw_ipv4(pkt, pktlen);
	else if (ipvx == IP6VERSION) 
		return send_raw_ipv6(pkt, pktlen);

	printf("proto version %d is unsupported\n", ipvx);
	return -EINVAL;
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


struct dps_t {
	uint8_t *pkt;
	uint32_t pktlen;
	// Time for the packet in milliseconds
	uint32_t timer;
};
// Note that the thread will automatically release dps_t and pkt_buff
void *delay_packet_send_fn(void *data) {
	struct dps_t *dpdt = data;

	uint8_t *pkt = dpdt->pkt;
	uint32_t pktlen = dpdt->pktlen;

	usleep(dpdt->timer * 1000);
	int ret = send_raw_socket(pkt, pktlen);
	if (ret < 0) {
		errno = -ret;
		perror("send delayed raw packet");
	}

	free(pkt);
	free(dpdt);
	return NULL;
}

void delay_packet_send(const unsigned char *data, unsigned int data_len, unsigned int delay_ms) {
	struct dps_t *dpdt = malloc(sizeof(struct dps_t));
	dpdt->pkt = malloc(data_len);
	memcpy(dpdt->pkt, data, data_len);
	dpdt->pktlen = data_len;
	dpdt->timer = delay_ms;
	pthread_t thr;
	pthread_create(&thr, NULL, delay_packet_send_fn, dpdt);
	pthread_detach(thr);
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	
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
		if ((ntohl(mnl_attr_get_u32(attr[NFQA_MARK])) & config.mark) == 
			config.mark) {
			return fallback_accept_packet(packet.id, *qdata);
		}
	}


	struct nlmsghdr *verdnlh;
	verdnlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, qdata->queue_num);

	int ret = process_packet(packet.payload, packet.payload_len);

	switch (ret) {
		case PKT_DROP:
			nfq_nlmsg_verdict_put(verdnlh, packet.id, NF_DROP);
			break;
		default:
			nfq_nlmsg_verdict_put(verdnlh, packet.id, NF_ACCEPT);
			break;
	}

        if (mnl_socket_sendto(*qdata->_nl, verdnlh, verdnlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                return MNL_CB_ERROR;
        }
	
	return MNL_CB_OK;
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

	if (config.use_gso) {
		mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
		mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
	}

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

	printf("Queue %d started\n", qdata.queue_num);

	while (1) {
		ret = mnl_socket_recvfrom(nl, buf, BUF_SIZE);
		if (ret == -1) {
			perror("mnl_socket_recvfrom");
			goto die;
		}

		ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, &qdata);
		if (ret < 0) {
			lgerror("mnl_cb_run", -EPERM);
			if (errno == EPERM) {
				printf("Probably another instance of youtubeUnblock with the same queue number is running\n");
			} else {
				printf("Make sure the nfnetlink_queue kernel module is loaded\n");
			}
			goto die;
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
static struct queue_res defqres = {0};

static struct queue_res threads_reses[MAX_THREADS];

void *init_queue_wrapper(void *qdconf) {
	struct queue_conf *qconf = qdconf;
	struct queue_res *thres = threads_reses + qconf->i;
	
	thres->status = init_queue(qconf->queue_num);

	fprintf(stderr, "Thread %d exited with status %d\n", qconf->i, thres->status);

	return thres;
}

struct instance_config_t instance_config = {
	.send_raw_packet = send_raw_socket,
	.send_delayed_packet = delay_packet_send,
};

int main(int argc, char *argv[]) {
	int ret;
	if ((ret = parse_args(argc, argv)) != 0) {
		if (ret < 0) {
			perror("Unable to parse args");
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	print_version();
	print_welcome();

	if (open_raw_socket() < 0) {
		perror("Unable to open raw socket");
		exit(EXIT_FAILURE);
	}

	if (config.use_ipv6) {
		if (open_raw6_socket() < 0) {
			perror("Unable to open raw socket for ipv6");
			close_raw_socket();
			exit(EXIT_FAILURE);
		}
	}

	struct queue_res *qres = &defqres;

	if (config.threads == 1) {
		struct queue_conf tconf = {
			.i = 0,
			.queue_num = config.queue_start_num
		};

		qres = init_queue_wrapper(&tconf);
	} else {
		printf("%d threads wil be used\n", config.threads);

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

