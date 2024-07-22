#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

/* NFQA_CT requires CTA_* attributes defined in nfnetlink_conntrack.h */
#include <linux/netfilter/nfnetlink_conntrack.h>

static struct mnl_socket *nl;

static void
nfq_send_verdict(int queue_num, uint32_t id)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nlattr *nest;

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
	nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

	/* example to set the connmark. First, start NFQA_CT section: */
	nest = mnl_attr_nest_start(nlh, NFQA_CT);

	/* then, add the connmark attribute: */
	mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
	/* more conntrack attributes, e.g. CTA_LABELS could be set here */

	/* end conntrack section */
	mnl_attr_nest_end(nlh, nest);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfqnl_msg_packet_hdr *ph = NULL;
	struct nlattr *attr[NFQA_MAX+1] = {};
	uint32_t id = 0, skbinfo;
	struct nfgenmsg *nfg;
	uint16_t plen;

	/* Parse netlink message received from the kernel, the array of
	 * attributes is set up to store metadata and the actual packet.
	 */
	if (nfq_nlmsg_parse(nlh, attr) < 0) {
		perror("problems parsing");
		return MNL_CB_ERROR;
	}

	nfg = mnl_nlmsg_get_payload(nlh);

	if (attr[NFQA_PACKET_HDR] == NULL) {
		fputs("metaheader not set\n", stderr);
		return MNL_CB_ERROR;
	}

	/* Access packet metadata, which provides unique packet ID, hook number
	 * and ethertype. See struct nfqnl_msg_packet_hdr for details.
	 */
	ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

	/* Access actual packet data length. */
	plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

	/* Access actual packet data */
	/* void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]); */

	/* Fetch metadata flags, possible flags values are:
	 *
	 * - NFQA_SKB_CSUMNOTREADY:
	 *	Kernel performed partial checksum validation, see CHECKSUM_PARTIAL.
	 * - NFQA_SKB_CSUM_NOTVERIFIED:
	 *	Kernel already verified checksum.
	 * - NFQA_SKB_GSO:
	 *	Not the original packet received from the wire. Kernel has
	 *	aggregated several packets into one single packet via GSO.
	 */
	skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

	/* Kernel has truncated the packet, fetch original packet length. */
	if (attr[NFQA_CAP_LEN]) {
		uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
		if (orig_len != plen)
			printf("truncated ");
	}

	if (skbinfo & NFQA_SKB_GSO)
		printf("GSO ");

	id = ntohl(ph->packet_id);
	printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u",
		id, ntohs(ph->hw_protocol), ph->hook, plen);

	/* Fetch ethernet destination address. */
	if (attr[NFQA_HWADDR]) {
		struct nfqnl_msg_packet_hw *hw = mnl_attr_get_payload(attr[NFQA_HWADDR]);
		unsigned int hwlen = ntohs(hw->hw_addrlen);
		const unsigned char *addr = hw->hw_addr;
		unsigned int i;

		printf(", hwaddr %02x", addr[0]);
		for (i = 1; i < hwlen; i++) {
			if (i >= sizeof(hw->hw_addr)) {
				printf("[truncated]");
				break;
			}
			printf(":%02x", (unsigned char)addr[i]);
		}

		printf(" len %u", hwlen);
	}

	/*
	 * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
	 * The application should behave as if the checksums are correct.
	 *
	 * If these packets are later forwarded/sent out, the checksums will
	 * be corrected by kernel/hardware.
	 */
	if (skbinfo & NFQA_SKB_CSUMNOTREADY)
		printf(", checksum not ready");
	puts(")");

	nfq_send_verdict(ntohs(nfg->res_id), id);

	return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
	char *buf;
	/* largest possible packet payload, plus netlink data overhead: */
	size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
	struct nlmsghdr *nlh;
	int ret;
	unsigned int portid, queue_num;

	if (argc != 2) {
		printf("Usage: %s [queue_num]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	queue_num = atoi(argv[1]);

	/*
	 * Set up netlink socket to communicate with the netfilter subsystem.
	 */
	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	buf = malloc(sizeof_buf);
	if (!buf) {
		perror("allocate receive buffer");
		exit(EXIT_FAILURE);
	}

	/* Configure the pipeline between kernel and userspace, build and send
	 * a netlink message to specify queue number to bind to. Your ruleset
	 * has to use this queue number to deliver packets to userspace.
	 */
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	/* Build and send a netlink message to specify how many bytes are
	 * copied from kernel to userspace for this queue.
	 */
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	/* ENOBUFS is signalled to userspace when packets were lost
	 * on kernel side.  In most cases, userspace isn't interested
	 * in this information, so turn it off.
	 */
	ret = 1;
	mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

	/* Loop forever on packets received from the kernel and run the
	 * callback handler.
	 */
	for (;;) {
		ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
		if (ret == -1) {
			perror("mnl_socket_recvfrom");
			exit(EXIT_FAILURE);
		}

		ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
		if (ret < 0){
			perror("mnl_cb_run");
			exit(EXIT_FAILURE);
		}
	}

	mnl_socket_close(nl);

	return 0;
}
