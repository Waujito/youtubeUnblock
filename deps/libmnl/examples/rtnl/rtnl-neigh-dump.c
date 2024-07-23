/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NDA_DST:
	case NDA_LLADDR:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[NDA_MAX + 1] = {};
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

	printf("index=%d family=%d ", ndm->ndm_ifindex, ndm->ndm_family);

	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_cb, tb);
	printf("dst=");
	if (tb[NDA_DST]) {
		void *addr = mnl_attr_get_payload(tb[NDA_DST]);
		char out[INET6_ADDRSTRLEN];

		if (inet_ntop(ndm->ndm_family, addr, out, sizeof(out)))
			printf("%s ", out);
	}

	mnl_attr_parse(nlh, sizeof(*ndm), data_attr_cb, tb);
	printf("lladdr=");
	if (tb[NDA_LLADDR]) {
		void *addr = mnl_attr_get_payload(tb[NDA_LLADDR]);
		unsigned char lladdr[6] = {0};

		if (memcpy(&lladdr, addr, 6))
			printf("%02x:%02x:%02x:%02x:%02x:%02x ",
			       lladdr[0], lladdr[1], lladdr[2],
			       lladdr[3], lladdr[4], lladdr[5]);
	}

	printf("state=");
	switch(ndm->ndm_state) {
	case NUD_INCOMPLETE:
		printf("incomplete ");
		break;
	case NUD_REACHABLE:
		printf("reachable ");
		break;
	case NUD_STALE:
		printf("stale ");
		break;
	case NUD_DELAY:
		printf("delay ");
		break;
	case NUD_PROBE:
		printf("probe ");
		break;
	case NUD_FAILED:
		printf("failed ");
		break;
	case NUD_NOARP:
		printf("noarp ");
		break;
	case NUD_PERMANENT:
		printf("permanent ");
		break;
	default:
		printf("%d ", ndm->ndm_state);
		break;
	}

	printf("\n");
	return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
	char buf[MNL_SOCKET_DUMP_SIZE];
	unsigned int seq, portid;
	struct mnl_socket *nl;
	struct nlmsghdr *nlh;
	struct ndmsg *nd;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <inet|inet6>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_GETNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);

	nd = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
	if (strcmp(argv[1], "inet") == 0)
		nd->ndm_family = AF_INET;
	else if (strcmp(argv[1], "inet6") == 0)
		nd->ndm_family = AF_INET6;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, data_cb, NULL);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return 0;
}
