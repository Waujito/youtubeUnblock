/* This example is placed in the public domain. */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <net/if.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifm;
	uint32_t seq, portid;
	union {
		in_addr_t ip;
		struct in6_addr ip6;
	} addr;
	int ret, family = AF_INET;

	uint32_t prefix;
	int iface;


	if (argc <= 3) {
		printf("Usage: %s iface destination cidr\n", argv[0]);
		printf("Example: %s eth0 10.0.1.12 32\n", argv[0]);
		printf("	 %s eth0 ffff::10.0.1.12 128\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	iface = if_nametoindex(argv[1]);
	if (iface == 0) {
		perror("if_nametoindex");
		exit(EXIT_FAILURE);
	}

	if (!inet_pton(AF_INET, argv[2], &addr)) {
		if (!inet_pton(AF_INET6, argv[2], &addr)) {
			perror("inet_pton");
			exit(EXIT_FAILURE);
		}
		family = AF_INET6;
	}

	if (sscanf(argv[3], "%u", &prefix) == 0) {
		perror("sscanf");
		exit(EXIT_FAILURE);
	}

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_NEWADDR;

	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));

	ifm->ifa_family = family;
	ifm->ifa_prefixlen = prefix;
	ifm->ifa_flags = IFA_F_PERMANENT;

	ifm->ifa_scope = RT_SCOPE_UNIVERSE;
	ifm->ifa_index = iface;

	/*
	 * The exact meaning of IFA_LOCAL and IFA_ADDRESS depend
	 * on the address family being used and the device type.
	 * For broadcast devices (like the interfaces we use),
	 * for IPv4 we specify both and they are used interchangeably.
	 * For IPv6, only IFA_ADDRESS needs to be set.
	 */
	if (family == AF_INET) {
		mnl_attr_put_u32(nlh, IFA_LOCAL, addr.ip);
		mnl_attr_put_u32(nlh, IFA_ADDRESS, addr.ip);
	} else {
		mnl_attr_put(nlh, IFA_ADDRESS, sizeof(struct in6_addr), &addr);
	}

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
	if (ret < 0) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret < 0) {
		perror("mnl_cb_run");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return 0;
}
