#define _GNU_SOURCE
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

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

#include "raw_replacements.h"

#ifndef NOUSE_GSO
#define USE_GSO
#endif

#ifndef USE_IP_FRAGMENTATION
#define USE_TCP_SEGMENTATION
#endif

#define RAWSOCKET_MARK 0xfc70

#ifdef USE_SEG2_DELAY
#define SEG2_DELAY 100
#endif

#ifndef NO_FAKE_SNI
#define FAKE_SNI
#endif


static struct {
	uint32_t queue_num;
	struct mnl_socket *nl;
	uint32_t portid;
	int rawsocket;

} config = {
	.rawsocket = -2
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

	config.queue_num = queue_num;
	return 0;

errormsg_help:
	err = errno;
	printf("Usage: %s [queue_num]\n", argv[0]);
	errno = err;
	if (errno == 0) errno = EINVAL;

	return -1;
}

static int open_socket(void) {
	if (config.nl != NULL) {
		errno = EALREADY;
		perror("socket is already opened");
		return -1;
	}

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

	config.nl = nl;
	config.portid = mnl_socket_get_portid(nl);

	return 0;
}


static int close_socket(void) {
	if (config.nl == NULL) return 1;
	if (mnl_socket_close(config.nl) < 0) {
		perror("mnl_socket_close");
		return -1;
	}

	config.nl = NULL;

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
		printf("setsockopt(IP_HDRINCL, 1) failed\n");
		return -1;
	}

	int mark = RAWSOCKET_MARK;
	if (setsockopt(config.rawsocket, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
	{
		printf("setsockopt(SO_MARK, %d) failed\n", mark);
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
		return -1;
	}

	config.rawsocket = -2;
	return 0;
}

// split packet to two ipv4 fragments.
static int ipv4_frag(struct pkt_buff *pktb, size_t payload_offset,
		     struct pkt_buff **frag1, struct pkt_buff **frag2) {
	uint8_t buff1[MNL_SOCKET_BUFFER_SIZE];
	uint8_t buff2[MNL_SOCKET_BUFFER_SIZE];

	struct iphdr *hdr = nfq_ip_get_hdr(pktb);
	size_t hdr_len = hdr->ihl * 4;

	uint8_t *payload = pktb_data(pktb) + hdr_len;
	size_t plen = pktb_len(pktb) - hdr_len;

	if (hdr == NULL || payload == NULL || plen <= payload_offset) {
		errno = EINVAL;
		return -1;
	}

	if (payload_offset & ((1 << 3) - 1)) {
		fprintf(stderr, "Payload offset MUST be a multiply of 8!\n");
		errno = EINVAL;
		return -1;
	}

	size_t f1_plen = payload_offset;
	size_t f1_dlen = f1_plen + hdr_len;

	size_t f2_plen = plen - payload_offset;
	size_t f2_dlen = f2_plen + hdr_len;

	memcpy(buff1, hdr, hdr_len);
	memcpy(buff2, hdr, hdr_len);

	memcpy(buff1 + hdr_len, payload, f1_plen);
	memcpy(buff2 + hdr_len, payload + payload_offset, f2_plen);

	struct iphdr *f1_hdr = (void *)buff1;
	struct iphdr *f2_hdr = (void *)buff2;

	uint16_t f1_frag_off = ntohs(f1_hdr->frag_off);
	uint16_t f2_frag_off = ntohs(f2_hdr->frag_off);

	f1_frag_off &= IP_OFFMASK;
	f1_frag_off |= IP_MF;
	
	if ((f2_frag_off & ~IP_OFFMASK) == IP_MF) {
		f2_frag_off &= IP_OFFMASK;
		f2_frag_off |= IP_MF;
	} else {
		f2_frag_off &= IP_OFFMASK;
	}
	
	f2_frag_off += (uint16_t)payload_offset / 8;

	f1_hdr->frag_off = htons(f1_frag_off);
	f1_hdr->tot_len = htons(f1_dlen);

	f2_hdr->frag_off = htons(f2_frag_off);
	f2_hdr->tot_len = htons(f2_dlen);


#ifdef DEBUG
	printf("Packet split in portion %zu %zu\n", f1_dlen, f2_dlen);
#endif

	nfq_ip_set_checksum(f1_hdr);
	nfq_ip_set_checksum(f2_hdr);

	*frag1 = pktb_alloc(AF_INET, buff1, f1_dlen, 0);
	if (*frag1 == NULL) 
		return -1;

	*frag2 = pktb_alloc(AF_INET, buff2, f2_dlen, 0);
	if (*frag2 == NULL) {
		pktb_free(*frag1);
		return -1;
	}

	return 0;
}

// split packet to two tcp-on-ipv4 segments.
static int tcp4_frag(struct pkt_buff *pktb, size_t payload_offset,
		     struct pkt_buff **seg1, struct pkt_buff **seg2) {
	uint8_t buff1[MNL_SOCKET_BUFFER_SIZE];
	uint8_t buff2[MNL_SOCKET_BUFFER_SIZE];

	struct iphdr *hdr = nfq_ip_get_hdr(pktb);
	size_t hdr_len = hdr->ihl * 4;
	if (hdr == NULL) {errno = EINVAL; return -1;}
	if (hdr->protocol != IPPROTO_TCP || !(ntohs(hdr->frag_off) & IP_DF)) {
		errno = EINVAL;
		return -1;
	}

	if (nfq_ip_set_transport_header(pktb, hdr)) 
		return -1;
	
	struct tcphdr *tcph = nfq_tcp_get_hdr(pktb);
	size_t tcph_len = tcph->doff * 4;
	if (tcph == NULL) {
		errno = EINVAL;
		return -1;
	}

	uint8_t *payload = nfq_tcp_get_payload(tcph, pktb);
	size_t plen = nfq_tcp_get_payload_len(tcph, pktb);

	if (hdr == NULL || payload == NULL || plen <= payload_offset) {
		errno = EINVAL;
		return -1;
	}

	size_t s1_plen = payload_offset;
	size_t s1_dlen = s1_plen + hdr_len + tcph_len;

	size_t s2_plen = plen - payload_offset;
	size_t s2_dlen = s2_plen + hdr_len + tcph_len;

	memcpy(buff1, hdr, hdr_len);
	memcpy(buff2, hdr, hdr_len);

	memcpy(buff1 + hdr_len, tcph, tcph_len);
	memcpy(buff2 + hdr_len, tcph, tcph_len);

	memcpy(buff1 + hdr_len + tcph_len, payload, s1_plen);
	memcpy(buff2 + hdr_len + tcph_len, payload + payload_offset, s2_plen);

	struct iphdr *s1_hdr = (void *)buff1;
	struct iphdr *s2_hdr = (void *)buff2;

	struct tcphdr *s1_tcph = (void *)(buff1 + hdr_len);
	struct tcphdr *s2_tcph = (void *)(buff2 + hdr_len);

	s1_hdr->tot_len = htons(s1_dlen);
	s2_hdr->tot_len = htons(s2_dlen);

	// s2_hdr->id = htons(ntohs(s1_hdr->id) + 1);
	s2_tcph->seq = htonl(ntohl(s2_tcph->seq) + payload_offset);
	// printf("%zu %du %du\n", payload_offset, ntohs(s1_tcph->seq), ntohs(s2_tcph->seq));
	
#ifdef DEBUG
	printf("Packet split in portion %zu %zu\n", s1_dlen, s2_dlen);
#endif

	nfq_tcp_compute_checksum_ipv4(s1_tcph, s1_hdr);
	nfq_tcp_compute_checksum_ipv4(s2_tcph, s2_hdr);

	*seg1 = pktb_alloc(AF_INET, buff1, s1_dlen, 0);
	if (*seg1 == NULL) 
		return -1;

	*seg2 = pktb_alloc(AF_INET, buff2, s2_dlen, 0);
	if (*seg2 == NULL) {
		pktb_free(*seg1);
		return -1;
	}


	return 0;
}

#define AVAILABLE_MTU 1384

static int send_raw_socket(struct pkt_buff *pktb) {
	if (pktb_len(pktb) > AVAILABLE_MTU) {
#ifdef DEBUG
		printf("Split packet!\n");
#endif

		struct pkt_buff *buff1;
		struct pkt_buff *buff2;

#ifdef USE_TCP_SEGMENTATION
		if (tcp4_frag(pktb, AVAILABLE_MTU-128, &buff1, &buff2) < 0)
			return -1;
#else
		if (ipv4_frag(pktb, AVAILABLE_MTU-128, &buff1, &buff2) < 0)
			return -1;

#endif

		int sent = 0;
		int status = send_raw_socket(buff1);

		if (status >= 0) sent += status;
		else {
			pktb_free(buff1);
			pktb_free(buff2);
			return status;
		}
		pktb_free(buff1);

		status = send_raw_socket(buff2);
		if (status >= 0) sent += status;
		else {
			pktb_free(buff2);
			return status;
		}
		pktb_free(buff2);

		return sent;
	}

	struct iphdr *iph = nfq_ip_get_hdr(pktb);
	if (iph == NULL)
		return -1;

	if(nfq_ip_set_transport_header(pktb, iph))
		return -1;

	int sin_port = 0;

	struct tcphdr *tcph = nfq_tcp_get_hdr(pktb);
	struct udphdr *udph = nfq_udp_get_hdr(pktb);

	if (tcph != NULL) {
		sin_port = tcph->dest;
		errno = 0;
	} else if (udph != NULL) {
		sin_port = udph->dest;
	} else {
		return -1;
	}

	struct sockaddr_in daddr = {
		.sin_family = AF_INET,
		.sin_port = sin_port,
		.sin_addr = {
			.s_addr = iph->daddr
		}
	};

	int sent = sendto(config.rawsocket, 
	    pktb_data(pktb), pktb_len(pktb), 0, 
	    (struct sockaddr *)&daddr, sizeof(daddr));
	return sent;
}

struct packet_data {
	uint32_t id;
	uint16_t hw_proto;
	uint8_t hook;
	
	void *payload;
	uint16_t payload_len;
};

/**
 * Used to accept unsupported packets (GSOs)
 */
static int fallback_accept_packet(uint32_t id) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *verdnlh;
        verdnlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, config.queue_num);
        nfq_nlmsg_verdict_put(verdnlh, id, NF_ACCEPT);

        if (mnl_socket_sendto(config.nl, verdnlh, verdnlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
                return MNL_CB_ERROR;
        }

        return MNL_CB_OK;
}

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_EXTENSION_SNI 0x0000
#define TLS_EXTENSION_CLIENT_HELLO_ENCRYPTED 0xfe0d

const char googlevideo_ending[] = "googlevideo.com";
const int googlevideo_len = 15;

#define GOOGLEVIDEO_MARK 0xfc74

struct verdict {
	int gvideo_hello; /* google video hello packet */
	int sni_offset; /* offset from start of tcp _payload_ */
	int sni_len;
};

/**
 * Processes tls payload of the tcp request.
 * 
 * data Payload data of TCP.
 * dlen Length of `data`.
 */
static struct verdict analyze_tls_data(
	const uint8_t *data, 
	uint32_t dlen) 
{
	struct verdict vrd = {0};

	size_t i = 0;
	const uint8_t *data_end = data + dlen;

	while (i + 4 < dlen) {
		const uint8_t *msgData = data + i;

		uint8_t tls_content_type = *msgData;
		uint8_t tls_vmajor = *(msgData + 1);
		uint8_t tls_vminor = *(msgData + 2);
		uint16_t message_length = ntohs(*(uint16_t *)(msgData + 3));
		const uint8_t *message_length_ptr = msgData + 3;


		if (i + 5 + message_length > dlen) break;

		if (tls_content_type != TLS_CONTENT_TYPE_HANDSHAKE) 
			goto nextMessage;


		const uint8_t *handshakeProto = msgData + 5;

		if (handshakeProto + 1 >= data_end) break;

		uint8_t handshakeType = *handshakeProto;

		if (handshakeType != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
			goto nextMessage;

		const uint8_t *msgPtr = handshakeProto;
		msgPtr += 1; 
		const uint8_t *handshakeProto_length_ptr = msgPtr + 1;
		msgPtr += 3 + 2 + 32;

		if (msgPtr + 1 >= data_end) break;
		uint8_t sessionIdLength = *msgPtr;
		msgPtr++;
		msgPtr += sessionIdLength;

		if (msgPtr + 2 >= data_end) break;
		uint16_t ciphersLength = ntohs(*(uint16_t *)msgPtr);
		msgPtr += 2;
		msgPtr += ciphersLength;

		if (msgPtr + 1 >= data_end) break;
		uint8_t compMethodsLen = *msgPtr;
		msgPtr++;
		msgPtr += compMethodsLen;

		if (msgPtr + 2 >= data_end) break;
		uint16_t extensionsLen = ntohs(*(uint16_t *)msgPtr);
		const uint8_t *extensionsLen_ptr = msgPtr;
		msgPtr += 2;

		const uint8_t *extensionsPtr = msgPtr;
		const uint8_t *extensions_end = extensionsPtr + extensionsLen;
		if (extensions_end > data_end) break;

		while (extensionsPtr < extensions_end) {
			const uint8_t *extensionPtr = extensionsPtr;
			if (extensionPtr + 4 >= extensions_end) break;

			uint16_t extensionType = 
				ntohs(*(uint16_t *)extensionPtr);
			extensionPtr += 2;

			uint16_t extensionLen = 
				ntohs(*(uint16_t *)extensionPtr);
			const uint8_t *extensionLen_ptr = extensionPtr;
			extensionPtr += 2;


			if (extensionPtr + extensionLen > extensions_end) 
				break;

			if (extensionType != TLS_EXTENSION_SNI) 
				goto nextExtension;

			const uint8_t *sni_ext_ptr = extensionPtr;

			if (sni_ext_ptr + 2 >= extensions_end) break;
			uint16_t sni_ext_dlen = ntohs(*(uint16_t *)sni_ext_ptr);

			const uint8_t *sni_ext_dlen_ptr = sni_ext_ptr;
			sni_ext_ptr += 2;

			const uint8_t *sni_ext_end = sni_ext_ptr + sni_ext_dlen;
			if (sni_ext_end >= extensions_end) break;
			
			if (sni_ext_ptr + 3 >= sni_ext_end) break;
			uint8_t sni_type = *sni_ext_ptr++;
			uint16_t sni_len = ntohs(*(uint16_t *)sni_ext_ptr);
			sni_ext_ptr += 2;

			if (sni_ext_ptr + sni_len > sni_ext_end) break;

			char *sni_name = (char *)sni_ext_ptr;
			// sni_len

			vrd.sni_offset = (uint8_t *)sni_name - data;
			vrd.sni_len = sni_len;

			char *gv_startp = sni_name + sni_len - googlevideo_len;
			if (sni_len >= googlevideo_len &&
				sni_len < 128 && 
				!strncmp(gv_startp, 
				googlevideo_ending, 
				googlevideo_len)) {

				vrd.gvideo_hello = 1;
			}

nextExtension:
			extensionsPtr += 2 + 2 + extensionLen;
		}
nextMessage:
		i += 5 + message_length;
	}

	return vrd;
}

static struct pkt_buff *gen_fake_sni(const struct iphdr *iph, const struct tcphdr *tcph) {
	int ip_len = iph->ihl * 4;
	int tcp_len = tcph->doff * 4;

	size_t pkt_size = ip_len + sizeof(fake_sni);
	struct pkt_buff *pkt = pktb_alloc(AF_INET, NULL, 0, pkt_size);
	if (pkt == NULL) return NULL;

	pktb_mangle(pkt, 0, 0, 0, (const char *)iph, ip_len);
	pktb_mangle(pkt, ip_len, 0, 0, fake_sni, sizeof(fake_sni));

	int ret = 0;
	struct iphdr *niph = nfq_ip_get_hdr(pkt);
	if (!niph) {
		perror("gen_fake_sni: ip header is null");
		goto err;
	}

	niph->protocol = IPPROTO_TCP;
	niph->tot_len = htons(pkt_size);

	ret = nfq_ip_set_transport_header(pkt, niph);
	if (ret < 0) {
		perror("gen_fake_sni: set transport header");
		goto err;
	}

	struct tcphdr *ntcph = nfq_tcp_get_hdr(pkt);
	if (!ntcph) { 
		perror("gen_fake_sni: nfq_tcp_get_hdr");
		goto err;
	}

	ntcph->th_dport = tcph->th_dport;
	ntcph->th_sport = tcph->th_sport;
	nfq_ip_set_checksum(niph);
	nfq_tcp_compute_checksum_ipv4(ntcph, niph);

	return pkt;
err:
	pktb_free(pkt);
	return NULL;

}
struct dps_t {
	struct pkt_buff *pkt;
	// Time for the packet in milliseconds
	uint32_t timer;
};
// Note that the thread will automatically release dps_t and pkt_buff
void *delay_packet_send(void *data) {
	struct dps_t *dpdt = data;
	struct pkt_buff *pkt = dpdt->pkt;

	usleep(dpdt->timer * 1000);
	send_raw_socket(pkt);

	pktb_free(pkt);
	free(dpdt);
	return NULL;
}
		     
static int process_packet(const struct packet_data packet) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *verdnlh;

#ifdef DEBUG_LOGGING
        printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u)\n",
	       packet.id, packet.hw_proto, packet.hook, packet.payload_len);
#endif

	if (packet.hw_proto != ETH_P_IP) {
		return fallback_accept_packet(packet.id);
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

	verdnlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, config.queue_num);
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
		
		struct pkt_buff *frag1;
		struct pkt_buff *frag2;
		nfq_nlmsg_verdict_put(verdnlh, packet.id, NF_DROP);


#ifdef USE_TCP_SEGMENTATION
		struct pkt_buff *fake_sni = gen_fake_sni(ip_header, tcph);
		if (fake_sni == NULL) goto fallback;

		int ret = 0;
#ifdef FAKE_SNI
		ret = send_raw_socket(fake_sni);
#endif
		if (ret < 0) {
			perror("send fake sni\n");
			pktb_free(fake_sni);
			goto fallback;
		}

		size_t ipd_offset = vrd.sni_offset;
		size_t mid_offset = ipd_offset + vrd.sni_len / 2;

		struct pkt_buff *pktb = pktb_alloc(
			family,
			packet.payload,
			packet.payload_len,
			0);

		if (pktb == NULL) {
			perror("pktb_alloc of payload");
			pktb_free(fake_sni);
			goto fallback;
		}
		
		if (tcp4_frag(pktb, mid_offset, &frag1, &frag2) < 0) {
			perror("tcp4_frag");
			pktb_free(pktb);
			pktb_free(fake_sni);
			goto fallback;
		}

		ret = send_raw_socket(frag2);
		if (ret < 0) {
			errno = ret;
			perror("raw frags send: frag2");
			pktb_free(frag1);
			goto err;
		}
		
#ifdef SEG2_DELAY
		struct dps_t *dpdt = malloc(sizeof(struct dps_t));
		dpdt->pkt = frag1;
		dpdt->timer = SEG2_DELAY;
		pthread_t thr;
		pthread_create(&thr, NULL, delay_packet_send, dpdt); 
		pthread_detach(thr);
#else
		ret = send_raw_socket(frag1);
		if (ret < 0) {
			errno = ret;
			perror("raw frags send: frag1");
			pktb_free(frag1);
			goto err;
		}
		pktb_free(frag1);
#endif
err:
		pktb_free(frag2);
		pktb_free(pktb);
		pktb_free(fake_sni);

#else
		// TODO: Implement compute of tcp checksum
		// GSO may turn kernel to not compute the tcp checksum.
		// Also it will never be meaningless to ensure the 
		// checksum is right.
		// nfq_tcp_compute_checksum_ipv4(tcph, ip_header);

		size_t ipd_offset = ((char *)data - (char *)tcph) + vrd.sni_offset;
		size_t mid_offset = ipd_offset + vrd.sni_len / 2;
		mid_offset += 8 - mid_offset % 8;
		

		if (ipv4_frag(pktb, mid_offset, &frag1, &frag2) < 0) {
			perror("ipv4_frag");
			goto fallback;
		}

		if ((send_raw_socket(frag1) == -1) || (send_raw_socket(frag2) == -1)) {
			perror("raw frags send");
		}

		pktb_free(frag1);
		pktb_free(frag2);
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

        if (mnl_socket_sendto(config.nl, verdnlh, verdnlh->nlmsg_len) < 0) {
                perror("mnl_socket_send");
		
		goto error;
        }
 
        return MNL_CB_OK;

fallback:
	return fallback_accept_packet(packet.id);
error:
	return MNL_CB_ERROR;
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
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
		return fallback_accept_packet(packet.id);
	}

	if (attr[NFQA_MARK] != NULL) {
		// Skip packets sent by rawsocket to escape infinity loop.
		if (ntohl(mnl_attr_get_u32(attr[NFQA_MARK])) == 
			RAWSOCKET_MARK) {
			return fallback_accept_packet(packet.id);
		}
	}


	return process_packet(packet);
}

int main(int argc, const char *argv[]) 
{

	if (parse_args(argc, argv)) {
		perror("Unable to parse args");
		exit(EXIT_FAILURE);
	}

#ifdef USE_TCP_SEGMENTATION
	printf("Using TCP segmentation\n");
#else 
	printf("Using IP fragmentation\n");
#endif 

#ifdef SEG2_DELAY
	printf("Some outgoing googlevideo request segments will be delayed for %d ms as of SEG2_DELAY define\n", SEG2_DELAY);
#endif 

#ifdef FAKE_SNI
	printf("Fake SNI will be sent before each googlevideo request\n");
#endif 

	if (open_socket()) {
		perror("Unable to open socket");
		exit(EXIT_FAILURE);
	}

	if (open_raw_socket() < 0) {
		perror("Unable to open raw socket");
		close_socket();
		exit(EXIT_FAILURE);
	}

	struct nlmsghdr *nlh;
	char *buf;
	size_t buf_size = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
	buf = malloc(buf_size);
	if (!buf) {
		perror("Allocate recieve buffer");
		goto die_sock;
	}


	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, config.queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(config.nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		goto die_buf;
	}

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, config.queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

#ifdef USE_GSO
	printf("GSO is enabled\n");

        mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
        mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
#endif

	if (mnl_socket_sendto(config.nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		goto die_buf;
	}

	/* ENOBUFS is signalled to userspace when packets were lost
          * on kernel side.  In most cases, userspace isn't interested
          * in this information, so turn it off.
          */
	int ret = 1;
	mnl_socket_setsockopt(config.nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

	while (1) {
		ret = mnl_socket_recvfrom(config.nl, buf, buf_size);
		if (ret == -1) {
			perror("mnl_socket_recvfrom");
			goto die_buf;
		}

		ret = mnl_cb_run(buf, ret, 0, config.portid, queue_cb, NULL);
		if (ret < 0) {
			perror("mnl_cb_run");
			// goto die_buf;
		}
	}


	printf("%d\n", config.queue_num);
	errno = 0;

	free(buf);
	close_socket();
	return 0;

die_buf:
	free(buf);
die_sock:
	close_raw_socket();
	close_socket();
	exit(EXIT_FAILURE);
}

