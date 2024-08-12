#ifndef YU_MANGLE_H
#define YU_MANGLE_H

#include "types.h"

#ifdef KERNEL_SPACE
#include <linux/string.h>
#include <linux/stddef.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <asm/byteorder.h>

/* from <netinet/ip.h> */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
#else
#define USER_SPACE
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

/**
 * Result of analyze_tls_data function
 */
struct tls_verdict {
	int target_sni; /* google video hello packet */
	int sni_offset; /* offset from start of tcp _payload_ */
	int sni_len;
};

/**
 * Processes the packet and finds TLS Client Hello information inside it.
 * data pointer points to start of TLS Message (TCP Payload)
 */
struct tls_verdict analyze_tls_data(const uint8_t *data, uint32_t dlen);

/**
 * Splits the packet to two IP fragments on position payload_offset.
 * payload_offset indicates the position relatively to start of IP payload
 * (start of transport header)
 */
int ip4_frag(const uint8_t *pkt, uint32_t pktlen, 
			uint32_t payload_offset, 
			uint8_t *frag1, uint32_t *f1len, 
			uint8_t *frag2, uint32_t *f2len);

/**
 * Splits the packet to two TCP segments on position payload_offset
 * payload_offset indicates the position relatively to start of TCP payload.
 */
int tcp4_frag(const uint8_t *pkt, uint32_t pktlen, 
			uint32_t payload_offset, 
			uint8_t *seg1, uint32_t *s1len, 
			uint8_t *seg2, uint32_t *s2len);

/**
 * Splits the raw packet payload to ip header and ip payload.
 */
int ip4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len, 
		       uint8_t **payload, uint32_t *plen);

/**
 * Splits the raw packet payload to ip header, tcp header and tcp payload.
 */
int tcp4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len,
		       struct tcphdr **tcph, uint32_t *tcph_len,
		       uint8_t **payload, uint32_t *plen);

void tcp4_set_checksum(struct tcphdr *tcph, struct iphdr *iph);
void ip4_set_checksum(struct iphdr *iph);

/**
 * Generates fake client hello message
 */
int gen_fake_sni(const struct iphdr *iph, const struct tcphdr *tcph, 
		 uint8_t *buf, uint32_t *buflen);

/**
 * Invalidates the raw packet. The function aims to invalid the packet
 * in such way as it will be accepted by DPI, but dropped by target server
 */
int fail4_packet(uint8_t *payload, uint32_t plen);

#define PKT_ACCEPT	0
#define PKT_DROP	1

/**
 * Processes the packet and returns verdict.
 * This is the primary function that traverses the packet.
 */
int process_packet(const uint8_t *packet, uint32_t packet_len);

/**
 * Sends fake client hello.
 */
int post_fake_sni(const struct iphdr *iph, unsigned int iph_len, 
		     const struct tcphdr *tcph, unsigned int tcph_len,
		     unsigned char sequence_len);

/**
 * Splits packet by poses and posts.
 * Poses are relative to start of TCP payload.
 * dvs used internally and should be zero.
 */
int send_tcp4_frags(
	const uint8_t *packet, uint32_t pktlen, 
	const uint32_t *poses, uint32_t poses_len, uint32_t dvs);

/**
 * Splits packet by poses and posts.
 * Poses are relative to start of TCP payload.
 * dvs used internally and should be zero.
 */
int send_ip4_frags(
	const uint8_t *packet, uint32_t pktlen, 
	const uint32_t *poses, uint32_t poses_len, uint32_t dvs);
#endif /* YU_MANGLE_H */
