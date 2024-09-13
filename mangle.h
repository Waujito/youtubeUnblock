#ifndef YU_MANGLE_H
#define YU_MANGLE_H

#include "types.h"

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
 * Generates fake client hello message
 */
int gen_fake_sni(const void *iph, uint32_t iph_len, 
		 const struct tcphdr *tcph, uint32_t tcph_len, 
		 uint8_t *buf, uint32_t *buflen);

/**
 * Invalidates the raw packet. The function aims to invalid the packet
 * in such way as it will be accepted by DPI, but dropped by target server
 */
int fail_packet(uint8_t *payload, uint32_t *plen, uint32_t avail_buflen);

#define PKT_ACCEPT	0
#define PKT_DROP	1

/**
 * Processes the packet and returns verdict.
 * This is the primary function that traverses the packet.
 */
int process_packet(const uint8_t *packet, uint32_t packet_len);


/**
 * Processe the TCP packet.
 * Returns verdict.
 */
int process_tcp_packet(const uint8_t *raw_payload, uint32_t raw_payload_len);


/**
 * Processes the UDP packet.
 * Returns verdict.
 */
int process_udp4_packet(const uint8_t *pkt, uint32_t pktlen);

/**
 * Sends fake client hello.
 */
int post_fake_sni(const void *iph, unsigned int iph_len, 
		     const struct tcphdr *tcph, unsigned int tcph_len,
		     unsigned char sequence_len);

/**
 * Splits packet by poses and posts.
 * Poses are relative to start of TCP payload.
 * dvs used internally and should be zero.
 */
int send_tcp_frags(
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
