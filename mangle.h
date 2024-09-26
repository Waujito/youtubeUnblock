#ifndef YU_MANGLE_H
#define YU_MANGLE_H

#include "types.h"

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
int process_udp_packet(const uint8_t *pkt, uint32_t pktlen);

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
