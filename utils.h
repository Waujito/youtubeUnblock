#ifndef UTILS_H
#define UTILS_H

#include "types.h"

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

/**
 * Splits the raw packet payload to ip header, udp header and udp payload.
 */
int udp4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len,
		       struct udphdr **udph,
		       uint8_t **payload, uint32_t *plen);

void tcp4_set_checksum(struct tcphdr *tcph, struct iphdr *iph);
void ip4_set_checksum(struct iphdr *iph);

#endif /* UTILS_H */
