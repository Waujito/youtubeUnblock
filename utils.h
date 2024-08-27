#ifndef UTILS_H
#define UTILS_H

#include "types.h"

#define IP4VERSION 4
#define IP6VERSION 6

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
// int tcp4_frag(const uint8_t *pkt, uint32_t pktlen, 
// 			uint32_t payload_offset, 
// 			uint8_t *seg1, uint32_t *s1len, 
// 			uint8_t *seg2, uint32_t *s2len);
int tcp_frag(const uint8_t *pkt, uint32_t pktlen,
			uint32_t payload_offset,
			uint8_t *seg1, uint32_t *s1len, 
			uint8_t *seg2, uint32_t *s2len);


/**
 * Splits the raw packet payload to ip header and ip payload.
 */
int ip4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len, 
		       uint8_t **payload, uint32_t *plen);

static inline int netproto_version(const uint8_t *pkt, uint32_t buflen) {
	if (pkt == NULL || buflen == 0)
		return -1;

	return (*pkt) >> 4;
}


/**
 * Splits the raw packet payload to ip header, tcp header and tcp payload.
 */
int tcp4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len,
		       struct tcphdr **tcph, uint32_t *tcph_len,
		       uint8_t **payload, uint32_t *plen);

/**
 * Splits the raw packet payload to ip header and ip payload.
 */
int ip6_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct ip6_hdr **iph, uint32_t *iph_len, 
		       uint8_t **payload, uint32_t *plen);

/**
 * Splits the raw packet payload to ip header, tcp header and tcp payload.
 */
int tcp6_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct ip6_hdr **iph, uint32_t *iph_len,
		       struct tcphdr **tcph, uint32_t *tcph_len,
		       uint8_t **payload, uint32_t *plen);

int tcp_payload_split(uint8_t *pkt, uint32_t buflen,
		      void **iph, uint32_t *iph_len,
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
void ip6_set_checksum(struct ip6_hdr *iph);
void tcp6_set_checksum(struct tcphdr *tcph, struct ip6_hdr *iph);

int  set_ip_checksum(void *iph, uint32_t iphb_len);
int  set_tcp_checksum(struct tcphdr *tcph, void *iph, uint32_t iphb_len);

#endif /* UTILS_H */
