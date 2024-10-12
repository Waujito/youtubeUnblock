#ifndef UTILS_H
#define UTILS_H

#include "types.h"
#include "config.h"

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

int udp6_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct ip6_hdr **iph, uint32_t *iph_len,
		       struct udphdr **udph,
		       uint8_t **payload, uint32_t *plen);

int udp_payload_split(uint8_t *pkt, uint32_t buflen,
		      void **iph, uint32_t *iph_len,
		      struct udphdr **udph,
		      uint8_t **payload, uint32_t *plen);

void tcp4_set_checksum(struct tcphdr *tcph, struct iphdr *iph);
void ip4_set_checksum(struct iphdr *iph);
void ip6_set_checksum(struct ip6_hdr *iph);
void tcp6_set_checksum(struct tcphdr *tcph, struct ip6_hdr *iph);

int  set_ip_checksum(void *iph, uint32_t iphb_len);
int  set_tcp_checksum(struct tcphdr *tcph, void *iph, uint32_t iphb_len);

void z_function(const char *str, int *zbuf, size_t len);

/**
 * Shifts data left delta bytes. Fills delta buffer with zeroes.
 */
void shift_data(uint8_t *data, uint32_t dlen, uint32_t delta);


struct failing_strategy {
	unsigned int strategy;
	uint8_t faking_ttl;
	uint32_t randseq_offset;
};


struct fake_type {

#define FAKE_PAYLOAD_RANDOM	0
#define FAKE_PAYLOAD_DATA	1
// In default mode all other options will be skipped.
#define FAKE_PAYLOAD_DEFAULT	2
	int type;	

	// Length of the final fake message. 
	// Pass 0 in RANDOM mode to make it random
	uint16_t fake_len;

	// Payload of the fake message of fake_len length. 
	// Will be omitted in RANDOM mode.
	const char *fake_data;

	unsigned int sequence_len;

	// If non-0 the packet send will be delayed for n milliseconds
	unsigned int seg2delay;

	// faking strategy of the fake packet.
	// Does not support bitmask, pass standalone strategy.
	// Pass 0 if you don't want any faking procedures.
	struct failing_strategy strategy;
};

/**
 * Invalidates the raw packet. The function aims to invalid the packet
 * in such way as it will be accepted by DPI, but dropped by target server
 *
 * Does not support bitmask, pass standalone strategy.
 */
int fail_packet(struct failing_strategy strategy, uint8_t *payload, uint32_t *plen, uint32_t avail_buflen);

/**
 * Shifts the payload right and pushes zeroes before it. Useful for TCP TLS faking.
 */
int seqovl_packet(uint8_t *payload, uint32_t *plen, uint32_t seq_delta);



static inline struct failing_strategy args_default_failing_strategy(void) {
	struct failing_strategy fl_strat = {
		.strategy = (unsigned int)config.faking_strategy,
		.faking_ttl = config.faking_ttl,
		.randseq_offset = (uint32_t)config.fakeseq_offset
	};
	return fl_strat;
}

static inline struct fake_type args_default_fake_type(void) {
	struct fake_type f_type = {
		.sequence_len = config.fake_sni_seq_len,
		.strategy = args_default_failing_strategy(),
	};

	switch (config.fake_sni_type) {
		case FAKE_PAYLOAD_RANDOM:
			f_type.type = FAKE_PAYLOAD_RANDOM;
			break;
		case FAKE_PAYLOAD_CUSTOM:
			f_type.type = FAKE_PAYLOAD_CUSTOM;
			f_type.fake_data = config.fake_custom_pkt;
			f_type.fake_len = config.fake_custom_pkt_sz;
			break;
		default:
			f_type.type = FAKE_PAYLOAD_CUSTOM;
			f_type.fake_data = config.fake_sni_pkt;
			f_type.fake_len = config.fake_sni_pkt_sz;
	}

	return f_type;
}

#endif /* UTILS_H */
