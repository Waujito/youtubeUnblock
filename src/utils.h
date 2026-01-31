/*
  youtubeUnblock - https://github.com/Waujito/youtubeUnblock

  Copyright (C) 2024-2025 Vadim Vetrov <vetrovvd@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
int ip4_frag(const uint8_t *pkt, size_t pktlen, 
			size_t payload_offset, 
			uint8_t *frag1, size_t *f1len, 
			uint8_t *frag2, size_t *f2len);

/**
 * Splits the packet to two TCP segments on position payload_offset
 * payload_offset indicates the position relatively to start of TCP payload.
 */
// int tcp4_frag(const uint8_t *pkt, size_t pktlen, 
// 			size_t payload_offset, 
// 			uint8_t *seg1, size_t *s1len, 
// 			uint8_t *seg2, size_t *s2len);
int tcp_frag(const uint8_t *pkt, size_t pktlen,
			size_t payload_offset,
			uint8_t *seg1, size_t *s1len, 
			uint8_t *seg2, size_t *s2len);


/**
 * Splits the raw packet payload to ip header and ip payload.
 */
int ip4_payload_split(uint8_t *pkt, size_t buflen,
		       struct iphdr **iph, size_t *iph_len, 
		       uint8_t **payload, size_t *plen);

static inline int netproto_version(const uint8_t *pkt, size_t buflen) {
	if (pkt == NULL || buflen == 0)
		return -1;

	return (*pkt) >> 4;
}


/**
 * Splits the raw packet payload to ip header, tcp header and tcp payload.
 */
int tcp4_payload_split(uint8_t *pkt, size_t buflen,
		       struct iphdr **iph, size_t *iph_len,
		       struct tcphdr **tcph, size_t *tcph_len,
		       uint8_t **payload, size_t *plen);

/**
 * Splits the raw packet payload to ip header and ip payload.
 */
int ip6_payload_split(uint8_t *pkt, size_t buflen,
		       struct ip6_hdr **iph, size_t *iph_len, 
		       uint8_t **payload, size_t *plen);

/**
 * Splits the raw packet payload to ip header, tcp header and tcp payload.
 */
int tcp6_payload_split(uint8_t *pkt, size_t buflen,
		       struct ip6_hdr **iph, size_t *iph_len,
		       struct tcphdr **tcph, size_t *tcph_len,
		       uint8_t **payload, size_t *plen);

int tcp_payload_split(uint8_t *pkt, size_t buflen,
		      void **iph, size_t *iph_len,
		      struct tcphdr **tcph, size_t *tcph_len,
		      uint8_t **payload, size_t *plen);

/**
 * Splits the raw packet payload to ip header, udp header and udp payload.
 */
int udp4_payload_split(uint8_t *pkt, size_t buflen,
		       struct iphdr **iph, size_t *iph_len,
		       struct udphdr **udph,
		       uint8_t **payload, size_t *plen);

int udp6_payload_split(uint8_t *pkt, size_t buflen,
		       struct ip6_hdr **iph, size_t *iph_len,
		       struct udphdr **udph,
		       uint8_t **payload, size_t *plen);

int udp_payload_split(uint8_t *pkt, size_t buflen,
		      void **iph, size_t *iph_len,
		      struct udphdr **udph,
		      uint8_t **payload, size_t *plen);

void tcp4_set_checksum(struct tcphdr *tcph, struct iphdr *iph);
void ip4_set_checksum(struct iphdr *iph);
void ip6_set_checksum(struct ip6_hdr *iph);
void tcp6_set_checksum(struct tcphdr *tcph, struct ip6_hdr *iph);
void udp4_set_checksum(struct udphdr *udph, struct iphdr *iph);
void udp6_set_checksum(struct udphdr *udph, struct ip6_hdr *iph);

int  set_ip_checksum(void *iph, size_t iphb_len);
int  set_tcp_checksum(struct tcphdr *tcph, void *iph, size_t iphb_len);
int  set_udp_checksum(struct udphdr *udph, void *iph, size_t iphb_len);

void z_function(const char *str, int *zbuf, size_t len);

/**
 * Shifts data left delta bytes. Fills delta buffer with zeroes.
 */
void shift_data(uint8_t *data, size_t dlen, size_t delta);


struct failing_strategy {
	unsigned int strategy;
	uint8_t faking_ttl;
	uint32_t faking_timestamp_decrease;
	size_t randseq_offset;
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

struct udp_failing_strategy {
	unsigned int strategy;
	uint8_t faking_ttl;
};

struct udp_fake_type {
	uint16_t fake_len;

	// faking strategy of the fake packet.
	// Does not support bitmask, pass standalone strategy.
	// Pass 0 if you don't want any faking procedures.
	struct udp_failing_strategy strategy;
};

/**
 * Invalidates the raw packet. The function aims to invalid the packet
 * in such way as it will be accepted by DPI, but dropped by target server
 *
 * Does not support bitmask, pass standalone strategy.
 */
int fail_packet(struct failing_strategy strategy, uint8_t *payload, size_t *plen, size_t avail_buflen);

/**
 * Shifts the payload right and pushes zeroes before it. Useful for TCP TLS faking.
 */
int seqovl_packet(uint8_t *payload, size_t *plen, size_t seq_delta);



static inline struct failing_strategy args_default_failing_strategy(const struct section_config_t *section) {
	struct failing_strategy fl_strat = {
		.strategy = (unsigned int)section->faking_strategy,
		.faking_ttl = section->faking_ttl,
		.faking_timestamp_decrease = section->faking_timestamp_decrease,
		.randseq_offset = (size_t)section->fakeseq_offset,
	};
	return fl_strat;
}

static inline struct fake_type args_default_fake_type(const struct section_config_t *section) {
	struct fake_type f_type = {
		.sequence_len = section->fake_sni_seq_len,
		.strategy = args_default_failing_strategy(section),
	};

	switch (section->fake_sni_type) {
		case FAKE_PAYLOAD_RANDOM:
			f_type.type = FAKE_PAYLOAD_RANDOM;
			break;
		case FAKE_PAYLOAD_CUSTOM:
			f_type.type = FAKE_PAYLOAD_CUSTOM;
			f_type.fake_data = section->fake_custom_pkt;
			f_type.fake_len = section->fake_custom_pkt_sz;
			break;
		default:
			f_type.type = FAKE_PAYLOAD_CUSTOM;
			f_type.fake_data = section->fake_sni_pkt;
			f_type.fake_len = section->fake_sni_pkt_sz;
	}

	return f_type;
}

#endif /* UTILS_H */
