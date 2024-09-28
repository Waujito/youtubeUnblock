#ifndef TLS_H
#define TLS_H

#include "types.h"


/**
 * Result of analyze_tls_data function
 */
struct tls_verdict {
	int target_sni; /* google video hello packet */
	int sni_offset; /* offset from start of tcp _payload_ */
	int sni_target_offset; /* offset of target domain instead of entire sni */
	int sni_len;
};

/**
 * Processes the packet and finds TLS Client Hello information inside it.
 * data pointer points to start of TLS Message (TCP Payload)
 */
struct tls_verdict analyze_tls_data(const uint8_t *data, uint32_t dlen);


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

	// faking strategy of the fake packet.
	// Does not support bitmask, pass standalone strategy.
	// Pass 0 if you don't want any faking procedures.
	unsigned int strategy;
};

/**
 * Generates the fake client hello message
 */
int gen_fake_sni(struct fake_type type,
		const void *iph, uint32_t iph_len, 
		const struct tcphdr *tcph, uint32_t tcph_len, 
		uint8_t *buf, uint32_t *buflen);

#endif /* TLS_H */
