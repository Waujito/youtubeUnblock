#ifndef TLS_H
#define TLS_H

#include "types.h"
#include "utils.h"


/**
 * Result of analyze_tls_data function
 */
struct tls_verdict {
	int target_sni; /* google video hello packet */
	int sni_offset; /* offset from start of tcp _payload_ */
	int sni_target_offset; /* offset of target domain instead of entire sni */
	int sni_target_len; /* offset of target domain instead of entire sni */
	int sni_len;
};

/**
 * Processes the packet and finds TLS Client Hello information inside it.
 * data pointer points to start of TLS Message (TCP Payload)
 */
struct tls_verdict analyze_tls_data(const struct section_config_t *section, const uint8_t *data, uint32_t dlen);


/**
 * Generates the fake client hello message
 */
int gen_fake_sni(struct fake_type type,
		const void *iph, uint32_t iph_len, 
		const struct tcphdr *tcph, uint32_t tcph_len, 
		uint8_t *buf, uint32_t *buflen);

#endif /* TLS_H */
