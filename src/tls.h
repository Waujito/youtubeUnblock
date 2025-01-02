#ifndef TLS_H
#define TLS_H

#include "types.h"
#include "utils.h"


/**
 * Result of analyze_tls_data function
 */
struct tls_verdict {
	const uint8_t *sni_ptr;
	int sni_len;

	int target_sni; /* boolean, 1 if target found */
	const uint8_t *target_sni_ptr; /* pointer to target domain instead of entire sni */
	int target_sni_len; /* length of target domain instead of entire sni */
};

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_EXTENSION_SNI 0x0000
#define TLS_EXTENSION_CLIENT_HELLO_ENCRYPTED 0xfe0d

#define TLS_MESSAGE_ANALYZE_INVALID	-1
#define TLS_MESSAGE_ANALYZE_FOUND	0
#define TLS_MESSAGE_ANALYZE_GOTO_NEXT	1

/**
 * Analyzes each TLS Client Hello message (inside TLS Record or QUIC CRYPTO FRAME)
 */
int analyze_tls_message(
	const struct section_config_t *section,
	const uint8_t *message_data, 
	size_t message_length,
	struct tls_verdict *tlsv
);


/**
 * Processes the packet and finds TLS Client Hello information inside it.
 * data pointer points to start of TLS Message (TCP Payload)
 *
 * Note that all the constant pointers of tls_verdict will be relative to data pointer
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
