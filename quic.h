#ifndef QUIC_H
#define QUIC_H
#include "types.h"


/**
* @macro
*
* :macro:`NGTCP2_INITIAL_SALT_V1` is a salt value which is used to
* derive initial secret.  It is used for QUIC v1.
*/
#define QUIC_INITIAL_SALT_V1 \
 "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad" \
 "\xcc\xbb\x7f\x0a"

/**
* @macro
*
* :macro:`NGTCP2_INITIAL_SALT_V2` is a salt value which is used to
* derive initial secret.  It is used for QUIC v2.
*/
#define QUIC_INITIAL_SALT_V2 \
 "\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb" \
 "\xf9\xbd\x2e\xd9"

#define QUIC_INITIAL_TYPE	0
#define QUIC_0_RTT_TYPE		1
#define QUIC_HANDSHAKE_TYPE	2
#define QUIC_RETRY_TYPE		3

#define QUIC_INITIAL_TYPE_V1	0b00
#define QUIC_0_RTT_TYPE_V1	0b01
#define QUIC_HANDSHAKE_TYPE_V1	0b10
#define QUIC_RETRY_TYPE_V1	0b11
#define quic_convtype_v1(type) (type)

#define QUIC_INITIAL_TYPE_V2	0b01
#define QUIC_0_RTT_TYPE_V2	0b10
#define QUIC_HANDSHAKE_TYPE_V2	0b11
#define QUIC_RETRY_TYPE_V2	0b00
#define quic_convtype_v2(type) (((type) + 1) & 0b11)

#define QUIC_V1	1		// RFC 9000
#define QUIC_V2	0x6b3343cf	// RFC 9369

static const uint32_t supported_versions[] = {
	QUIC_V1,
	QUIC_V2,
};

/**
 * Quic Large Header
 */
struct quic_lhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t number_length:2;
	uint8_t reserved:2;
	uint8_t type:2;
	uint8_t fixed:1;
	uint8_t form:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t form:1;
	uint8_t fixed:1;
	uint8_t type:2;
	uint8_t reserved:2;
	uint8_t number_length:2;
#else
#error "Undefined endian"
#endif
	uint32_t version;
}__attribute__((packed));

/**
 * Quic Large Header Ids 
 * (separated from the original header because of varying dst 
 */
struct quic_cids {
	uint8_t dst_len;
	uint8_t *dst_id;
	uint8_t src_len;
	uint8_t *src_id;
};

/**
 * Parses QUIС raw data (UDP payload) to quic large header and 
 * quic payload.
 *
 * \qch_len is sizeof(qch) + qci->dst_len + qci->src_id
 * \payload is Type-Specific payload (#17.2).
 */
int quic_parse_data(uint8_t *raw_payload, uint32_t raw_payload_len,
		struct quic_lhdr **qch, uint32_t *qch_len,
		struct quic_cids *qci,
		uint8_t **payload, uint32_t *plen);
		

/**
 * Parses QUIC variable-length integer. (#16)
 * \variable is a pointer to the sequence to be parsed
 * (varlen integer in big endian format)
 *
 * \mlen Used to signal about variable length and validate left length
 * in the buffer.
 */
uint64_t quic_parse_varlength(uint8_t *variable, uint64_t *mlen);

// quici stands for QUIC Initial

/**
 * This structure should be parsed
 */
struct quici_hdr {
	uint64_t token_len;
	uint8_t *token;
	uint64_t length;
	uint32_t packet_number;
};

/**
 * Parses QUIC initial payload.
 * \inpayload is a raw QUIC payload (payload after quic large header)
 */
int quic_parse_initial_message(uint8_t *inpayload, uint32_t inplen,
			const struct quic_lhdr *qch,
			struct quici_hdr *qhdr,
			uint8_t **payload, uint32_t *plen);

#endif /* QUIC_H */
