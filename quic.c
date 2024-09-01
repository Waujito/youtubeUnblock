#include "quic.h"
#include "logging.h"


/**
 * Packet number.
 */
struct quic_pnumber {
	uint8_t d1;
	uint8_t d2;
	uint8_t d3;
	uint8_t d4;
};

uint64_t quic_parse_varlength(uint8_t *variable, uint64_t *mlen) {
	if (mlen && *mlen == 0) return 0;
	uint64_t vr = (*variable & 0x3F);
	uint8_t len = 1 << (*variable >> 6);

	if (mlen) {
		if (*mlen < len) return 0;
		*mlen = len;
	}

	++variable;
	for (uint8_t i = 1; i < len; i++) {
		vr = (vr << 8) + *variable;
		++variable;
	}

	return vr;
}

int quic_parse_data(uint8_t *raw_payload, uint32_t raw_payload_len,
		struct quic_lhdr **qch, uint32_t *qch_len,
		struct quic_cids *qci,
		uint8_t **payload, uint32_t *plen) {
	if (	raw_payload == NULL || 
		raw_payload_len < sizeof(struct quic_lhdr)) 
		goto invalid_packet;

	struct quic_lhdr *nqch = (struct quic_lhdr *)raw_payload;
	uint32_t left_len = raw_payload_len - sizeof(struct quic_lhdr);
	uint8_t *cur_rawptr = raw_payload + sizeof(struct quic_lhdr);
	if (!nqch->fixed) {
		lgtrace_addp("quic fixed uset");
		return -EPROTO;
	}

	uint8_t found = 0;
	for (uint8_t i = 0; i < 2; i++) {
		if (ntohl(nqch->version) == supported_versions[i]) {
			found = 1;
		}
	}

	if (!found) {
		lgtrace_addp("quic version undefined %d", ntohl(nqch->version));
		return -EPROTO;
	}

	lgtrace_addp("quic version valid %d", ntohl(nqch->version));

	if (left_len < 2) goto invalid_packet;
	struct quic_cids nqci = {0};

	nqci.dst_len = *cur_rawptr++;
	left_len--;
	if (left_len < nqci.dst_len) goto invalid_packet;
	nqci.dst_id = cur_rawptr;
	cur_rawptr += nqci.dst_len;
	left_len -= nqci.dst_len;

	nqci.src_len = *cur_rawptr++;
	left_len--;
	if (left_len < nqci.src_len) goto invalid_packet;
	nqci.src_id = cur_rawptr;
	cur_rawptr += nqci.src_len;
	left_len -= nqci.src_len;

	if (qch) *qch = nqch;
	if (qch_len) {
		*qch_len = sizeof(struct quic_lhdr) + 
			nqci.src_len + nqci.dst_len;
	}
	if (qci) *qci = nqci;
	if (payload) *payload = cur_rawptr;
	if (plen) *plen = left_len;

	return 0;

invalid_packet:
	return -EINVAL;
}

int quic_parse_initial_message(uint8_t *inpayload, uint32_t inplen,
			const struct quic_lhdr *qch, 
			struct quici_hdr *qhdr,
			uint8_t **payload, uint32_t *plen) {
	if (inplen < 3) goto invalid_packet;
	struct quici_hdr nqhdr;

	uint8_t *cur_ptr = inpayload;
	uint32_t left_len = inplen;
	uint64_t tlen = left_len;

	nqhdr.token_len = quic_parse_varlength(cur_ptr, &tlen);
	nqhdr.token = cur_ptr + tlen;
	
	if (left_len < nqhdr.token_len + tlen) 
		goto invalid_packet;
	cur_ptr += tlen + nqhdr.token_len;
	left_len -= tlen + nqhdr.token_len;

	tlen = left_len;
	nqhdr.length = quic_parse_varlength(cur_ptr, &tlen);

	if (left_len != nqhdr.length + tlen && 
		left_len <= qch->number_length + 1)
		goto invalid_packet;

	uint32_t packet_number = 0;

	for (uint8_t i = 0; i <= qch->number_length; i++) {
		packet_number = (packet_number << 8) + *cur_ptr++;
		left_len--;
	}

	nqhdr.packet_number = packet_number;

	if (qhdr) *qhdr = nqhdr;
	if (payload) *payload = cur_ptr;
	if (plen) *plen = left_len;

	return 0;

invalid_packet:
	lgerror("QUIC invalid Initial packet", -EINVAL);
	return -EINVAL;
}
