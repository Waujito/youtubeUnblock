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

#include "quic.h"
#include "tls.h"
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

uint64_t quic_parse_varlength(const uint8_t *variable, size_t *mlen) {
	if (mlen && *mlen == 0) return 0;
	uint64_t vr = (*variable & 0x3F);
	uint8_t len = 1 << (*variable >> 6);

	if (mlen) {
		if (*mlen < len) {
			*mlen = 0;
			return 0;
		}
		*mlen = len;
	}

	++variable;
	for (uint8_t i = 1; i < len; i++) {
		vr = (vr << 8) + *variable;
		++variable;
	}

	return vr;
}

int quic_get_version(uint32_t *version, const struct quic_lhdr *qch) {
	uint32_t qversion = ntohl(qch->version);
	*version = qversion;

	switch (qversion) {
		case QUIC_V1:
		case QUIC_V2:
			return 0;
		default:
			return -EINVAL;
	}
}

int quic_check_is_initial(const struct quic_lhdr *qch) {
	uint32_t qversion;
	int ret;
	ret = quic_get_version(&qversion, qch);
	if (qversion < 0) return 0;

	uint8_t qtype = qch->type;

	switch (qversion) {
		case QUIC_V1:
			qtype = quic_convtype_v1(qtype);
			break;
		case QUIC_V2:
			qtype = quic_convtype_v2(qtype);
			break;
		default:
			return 0;
	}

	if (qtype != QUIC_INITIAL_TYPE) {
		return 0;
	}

	return 1;
}

int quic_parse_data(const uint8_t *raw_payload, size_t raw_payload_len,
		const struct quic_lhdr **qch, size_t *qch_len,
		struct quic_cids *qci,
		const uint8_t **payload, size_t *plen) {
	if (	raw_payload == NULL || 
		raw_payload_len < sizeof(struct quic_lhdr)) 
		goto invalid_packet;

	const struct quic_lhdr *nqch = (const struct quic_lhdr *)raw_payload;
	size_t left_len = raw_payload_len - sizeof(struct quic_lhdr);
	const uint8_t *cur_rawptr = raw_payload + sizeof(struct quic_lhdr);
	int ret;
	uint32_t qversion;

	if (!nqch->fixed) {
		lgtrace_addp("quic fixed unset");
		return -EPROTO;
	}

	ret = quic_get_version(&qversion, nqch);

	if (ret < 0) {
		lgtrace_addp("quic version undefined %u", qversion);
		return -EPROTO;
	}

	lgtrace_addp("quic version valid %u", qversion);

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

int quic_parse_initial_header(const uint8_t *inpayload, size_t inplen,
			struct quici_hdr *qhdr) {
	if (inplen < 3) goto invalid_packet;
	struct quici_hdr nqhdr;

	const uint8_t *cur_ptr = inpayload;
	size_t left_len = inplen;
	size_t tlen = left_len;

	nqhdr.token_len = quic_parse_varlength(cur_ptr, &tlen);
	nqhdr.token = cur_ptr + tlen;
	
	if (left_len < nqhdr.token_len + tlen) 
		goto invalid_packet;
	cur_ptr += tlen + nqhdr.token_len;
	left_len -= tlen + nqhdr.token_len;

	tlen = left_len;
	nqhdr.length = quic_parse_varlength(cur_ptr, &tlen);

	if (left_len < nqhdr.length + tlen ||
		nqhdr.length < QUIC_SAMPLE_SIZE + 
				QUIC_SAMPLE_OFFSET
	)
		goto invalid_packet;
	cur_ptr += tlen;

	nqhdr.protected_payload = cur_ptr;
	nqhdr.sample = cur_ptr + QUIC_SAMPLE_OFFSET;
	nqhdr.sample_length = QUIC_SAMPLE_SIZE;

	if (qhdr) *qhdr = nqhdr;

	return 0;

invalid_packet:
	lgerror(-EINVAL, "QUIC invalid Initial packet");
	return -EINVAL;
}

ssize_t quic_parse_crypto(struct quic_frame_crypto *crypto_frame,
			  const uint8_t *frame, size_t flen) {
	const uint8_t *curptr = frame;
	size_t curptr_len = flen;
	size_t vln;
	*crypto_frame = (struct quic_frame_crypto){0};

	if (flen == 0 || *frame != QUIC_FRAME_CRYPTO || 
		crypto_frame == NULL) 
		return -EINVAL;

	
	curptr++, curptr_len--;

	vln = curptr_len;
	size_t offset = quic_parse_varlength(curptr, &vln);
	curptr += vln, curptr_len -= vln;
	if (vln == 0) {
		return -EINVAL;
	}
	

	vln = curptr_len;
	size_t length = quic_parse_varlength(curptr, &vln);
	curptr += vln, curptr_len -= vln;
	if (vln == 0) {
		return -EINVAL;
	}

	if (length > curptr_len)
		return -EINVAL;

	crypto_frame->offset = offset;
	crypto_frame->payload_length = length;
	crypto_frame->payload = curptr;

	curptr += length;
	curptr_len -= length;

	return flen - curptr_len;
}

int udp_fail_packet(struct udp_failing_strategy strategy, uint8_t *payload, size_t *plen, size_t avail_buflen) {
	void *iph;
	size_t iph_len;
	struct udphdr *udph;
	uint8_t *data;
	size_t dlen;
	int ret;

	ret = udp_payload_split(payload, *plen, 
			&iph, &iph_len, &udph,
			&data, &dlen);

	uint32_t ipxv = netproto_version(payload, *plen);

	if (ret < 0) {
		return ret;
	}


	if (strategy.strategy == FAKE_STRAT_TTL) {
		lgtrace_addp("Set fake ttl to %d", strategy.faking_ttl);

		if (ipxv == IP4VERSION) {
			((struct iphdr *)iph)->ttl = strategy.faking_ttl;
		} else if (ipxv == IP6VERSION) {
			((struct ip6_hdr *)iph)->ip6_hops = strategy.faking_ttl;
		} else {
			lgerror(-EINVAL, "fail_packet: IP version is unsupported");
			return -EINVAL;
		}
	}

	if (ipxv == IP4VERSION) {
		((struct iphdr *)iph)->frag_off = 0;
	}


	set_ip_checksum(iph, iph_len);

	if (strategy.strategy == FAKE_STRAT_UDP_CHECK) {
		lgtrace_addp("break fake udp checksum");
		udph->check += 1;
	}

	return 0;
}

int gen_fake_udp(struct udp_fake_type type,
		const void *ipxh, size_t iph_len, 
		const struct udphdr *udph,
		uint8_t *buf, size_t *buflen) {
	size_t data_len = type.fake_len;

	if (!ipxh || !udph || !buf || !buflen)
		return -EINVAL;

	int ipxv = netproto_version(ipxh, iph_len);

	if (ipxv == IP4VERSION) {
		const struct iphdr *iph = ipxh;

		memcpy(buf, iph, iph_len);
		struct iphdr *niph = (struct iphdr *)buf;

		niph->protocol = IPPROTO_UDP;
	} else if (ipxv == IP6VERSION) {
		const struct ip6_hdr *iph = ipxh;

		iph_len = sizeof(struct ip6_hdr);
		memcpy(buf, iph, iph_len);
		struct ip6_hdr *niph = (struct ip6_hdr *)buf;

		niph->ip6_nxt = IPPROTO_UDP;
	} else {
		return -EINVAL;
	}

	size_t dlen = iph_len + sizeof(struct udphdr) + data_len;

	if (*buflen < dlen) 
		return -ENOMEM;

	memcpy(buf + iph_len, udph, sizeof(struct udphdr));
	uint8_t *bfdptr = buf + iph_len + sizeof(struct udphdr);

	memset(bfdptr, 0, data_len);

	if (ipxv == IP4VERSION) {
		struct iphdr *niph = (struct iphdr *)buf;
		niph->tot_len = htons(dlen);
		niph->id = randint();
	} else if (ipxv == IP6VERSION) {
		struct ip6_hdr *niph = (struct ip6_hdr *)buf;
		niph->ip6_plen = htons(dlen - iph_len);
	}

	struct udphdr *nudph = (struct udphdr *)(buf + iph_len);
	nudph->len = htons(sizeof(struct udphdr) + data_len);
	
	set_udp_checksum(nudph, buf, iph_len);

	udp_fail_packet(type.strategy, buf, &dlen, *buflen);

	*buflen = dlen;
	
	return 0;
}

int parse_quic_decrypted(
	const struct section_config_t *section,
	const uint8_t *decrypted_message, size_t decrypted_message_len,
	uint8_t **crypto_message_buf, size_t *crypto_message_buf_len
) {
	const uint8_t *curptr = decrypted_message;
	ssize_t curptr_len = decrypted_message_len;
	ssize_t fret;
	int ret;
	struct tls_verdict tlsv = {0};
	struct quic_frame_crypto fr_cr;

	uint8_t *crypto_message = calloc(AVAILABLE_MTU, 1);
	if (crypto_message == NULL) {
		lgerror(-ENOMEM, "No memory");
		return -ENOMEM;
	}

	int crypto_message_len = AVAILABLE_MTU;

	while (curptr_len > 0) {
		uint8_t type = curptr[0];
		switch (type) {
			case QUIC_FRAME_PING:
				lgtrace_addp("ping");
				goto pl_incr;
			case QUIC_FRAME_PADDING:
				if (curptr == decrypted_message ||
					*(curptr - 1) != QUIC_FRAME_PADDING) {
					lgtrace_addp("padding");
				}
pl_incr:
				curptr++, curptr_len--;
				break;
			case QUIC_FRAME_CRYPTO:
				fret = quic_parse_crypto(&fr_cr, curptr, curptr_len);
				lgtrace_addp("crypto len=%zu offset=%zu fret=%zd", fr_cr.payload_length, fr_cr.offset, fret);
				if (fret < 0) {
					lgtrace_addp("Crypto parse error");
					goto out;
				}

				curptr += fret;
				curptr_len -= fret;

				if (fr_cr.offset <= crypto_message_len && 
					fr_cr.payload_length <= crypto_message_len && 
					fr_cr.payload_length <= crypto_message_len
				) {

					memcpy(crypto_message + fr_cr.offset, 
					fr_cr.payload, fr_cr.payload_length);
				}
				
				break;
			default:
				lgtrace_addp("Frame invalid hash: %02x", type);
				goto out;
		}
	}

out:
	*crypto_message_buf = crypto_message;
	*crypto_message_buf_len = crypto_message_len;	

	return 0;
}

int detect_udp_filtered(const struct section_config_t *section,
			const uint8_t *payload, size_t plen) {
	const void *iph;
	size_t iph_len;
	const struct udphdr *udph;
	const uint8_t *data;
	size_t dlen;
	int ret;

	ret = udp_payload_split((uint8_t *)payload, plen,
			      (void **)&iph, &iph_len, 
			      (struct udphdr **)&udph,
			      (uint8_t **)&data, &dlen);
	int udp_dport = ntohs(udph->dest);
	
	if (ret < 0) {
		goto skip;
	}
	
	if (section->udp_filter_quic != UDP_FILTER_QUIC_DISABLED) {
		const struct quic_lhdr *qch;
		size_t qch_len;
		struct quic_cids qci;
		const uint8_t *quic_in_payload;
		size_t quic_in_plen;

		lgtrace_addp("QUIC probe");

		ret = quic_parse_data((uint8_t *)data, dlen, 
			 &qch, &qch_len, &qci, 
			 &quic_in_payload, &quic_in_plen);

		if (ret < 0) {
			lgtrace_addp("QUIC undefined type");
			goto match_port;
		}

		lgtrace_addp("QUIC detected");

			
		if (!quic_check_is_initial(qch)) {
			lgtrace_addp("QUIC not initial");
			goto match_port;
		}

		lgtrace_addp("QUIC initial message");

		if (section->udp_filter_quic == UDP_FILTER_QUIC_ALL) {
			lgtrace_addp("QUIC early approve");
			goto approve;
		}

		uint8_t *decrypted_payload;
		size_t decrypted_payload_len;
		const uint8_t *decrypted_message;
		size_t decrypted_message_len;
		uint8_t *crypto_message;
		size_t crypto_message_len;
		struct tls_verdict tlsv;

		ret = quic_parse_initial_message(
			data, dlen,
			&decrypted_payload, &decrypted_payload_len,
			&decrypted_message, &decrypted_message_len
		);

		if (ret < 0) {
			goto match_port;
		}

		ret = parse_quic_decrypted(section,
			decrypted_message, decrypted_message_len,
			&crypto_message, &crypto_message_len
		);
		free(decrypted_payload);
		decrypted_payload = NULL;

		if (ret < 0) {
			goto match_port;
		}

		if (section->sni_detection == SNI_DETECTION_BRUTE) {
			ret = bruteforce_analyze_sni_str(section, crypto_message, crypto_message_len, &tlsv);
		} else {
			ret = analyze_tls_message(
				section, crypto_message, crypto_message_len, &tlsv
			);
		}

		if (tlsv.sni_len != 0) {
			lgtrace_addp("QUIC SNI detected: %.*s", tlsv.sni_len, tlsv.sni_ptr);
		}

		if (tlsv.target_sni) {
			lgdebug("QUIC target SNI detected: %.*s", tlsv.sni_len, tlsv.sni_ptr);
			free(crypto_message);
			crypto_message = NULL;
			goto approve;
		}

		free(crypto_message);
		crypto_message = NULL;
	}

match_port:

	for (int i = 0; i < section->udp_dport_range_len; i++) {
		struct udp_dport_range crange = section->udp_dport_range[i];
		if (udp_dport >= crange.start && udp_dport <= crange.end) {
			lgtrace_addp("matched to %d-%d", crange.start, crange.end);
			goto approve;
		}
	}

skip:
	return 0;
approve:
	return 1;
}
