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

uint64_t quic_parse_varlength(const uint8_t *variable, uint64_t *mlen) {
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

int64_t quic_get_version(const struct quic_lhdr *qch) {
	int64_t qversion = ntohl(qch->version);

	switch (qversion) {
		case QUIC_V1:
		case QUIC_V2:
			return qversion;
		default:
			return -qversion;
	}
}

int quic_check_is_initial(const struct quic_lhdr *qch) {
	int64_t qversion = quic_get_version(qch);
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

int quic_parse_data(const uint8_t *raw_payload, uint32_t raw_payload_len,
		const struct quic_lhdr **qch, uint32_t *qch_len,
		struct quic_cids *qci,
		const uint8_t **payload, uint32_t *plen) {
	if (	raw_payload == NULL || 
		raw_payload_len < sizeof(struct quic_lhdr)) 
		goto invalid_packet;

	const struct quic_lhdr *nqch = (const struct quic_lhdr *)raw_payload;
	uint32_t left_len = raw_payload_len - sizeof(struct quic_lhdr);
	const uint8_t *cur_rawptr = raw_payload + sizeof(struct quic_lhdr);
	if (!nqch->fixed) {
		lgtrace_addp("quic fixed unset");
		return -EPROTO;
	}

	int64_t qversion = quic_get_version(nqch);

	if (qversion < 0) {
		lgtrace_addp("quic version undefined %ld", -qversion);
		return -EPROTO;
	}

	lgtrace_addp("quic version valid %ld", qversion);

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

int quic_parse_initial_header(const uint8_t *inpayload, uint32_t inplen,
			struct quici_hdr *qhdr) {
	if (inplen < 3) goto invalid_packet;
	struct quici_hdr nqhdr;

	const uint8_t *cur_ptr = inpayload;
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

int udp_fail_packet(struct udp_failing_strategy strategy, uint8_t *payload, uint32_t *plen, uint32_t avail_buflen) {
	void *iph;
	uint32_t iph_len;
	struct udphdr *udph;
	uint8_t *data;
	uint32_t dlen;
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
		const void *ipxh, uint32_t iph_len, 
		const struct udphdr *udph,
		uint8_t *buf, uint32_t *buflen) {
	uint32_t data_len = type.fake_len;

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

	uint32_t dlen = iph_len + sizeof(struct udphdr) + data_len;

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

int detect_udp_filtered(const struct section_config_t *section,
			const uint8_t *payload, uint32_t plen) {
	const void *iph;
	uint32_t iph_len;
	const struct udphdr *udph;
	const uint8_t *data;
	uint32_t dlen;
	int ret;

	ret = udp_payload_split((uint8_t *)payload, plen,
			      (void **)&iph, &iph_len, 
			      (struct udphdr **)&udph,
			      (uint8_t **)&data, &dlen);
	int udp_dport = ntohs(udph->dest);
	lgtrace_addp("UDP dport: %d", udp_dport);

	
	if (ret < 0) {
		goto skip;
	}
	
	if (section->udp_filter_quic) {
		const struct quic_lhdr *qch;
		uint32_t qch_len;
		struct quic_cids qci;
		const uint8_t *quic_raw_payload;
		uint32_t quic_raw_plen;

		lgtrace_addp("QUIC probe");

		ret = quic_parse_data((uint8_t *)data, dlen, 
			 &qch, &qch_len, &qci, 
			 &quic_raw_payload, &quic_raw_plen);

		if (ret < 0) {
			lgtrace_addp("QUIC undefined type");
			goto match_port;
		}

		lgtrace_addp("QUIC detected");

		uint8_t qtype = qch->type;
		if (qch->version == QUIC_V1)
			qtype = quic_convtype_v1(qtype);
		else if (qch->version == QUIC_V2) 
			qtype = quic_convtype_v2(qtype);

		if (qtype != QUIC_INITIAL_TYPE) {
			lgtrace_addp("QUIC message type: %d", qtype);
			goto match_port;
		}

		lgtrace_addp("QUIC initial message");

		goto approve;
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
