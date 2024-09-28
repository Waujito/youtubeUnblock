#define _GNU_SOURCE
#include "types.h" // IWYU pragma: keep
#include "mangle.h"
#include "config.h"
#include "utils.h"
#include "quic.h"
#include "logging.h"
#include "tls.h"

#ifndef KERNEL_SPACE
#include <stdlib.h>
#endif

int process_packet(const uint8_t *raw_payload, uint32_t raw_payload_len) {
	if (raw_payload_len > MAX_PACKET_SIZE) {
		return PKT_ACCEPT;
	}

	const struct iphdr *iph;
	const struct ip6_hdr *ip6h;
	uint32_t iph_len;
	const uint8_t *ip_payload;
	uint32_t ip_payload_len;

	int transport_proto = -1;
	int ipver = netproto_version(raw_payload, raw_payload_len);
	int ret;


	if (ipver == IP4VERSION) {
		ret = ip4_payload_split((uint8_t *)raw_payload, raw_payload_len,
			 (struct iphdr **)&iph, &iph_len, 
			 (uint8_t **)&ip_payload, &ip_payload_len);

		if (ret < 0)
			goto accept;

		transport_proto = iph->protocol;

	} else if (ipver == IP6VERSION && config.use_ipv6) {
		ret = ip6_payload_split((uint8_t *)raw_payload, raw_payload_len,
			 (struct ip6_hdr **)&ip6h, &iph_len, 
			 (uint8_t **)&ip_payload, &ip_payload_len);

		if (ret < 0)
			goto accept;

		transport_proto = ip6h->ip6_nxt;

	} else {
		lgtracemsg("Unknown layer 3 protocol version: %d", ipver);
		goto accept;
	}

	
	switch (transport_proto) {
	case IPPROTO_TCP:
		return process_tcp_packet(raw_payload, raw_payload_len);
	case IPPROTO_UDP:
		return process_udp_packet(raw_payload, raw_payload_len);
	default:
		goto accept;
	}
	
accept:
	return PKT_ACCEPT;
}

int process_tcp_packet(const uint8_t *raw_payload, uint32_t raw_payload_len) {
	const void *ipxh;
	uint32_t iph_len;
	const struct tcphdr *tcph;
	uint32_t tcph_len;
	const uint8_t *data;
	uint32_t dlen;


	int ipxv = netproto_version(raw_payload, raw_payload_len);

	lgtrace_start("TCP");
	lgtrace_addp("IPv%d", ipxv);

	int ret = tcp_payload_split((uint8_t *)raw_payload, raw_payload_len,
			      (void *)&ipxh, &iph_len,
			      (struct tcphdr **)&tcph, &tcph_len,
			      (uint8_t **)&data, &dlen);


	if (ret < 0) {
		goto accept;
	}

	if (tcph->syn && config.synfake) {
		lgtrace_addp("TCP syn alter");

		NETBUF_ALLOC(payload, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(payload)) {
			lgerror("Allocation error", -ENOMEM);
			goto accept;
		}

		memcpy(payload, ipxh, iph_len);
		memcpy(payload + iph_len, tcph, tcph_len);
		uint32_t fake_len = config.fake_sni_pkt_sz;

		if (config.synfake_len) 
			fake_len = min(config.synfake_len, fake_len);

		memcpy(payload + iph_len + tcph_len, config.fake_sni_pkt, fake_len);


		struct tcphdr *tcph = (struct tcphdr *)(payload + iph_len);
		if (ipxv == IP4VERSION) {
			struct iphdr *iph = (struct iphdr *)payload;
			iph->tot_len = htons(iph_len + tcph_len + fake_len);
			set_ip_checksum(payload, iph_len);
			set_tcp_checksum(tcph, iph, iph_len);
		} else if (ipxv == IP6VERSION) {
			struct ip6_hdr *ip6h = (struct ip6_hdr *)payload;
			ip6h->ip6_plen = ntohs(tcph_len + fake_len);
			set_ip_checksum(ip6h, iph_len);
			set_tcp_checksum(tcph, ip6h, iph_len);
		}


		ret = instance_config.send_raw_packet(payload, iph_len + tcph_len + fake_len);
		if (ret < 0) {
			lgerror("send_syn_altered", ret);

			NETBUF_FREE(payload);
			goto accept;
		}
		lgtrace_addp("rawsocket sent %d", ret);

		NETBUF_FREE(payload);
		goto drop;
	}

	if (tcph->syn) goto accept;

	struct tls_verdict vrd = analyze_tls_data(data, dlen);
	lgtrace_addp("Analyzed, %d", vrd.target_sni);

	if (vrd.target_sni) {
		lgdebugmsg("Target SNI detected: %.*s", vrd.sni_len, data + vrd.sni_offset);

		uint32_t payload_len = raw_payload_len;
		NETBUF_ALLOC(payload, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(payload)) {
			lgerror("Allocation error", -ENOMEM);
			goto accept; 
		}

		memcpy(payload, raw_payload, raw_payload_len);

		void *iph;
		uint32_t iph_len;
		struct tcphdr *tcph;
		uint32_t tcph_len;
		uint8_t *data;
		uint32_t dlen;

		int ret = tcp_payload_split(payload, payload_len,
				      &iph, &iph_len, &tcph, &tcph_len,
				      &data, &dlen);

		if (ret < 0) {
			lgerror("tcp_payload_split in targ_sni", ret);
			goto accept_lc;
		}

		if (config.fk_winsize) {
			tcph->window = htons(config.fk_winsize);
		}

		set_ip_checksum(iph, iph_len);
		set_tcp_checksum(tcph, iph, iph_len);
		
		if (dlen > 1480 && config.verbose) {
			lgdebugmsg("WARNING! Client Hello packet is too big and may cause issues!");
		}

		if (config.fake_sni) {
			post_fake_sni(iph, iph_len, tcph, tcph_len, 
				config.fake_sni_seq_len);	
		}

		size_t ipd_offset;
		size_t mid_offset;

		switch (config.fragmentation_strategy) {
			case FRAG_STRAT_TCP: {
				ipd_offset = vrd.sni_target_offset;
				mid_offset = ipd_offset + vrd.sni_len / 2;

				uint32_t poses[2];
				int cnt = 0;

				if (config.frag_sni_pos && dlen > config.frag_sni_pos) {
					poses[cnt++] = config.frag_sni_pos;
				}

				if (config.frag_middle_sni) {
					poses[cnt++] = mid_offset;
				}

				if (cnt > 1 && poses[0] > poses[1]) {
					uint32_t tmp = poses[0];
					poses[0] = poses[1];
					poses[1] = tmp;
				}

				ret = send_tcp_frags(payload, payload_len, poses, cnt, 0);
				if (ret < 0) {
					lgerror("tcp4 send frags", ret);
					goto accept_lc;
				}

				goto drop_lc;
			}
			break;
			case FRAG_STRAT_IP: 
			if (ipxv == IP4VERSION) {
				ipd_offset = ((char *)data - (char *)tcph) + vrd.sni_target_offset;
				mid_offset = ipd_offset + vrd.sni_len / 2;
				mid_offset += 8 - mid_offset % 8;

				uint32_t poses[2];
				int cnt = 0;

				if (config.frag_sni_pos && dlen > config.frag_sni_pos) {
					poses[cnt] = config.frag_sni_pos + ((char *)data - (char *)tcph);
					poses[cnt] += 8 - poses[cnt] % 8;
					cnt++;
				}

				if (config.frag_middle_sni) {
					poses[cnt++] = mid_offset;
				}

				if (cnt > 1 && poses[0] > poses[1]) {
					uint32_t tmp = poses[0];
					poses[0] = poses[1];
					poses[1] = tmp;
				}

				ret = send_ip4_frags(payload, payload_len, poses, cnt, 0);
				if (ret < 0) {
					lgerror("ip4 send frags", ret);
					goto accept_lc;
				}

				goto drop_lc;
			} else {
				printf("WARNING: IP fragmentation is supported only for IPv4\n");	
				goto default_send;
			}
			default:
			default_send:
				ret = instance_config.send_raw_packet(payload, payload_len);
				if (ret < 0) {
					lgerror("raw pack send", ret);
					goto accept_lc;
				}

				goto drop_lc;
		}



		goto drop_lc;

accept_lc:
		NETBUF_FREE(payload);
		goto accept;
drop_lc:
		NETBUF_FREE(payload);
		goto drop;

	}

accept:
	lgtrace_addp("accept");
	lgtrace_end();

	return PKT_ACCEPT;
drop:
	lgtrace_addp("drop");
	lgtrace_end();

	return PKT_DROP;
}

int process_udp_packet(const uint8_t *pkt, uint32_t pktlen) {
	const void *iph;
	uint32_t iph_len;
	const struct udphdr *udph;
	const uint8_t *data;
	uint32_t dlen;
	int ipver = netproto_version(pkt, pktlen);
	lgtrace_start("Got udp packet");
	lgtrace_addp("IPv%d", ipver);

	int ret = udp_payload_split((uint8_t *)pkt, pktlen,
			      (void **)&iph, &iph_len, 
			      (struct udphdr **)&udph,
			      (uint8_t **)&data, &dlen);

	
	if (ret < 0) {
		lgtrace_addp("undefined");
		goto accept;
	}

	if (dlen > 10 && config.verbose >= VERBOSE_TRACE) {
		printf("UDP payload start: [ ");
		for (int i = 0; i < 10; i++) {
			printf("%02x ", data[i]);
		}
		printf("], ");
	}

	lgtrace_addp("QUIC probe");
	const struct quic_lhdr *qch;
	uint32_t qch_len;
	struct quic_cids qci;
	uint8_t *quic_raw_payload;
	uint32_t quic_raw_plen;
	ret = quic_parse_data((uint8_t *)data, dlen, 
		 (struct quic_lhdr **)&qch, &qch_len, &qci, 
		 &quic_raw_payload, &quic_raw_plen);

	if (ret < 0) {
		lgtrace_addp("undefined type");
		goto accept;
	}

	lgtrace_addp("QUIC detected");
	uint8_t qtype = qch->type;

	if (config.quic_drop) {
		goto drop;
	}

	if (qch->version == QUIC_V1)
		qtype = quic_convtype_v1(qtype);
	else if (qch->version == QUIC_V2) 
		qtype = quic_convtype_v2(qtype);

	if (qtype != QUIC_INITIAL_TYPE) {
		lgtrace_addp("quic message type: %d", qtype);
		goto accept;
	}
	
	lgtrace_addp("quic initial message");

accept:
	lgtrace_addp("accepted");
	lgtrace_end();

	return PKT_ACCEPT;
drop:
	lgtrace_addp("dropped");
	lgtrace_end();

	return PKT_DROP;
}

int send_ip4_frags(const uint8_t *packet, uint32_t pktlen, const uint32_t *poses, uint32_t poses_sz, uint32_t dvs) {
	if (poses_sz == 0) {
		if (config.seg2_delay && ((dvs > 0) ^ config.frag_sni_reverse)) {
			if (!instance_config.send_delayed_packet) {
				return -EINVAL;
			}

			instance_config.send_delayed_packet(
				packet, pktlen, config.seg2_delay);

			return 0;
		} else {
			return instance_config.send_raw_packet(
				packet, pktlen);
		}
	} else {
		NETBUF_ALLOC(frag1, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(frag1)) {
			lgerror("Allocation error", -ENOMEM);
			return -ENOMEM;
		}

		NETBUF_ALLOC(frag2, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(frag2)) {
			lgerror("Allocation error", -ENOMEM);
			NETBUF_FREE(frag1);
			return -ENOMEM;
		}

		uint32_t f1len = MAX_PACKET_SIZE;
		uint32_t f2len = MAX_PACKET_SIZE;

		int ret;

		if (dvs > poses[0]) {
			lgerror("send_frags: Recursive dvs(%d) is more than poses0(%d)", -EINVAL, dvs, poses[0]);
			ret = -EINVAL;
			goto erret_lc;
		}

		ret = ip4_frag(packet, pktlen, poses[0] - dvs, 
			frag1, &f1len, frag2, &f2len);

		if (ret < 0) {
			lgerror("send_frags: frag: with context packet with size %d, position: %d, recursive dvs: %d", ret, pktlen, poses[0], dvs);
			goto erret_lc;
		}

		if (config.frag_sni_reverse)
			goto send_frag2;
send_frag1:
		ret = send_ip4_frags(frag1, f1len, NULL, 0, 0);
		if (ret < 0) {
			goto erret_lc;
		}

		if (config.frag_sni_reverse)
			goto out_lc;

send_frag2:
		dvs += poses[0];
		ret = send_ip4_frags(frag2, f2len, poses + 1, poses_sz - 1, dvs);
		if (ret < 0) {
			goto erret_lc;
		}

		if (config.frag_sni_reverse)
			goto send_frag1;

out_lc:
		NETBUF_FREE(frag1);
		NETBUF_FREE(frag2);
		goto out;
erret_lc:
		NETBUF_FREE(frag1);
		NETBUF_FREE(frag2);
		return ret;
	}

out:
	return 0;
}

int send_tcp_frags(const uint8_t *packet, uint32_t pktlen, const uint32_t *poses, uint32_t poses_sz, uint32_t dvs) {
	if (poses_sz == 0) {
		if (config.seg2_delay && ((dvs > 0) ^ config.frag_sni_reverse)) {
			if (!instance_config.send_delayed_packet) {
				return -EINVAL;
			}

			instance_config.send_delayed_packet(
				packet, pktlen, config.seg2_delay);

			return 0;
		} else {
			lgtrace_addp("raw send packet of %d bytes with %d dvs", pktlen, dvs);
			return instance_config.send_raw_packet(
				packet, pktlen);
		}
	} else {
		NETBUF_ALLOC(frag1, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(frag1)) {
			lgerror("Allocation error", -ENOMEM);
			return -ENOMEM;
		}

		NETBUF_ALLOC(frag2, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(frag2)) {
			lgerror("Allocation error", -ENOMEM);
			NETBUF_FREE(frag1);
			return -ENOMEM;
		}

		NETBUF_ALLOC(fake_pad, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(fake_pad)) {
			lgerror("Allocation error", -ENOMEM);
			NETBUF_FREE(frag1);
			NETBUF_FREE(frag2);
			return -ENOMEM;
		}


		uint32_t f1len = MAX_PACKET_SIZE;
		uint32_t f2len = MAX_PACKET_SIZE;
		uint32_t fake_pad_len = MAX_PACKET_SIZE;

		int ret;

		if (dvs > poses[0]) {
			lgerror("send_frags: Recursive dvs(%d) is more than poses0(%d)", -EINVAL, dvs, poses[0]);
			ret = -EINVAL;
			goto erret_lc;
		}


		ret = tcp_frag(packet, pktlen, poses[0] - dvs, 
			frag1, &f1len, frag2, &f2len);

		lgtrace_addp("Packet split in %d bytes position of payload start, dvs: %d to two packets of %d and %d lengths", poses[0], dvs, f1len, f2len);

		if (ret < 0) {
			lgerror("send_frags: tcp_frag: with context packet with size %d, position: %d, recursive dvs: %d", ret, pktlen, poses[0], dvs);
			goto erret_lc;
		}


		if (config.frag_sni_reverse)
			goto send_frag2;
		
send_frag1:
		{
			ret = send_tcp_frags(frag1, f1len, NULL, 0, 0);
			if (ret < 0) {
				goto erret_lc;
			}

			if (config.frag_sni_reverse) 
				goto out_lc;
		}

send_fake:
		if (config.frag_sni_faked) {
			ITER_FAKE_STRAT(config.faking_strategy, strategy) {
				uint32_t iphfl, tcphfl;
				fake_pad_len = f2len;
				ret = tcp_payload_split(frag2, f2len, NULL, &iphfl, NULL, &tcphfl, NULL, NULL);
				if (ret < 0) {
					lgerror("Invalid frag2", ret);
					goto erret_lc;
				}
				memcpy(fake_pad, frag2, iphfl + tcphfl);
				memset(fake_pad + iphfl + tcphfl, 0, f2len - iphfl - tcphfl);
				struct tcphdr *fakethdr = (void *)(fake_pad + iphfl);
				if (config.faking_strategy == FAKE_STRAT_PAST_SEQ) {
					lgtrace("frag fake sent with %u -> ", ntohl(fakethdr->seq));
					fakethdr->seq = htonl(ntohl(fakethdr->seq) - dvs);
					lgtrace_addp("%u, ", ntohl(fakethdr->seq));
				}
				ret = fail_packet(strategy, 
					fake_pad, &fake_pad_len, MAX_PACKET_SIZE);
				if (ret < 0) {
					lgerror("Failed to fail packet", ret);
					goto erret_lc;
				}
				ret = send_tcp_frags(fake_pad, fake_pad_len, NULL, 0, 0);
				if (ret < 0) {
					goto erret_lc;
				}
			}
		}

		if (config.frag_sni_reverse)
			goto send_frag1;

send_frag2:
		{
			dvs += poses[0];
			ret = send_tcp_frags(frag2, f2len, poses + 1, poses_sz - 1, dvs);
			if (ret < 0) {
				goto erret_lc;
			}

			if (config.frag_sni_reverse)
				goto send_fake;
		}
out_lc:
		NETBUF_FREE(frag1);
		NETBUF_FREE(frag2);
		NETBUF_FREE(fake_pad);
		goto out;
erret_lc:
		NETBUF_FREE(frag1);
		NETBUF_FREE(frag2);
		NETBUF_FREE(fake_pad);
		return ret;
	}
out:
	return 0;
}

int post_fake_sni(const void *iph, unsigned int iph_len, 
		     const struct tcphdr *tcph, unsigned int tcph_len,
		     unsigned char sequence_len) {
	uint8_t rfsiph[128];
	uint8_t rfstcph[60];
	int ret;

	memcpy(rfsiph, iph, iph_len);
	memcpy(rfstcph, tcph, tcph_len);

	void *fsiph = (void *)rfsiph;
	struct tcphdr *fstcph = (void *)rfstcph;

	ITER_FAKE_STRAT(config.faking_strategy, strategy) {
		struct fake_type fake_seq_type = {
			.type = FAKE_PAYLOAD_DEFAULT,
			.strategy = strategy,
		};

		switch (config.fake_sni_seq_type) {
			case FAKE_PAYLOAD_RANDOM:
				fake_seq_type.type = FAKE_PAYLOAD_RANDOM;
				break;
			case FAKE_PAYLOAD_CUSTOM:
				fake_seq_type.type = FAKE_PAYLOAD_CUSTOM;
				fake_seq_type.fake_data = config.fake_custom_pkt;
				fake_seq_type.fake_len = config.fake_custom_pkt_sz;
				break;
			default:
				fake_seq_type.type = FAKE_PAYLOAD_DEFAULT;
		}

		// one goes for default fake
		for (int i = 1; i < sequence_len; i++) {
			NETBUF_ALLOC(fake_sni, MAX_PACKET_SIZE);
			if (!NETBUF_CHECK(fake_sni)) {
				lgerror("Allocation error", -ENOMEM);
				return -ENOMEM;
			}
			uint32_t fsn_len = MAX_PACKET_SIZE;
			
			ret = gen_fake_sni(
				fake_seq_type,
				fsiph, iph_len, fstcph, tcph_len, 
				fake_sni, &fsn_len);
			if (ret < 0) {
				lgerror("gen_fake_sni", ret);
				goto erret_lc;
			}

			lgtrace_addp("post fake sni #%d", i + 1);
			lgtrace_addp("post with %d bytes", fsn_len);
			ret = instance_config.send_raw_packet(fake_sni, fsn_len);
			if (ret < 0) {
				lgerror("send fake sni", ret);
				goto erret_lc;
			}

			if (!(config.faking_strategy == FAKE_STRAT_PAST_SEQ ||
				config.faking_strategy == FAKE_STRAT_RAND_SEQ)) {

				uint32_t iph_len;
				uint32_t tcph_len;
				uint32_t plen;
				ret = tcp_payload_split(
					fake_sni, fsn_len, 
					&fsiph, &iph_len,
					&fstcph, &tcph_len,
					NULL, &plen);

				if (ret < 0) {
					lgtrace_addp("continue fake seq");
					goto erret_lc;
				}

				fstcph->seq = htonl(ntohl(fstcph->seq) + plen);
				memcpy(rfsiph, fsiph, iph_len);
				memcpy(rfstcph, fstcph, tcph_len);
				fsiph = (void *)rfsiph;
				fstcph = (void *)rfstcph;
			}
			
			NETBUF_FREE(fake_sni);
			continue;
erret_lc:
			NETBUF_FREE(fake_sni);
			return ret;
		}

		struct fake_type ftype = {
			.type = FAKE_PAYLOAD_DEFAULT,
			.strategy = strategy
		};

		switch (config.fake_sni_type) {
			case FAKE_PAYLOAD_RANDOM:
				ftype.type = FAKE_PAYLOAD_RANDOM;
				break;
			case FAKE_PAYLOAD_CUSTOM:
				ftype.type = FAKE_PAYLOAD_CUSTOM;
				ftype.fake_data = config.fake_custom_pkt;
				ftype.fake_len = config.fake_custom_pkt_sz;
				break;
			default:
				ftype.type = FAKE_PAYLOAD_DEFAULT;
		}

		NETBUF_ALLOC(fake_sni, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(fake_sni)) {
			lgerror("Allocation error", -ENOMEM);
			return -ENOMEM;
		}
		uint32_t fsn_len = MAX_PACKET_SIZE;
		ret = gen_fake_sni(
			ftype,
			iph, iph_len, tcph, tcph_len, 
			fake_sni, &fsn_len);
		if (ret < 0) {
			lgerror("gen_fake_sni", ret);
			goto erret_lc_cst;
		}

		lgtrace_addp("post normal fake sni");
		lgtrace_addp("post with %d bytes", fsn_len);
		ret = instance_config.send_raw_packet(fake_sni, fsn_len);
		if (ret < 0) {
			lgerror("send fake sni", ret);
			goto erret_lc_cst;
		}

		goto after_cus2;

erret_lc_cst:
		NETBUF_FREE(fake_sni);
		return ret;
after_cus2:
		;
	}

	return 0;
}

