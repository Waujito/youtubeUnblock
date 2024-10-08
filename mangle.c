#define _GNU_SOURCE
#include "types.h" // IWYU pragma: keep
#include "mangle.h"
#include "config.h"
#include "utils.h"
#include "quic.h"
#include "logging.h"

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
				ipd_offset = vrd.sni_offset;
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
				ipd_offset = ((char *)data - (char *)tcph) + vrd.sni_offset;
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
			ret = fail_packet(fake_pad, &fake_pad_len, MAX_PACKET_SIZE);
			if (ret < 0) {
				lgerror("Failed to fail packet", ret);
				goto erret_lc;
			}
			ret = send_tcp_frags(fake_pad, fake_pad_len, NULL, 0, 0);
			if (ret < 0) {
				goto erret_lc;
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

	for (int i = 0; i < sequence_len; i++) {
		NETBUF_ALLOC(fake_sni, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(fake_sni)) {
			lgerror("Allocation error", -ENOMEM);
			return -ENOMEM;
		}
		uint32_t fsn_len = MAX_PACKET_SIZE;
		ret = gen_fake_sni(fsiph, iph_len, fstcph, tcph_len, 
		     fake_sni, &fsn_len);
		if (ret < 0) {
			lgerror("gen_fake_sni", ret);
			goto erret_lc;
		}

		lgtrace_addp("post fake sni #%d", i + 1);
		lgtrace_addp("post with %d", fsn_len);
		ret = instance_config.send_raw_packet(fake_sni, fsn_len);
		if (ret < 0) {
			lgerror("send fake sni", ret);
			goto erret_lc;
		}

		uint32_t iph_len;
		uint32_t tcph_len;
		uint32_t plen;
		tcp_payload_split(
			fake_sni, fsn_len, 
			&fsiph, &iph_len,
			&fstcph, &tcph_len,
			NULL, &plen);


		fstcph->seq = htonl(ntohl(fstcph->seq) + plen);
		memcpy(rfsiph, fsiph, iph_len);
		memcpy(rfstcph, fstcph, tcph_len);
		fsiph = (void *)rfsiph;
		fstcph = (void *)rfstcph;

		NETBUF_FREE(fake_sni);
		continue;
erret_lc:
		NETBUF_FREE(fake_sni);
		return ret;
	}

	return 0;
}

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_EXTENSION_SNI 0x0000
#define TLS_EXTENSION_CLIENT_HELLO_ENCRYPTED 0xfe0d

/**
 * Processes tls payload of the tcp request.
 * 
 * data Payload data of TCP.
 * dlen Length of `data`.
 */
struct tls_verdict analyze_tls_data(
	const uint8_t *data, 
	uint32_t dlen) 
{
	struct tls_verdict vrd = {0};

	size_t i = 0;
	const uint8_t *data_end = data + dlen;

	while (i + 4 < dlen) {
		const uint8_t *msgData = data + i;

		uint8_t tls_content_type = *msgData;
		uint8_t tls_vmajor = *(msgData + 1);
		uint16_t message_length = ntohs(*(uint16_t *)(msgData + 3));

		if (tls_vmajor != 0x03) goto nextMessage;

		if (i + 5 > dlen) break;

		if (tls_content_type != TLS_CONTENT_TYPE_HANDSHAKE) 
			goto nextMessage;

		if (config.sni_detection == SNI_DETECTION_BRUTE) {
			goto brute;
		}

		const uint8_t *handshakeProto = msgData + 5;

		if (handshakeProto + 1 >= data_end) break;

		uint8_t handshakeType = *handshakeProto;

		if (handshakeType != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
			goto nextMessage;

		const uint8_t *msgPtr = handshakeProto;
		msgPtr += 1; 
		msgPtr += 3 + 2 + 32;

		if (msgPtr + 1 >= data_end) break;
		uint8_t sessionIdLength = *msgPtr;
		msgPtr++;
		msgPtr += sessionIdLength;

		if (msgPtr + 2 >= data_end) break;
		uint16_t ciphersLength = ntohs(*(uint16_t *)msgPtr);
		msgPtr += 2;
		msgPtr += ciphersLength;

		if (msgPtr + 1 >= data_end) break;
		uint8_t compMethodsLen = *msgPtr;
		msgPtr++;
		msgPtr += compMethodsLen;

		if (msgPtr + 2 >= data_end) break;
		uint16_t extensionsLen = ntohs(*(uint16_t *)msgPtr);
		msgPtr += 2;

		const uint8_t *extensionsPtr = msgPtr;
		const uint8_t *extensions_end = extensionsPtr + extensionsLen;
		if (extensions_end > data_end) extensions_end = data_end;

		while (extensionsPtr < extensions_end) {
			const uint8_t *extensionPtr = extensionsPtr;
			if (extensionPtr + 4 >= extensions_end) break;

			uint16_t extensionType = 
				ntohs(*(uint16_t *)extensionPtr);
			extensionPtr += 2;

			uint16_t extensionLen = 
				ntohs(*(uint16_t *)extensionPtr);
			extensionPtr += 2;


			if (extensionPtr + extensionLen > extensions_end) 
				break;

			if (extensionType != TLS_EXTENSION_SNI) 
				goto nextExtension;

			const uint8_t *sni_ext_ptr = extensionPtr;

			if (sni_ext_ptr + 2 >= extensions_end) break;
			uint16_t sni_ext_dlen = ntohs(*(uint16_t *)sni_ext_ptr);

			sni_ext_ptr += 2;

			const uint8_t *sni_ext_end = sni_ext_ptr + sni_ext_dlen;
			if (sni_ext_end >= extensions_end) break;
			
			if (sni_ext_ptr + 3 >= sni_ext_end) break;
			sni_ext_ptr++;
			uint16_t sni_len = ntohs(*(uint16_t *)sni_ext_ptr);
			sni_ext_ptr += 2;

			if (sni_ext_ptr + sni_len > sni_ext_end) break;

			char *sni_name = (char *)sni_ext_ptr;

			vrd.sni_offset = (uint8_t *)sni_name - data;
			vrd.sni_len = sni_len;

			if (config.all_domains) {
				vrd.target_sni = 1;
				goto check_domain;
			}


			unsigned int j = 0;
			for (unsigned int i = 0; i <= config.domains_strlen; i++) {
				if (	i > j &&
					(i == config.domains_strlen	||	
					config.domains_str[i] == '\0'	||
					config.domains_str[i] == ','	|| 
					config.domains_str[i] == '\n'	)) {

					unsigned int domain_len = (i - j);
					const char *sni_startp = sni_name + sni_len - domain_len;
					const char *domain_startp = config.domains_str + j;

					if (sni_len >= domain_len &&
						sni_len < 128 && 
						!strncmp(sni_startp, 
						domain_startp, 
						domain_len)) {
							vrd.target_sni = 1;
							goto check_domain;
					}

					j = i + 1;
				}
			}

check_domain:
			if (vrd.target_sni == 1 && config.exclude_domains_strlen != 0) {
				unsigned int j = 0;
				for (unsigned int i = 0; i <= config.exclude_domains_strlen; i++) {
					if (	i > j &&
						(i == config.exclude_domains_strlen	||	
						config.exclude_domains_str[i] == '\0'	||
						config.exclude_domains_str[i] == ','	|| 
						config.exclude_domains_str[i] == '\n'	)) {

						unsigned int domain_len = (i - j);
						const char *sni_startp = sni_name + sni_len - domain_len;
						const char *domain_startp = config.exclude_domains_str + j;

						if (sni_len >= domain_len &&
							sni_len < 128 && 
							!strncmp(sni_startp, 
							domain_startp, 
							domain_len)) {

							vrd.target_sni = 0;
							lgdebugmsg("Excluded SNI: %.*s", 
								vrd.sni_len, data + vrd.sni_offset);
							goto out;
						}

						j = i + 1;
					}
				}
			}

			goto out;

nextExtension:
			extensionsPtr += 2 + 2 + extensionLen;
		}
nextMessage:
		i += 5 + message_length;
	}

out:
	return vrd;


brute:
	if (config.all_domains) {
		vrd.target_sni = 1;
		vrd.sni_len = 0;
		vrd.sni_offset = dlen / 2;
		goto out;
	}

	unsigned int j = 0;
	for (unsigned int i = 0; i <= config.domains_strlen; i++) {
		if (	i > j &&
			(i == config.domains_strlen	||	
			config.domains_str[i] == '\0'	||
			config.domains_str[i] == ','	|| 
			config.domains_str[i] == '\n'	)) {

			unsigned int domain_len = (i - j);
			const char *domain_startp = config.domains_str + j;

			if (domain_len + dlen + 1> MAX_PACKET_SIZE) { 
				continue;
			}

			NETBUF_ALLOC(buf, MAX_PACKET_SIZE);
			if (!NETBUF_CHECK(buf)) {
				lgerror("Allocation error", -ENOMEM);
				goto out;
			}
			NETBUF_ALLOC(nzbuf, MAX_PACKET_SIZE * sizeof(int));
			if (!NETBUF_CHECK(nzbuf)) {
				lgerror("Allocation error", -ENOMEM);
				NETBUF_FREE(buf);
				goto out;
			}

			int *zbuf = (void *)nzbuf;

			memcpy(buf, domain_startp, domain_len);
			memcpy(buf + domain_len, "#", 1);
			memcpy(buf + domain_len + 1, data, dlen);

			z_function((char *)buf, zbuf, domain_len + 1 + dlen);

			for (unsigned int k = 0; k < dlen; k++) {
				if (zbuf[k] == domain_len) {
					vrd.target_sni = 1;
					vrd.sni_len = domain_len;
					vrd.sni_offset = (k - domain_len - 1);
					NETBUF_FREE(buf);
					NETBUF_FREE(nzbuf);
					goto out;
				}
			}


			j = i + 1;

			NETBUF_FREE(buf);
			NETBUF_FREE(nzbuf);
		}
	}

	goto out;
}

int gen_fake_sni(const void *ipxh, uint32_t iph_len, 
		 const struct tcphdr *tcph, uint32_t tcph_len,
		 uint8_t *buf, uint32_t *buflen) {

	if (!ipxh || !tcph || !buf || !buflen)
		return -EINVAL;

	int ipxv = netproto_version(ipxh, iph_len);

	if (ipxv == IP4VERSION) {
		const struct iphdr *iph = ipxh;

		memcpy(buf, iph, iph_len);
		struct iphdr *niph = (struct iphdr *)buf;

		niph->protocol = IPPROTO_TCP;
	} else if (ipxv == IP6VERSION) {
		const struct ip6_hdr *iph = ipxh;

		iph_len = sizeof(struct ip6_hdr);
		memcpy(buf, iph, iph_len);
		struct ip6_hdr *niph = (struct ip6_hdr *)buf;

		niph->ip6_nxt = IPPROTO_TCP;
	} else {
		return -EINVAL;
	}

	const char *data = config.fake_sni_pkt;
	size_t data_len = config.fake_sni_pkt_sz;

	uint32_t dlen = iph_len + tcph_len + data_len;

	if (*buflen < dlen) 
		return -ENOMEM;

	memcpy(buf + iph_len, tcph, tcph_len);
	memcpy(buf + iph_len + tcph_len, data, data_len);


	if (ipxv == IP4VERSION) {
		struct iphdr *niph = (struct iphdr *)buf;
		niph->tot_len = htons(dlen);
	} else if (ipxv == IP6VERSION) {
		struct ip6_hdr *niph = (struct ip6_hdr *)buf;
		niph->ip6_plen = htons(dlen - iph_len);
	}

	fail_packet(buf, &dlen, *buflen);
	*buflen = dlen;
	
	return 0;
}

#define TCP_MD5SIG_LEN 16
#define TCP_MD5SIG_KIND 19
struct tcp_md5sig_opt {
	uint8_t kind;
	uint8_t len;
	uint8_t sig[TCP_MD5SIG_LEN];
};
#define TCP_MD5SIG_OPT_LEN (sizeof(struct tcp_md5sig_opt))
// Real length of the option, with NOOP fillers
#define TCP_MD5SIG_OPT_RLEN 20

int fail_packet(uint8_t *payload, uint32_t *plen, uint32_t avail_buflen) {
	void *iph;
	uint32_t iph_len;
	struct tcphdr *tcph;
	uint32_t tcph_len;
	uint8_t *data;
	uint32_t dlen;
	int ret;

	ret = tcp_payload_split(payload, *plen, 
			&iph, &iph_len, &tcph, &tcph_len,
			&data, &dlen);

	uint32_t ipxv = netproto_version(payload, *plen);

	if (ret < 0) {
		return ret;
	}


	if (config.faking_strategy == FAKE_STRAT_RAND_SEQ) {
		lgtrace("fake seq: %u -> ", ntohl(tcph->seq));

		if (config.fakeseq_offset) {
			tcph->seq = htonl(ntohl(tcph->seq) - config.fakeseq_offset);
		} else {
#ifdef KERNEL_SPACE
			tcph->seq = 124;
#else
			tcph->seq = random();
#endif

		}

		lgtrace_addp("%u", ntohl(tcph->seq));
	} else if (config.faking_strategy == FAKE_STRAT_PAST_SEQ) {
		lgtrace("fake seq: %u -> ", ntohl(tcph->seq));
		tcph->seq = htonl(ntohl(tcph->seq) - dlen);
		lgtrace_addp("%u", ntohl(tcph->seq));

	} else if (config.faking_strategy == FAKE_STRAT_TTL) {
		lgtrace_addp("set fake ttl to %d", config.faking_ttl);

		if (ipxv == IP4VERSION) {
			((struct iphdr *)iph)->ttl = config.faking_ttl;
		} else if (ipxv == IP6VERSION) {
			((struct ip6_hdr *)iph)->ip6_hops = config.faking_ttl;
		} else {
			lgerror("fail_packet: IP version is unsupported", -EINVAL);
			return -EINVAL;
		}
	} else if (config.faking_strategy == FAKE_STRAT_TCP_MD5SUM) {
		int optp_len = tcph_len - sizeof(struct tcphdr);
		int delta = TCP_MD5SIG_OPT_RLEN - optp_len;
		lgtrace_addp("Incr delta %d: %d -> %d", delta, optp_len, optp_len + delta);
		
		if (delta > 0) {
			if (avail_buflen - *plen < delta) {
				return -1;
			}
			uint8_t *ndata = data + delta;
			uint8_t *ndptr = ndata + dlen;
			uint8_t *dptr = data + dlen;
			for (size_t i = dlen + 1; i > 0; i--) {
				*ndptr = *dptr;
				--ndptr, --dptr;
			}
			data = ndata;
			tcph_len = tcph_len + delta;
			tcph->doff = tcph_len >> 2;
			if (ipxv == IP4VERSION) {
				((struct iphdr *)iph)->tot_len = htons(ntohs(((struct iphdr *)iph)->tot_len) + delta);
			} else if (ipxv == IP6VERSION) {
				((struct ip6_hdr *)iph)->ip6_plen = htons(ntohs(((struct ip6_hdr *)iph)->ip6_plen) + delta);
			} else {
				lgerror("fail_packet: IP version is unsupported", -EINVAL);
				return -EINVAL;
			}
			optp_len += delta;
			*plen += delta;
		}

		uint8_t *optplace = (uint8_t *)tcph + sizeof(struct tcphdr);
		struct tcp_md5sig_opt *mdopt = (void *)optplace;
		mdopt->kind = TCP_MD5SIG_KIND;
		mdopt->len = TCP_MD5SIG_OPT_LEN;

		optplace += sizeof(struct tcp_md5sig_opt);
		optp_len -= sizeof(struct tcp_md5sig_opt);

		while (optp_len-- > 0) {
			*optplace++ = 0x01;
		}
	}

	set_ip_checksum(iph, iph_len);
	set_tcp_checksum(tcph, iph, iph_len);

	if (config.faking_strategy == FAKE_STRAT_TCP_CHECK) {
		lgtrace_addp("break fake tcp checksum");
		tcph->check += 1;
	}

	return 0;
}
