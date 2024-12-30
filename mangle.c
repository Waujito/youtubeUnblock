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

	lgtrace_start();
	lgtrace_addp("IPv%d", ipver);

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

	int verdict = PKT_CONTINUE;

	if (transport_proto == IPPROTO_TCP) 
		lgtrace_addp("TCP");
	else if (transport_proto == IPPROTO_UDP) 
		lgtrace_addp("UDP");

	
	ITER_CONFIG_SECTIONS(&config, section) {
		lgtrace_addp("Section #%d", CONFIG_SECTION_NUMBER(section));

		switch (transport_proto) {
		case IPPROTO_TCP:
			verdict = process_tcp_packet(section, raw_payload, raw_payload_len);
			break;
		case IPPROTO_UDP:
			verdict = process_udp_packet(section, raw_payload, raw_payload_len);
			break;
		}

		if (verdict == PKT_CONTINUE) {
			lgtrace_addp("continue_flow");
			continue;
		}

		goto ret_verdict;
	}

accept:	
	verdict = PKT_ACCEPT;

ret_verdict:

	switch (verdict) {
	case PKT_ACCEPT:
		lgtrace_addp("accept");
		break;
	case PKT_DROP:
		lgtrace_addp("drop");
		break;
	default:
		lgtrace_addp("unknow verdict: %d", verdict);
	}
	lgtrace_end();

	return verdict;
}

int process_tcp_packet(const struct section_config_t *section, const uint8_t *raw_payload, uint32_t raw_payload_len) {
	const void *ipxh;
	uint32_t iph_len;
	const struct tcphdr *tcph;
	uint32_t tcph_len;
	const uint8_t *data;
	uint32_t dlen;


	int ipxv = netproto_version(raw_payload, raw_payload_len);

	int ret = tcp_payload_split((uint8_t *)raw_payload, raw_payload_len,
			      (void *)&ipxh, &iph_len,
			      (struct tcphdr **)&tcph, &tcph_len,
			      (uint8_t **)&data, &dlen);


	if (ret < 0) {
		goto accept;
	}

	if (tcph->syn && section->synfake) {
		lgtrace_addp("TCP syn alter");

		NETBUF_ALLOC(payload, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(payload)) {
			lgerror(-ENOMEM, "Allocation error");
			goto accept;
		}

		memcpy(payload, ipxh, iph_len);
		memcpy(payload + iph_len, tcph, tcph_len);
		uint32_t fake_len = section->fake_sni_pkt_sz;

		if (section->synfake_len) 
			fake_len = min(section->synfake_len, fake_len);

		memcpy(payload + iph_len + tcph_len, section->fake_sni_pkt, fake_len);


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
			lgerror(ret, "send_syn_altered");

			NETBUF_FREE(payload);
			goto accept;
		}

		NETBUF_FREE(payload);
		goto drop;
	}

	if (tcph->syn) goto continue_flow;

	if (!section->tls_enabled)
		goto continue_flow;

	struct tls_verdict vrd = analyze_tls_data(section, data, dlen);
	lgtrace_addp("TLS analyzed");

	if (vrd.sni_len != 0) {
		lgtrace_addp("SNI detected: %.*s", vrd.sni_len, data + vrd.sni_offset);
	}

	if (vrd.target_sni) {
		lgdebugmsg("Target SNI detected: %.*s", vrd.sni_len, data + vrd.sni_offset);

		uint32_t payload_len = raw_payload_len;
		NETBUF_ALLOC(payload, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(payload)) {
			lgerror(-ENOMEM, "Allocation error");
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
			lgerror(ret, "tcp_payload_split in targ_sni");
			goto accept_lc;
		}

		if (section->fk_winsize) {
			tcph->window = htons(section->fk_winsize);
			set_tcp_checksum(tcph, iph, iph_len);
		}

		if (0) {
			int delta = 2;
			ret = seqovl_packet(payload, &payload_len, delta);
			int ret = tcp_payload_split(payload, payload_len,
				      &iph, &iph_len, &tcph, &tcph_len,
				      &data, &dlen);
			if (ret < 0) {
				lgerror(ret, "seqovl_packet delta %d", delta);
			}
		}

		
		if (dlen > 1480 && config.verbose) {
			lgdebugmsg("WARNING! Client Hello packet is too big and may cause issues!");
		}

		if (section->fake_sni) {
			post_fake_sni(args_default_fake_type(section), iph, iph_len, tcph, tcph_len);	
		}

		size_t ipd_offset;
		size_t mid_offset;

		switch (section->fragmentation_strategy) {
			case FRAG_STRAT_TCP: {
				ipd_offset = vrd.sni_target_offset;
				mid_offset = ipd_offset + vrd.sni_target_len / 2;

				uint32_t poses[2];
				int cnt = 0;

				if (section->frag_sni_pos && dlen > section->frag_sni_pos) {
					poses[cnt++] = section->frag_sni_pos;
				}

				if (section->frag_middle_sni) {
					poses[cnt++] = mid_offset;
				}

				if (cnt > 1 && poses[0] > poses[1]) {
					uint32_t tmp = poses[0];
					poses[0] = poses[1];
					poses[1] = tmp;
				}

				ret = send_tcp_frags(section, payload, payload_len, poses, cnt, 0);
				if (ret < 0) {
					lgerror(ret, "tcp4 send frags");
					goto accept_lc;
				}

				goto drop_lc;
			}
			break;
			case FRAG_STRAT_IP: 
			if (ipxv == IP4VERSION) {
				ipd_offset = ((char *)data - (char *)tcph) + vrd.sni_target_offset;
				mid_offset = ipd_offset + vrd.sni_target_len / 2;
				mid_offset += 8 - mid_offset % 8;

				uint32_t poses[2];
				int cnt = 0;

				if (section->frag_sni_pos && dlen > section->frag_sni_pos) {
					poses[cnt] = section->frag_sni_pos + ((char *)data - (char *)tcph);
					poses[cnt] += 8 - poses[cnt] % 8;
					cnt++;
				}

				if (section->frag_middle_sni) {
					poses[cnt++] = mid_offset;
				}

				if (cnt > 1 && poses[0] > poses[1]) {
					uint32_t tmp = poses[0];
					poses[0] = poses[1];
					poses[1] = tmp;
				}

				ret = send_ip4_frags(section, payload, payload_len, poses, cnt, 0);
				if (ret < 0) {
					lgerror(ret, "ip4 send frags");
					goto accept_lc;
				}

				goto drop_lc;
			} else {
				lginfo("WARNING: IP fragmentation is supported only for IPv4\n");	
				goto default_send;
			}
			default:
			default_send:
				ret = instance_config.send_raw_packet(payload, payload_len);
				if (ret < 0) {
					lgerror(ret, "raw pack send");
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

continue_flow:
	return PKT_CONTINUE;
accept:
	return PKT_ACCEPT;
drop:
	return PKT_DROP;
}

int process_udp_packet(const struct section_config_t *section, const uint8_t *pkt, uint32_t pktlen) {
	const void *iph;
	uint32_t iph_len;
	const struct udphdr *udph;
	const uint8_t *data;
	uint32_t dlen;

	int ret = udp_payload_split((uint8_t *)pkt, pktlen,
			      (void **)&iph, &iph_len, 
			      (struct udphdr **)&udph,
			      (uint8_t **)&data, &dlen);

	
	if (ret < 0) {
		lgtrace_addp("undefined");
		goto accept;
	}

	if (dlen > 10 && config.verbose == VERBOSE_TRACE) {
		char logging_buf[128];
		char *bufpt = logging_buf;
		bufpt += sprintf(bufpt, "UDP payload start: [ ");
		for (int i = 0; i < 10; i++) {
			bufpt += sprintf(bufpt, "%02x ", data[i]);
		}
		bufpt += sprintf(bufpt, "]");
		lgtrace_addp("%s", logging_buf); 
	}


	if (!detect_udp_filtered(section, pkt, pktlen)) 
		goto continue_flow;

	if (section->udp_mode == UDP_MODE_DROP)
		goto drop;
	else if (section->udp_mode == UDP_MODE_FAKE) {
		for (int i = 0; i < section->udp_fake_seq_len; i++) {
			NETBUF_ALLOC(fake_udp, MAX_PACKET_SIZE);
			if (!NETBUF_CHECK(fake_udp)) {
				lgerror(-ENOMEM, "Allocation error");
				return -ENOMEM;
			}
			uint32_t fsn_len = MAX_PACKET_SIZE;

			struct udp_fake_type fake_type = {
				.fake_len = section->udp_fake_len,
				.strategy = {
					.strategy = section->udp_faking_strategy,
					.faking_ttl = section->faking_ttl,
				},
			};
			ret = gen_fake_udp(fake_type, iph, iph_len, udph, fake_udp, &fsn_len);
			if (ret < 0) {
				lgerror(ret, "gen_fake_udp");
				goto erret_lc;
			}

			lgtrace_addp("post fake udp #%d", i + 1);

			ret = instance_config.send_raw_packet(fake_udp, fsn_len);
			if (ret < 0) {
				lgerror(ret, "send fake udp");
				goto erret_lc;
			}
						
			NETBUF_FREE(fake_udp);
			continue;
erret_lc:
			NETBUF_FREE(fake_udp);
			goto accept;
		}

		
		ret = instance_config.send_raw_packet(pkt, pktlen);
		goto drop;
	}

continue_flow:
	return PKT_CONTINUE;
accept:
	return PKT_ACCEPT;
drop:
	return PKT_DROP;
}

int send_ip4_frags(const struct section_config_t *section, const uint8_t *packet, uint32_t pktlen, const uint32_t *poses, uint32_t poses_sz, uint32_t dvs) {
	if (poses_sz == 0) {
		if (section->seg2_delay && ((dvs > 0) ^ section->frag_sni_reverse)) {
			if (!instance_config.send_delayed_packet) {
				return -EINVAL;
			}

			lgtrace_addp("Sent %d delayed for %d", pktlen, section->seg2_delay);
			instance_config.send_delayed_packet(
				packet, pktlen, section->seg2_delay);

			return 0;
		} else {
			lgtrace_addp("Sent %d bytes", pktlen);
			return instance_config.send_raw_packet(
				packet, pktlen);
		}
	} else {
		NETBUF_ALLOC(frag1, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(frag1)) {
			lgerror(-ENOMEM, "Allocation error");
			return -ENOMEM;
		}

		NETBUF_ALLOC(frag2, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(frag2)) {
			lgerror(-ENOMEM, "Allocation error");
			NETBUF_FREE(frag1);
			return -ENOMEM;
		}

/*
		NETBUF_ALLOC(fake_pad, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(fake_pad)) {
			lgerror(-ENOMEM, "Allocation error");
			NETBUF_FREE(frag1);
			NETBUF_FREE(frag2);
			return -ENOMEM;
		}
*/

		uint32_t f1len = MAX_PACKET_SIZE;
		uint32_t f2len = MAX_PACKET_SIZE;
		// uint32_t fake_pad_len = MAX_PACKET_SIZE;

		int ret;

		if (dvs > poses[0]) {
			lgerror(-EINVAL, "send_frags: Recursive dvs(%d) is more than poses0(%d)", dvs, poses[0]);
			ret = -EINVAL;
			goto erret_lc;
		}

		uint32_t frag_pos = poses[0] - dvs;
		frag_pos += 8 - frag_pos % 8;

		ret = ip4_frag(packet, pktlen, frag_pos, 
			frag1, &f1len, frag2, &f2len);

		if (ret < 0) {
			lgerror(ret, "send_frags: frag: with context packet with size %d, position: %d, recursive dvs: %d", pktlen, poses[0], dvs);
			goto erret_lc;
		}

		dvs += frag_pos;

		if (section->frag_sni_reverse)
			goto send_frag2;
send_frag1:
		ret = send_ip4_frags(section, frag1, f1len, NULL, 0, 0);
		if (ret < 0) {
			goto erret_lc;
		}

		if (section->frag_sni_reverse)
			goto out_lc;

send_fake:
/*
		if (section->frag_sni_faked) {
			ITER_FAKE_STRAT(section->faking_strategy, strategy) {
				uint32_t iphfl;
				fake_pad_len = f2len;
				ret = ip4_payload_split(frag2, f2len, NULL, &iphfl, NULL, NULL);
				if (ret < 0) {
					lgerror("Invalid frag2", ret);
					goto erret_lc;
				}
				memcpy(fake_pad, frag2, iphfl + sizeof(struct udphdr));
				memset(fake_pad + iphfl + sizeof(struct udphdr), 0, f2len - iphfl - sizeof(struct udphdr));
				((struct iphdr *)fake_pad)->tot_len = htons(fake_pad_len);
				((struct iphdr *)fake_pad)->id = 1;
				((struct iphdr *)fake_pad)->ttl = 8;
				((struct iphdr *)fake_pad)->frag_off = 0;
				ip4_set_checksum((struct iphdr*)fake_pad);
				// *(struct udphdr *)(fake_pad + iphfl) = *(struct udphdr *)(frag2 + iphfl);
				ret = send_ip4_frags(fake_pad, fake_pad_len, NULL, 0, 0);
				if (ret < 0) {
					goto erret_lc;
				}
			}
		}
*/

		if (section->frag_sni_reverse)
			goto send_frag1;

send_frag2:
		ret = send_ip4_frags(section, frag2, f2len, poses + 1, poses_sz - 1, dvs);
		if (ret < 0) {
			goto erret_lc;
		}

		if (section->frag_sni_reverse)
			goto send_fake;

out_lc:
		NETBUF_FREE(frag1);
		NETBUF_FREE(frag2);
		// NETBUF_FREE(fake_pad);
		goto out;
erret_lc:
		NETBUF_FREE(frag1);
		NETBUF_FREE(frag2);
		// NETBUF_FREE(fake_pad);
		return ret;
	}

out:
	return 0;
}

int send_tcp_frags(const struct section_config_t *section, const uint8_t *packet, uint32_t pktlen, const uint32_t *poses, uint32_t poses_sz, uint32_t dvs) {
	if (poses_sz == 0) {
		if (section->seg2_delay && ((dvs > 0) ^ section->frag_sni_reverse)) {
			if (!instance_config.send_delayed_packet) {
				return -EINVAL;
			}

			instance_config.send_delayed_packet(
				packet, pktlen, section->seg2_delay);

			return 0;
		} else {
			lgtrace_addp("raw send packet of %d bytes with %d dvs", pktlen, dvs);
			return instance_config.send_raw_packet(
				packet, pktlen);
		}
	} else {
		NETBUF_ALLOC(frag1, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(frag1)) {
			lgerror(-ENOMEM, "Allocation error");
			return -ENOMEM;
		}

		NETBUF_ALLOC(frag2, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(frag2)) {
			lgerror(-ENOMEM, "Allocation error");
			NETBUF_FREE(frag1);
			return -ENOMEM;
		}

		uint32_t f1len = MAX_PACKET_SIZE;
		uint32_t f2len = MAX_PACKET_SIZE;

		int ret;

		if (dvs > poses[0]) {
			lgerror(-EINVAL, "send_frags: Recursive dvs(%d) is more than poses0(%d)", dvs, poses[0]);
			ret = -EINVAL;
			goto erret_lc;
		}


		ret = tcp_frag(packet, pktlen, poses[0] - dvs, 
			frag1, &f1len, frag2, &f2len);


		lgtrace_addp("Packet split in %d bytes position of payload start, dvs: %d to two packets of %d and %d lengths", poses[0], dvs, f1len, f2len);

		if (ret < 0) {
			lgerror(ret, "send_frags: tcp_frag: with context packet with size %d, position: %d, recursive dvs: %d", pktlen, poses[0], dvs);
			goto erret_lc;
		}


		dvs += poses[0];

		if (section->frag_sni_reverse)
			goto send_frag2;
		
send_frag1:
		{
			ret = send_tcp_frags(section, frag1, f1len, NULL, 0, 0);
			if (ret < 0) {
				goto erret_lc;
			}

			if (section->frag_sni_reverse) 
				goto out_lc;
		}

send_fake:
		if (section->frag_sni_faked) {
			uint32_t iphfl, tcphfl;
			void *iph;
			struct tcphdr *tcph;
			ret = tcp_payload_split(frag2, f2len, &iph, &iphfl, &tcph, &tcphfl, NULL, NULL);
			struct fake_type f_type = args_default_fake_type(section);
			if ((f_type.strategy.strategy & FAKE_STRAT_PAST_SEQ) == FAKE_STRAT_PAST_SEQ) {
				f_type.strategy.strategy ^= FAKE_STRAT_PAST_SEQ;
				f_type.strategy.strategy |= FAKE_STRAT_RAND_SEQ;
				f_type.strategy.randseq_offset = dvs;
			}

			f_type.seg2delay = section->seg2_delay;

			post_fake_sni(f_type, iph, iphfl, tcph, tcphfl);	
		}

		if (section->frag_sni_reverse)
			goto send_frag1;

send_frag2:
		{
			ret = send_tcp_frags(section, frag2, f2len, poses + 1, poses_sz - 1, dvs);
			if (ret < 0) {
				goto erret_lc;
			}

			if (section->frag_sni_reverse)
				goto send_fake;
		}
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

int post_fake_sni(struct fake_type f_type, 
		const void *iph, unsigned int iph_len, 
		const struct tcphdr *tcph, unsigned int tcph_len) {

	uint8_t rfsiph[128];
	uint8_t rfstcph[60];
	int ret;

	int ipxv = netproto_version(iph, iph_len);

	memcpy(rfsiph, iph, iph_len);
	memcpy(rfstcph, tcph, tcph_len);

	void *fsiph = (void *)rfsiph;
	struct tcphdr *fstcph = (void *)rfstcph;

	ITER_FAKE_STRAT(f_type.strategy.strategy, strategy) {
		struct fake_type fake_seq_type = f_type;
		fake_seq_type.strategy.strategy = strategy;

		// one goes for default fake
		for (int i = 0; i < fake_seq_type.sequence_len; i++) {
			NETBUF_ALLOC(fake_sni, MAX_PACKET_SIZE);
			if (!NETBUF_CHECK(fake_sni)) {
				lgerror(-ENOMEM, "Allocation error");
				return -ENOMEM;
			}
			uint32_t fsn_len = MAX_PACKET_SIZE;
			
			ret = gen_fake_sni(
				fake_seq_type,
				fsiph, iph_len, fstcph, tcph_len, 
				fake_sni, &fsn_len);
			if (ret < 0) {
				lgerror(ret, "gen_fake_sni");
				goto erret_lc;
			}

			lgtrace_addp("post fake sni #%d", i + 1);

			if (f_type.seg2delay) {
				ret = instance_config.send_delayed_packet(fake_sni, fsn_len, f_type.seg2delay);
			} else {
				ret = instance_config.send_raw_packet(fake_sni, fsn_len);
			}
			if (ret < 0) {
				lgerror(ret, "send fake sni");
				goto erret_lc;
			}
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


			if (!(strategy == FAKE_STRAT_PAST_SEQ ||
				strategy == FAKE_STRAT_RAND_SEQ)) {
				fstcph->seq = htonl(ntohl(fstcph->seq) + plen);
			}

			if (ipxv == IP4VERSION) {
				((struct iphdr *)fsiph)->id = htons(ntohs(((struct iphdr *)fsiph)->id) + 1);
			}

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
	}

	return 0;
}

