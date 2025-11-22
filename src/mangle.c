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
#else
#include "linux/inet.h"
#endif

int process_packet(const struct config_t *config, const struct packet_data *pd) {
	const uint8_t *raw_payload = pd->payload;
	uint32_t raw_payload_len = pd->payload_len;

	if (raw_payload_len > MAX_PACKET_SIZE) {
		return PKT_ACCEPT;
	}

	const struct iphdr *iph;
	const struct ip6_hdr *ip6h;
	size_t iph_len;
	const uint8_t *ip_payload;
	size_t ip_payload_len;
	const char *bpt;

	int transport_proto = -1;
	int ipver = netproto_version(raw_payload, raw_payload_len);
	int ret;

	lgtrace_start();

	lgtrace_wr("IPv%d ", ipver);

	if (ipver == IP4VERSION) {
		ret = ip4_payload_split((uint8_t *)raw_payload, raw_payload_len,
			 (struct iphdr **)&iph, &iph_len, 
			 (uint8_t **)&ip_payload, &ip_payload_len);	

		if (ret < 0)
			goto accept;

		transport_proto = iph->protocol;

	} 
#ifndef NO_IPV6
	else if (ipver == IP6VERSION && config->use_ipv6) {
		ret = ip6_payload_split((uint8_t *)raw_payload, raw_payload_len,
			 (struct ip6_hdr **)&ip6h, &iph_len, 
			 (uint8_t **)&ip_payload, &ip_payload_len);

		if (ret < 0)
			goto accept;

		transport_proto = ip6h->ip6_nxt;

	} 
#endif
	else {
		lgtrace("Unknown layer 3 protocol version: %d", ipver);
		goto accept;
	}

	if (LOG_LEVEL >= VERBOSE_TRACE) {
		bpt = inet_ntop(
			ipver == IP4VERSION ? AF_INET : AF_INET6, 
			ipver == IP4VERSION ? (void *)(&iph->saddr) : 
				(void *)(&ip6h->ip6_src), 
			ylgh_curptr, ylgh_leftbuf); 
		if (bpt != NULL) {
			ret = strnlen(bpt, ylgh_leftbuf);
			ylgh_leftbuf -= ret;
			ylgh_curptr += ret;
		}

		lgtrace_wr(" => ");

		bpt = inet_ntop(
			ipver == IP4VERSION ? AF_INET : AF_INET6, 
			ipver == IP4VERSION ? (void *)(&iph->daddr) : 
				(void *)(&ip6h->ip6_dst),  
			ylgh_curptr, ylgh_leftbuf); 
		if (bpt != NULL) {
			ret = strnlen(bpt, ylgh_leftbuf);
			ylgh_leftbuf -= ret;
			ylgh_curptr += ret;

		}
		
		lgtrace_wr(" ");
		const uint8_t *transport_payload = NULL;
		size_t transport_payload_len = 0;
		int sport = -1, dport = -1;

		if (transport_proto == IPPROTO_TCP) {
			lgtrace_wr("TCP ");
			const struct tcphdr *tcph;
			ret = tcp_payload_split((uint8_t *)raw_payload, raw_payload_len,
				      NULL, NULL,
				      (struct tcphdr **)&tcph, NULL,
				      (uint8_t **)&transport_payload, &transport_payload_len);

			if (ret == 0) {
				sport = ntohs(tcph->source);
				dport = ntohs(tcph->dest);
			}

		} else if (transport_proto == IPPROTO_UDP) {
			lgtrace_wr("UDP ");
			const struct udphdr *udph = ((const struct udphdr *)ip_payload);
			ret = udp_payload_split((uint8_t *)raw_payload, raw_payload_len,
				      NULL, NULL,
				      (struct udphdr **)&udph,
				      (uint8_t **)&transport_payload, &transport_payload_len);

			if (ret == 0) {
				sport = ntohs(udph->source);
				dport = ntohs(udph->dest);
			}
		}

		lgtrace_wr("%d => %d ", sport, dport);
		lgtrace_write();

		lgtrace_wr("Transport payload: [ ");
		for (int i = 0; i < min((int)16, (int)transport_payload_len); i++) {
			lgtrace_wr("%02x ", transport_payload[i]);
		}
		lgtrace_wr("]");
		lgtrace_write();
	}

	int verdict = PKT_CONTINUE;

	ITER_CONFIG_SECTIONS(config, section) {
		lgtrace_wr("Section #%d: ", CONFIG_SECTION_NUMBER(section));

		switch (transport_proto) {
		case IPPROTO_TCP:
			verdict = process_tcp_packet(section, raw_payload, raw_payload_len);
			break;
		case IPPROTO_UDP:
			verdict = process_udp_packet(section, raw_payload, raw_payload_len);
			break;
		}

		if (verdict == PKT_CONTINUE) {
			lgtrace_wr("continue_flow");
			lgtrace_write();
			continue;
		}

		lgtrace_write();
		goto ret_verdict;
	}

accept:	
	verdict = PKT_ACCEPT;

ret_verdict:

	switch (verdict) {
	case PKT_ACCEPT:
		lgtrace_wr("accept");
		break;
	case PKT_DROP:
		lgtrace_wr("drop");
		break;
	default:
		lgtrace_wr("unknown verdict: %d", verdict);
	}
	lgtrace_end();

	return verdict;
}

int process_tcp_packet(const struct section_config_t *section, const uint8_t *raw_payload, size_t raw_payload_len) {
	const void *ipxh;
	size_t iph_len;
	const struct tcphdr *tcph;
	size_t tcph_len;
	const uint8_t *data;
	size_t dlen;


	int ipxv = netproto_version(raw_payload, raw_payload_len);

	int ret = tcp_payload_split((uint8_t *)raw_payload, raw_payload_len,
			      (void *)&ipxh, &iph_len,
			      (struct tcphdr **)&tcph, &tcph_len,
			      (uint8_t **)&data, &dlen);


	if (ret < 0) {
		return PKT_ACCEPT;
	}

	// As defined by TLS standard.
	if (section->dport_filter && ntohs(tcph->dest) != 443) {
		return PKT_ACCEPT;
	}

	if (tcph->syn && section->synfake) {
		lgtrace_addp("TCP syn alter");

		size_t fake_len = section->fake_sni_pkt_sz;
		if (section->synfake_len) 
			fake_len = min((int)section->synfake_len, (int)fake_len);


		size_t payload_len = iph_len + tcph_len + fake_len;
		uint8_t *payload = malloc(payload_len);
		if (payload == NULL) {
			lgerror(-ENOMEM, "Allocation error");
			return PKT_ACCEPT;
		}

		memcpy(payload, ipxh, iph_len);
		memcpy(payload + iph_len, tcph, tcph_len);	
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


		ret = instance_config.send_raw_packet(payload, payload_len);
		if (ret < 0) {
			lgerror(ret, "send_syn_altered");

			free(payload);
			return PKT_ACCEPT;
		}

		free(payload);
		return PKT_DROP;
	}

	if (tcph->syn) 
		return PKT_CONTINUE;

	if (!section->tls_enabled)
		return PKT_CONTINUE;

	struct tls_verdict vrd = analyze_tls_data(section, data, dlen);
	lgtrace_addp("TLS analyzed");

	if (vrd.sni_len != 0) {
		lgtrace_addp("SNI detected: %.*s", vrd.sni_len, vrd.sni_ptr);
	}

	if (vrd.target_sni) {
		lgdebug("Target SNI detected: %.*s", vrd.sni_len, vrd.sni_ptr);
		size_t target_sni_offset = vrd.target_sni_ptr - data;


		size_t payload_len = raw_payload_len;
		uint8_t *payload = malloc(raw_payload_len);
		if (payload == NULL) {
			lgerror(-ENOMEM, "Allocation error");
			return PKT_ACCEPT;
		}
		memcpy(payload, raw_payload, raw_payload_len);

		void *iph;
		size_t iph_len;
		struct tcphdr *tcph;
		size_t tcph_len;
		uint8_t *data;
		size_t dlen;

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

/*
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
*/
		
		if (dlen > AVAILABLE_MTU) {
			lgdebug("WARNING! Client Hello packet is too big and may cause issues!");
		}

		if (section->fake_sni) {
			post_fake_sni(args_default_fake_type(section), iph, iph_len, tcph, tcph_len);
		}

		size_t ipd_offset;
		size_t mid_offset;

		switch (section->fragmentation_strategy) {
		case FRAG_STRAT_TCP: 
		{
			ipd_offset = target_sni_offset;
			mid_offset = ipd_offset + vrd.target_sni_len / 2;

			// hardcode googlevideo.com split
			// googlevideo domains are very long, so
			// it is possible for the entire domain to not be
			// splitted (split goes for subdomain)
			if (vrd.target_sni_len > 30) {
				mid_offset = ipd_offset + 
					vrd.target_sni_len - 12;
			}

			size_t poses[2];
			int cnt = 0;

			if (section->frag_sni_pos && dlen > section->frag_sni_pos) {
				poses[cnt++] = section->frag_sni_pos;
			}

			if (section->frag_middle_sni) {
				poses[cnt++] = mid_offset;
			}

			if (cnt > 1 && poses[0] > poses[1]) {
				size_t tmp = poses[0];
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
			ipd_offset = ((char *)data - (char *)tcph) + target_sni_offset;
			mid_offset = ipd_offset + vrd.target_sni_len / 2;
			mid_offset += 8 - mid_offset % 8;

			size_t poses[2];
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
				size_t tmp = poses[0];
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
			lginfo("WARNING: IP fragmentation is supported only for IPv4");	
			goto default_send;
		}
		break;
		}

default_send:
		ret = instance_config.send_raw_packet(payload, payload_len);
		if (ret < 0) {
			lgerror(ret, "raw pack send");
			goto accept_lc;
		}

		goto drop_lc;

accept_lc:
		free(payload);
		return PKT_ACCEPT;
drop_lc:
		free(payload);
		return PKT_DROP;
	}

	return PKT_CONTINUE;
}

int process_udp_packet(const struct section_config_t *section, const uint8_t *pkt, size_t pktlen) {
	const void *iph;
	size_t iph_len;
	const struct udphdr *udph;
	const uint8_t *data;
	size_t dlen;

	int ret = udp_payload_split((uint8_t *)pkt, pktlen,
			      (void **)&iph, &iph_len, 
			      (struct udphdr **)&udph,
			      (uint8_t **)&data, &dlen);

	
	if (ret < 0) {
		lgtrace_addp("undefined");
		goto accept;
	}

	if (!detect_udp_filtered(section, pkt, pktlen)) 
		goto continue_flow;

	if (section->udp_mode == UDP_MODE_DROP)
		goto drop;
	else if (section->udp_mode == UDP_MODE_FAKE) {
		for (int i = 0; i < section->udp_fake_seq_len; i++) {
			uint8_t *fake_udp;
			size_t fake_udp_len;

			struct udp_fake_type fake_type = {
				.fake_len = section->udp_fake_len,
				.strategy = {
					.strategy = section->udp_faking_strategy,
					.faking_ttl = section->faking_ttl,
				},
			};
			ret = gen_fake_udp(fake_type, iph, iph_len, udph, &fake_udp, &fake_udp_len);
			if (ret < 0) {
				lgerror(ret, "gen_fake_udp");
				goto erret;
			}

			lgtrace_addp("post fake udp #%d", i + 1);

			ret = instance_config.send_raw_packet(fake_udp, fake_udp_len);
			if (ret < 0) {
				lgerror(ret, "send fake udp");
				goto erret_lc;
			}
						
			free(fake_udp);
			continue;
erret_lc:
			free(fake_udp);
erret:
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

int send_ip4_frags(const struct section_config_t *section, const uint8_t *packet, size_t pktlen, const size_t *poses, size_t poses_sz, size_t dvs) {
	if (poses_sz == 0) {
		lgtrace_addp("raw send packet of %zu bytes with %zu dvs", pktlen, dvs);
		if (section->seg2_delay && ((dvs > 0) ^ section->frag_sni_reverse)) {
			return instance_config.send_delayed_packet(
				packet, pktlen, section->seg2_delay);
		} else {
			return instance_config.send_raw_packet(
				packet, pktlen);
		}
	} else {
		size_t f1len = pktlen;
		uint8_t *frag1 = malloc(f1len);
		if (frag1 == NULL) {
			lgerror(-ENOMEM, "Allocation error");
			return -ENOMEM;
		}

		size_t f2len = pktlen;
		uint8_t *frag2 = malloc(f2len);
		if (frag2 == NULL) {
			lgerror(-ENOMEM, "Allocation error");
			free(frag1);
			return -ENOMEM;
		}

		int ret;

		if (dvs > poses[0]) {
			lgerror(-EINVAL, "send_frags: Recursive dvs(%zu) is more than poses0(%zu)", dvs, poses[0]);
			ret = -EINVAL;
			goto erret_lc;
		}

		size_t frag_pos = poses[0] - dvs;
		frag_pos += 8 - frag_pos % 8;

		ret = ip4_frag(packet, pktlen, frag_pos, 
			frag1, &f1len, frag2, &f2len);

		if (ret < 0) {
			lgerror(ret, "send_frags: frag: with context packet with size %zu, position: %zu, recursive dvs: %zu", pktlen, poses[0], dvs);
			goto erret_lc;
		}

		if (section->frag_sni_reverse)
			goto send_frag2;
send_frag1:
		ret = send_ip4_frags(section, frag1, f1len, NULL, 0, 0);
		if (ret < 0) {
			goto erret_lc;
		}

		if (section->frag_sni_reverse)
			goto out_lc;

send_frag2:
		ret = send_ip4_frags(section, frag2, f2len, poses + 1, poses_sz - 1, poses[0]);
		if (ret < 0) {
			goto erret_lc;
		}

		if (section->frag_sni_reverse)
			goto send_frag1;

out_lc:
		free(frag1);
		free(frag2);
		goto out;
erret_lc:
		free(frag1);
		free(frag2);
		return ret;
	}

out:
	return 0;
}

int send_tcp_frags(const struct section_config_t *section, const uint8_t *packet, size_t pktlen, const size_t *poses, size_t poses_sz, size_t dvs) {
	if (poses_sz == 0) {
		lgtrace_addp("raw send packet of %zu bytes with %zu dvs", pktlen, dvs);
		if (section->seg2_delay && ((dvs > 0) ^ section->frag_sni_reverse)) {
			return instance_config.send_delayed_packet(
				packet, pktlen, section->seg2_delay);
		} else {
			return instance_config.send_raw_packet(
				packet, pktlen);
		}
	} else {
		size_t f1len = pktlen;
		uint8_t *frag1 = malloc(f1len);
		if (frag1 == NULL) {
			lgerror(-ENOMEM, "Allocation error");
			return -ENOMEM;
		}

		size_t f2len = pktlen;
		uint8_t *frag2 = malloc(f2len);
		if (frag2 == NULL) {
			lgerror(-ENOMEM, "Allocation error");
			free(frag1);
			return -ENOMEM;
		}

		int ret;

		if (dvs > poses[0]) {
			lgerror(-EINVAL, "send_frags: Recursive dvs(%zu) is more than poses0(%zu)", dvs, poses[0]);
			ret = -EINVAL;
			goto erret_lc;
		}

		ret = tcp_frag(packet, pktlen, poses[0] - dvs, 
			frag1, &f1len, frag2, &f2len);


		lgtrace_addp("Packet split in %zu bytes position of payload start, dvs: %zu to two packets of %zu and %zu lengths", poses[0], dvs, f1len, f2len);

		if (ret < 0) {
			lgerror(ret, "send_frags: tcp_frag: with context packet with size %zu, position: %zu", pktlen, poses[0]);
			goto erret_lc;
		}


		if (section->frag_sni_reverse)
			goto send_frag2;
		
send_frag1:
		ret = send_tcp_frags(section, frag1, f1len, NULL, 0, 0);
		if (ret < 0) {
			goto erret_lc;
		}

		if (section->frag_sni_reverse) 
			goto out_lc;

send_fake:
		if (section->frag_sni_faked) {
			size_t iphfl, tcphfl;
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
		ret = send_tcp_frags(section, frag2, f2len, poses + 1, poses_sz - 1, poses[0]);
		if (ret < 0) {
			goto erret_lc;
		}

		if (section->frag_sni_reverse)
			goto send_fake;
out_lc:
		free(frag1);
		free(frag2);
		goto out;
erret_lc:
		free(frag1);
		free(frag2);
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
			uint8_t *fake_sni;
			size_t fake_sni_len;
						
			ret = gen_fake_sni(
				fake_seq_type,
				fsiph, iph_len, fstcph, tcph_len, 
				&fake_sni, &fake_sni_len);
			if (ret < 0) {
				lgerror(ret, "gen_fake_sni");
				return ret;
			}

			lgtrace_addp("post fake sni #%d", i + 1);

			if (f_type.seg2delay) {
				ret = instance_config.send_delayed_packet(fake_sni, fake_sni_len, f_type.seg2delay);
			} else {
				ret = instance_config.send_raw_packet(fake_sni, fake_sni_len);
			}
			if (ret < 0) {
				lgerror(ret, "send fake sni");
				goto erret_lc;
			}
			size_t iph_len;
			size_t tcph_len;
			size_t plen;
			ret = tcp_payload_split(
				fake_sni, fake_sni_len, 
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
			
			free(fake_sni);
			continue;
erret_lc:
			free(fake_sni);
			return ret;
		}
	}

	return 0;
}

