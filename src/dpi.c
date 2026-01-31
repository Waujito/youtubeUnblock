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

/**
* dpi.c - Inspects packets for blocked patterns.
* "If you want to bypass the DPI, you should became the DPI"
*/

#define _GNU_SOURCE
#include "types.h" // IWYU pragma: keep
#ifndef KERNEL_SPACE
#include <stdlib.h>
#else
#include "linux/inet.h"
#endif

#include "dpi.h"
#include "config.h"
#include "utils.h"
#include "quic.h"
#include "logging.h"
#include "tls.h"

#include "mangle.h"

int log_packet(const struct parsed_packet *pkt);

#define MAX_FRAGMENTATION_PTS 16

struct fragmentation_points {
	size_t payload_points[16];
	int used_points;
};

int process_packet(const struct config_t *config, const struct packet_data *pd) {
	assert (config);
	assert (pd);

	struct parsed_packet pkt = {0};
	int ret = 0;

	pkt.yct = pd->yct;

	lgtrace_start();	

	pkt.raw_payload = pd->payload;
	pkt.raw_payload_len = pd->payload_len;

	if (pkt.raw_payload_len > MAX_PACKET_SIZE) {
		return PKT_ACCEPT;
	}

	pkt.ipver = netproto_version(pkt.raw_payload, pkt.raw_payload_len);

	lgtrace_wr("IPv%d ", pkt.ipver);

	pkt.transport_proto = -1;
	if (pkt.ipver == IP4VERSION) {
		ret = ip4_payload_split((uint8_t *)pkt.raw_payload, pkt.raw_payload_len,
			 (struct iphdr **)&pkt.iph, &pkt.iph_len,
			 (uint8_t **)&pkt.ip_payload, &pkt.ip_payload_len);

		if (ret < 0)
			goto accept;

		pkt.transport_proto = pkt.iph->protocol;
	} 
#ifndef NO_IPV6
	else if (pkt.ipver == IP6VERSION && config->use_ipv6) {
		ret = ip6_payload_split((uint8_t *)pkt.raw_payload, pkt.raw_payload_len,
			 (struct ip6_hdr **)&pkt.ip6h, &pkt.iph_len,
			 (uint8_t **)&pkt.ip_payload, &pkt.ip_payload_len);


		if (ret < 0)
			goto accept;

		pkt.transport_proto = pkt.ip6h->ip6_nxt;
	} 
#endif

	if (pkt.transport_proto == IPPROTO_TCP) {
		int ret = tcp_payload_split((uint8_t *)pkt.raw_payload, pkt.raw_payload_len,
			      NULL, NULL,
			      (struct tcphdr **)&pkt.tcph, &pkt.tcph_len,
			      (uint8_t **)&pkt.transport_payload, &pkt.transport_payload_len);
		if (ret < 0)
			goto accept;
	} else if (pkt.transport_proto == IPPROTO_UDP) {
		int ret = udp_payload_split((uint8_t *)pkt.raw_payload, pkt.raw_payload_len,
			      NULL, NULL,
			      (struct udphdr **)&pkt.udph,
			      (uint8_t **)&pkt.transport_payload, &pkt.transport_payload_len);

		if (ret < 0)
			goto accept;
	}

	if (LOG_LEVEL >= VERBOSE_TRACE) {
		log_packet(&pkt);
	}

	int verdict = PKT_CONTINUE;

	ITER_CONFIG_SECTIONS(config, section) {
		lgtrace_wr("Section #%d: ", CONFIG_SECTION_NUMBER(section));

		switch (pkt.transport_proto) {
		case IPPROTO_TCP:
			verdict = process_tcp_packet(section, &pkt);
			break;
		case IPPROTO_UDP:
			verdict = process_udp_packet(section, &pkt);
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

enum tls_proc_verdict {
	TLS_NOT_MATCHED,
	TLS_ERROR,
	TLS_MATCHED,
};

enum tls_proc_verdict process_tls_packet(const struct section_config_t *section,
		       const struct parsed_packet *pkt,
		       struct fragmentation_points *frag_pts);


int perform_attack(const struct section_config_t *section,
		   const struct parsed_packet *pkt, const struct fragmentation_points *frag_pts);

int process_tcp_packet(const struct section_config_t *section, const struct parsed_packet *pkt) {
	assert (section);
	assert (pkt);

	assert (pkt->transport_proto == IPPROTO_TCP);

	uint16_t dport = ntohs(pkt->tcph->dest);

	if (section->tcp_dport_range_len) {
		int is_dport_matched = 0;

		for (int i = 0; i < section->tcp_dport_range_len; i++) {
			struct dport_range crange = section->tcp_dport_range[i];
			if (dport >= crange.start && dport <= crange.end) {
				lgtrace_addp("matched to %d-%d", crange.start, crange.end);
				is_dport_matched = 1;
			}
		}

		if (!is_dport_matched) {
			return PKT_CONTINUE;
		}
	} else if (section->dport_filter && dport != 443) {
			return PKT_CONTINUE;
	}

	if (pkt->tcph->syn && section->synfake) {	
		return send_synfake(section, pkt);
	}

	if (pkt->tcph->syn) 
		return PKT_CONTINUE;

	int is_matched = 0;
	struct fragmentation_points frag_pts = {0};

	if (!is_matched && section->tls_enabled) {
		enum tls_proc_verdict vrd = process_tls_packet(section, pkt, &frag_pts);

		if (vrd == TLS_ERROR) {
			return PKT_ACCEPT;
		}

		if (vrd == TLS_MATCHED) {
			is_matched = 1;
		}
	}

	if (!is_matched && section->tcp_match_connpkts && pkt->yct.orig_packets) {
		if (pkt->yct.orig_packets <= section->tcp_match_connpkts) {
			lgtrace_addp("connpackets match: %lu <= %d",
				pkt->yct.orig_packets, section->tcp_match_connpkts);
			is_matched = 1;

			frag_pts.used_points = 0;
			if (section->frag_sni_pos &&
				pkt->transport_payload_len > section->frag_sni_pos) {
				frag_pts.payload_points[frag_pts.used_points++] = 
					section->frag_sni_pos;
				lgtrace_addp("frag set to %d", section->frag_sni_pos);
			}
		}
	}


	if (is_matched) {
		return perform_attack(section, pkt, &frag_pts);
	}

	return PKT_CONTINUE;
}

static void bubblesort(size_t arr[], size_t n){
	for (int i = 0; i < n - 1; i++) {
		for (int j = 0; j < n - 1 - i; j++) {
			if (arr[j] > arr[j + 1]) {
				int temp = arr[j];
				arr[j] = arr[j + 1];
				arr[j + 1] = temp;
			}
		}
	}
}

enum tls_proc_verdict process_tls_packet(const struct section_config_t *section,
		       const struct parsed_packet *pkt,
		       struct fragmentation_points *frag_pts) {
	assert (section);
	assert (pkt);
	

	struct tls_verdict vrd = analyze_tls_data(section,
					   pkt->transport_payload, pkt->transport_payload_len);
	lgtrace_addp("TLS analyzed");

	if (vrd.sni_len != 0) {
		lgtrace_addp("SNI detected: %.*s", vrd.sni_len, vrd.sni_ptr);
	}

	if (vrd.target_sni) {
		lgdebug("Target SNI detected: %.*s", vrd.sni_len, vrd.sni_ptr);
		size_t target_sni_offset = vrd.target_sni_ptr - pkt->transport_payload;

		size_t ipd_offset = target_sni_offset;
		size_t mid_offset = ipd_offset + vrd.target_sni_len / 2;

		// hardcode googlevideo.com split
		// googlevideo domains are very long, so
		// it is possible for the entire domain to not be
		// splitted (split goes for subdomain)
		if (vrd.target_sni_len > 30) {
			mid_offset = ipd_offset + 
				vrd.target_sni_len - 12;
		}

		frag_pts->used_points = 0;

		if (section->frag_sni_pos && pkt->transport_payload_len > section->frag_sni_pos) {
			frag_pts->payload_points[frag_pts->used_points++] = section->frag_sni_pos;
		}

		if (section->frag_middle_sni) {
			frag_pts->payload_points[frag_pts->used_points++] = mid_offset;
		}

		bubblesort(frag_pts->payload_points, frag_pts->used_points);

		return TLS_MATCHED;
	}

	return TLS_NOT_MATCHED;
}

int perform_attack(const struct section_config_t *section,
		   const struct parsed_packet *pkt, const struct fragmentation_points *frag_pts) {
	assert (section);
	assert (pkt);
	assert (frag_pts);

	int ret = 0;

	size_t payload_len = pkt->raw_payload_len;
	uint8_t *payload = malloc(pkt->raw_payload_len);
	if (payload == NULL) {
		lgerror(-ENOMEM, "Allocation error");
		return PKT_ACCEPT;
	}

	memcpy(payload, pkt->raw_payload, pkt->raw_payload_len);

	if (pkt->transport_payload_len > AVAILABLE_MTU) {
		lgdebug("WARNING! Tartget packet is too big and may cause issues!");
	}

	if (section->fake_sni) {
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
	

		struct fake_type f_type = args_default_fake_type(section);
		post_fake_sni(f_type, iph, iph_len, tcph, tcph_len);
	} 


	if (frag_pts->used_points > 0) {
		if (section->fragmentation_strategy == FRAG_STRAT_TCP) {
			ret = send_tcp_frags(section, payload, payload_len, frag_pts->payload_points,
						frag_pts->used_points, 0);
			if (ret < 0) {
				lgerror(ret, "tcp4 send frags");
				goto accept_lc;
			}

			goto drop_lc;
		} else if (section->fragmentation_strategy == FRAG_STRAT_IP && pkt->ipver == IP4VERSION) {
			ret = send_ip4_frags(section, payload, payload_len, frag_pts->payload_points,
						frag_pts->used_points, 0);
			if (ret < 0) {
				lgerror(ret, "tcp4 send frags");
				goto accept_lc;
			}

			goto drop_lc;

		} else if (section->fragmentation_strategy == FRAG_STRAT_IP && pkt->ipver != IP4VERSION) {
			lginfo("WARNING: IP fragmentation is supported only for IPv4");	
			goto accept_lc;
		}
	}


accept_lc:
		free(payload);
		return PKT_ACCEPT;
drop_lc:
		free(payload);
		return PKT_DROP;
}

int process_udp_packet(const struct section_config_t *section, const struct parsed_packet *pkt) {
	assert (section);
	assert (pkt);
	
	assert (pkt->transport_proto == IPPROTO_UDP);

	int ret = 0;

	if (!detect_udp_filtered(section, pkt->raw_payload, pkt->raw_payload_len)) 
		goto continue_flow;

	if (section->udp_mode == UDP_MODE_DROP)
		goto drop;
	else if (section->udp_mode == UDP_MODE_FAKE) {
		for (int i = 0; i < section->udp_fake_seq_len; i++) {
			uint8_t *fake_udp = NULL;
			size_t fake_udp_len = 0;

			struct udp_fake_type fake_type = {
				.fake_len = section->udp_fake_len,
				.strategy = {
					.strategy = section->udp_faking_strategy,
					.faking_ttl = section->faking_ttl,
				},
			};
			ret = gen_fake_udp(fake_type, pkt->iph, pkt->iph_len, pkt->udph,
						&fake_udp, &fake_udp_len);
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

		
		// requeue
		ret = instance_config.send_raw_packet(pkt->raw_payload, pkt->raw_payload_len);
		goto drop;
	}

continue_flow:
	return PKT_CONTINUE;
accept:
	return PKT_ACCEPT;
drop:
	return PKT_DROP;
}
	
int log_packet(const struct parsed_packet *pkt) {
	int ret = 0;

	const char *bpt = inet_ntop(
		pkt->ipver == IP4VERSION ? AF_INET : AF_INET6, 
		pkt->ipver == IP4VERSION ? (void *)(&pkt->iph->saddr) : 
			(void *)(&pkt->ip6h->ip6_src), 
		ylgh_curptr, ylgh_leftbuf); 
	if (bpt != NULL) {
		ret = strnlen(bpt, ylgh_leftbuf);
		ylgh_leftbuf -= ret;
		ylgh_curptr += ret;
	}

	lgtrace_wr(" => ");

	bpt = inet_ntop(
		pkt->ipver == IP4VERSION ? AF_INET : AF_INET6, 
		pkt->ipver == IP4VERSION ? (void *)(&pkt->iph->daddr) : 
			(void *)(&pkt->ip6h->ip6_dst),  
		ylgh_curptr, ylgh_leftbuf); 
	if (bpt != NULL) {
		ret = strnlen(bpt, ylgh_leftbuf);
		ylgh_leftbuf -= ret;
		ylgh_curptr += ret;

	}
	
	lgtrace_wr(" ");
	int sport = -1, dport = -1;

	if (pkt->transport_proto == IPPROTO_TCP) {
		lgtrace_wr("TCP ");

		sport = ntohs(pkt->tcph->source);
		dport = ntohs(pkt->tcph->dest);

	} else if (pkt->transport_proto == IPPROTO_UDP) {
		lgtrace_wr("UDP ");

		sport = ntohs(pkt->udph->source);
		dport = ntohs(pkt->udph->dest);
	}

	lgtrace_wr("%d => %d ", sport, dport);
	lgtrace_write();

	lgtrace_wr("Transport payload: [ ");
	for (int i = 0; i < min((int)16, (int)pkt->transport_payload_len); i++) {
		lgtrace_wr("%02x ", pkt->transport_payload[i]);
	}
	lgtrace_wr("]");
	lgtrace_write();
}
