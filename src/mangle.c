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
#include "dpi.h"

#ifndef KERNEL_SPACE
#include <stdlib.h>
#else
#include "linux/inet.h"
#endif

int send_synfake(const struct section_config_t *section, const struct parsed_packet *pkt) {
	assert (section);
	assert (pkt);

	assert (pkt->transport_proto == IPPROTO_TCP);
	assert (pkt->tcph->syn);

	lgtrace_addp("TCP syn alter");

	size_t fake_len = section->fake_sni_pkt_sz;
	if (section->synfake_len) 
		fake_len = min((int)section->synfake_len, (int)fake_len);


	size_t payload_len = pkt->iph_len + pkt->tcph_len + fake_len;
	uint8_t *payload = malloc(payload_len);
	if (payload == NULL) {
		lgerror(-ENOMEM, "Allocation error");
		return PKT_ACCEPT;
	}

	memcpy(payload, pkt->ipxh, pkt->iph_len);
	memcpy(payload + pkt->iph_len, pkt->tcph, pkt->tcph_len);	
	memcpy(payload + pkt->iph_len + pkt->tcph_len, section->fake_sni_pkt, fake_len);

	struct tcphdr *tcph = (struct tcphdr *)(payload + pkt->iph_len);
	if (pkt->ipver == IP4VERSION) {
		struct iphdr *iph = (struct iphdr *)payload;
		iph->tot_len = htons(pkt->iph_len + pkt->tcph_len + fake_len);
		set_ip_checksum(payload, pkt->iph_len);
		set_tcp_checksum(tcph, iph, pkt->iph_len);
	} else if (pkt->ipver == IP6VERSION) {
		struct ip6_hdr *ip6h = (struct ip6_hdr *)payload;
		ip6h->ip6_plen = ntohs(pkt->tcph_len + fake_len);
		set_ip_checksum(ip6h, pkt->iph_len);
		set_tcp_checksum(tcph, ip6h, pkt->iph_len);
	}

	int ret = instance_config.send_raw_packet(payload, payload_len);
	if (ret < 0) {
		lgerror(ret, "send_syn_altered");

		free(payload);
		return PKT_ACCEPT;
	}

	free(payload);
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
		if (section->seg2_delay) {// && ((dvs > 0) ^ section->frag_sni_reverse)) {
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

	struct fake_type fake_seq_type = f_type;

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


		if (!(CHECK_BITFIELD(f_type.strategy.strategy, FAKE_STRAT_PAST_SEQ) ||
			CHECK_BITFIELD(f_type.strategy.strategy, FAKE_STRAT_RAND_SEQ))) {
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

	return 0;
}

