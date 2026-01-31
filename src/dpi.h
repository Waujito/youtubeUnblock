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

#ifndef YU_DPI_H
#define YU_DPI_H

#include "types.h"
#include "tls.h"
#include "config.h"

#define PKT_ACCEPT	0
#define PKT_DROP	1
// Used for section config
#define PKT_CONTINUE	2

struct parsed_packet {
	const uint8_t *raw_payload;
	uint32_t raw_payload_len;

	int ipver;
	union {
		void *ipxh;
		const struct iphdr *iph;

#ifndef NO_IPV6
		const struct ip6_hdr *ip6h;
#endif
	};
	size_t iph_len;

	const uint8_t *ip_payload;
	size_t ip_payload_len;

	int transport_proto;
	union {
		struct {
			const struct tcphdr *tcph;
			size_t tcph_len;
		};
		struct {
			const struct udphdr *udph;
		};
	};

	const uint8_t *transport_payload;
	size_t transport_payload_len;

	struct ytb_conntrack yct;
};

/**
 * Processes the packet and returns verdict.
 * This is the primary function that traverses the packet.
 */
int process_packet(const struct config_t *config, const struct packet_data *pd);


/**
 * Processe the TCP packet.
 * Returns verdict.
 */
int process_tcp_packet(const struct section_config_t *section, const struct parsed_packet *pkt);


/**
 * Processes the UDP packet.
 * Returns verdict.
 */
int process_udp_packet(const struct section_config_t *section, const struct parsed_packet *pkt);

#endif /* DPI_H */
