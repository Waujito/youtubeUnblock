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

#ifndef YU_MANGLE_H
#define YU_MANGLE_H

#include "types.h"
#include "tls.h"
#include "config.h"
#include "dpi.h"

#define PKT_ACCEPT	0
#define PKT_DROP	1
// Used for section config
#define PKT_CONTINUE	2


/**
 * Sends synfake message
 */
int send_synfake(const struct section_config_t *section, const struct parsed_packet *pkt);


/**
 * Sends fake client hello.
 */
int post_fake_sni(struct fake_type f_type, 
		const void *iph, unsigned int iph_len, 
		const struct tcphdr *tcph, unsigned int tcph_len);

/**
 * Splits packet by poses and posts.
 * Poses are relative to start of TCP payload.
 * dvs used internally and should be zero.
 */
int send_tcp_frags(const struct section_config_t *section,
	const uint8_t *packet, size_t pktlen, 
	const size_t *poses, size_t poses_len, size_t dvs);

/**
 * Splits packet by poses and posts.
 * Poses are relative to start of TCP payload.
 * dvs used internally and should be zero.
 */
int send_ip4_frags(const struct section_config_t *section,
	const uint8_t *packet, size_t pktlen, 
	const size_t *poses, size_t poses_len, size_t dvs);
#endif /* YU_MANGLE_H */
