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

#ifndef TLS_H
#define TLS_H

#include "types.h"
#include "utils.h"


/**
 * Result of analyze_tls_data function
 */
struct tls_verdict {
	const uint8_t *sni_ptr;
	int sni_len;

	int target_sni; /* boolean, 1 if target found */
	const uint8_t *target_sni_ptr; /* pointer to target domain instead of entire sni */
	int target_sni_len; /* length of target domain instead of entire sni */
};

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_EXTENSION_SNI 0x0000
#define TLS_EXTENSION_CLIENT_HELLO_ENCRYPTED 0xfe0d

#define TLS_MESSAGE_ANALYZE_INVALID	-1
#define TLS_MESSAGE_ANALYZE_FOUND	0
#define TLS_MESSAGE_ANALYZE_GOTO_NEXT	1

/**
 * Analyzes each TLS Client Hello message (inside TLS Record or QUIC CRYPTO FRAME)
 */
int analyze_tls_message(
	const struct section_config_t *section,
	const uint8_t *message_data, 
	size_t message_length,
	struct tls_verdict *tlsv
);

/**
 * Tries to bruteforce over the packet and match domains as plain text
 */
int bruteforce_analyze_sni_str(
	const struct section_config_t *section,
	const uint8_t *data, size_t dlen,
	struct tls_verdict *vrd
);


/**
 * Processes the packet and finds TLS Client Hello information inside it.
 * data pointer points to start of TLS Message (TCP Payload)
 *
 * Note that all the constant pointers of tls_verdict will be relative to data pointer
 */
struct tls_verdict analyze_tls_data(const struct section_config_t *section, const uint8_t *data, size_t dlen);


/**
 * Generates the fake client hello message
 */
int gen_fake_sni(struct fake_type type,
		const void *iph, size_t iph_len, 
		const struct tcphdr *tcph, size_t tcph_len, 
		uint8_t *buf, size_t *buflen);

#endif /* TLS_H */
