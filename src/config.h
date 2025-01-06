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

#ifndef YTB_CONFIG_H
#define YTB_CONFIG_H

#ifndef KERNEL_SPACE
#define USER_SPACE
#endif

#include "types.h"

typedef int (*raw_send_t)(const unsigned char *data, size_t data_len);
/**
 * Sends the packet after delay_ms. The function should schedule send and return immediately
 * (for example, open daemon thread)
 */
typedef int (*delayed_send_t)(const unsigned char *data, size_t data_len, unsigned int delay_ms);

struct instance_config_t {
	raw_send_t send_raw_packet;
	delayed_send_t send_delayed_packet;
};
extern struct instance_config_t instance_config;

struct udp_dport_range {
	uint16_t start;
	uint16_t end;
};

struct domains_list {
	char *domain_name;
	uint16_t domain_len;

	struct domains_list *next;
};

struct section_config_t {
	int id;
	struct section_config_t *next;
	struct section_config_t *prev;

	struct domains_list *sni_domains;
	struct domains_list *exclude_sni_domains;
	unsigned int all_domains;

	int tls_enabled;

	int fragmentation_strategy;
	int frag_sni_reverse;
	int frag_sni_faked;
	int faking_strategy;
	int frag_middle_sni;
	int frag_sni_pos;
	unsigned char faking_ttl;
	int fake_sni;
	unsigned int fake_sni_seq_len;

#define FAKE_PAYLOAD_RANDOM	0
#define FAKE_PAYLOAD_CUSTOM	1
// In default mode all other options will be skipped.
#define FAKE_PAYLOAD_DEFAULT	2
	int fake_sni_type;

	/* In milliseconds */
	unsigned int seg2_delay;
	int synfake;
	unsigned int synfake_len;

	const char *fake_sni_pkt;
	unsigned int fake_sni_pkt_sz;

	char *fake_custom_pkt;
	unsigned int fake_custom_pkt_sz;

	unsigned int fk_winsize;
	int fakeseq_offset;

#define SNI_DETECTION_PARSE 0
#define SNI_DETECTION_BRUTE 1
	int sni_detection;

	int udp_mode;
	unsigned int udp_fake_seq_len;
	unsigned int udp_fake_len;
	int udp_faking_strategy;

	struct udp_dport_range *udp_dport_range;
	int udp_dport_range_len;
	int udp_filter_quic;
};

#define MAX_CONFIGLIST_LEN 64

struct config_t {
	unsigned int queue_start_num;
	int threads;
	int use_gso;
	int use_ipv6;
	unsigned int mark;
	int daemonize;
	// Same as daemon() noclose
	int noclose;
	int syslog;
	int instaflush;

	int connbytes_limit;

#define VERBOSE_INFO	0
#define VERBOSE_DEBUG	1
#define VERBOSE_TRACE	2
	int verbose;

	struct section_config_t *first_section;
	struct section_config_t *last_section;
};

extern struct config_t config;

#define ITER_CONFIG_SECTIONS(config, section) \
for (struct section_config_t *section = (config)->last_section; section != NULL; section = section->prev)

#define CONFIG_SECTION_NUMBER(section) ((section)->id)

#define MAX_THREADS 16

#ifndef THREADS_NUM
#define THREADS_NUM 1
#endif

#if THREADS_NUM > MAX_THREADS
#error "Too much threads"
#endif

#ifndef NOUSE_GSO
#define USE_GSO
#endif

#define FRAG_STRAT_TCP	0
#define FRAG_STRAT_IP	1
#define FRAG_STRAT_NONE	2

#ifndef FRAGMENTATION_STRATEGY
#define FRAGMENTATION_STRATEGY FRAG_STRAT_TCP
#endif

#define DEFAULT_RAWSOCKET_MARK (1 << 15)

#ifdef USE_SEG2_DELAY
#define SEG2_DELAY 100
#endif

#define FAKE_TTL 8

#define FAKE_STRAT_NONE		0
// Will invalidate fake packets by out-of-ack_seq out-of-seq request
#define FAKE_STRAT_RAND_SEQ	(1 << 0)
// Will assume that GGC server is located further than FAKE_TTL
// Thus, Fake packet will be eliminated automatically.
#define FAKE_STRAT_TTL		(1 << 1)
#define FAKE_STRAT_PAST_SEQ	(1 << 2)
#define FAKE_STRAT_TCP_CHECK	(1 << 3)
#define FAKE_STRAT_TCP_MD5SUM	(1 << 4)
#define FAKE_STRAT_UDP_CHECK	(1 << 5)

#define FAKE_STRAT_COUNT	6

/**
 * This macros iterates through all faking strategies and executes code under it.
 * destination strategy will be available under name of `strategy` variable.
 */
#define ITER_FAKE_STRAT(fake_bitmask, strategy) \
for (int strategy = 1; strategy <= (1 << FAKE_STRAT_COUNT); strategy <<= 1) \
if ((fake_bitmask) & strategy) 

#ifndef FAKING_STRATEGY
#define FAKING_STRATEGY FAKE_STRAT_PAST_SEQ
#endif

#define MAX_FAKE_SIZE 1300

#if !defined(SILENT) && !defined(KERNEL_SPACE)
#define DEBUG
#endif

// The Maximum Transmission Unit size for rawsocket
// Larger packets will be fragmented. Applicable for Chrome's kyber.
#define AVAILABLE_MTU 1400

#define DEFAULT_QUEUE_NUM 537

#define MAX_PACKET_SIZE 8192

#define DEFAULT_SNISTR "googlevideo.com,ggpht.com,ytimg.com,youtube.com,play.google.com,youtu.be,youtubei.googleapis.com,youtube.googleapis.com,youtubeembeddedplayer.googleapis.com,googleusercontent.com,gstatic.com,l.google.com"

static const char default_snistr[] = DEFAULT_SNISTR;

enum {
	UDP_MODE_DROP,
	UDP_MODE_FAKE,
};

enum {
	UDP_FILTER_QUIC_DISABLED,
	UDP_FILTER_QUIC_ALL,
	UDP_FILTER_QUIC_PARSED,
};

#define default_section_config {				\
	.sni_domains = NULL,					\
	.exclude_sni_domains = NULL,				\
	.all_domains = 0,					\
	.tls_enabled = 1,					\
	.frag_sni_reverse = 1,                                  \
	.frag_sni_faked = 0,                                    \
	.fragmentation_strategy = FRAGMENTATION_STRATEGY,       \
	.faking_strategy = FAKING_STRATEGY,                     \
	.faking_ttl = FAKE_TTL,                                 \
	.fake_sni = 1,                                          \
	.fake_sni_seq_len = 1,                                  \
	.fake_sni_type = FAKE_PAYLOAD_DEFAULT,                  \
	.fake_custom_pkt = NULL,				\
	.fake_custom_pkt_sz = 0,				\
	.frag_middle_sni = 1,                                   \
	.frag_sni_pos = 1,                                      \
	.fakeseq_offset = 10000,                                \
	.synfake = 0,                                           \
	.synfake_len = 0,                                       \
                                                                \
	.seg2_delay = 0,                                        \
                                                                \
	.sni_detection = SNI_DETECTION_PARSE,                   \
								\
	.udp_mode = UDP_MODE_FAKE,				\
	.udp_fake_seq_len = 6,					\
	.udp_fake_len = 64,					\
	.udp_faking_strategy = FAKE_STRAT_NONE,			\
	.udp_dport_range = NULL,				\
	.udp_dport_range_len = 0,				\
	.udp_filter_quic = UDP_FILTER_QUIC_DISABLED,		\
								\
	.prev	= NULL,						\
	.next	= NULL,						\
	.id	= 0,						\
}

#define default_config_set {					\
	.threads = THREADS_NUM,					\
	.queue_start_num = DEFAULT_QUEUE_NUM,                   \
	.mark = DEFAULT_RAWSOCKET_MARK,                         \
	.use_ipv6 = 1,                                          \
	.connbytes_limit = 8,                                   \
                                                                \
	.verbose = VERBOSE_DEBUG,                               \
	.use_gso = 1,                                           \
                                                                \
	.first_section = NULL,					\
	.last_section = NULL,					\
                                                                \
	.daemonize = 0,                                         \
	.noclose = 0,                                           \
	.syslog = 0,                                            \
	.instaflush = 0,                                        \
}

#define CONFIG_SET(config)			\
struct config_t config = default_config_set;	\
config->last_section = &(config.default_config) \


struct ytb_conntrack {
	uint32_t mask;

	uint64_t orig_packets;
	uint64_t repl_packets;
	uint64_t orig_bytes;
	uint64_t repl_bytes;
	uint32_t connmark;
	uint32_t id;
};

enum yct_attrs {
	YCTATTR_ORIG_PACKETS,
	YCTATTR_REPL_PACKETS,
	YCTATTR_ORIG_BYTES,
	YCTATTR_REPL_BYTES,
	YCTATTR_CONNMARK,
	YCTATTR_CONNID,
};
/* enum yct_attrs attr, struct ytb_conntrack * yct */
#define yct_set_mask_attr(attr, yct) \
	((yct)->mask |= (1 << (attr)))

/* enum yct_attrs attr, const struct ytb_conntrack * yct */
#define yct_is_mask_attr(attr, yct) \
	(((yct)->mask & (1 << (attr))) == (1 << (attr)))

/* enum yct_attrs attr, struct ytb_conntrack * yct */
#define yct_del_mask_attr(attr, yct) \
	(yct)->mask &= ~(1 << (attr))


struct packet_data {
	const uint8_t *payload;
	size_t payload_len;
	struct ytb_conntrack yct;
};

#endif /* YTB_CONFIG_H */
