#ifndef YTB_CONFIG_H
#define YTB_CONFIG_H

typedef int (*raw_send_t)(const unsigned char *data, unsigned int data_len);
/**
 * Sends the packet after delay_ms. The function should schedule send and return immediately
 * (for example, open daemon thread)
 */
typedef void (*delayed_send_t)(const unsigned char *data, unsigned int data_len, unsigned int delay_ms);

struct instance_config_t {
	raw_send_t send_raw_packet;
	delayed_send_t send_delayed_packet;
};
extern struct instance_config_t instance_config;

struct config_t {
	unsigned int queue_start_num;
	int threads;
	int use_gso;
	int use_ipv6;
	int fragmentation_strategy;
	int frag_sni_reverse;
	int frag_sni_faked;
	int faking_strategy;
	int frag_middle_sni;
	int frag_sni_pos;
	unsigned char faking_ttl;
	int fake_sni;
	unsigned int fake_sni_seq_len;
#define VERBOSE_INFO	0
#define VERBOSE_DEBUG	1
#define VERBOSE_TRACE	2
	int verbose;
	int quic_drop;
#define SNI_DETECTION_PARSE 0
#define SNI_DETECTION_BRUTE 1
	int sni_detection;
	/* In milliseconds */
	unsigned int seg2_delay;
	const char *domains_str;
	unsigned int domains_strlen;
	const char *exclude_domains_str;
	unsigned int exclude_domains_strlen;
	unsigned int all_domains;
	const char *fake_sni_pkt;
	unsigned int fake_sni_pkt_sz;
	unsigned int fk_winsize;
	unsigned int fakeseq_offset;
	unsigned int mark;
	int synfake;
	unsigned int synfake_len;
};

extern struct config_t config;

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

// Will invalidate fake packets by out-of-ack_seq out-of-seq request
#define FAKE_STRAT_RAND_SEQ	1
// Will assume that GGC server is located further than FAKE_TTL
// Thus, Fake packet will be eliminated automatically.
#define FAKE_STRAT_TTL		2
#define FAKE_STRAT_PAST_SEQ	3
#define FAKE_STRAT_TCP_CHECK	4
#define FAKE_STRAT_TCP_MD5SUM	5


#ifndef FAKING_STRATEGY
#define FAKING_STRATEGY FAKE_STRAT_PAST_SEQ
#endif

#if !defined(SILENT) && !defined(KERNEL_SPACE)
#define DEBUG
#endif

// The Maximum Transmission Unit size for rawsocket
// Larger packets will be fragmented. Applicable for Chrome's kyber.
#define AVAILABLE_MTU 1500

#define DEFAULT_QUEUE_NUM 537

#define MAX_PACKET_SIZE 8192

static const char defaul_snistr[] = "googlevideo.com,ggpht.com,ytimg.com,youtube.com,play.google.com,youtu.be,googleapis.com,googleusercontent.com,gstatic.com,l.google.com";

#endif /* YTB_CONFIG_H */
