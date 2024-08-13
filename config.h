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

struct sni_target {
	struct sni_target *next;
	char *sni_str;
	int sni_len;
};

struct config_t {
	unsigned int queue_start_num;
	int threads;
	int use_gso;
	int fragmentation_strategy;
	int frag_sni_reverse;
	int frag_sni_faked;
	int faking_strategy;
	unsigned char faking_ttl;
	int fake_sni;
	unsigned int fake_sni_seq_len;
	int verbose;
	/* In milliseconds */
	unsigned int seg2_delay;
	struct sni_target *sni_targets;
	char *sni_file;
	unsigned int all_domains;
	const char *fake_sni_pkt;
	unsigned int fake_sni_pkt_sz;
	unsigned int fk_winsize;
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

#define RAWSOCKET_MARK (1 << 15)

#ifdef USE_SEG2_DELAY
#define SEG2_DELAY 100
#endif

#define FAKE_TTL 8

// Will invalidate fake packets by out-of-ack_seq out-of-seq request
#define FAKE_STRAT_ACK_SEQ 1
// Will assume that GGC server is located further than FAKE_TTL
// Thus, Fake packet will be eliminated automatically.
#define FAKE_STRAT_TTL 2


#ifndef FAKING_STRATEGY
#define FAKING_STRATEGY FAKE_STRAT_ACK_SEQ
#endif

#if !defined(SILENT) && !defined(KERNEL_SPACE)
#define DEBUG
#endif

// The Maximum Transmission Unit size for rawsocket
// Larger packets will be fragmented. Applicable for Chrome's kyber.
#define AVAILABLE_MTU 1384

#define DEFAULT_QUEUE_NUM 537

#define MAX_PACKET_SIZE 8192

#define MAX_SNI_LEN 128

#endif /* YTB_CONFIG_H */
