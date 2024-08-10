
struct config_t {
	unsigned int queue_start_num;
	int rawsocket;
	int threads;
	int use_gso;
	int fragmentation_strategy;
	unsigned char fake_sni_ttl;
	int  fake_sni_strategy;
	int verbose;
	unsigned int seg2_delay;
	const char *domains_str;
	unsigned int domains_strlen;
	unsigned int all_domains;
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

#define FAKE_SNI_TTL 8

// No fake SNI
#define FKSN_STRAT_NONE 0
// Will invalidate fake client hello by out-of-ack_seq out-of-seq request
#define FKSN_STRAT_ACK_SEQ 1
// Will assume that GGC server is located further than FAKE_SNI_TTL
// Thus, Fake Client Hello will be eliminated automatically.
#define FKSN_STRAT_TTL 2


#ifdef NO_FAKE_SNI
#define FAKE_SNI_STRATEGY FKSN_STRAT_NONE
#endif

#ifndef FAKE_SNI_STRATEGY
#define FAKE_SNI_STRATEGY FKSN_STRAT_ACK_SEQ
#endif

#if !defined(SILENT) && !defined(KERNEL_SPACE)
#define DEBUG
#endif

// The Maximum Transmission Unit size for rawsocket
// Larger packets will be fragmented. Applicable for Chrome's kyber.
#define AVAILABLE_MTU 1384

#define DEFAULT_QUEUE_NUM 537

static const char defaul_snistr[] = "googlevideo.com,ggpht.com,ytimg.com,youtube.com,play.google.com,youtu.be,googleapis.com,googleusercontent.com,gstatic.com,l.google.com";
