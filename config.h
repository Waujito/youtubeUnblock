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

#define FRAGMENTATION_STRATEGY FRAG_STRAT_TCP

#if FRAGMENTATION_STRATEGY == FRAG_STRAT_TCP
	#define USE_TCP_SEGMENTATION
#elif FRAGMENTATION_STRATEGY == FRAG_STRAT_IP
	#define USE_IP_FRAGMENTATION
#elif FRAGMENTATION_STRATEGY == FRAG_STRAT_NONE
	#define USE_NO_FRAGMENTATION
#endif 

#define RAWSOCKET_MARK (1 << 15)

#ifdef USE_SEG2_DELAY
#define SEG2_DELAY 100
#endif

#ifndef NO_FAKE_SNI
#define FAKE_SNI
#endif

#define FAKE_SNI_TTL 8

// Will invalidate fake client hello by out-of-ack_seq out-of-seq request
#define FKSN_STRAT_ACK_SEQ 0
// Will assume that GGC server is located further than FAKE_SNI_TTL
// Thus, Fake Client Hello will be eliminated automatically.
#define FKSN_STRAT_TTL 1

#define FAKE_SNI_STRATEGY FKSN_STRAT_ACK_SEQ

#if !defined(SILENT) && !defined(KERNEL_SPACE)
#define DEBUG
#endif

