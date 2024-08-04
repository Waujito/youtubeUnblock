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

#if !defined(SILENT) && !defined(KERNEL_SPACE)
#define DEBUG
#endif

