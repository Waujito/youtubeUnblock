#include "config.h"
#include "raw_replacements.h"
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>


struct config_t config = {
	.threads = THREADS_NUM,
	.frag_sni_reverse = 1,
	.frag_sni_faked = 0,
	.fragmentation_strategy = FRAGMENTATION_STRATEGY,
	.faking_strategy = FAKING_STRATEGY,
	.faking_ttl = FAKE_TTL,
	.fake_sni = 1,
	.fake_sni_seq_len = 1,
	.frag_middle_sni = 1,
	.frag_sni_pos = 1,
	.use_ipv6 = 1,
	.fakeseq_offset = 10000,
	.mark = DEFAULT_RAWSOCKET_MARK,
	.synfake = 0,
	.synfake_len = 0,

	.sni_detection = SNI_DETECTION_PARSE,

#ifdef SEG2_DELAY
	.seg2_delay = SEG2_DELAY,
#else
	.seg2_delay = 0,
#endif

#ifdef USE_GSO
	.use_gso = true,
#else
	.use_gso = false,
#endif

#ifdef DEBUG
	.verbose = 1,
#else
	.verbose = 0,
#endif

	.domains_str = defaul_snistr,
	.domains_strlen = sizeof(defaul_snistr),

	.exclude_domains_str = "",
	.exclude_domains_strlen = 0,

	.queue_start_num = DEFAULT_QUEUE_NUM,
	.fake_sni_pkt = fake_sni_old,
	.fake_sni_pkt_sz = sizeof(fake_sni_old) - 1, // - 1 for null-terminator
};

#define OPT_SNI_DOMAINS		1
#define OPT_EXCLUDE_DOMAINS	25
#define OPT_FAKE_SNI 		2
#define OPT_FAKING_TTL		3
#define OPT_FAKING_STRATEGY	10
#define OPT_FAKE_SNI_SEQ_LEN	11
#define OPT_FRAG    		4
#define OPT_FRAG_SNI_REVERSE	12
#define OPT_FRAG_SNI_FAKED	13
#define OPT_FRAG_MIDDLE_SNI	18
#define OPT_FRAG_SNI_POS	19
#define OPT_FK_WINSIZE		14
#define OPT_TRACE		15
#define OPT_QUIC_DROP		16
#define OPT_SNI_DETECTION	17
#define OPT_NO_IPV6		20
#define OPT_FAKE_SEQ_OFFSET	21
#define OPT_PACKET_MARK 	22
#define OPT_SYNFAKE	 	23
#define OPT_SYNFAKE_LEN	 	24
#define OPT_SEG2DELAY 		5
#define OPT_THREADS 		6
#define OPT_SILENT 		7
#define OPT_NO_GSO 		8
#define OPT_QUEUE_NUM		9

#define OPT_MAX OPT_SNI_DOMAINS

static struct option long_opt[] = {
	{"help",		0, 0, 'h'},
	{"version",		0, 0, 'v'},
	{"sni-domains",		1, 0, OPT_SNI_DOMAINS},
	{"exclude-domains",	1, 0, OPT_EXCLUDE_DOMAINS},
	{"fake-sni",		1, 0, OPT_FAKE_SNI},
	{"synfake",		1, 0, OPT_SYNFAKE},
	{"synfake-len",		1, 0, OPT_SYNFAKE_LEN},
	{"fake-sni-seq-len",	1, 0, OPT_FAKE_SNI_SEQ_LEN},
	{"faking-strategy",	1, 0, OPT_FAKING_STRATEGY},
	{"fake-seq-offset",	1, 0, OPT_FAKE_SEQ_OFFSET},
	{"faking-ttl",		1, 0, OPT_FAKING_TTL},
	{"frag",		1, 0, OPT_FRAG},
	{"frag-sni-reverse",	1, 0, OPT_FRAG_SNI_REVERSE},
	{"frag-sni-faked",	1, 0, OPT_FRAG_SNI_FAKED},
	{"frag-middle-sni",	1, 0, OPT_FRAG_MIDDLE_SNI},
	{"frag-sni-pos",	1, 0, OPT_FRAG_SNI_POS},
	{"fk-winsize",		1, 0, OPT_FK_WINSIZE},
	{"quic-drop",		0, 0, OPT_QUIC_DROP},
	{"sni-detection",	1, 0, OPT_SNI_DETECTION},
	{"seg2delay",		1, 0, OPT_SEG2DELAY},
	{"threads",		1, 0, OPT_THREADS},
	{"silent",		0, 0, OPT_SILENT},
	{"trace",		0, 0, OPT_TRACE},
	{"no-gso",		0, 0, OPT_NO_GSO},
	{"no-ipv6",		0, 0, OPT_NO_IPV6},
	{"queue-num",		1, 0, OPT_QUEUE_NUM},
	{"packet-mark",		1, 0, OPT_PACKET_MARK},
	{0,0,0,0}
};

static long parse_numeric_option(const char* value) {
	errno = 0;

	if (*value == '\0') {
		errno = EINVAL;
		return 0;
	}

	char* end;
	long result = strtol(value, &end, 10);
	if (*end != '\0') {
		errno = EINVAL;
		return 0;
	}

	return result;
}

void print_version() {
  	printf("youtubeUnblock\n");	
	printf("Bypasses deep packet inspection systems that relies on SNI\n");
	printf("\n");
}

void print_usage(const char *argv0) {
	print_version();

	printf("Usage: %s [ OPTIONS ] \n", argv0);
	printf("Options:\n");
	printf("\t--queue-num=<number of netfilter queue>\n");
	printf("\t--sni-domains=<comma separated domain list>|all\n");
	printf("\t--exclude-domains=<comma separated domain list>\n");
	printf("\t--fake-sni={1|0}\n");
	printf("\t--fake-sni-seq-len=<length>\n");
	printf("\t--fake-seq-offset=<offset>\n");
	printf("\t--faking-ttl=<ttl>\n");
	printf("\t--faking-strategy={randseq|ttl|tcp_check|pastseq}\n");
	printf("\t--synfake={1|0}\n");
	printf("\t--synfake-len=<len>\n");
	printf("\t--frag={tcp,ip,none}\n");
	printf("\t--frag-sni-reverse={0|1}\n");
	printf("\t--frag-sni-faked={0|1}\n");
	printf("\t--frag-middle-sni={0|1}\n");
	printf("\t--frag-sni-pos=<pos>\n");
	printf("\t--fk-winsize=<winsize>\n");
	printf("\t--quic-drop\n");
	printf("\t--sni-detection={parse|brute}\n");
	printf("\t--seg2delay=<delay>\n");
	printf("\t--threads=<threads number>\n");
	printf("\t--packet-mark=<mark>\n");
	printf("\t--silent\n");
	printf("\t--trace\n");
	printf("\t--no-gso\n");
	printf("\t--no-ipv6\n");
	printf("\n");
}

int parse_args(int argc, char *argv[]) {
  	int opt;
	int optIdx;
	long num;

	while ((opt = getopt_long(argc, argv, "hv", long_opt, &optIdx)) != -1) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			goto stop_exec;
		case 'v':
			print_version();
			goto stop_exec;
		case OPT_TRACE:
			config.verbose = 2;
			break;
		case OPT_SILENT:
			config.verbose = 0;
			break;
		case OPT_NO_GSO:
			config.use_gso = 0;
			break;
		case OPT_NO_IPV6:
			config.use_ipv6 = 0;
			break;
		case OPT_QUIC_DROP:
			config.quic_drop = 1;
			break;
		case OPT_SNI_DOMAINS:
			if (!strcmp(optarg, "all")) {
				config.all_domains = 1;
			}

			config.domains_str = optarg;
			config.domains_strlen = strlen(config.domains_str);
			break;
		case OPT_EXCLUDE_DOMAINS:
			config.exclude_domains_str = optarg;
			config.exclude_domains_strlen = strlen(config.exclude_domains_str);
			break;
		case OPT_SNI_DETECTION:
			if (strcmp(optarg, "parse") == 0) {
				config.sni_detection = SNI_DETECTION_PARSE;
			} else if (strcmp(optarg, "brute") == 0) {
				config.sni_detection = SNI_DETECTION_BRUTE;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG:
			if (strcmp(optarg, "tcp") == 0) {
				config.fragmentation_strategy = FRAG_STRAT_TCP;
			} else if (strcmp(optarg, "ip") == 0) {
				config.fragmentation_strategy = FRAG_STRAT_IP;
			} else if (strcmp(optarg, "none") == 0) {
				config.fragmentation_strategy = FRAG_STRAT_NONE;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG_SNI_FAKED:
			if (strcmp(optarg, "1") == 0) {
				config.frag_sni_faked = 1;
			} else if (strcmp(optarg, "0") == 0) {
				config.frag_sni_faked = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG_SNI_REVERSE:
			if (strcmp(optarg, "1") == 0) {
				config.frag_sni_reverse = 1;
			} else if (strcmp(optarg, "0") == 0) {
				config.frag_sni_reverse = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG_MIDDLE_SNI:
			if (strcmp(optarg, "1") == 0) {
				config.frag_middle_sni = 1;
			} else if (strcmp(optarg, "0") == 0) {
				config.frag_middle_sni = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG_SNI_POS:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.frag_sni_pos = num;
			break;
		case OPT_FAKING_STRATEGY:
			if (strcmp(optarg, "randseq") == 0) {
				config.faking_strategy = FAKE_STRAT_RAND_SEQ;
			} else if (strcmp(optarg, "ttl") == 0) {
				config.faking_strategy = FAKE_STRAT_TTL;
			} else if (strcmp(optarg, "tcp_check") == 0) {
				config.faking_strategy = FAKE_STRAT_TCP_CHECK;
			} else if (strcmp(optarg, "pastseq") == 0) {
				config.faking_strategy = FAKE_STRAT_PAST_SEQ;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FAKING_TTL:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0 || num > 255) {
				goto invalid_opt;
			}

			config.faking_ttl = num;
			break;
		case OPT_FAKE_SEQ_OFFSET:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.fakeseq_offset = num;
			break;
		case OPT_FAKE_SNI:
			if (strcmp(optarg, "1") == 0) {
				config.fake_sni = 1;				
			} else if (strcmp(optarg, "0") == 0) {
				config.fake_sni = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FAKE_SNI_SEQ_LEN:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0 || num > 255) {
				goto invalid_opt;
			}

			config.fake_sni_seq_len = num;
			break;
		case OPT_FK_WINSIZE:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.fk_winsize = num;
			break;
		case OPT_SYNFAKE:
			if (strcmp(optarg, "1") == 0) {
				config.synfake = 1;
			} else if (strcmp(optarg, "0") == 0) {
				config.synfake = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_SYNFAKE_LEN:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.synfake_len = num;
			break;
		case OPT_SEG2DELAY:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.seg2_delay = num;
			break;
		case OPT_THREADS:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0 || num > MAX_THREADS) {
				goto invalid_opt;
			}

			config.threads = num;
			break;
		case OPT_QUEUE_NUM:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.queue_start_num = num;
			break;
		case OPT_PACKET_MARK:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.mark = num;
			break;

		default:
			goto error;
		}
	}


// out:
	errno = 0;
	return 0;
stop_exec:
	errno = 0;
	return 1;

invalid_opt:
	printf("Invalid option %s\n", long_opt[optIdx].name);
error:
	print_usage(argv[0]);
	errno = EINVAL;
	return -1;
}

void print_welcome() {
	switch (config.fragmentation_strategy) {
		case FRAG_STRAT_TCP:
			printf("Using TCP segmentation\n");
			break;
		case FRAG_STRAT_IP:
			printf("Using IP fragmentation\n");
			break;
		default:
			printf("SNI fragmentation is disabled\n");
			break;
	}

	if (config.seg2_delay) {
		printf("Some outgoing googlevideo request segments will be delayed for %d ms as of seg2_delay define\n", config.seg2_delay);
	}

	if (config.fake_sni) {
		printf("Fake SNI will be sent before each target client hello\n");
	} else {
		printf("Fake SNI is disabled\n");
	}

	if (config.frag_sni_reverse) {
		printf("Fragmentation Client Hello will be reversed\n");
	}

	if (config.frag_sni_faked) {
		printf("Fooling packets will be sent near the original Client Hello\n");
	}

	if (config.fake_sni_seq_len > 1) {
		printf("Faking sequence of length %d will be built as fake sni\n", config.fake_sni_seq_len);
	}

	switch (config.faking_strategy) {
		case FAKE_STRAT_TTL:
			printf("TTL faking strategy will be used with TTL %d\n", config.faking_ttl);
			break;
		case FAKE_STRAT_RAND_SEQ:
			printf("Random seq faking strategy will be used\n");
			printf("Fake seq offset set to %u\n", config.fakeseq_offset);
			break;
		case FAKE_STRAT_TCP_CHECK:
			printf("TCP checksum faking strategy will be used\n");
			break;
		case FAKE_STRAT_PAST_SEQ:
			printf("Past seq faking strategy will be used\n");
			break;
	}

	if (config.fk_winsize) {
		printf("Response TCP window will be set to %d with the appropriate scale\n", config.fk_winsize);
	}

	if (config.synfake) {
		printf("Fake SYN payload will be sent with each TCP request SYN packet\n");
	}


	if (config.use_gso) {
		printf("GSO is enabled\n");
	}

	if (config.use_ipv6) {
		printf("IPv6 is enabled\n");
	} else {
		printf("IPv6 is disabled\n");
	}

	if (config.quic_drop) {
		printf("All QUIC packets will be dropped\n");
	}

	if (config.sni_detection == SNI_DETECTION_BRUTE) {
		printf("Server Name Extension will be parsed in the bruteforce mode\n");
	}

	if (config.all_domains) {
		printf("All Client Hello will be targetted by youtubeUnblock!\n");
	}

}
