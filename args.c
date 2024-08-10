#include "config.h"
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>


struct config_t config = {
	.rawsocket = -2,
	.threads = THREADS_NUM,
	.fragmentation_strategy = FRAGMENTATION_STRATEGY,
	.fake_sni_strategy = FAKE_SNI_STRATEGY,
	.fake_sni_ttl = FAKE_SNI_TTL,

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
	.verbose = true,
#else
	.verbose = false,
#endif
	.domains_str = defaul_snistr,
	.domains_strlen = sizeof(defaul_snistr),

	.queue_start_num = DEFAULT_QUEUE_NUM,
};

#define OPT_SNI_DOMAINS		1
#define OPT_FAKE_SNI 		2
#define OPT_FAKE_SNI_TTL	3
#define OPT_FRAG    		4
#define OPT_SEG2DELAY 		5
#define OPT_THREADS 		6
#define OPT_SILENT 		7
#define OPT_NO_GSO 		8
#define OPT_QUEUE_NUM		9

static struct option long_opt[] = {
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{"sni-domains", 1, 0, OPT_SNI_DOMAINS},
	{"fake-sni", 1, 0, OPT_FAKE_SNI},
	{"fake-sni-ttl", 1, 0, OPT_FAKE_SNI_TTL},
	{"frag", 1, 0, OPT_FRAG},
	{"seg2delay", 1, 0, OPT_SEG2DELAY},
	{"threads", 1, 0, OPT_THREADS},
	{"silent", 0, 0, OPT_SILENT},
	{"no-gso", 0, 0, OPT_NO_GSO},
	{"queue-num", 1, 0, OPT_QUEUE_NUM},
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
	printf("Bypasses youtube detection systems that relies on SNI\n");
}

void print_usage(const char *argv0) {
	print_version();

	printf("Usage: %s [ OPTIONS ] \n", argv0);
	printf("Options:\n");
	printf("\t--queue-num=<number of netfilter queue>\n");
	printf("\t--sni-domains=<comma separated domain list>|all\n");
	printf("\t--fake-sni={ack,ttl,none}\n");
	printf("\t--fake-sni-ttl=<ttl>\n");
	printf("\t--frag={tcp,ip,none}\n");
	printf("\t--seg2delay=<delay>\n");
	printf("\t--threads=<threads number>\n");
	printf("\t--silent\n");
	printf("\t--no-gso\n");
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
				goto out;
			case 'v':
				print_version();
				goto out;
			case OPT_SILENT:
				config.verbose = 0;
				break;
			case OPT_NO_GSO:
				config.use_gso = 0;
				break;
			case OPT_SNI_DOMAINS:
				if (strcmp(optarg, "all")) {
					config.all_domains = 1;
				}
				config.domains_str = optarg;
				config.domains_strlen = strlen(config.domains_str);

				break;
			case OPT_FRAG:
				if (strcmp(optarg, "tcp") == 0) {
					config.fragmentation_strategy = FRAG_STRAT_TCP;
				} else if (strcmp(optarg, "ip") == 0) {
					config.fragmentation_strategy = FRAG_STRAT_IP;
				} else if (strcmp(optarg, "none") == 0) {
					config.fragmentation_strategy = FRAG_STRAT_NONE;
				} else {
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				break;
			case OPT_FAKE_SNI:
				if (strcmp(optarg, "ack") == 0) {
					config.fake_sni_strategy = FKSN_STRAT_ACK_SEQ;
				} else if (strcmp(optarg, "ttl") == 0) {
					config.fake_sni_strategy = FKSN_STRAT_TTL;
				} else if (strcmp(optarg, "none") == 0) {
					config.fake_sni_strategy = FKSN_STRAT_NONE;
				} else {
					errno = EINVAL;
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				break;
			case OPT_SEG2DELAY:
				num = parse_numeric_option(optarg);
				if (errno != 0 || num < 0) {
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				config.seg2_delay = num;
				break;
			case OPT_THREADS:
				num = parse_numeric_option(optarg);
				if (errno != 0 || num < 0 || num > MAX_THREADS) {
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				config.threads = num;
				break;
			case OPT_FAKE_SNI_TTL:
				num = parse_numeric_option(optarg);
				if (errno != 0 || num < 0 || num > 255) {
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				config.fake_sni_ttl = num;
				break;
			case OPT_QUEUE_NUM:
				num = parse_numeric_option(optarg);
				if (errno != 0 || num < 0) {
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				config.queue_start_num = num;
				break;
			default:
				goto error;
		}
	}

	

	errno = 0;
	return 0;
out:
	errno = 0;
	return 1;
error:
	print_usage(argv[0]);
	errno = EINVAL;
	return -1;
}
