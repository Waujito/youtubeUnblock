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
	.all_domains = false,
	.sni_file = "domains.txt",
	.sni_targets = NULL,

	.queue_start_num = DEFAULT_QUEUE_NUM,
	.fake_sni_pkt = fake_sni,
	.fake_sni_pkt_sz = sizeof(fake_sni) - 1, // - 1 for null-terminator
};

#define OPT_SNI_DOMAINS_ALL	1
#define OPT_SNI_DOMAINS_FILE	15
#define OPT_FAKE_SNI 		2
#define OPT_FAKING_TTL		3
#define OPT_FAKING_STRATEGY	10
#define OPT_FAKE_SNI_SEQ_LEN	11
#define OPT_FRAG    		4
#define OPT_FRAG_SNI_REVERSE	12
#define OPT_FRAG_SNI_FAKED	13
#define OPT_FK_WINSIZE		14
#define OPT_SEG2DELAY 		5
#define OPT_THREADS 		6
#define OPT_SILENT 		7
#define OPT_NO_GSO 		8
#define OPT_QUEUE_NUM		9

#define OPT_MAX OPT_FRAG_SNI_FAKED

static struct option long_opt[] = {
	{"help",		0, 0, 'h'},
	{"version",		0, 0, 'v'},
	{"sni-domains-all",	1, 0, OPT_SNI_DOMAINS_ALL},
	{"sni-domains-file",	1, 0, OPT_SNI_DOMAINS_FILE},
	{"fake-sni",		1, 0, OPT_FAKE_SNI},
	{"fake-sni-seq-len",	1, 0, OPT_FAKE_SNI_SEQ_LEN},
	{"faking-strategy",	1, 0, OPT_FAKING_STRATEGY},
	{"faking-ttl",		1, 0, OPT_FAKING_TTL},
	{"frag",		1, 0, OPT_FRAG},
	{"frag-sni-reverse",	1, 0, OPT_FRAG_SNI_REVERSE},
	{"frag-sni-faked",	1, 0, OPT_FRAG_SNI_FAKED},
	{"fk-winsize",		1, 0, OPT_FK_WINSIZE},
	{"seg2delay",		1, 0, OPT_SEG2DELAY},
	{"threads",		1, 0, OPT_THREADS},
	{"silent",		0, 0, OPT_SILENT},
	{"no-gso",		0, 0, OPT_NO_GSO},
	{"queue-num",		1, 0, OPT_QUEUE_NUM},
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
	printf("\t--sni-domains-all={1|0}\n");
	printf("\t--sni-domains-file=[filename]\n");
	printf("\t--fake-sni={1|0}\n");
	printf("\t--fake-sni-seq-len=<length>\n");
	printf("\t--faking-ttl=<ttl>\n");
	printf("\t--faking-strategy={ack,ttl}\n");
	printf("\t--frag={tcp,ip,none}\n");
	printf("\t--frag-sni-reverse={0|1}\n");
	printf("\t--frag-sni-faked={0|1}\n");
	printf("\t--fk-winsize=<winsize>\n");
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
			case OPT_SNI_DOMAINS_ALL:
				config.all_domains = 1;
				break;
			case OPT_SNI_DOMAINS_FILE:
				config.sni_file = optarg;
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
			case OPT_FRAG_SNI_FAKED:
				if (strcmp(optarg, "1") == 0) {
					config.frag_sni_faked = 1;				
				} else if (strcmp(optarg, "0") == 0) {
					config.frag_sni_faked = 0;
				} else {
					errno = EINVAL;
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				break;
			case OPT_FRAG_SNI_REVERSE:
				if (strcmp(optarg, "1") == 0) {
					config.frag_sni_reverse = 1;				
				} else if (strcmp(optarg, "0") == 0) {
					config.frag_sni_reverse = 0;
				} else {
					errno = EINVAL;
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				break;
			case OPT_FAKING_STRATEGY:
				if (strcmp(optarg, "ack") == 0) {
					config.faking_strategy = FAKE_STRAT_ACK_SEQ;
				} else if (strcmp(optarg, "ttl") == 0) {
					config.faking_strategy = FAKE_STRAT_TTL;
				} else {
					errno = EINVAL;
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				break;
			case OPT_FAKING_TTL:
				num = parse_numeric_option(optarg);
				if (errno != 0 || num < 0 || num > 255) {
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				config.faking_ttl = num;
				break;

			case OPT_FAKE_SNI:
				if (strcmp(optarg, "1") == 0) {
					config.fake_sni = 1;				
				} else if (strcmp(optarg, "0") == 0) {
					config.fake_sni = 0;
				} else {
					errno = EINVAL;
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				break;
			case OPT_FAKE_SNI_SEQ_LEN:
				num = parse_numeric_option(optarg);
				if (errno != 0 || num < 0 || num > 255) {
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				config.fake_sni_seq_len = num;
				break;
			case OPT_FK_WINSIZE:
				num = parse_numeric_option(optarg);
				if (errno != 0 || num < 0) {
					printf("Invalid option %s\n", long_opt[optIdx].name);
					goto error;
				}

				config.fk_winsize = num;
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
		case FAKE_STRAT_ACK_SEQ:
			printf("Ack-Seq faking strategy will be used\n");
			break;
	}

	if (config.fk_winsize) {
		printf("Response TCP window will be set to %d with the appropriate scale\n", config.fk_winsize);
	}


	if (config.use_gso) {
		printf("GSO is enabled\n");
	}

	if (config.all_domains) {
		printf("All Client Hello will be targetted by youtubeUnblock!\n");
	}
}

int parse_sni_list () {
	char buf[MAX_SNI_LEN];
	char *p;
	struct sni_target *t;
	struct sni_target *cur;
	char *sni_buf;
  
	if (config.all_domains) {
		printf("Enabled for all SNI!\n");
		return 0;
	}

	printf("Reading target SNI from file: %s\n", config.sni_file);

	if (access(config.sni_file, F_OK) != 0) {
		printf("parse_sni_list: Domains file does not exists: %s\n", config.sni_file);
		return -1;
	}

	FILE *f;
	f = fopen(config.sni_file, "r");
	if (f == NULL) {
		printf("parse_sni_list: Can't open file %s\n", config.sni_file);
		return -2;
	}

	while ( fgets(buf, MAX_SNI_LEN, f) ) {
		if ((p = strchr(buf, '\r')))
			*p = 0;
		if ((p = strchr(buf, '\n')))
			*p = 0;
		if (strlen(buf) < 1)
			continue;
		if (buf[0] == '#')
			continue;
		if (config.verbose)
			printf("Adding domain to SNI targets: %s\n", buf);

		/* dont be scared of malloc, and by the way we don't need to
		 * free them at all because heap will be destroyed at program
		 * exit and we have no live config reload functionality yet */
		t = (struct sni_target *)malloc(sizeof(struct sni_target));
		t->sni_len = strlen(buf);
    
		sni_buf = (char *)malloc(t->sni_len + 1);
		strcpy(sni_buf, buf);
		t->sni_str = sni_buf;

		/* always insert to head */
		t->next = config.sni_targets;
		config.sni_targets = t;
	}
	fclose(f);

	if (config.sni_targets == NULL) {
		printf("parse_sni_list: Domains file have no domains\n");
		return -3;
	}
  
	return 0;
}
