#include "config.h"
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "args.h"

static char custom_fake_buf[MAX_FAKE_SIZE];

struct config_t config = {
	.threads = THREADS_NUM,
	.queue_start_num = DEFAULT_QUEUE_NUM,
	.mark = DEFAULT_RAWSOCKET_MARK,
	.use_ipv6 = 1,

	.verbose = VERBOSE_DEBUG,
	.use_gso = true,

	.default_config = default_section_config,
	.custom_configs_len = 0
};

#define OPT_SNI_DOMAINS		1
#define OPT_EXCLUDE_DOMAINS	25
#define OPT_FAKE_SNI 		2
#define OPT_FAKING_TTL		3
#define OPT_FAKING_STRATEGY	10
#define OPT_FAKE_SNI_SEQ_LEN	11
#define OPT_FAKE_SNI_TYPE	27
#define OPT_FAKE_CUSTOM_PAYLOAD	28
#define OPT_START_SECTION	29
#define OPT_END_SECTION		30
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

#define OPT_MAX OPT_END_SECTION

static struct option long_opt[] = {
	{"help",		0, 0, 'h'},
	{"version",		0, 0, 'v'},
	{"sni-domains",		1, 0, OPT_SNI_DOMAINS},
	{"exclude-domains",	1, 0, OPT_EXCLUDE_DOMAINS},
	{"fake-sni",		1, 0, OPT_FAKE_SNI},
	{"synfake",		1, 0, OPT_SYNFAKE},
	{"synfake-len",		1, 0, OPT_SYNFAKE_LEN},
	{"fake-sni-seq-len",	1, 0, OPT_FAKE_SNI_SEQ_LEN},
	{"fake-sni-type",	1, 0, OPT_FAKE_SNI_TYPE},
	{"fake-custom-payload", 1, 0, OPT_FAKE_CUSTOM_PAYLOAD},
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
	{"fbegin",		0, 0, OPT_START_SECTION},
	{"fend",		0, 0, OPT_END_SECTION},
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
  	printf("youtubeUnblock" 
#if defined(PKG_VERSION)
	" " PKG_VERSION
#endif
	"\n"
	);	
	printf("Bypasses deep packet inspection systems that rely on SNI\n");
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
	printf("\t--fake-sni-type={default|random|custom}\n");
	printf("\t--fake-custom-payload=<hex payload>\n");
	printf("\t--fake-seq-offset=<offset>\n");
	printf("\t--faking-ttl=<ttl>\n");
	printf("\t--faking-strategy={randseq|ttl|tcp_check|pastseq|md5sum}\n");
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
	printf("\t--fbegin\n");
	printf("\t--fend\n");
	printf("\n");
}

int parse_args(int argc, char *argv[]) {
  	int opt;
	int optIdx = 0;
	long num;

	struct section_config_t *sect_config = &config.default_config;
	
#define SECT_ITER_DEFAULT	1
#define SECT_ITER_INSIDE	2
#define SECT_ITER_OUTSIDE	3

	int section_iter = SECT_ITER_DEFAULT;

	while ((opt = getopt_long(argc, argv, "hv", long_opt, &optIdx)) != -1) {
		switch (opt) {
/* config_t scoped configs */
		case 'h':
			print_usage(argv[0]);
			goto stop_exec;
		case 'v':
			print_version();
			goto stop_exec;
		case OPT_TRACE:
			if (section_iter != SECT_ITER_DEFAULT)
				goto invalid_opt;
			config.verbose = 2;
			break;
		case OPT_SILENT:
			if (section_iter != SECT_ITER_DEFAULT)
				goto invalid_opt;

			config.verbose = 0;
			break;
		case OPT_NO_GSO:
			if (section_iter != SECT_ITER_DEFAULT)
				goto invalid_opt;

			config.use_gso = 0;
			break;
		case OPT_NO_IPV6:
			if (section_iter != SECT_ITER_DEFAULT)
				goto invalid_opt;

			config.use_ipv6 = 0;
			break;
		case OPT_THREADS:
			if (section_iter != SECT_ITER_DEFAULT)
				goto invalid_opt;

			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0 || num > MAX_THREADS) {
				goto invalid_opt;
			}

			config.threads = num;
			break;
		case OPT_QUEUE_NUM:
			if (section_iter != SECT_ITER_DEFAULT)
				goto invalid_opt;

			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.queue_start_num = num;
			break;
		case OPT_PACKET_MARK:
			if (section_iter != SECT_ITER_DEFAULT)
				goto invalid_opt;

			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			config.mark = num;
			break;
		case OPT_START_SECTION:
			if (section_iter != SECT_ITER_DEFAULT && section_iter != SECT_ITER_OUTSIDE)
				goto invalid_opt;

			sect_config = &config.custom_configs[config.custom_configs_len++];
			*sect_config = (struct section_config_t)default_section_config;
			section_iter = SECT_ITER_INSIDE;

			break;
		case OPT_END_SECTION:
			if (section_iter != SECT_ITER_INSIDE)
				goto invalid_opt;

			section_iter = SECT_ITER_OUTSIDE;
			sect_config = &config.default_config;
			break;

/* section_config_t scoped configs */
		case OPT_SNI_DOMAINS:
			if (!strcmp(optarg, "all")) {
				sect_config->all_domains = 1;
			}

			sect_config->domains_str = optarg;
			sect_config->domains_strlen = strlen(sect_config->domains_str);
			break;
		case OPT_EXCLUDE_DOMAINS:
			sect_config->exclude_domains_str = optarg;
			sect_config->exclude_domains_strlen = strlen(sect_config->exclude_domains_str);
			break;
		case OPT_FRAG:
			if (strcmp(optarg, "tcp") == 0) {
				sect_config->fragmentation_strategy = FRAG_STRAT_TCP;
			} else if (strcmp(optarg, "ip") == 0) {
				sect_config->fragmentation_strategy = FRAG_STRAT_IP;
			} else if (strcmp(optarg, "none") == 0) {
				sect_config->fragmentation_strategy = FRAG_STRAT_NONE;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG_SNI_FAKED:
			if (strcmp(optarg, "1") == 0) {
				sect_config->frag_sni_faked = 1;
			} else if (strcmp(optarg, "0") == 0) {
				sect_config->frag_sni_faked = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG_SNI_REVERSE:
			if (strcmp(optarg, "1") == 0) {
				sect_config->frag_sni_reverse = 1;
			} else if (strcmp(optarg, "0") == 0) {
				sect_config->frag_sni_reverse = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG_MIDDLE_SNI:
			if (strcmp(optarg, "1") == 0) {
				sect_config->frag_middle_sni = 1;
			} else if (strcmp(optarg, "0") == 0) {
				sect_config->frag_middle_sni = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FRAG_SNI_POS:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			sect_config->frag_sni_pos = num;
			break;
		case OPT_FAKING_STRATEGY:
			if (strcmp(optarg, "randseq") == 0) {
				sect_config->faking_strategy = FAKE_STRAT_RAND_SEQ;
			} else if (strcmp(optarg, "ttl") == 0) {
				sect_config->faking_strategy = FAKE_STRAT_TTL;
			} else if (strcmp(optarg, "tcp_check") == 0) {
				sect_config->faking_strategy = FAKE_STRAT_TCP_CHECK;
			} else if (strcmp(optarg, "pastseq") == 0) {
				sect_config->faking_strategy = FAKE_STRAT_PAST_SEQ;
			} else if (strcmp(optarg, "md5sum") == 0) {
				sect_config->faking_strategy = FAKE_STRAT_TCP_MD5SUM;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FAKING_TTL:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0 || num > 255) {
				goto invalid_opt;
			}

			sect_config->faking_ttl = num;
			break;
		case OPT_FAKE_SEQ_OFFSET:
			num = parse_numeric_option(optarg);
			if (errno != 0) {
				goto invalid_opt;
			}

			sect_config->fakeseq_offset = num;
			break;
		case OPT_FAKE_SNI:
			if (strcmp(optarg, "1") == 0) {
				sect_config->fake_sni = 1;				
			} else if (strcmp(optarg, "0") == 0) {
				sect_config->fake_sni = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FAKE_SNI_SEQ_LEN:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0 || num > 255) {
				goto invalid_opt;
			}

			sect_config->fake_sni_seq_len = num;
			break;
		case OPT_FAKE_SNI_TYPE:
			if (strcmp(optarg, "default") == 0) {
				sect_config->fake_sni_type = FAKE_PAYLOAD_DEFAULT;
			} else if (strcmp(optarg, "random") == 0) {
				sect_config->fake_sni_type = FAKE_PAYLOAD_RANDOM;
			} else if (strcmp(optarg, "custom") == 0) {
				sect_config->fake_sni_type = FAKE_PAYLOAD_CUSTOM;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_FAKE_CUSTOM_PAYLOAD: {
				uint8_t *const custom_buf = (uint8_t *)custom_fake_buf;

				const char *custom_hex_fake = optarg;
				size_t custom_hlen = strlen(custom_hex_fake);
				if ((custom_hlen & 1) == 1) {
					printf("Custom fake hex should be divisible by two\n");
					goto invalid_opt;
				}


				size_t custom_len = custom_hlen >> 1;
				if (custom_len > MAX_FAKE_SIZE) {
					printf("Custom fake is too large\n");
					goto invalid_opt;
				}

				for (int i = 0; i < custom_len; i++) {
					sscanf(custom_hex_fake + (i << 1), "%2hhx", custom_buf + i);
				}

				sect_config->fake_custom_pkt_sz = custom_len;
				sect_config->fake_custom_pkt = (char *)custom_buf;
			}
			break;
		case OPT_FK_WINSIZE:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			sect_config->fk_winsize = num;
			break;

		case OPT_SEG2DELAY:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			sect_config->seg2_delay = num;
			break;
		case OPT_QUIC_DROP:
			sect_config->quic_drop = 1;
			break;
		case OPT_SNI_DETECTION:
			if (strcmp(optarg, "parse") == 0) {
				sect_config->sni_detection = SNI_DETECTION_PARSE;
			} else if (strcmp(optarg, "brute") == 0) {
				sect_config->sni_detection = SNI_DETECTION_BRUTE;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_SYNFAKE:
			if (strcmp(optarg, "1") == 0) {
				sect_config->synfake = 1;
			} else if (strcmp(optarg, "0") == 0) {
				sect_config->synfake = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_SYNFAKE_LEN:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}
			sect_config->synfake_len = num;
			break;
		default:
			goto error;
		}

	}


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
	if (config.use_gso) {
		printf("GSO is enabled\n");
	}

	if (config.use_ipv6) {
		printf("IPv6 is enabled\n");
	} else {
		printf("IPv6 is disabled\n");
	}
	
	printf("Detected %d config sections\n", config.custom_configs_len + 1);
	printf("The sections will be processed in ordred they goes in this output\n");

	ITER_CONFIG_SECTIONS(section) {
		int section_number = CONFIG_SECTION_NUMBER(section);
		printf("Section #%d\n", section_number);

		switch (section->fragmentation_strategy) {
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

		if (section->seg2_delay) {
			printf("Some outgoing googlevideo request segments will be delayed for %d ms as of seg2_delay define\n", section->seg2_delay);
		}

		if (section->fake_sni) {
			printf("Fake SNI will be sent before each target client hello\n");
		} else {
			printf("Fake SNI is disabled\n");
		}

		if (section->frag_sni_reverse) {
			printf("Fragmentation Client Hello will be reversed\n");
		}

		if (section->frag_sni_faked) {
			printf("Fooling packets will be sent near the original Client Hello\n");
		}

		if (section->fake_sni_seq_len > 1) {
			printf("Faking sequence of length %d will be built as fake sni\n", section->fake_sni_seq_len);
		}

		switch (section->faking_strategy) {
			case FAKE_STRAT_TTL:
				printf("TTL faking strategy will be used with TTL %d\n", section->faking_ttl);
				break;
			case FAKE_STRAT_RAND_SEQ:
				printf("Random seq faking strategy will be used\n");
				printf("Fake seq offset set to %u\n", section->fakeseq_offset);
				break;
			case FAKE_STRAT_TCP_CHECK:
				printf("TCP checksum faking strategy will be used\n");
				break;
			case FAKE_STRAT_PAST_SEQ:
				printf("Past seq faking strategy will be used\n");
				break;
			case FAKE_STRAT_TCP_MD5SUM:
				printf("md5sum faking strategy will be used\n");
				break;
		}

		if (section->fk_winsize) {
			printf("Response TCP window will be set to %d with the appropriate scale\n", section->fk_winsize);
		}

		if (section->synfake) {
			printf("Fake SYN payload will be sent with each TCP request SYN packet\n");
		}

		if (section->quic_drop) {
			printf("All QUIC packets will be dropped\n");
		}

		if (section->sni_detection == SNI_DETECTION_BRUTE) {
			printf("Server Name Extension will be parsed in the bruteforce mode\n");
		}

		if (section->all_domains) {
			printf("All Client Hello will be targeted by youtubeUnblock!\n");
		} else {
			printf("Target sni domains: %s\n", section->domains_str);
		}
	}
}

