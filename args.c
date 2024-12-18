#include "config.h"
#include "types.h"

#include "types.h"
#include "args.h"
#include "logging.h"
#include "getopt.h"
#include "raw_replacements.h"

#ifdef KERNEL_SPACE
static int errno = 0;
#define strtol kstrtol
#endif

struct config_t config = default_config_set; 

static int parse_sni_domains(struct domains_list **dlist, const char *domains_str, size_t domains_strlen) {
	// Empty and shouldn't be used
	struct domains_list ndomain = {0};
	struct domains_list *cdomain = &ndomain;

	unsigned int j = 0;
	for (unsigned int i = 0; i <= domains_strlen; i++) {
		if ((	i == domains_strlen	||	
			domains_str[i] == '\0'	||
			domains_str[i] == ','	|| 
			domains_str[i] == '\n'	)) {

			if (i == j) {
				j++;
				continue;
			}

			unsigned int domain_len = (i - j);
			const char *domain_startp = domains_str + j;
			struct domains_list *edomain = malloc(sizeof(struct domains_list));
			*edomain = (struct domains_list){0};
			if (edomain == NULL) {
				return -ENOMEM;
			}

			edomain->domain_len = domain_len;
			edomain->domain_name = malloc(domain_len + 1);
			if (edomain->domain_name == NULL) {
				return -ENOMEM;
			}

			strncpy(edomain->domain_name, domain_startp, domain_len);
			edomain->domain_name[domain_len] = '\0';
			cdomain->next = edomain;
			cdomain = edomain;

			j = i + 1;
		}
	}

	*dlist = ndomain.next;
	return 0;
}

static void free_sni_domains(struct domains_list *dlist) {
	for (struct domains_list *ldl = dlist; ldl != NULL;) {
		struct domains_list *ndl = ldl->next;
		SFREE(ldl->domain_name);
		SFREE(ldl);
		ldl = ndl;
	}
}

static long parse_numeric_option(const char* value) {
	errno = 0;

	if (*value == '\0') {
		errno = EINVAL;
		return 0;
	}

	long result;
	int len;
	sscanf(value, "%ld%n", &result, &len);
	if (*(value + len) != '\0') {
		errno = EINVAL;
		return 0;
	}

	return result;
}

static int parse_udp_dport_range(char *str, struct udp_dport_range **udpr, int *udpr_len) {
	int seclen = 1;
	const char *p = str;
	while (*p != '\0') {
		if (*p == ',')
			seclen++;
		p++;
	}
	
#ifdef KERNEL_SPACE
	struct udp_dport_range *udp_dport_ranges = kmalloc(
		seclen * sizeof(struct udp_dport_range), GFP_KERNEL);

#else
	struct udp_dport_range *udp_dport_ranges = malloc(
		seclen * sizeof(struct udp_dport_range));
#endif
	if (udp_dport_ranges == NULL) {
		return -ENOMEM;
	}

	int i = 0;


	p = str;
	const char *ep = p;
	while (1) {
		if (*ep == '\0' || *ep == ',') {
			if (ep == p) {
				if (*ep == '\0')
					break;

				p++, ep++;
				continue;
			}

			const char *endp;
			long num1;
			int len;
			sscanf(p, "%ld%n", &num1, &len);
			endp = p + len;
			long num2 = num1;
			
			if (endp != ep) {
				if (*endp == '-') {
					endp++;
					int len;
					sscanf(endp, "%ld%n", &num2, &len);
					endp = endp + len;

					if (endp != ep)
						goto erret;
				} else {
					goto erret;
				}
			}

			if (
				!(num1 > 0 && num1 < (1 << 16)) || 
				!(num2 > 0 && num2 < (1 << 16)) ||
				num2 < num1
			) 
				goto erret;
				
			udp_dport_ranges[i] = (struct udp_dport_range){
				.start = num1,
				.end = num2
			};
			i++;

			if (*ep == '\0') {
				break;
			} else {
				p = ep + 1;
				ep = p;
			}
		} else {
			ep++;
		}
	}

	if (i == 0) {
		free(udp_dport_ranges);
	}

	*udpr = udp_dport_ranges;
	*udpr_len = i;
	return 0;

erret:
	free(udp_dport_ranges);

	return -1;
}

// Allocates and fills custom fake buffer
static int parse_fake_custom_payload(
	const char *custom_hex_fake,
	char **custom_fake_buf, unsigned int *custom_fake_len) {
	int ret;

	size_t custom_hlen = strlen(custom_hex_fake);
	if ((custom_hlen & 1) == 1) {
		printf("Custom fake hex should be divisible by two\n");
		return -EINVAL;
	}

	size_t custom_len = custom_hlen >> 1;
	if (custom_len > MAX_FAKE_SIZE) {
		printf("Custom fake is too large\n");
		return -EINVAL;
	}
	unsigned char *custom_buf = malloc(custom_len);

	for (int i = 0; i < custom_len; i++) {
		ret = sscanf(custom_hex_fake + (i << 1), "%2hhx", custom_buf + i);
		if (ret != 1) {
			free(custom_buf);
			return -EINVAL;
		}
	}

	*custom_fake_buf = (char *)custom_buf;
	*custom_fake_len = custom_len;
	return 0;
}

enum {
	OPT_SNI_DOMAINS,
	OPT_EXCLUDE_DOMAINS,
	OPT_FAKE_SNI,
	OPT_FAKING_TTL,
	OPT_FAKING_STRATEGY,
	OPT_FAKE_SNI_SEQ_LEN,
	OPT_FAKE_SNI_TYPE,
	OPT_FAKE_CUSTOM_PAYLOAD,
	OPT_START_SECTION,
	OPT_END_SECTION,
	OPT_DAEMONIZE,
	OPT_NOCLOSE,
	OPT_SYSLOG,
	OPT_FRAG,
	OPT_FRAG_SNI_REVERSE,
	OPT_FRAG_SNI_FAKED,
	OPT_FRAG_MIDDLE_SNI,
	OPT_FRAG_SNI_POS,
	OPT_FK_WINSIZE,
	OPT_TRACE,
	OPT_QUIC_DROP,
	OPT_SNI_DETECTION,
	OPT_NO_IPV6,
	OPT_FAKE_SEQ_OFFSET,
	OPT_PACKET_MARK,
	OPT_SYNFAKE,
	OPT_SYNFAKE_LEN,
	OPT_SEG2DELAY,
	OPT_THREADS,
	OPT_SILENT,
	OPT_NO_GSO,
	OPT_QUEUE_NUM,
	OPT_UDP_MODE,
	OPT_UDP_FAKE_SEQ_LEN,
	OPT_UDP_FAKE_PAYLOAD_LEN,
	OPT_UDP_FAKING_STRATEGY,
	OPT_UDP_DPORT_FILTER,
	OPT_UDP_FILTER_QUIC,
	OPT_TLS_ENABLED,
	OPT_CLS,
	OPT_HELP,
	OPT_VERSION,
	OPT_CONNBYTES_LIMIT,
};

static struct option long_opt[] = {
	{"help",		0, 0, OPT_HELP},
	{"version",		0, 0, OPT_VERSION},
	{"sni-domains",		1, 0, OPT_SNI_DOMAINS},
	{"exclude-domains",	1, 0, OPT_EXCLUDE_DOMAINS},
	{"fake-sni",		1, 0, OPT_FAKE_SNI},
	{"synfake",		1, 0, OPT_SYNFAKE},
	{"synfake-len",		1, 0, OPT_SYNFAKE_LEN},
	{"tls",			1, 0, OPT_TLS_ENABLED},
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
	{"udp-mode",		1, 0, OPT_UDP_MODE},
	{"udp-fake-seq-len",	1, 0, OPT_UDP_FAKE_SEQ_LEN},
	{"udp-fake-len",	1, 0, OPT_UDP_FAKE_PAYLOAD_LEN},
	{"udp-faking-strategy",	1, 0, OPT_UDP_FAKING_STRATEGY},
	{"udp-dport-filter",	1, 0, OPT_UDP_DPORT_FILTER},
	{"udp-filter-quic",	1, 0, OPT_UDP_FILTER_QUIC},
	{"threads",		1, 0, OPT_THREADS},
	{"silent",		0, 0, OPT_SILENT},
	{"trace",		0, 0, OPT_TRACE},
	{"no-gso",		0, 0, OPT_NO_GSO},
	{"no-ipv6",		0, 0, OPT_NO_IPV6},
	{"daemonize",		0, 0, OPT_DAEMONIZE},
	{"noclose",		0, 0, OPT_NOCLOSE},
	{"syslog",		0, 0, OPT_SYSLOG},
	{"queue-num",		1, 0, OPT_QUEUE_NUM},
	{"packet-mark",		1, 0, OPT_PACKET_MARK},
	{"connbytes-limit",	1, 0, OPT_CONNBYTES_LIMIT},
	{"fbegin",		0, 0, OPT_START_SECTION},
	{"fend",		0, 0, OPT_END_SECTION},
	{"cls",			0, 0, OPT_CLS},
	{0,			0, 0, 0},
};

void print_version(void) {
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
	printf("\t--tls={enabled|disabled}\n");
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
	printf("\t--udp-mode={drop|fake}\n");
	printf("\t--udp-fake-seq-len=<amount of faking packets sent>\n");
	printf("\t--udp-fake-len=<size of upd fake>\n");
	printf("\t--udp-faking-strategy={checksum|ttl}\n");
	printf("\t--udp-dport-filter=<5,6,200-500>\n");
	printf("\t--udp-filter-quic={disabled|all}\n");
	printf("\t--threads=<threads number>\n");
	printf("\t--packet-mark=<mark>\n");
	printf("\t--connbytes-limit=<pkts>\n");
	printf("\t--silent\n");
	printf("\t--trace\n");
	printf("\t--no-gso\n");
	printf("\t--no-ipv6\n");
	printf("\t--daemonize\n");
	printf("\t--noclose\n");
	printf("\t--syslog\n");
	printf("\t--fbegin\n");
	printf("\t--fend\n");
	printf("\n");
}

int yparse_args(int argc, char *argv[]) {
  	int opt;
	int optIdx = 0;
	optind=1, opterr=1, optreset=0;
	long num;
	int ret;

	struct config_t rep_config;
	ret = init_config(&rep_config);
	if (ret < 0) 
		return ret;
	struct section_config_t *default_section = rep_config.last_section;

	struct section_config_t *sect_config = rep_config.last_section;
	int sect_i = 0;
	sect_config->id = sect_i++;
	
#define SECT_ITER_DEFAULT	1
#define SECT_ITER_INSIDE	2
#define SECT_ITER_OUTSIDE	3

	int section_iter = SECT_ITER_DEFAULT;

	while ((opt = getopt_long(argc, argv, "", long_opt, &optIdx)) != -1) {
		switch (opt) {
		case OPT_CLS:
			free_config(rep_config);
			ret = init_config(&rep_config);
			if (ret < 0) 
				return ret;
			default_section = rep_config.last_section;

			sect_config = rep_config.last_section;
			sect_i = 0;
			sect_config->id = sect_i++;
			section_iter = SECT_ITER_DEFAULT;

			break;

/* config_t scoped configs */
		case OPT_HELP:
			print_usage(argv[0]);
#ifndef KERNEL_SPACE
			goto stop_exec;
#else 
			break;
#endif
		case OPT_VERSION:
			print_version();
#ifndef KERNEL_SPACE
			goto stop_exec;
#else 
			break;
#endif
		case OPT_TRACE:
			rep_config.verbose = 2;
			break;
		case OPT_SILENT:
			rep_config.verbose = 0;
			break;
		case OPT_NO_GSO:
			rep_config.use_gso = 0;
			break;
		case OPT_NO_IPV6:
			rep_config.use_ipv6 = 0;
			break;
		case OPT_DAEMONIZE:
			rep_config.daemonize = 1;
			break;
		case OPT_NOCLOSE:
			rep_config.noclose = 1;
			break;
		case OPT_SYSLOG:
			rep_config.syslog = 1;
			break;
		case OPT_THREADS:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0 || num > MAX_THREADS) {
				goto invalid_opt;
			}

			rep_config.threads = num;
			break;
		case OPT_QUEUE_NUM:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			rep_config.queue_start_num = num;
			break;
		case OPT_PACKET_MARK:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			rep_config.mark = num;
			break;
		case OPT_CONNBYTES_LIMIT:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}
			rep_config.connbytes_limit = num;
			break;
		case OPT_START_SECTION: 
		{
			struct section_config_t *nsect;
			ret = init_section_config(&nsect, rep_config.last_section);
			if (ret < 0) {
				goto error;
			}
			rep_config.last_section->next = nsect;
			rep_config.last_section = nsect;
			sect_config = nsect;
			sect_config->id = sect_i++;
			section_iter = SECT_ITER_INSIDE;

			break;
		}
		case OPT_END_SECTION:
			if (section_iter != SECT_ITER_INSIDE)
				goto invalid_opt;

			section_iter = SECT_ITER_OUTSIDE;
			sect_config = default_section;
			break;

/* section_config_t scoped configs */
		case OPT_TLS_ENABLED:
			if (strcmp(optarg, "enabled") == 0) {
				sect_config->tls_enabled = 1;
			} else if (strcmp(optarg, "disabled") == 0) {
				sect_config->tls_enabled = 0;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_SNI_DOMAINS:
			free_sni_domains(sect_config->sni_domains);
			sect_config->all_domains = 0;
			if (!strcmp(optarg, "all")) {
				sect_config->all_domains = 1;
			}

			ret = parse_sni_domains(&sect_config->sni_domains, optarg, strlen(optarg));
			if (ret < 0)
				goto error;
			break;
		case OPT_EXCLUDE_DOMAINS:
			free_sni_domains(sect_config->exclude_sni_domains);
			ret = parse_sni_domains(&sect_config->exclude_sni_domains, optarg, strlen(optarg));
			if (ret < 0)
				goto error;

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
		case OPT_FAKE_CUSTOM_PAYLOAD: 			
			SFREE(sect_config->fake_custom_pkt);

			ret = parse_fake_custom_payload(optarg, &sect_config->fake_custom_pkt, &sect_config->fake_custom_pkt_sz);
			if (ret == -EINVAL) {
				goto invalid_opt;
			} else if (ret < 0) {
				goto error;
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
			sect_config->udp_filter_quic = UDP_FILTER_QUIC_ALL;
			sect_config->udp_mode = UDP_MODE_DROP;
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
		case OPT_UDP_MODE:
			if (strcmp(optarg, "drop") == 0) {
				sect_config->udp_mode = UDP_MODE_DROP;
			} else if (strcmp(optarg, "fake") == 0) {
				sect_config->udp_mode = UDP_MODE_FAKE;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_UDP_FAKING_STRATEGY:
			if (strcmp(optarg, "checksum") == 0) {
				sect_config->udp_faking_strategy = FAKE_STRAT_UDP_CHECK;
			} else if (strcmp(optarg, "ttl") == 0) {
				sect_config->udp_faking_strategy = FAKE_STRAT_TTL;
			} else {
				goto invalid_opt;
			}

			break;
		case OPT_UDP_FAKE_SEQ_LEN:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0) {
				goto invalid_opt;
			}

			sect_config->udp_fake_seq_len = num;
			break;
		case OPT_UDP_FAKE_PAYLOAD_LEN:
			num = parse_numeric_option(optarg);
			if (errno != 0 || num < 0 || num > 1300) {
				goto invalid_opt;
			}

			sect_config->udp_fake_len = num;
			break;
		case OPT_UDP_DPORT_FILTER: 
		{
			SFREE(sect_config->udp_dport_range);
			if (parse_udp_dport_range(optarg, &sect_config->udp_dport_range, &sect_config->udp_dport_range_len) < 0) {
				goto invalid_opt;
			}
			break;
		}
		case OPT_UDP_FILTER_QUIC:
			if (strcmp(optarg, "disabled") == 0) {
				sect_config->udp_filter_quic = UDP_FILTER_QUIC_DISABLED;
			} else if (strcmp(optarg, "all") == 0) {
				sect_config->udp_filter_quic = UDP_FILTER_QUIC_ALL;
			} else {
				goto invalid_opt;
			}

			break;
		default:
			goto error;
		}

	}

	struct config_t old_config = config;
	config = rep_config;
	free_config(old_config);

	errno = 0;
	return 0;

#ifndef KERNEL_SPACE
stop_exec:
	free_config(rep_config);
	errno = 0;
	return 1;
#endif

invalid_opt:
	printf("Invalid option %s\n", long_opt[optIdx].name);
	ret = -EINVAL;
error:
#ifndef KERNEL_SPACE
	print_usage(argv[0]);
#endif
	if (ret != -EINVAL) {
		lgerror(ret, "Error thrown in %s\n", long_opt[optIdx].name);
	}

	errno = -ret;
	free_config(rep_config);
	return -errno;
}

#define print_cnf_raw(fmt, ...) do {				\
	sz = snprintf(buf_ptr, buf_sz, fmt, ##__VA_ARGS__);	\
	if (sz > buf_sz) { buf_sz = 0; }			\
	else { buf_sz -= sz; }					\
	buf_ptr += sz;						\
} while(0)

#define print_cnf_buf(fmt, ...) print_cnf_raw(fmt " ", ##__VA_ARGS__)
// Returns written buffer size
static size_t print_config_section(const struct section_config_t *section, char *buffer, size_t buffer_size) {
	char *buf_ptr = buffer;
	size_t buf_sz = buffer_size;
	size_t sz;

	if (section->tls_enabled) {
		print_cnf_buf("--tls=enabled");
		if (section->sni_domains != NULL) {
			print_cnf_raw("--sni-domains=");
			for (struct domains_list *sne = section->sni_domains; sne != NULL; sne = sne->next) {
				print_cnf_raw("%s,", sne->domain_name);
			}
			print_cnf_raw(" ");
		}
		if (section->exclude_sni_domains != NULL) {
			print_cnf_raw("--exclude-domains=");
			for (struct domains_list *sne = section->exclude_sni_domains; sne != NULL; sne = sne->next) {
				print_cnf_raw("%s,", sne->domain_name);
			}
			print_cnf_raw(" ");
		}

		switch(section->fragmentation_strategy) {
		case FRAG_STRAT_IP:
			print_cnf_buf("--frag=ip");
			break;
		case FRAG_STRAT_TCP:
			print_cnf_buf("--frag=tcp");
			break;
		case FRAG_STRAT_NONE:
			print_cnf_buf("--frag=none");
			break;
		}

		print_cnf_buf("frag-sni-reverse=%d", section->frag_sni_reverse);
		print_cnf_buf("frag-sni-faked=%d", section->frag_sni_faked);
		print_cnf_buf("frag-middle-sni=%d", section->frag_middle_sni);
		print_cnf_buf("frag-sni-pos=%d", section->frag_sni_pos);
		print_cnf_buf("fk-winsize=%d", section->fk_winsize);

		if (section->fake_sni) {
			print_cnf_buf("--fake-sni=1");
			print_cnf_buf("--fake-sni-seq-len=%d", section->fake_sni_seq_len);
			switch(section->fake_sni_type) {
			case FAKE_PAYLOAD_CUSTOM:
				print_cnf_buf("--fake-sni-type=custom");
				print_cnf_buf("--fake-custom-payload=<hidden>");
				break;
			case FAKE_PAYLOAD_RANDOM:
				print_cnf_buf("--fake-sni-type=random");
				break;
			case FAKE_PAYLOAD_DEFAULT:
				print_cnf_buf("--fake-sni-type=default");
				break;
			}

			switch(section->faking_strategy) {
			case FAKE_STRAT_TTL:
				print_cnf_buf("--faking-strategy=ttl");
				print_cnf_buf("--faking-ttl=%d", section->faking_ttl);
				break;
			case FAKE_STRAT_RAND_SEQ:
				print_cnf_buf("--faking-strategy=randseq");
				break;
			case FAKE_STRAT_TCP_CHECK:
				print_cnf_buf("--faking-strategy=tcp_check");
				break;
			case FAKE_STRAT_TCP_MD5SUM:
				print_cnf_buf("--faking-strategy=md5sum");
				break;
			case FAKE_STRAT_PAST_SEQ:
				print_cnf_buf("--faking-strategy=pastseq");
				print_cnf_buf("--fake-seq-offset=%d", section->fakeseq_offset);
				break;

			}

			switch(section->sni_detection) {
			case SNI_DETECTION_BRUTE:
				print_cnf_buf("--sni_detection=brute");
				break;
			case SNI_DETECTION_PARSE:
				print_cnf_buf("--sni_detection=parse");
				break;

			}

			print_cnf_buf("--seg2delay=%d", section->seg2_delay);
		}
	} else {
		print_cnf_buf("--tls=disabled");
	}

	if (section->synfake) {
		print_cnf_buf("--synfake=1");
		print_cnf_buf("--synfake-len=%d", section->synfake_len);
	} else {
		print_cnf_buf("--synfake=0");
	}


	if (section->udp_filter_quic == UDP_FILTER_QUIC_ALL && section->udp_mode == UDP_MODE_DROP) {
		print_cnf_buf("--drop-quic");
	}

	switch(section->udp_filter_quic) {
	case UDP_FILTER_QUIC_ALL:
		print_cnf_buf("--udp-filter-quic=all");
		break;
	case UDP_FILTER_QUIC_DISABLED:
		print_cnf_buf("--udp-filter-quic=disabled");
		break;
	}

	if (section->udp_dport_range_len != 0) {

		print_cnf_raw("--udp-dport-filter=");
		for (int i = 0; i < section->udp_dport_range_len; i++) {
			struct udp_dport_range range = section->udp_dport_range[i];
			print_cnf_raw("%d-%d,", range.start, range.end);
		}
		print_cnf_raw(" ");

	}


	if (section->udp_filter_quic != UDP_FILTER_QUIC_DISABLED || section->udp_dport_range_len != 0) {
		switch(section->udp_mode) {
		case UDP_MODE_DROP:
			print_cnf_buf("--udp-mode=drop");
			break;
		case UDP_MODE_FAKE:
			print_cnf_buf("--udp-mode=fake");
			print_cnf_buf("--udp-fake-seq-len=%d", section->udp_fake_seq_len);
			{
				switch(section->udp_faking_strategy) {
				case FAKE_STRAT_UDP_CHECK:
					print_cnf_buf("--udp-faking-strategy=checksum");
					break;
				case FAKE_STRAT_TTL:
					print_cnf_buf("--udp-faking-strategy=ttl");
				}
			}
			break;
		}
	}

	return buffer_size - buf_sz;
}
// Returns written buffer length
size_t print_config(char *buffer, size_t buffer_size) {
	char *buf_ptr = buffer;
	size_t buf_sz = buffer_size;
	size_t sz;

#ifndef KERNEL_SPACE
	print_cnf_buf("--queue-num=%d", config.queue_start_num);
	print_cnf_buf("--threads=%d", config.threads);
#endif
	print_cnf_buf("--mark=%d", config.mark);

#ifndef KERNEL_SPACE
	if (config.daemonize) {
		print_cnf_buf("--daemonize");
	}
	if (config.syslog) {
		print_cnf_buf("--syslog");
	}
	if (config.noclose) {
		print_cnf_buf("--noclose");
	}
	if (!config.use_gso) {
		print_cnf_buf("--no-gso");
	}
#endif

#ifdef KERNEL_SPACE
	print_cnf_buf("--connbytes-limit=%d", config.connbytes_limit);
#endif
	if (!config.use_ipv6) {
		print_cnf_buf("--no-ipv6");
	}
	if (config.verbose == VERBOSE_TRACE) {
		print_cnf_buf("--trace");
	}
	if (config.verbose == VERBOSE_INFO) {
		print_cnf_buf("--silent");
	}
	
	size_t wbuf_len = print_config_section(config.first_section, buf_ptr, buf_sz);
	buf_ptr += wbuf_len;
	buf_sz -= wbuf_len;

	for (struct section_config_t *section = config.first_section->next; 
		section != NULL; section = section->next) {
		print_cnf_buf("--fbegin");
		wbuf_len = print_config_section(section, buf_ptr, buf_sz);
		buf_ptr += wbuf_len;
		buf_sz -= wbuf_len;
		print_cnf_buf("--fend");
	}

	return buffer_size - buf_sz;
}

void print_welcome(void) {
	char *welcome_message = malloc(4000);
	if (welcome_message == NULL) 
		return;

	size_t sz = print_config(welcome_message, 4000);
	printf("Running with flags: %.*s\n", (int)sz, welcome_message);
	free(welcome_message);
}

int init_section_config(struct section_config_t **section, struct section_config_t *prev) {
	struct section_config_t *def_section = NULL;
	int ret;
#ifdef KERNEL_SPACE
	def_section = kmalloc(sizeof(struct section_config_t), GFP_KERNEL);
#else
	def_section = malloc(sizeof(struct section_config_t));
#endif
	*def_section = (struct section_config_t)default_section_config;
	def_section->prev = prev;

	if (def_section == NULL) 
		return -ENOMEM;

	ret = parse_sni_domains(&def_section->sni_domains, default_snistr, sizeof(default_snistr));
	if (ret < 0) {
		free(def_section);
		return ret;
	}

	def_section->fake_sni_pkt = fake_sni_old; 
	def_section->fake_sni_pkt_sz = sizeof(fake_sni_old) - 1;

	*section = def_section;
	return 0;
}

int init_config(struct config_t *config) {
	struct config_t def_config = default_config_set;
	int ret = 0;
	struct section_config_t *def_section = NULL;
	ret = init_section_config(&def_section, NULL);
	if (ret < 0)
		return ret;
	def_config.last_section = def_section;
	def_config.first_section = def_section;

	*config = def_config;

	return 0;
}

void free_config_section(struct section_config_t *section) {
	if (section->udp_dport_range_len != 0) {
		SFREE(section->udp_dport_range);
	}

	free_sni_domains(section->sni_domains);
	section->sni_domains = NULL;
	free_sni_domains(section->exclude_sni_domains);
	section->exclude_sni_domains = NULL;

	section->fake_custom_pkt_sz = 0;
	SFREE(section->fake_custom_pkt);

	free(section);
}

void free_config(struct config_t config) {
	for (struct section_config_t *sct = config.last_section; sct != NULL;) {
		struct section_config_t *psct = sct->prev;
		free_config_section(sct);
		sct = psct;
	}
}
