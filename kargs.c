#include "config.h"
#include "raw_replacements.h"
#include "types.h"
#include <linux/moduleparam.h>
#include "types.h"

#define STR_MAXLEN 2048

static char custom_fake_buf[MAX_FAKE_SIZE];

static const struct section_config_t default_section_config = {
	.frag_sni_reverse = 1,
	.frag_sni_faked = 0,
	.fragmentation_strategy = FRAGMENTATION_STRATEGY,
	.faking_strategy = FAKING_STRATEGY,
	.faking_ttl = FAKE_TTL,
	.fake_sni = 1,
	.fake_sni_seq_len = 1,
	.fake_sni_type = FAKE_PAYLOAD_DEFAULT,
	.frag_middle_sni = 1,
	.frag_sni_pos = 1,
	.fakeseq_offset = 10000,
	.synfake = 0,
	.synfake_len = 0,
	.quic_drop = 0,

	.seg2_delay = 0,

	.domains_str = defaul_snistr,
	.domains_strlen = sizeof(defaul_snistr),

	.exclude_domains_str = "",
	.exclude_domains_strlen = 0,

	.fake_sni_pkt = fake_sni_old,
	.fake_sni_pkt_sz = sizeof(fake_sni_old) - 1, // - 1 for null-terminator
	.fake_custom_pkt = custom_fake_buf,
	.fake_custom_pkt_sz = 0,
	.sni_detection = SNI_DETECTION_PARSE,
};

struct config_t config = {
	.threads = THREADS_NUM,
	.queue_start_num = DEFAULT_QUEUE_NUM,
	.mark = DEFAULT_RAWSOCKET_MARK,
	.use_ipv6 = 1,

	.verbose = VERBOSE_DEBUG,
	.use_gso = 1,

	.default_config = default_section_config,
	.custom_configs_len = 0
};

static struct section_config_t *const def_section = &config.default_config;

static int unumeric_set(const char *val, const struct kernel_param *kp) {
	int n = 0, ret;
	ret = kstrtoint(val, 10, &n);
	if (ret != 0 || n < 0)
		return -EINVAL;


	return param_set_int(val, kp);
}

static int boolean_set(const char *val, const struct kernel_param *kp) {
	int n = 0, ret;
	ret = kstrtoint(val, 10, &n);
	if (ret != 0 || (n != 0 && n != 1))
		return -EINVAL;

	return param_set_int(val, kp);
}

static int inverse_boolean_set(const char *val, const struct kernel_param *kp) {
	int n = 0, ret;
	ret = kstrtoint(val, 10, &n);
	if (ret != 0 || (n != 0 && n != 1))
		return -EINVAL;

	n = !n;
	if (kp->arg == NULL) 
		return -EINVAL;

	*(int *)kp->arg = n;
	return 0;
}

static int inverse_boolean_get(char *buffer, const struct kernel_param *kp) {
	if (*(int *)kp->arg == 0) {
		buffer[0] = '1';
	} else {
		buffer[0] = '0';
	}
	buffer[1] = '\0';
	return strlen(buffer);
}

static const struct kernel_param_ops unumeric_parameter_ops = {
	.set = unumeric_set,
	.get = param_get_int
};

static const struct kernel_param_ops boolean_parameter_ops = {
	.set = boolean_set,
	.get = param_get_int
};

static const struct kernel_param_ops inverse_boolean_ops = {
	.set = inverse_boolean_set,
	.get = inverse_boolean_get,
};

module_param_cb(fake_sni, &boolean_parameter_ops, &def_section->fake_sni, 0664);
module_param_cb(fake_sni_seq_len, &unumeric_parameter_ops, &def_section->fake_sni_seq_len, 0664);
module_param_cb(faking_ttl, &unumeric_parameter_ops, &def_section->faking_ttl, 0664);
module_param_cb(fake_seq_offset, &unumeric_parameter_ops, &def_section->fakeseq_offset, 0664);
module_param_cb(frag_sni_reverse, &unumeric_parameter_ops, &def_section->frag_sni_reverse, 0664);
module_param_cb(frag_sni_faked, &boolean_parameter_ops, &def_section->frag_sni_faked, 0664);
module_param_cb(frag_middle_sni, &boolean_parameter_ops, &def_section->frag_middle_sni, 0664);
module_param_cb(frag_sni_pos, &unumeric_parameter_ops, &def_section->frag_sni_pos, 0664);
module_param_cb(fk_winsize, &unumeric_parameter_ops, &def_section->fk_winsize, 0664);
module_param_cb(synfake, &boolean_parameter_ops, &def_section->synfake, 0664);
module_param_cb(synfake_len, &unumeric_parameter_ops, &def_section->synfake_len, 0664);
module_param_cb(packet_mark, &unumeric_parameter_ops, &config.mark, 0664);
// module_param_cb(seg2delay, &unumeric_parameter_ops, &def_section->seg2_delay, 0664);

static int sni_domains_set(const char *val, const struct kernel_param *kp) {
	size_t len;
	int ret;

	len = strnlen(val, STR_MAXLEN + 1);
	if (len == STR_MAXLEN + 1) {
		pr_err("%s: string parameter too long\n", kp->name);
		return -ENOSPC;
	}

	if (len >= 1 && val[len - 1] == '\n') {
		len--;
	}

	ret = param_set_charp(val, kp);

	if (ret < 0) {
		def_section->domains_strlen = 0;
	} else {
		def_section->domains_strlen = len;
		if (len == 3 && !strncmp(val, "all", len)) {
			def_section->all_domains = 1;
		} else {
			def_section->all_domains = 0;
		}
	}


	return ret;
}

static const struct kernel_param_ops sni_domains_ops = {
	.set = sni_domains_set,
	.get = param_get_charp,
};

module_param_cb(sni_domains, &sni_domains_ops, &def_section->domains_str, 0664);

static int exclude_domains_set(const char *val, const struct kernel_param *kp) {
	size_t len;
	int ret;

	len = strnlen(val, STR_MAXLEN + 1);
	if (len == STR_MAXLEN + 1) {
		pr_err("%s: string parameter too long\n", kp->name);
		return -ENOSPC;
	}

	ret = param_set_charp(val, kp);

	if (ret < 0) {
		def_section->exclude_domains_strlen = 0;
	} else {
		def_section->exclude_domains_strlen = len;
	}

	return ret;
}

static const struct kernel_param_ops exclude_domains_ops = {
	.set = exclude_domains_set,
	.get = param_get_charp,
};

module_param_cb(exclude_domains, &exclude_domains_ops, &def_section->exclude_domains_str, 0664);

module_param_cb(no_ipv6, &inverse_boolean_ops, &config.use_ipv6, 0664);
module_param_cb(quic_drop, &boolean_parameter_ops, &def_section->quic_drop, 0664);

static int verbosity_set(const char *val, const struct kernel_param *kp) {
	size_t len;

	len = strnlen(val, STR_MAXLEN + 1);
	if (len == STR_MAXLEN + 1) {
		pr_err("%s: string parameter too long\n", kp->name);
		return -ENOSPC;
	}

	if (len >= 1 && val[len - 1] == '\n') {
		len--;
	}

	if (strncmp(val, "trace", len) == 0) {
		*(int *)kp->arg = VERBOSE_TRACE;
	} else if (strncmp(val, "debug", len) == 0) {
		*(int *)kp->arg = VERBOSE_DEBUG;
	} else if (strncmp(val, "silent", len) == 0) {
		*(int *)kp->arg = VERBOSE_INFO;
	} else {
		return -EINVAL;
	}

	return 0;
}


static int verbosity_get(char *buffer, const struct kernel_param *kp) {
	switch (*(int *)kp->arg) {
		case VERBOSE_TRACE:
			strcpy(buffer, "trace\n");
			break;
		case VERBOSE_DEBUG:
			strcpy(buffer, "debug\n");
			break;
		case VERBOSE_INFO:
			strcpy(buffer, "silent\n");
			break;
		default:
			strcpy(buffer, "unknown\n");
	}

	return strlen(buffer);
}

static const struct kernel_param_ops verbosity_ops = {
	.set = verbosity_set,
	.get = verbosity_get,
};

module_param_cb(verbosity, &verbosity_ops, &config.verbose, 0664);

static int frag_strat_set(const char *val, const struct kernel_param *kp) {
	size_t len;

	len = strnlen(val, STR_MAXLEN + 1);
	if (len == STR_MAXLEN + 1) {
		pr_err("%s: string parameter too long\n", kp->name);
		return -ENOSPC;
	}

	if (len >= 1 && val[len - 1] == '\n') {
		len--;
	}

	if (strncmp(val, "tcp", len) == 0) {
		*(int *)kp->arg = FRAG_STRAT_TCP;
	} else if (strncmp(val, "ip", len) == 0) {
		*(int *)kp->arg = FRAG_STRAT_IP;
	} else if (strncmp(val, "none", len) == 0) {
		*(int *)kp->arg = FRAG_STRAT_NONE;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int frag_strat_get(char *buffer, const struct kernel_param *kp) {
	switch (*(int *)kp->arg) {
		case FRAG_STRAT_TCP:
			strcpy(buffer, "tcp\n");
			break;
		case FRAG_STRAT_IP:
			strcpy(buffer, "ip\n");
			break;
		case FRAG_STRAT_NONE:
			strcpy(buffer, "none\n");
			break;
		default:
			strcpy(buffer, "unknown\n");
	}

	return strlen(buffer);
}

static const struct kernel_param_ops frag_strat_ops = {
	.set = frag_strat_set,
	.get = frag_strat_get,
};

module_param_cb(fragmentation_strategy, &frag_strat_ops, &def_section->fragmentation_strategy, 0664);

static int fake_strat_set(const char *val, const struct kernel_param *kp) {
	size_t len;

	len = strnlen(val, STR_MAXLEN + 1);
	if (len == STR_MAXLEN + 1) {
		pr_err("%s: string parameter too long\n", kp->name);
		return -ENOSPC;
	}

	if (len >= 1 && val[len - 1] == '\n') {
		len--;
	}

	if (strncmp(val, "randseq", len) == 0) {
		*(int *)kp->arg = FAKE_STRAT_RAND_SEQ;
	} else if (strncmp(val, "ttl", len) == 0) {
		*(int *)kp->arg = FAKE_STRAT_TTL;
	} else if (strncmp(val, "tcp_check", len) == 0) {
		*(int *)kp->arg = FAKE_STRAT_TCP_CHECK;
	} else if (strncmp(val, "pastseq", len) == 0) {
		*(int *)kp->arg = FAKE_STRAT_PAST_SEQ;
	} else if (strncmp(val, "md5sum", len) == 0) {
		*(int *)kp->arg = FAKE_STRAT_TCP_MD5SUM;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int fake_strat_get(char *buffer, const struct kernel_param *kp) {
	switch (*(int *)kp->arg) {
		case FAKE_STRAT_RAND_SEQ:
			strcpy(buffer, "randseq\n");
			break;
		case FAKE_STRAT_TTL:
			strcpy(buffer, "ttl\n");
			break;
		case FAKE_STRAT_TCP_CHECK:
			strcpy(buffer, "tcp_check\n");
			break;
		case FAKE_STRAT_PAST_SEQ:
			strcpy(buffer, "pastseq\n");
			break;
		case FAKE_STRAT_TCP_MD5SUM:
			strcpy(buffer, "md5sum\n");
			break;
		default:
			strcpy(buffer, "unknown\n");
	}

	return strlen(buffer);
}

static const struct kernel_param_ops fake_strat_ops = {
	.set = fake_strat_set,
	.get = fake_strat_get,
};

module_param_cb(faking_strategy, &fake_strat_ops, &def_section->faking_strategy, 0664);

static int sni_detection_set(const char *val, const struct kernel_param *kp) {
	size_t len;

	len = strnlen(val, STR_MAXLEN + 1);
	if (len == STR_MAXLEN + 1) {
		pr_err("%s: string parameter too long\n", kp->name);
		return -ENOSPC;
	}

	if (len >= 1 && val[len - 1] == '\n') {
		len--;
	}

	if (strncmp(val, "parse", len) == 0) {
		*(int *)kp->arg = SNI_DETECTION_PARSE;
	} else if (strncmp(val, "brute", len) == 0) {
		*(int *)kp->arg = SNI_DETECTION_BRUTE;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int sni_detection_get(char *buffer, const struct kernel_param *kp) {
	switch (*(int *)kp->arg) {
		case SNI_DETECTION_PARSE:
			strcpy(buffer, "parse\n");
			break;
		case SNI_DETECTION_BRUTE:
			strcpy(buffer, "brute\n");
			break;
		default:
			strcpy(buffer, "unknown\n");
	}

	return strlen(buffer);
}

static const struct kernel_param_ops sni_detection_ops = {
	.set = sni_detection_set,
	.get = sni_detection_get,
};

module_param_cb(sni_detection, &sni_detection_ops, &def_section->sni_detection, 0664);

static int fake_type_set(const char *val, const struct kernel_param *kp) {
	size_t len;

	len = strnlen(val, STR_MAXLEN + 1);
	if (len == STR_MAXLEN + 1) {
		pr_err("%s: string parameter too long\n", kp->name);
		return -ENOSPC;
	}

	if (len >= 1 && val[len - 1] == '\n') {
		len--;
	}

	if (strncmp(val, "default", len) == 0) {
		*(int *)kp->arg = FAKE_PAYLOAD_DEFAULT;
	} else if (strncmp(val, "custom", len) == 0) {
		*(int *)kp->arg = FAKE_PAYLOAD_CUSTOM;
	} else if (strncmp(val, "random", len) == 0) {
		*(int *)kp->arg = FAKE_PAYLOAD_RANDOM;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int fake_type_get(char *buffer, const struct kernel_param *kp) {
	switch (*(int *)kp->arg) {
		case FAKE_PAYLOAD_DEFAULT:
			strcpy(buffer, "default\n");
			break;
		case FAKE_PAYLOAD_RANDOM:
			strcpy(buffer, "random\n");
			break;
		case FAKE_PAYLOAD_CUSTOM:
			strcpy(buffer, "custom\n");
			break;
		default:
			strcpy(buffer, "unknown\n");
	}

	return strlen(buffer);
}

static const struct kernel_param_ops fake_type_ops = {
	.set = fake_type_set,
	.get = fake_type_get,
};

module_param_cb(fake_sni_type, &fake_type_ops, &def_section->fake_sni_type, 0664);

static int fake_custom_pl_set(const char *val, const struct kernel_param *kp) {
	size_t len;

	len = strnlen(val, STR_MAXLEN + 1);
	if (len == STR_MAXLEN + 1) {
		pr_err("%s: string parameter too long\n", kp->name);
		return -ENOSPC;
	}

	if (len >= 1 && val[len - 1] == '\n') {
		len--;
	}

	uint8_t *const custom_buf = (uint8_t *)custom_fake_buf;
	const char *custom_hex_fake = val;
	size_t custom_hlen = len;

	if ((custom_hlen & 1) == 1) {
		return -EINVAL;
	}


	size_t custom_len = custom_hlen >> 1;
	if (custom_len > MAX_FAKE_SIZE) {
		return -EINVAL;
	}

	for (int i = 0; i < custom_len; i++) {
		sscanf(custom_hex_fake + (i << 1), "%2hhx", custom_buf + i);
	}

	def_section->fake_custom_pkt_sz = custom_len;
	def_section->fake_custom_pkt = (char *)custom_buf;

	return 0;
}

static int fake_custom_pl_get(char *buffer, const struct kernel_param *kp) {
	int cflen = def_section->fake_custom_pkt_sz;
	const uint8_t *cbf_data = def_section->fake_custom_pkt;
	int bflen = def_section->fake_custom_pkt_sz << 1;

	for (int i = 0; i < cflen; i++) {
		sprintf(buffer + (i << 1), "%02x", *((unsigned char *)cbf_data + i));
	}

	return bflen;
}

static const struct kernel_param_ops fake_custom_pl_ops = {
	.set = fake_custom_pl_set,
	.get = fake_custom_pl_get,
};

module_param_cb(fake_custom_payload, &fake_custom_pl_ops, &def_section->fake_custom_pkt, 0664);
