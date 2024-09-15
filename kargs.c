#include "config.h"
#include "raw_replacements.h"
#include "types.h"
#include <linux/moduleparam.h>

#define STR_MAXLEN 2048

struct config_t config = {
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
	.use_gso = 1,
#else
	.use_gso = false,
#endif

#ifdef DEBUG
	.verbose = 2,
#else
	.verbose = 1,
#endif

	.domains_str = defaul_snistr,
	.domains_strlen = sizeof(defaul_snistr),

	.queue_start_num = DEFAULT_QUEUE_NUM,
	.fake_sni_pkt = fake_sni_old,
	.fake_sni_pkt_sz = sizeof(fake_sni_old) - 1, // - 1 for null-terminator
};

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
	return 0;
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

module_param_cb(fake_sni, &boolean_parameter_ops, &config.fake_sni, 0664);
module_param_cb(fake_sni_seq_len, &unumeric_parameter_ops, &config.fake_sni_seq_len, 0664);
module_param_cb(faking_ttl, &unumeric_parameter_ops, &config.faking_ttl, 0664);
module_param_cb(fake_seq_offset, &unumeric_parameter_ops, &config.fakeseq_offset, 0664);
module_param_cb(frag_sni_reverse, &unumeric_parameter_ops, &config.frag_sni_reverse, 0664);
module_param_cb(frag_sni_faked, &boolean_parameter_ops, &config.frag_sni_faked, 0664);
module_param_cb(frag_middle_sni, &boolean_parameter_ops, &config.frag_middle_sni, 0664);
module_param_cb(frag_sni_pos, &unumeric_parameter_ops, &config.frag_sni_pos, 0664);
module_param_cb(fk_winsize, &unumeric_parameter_ops, &config.fk_winsize, 0664);
module_param_cb(synfake, &boolean_parameter_ops, &config.synfake, 0664);
module_param_cb(synfake_len, &unumeric_parameter_ops, &config.synfake_len, 0664);
module_param_cb(packet_mark, &unumeric_parameter_ops, &config.mark, 0664);

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
		config.domains_strlen = 0;
	} else {
		config.domains_strlen = len;
		if (len == 3 && !strncmp(val, "all", len)) {
			config.all_domains = 1;
		} else {
			config.all_domains = 0;
		}
	}


	return ret;
}

static const struct kernel_param_ops sni_domains_ops = {
	.set = sni_domains_set,
	.get = param_get_charp,
};

module_param_cb(sni_domains, &sni_domains_ops, &config.domains_str, 0664);

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
		config.exclude_domains_strlen = 0;
	} else {
		config.exclude_domains_strlen = len;
	}

	return ret;
}

static const struct kernel_param_ops exclude_domains_ops = {
	.set = exclude_domains_set,
	.get = param_get_charp,
};

module_param_cb(exclude_domains, &exclude_domains_ops, &config.exclude_domains_str, 0664);

module_param_cb(no_ipv6, &inverse_boolean_ops, &config.use_ipv6, 0664);
module_param_cb(silent, &inverse_boolean_ops, &config.verbose, 0664);
module_param_cb(quic_drop, &boolean_parameter_ops, &config.quic_drop, 0664);

static int verbose_trace_set(const char *val, const struct kernel_param *kp) {
	int n = 0, ret;
	ret = kstrtoint(val, 10, &n);
	if (ret != 0 || (n != 0 && n != 1))
		return -EINVAL;

	if (n) {
		n = VERBOSE_TRACE;
	} else {
		n = VERBOSE_DEBUG;
	}
	if (kp->arg == NULL) 
		return -EINVAL;

	*(int *)kp->arg = n;
	return 0;
}

static const struct kernel_param_ops verbose_trace_ops = {
	.set = verbose_trace_set,
	.get = param_get_int,
};
module_param_cb(trace, &verbose_trace_ops, &config.verbose, 0664);
