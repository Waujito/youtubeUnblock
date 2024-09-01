// Used to register target in iptables
#include <stdio.h>
#include <xtables.h>

#include <linux/netfilter_ipv6/ip6_tables.h>
#include "ipt_YTUNBLOCK.h"

#define _init __attribute__((constructor)) _INIT
#define __maybe_unused __attribute__((__unused__))

static void YTKB_help(void) {
	printf("Youtube Unblock - bypass youtube slowdown DPI in Russia\n");
}

static struct xtables_target ykb6_tg_reg = {
	.name           = "YTUNBLOCK",
	.version        = XTABLES_VERSION,
	.family         = NFPROTO_IPV6,
	.size           = XT_ALIGN(sizeof(struct xt_ytunblock_tginfo)),
	.userspacesize  = XT_ALIGN(sizeof(struct xt_ytunblock_tginfo)),
	.help           = YTKB_help,
};

void _init(void) {
    xtables_register_target(&ykb6_tg_reg);
}
