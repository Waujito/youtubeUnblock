/**
 * Thanks https://github.com/NICMx/Jool/blob/5f60dcda5944b01cc43c3be342aad26af8161bcb/include/nat64/mod/common/nf_wrapper.h for mapped kernel versions
 */
#ifndef _JOOL_MOD_NF_WRAPPER_H
#define _JOOL_MOD_NF_WRAPPER_H

/**
 * @file
 * The kernel API is far from static. In particular, the Netfilter packet entry
 * function keeps changing. nf_hook.c, the file where we declare our packet
 * entry function, has been quite difficult to read for a while now. It's pretty
 * amusing, because we don't even use any of the noisy arguments.
 *
 * This file declares a usable function header that abstracts away all those
 * useless arguments.
 */

#include <linux/version.h>

/* If this is a Red Hat-based kernel (Red Hat, CentOS, Fedora, etc)... */
#ifdef RHEL_RELEASE_CODE

#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		const struct nf_hook_state *state) \

#elif RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#else

#error "Sorry; this version of RHEL is not supported because it's kind of old."

#endif /* RHEL_RELEASE_CODE >= x */


/* If this NOT a RedHat-based kernel (Ubuntu, Debian, SuSE, etc)... */
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		void *priv, \
		struct sk_buff *skb, \
		const struct nf_hook_state *state)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct nf_hook_state *state)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		unsigned int hooknum, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#else
#error "Linux < 3.0 isn't supported at all."

#endif /* LINUX_VERSION_CODE > n */

#endif /* RHEL or not RHEL */

#endif /* _JOOL_MOD_NF_WRAPPER_H */
