/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Vyatta Inc. <http://www.vyatta.com>
 */

#include <stdio.h>
#define _GNU_SOURCE
#include <netinet/ip_icmp.h>

#include <libnetfilter_queue/libnetfilter_queue_icmp.h>

#include "internal.h"

/**
 * \defgroup icmp ICMP helper functions
 *
 * \manonly
.SH SYNOPSIS
.nf
\fB
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue_icmp.h>
\endmanonly
 *
 * @{
 */

/**
 * nfq_icmp_get_hdr - get the ICMP header.
 * \param pktb: pointer to user-space network packet buffer
 * \returns validated pointer to the ICMP header or NULL if the ICMP header was
 * not set or if a minimal length check fails.
 * \note You have to call nfq_ip_set_transport_header() or
 * nfq_ip6_set_transport_header() first to set the ICMP header.
 */
EXPORT_SYMBOL
struct icmphdr *nfq_icmp_get_hdr(struct pkt_buff *pktb)
{
	if (pktb->transport_header == NULL)
		return NULL;

	/* No room for the ICMP header. */
	if (pktb_tail(pktb) - pktb->transport_header < sizeof(struct icmphdr))
		return NULL;

	return (struct icmphdr *)pktb->transport_header;
}

/**
 * @}
 */
