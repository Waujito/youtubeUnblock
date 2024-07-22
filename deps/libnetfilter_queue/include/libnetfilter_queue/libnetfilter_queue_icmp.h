#ifndef _LIBNFQUEUE_ICMP_H_
#define _LIBNFQUEUE_ICMP_H_

struct pkt_buff;

struct icmphdr *nfq_icmp_get_hdr(struct pkt_buff *pktb);

#endif
