#include "utils.h"
#include "logging.h"
#include "types.h"

#ifndef KERNEL_SPACE 
#include <stdlib.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
	#include <net/ip6_checksum.h>
	#include <net/checksum.h>
#else
	#include <net/checksum.h>
#endif
#endif


void tcp4_set_checksum(struct tcphdr *tcph, struct iphdr *iph) 
{
#ifdef KERNEL_SPACE
	uint32_t tcp_packet_len = ntohs(iph->tot_len) - (iph->ihl << 2);
	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(
		iph->saddr, iph->daddr, tcp_packet_len,
		IPPROTO_TCP, 
		csum_partial(tcph, tcp_packet_len, 0));
#else
	nfq_tcp_compute_checksum_ipv4(tcph, iph);
#endif
}

void ip4_set_checksum(struct iphdr *iph) 
{
#ifdef KERNEL_SPACE
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);
#else
	nfq_ip_set_checksum(iph);
#endif
}

void tcp6_set_checksum(struct tcphdr *tcph, struct ip6_hdr *iph) {
#ifdef KERNEL_SPACE
	tcph->check = 0;
	tcph->check = csum_ipv6_magic(&iph->saddr, &iph->daddr, 
		 ntohs(iph->ip6_plen), IPPROTO_TCP, 
		 csum_partial(tcph, ntohs(iph->ip6_plen), 0));
#else
	nfq_tcp_compute_checksum_ipv6(tcph, iph);
#endif
}

int set_ip_checksum(void *iph, uint32_t iphb_len) {
	int ipvx = netproto_version(iph, iphb_len);

	if (ipvx == IP4VERSION) {
		ip4_set_checksum(iph);
	} else if (ipvx == IP6VERSION) { // IP6 has no checksums
	} else 
		return -1;

	return 0;
}

int set_tcp_checksum(struct tcphdr *tcph, void *iph, uint32_t iphb_len) {
	int ipvx = netproto_version(iph, iphb_len);

	if (ipvx == IP4VERSION) {
		tcp4_set_checksum(tcph, iph);
	} else if (ipvx == IP6VERSION) {
		tcp6_set_checksum(tcph, iph);
	} else 
		return -1;

	return 0;
}

int ip4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len, 
		       uint8_t **payload, uint32_t *plen) {
	if (pkt == NULL || buflen < sizeof(struct iphdr)) {
		lgerror(-EINVAL, "ip4_payload_split: pkt|buflen");
		return -EINVAL;
	}

	struct iphdr *hdr = (struct iphdr *)pkt;
	if (netproto_version(pkt, buflen) != IP4VERSION) {
		lgerror(-EINVAL, "ip4_payload_split: ipversion");
		return -EINVAL;
	}

	uint32_t hdr_len = hdr->ihl * 4;
	uint32_t pktlen = ntohs(hdr->tot_len);
	if (buflen < pktlen || hdr_len > pktlen) {
		lgerror(-EINVAL, "ip4_payload_split: buflen cmp pktlen");
		return -EINVAL;
	}

	if (iph) 
		*iph = hdr;
	if (iph_len)
		*iph_len = hdr_len;
	if (payload)
		*payload = pkt + hdr_len;
	if (plen)
		*plen = pktlen - hdr_len;

	return 0;
}

int tcp4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len,
		       struct tcphdr **tcph, uint32_t *tcph_len,
		       uint8_t **payload, uint32_t *plen) {
	struct iphdr *hdr;
	uint32_t hdr_len;
	struct tcphdr *thdr;
	uint32_t thdr_len;
	
	uint8_t *tcph_pl;
	uint32_t tcph_plen;

	if (ip4_payload_split(pkt, buflen, &hdr, &hdr_len, 
			&tcph_pl, &tcph_plen)){
		return -EINVAL;
	}


	if (
		hdr->protocol != IPPROTO_TCP || 
		tcph_plen < sizeof(struct tcphdr)) {
		return -EINVAL;
	}


	thdr = (struct tcphdr *)(tcph_pl);
	thdr_len = thdr->doff * 4;

	if (thdr_len > tcph_plen) {
		return -EINVAL;
	}

	if (iph) *iph = hdr;
	if (iph_len) *iph_len = hdr_len;
	if (tcph) *tcph = thdr;
	if (tcph_len) *tcph_len = thdr_len;
	if (payload) *payload = tcph_pl + thdr_len;
	if (plen) *plen = tcph_plen - thdr_len;

	return 0;
}

int ip6_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct ip6_hdr **iph, uint32_t *iph_len, 
		       uint8_t **payload, uint32_t *plen) {
	if (pkt == NULL || buflen < sizeof(struct ip6_hdr)) {
		lgerror(-EINVAL, "ip6_payload_split: pkt|buflen");
		return -EINVAL;
	}

	struct ip6_hdr *hdr = (struct ip6_hdr *)pkt;
	if (netproto_version(pkt, buflen) != 6) {
		lgerror(-EINVAL, "ip6_payload_split: ip6version");
		return -EINVAL;
	}

	uint32_t hdr_len = sizeof(struct ip6_hdr);
	uint32_t pktlen = ntohs(hdr->ip6_plen);
	if (buflen < pktlen) {
		lgerror(-EINVAL, "ip6_payload_split: buflen cmp pktlen: %d %d", buflen, pktlen);
		return -EINVAL;
	}

	if (iph) 
		*iph = hdr;
	if (iph_len)
		*iph_len = hdr_len;
	if (payload)
		*payload = pkt + hdr_len;
	if (plen)
		*plen = pktlen;

	return 0;
}

int tcp6_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct ip6_hdr **iph, uint32_t *iph_len,
		       struct tcphdr **tcph, uint32_t *tcph_len,
		       uint8_t **payload, uint32_t *plen) {
	struct ip6_hdr *hdr;
	uint32_t hdr_len;
	struct tcphdr *thdr;
	uint32_t thdr_len;
	
	uint8_t *tcph_pl;
	uint32_t tcph_plen;

	if (ip6_payload_split(pkt, buflen, &hdr, &hdr_len, 
			&tcph_pl, &tcph_plen)){
		return -EINVAL;
	}


	if (
		hdr->ip6_nxt != IPPROTO_TCP || 
		tcph_plen < sizeof(struct tcphdr)) {
		return -EINVAL;
	}


	thdr = (struct tcphdr *)(tcph_pl);
	thdr_len = thdr->doff * 4;

	if (thdr_len > tcph_plen) {
		return -EINVAL;
	}

	if (iph) *iph = hdr;
	if (iph_len) *iph_len = hdr_len;
	if (tcph) *tcph = thdr;
	if (tcph_len) *tcph_len = thdr_len;
	if (payload) *payload = tcph_pl + thdr_len;
	if (plen) *plen = tcph_plen - thdr_len;

	return 0;
}

int tcp_payload_split(uint8_t *pkt, uint32_t buflen,
		      void **iph, uint32_t *iph_len,
		      struct tcphdr **tcph, uint32_t *tcph_len,
		      uint8_t **payload, uint32_t *plen) {
	int netvers = netproto_version(pkt, buflen);
	if (netvers == IP4VERSION) {
		return tcp4_payload_split(pkt, buflen, (struct iphdr **)iph, iph_len, tcph, tcph_len, payload, plen);
	} else if (netvers == IP6VERSION) {
		return tcp6_payload_split(pkt, buflen, (struct ip6_hdr **)iph, iph_len, tcph, tcph_len, payload, plen);
	} else {
		lgerror(-EINVAL, "Internet Protocol version is unsupported");
		return -EINVAL;
	}
}


int udp4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len,
		       struct udphdr **udph,
		       uint8_t **payload, uint32_t *plen) {
	struct iphdr *hdr;
	uint32_t hdr_len;
	struct udphdr *uhdr;
	
	uint8_t *ip_ph;
	uint32_t ip_phlen;

	if (ip4_payload_split(pkt, buflen, &hdr, &hdr_len, 
			&ip_ph, &ip_phlen)){
		return -EINVAL;
	}


	if (
		hdr->protocol != IPPROTO_UDP || 
		ip_phlen < sizeof(struct udphdr)) {
		return -EINVAL;
	}


	uhdr = (struct udphdr *)(ip_ph);
	if (uhdr->len != 0 && ntohs(uhdr->len) != ip_phlen) {
		return -EINVAL;
	}

	if (iph) *iph = hdr;
	if (iph_len) *iph_len = hdr_len;
	if (udph) *udph = uhdr;
	if (payload) *payload = ip_ph + sizeof(struct udphdr);
	if (plen) *plen = ip_phlen - sizeof(struct udphdr);

	return 0;
}

int udp6_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct ip6_hdr **iph, uint32_t *iph_len,
		       struct udphdr **udph,
		       uint8_t **payload, uint32_t *plen) {
	struct ip6_hdr *hdr;
	uint32_t hdr_len;
	struct udphdr *uhdr;
	
	uint8_t *ip_ph;
	uint32_t ip_phlen;

	if (ip6_payload_split(pkt, buflen, &hdr, &hdr_len, 
			&ip_ph, &ip_phlen)){
		return -EINVAL;
	}


	if (
		hdr->ip6_nxt != IPPROTO_UDP || 
		ip_phlen < sizeof(struct udphdr)) {
		return -EINVAL;
	}


	uhdr = (struct udphdr *)(ip_ph);
	if (uhdr->len != 0 && ntohs(uhdr->len) != ip_phlen) {
		return -EINVAL;
	}

	if (iph) *iph = hdr;
	if (iph_len) *iph_len = hdr_len;
	if (udph) *udph = uhdr;
	if (payload) *payload = ip_ph + sizeof(struct udphdr);
	if (plen) *plen = ip_phlen - sizeof(struct udphdr);

	return 0;
}

int udp_payload_split(uint8_t *pkt, uint32_t buflen,
		      void **iph, uint32_t *iph_len,
		      struct udphdr **udph,
		      uint8_t **payload, uint32_t *plen) {
	int netvers = netproto_version(pkt, buflen);
	if (netvers == IP4VERSION) {
		return udp4_payload_split(pkt, buflen, (struct iphdr **)iph, iph_len, udph, payload, plen);
	} else if (netvers == IP6VERSION) {
		return udp6_payload_split(pkt, buflen, (struct ip6_hdr **)iph, iph_len, udph, payload, plen);
	} else {
		lgerror(-EINVAL, "Internet Protocol version is unsupported");
		return -EINVAL;
	}
}

// split packet to two ipv4 fragments.
int ip4_frag(const uint8_t *pkt, uint32_t buflen, uint32_t payload_offset, 
			uint8_t *frag1, uint32_t *f1len, 
			uint8_t *frag2, uint32_t *f2len) {
	
	struct iphdr *hdr;
	const uint8_t *payload;
	uint32_t plen;
	uint32_t hdr_len;
	int ret;

	if (!frag1 || !f1len || !frag2 || !f2len)
		return -EINVAL;

	if ((ret = ip4_payload_split(
		(uint8_t *)pkt, buflen, 
		&hdr, &hdr_len, (uint8_t **)&payload, &plen)) < 0) {
		lgerror(ret, "ipv4_frag: TCP Header extract error");
		return -EINVAL;
	}

	if (plen <= payload_offset) {
		return -EINVAL;
	}

	if (payload_offset & ((1 << 3) - 1)) {
		lgerror(-EINVAL, "ipv4_frag: Payload offset MUST be a multiply of 8!");

		return -EINVAL;
	}

	uint32_t f1_plen = payload_offset;
	uint32_t f1_dlen = f1_plen + hdr_len;

	uint32_t f2_plen = plen - payload_offset;
	uint32_t f2_dlen = f2_plen + hdr_len;

	if (*f1len < f1_dlen || *f2len < f2_dlen) {
		return -ENOMEM;
	}
	*f1len = f1_dlen;
	*f2len = f2_dlen;

	memcpy(frag1, hdr, hdr_len);
	memcpy(frag2, hdr, hdr_len);

	memcpy(frag1 + hdr_len, payload, f1_plen);
	memcpy(frag2 + hdr_len, payload + payload_offset, f2_plen);

	struct iphdr *f1_hdr = (void *)frag1;
	struct iphdr *f2_hdr = (void *)frag2;

	uint16_t f1_frag_off = ntohs(f1_hdr->frag_off);
	uint16_t f2_frag_off = ntohs(f2_hdr->frag_off);

	f1_frag_off &= IP_OFFMASK;
	f1_frag_off |= IP_MF;
	
	if ((f2_frag_off & ~IP_OFFMASK) == IP_MF) {
		f2_frag_off &= IP_OFFMASK;
		f2_frag_off |= IP_MF;
	} else {
		f2_frag_off &= IP_OFFMASK;
	}
	
	f2_frag_off += (uint16_t)payload_offset / 8;

	f1_hdr->frag_off = htons(f1_frag_off);
	f1_hdr->tot_len = htons(f1_dlen);

	f2_hdr->frag_off = htons(f2_frag_off);
	f2_hdr->tot_len = htons(f2_dlen);

	ip4_set_checksum(f1_hdr);
	ip4_set_checksum(f2_hdr);

	return 0;
}

// split packet to two tcp-on-ipv4 segments.
int tcp_frag(const uint8_t *pkt, uint32_t buflen, uint32_t payload_offset, 
			uint8_t *seg1, uint32_t *s1len, 
			uint8_t *seg2, uint32_t *s2len) {

	void *hdr;
	uint32_t hdr_len;
	struct tcphdr *tcph;
	uint32_t tcph_len;
	uint32_t plen;
	const uint8_t *payload;
	int ret;

	if (!seg1 || !s1len || !seg2 || !s2len)
		return -EINVAL;

	if ((ret = tcp_payload_split((uint8_t *)pkt, buflen,
				&hdr, &hdr_len,
				&tcph, &tcph_len,
				(uint8_t **)&payload, &plen)) < 0) {
		lgerror(ret, "tcp_frag: tcp_payload_split");

		return -EINVAL;
	}

	int ipvx = netproto_version(pkt, buflen);


	if (ipvx == IP4VERSION) {
		struct iphdr *iphdr = hdr;
		if (
			ntohs(iphdr->frag_off) & IP_MF || 
			ntohs(iphdr->frag_off) & IP_OFFMASK) {
			lgdebugmsg("tcp_frag: ip4: frag value: %d",
				ntohs(iphdr->frag_off));
			lgerror(-EINVAL, "tcp_frag: ip4: ip fragmentation is set");
			return -EINVAL;
		}
	}


	if (plen <= payload_offset) {
		return -EINVAL;
	}

	uint32_t s1_plen = payload_offset;
	uint32_t s1_dlen = s1_plen + hdr_len + tcph_len;

	uint32_t s2_plen = plen - payload_offset;
	uint32_t s2_dlen = s2_plen + hdr_len + tcph_len;

	if (*s1len < s1_dlen || *s2len < s2_dlen) 
		return -ENOMEM;

	*s1len = s1_dlen;
	*s2len = s2_dlen;

	memcpy(seg1, hdr, hdr_len);
	memcpy(seg2, hdr, hdr_len);

	memcpy(seg1 + hdr_len, tcph, tcph_len);
	memcpy(seg2 + hdr_len, tcph, tcph_len);

	memcpy(seg1 + hdr_len + tcph_len, payload, s1_plen);
	memcpy(seg2 + hdr_len + tcph_len, payload + payload_offset, s2_plen);

	if (ipvx == IP4VERSION) {
		struct iphdr *s1_hdr = (void *)seg1;
		struct iphdr *s2_hdr = (void *)seg2;
		s1_hdr->tot_len = htons(s1_dlen);
		s2_hdr->tot_len = htons(s2_dlen);
		s1_hdr->id = randint();
		s2_hdr->id = randint();

		set_ip_checksum(s1_hdr, sizeof(struct iphdr));
		set_ip_checksum(s2_hdr, sizeof(struct iphdr));
	} else {
		struct ip6_hdr *s1_hdr = (void *)seg1;
		struct ip6_hdr *s2_hdr = (void *)seg2;
		s1_hdr->ip6_plen = htons(s1_dlen - hdr_len);
		s2_hdr->ip6_plen = htons(s2_dlen - hdr_len);
	}

	struct tcphdr *s1_tcph = (void *)(seg1 + hdr_len);
	struct tcphdr *s2_tcph = (void *)(seg2 + hdr_len);
	
	s2_tcph->seq = htonl(ntohl(s2_tcph->seq) + payload_offset);

	set_tcp_checksum(s1_tcph, seg1, hdr_len);
	set_tcp_checksum(s2_tcph, seg2, hdr_len);

	return 0;
}

void z_function(const char *str, int *zbuf, size_t len) {
	zbuf[0] = len;

	int lh = 0, rh = 1;
	for (int i = 1; i < (int)len; i++) {
		zbuf[i] = 0;
		if (i < rh) {
			zbuf[i] = zbuf[i - lh];
			if (rh - i < zbuf[i])
				zbuf[i] = rh - i;
		}

		while (i + zbuf[i] < len && str[zbuf[i]] == str[i + zbuf[i]])
			zbuf[i]++;

		if (i + zbuf[i] > rh) {
			lh = i;
			rh = i + zbuf[i];
		}
	}
}

void shift_data(uint8_t *data, uint32_t dlen, uint32_t delta) {
	uint8_t *ndptr = data + delta + dlen;
	uint8_t *dptr = data + dlen;
	uint8_t *ndlptr = data;
	for (size_t i = dlen + 1; i > 0; i--) {
		*ndptr = *dptr;
		--ndptr, --dptr;
	}
	for (size_t i = 0; i < delta; i++) {
		*ndlptr++ = 0;
	}
}

#define TCP_MD5SIG_LEN 16
#define TCP_MD5SIG_KIND 19
struct tcp_md5sig_opt {
	uint8_t kind;
	uint8_t len;
	uint8_t sig[TCP_MD5SIG_LEN];
};
#define TCP_MD5SIG_OPT_LEN (sizeof(struct tcp_md5sig_opt))
// Real length of the option, with NOOP fillers
#define TCP_MD5SIG_OPT_RLEN 20

int fail_packet(struct failing_strategy strategy, uint8_t *payload, uint32_t *plen, uint32_t avail_buflen) {
	void *iph;
	uint32_t iph_len;
	struct tcphdr *tcph;
	uint32_t tcph_len;
	uint8_t *data;
	uint32_t dlen;
	int ret;

	ret = tcp_payload_split(payload, *plen, 
			&iph, &iph_len, &tcph, &tcph_len,
			&data, &dlen);

	uint32_t ipxv = netproto_version(payload, *plen);

	if (ret < 0) {
		return ret;
	}


	if (strategy.strategy == FAKE_STRAT_RAND_SEQ) {
		lgtrace("fake seq: %u -> ", ntohl(tcph->seq));

		tcph->seq = htonl(ntohl(tcph->seq) - (strategy.randseq_offset + dlen));

		lgtrace_addp("%u", ntohl(tcph->seq));
	} else if (strategy.strategy == FAKE_STRAT_PAST_SEQ) {
		lgtrace("fake seq: %u -> ", ntohl(tcph->seq));
		tcph->seq = htonl(ntohl(tcph->seq) - dlen);
		lgtrace_addp("%u", ntohl(tcph->seq));

	} else if (strategy.strategy == FAKE_STRAT_TTL) {
		lgtrace_addp("set fake ttl to %d", strategy.faking_ttl);

		if (ipxv == IP4VERSION) {
			((struct iphdr *)iph)->ttl = strategy.faking_ttl;
		} else if (ipxv == IP6VERSION) {
			((struct ip6_hdr *)iph)->ip6_hops = strategy.faking_ttl;
		} else {
			lgerror(-EINVAL, "fail_packet: IP version is unsupported");
			return -EINVAL;
		}
	} else if (strategy.strategy == FAKE_STRAT_TCP_MD5SUM) {
		int optp_len = tcph_len - sizeof(struct tcphdr);
		int delta = TCP_MD5SIG_OPT_RLEN - optp_len;
		lgtrace_addp("Incr delta %d: %d -> %d", delta, optp_len, optp_len + delta);
		
		if (delta > 0) {
			if (avail_buflen - *plen < delta) {
				return -1;
			}

			shift_data(data, dlen, delta);
			data += delta;
			tcph_len = tcph_len + delta;
			tcph->doff = tcph_len >> 2;
			if (ipxv == IP4VERSION) {
				((struct iphdr *)iph)->tot_len = htons(ntohs(((struct iphdr *)iph)->tot_len) + delta);
			} else if (ipxv == IP6VERSION) {
				((struct ip6_hdr *)iph)->ip6_plen = htons(ntohs(((struct ip6_hdr *)iph)->ip6_plen) + delta);
			} else {
				lgerror(-EINVAL, "fail_packet: IP version is unsupported");
				return -EINVAL;
			}
			optp_len += delta;
			*plen += delta;
		}

		uint8_t *optplace = (uint8_t *)tcph + sizeof(struct tcphdr);
		struct tcp_md5sig_opt *mdopt = (void *)optplace;
		mdopt->kind = TCP_MD5SIG_KIND;
		mdopt->len = TCP_MD5SIG_OPT_LEN;

		optplace += sizeof(struct tcp_md5sig_opt);
		optp_len -= sizeof(struct tcp_md5sig_opt);

		while (optp_len-- > 0) {
			*optplace++ = 0x01;
		}
	}

	if (ipxv == IP4VERSION) {
		((struct iphdr *)iph)->frag_off = 0;
	}


	set_ip_checksum(iph, iph_len);
	set_tcp_checksum(tcph, iph, iph_len);

	if (strategy.strategy == FAKE_STRAT_TCP_CHECK) {
		lgtrace_addp("break fake tcp checksum");
		tcph->check += 1;
	}

	return 0;
}

int seqovl_packet(uint8_t *payload, uint32_t *plen, uint32_t seq_delta) {
	int ipxv = netproto_version(payload, *plen);

	void *iph;
	uint32_t iph_len;
	struct tcphdr *tcph;
	uint32_t tcph_len;
	uint8_t *data;
	uint32_t dlen;


	int ret = tcp_payload_split(payload, *plen,
			      &iph, &iph_len, &tcph, &tcph_len,
			      &data, &dlen);

	if (ret < 0) {
		return -1;
	}

	if (ipxv == IP4VERSION) {
		struct iphdr *ip4h = iph;
		ip4h->tot_len = htons(ntohs(ip4h->tot_len) + seq_delta); 
	} else if (ipxv == IP6VERSION) {
		struct ip6_hdr *ip6h = iph;
		ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) + seq_delta); 
	} else {
		return -1;
	}

	tcph->seq = htons(ntohs(tcph->seq) - seq_delta);
	shift_data(data, dlen, seq_delta);
	*plen += seq_delta;

	set_ip_checksum(iph, iph_len);
	set_tcp_checksum(tcph, iph, iph_len);
	return 0;
}

