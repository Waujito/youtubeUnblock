#include <stdlib.h>
#define _GNU_SOURCE
#include "mangle.h"
#include "config.h"

#ifdef KERNEL_SPACE
#include <linux/printk.h>
#include <linux/ip.h>

#define printf pr_info
#define perror pr_err
#define lgerror(msg, ret) (pr_err(msg ": %d\n", ret))
#else 
#include <stdio.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint16_t __u16;

#define lgerror(msg, ret) __extension__ ({errno = -ret; perror(msg);})
#endif


int process_packet(const uint8_t *raw_payload, uint32_t raw_payload_len) {
	if (raw_payload_len > MAX_PACKET_SIZE) {
		return PKT_ACCEPT;
	}

	const struct iphdr *iph;
	uint32_t iph_len;
	const struct tcphdr *tcph;
	uint32_t tcph_len;
	const uint8_t *data;
	uint32_t dlen;

	int ret = tcp4_payload_split((uint8_t *)raw_payload, raw_payload_len,
			      (struct iphdr **)&iph, &iph_len, (struct tcphdr **)&tcph, &tcph_len,
			      (uint8_t **)&data, &dlen);

	if (ret < 0) {
		goto accept;
	}

	struct tls_verdict vrd = analyze_tls_data(data, dlen);

	if (vrd.target_sni) {
		if (config.verbose)
			printf("Target SNI detected: %.*s\n", vrd.sni_len, data + vrd.sni_offset);

		uint8_t payload[MAX_PACKET_SIZE];
		uint32_t payload_len = raw_payload_len;
		memcpy(payload, raw_payload, raw_payload_len);

		struct iphdr *iph;
		uint32_t iph_len;
		struct tcphdr *tcph;
		uint32_t tcph_len;
		uint8_t *data;
		uint32_t dlen;

		int ret = tcp4_payload_split(payload, payload_len,
				      &iph, &iph_len, &tcph, &tcph_len,
				      &data, &dlen);

		if (config.fk_winsize) {
			tcph->window = htons(config.fk_winsize);
		}

		ip4_set_checksum(iph);
		tcp4_set_checksum(tcph, iph);

		
		if (dlen > 1480 && config.verbose) {
			printf("WARNING! Client Hello packet is too big and may cause issues!\n");
		}

		if (config.fake_sni) {
			post_fake_sni(iph, iph_len, tcph, tcph_len, 
				config.fake_sni_seq_len);	
		}

		size_t ipd_offset;
		size_t mid_offset;

		switch (config.fragmentation_strategy) {
			case FRAG_STRAT_TCP: {
				ipd_offset = vrd.sni_offset;
				mid_offset = ipd_offset + vrd.sni_len / 2;

				uint32_t poses[] = { 2, mid_offset };

				ret = send_tcp4_frags(payload, payload_len, poses, 2, 0);
				if (ret < 0) {
					lgerror("tcp4 send frags", ret);
					goto accept;
				}

				goto drop;
			}
			break;
			case FRAG_STRAT_IP: {
				ipd_offset = ((char *)data - (char *)tcph) + vrd.sni_offset;
				mid_offset = ipd_offset + vrd.sni_len / 2;
				mid_offset += 8 - mid_offset % 8;

				uint32_t poses[] = { mid_offset };
				ret = send_ip4_frags(payload, payload_len, poses, 1, 0);
				if (ret < 0) {
					lgerror("ip4 send frags", ret);
					goto accept;
				}

				goto drop;
			}
			break;
			default:
				ret = instance_config.send_raw_packet(payload, payload_len);
				if (ret < 0) {
					lgerror("raw pack send", ret);
					goto accept;
				}

				goto drop;
		}



		goto drop;
	}

accept:
	return PKT_ACCEPT;
drop:
	return PKT_DROP;
}

int send_ip4_frags(const uint8_t *packet, uint32_t pktlen, const uint32_t *poses, uint32_t poses_sz, uint32_t dvs) {
	if (poses_sz == 0) {
		if (config.seg2_delay && ((dvs > 0) ^ config.frag_sni_reverse)) {
			if (!instance_config.send_delayed_packet) {
				return -EINVAL;
			}

			instance_config.send_delayed_packet(
				packet, pktlen, config.seg2_delay);

			return 0;
		} else {
			return instance_config.send_raw_packet(
				packet, pktlen);
		}
	} else {
		uint8_t frag1[MAX_PACKET_SIZE];
		uint8_t frag2[MAX_PACKET_SIZE];
		uint32_t f1len = MAX_PACKET_SIZE;
		uint32_t f2len = MAX_PACKET_SIZE;

		int ret;

		if (dvs > poses[0]) {
			printf("send_frags: Recursive dvs(%d) is more than poses0(%d)\n", dvs, poses[0]);
			return -EINVAL;
		}

		ret = ip4_frag(packet, pktlen, poses[0] - dvs, 
			frag1, &f1len, frag2, &f2len);

		if (ret < 0) {
			lgerror("send_frags: frag", ret);
			printf("Error context: packet with size %d, position: %d, recursive dvs: %d\n", pktlen, poses[0], dvs);
			return ret;
		}

		if (config.frag_sni_reverse)
			goto send_frag2;
send_frag1:
		ret = send_ip4_frags(frag1, f1len, NULL, 0, 0);
		if (ret < 0) {
			return ret;
		}

		if (config.frag_sni_reverse)
			goto out;

send_frag2:
		dvs += poses[0];
		ret = send_ip4_frags(frag2, f2len, poses + 1, poses_sz - 1, dvs);
		if (ret < 0) {
			return ret;
		}

		if (config.frag_sni_reverse)
			goto send_frag1;
	}

out:
	return 0;
}

int send_tcp4_frags(const uint8_t *packet, uint32_t pktlen, const uint32_t *poses, uint32_t poses_sz, uint32_t dvs) {
	if (poses_sz == 0) {
		if (config.seg2_delay && ((dvs > 0) ^ config.frag_sni_reverse)) {
			if (!instance_config.send_delayed_packet) {
				return -EINVAL;
			}

			instance_config.send_delayed_packet(
				packet, pktlen, config.seg2_delay);

			return 0;
		} else {
			return instance_config.send_raw_packet(
				packet, pktlen);
		}
	} else {
		uint8_t frag1[MAX_PACKET_SIZE];
		uint8_t frag2[MAX_PACKET_SIZE];
		uint8_t fake_pad[MAX_PACKET_SIZE];
		uint32_t f1len = MAX_PACKET_SIZE;
		uint32_t f2len = MAX_PACKET_SIZE;

		int ret;

		if (dvs > poses[0]) {
			printf("send_frags: Recursive dvs(%d) is more than poses0(%d)\n", dvs, poses[0]);
			return -EINVAL;
		}

		ret = tcp4_frag(packet, pktlen, poses[0] - dvs, 
			frag1, &f1len, frag2, &f2len);

		if (ret < 0) {
			lgerror("send_frags: frag", ret);
			printf("Error context: packet with size %d, position: %d, recursive dvs: %d\n", pktlen, poses[0], dvs);
			return ret;
		}

		if (config.frag_sni_reverse)
			goto send_frag2;
		
send_frag1:
		{
			ret = send_tcp4_frags(frag1, f1len, NULL, 0, 0);
			if (ret < 0) {
				return ret;
			}

			if (config.frag_sni_reverse) 
				goto out;
		}

send_fake:
		if (config.frag_sni_faked) {
			uint32_t iphfl, tcphfl;
			ret = tcp4_payload_split(frag2, f2len, NULL, &iphfl, NULL, &tcphfl, NULL, NULL);
			if (ret < 0) {
				lgerror("Invalid frag2", ret);
				return ret;
			}
			memcpy(fake_pad, frag2, iphfl + tcphfl);
			memset(fake_pad + iphfl + tcphfl, 0, f2len - iphfl - tcphfl);
			ret = fail4_packet(fake_pad, f2len);
			if (ret < 0) {
				lgerror("Failed to fail packet", ret);
				return ret;
			}
			ret = send_tcp4_frags(fake_pad, f2len, NULL, 0, 0);
			if (ret < 0) {
				return ret;
			}

		}

		if (config.frag_sni_reverse)
			goto send_frag1;

send_frag2:
		{
			dvs += poses[0];
			ret = send_tcp4_frags(frag2, f2len, poses + 1, poses_sz - 1, dvs);
			if (ret < 0) {
				return ret;
			}

			if (config.frag_sni_reverse)
				goto send_fake;
		}
	}
out:
	return 0;
}

int post_fake_sni(const struct iphdr *iph, unsigned int iph_len, 
		     const struct tcphdr *tcph, unsigned int tcph_len,
		     unsigned char sequence_len) {
	uint8_t rfsiph[60];
	uint8_t rfstcph[60];
	int ret;

	memcpy(rfsiph, iph, iph_len);
	memcpy(rfstcph, tcph, tcph_len);

	struct iphdr *fsiph = (void *)rfsiph;
	struct tcphdr *fstcph = (void *)rfstcph;

	for (int i = 0; i < sequence_len; i++) {
		uint8_t fake_sni[MAX_PACKET_SIZE];
		uint32_t fsn_len = MAX_PACKET_SIZE;
		ret = gen_fake_sni(fsiph, fstcph, fake_sni, &fsn_len);
		if (ret < 0) {
			lgerror("gen_fake_sni", ret);
			return ret;
		}

		ret = instance_config.send_raw_packet(fake_sni, fsn_len);
		if (ret < 0) {
			lgerror("send fake sni", ret);
			return ret;
		}

		uint32_t iph_len;
		uint32_t tcph_len;
		uint32_t plen;
		tcp4_payload_split(
			fake_sni, fsn_len, 
			&fsiph, &iph_len, &fstcph, &tcph_len,
			NULL, &plen);


		fstcph->seq = htonl(ntohl(fstcph->seq) + plen);
		memcpy(rfsiph, fsiph, iph_len);
		memcpy(rfstcph, fstcph, tcph_len);
		fsiph = (void *)rfsiph;
		fstcph = (void *)rfstcph;

	}

	return 0;
}

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


int ip4_payload_split(__u8 *pkt, __u32 buflen,
		       struct iphdr **iph, __u32 *iph_len, 
		       __u8 **payload, __u32 *plen) {
	if (pkt == NULL || buflen < sizeof(struct iphdr)) {
		lgerror("ip4_payload_split: pkt|buflen", -EINVAL);
		return -EINVAL;
	}

	struct iphdr *hdr = (struct iphdr *)pkt;
	if (hdr->version != IPVERSION) {
		lgerror("ip4_payload_split: ipversion", -EINVAL);
		return -EINVAL;
	}

	__u32 hdr_len = hdr->ihl * 4;
	__u32 pktlen = ntohs(hdr->tot_len);
	if (buflen < pktlen || hdr_len > pktlen) {
		lgerror("ip4_payload_split: buflen cmp pktlen", -EINVAL);
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

int tcp4_payload_split(__u8 *pkt, __u32 buflen,
		       struct iphdr **iph, __u32 *iph_len,
		       struct tcphdr **tcph, __u32 *tcph_len,
		       __u8 **payload, __u32 *plen) {
	struct iphdr *hdr;
	__u32 hdr_len;
	struct tcphdr *thdr;
	__u32 thdr_len;
	
	__u8 *tcph_pl;
	__u32 tcph_plen;

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

// split packet to two ipv4 fragments.
int ip4_frag(const __u8 *pkt, __u32 buflen, __u32 payload_offset, 
			__u8 *frag1, __u32 *f1len, 
			__u8 *frag2, __u32 *f2len) {
	
	struct iphdr *hdr;
	const __u8 *payload;
	__u32 plen;
	__u32 hdr_len;
	int ret;

	if (!frag1 || !f1len || !frag2 || !f2len)
		return -EINVAL;

	if ((ret = ip4_payload_split(
		(__u8 *)pkt, buflen, 
		&hdr, &hdr_len, (__u8 **)&payload, &plen)) < 0) {
		lgerror("ipv4_frag: TCP Header extract error", ret);
		return -EINVAL;
	}

	if (plen <= payload_offset) {
		return -EINVAL;
	}

	if (payload_offset & ((1 << 3) - 1)) {
		lgerror("ipv4_frag: Payload offset MUST be a multiply of 8!", -EINVAL);

		return -EINVAL;
	}

	__u32 f1_plen = payload_offset;
	__u32 f1_dlen = f1_plen + hdr_len;

	__u32 f2_plen = plen - payload_offset;
	__u32 f2_dlen = f2_plen + hdr_len;

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

	__u16 f1_frag_off = ntohs(f1_hdr->frag_off);
	__u16 f2_frag_off = ntohs(f2_hdr->frag_off);

	f1_frag_off &= IP_OFFMASK;
	f1_frag_off |= IP_MF;
	
	if ((f2_frag_off & ~IP_OFFMASK) == IP_MF) {
		f2_frag_off &= IP_OFFMASK;
		f2_frag_off |= IP_MF;
	} else {
		f2_frag_off &= IP_OFFMASK;
	}
	
	f2_frag_off += (__u16)payload_offset / 8;

	f1_hdr->frag_off = htons(f1_frag_off);
	f1_hdr->tot_len = htons(f1_dlen);

	f2_hdr->frag_off = htons(f2_frag_off);
	f2_hdr->tot_len = htons(f2_dlen);


	if (config.verbose)
		printf("Packet split in portion %u %u\n", f1_plen, f2_plen);

	ip4_set_checksum(f1_hdr);
	ip4_set_checksum(f2_hdr);

	return 0;
}

// split packet to two tcp-on-ipv4 segments.
int tcp4_frag(const __u8 *pkt, __u32 buflen, __u32 payload_offset, 
			__u8 *seg1, __u32 *s1len, 
			__u8 *seg2, __u32 *s2len) {

	struct iphdr *hdr;
	__u32 hdr_len;
	struct tcphdr *tcph;
	__u32 tcph_len;
	__u32 plen;
	const __u8 *payload;
	int ret;

	if (!seg1 || !s1len || !seg2 || !s2len)
		return -EINVAL;

	if ((ret = tcp4_payload_split((__u8 *)pkt, buflen,
				&hdr, &hdr_len,
				&tcph, &tcph_len,
				(__u8 **)&payload, &plen)) < 0) {
		lgerror("tcp4_frag: tcp4_payload_split", ret);

		return -EINVAL;
	}


	if (
		ntohs(hdr->frag_off) & IP_MF || 
		ntohs(hdr->frag_off) & IP_OFFMASK) {
		printf("tcp4_frag: frag value: %d\n",
			ntohs(hdr->frag_off));
		lgerror("tcp4_frag: ip fragmentation is set", -EINVAL);
		return -EINVAL;
	}


	if (plen <= payload_offset) {
		return -EINVAL;
	}

	__u32 s1_plen = payload_offset;
	__u32 s1_dlen = s1_plen + hdr_len + tcph_len;

	__u32 s2_plen = plen - payload_offset;
	__u32 s2_dlen = s2_plen + hdr_len + tcph_len;

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

	struct iphdr *s1_hdr = (void *)seg1;
	struct iphdr *s2_hdr = (void *)seg2;

	struct tcphdr *s1_tcph = (void *)(seg1 + hdr_len);
	struct tcphdr *s2_tcph = (void *)(seg2 + hdr_len);

	s1_hdr->tot_len = htons(s1_dlen);
	s2_hdr->tot_len = htons(s2_dlen);

	s2_tcph->seq = htonl(ntohl(s2_tcph->seq) + payload_offset);

	if (config.verbose)
		printf("Packet split in portion %u %u\n", s1_plen, s2_plen);

	tcp4_set_checksum(s1_tcph, s1_hdr);
	tcp4_set_checksum(s2_tcph, s2_hdr);

	return 0;
}

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_EXTENSION_SNI 0x0000
#define TLS_EXTENSION_CLIENT_HELLO_ENCRYPTED 0xfe0d

typedef __u8 uint8_t;
typedef __u32 uint32_t;
typedef __u16 uint16_t;

/**
 * Processes tls payload of the tcp request.
 * 
 * data Payload data of TCP.
 * dlen Length of `data`.
 */
struct tls_verdict analyze_tls_data(
	const uint8_t *data, 
	uint32_t dlen) 
{
	struct tls_verdict vrd = {0};

	size_t i = 0;
	const uint8_t *data_end = data + dlen;

	while (i + 4 < dlen) {
		const uint8_t *msgData = data + i;

		uint8_t tls_content_type = *msgData;
		uint8_t tls_vmajor = *(msgData + 1);
		uint8_t tls_vminor = *(msgData + 2);
		uint16_t message_length = ntohs(*(uint16_t *)(msgData + 3));
		const uint8_t *message_length_ptr = msgData + 3;


		if (i + 5 + message_length > dlen) break;

		if (tls_content_type != TLS_CONTENT_TYPE_HANDSHAKE) 
			goto nextMessage;


		const uint8_t *handshakeProto = msgData + 5;

		if (handshakeProto + 1 >= data_end) break;

		uint8_t handshakeType = *handshakeProto;

		if (handshakeType != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
			goto nextMessage;

		const uint8_t *msgPtr = handshakeProto;
		msgPtr += 1; 
		const uint8_t *handshakeProto_length_ptr = msgPtr + 1;
		msgPtr += 3 + 2 + 32;

		if (msgPtr + 1 >= data_end) break;
		uint8_t sessionIdLength = *msgPtr;
		msgPtr++;
		msgPtr += sessionIdLength;

		if (msgPtr + 2 >= data_end) break;
		uint16_t ciphersLength = ntohs(*(uint16_t *)msgPtr);
		msgPtr += 2;
		msgPtr += ciphersLength;

		if (msgPtr + 1 >= data_end) break;
		uint8_t compMethodsLen = *msgPtr;
		msgPtr++;
		msgPtr += compMethodsLen;

		if (msgPtr + 2 >= data_end) break;
		uint16_t extensionsLen = ntohs(*(uint16_t *)msgPtr);
		const uint8_t *extensionsLen_ptr = msgPtr;
		msgPtr += 2;

		const uint8_t *extensionsPtr = msgPtr;
		const uint8_t *extensions_end = extensionsPtr + extensionsLen;
		if (extensions_end > data_end) break;

		while (extensionsPtr < extensions_end) {
			const uint8_t *extensionPtr = extensionsPtr;
			if (extensionPtr + 4 >= extensions_end) break;

			uint16_t extensionType = 
				ntohs(*(uint16_t *)extensionPtr);
			extensionPtr += 2;

			uint16_t extensionLen = 
				ntohs(*(uint16_t *)extensionPtr);
			const uint8_t *extensionLen_ptr = extensionPtr;
			extensionPtr += 2;


			if (extensionPtr + extensionLen > extensions_end) 
				break;

			if (extensionType != TLS_EXTENSION_SNI) 
				goto nextExtension;

			const uint8_t *sni_ext_ptr = extensionPtr;

			if (sni_ext_ptr + 2 >= extensions_end) break;
			uint16_t sni_ext_dlen = ntohs(*(uint16_t *)sni_ext_ptr);

			const uint8_t *sni_ext_dlen_ptr = sni_ext_ptr;
			sni_ext_ptr += 2;

			const uint8_t *sni_ext_end = sni_ext_ptr + sni_ext_dlen;
			if (sni_ext_end >= extensions_end) break;
			
			if (sni_ext_ptr + 3 >= sni_ext_end) break;
			uint8_t sni_type = *sni_ext_ptr++;
			uint16_t sni_len = ntohs(*(uint16_t *)sni_ext_ptr);
			sni_ext_ptr += 2;

			if (sni_ext_ptr + sni_len > sni_ext_end) break;

			char *sni_name = (char *)sni_ext_ptr;

			vrd.sni_offset = (uint8_t *)sni_name - data;
			vrd.sni_len = sni_len;

			if (config.all_domains) {
				vrd.target_sni = 1;
				goto out;
			}


			unsigned int j = 0;
			struct sni_target *cur = config.sni_targets;
			while (cur != NULL) {
				const char *sni_startp = sni_name + sni_len - domain_len;

				if (sni_len >= cur->sni_len &&
				    sni_len < 128 && 
				    !strncmp(sni_startp, cur->sni_str, cur->sni_len)) {
					vrd.target_sni = 1;
				}
				cur = cur->next;
			}
nextExtension:
			extensionsPtr += 2 + 2 + extensionLen;
		}
nextMessage:
		i += 5 + message_length;
	}

out:
	return vrd;
}

int gen_fake_sni(const struct iphdr *iph, const struct tcphdr *tcph, 
		 uint8_t *buf, uint32_t *buflen) {

	if (!iph || !tcph || !buf || !buflen)
		return -EINVAL;

	int ip_len = iph->ihl * 4;
	int tcph_len = tcph->doff * 4;

	const char *data = config.fake_sni_pkt;
	size_t data_len = config.fake_sni_pkt_sz;

	size_t dlen = ip_len + tcph_len + data_len;

	if (*buflen < dlen) 
		return -ENOMEM;

	memcpy(buf, iph, ip_len);
	memcpy(buf + ip_len, tcph, tcph_len);
	memcpy(buf + ip_len + tcph_len, data, data_len);

	struct iphdr *niph = (struct iphdr *)buf;
	struct tcphdr *ntcph = (struct tcphdr *)(buf + ip_len);

	niph->protocol = IPPROTO_TCP;
	niph->tot_len = htons(dlen);

	fail4_packet(buf, *buflen);

	*buflen = dlen;
	return 0;
}

int fail4_packet(uint8_t *payload, uint32_t plen) {
	struct iphdr *iph;
	uint32_t iph_len;
	struct tcphdr *tcph;
	uint32_t tcph_len;
	uint8_t *data;
	uint32_t dlen;
	int ret;

	ret = tcp4_payload_split(payload, plen, 
			&iph, &iph_len, &tcph, &tcph_len,
			&data, &dlen);

	if (ret < 0) {
		return ret;
	}

	if (config.faking_strategy == FAKE_STRAT_ACK_SEQ) {
		tcph->seq = random();
		tcph->ack_seq = random();
	} else if (config.faking_strategy == FAKE_STRAT_TTL) {
		iph->ttl = config.faking_ttl;
	}

	ip4_set_checksum(iph);
	tcp4_set_checksum(tcph, iph);

	return 0;
}
