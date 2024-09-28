#include "types.h"
#include "tls.h"
#include "config.h"
#include "logging.h"
#include "utils.h"

#ifndef KERNEL_SPACE
#include <stdlib.h>
#include <sys/random.h>
#endif

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_EXTENSION_SNI 0x0000
#define TLS_EXTENSION_CLIENT_HELLO_ENCRYPTED 0xfe0d

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
		uint16_t message_length = ntohs(*(uint16_t *)(msgData + 3));

		if (tls_vmajor != 0x03) goto nextMessage;

		if (i + 5 > dlen) break;

		if (tls_content_type != TLS_CONTENT_TYPE_HANDSHAKE) 
			goto nextMessage;

		if (config.sni_detection == SNI_DETECTION_BRUTE) {
			goto brute;
		}

		const uint8_t *handshakeProto = msgData + 5;

		if (handshakeProto + 1 >= data_end) break;

		uint8_t handshakeType = *handshakeProto;

		if (handshakeType != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
			goto nextMessage;

		const uint8_t *msgPtr = handshakeProto;
		msgPtr += 1; 
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
		msgPtr += 2;

		const uint8_t *extensionsPtr = msgPtr;
		const uint8_t *extensions_end = extensionsPtr + extensionsLen;
		if (extensions_end > data_end) extensions_end = data_end;

		while (extensionsPtr < extensions_end) {
			const uint8_t *extensionPtr = extensionsPtr;
			if (extensionPtr + 4 >= extensions_end) break;

			uint16_t extensionType = 
				ntohs(*(uint16_t *)extensionPtr);
			extensionPtr += 2;

			uint16_t extensionLen = 
				ntohs(*(uint16_t *)extensionPtr);
			extensionPtr += 2;


			if (extensionPtr + extensionLen > extensions_end) 
				break;

			if (extensionType != TLS_EXTENSION_SNI) 
				goto nextExtension;

			const uint8_t *sni_ext_ptr = extensionPtr;

			if (sni_ext_ptr + 2 >= extensions_end) break;
			uint16_t sni_ext_dlen = ntohs(*(uint16_t *)sni_ext_ptr);

			sni_ext_ptr += 2;

			const uint8_t *sni_ext_end = sni_ext_ptr + sni_ext_dlen;
			if (sni_ext_end >= extensions_end) break;
			
			if (sni_ext_ptr + 3 >= sni_ext_end) break;
			sni_ext_ptr++;
			uint16_t sni_len = ntohs(*(uint16_t *)sni_ext_ptr);
			sni_ext_ptr += 2;

			if (sni_ext_ptr + sni_len > sni_ext_end) break;

			char *sni_name = (char *)sni_ext_ptr;

			vrd.sni_offset = (uint8_t *)sni_name - data;
			vrd.sni_target_offset = vrd.sni_offset;
			vrd.sni_len = sni_len;

			if (config.all_domains) {
				vrd.target_sni = 1;
				goto check_domain;
			}

			unsigned int j = 0;
			for (unsigned int i = 0; i <= config.domains_strlen; i++) {
				if (	i > j &&
					(i == config.domains_strlen	||	
					config.domains_str[i] == '\0'	||
					config.domains_str[i] == ','	|| 
					config.domains_str[i] == '\n'	)) {

					unsigned int domain_len = (i - j);
					const char *sni_startp = sni_name + sni_len - domain_len;
					const char *domain_startp = config.domains_str + j;

					if (sni_len >= domain_len &&
						sni_len < 128 && 
						!strncmp(sni_startp, 
						domain_startp, 
						domain_len)) {
							vrd.target_sni = 1;
							vrd.sni_target_offset = (const uint8_t *)sni_startp - data;
							goto check_domain;
					}

					j = i + 1;
				}
			}

check_domain:
			if (vrd.target_sni == 1 && config.exclude_domains_strlen != 0) {
				unsigned int j = 0;
				for (unsigned int i = 0; i <= config.exclude_domains_strlen; i++) {
					if (	i > j &&
						(i == config.exclude_domains_strlen	||	
						config.exclude_domains_str[i] == '\0'	||
						config.exclude_domains_str[i] == ','	|| 
						config.exclude_domains_str[i] == '\n'	)) {

						unsigned int domain_len = (i - j);
						const char *sni_startp = sni_name + sni_len - domain_len;
						const char *domain_startp = config.exclude_domains_str + j;

						if (sni_len >= domain_len &&
							sni_len < 128 && 
							!strncmp(sni_startp, 
							domain_startp, 
							domain_len)) {

							vrd.target_sni = 0;
							lgdebugmsg("Excluded SNI: %.*s", 
								vrd.sni_len, data + vrd.sni_offset);
							goto out;
						}

						j = i + 1;
					}
				}
			}

			goto out;

nextExtension:
			extensionsPtr += 2 + 2 + extensionLen;
		}
nextMessage:
		i += 5 + message_length;
	}

out:
	return vrd;


brute:
	if (config.all_domains) {
		vrd.target_sni = 1;
		vrd.sni_len = 0;
		vrd.sni_offset = dlen / 2;
		goto out;
	}

	unsigned int j = 0;
	for (unsigned int i = 0; i <= config.domains_strlen; i++) {
		if (	i > j &&
			(i == config.domains_strlen	||	
			config.domains_str[i] == '\0'	||
			config.domains_str[i] == ','	|| 
			config.domains_str[i] == '\n'	)) {

			unsigned int domain_len = (i - j);
			const char *domain_startp = config.domains_str + j;

			if (domain_len + dlen + 1> MAX_PACKET_SIZE) { 
				continue;
			}

			NETBUF_ALLOC(buf, MAX_PACKET_SIZE);
			if (!NETBUF_CHECK(buf)) {
				lgerror("Allocation error", -ENOMEM);
				goto out;
			}
			NETBUF_ALLOC(nzbuf, MAX_PACKET_SIZE * sizeof(int));
			if (!NETBUF_CHECK(nzbuf)) {
				lgerror("Allocation error", -ENOMEM);
				NETBUF_FREE(buf);
				goto out;
			}

			int *zbuf = (void *)nzbuf;

			memcpy(buf, domain_startp, domain_len);
			memcpy(buf + domain_len, "#", 1);
			memcpy(buf + domain_len + 1, data, dlen);

			z_function((char *)buf, zbuf, domain_len + 1 + dlen);

			for (unsigned int k = 0; k < dlen; k++) {
				if (zbuf[k] == domain_len) {
					vrd.target_sni = 1;
					vrd.sni_len = domain_len;
					vrd.sni_offset = (k - domain_len - 1);
					vrd.sni_target_offset = vrd.sni_offset;
					NETBUF_FREE(buf);
					NETBUF_FREE(nzbuf);
					goto out;
				}
			}


			j = i + 1;

			NETBUF_FREE(buf);
			NETBUF_FREE(nzbuf);
		}
	}

	goto out;
}

int gen_fake_sni(struct fake_type type,
		const void *ipxh, uint32_t iph_len, 
		const struct tcphdr *tcph, uint32_t tcph_len,
		uint8_t *buf, uint32_t *buflen) {

	uint32_t data_len = type.fake_len;
	if (type.type == FAKE_PAYLOAD_RANDOM && data_len == 0) {
#ifdef KERNEL_SPACE
		
		// get_random_bytes(&data_len, sizeof(data_len));
		data_len = get_random_u32() % 1200;
#else
		data_len = random() % 1200;
#endif
	} else if (type.type == FAKE_PAYLOAD_DEFAULT) {
		data_len = config.fake_sni_pkt_sz;
	}

	if (!ipxh || !tcph || !buf || !buflen)
		return -EINVAL;

	int ipxv = netproto_version(ipxh, iph_len);

	if (ipxv == IP4VERSION) {
		const struct iphdr *iph = ipxh;

		memcpy(buf, iph, iph_len);
		struct iphdr *niph = (struct iphdr *)buf;

		niph->protocol = IPPROTO_TCP;
	} else if (ipxv == IP6VERSION) {
		const struct ip6_hdr *iph = ipxh;

		iph_len = sizeof(struct ip6_hdr);
		memcpy(buf, iph, iph_len);
		struct ip6_hdr *niph = (struct ip6_hdr *)buf;

		niph->ip6_nxt = IPPROTO_TCP;
	} else {
		return -EINVAL;
	}

	uint32_t dlen = iph_len + tcph_len + data_len;

	if (*buflen < dlen) 
		return -ENOMEM;

	memcpy(buf + iph_len, tcph, tcph_len);
	uint8_t *bfdptr = buf + iph_len + tcph_len;

	switch (type.type) {
		case FAKE_PAYLOAD_DEFAULT:
			memcpy(bfdptr, config.fake_sni_pkt, data_len);
			break;
		case FAKE_PAYLOAD_DATA:
			memcpy(bfdptr, type.fake_data, data_len);
			break;
		default: // FAKE_PAYLOAD_RANDOM
#ifdef KERNEL_SPACE
		get_random_bytes(bfdptr, data_len);
#else
			getrandom(bfdptr, data_len, 0);
#endif
	}

	if (ipxv == IP4VERSION) {
		struct iphdr *niph = (struct iphdr *)buf;
		niph->tot_len = htons(dlen);
	} else if (ipxv == IP6VERSION) {
		struct ip6_hdr *niph = (struct ip6_hdr *)buf;
		niph->ip6_plen = htons(dlen - iph_len);
	}

	fail_packet(type.strategy, buf, &dlen, *buflen);

	*buflen = dlen;
	
	return 0;
}

