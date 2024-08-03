#ifndef YU_MANGLE_H
#define YU_MANGLE_H
#define RAWSOCKET_MARK 0xfc70

#define DEBUG

#ifdef KERNEL_SPACE
#include <linux/types.h>
typedef __u8 uint8_t;
typedef __u32 uint32_t;

#include <linux/string.h>
#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <asm/byteorder.h>

/* from <netinet/ip.h> */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
#else
#define USER_SPACE

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

struct verdict {
	int gvideo_hello; /* google video hello packet */
	int sni_offset; /* offset from start of tcp _payload_ */
	int sni_len;
};

struct verdict analyze_tls_data(const uint8_t *data, uint32_t dlen);

int ip4_frag(const uint8_t *pkt, uint32_t pktlen, 
			uint32_t payload_offset, 
			uint8_t *frag1, uint32_t *f1len, 
			uint8_t *frag2, uint32_t *f2len);

int tcp4_frag(const uint8_t *pkt, uint32_t pktlen, 
			uint32_t payload_offset, 
			uint8_t *seg1, uint32_t *s1len, 
			uint8_t *seg2, uint32_t *s2len);

int ip4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len, 
		       uint8_t **payload, uint32_t *plen);

int tcp4_payload_split(uint8_t *pkt, uint32_t buflen,
		       struct iphdr **iph, uint32_t *iph_len,
		       struct tcphdr **tcph, uint32_t *tcph_len,
		       uint8_t **payload, uint32_t *plen);
#endif /* YU_MANGLE_H */
