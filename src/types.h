/*
  youtubeUnblock - https://github.com/Waujito/youtubeUnblock

  Copyright (C) 2024-2025 Vadim Vetrov <vetrovvd@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#ifndef TYPES_H
#define TYPES_H
#include <asm/byteorder.h>

#ifdef KERNEL_SPACE
#include <linux/errno.h> // IWYU pragma: export
#include <linux/string.h> // IWYU pragma: export

#include <linux/types.h>

typedef __u8	uint8_t;
typedef __u16	uint16_t;
typedef __u32 	uint32_t;
typedef __u64 	uint64_t;
typedef __s8	int8_t;
typedef __s16	int16_t;
typedef __s32	int32_t;
typedef __s64	int64_t;

typedef __s32 int_least32_t;	/* integer of >= 32 bits */
typedef __s16 int_least16_t;	/* integer of >= 16 bits */
#else /* USER_SPACE */

#include <errno.h>  // IWYU pragma: export
#include <stdint.h> // IWYU pragma: export
#include <string.h> // IWYU pragma: export
#include <stdlib.h> // IWYU pragma: export


#define _NO_GETRANDOM ((__GLIBC__ <= 2 && __GLIBC_MINOR__ < 25))

#if !_NO_GETRANDOM
#include <sys/random.h> // IWYU pragma: export
#endif

#endif /* SPACES */

// Network specific structures
#ifdef KERNEL_SPACE
#include <linux/stddef.h> // IWYU pragma: export
#include <linux/net.h> // IWYU pragma: export
#include <linux/in.h> // IWYU pragma: export
#include <linux/ip.h> // IWYU pragma: export
#include <linux/ipv6.h> // IWYU pragma: export
#include <linux/tcp.h> // IWYU pragma: export
#include <linux/version.h>

#define free kfree
#define malloc(size) kmalloc((size), GFP_KERNEL)

#define ip6_hdr ipv6hdr

/* from <netinet/ip.h> */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */

#ifdef __LITTLE_ENDIAN
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER __LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define __LITTLE_ENDIAN 1234
#define __BYTE_ORDER __BIG_ENDIAN
#else
#error "Unsupported endian"
#endif

#define ip6_plen payload_len
#define ip6_nxt nexthdr
#define ip6_hops hop_limit
#define ip6_hlim hop_limit
#define ip6_src saddr
#define ip6_dst daddr

#else /* USER_SPACE */
#include <arpa/inet.h>		// IWYU pragma: export
#include <netinet/ip.h>		// IWYU pragma: export
#include <netinet/ip6.h>	// IWYU pragma: export
#include <netinet/tcp.h>	// IWYU pragma: export
#include <netinet/udp.h>	// IWYU pragma: export
#endif

#define SFREE(item) do {	\
free((item));			\
(item) = NULL;			\
} while (0)

#ifndef KERNEL_SPACE

#define max(a,b)__extension__\
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

#define min(a,b)__extension__\
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})

#endif /* not a KERNEL_SPACE */

/* An alternative memory allocation strategy for userspace app */
// #define ALLOC_MALLOC

/**
 * Use NETBUF_ALLOC and NETBUF_FREE as an abstraction of memory allocation.
 * Do not use it within expressions, consider these defines as separate statements.
 *
 * Use NETBUF_CHECK to check that buffer was properly allocated.
 */
#ifdef KERNEL_SPACE
#include <linux/gfp.h>
#define NETBUF_ALLOC(buf, buf_len) __u8* buf = kmalloc(buf_len, GFP_KERNEL);
#define NETBUF_CHECK(buf) ((buf) != NULL)
#define NETBUF_FREE(buf) kfree(buf);
#elif defined(ALLOC_MALLOC)
#include <stdlib.h>
#define NETBUF_ALLOC(buf, buf_len) __u8* buf = malloc(buf_len);
#define NETBUF_CHECK(buf) ((buf) != NULL)
#define NETBUF_FREE(buf) free(buf);
#else
#define NETBUF_ALLOC(buf, buf_len) __u8 buf[buf_len];
#define NETBUF_CHECK(buf) (1)
#define NETBUF_FREE(buf) ;
#endif

static inline int randint(void) {
	int rnd;
	
#ifdef KERNEL_SPACE
		get_random_bytes(&rnd, sizeof(rnd));
#else
		rnd = random();
#endif

	return rnd;
}

#endif /* TYPES_H */
