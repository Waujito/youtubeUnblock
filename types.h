#ifndef TYPES_H
#define TYPES_H
#include <bits/endian.h>

#ifdef KERNEL_SCOPE
#include <linux/errno.h> // IWYU pragma: export
#include <linux/string.h> // IWYU pragma: export

#include <linux/types.h>
typedef __u8	uint8_t;
typedef __u16	uint16_t;
typedef __u32 	uint32_t;
typedef __u64 	uint64_t;
typedef __i8	int8_t;
typedef __i16	int16_t;
typedef __i32	int32_t;
typedef __i64	int64_t;
#else /* USERSPACE_SCOPE */

#include <errno.h>  // IWYU pragma: export
#include <stdint.h> // IWYU pragma: export
#include <string.h> // IWYU pragma: export

#endif /* SCOPES */

// Network specific structures
#ifdef KERNEL_SPACE
#include <linux/stddef.h> // IWYU pragma: export
#include <linux/net.h> // IWYU pragma: export
#include <linux/in.h> // IWYU pragma: export
#include <linux/ip.h> // IWYU pragma: export
#include <linux/tcp.h> // IWYU pragma: export

/* from <netinet/ip.h> */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
#else
#define USER_SPACE
#include <arpa/inet.h>		// IWYU pragma: export
#include <netinet/ip.h>		// IWYU pragma: export
#include <netinet/tcp.h>	// IWYU pragma: export
#include <netinet/udp.h>	// IWYU pragma: export
#endif

#endif /* TYPES_H */
