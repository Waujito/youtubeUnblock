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

#include <linux/printk.h>
#define printf pr_info
#define perror pr_err
#define lgerror(msg, ret) (pr_err(msg ": %d\n", ret))

#else /* USERSPACE_SCOPE */

#include <errno.h>  // IWYU pragma: export
#include <stdint.h> // IWYU pragma: export
#include <string.h> // IWYU pragma: export

#include <stdio.h> // IWYU pragma: export
#define lgerror(msg, ret) __extension__ ({errno = -ret; perror(msg);})


#endif /* SCOPES */

#endif /* TYPES_H */
