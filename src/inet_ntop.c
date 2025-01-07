/**

    musl libc

musl, pronounced like the word "mussel", is an MIT-licensed
implementation of the standard C library targetting the Linux syscall
API, suitable for use in a wide range of deployment environments. musl
offers efficient static and dynamic linking support, lightweight code
and low runtime overhead, strong fail-safe guarantees under correct
usage, and correctness in the sense of standards conformance and
safety. musl is built on the principle that these goals are best
achieved through simple code that is easy to understand and maintain.

The 1.1 release series for musl features coverage for all interfaces
defined in ISO C99 and POSIX 2008 base, along with a number of
non-standardized interfaces for compatibility with Linux, BSD, and
glibc functionality.

For basic installation instructions, see the included INSTALL file.
Information on full musl-targeted compiler toolchains, system
bootstrapping, and Linux distributions built on musl can be found on
the project website:

    http://www.musl-libc.org/
*/

#include "types.h"

// #ifndef KERNEL_SPACE
// #error "For user space use glibc inet_ntop"
// #endif

const char *inet_ntop(int af, const void *restrict a0, char *restrict s, socklen_t l)
{
	const unsigned char *a = a0;
	int i, j, max, best;
	char buf[100];

	switch (af) {
	case AF_INET:
		if (snprintf(s, l, "%d.%d.%d.%d", a[0],a[1],a[2],a[3]) < l)
			return s;
		break;
	case AF_INET6:
		if (memcmp(a, "\0\0\0\0\0\0\0\0\0\0\377\377", 12))
			snprintf(buf, sizeof buf,
				"%x:%x:%x:%x:%x:%x:%x:%x",
				256*a[0]+a[1],256*a[2]+a[3],
				256*a[4]+a[5],256*a[6]+a[7],
				256*a[8]+a[9],256*a[10]+a[11],
				256*a[12]+a[13],256*a[14]+a[15]);
		else
			snprintf(buf, sizeof buf,
				"%x:%x:%x:%x:%x:%x:%d.%d.%d.%d",
				256*a[0]+a[1],256*a[2]+a[3],
				256*a[4]+a[5],256*a[6]+a[7],
				256*a[8]+a[9],256*a[10]+a[11],
				a[12],a[13],a[14],a[15]);
		/* Replace longest /(^0|:)[:0]{2,}/ with "::" */
		for (i=best=0, max=2; buf[i]; i++) {
			if (i && buf[i] != ':') continue;
			j = strspn(buf+i, ":0");
			if (j>max) best=i, max=j;
		}
		if (max>3) {
			buf[best] = buf[best+1] = ':';
			memmove(buf+best+2, buf+best+max, i-best-max+1);
		}
		if (strlen(buf) < l) {
			strcpy(s, buf);
			return s;
		}
		break;
	default:
		return 0;
	}
	return 0;
}
