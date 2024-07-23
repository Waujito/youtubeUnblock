include $(top_srcdir)/Make_global.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src include examples doxygen
DIST_SUBDIRS = src include examples doxygen

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmnl.pc

${pkgconfig_DATA}: ${top_builddir}/config.status
