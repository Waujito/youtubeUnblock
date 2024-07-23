dnl Process this file with autoconf to create configure.

AC_INIT([libnetfilter_queue], [1.0.5])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
	tar-pax no-dist-gzip dist-xz 1.6])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_ARG_ENABLE([html-doc],
	      AS_HELP_STRING([--enable-html-doc], [Enable html documentation]),
	      [], [enable_html_doc=no])
AM_CONDITIONAL([BUILD_HTML], [test "$enable_html_doc" = yes])
AS_IF([test "$enable_html_doc" = yes],
	[AC_SUBST(GEN_HTML, YES)],
	[AC_SUBST(GEN_HTML, NO)])

AC_ARG_ENABLE([man-pages],
	      AS_HELP_STRING([--disable-man-pages], [Disable man page documentation]),
	      [], [enable_man_pages=yes])
AM_CONDITIONAL([BUILD_MAN], [test "$enable_man_pages" = yes])
AS_IF([test "$enable_man_pages" = yes],
	[AC_SUBST(GEN_MAN, YES)],
	[AC_SUBST(GEN_MAN, NO)])

AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_INSTALL
CHECK_GCC_FVISIBILITY

case "$host" in
*-*-linux* | *-*-uclinux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

dnl Dependencies
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 0.0.41])
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])

AS_IF([test "$enable_man_pages" = no -a "$enable_html_doc" = no],
      [with_doxygen=no], [with_doxygen=yes])

AS_IF([test "x$with_doxygen" != xno], [
	AC_CHECK_PROGS([DOXYGEN], [doxygen], [""])
	AC_CHECK_PROGS([DOT], [dot], [""])
	AS_IF([test "x$DOT" != "x"],
	      [AC_SUBST(HAVE_DOT, YES)],
	      [AC_SUBST(HAVE_DOT, NO)])
])

AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AS_IF([test "x$DOXYGEN" = x], [
	AS_IF([test "x$with_doxygen" != xno], [
		dnl Only run doxygen Makefile if doxygen installed
		AC_MSG_WARN([Doxygen not found - not building documentation])
		enable_html_doc=no
		enable_man_pages=no
	])
], [
	dnl Warn user if html docs will be missing diagrams
	AS_IF([test "$enable_html_doc" = yes -a -z "$DOT"],
		AC_MSG_WARN([Dot not found - install graphviz to get interactive diagrams in HTML]))
])

dnl Output the makefiles
AC_CONFIG_FILES([Makefile src/Makefile utils/Makefile examples/Makefile
	libnetfilter_queue.pc
	include/Makefile include/libnetfilter_queue/Makefile
	doxygen/Makefile doxygen/doxygen.cfg
	include/linux/Makefile include/linux/netfilter/Makefile])

AC_OUTPUT

echo "
libnetfilter_queue configuration:
man pages:                      ${enable_man_pages}
html docs:                      ${enable_html_doc}"
