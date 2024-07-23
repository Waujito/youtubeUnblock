if HAVE_DOXYGEN

doc_srcs = $(top_srcdir)/src/libnetfilter_queue.c\
           $(top_srcdir)/src/nlmsg.c\
           $(top_srcdir)/src/extra/checksum.c\
           $(top_srcdir)/src/extra/ipv4.c\
           $(top_srcdir)/src/extra/pktbuff.c\
           $(top_srcdir)/src/extra/ipv6.c\
           $(top_srcdir)/src/extra/tcp.c\
           $(top_srcdir)/src/extra/udp.c\
           $(top_srcdir)/src/extra/icmp.c

doxyfile.stamp: $(doc_srcs) Makefile build_man.sh
	rm -rf html man
	doxygen doxygen.cfg >/dev/null

if BUILD_MAN
	$(abs_top_srcdir)/doxygen/build_man.sh libnetfilter_queue libnetfilter_queue.c
endif

	touch doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf man html
install-data-local:
if BUILD_MAN
	mkdir -p $(DESTDIR)$(mandir)/man3
	cp --no-dereference --preserve=links,mode,timestamps man/man3/*.3\
	  $(DESTDIR)$(mandir)/man3/
endif
if BUILD_HTML
	mkdir  -p $(DESTDIR)$(htmldir)
	cp  --no-dereference --preserve=links,mode,timestamps html/*\
		$(DESTDIR)$(htmldir)
endif

# make distcheck needs uninstall-local
uninstall-local:
	rm -rf $(DESTDIR)$(mandir) man html doxyfile.stamp $(DESTDIR)$(htmldir)
endif

EXTRA_DIST = build_man.sh
