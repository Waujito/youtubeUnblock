if HAVE_DOXYGEN
doc_srcs = $(shell find $(top_srcdir)/src -name '*.c')

doxyfile.stamp: $(doc_srcs) Makefile.am
	rm -rf html man
	doxygen doxygen.cfg >/dev/null
	$(SHELL) $(top_srcdir)/doxygen/finalize_manpages.sh
	touch doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(top_srcdir)/doxygen/man $(top_srcdir)/doxygen/html
install-data-local:
	mkdir -p $(DESTDIR)$(mandir)/man3
	cp --no-dereference --preserve=links,mode,timestamps man/man3/*.3\
	  $(DESTDIR)$(mandir)/man3/

# make distcheck needs uninstall-local
uninstall-local:
	rm -r $(DESTDIR)$(mandir) man html doxyfile.stamp
endif

EXTRA_DIST = finalize_manpages.sh
