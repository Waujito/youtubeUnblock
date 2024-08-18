USPACE_TARGETS := default all install uninstall dev run_dev
KMAKE_TARGETS := kmake kload kunload kreload xmod xtclean

.PHONY: $(USPACE_TARGETS) $(KMAKE_TARGETS) clean
$(USPACE_TARGETS):
	@$(MAKE) -f uspace.mk $@

$(KMAKE_TARGETS):
	@$(MAKE) -f kmake.mk $@

clean:
	-@$(MAKE) -f uspace.mk clean

distclean: clean
	-@$(MAKE) -f uspace.mk distclean


kclean:
	-@$(MAKE) -f kmake.mk kclean
