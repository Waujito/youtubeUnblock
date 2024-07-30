USPACE_TARGETS := default all install uninstall dev run_dev
KMAKE_TARGETS := kmake kload kunload kreload

.PHONY: $(USPACE_TARGETS) $(KMAKE_TARGETS) clean
$(USPACE_TARGETS):
	@$(MAKE) -f uspace.mk $@

$(KMAKE_TARGETS):
	@$(MAKE) -f kmake.mk $@

clean:
	-@$(MAKE) -f kmake.mk kclean
	@$(MAKE) -f uspace.mk clean

