USPACE_TARGETS := default all install uninstall dev run_dev
KMAKE_TARGETS := kmake kload kunload kreload xmod xtclean

.PHONY: $(USPACE_TARGETS) $(KMAKE_TARGETS) clean
$(USPACE_TARGETS):
	@$(MAKE) -ef uspace.mk $@

$(KMAKE_TARGETS):
	@$(MAKE) -ef kmake.mk $@

clean:
	-@$(MAKE) -ef kmake.mk kclean
	@$(MAKE) -ef uspace.mk clean

