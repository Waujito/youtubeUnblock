include $(TOPDIR)/rules.mk

PKG_NAME:=ytunblock
PKG_VERSION:=@VERSION@

PKG_REV:=main
PKG_SOURCE:=$(PKG_REV).tar.gz
PKG_SOURCE_URL:=https://github.com/Waujito/youtubeUnblock/archive/
PKG_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/youtubeUnblock-$(PKG_REV)
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ytunblock
	SECTION:=net
	CATEGORY:=Network
	TITLE:=youtubeUnblock
	URL:=https://github.com/Waujito/youtubeUnblock
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
	$(TARGET_CONFIGURE_OPTS) \
	CROSS_COMPILE_PLATFORM=$(GNU_TARGET_NAME)
endef

define Package/ytunblock/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/youtubeUnblock $(1)/usr/bin/ytunblock

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ytunblock.init $(1)/etc/init.d/ytunblock

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/ytunblock.config $(1)/etc/config/ytunblock
endef

$(eval $(call BuildPackage,ytunblock))
