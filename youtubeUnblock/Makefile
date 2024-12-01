# This file is used by OpenWRT SDK buildsystem to package the application for routers.

include $(TOPDIR)/rules.mk

PKG_NAME:=youtubeUnblock
PKG_VERSION:=1.0.0
PKG_REV:=f5a6c5718fd99081e0428ee1ae14dccbab9d33d5
PKG_RELEASE:=4

PKG_SOURCE_URL:=https://github.com/Waujito/youtubeUnblock.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/youtubeUnblock
	SECTION:=services
	CATEGORY:=Networking
	TITLE:=youtubeUnblock
	DEPENDS:=+libpthread
	URL:=https://github.com/Waujito/youtubeUnblock
	MAINTAINER:=Vadim Vetrov <vetrovvd@gmail.com>
	VERSION:=$(PKG_VERSION)~$(shell echo $(PKG_REV) | cut -c 1-7)-r$(PKG_RELEASE)
endef

define Package/youtubeUnblock/description
	Bypasses Googlevideo detection systems that relies on SNI
endef

define Build/Prepare
        $(Build/Prepare/Default)
	$(Build/Patch)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		PATH="$(TARGET_PATH)" \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		CROSS_COMPILE_PLATFORM="$(TARGET_CROSS:-=)"
endef

define Package/youtubeUnblock/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/youtubeUnblock $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/youtubeUnblock $(1)/etc/init.d/youtubeUnblock
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-youtubeUnblock.sh $(1)/etc/uci-defaults/99-youtubeUnblock.sh
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/ruleset-post/
	$(INSTALL_DATA) ./files/nftables.d/537-youtubeUnblock.nft $(1)/usr/share/nftables.d/ruleset-post/537-youtubeUnblock.nft
	$(INSTALL_DIR) $(1)/usr/share/youtubeUnblock/
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-youtubeUnblock.sh $(1)/usr/share/youtubeUnblock/youtubeUnblock_defaults.sh
endef

define Package/youtubeUnblock/postinst
[ -n "$${IPKG_INSTROOT}" ] || { \
	/etc/init.d/firewall reload 2>&1
	exit 0
}
endef

$(eval $(call BuildPackage,youtubeUnblock))
