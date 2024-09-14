# This file is used by OpenWRT SDK buildsystem to package the application for routers.

include $(TOPDIR)/rules.mk

PKG_NAME:=youtubeUnblock
PKG_VERSION:=0.3.2
PKG_REV:=725dc1a6d22503b89e37a77c9c2587244d63c74f
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/Waujito/youtubeUnblock.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

LUA_LIBRARYDIR = /usr/lib/lua
LUCI_LIBRARYDIR = $(LUA_LIBRARYDIR)/luci

include $(INCLUDE_DIR)/package.mk

define Package/youtubeUnblock
	SECTION:=services
	CATEGORY:=Networking
	TITLE:=youtubeUnblock
	DEPENDS:=+libpthread +luci-base +luci-compat
	URL:=https://github.com/Waujito/youtubeUnblock
	MAINTAINER:=Vadim Vetrov <vetrovvd@gmail.com>
	VERSION:=$(PKG_VERSION)-$(BOARD)-$(PKG_RELEASE)
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
	$(INSTALL_DIR) $(1)$(LUCI_LIBRARYDIR)/controller
	$(INSTALL_DIR) $(1)$(LUCI_LIBRARYDIR)/model/cbi
	$(INSTALL_DATA) ./files/luasrc/controller/* $(1)$(LUCI_LIBRARYDIR)/controller
	$(INSTALL_DATA) ./files/luasrc/model/cbi/* $(1)$(LUCI_LIBRARYDIR)/model/cbi
endef

$(eval $(call BuildPackage,youtubeUnblock))
