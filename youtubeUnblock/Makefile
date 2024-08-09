# This file is used by OpenWRT SDK buildsystem to package the application for routers.

include $(TOPDIR)/rules.mk

PKG_NAME:=youtubeUnblock
PKG_VERSION:=0.2.2
PKG_REV:=7d60fd885490fdeaa0987741f1dd6a607e903862
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/Waujito/youtubeUnblock.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/youtubeUnblock
	SECTION:=net
	CATEGORY:=Networking
	TITLE:=youtubeUnblock
	DEPENDS:=+kmod-nfnetlink-queue +libpthread
	URL:=https://github.com/Waujito/youtubeUnblock
	MAINTAINER:=Vadim Vetrov <vetrovvd@gmail.com>
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
	$(INSTALL_BIN) ./files/youtubeUnblock.owrt $(1)/etc/init.d/youtubeUnblock
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/ruleset-post/
	$(CP) ./files/537-youtubeUnblock.nft $(1)/usr/share/nftables.d/ruleset-post/537-youtubeUnblock.nft
endef

$(eval $(call BuildPackage,youtubeUnblock))
