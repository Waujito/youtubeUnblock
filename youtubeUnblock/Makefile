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
	URL:=https://github.com/Waujito/youtubeUnblock
	MAINTAINER:=Vadim Vetrov <vetrovvd@gmail.com>
	DEPENDS:=+kmod-nft-queue
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
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/youtubeUnblock $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S51youtubeUnblock $(1)/opt/etc/init.d/S51youtubeUnblock
endef

$(eval $(call BuildPackage,youtubeUnblock))
