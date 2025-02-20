# This file is used by OpenWRT SDK buildsystem to package the application for routers.

include $(TOPDIR)/rules.mk

PKG_NAME:=youtubeUnblockEntware
PKG_VERSION:=1.0.0
PKG_REV:=f37c3dd49611c8e038ce97b11406afd007c52fcb
PKG_RELEASE:=10

PKG_SOURCE_URL:=https://github.com/Waujito/youtubeUnblock.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/youtubeUnblockEntware
	SECTION:=net
	CATEGORY:=Networking
	TITLE:=youtubeUnblock
	DEPENDS:=+libpthread
	URL:=https://github.com/Waujito/youtubeUnblock
	MAINTAINER:=Vadim Vetrov <vetrovvd@gmail.com>
	VERSION:=$(PKG_VERSION)~$(shell echo $(PKG_REV) | cut -c 1-7)-r$(PKG_RELEASE)
endef

define Package/youtubeUnblockEntware/description
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

define Package/youtubeUnblockEntware/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/youtubeUnblock $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S51youtubeUnblock $(1)/opt/etc/init.d/S91youtubeUnblock
	$(INSTALL_DIR) $(1)/opt/etc/ndm/netfilter.d/
	$(INSTALL_BIN) ./files/ndm_youtubeUnblock.sh $(1)/opt/etc/ndm/netfilter.d/000-youtubeUnblock.sh
endef

$(eval $(call BuildPackage,youtubeUnblockEntware))
