# This file is used by OpenWRT SDK buildsystem to package the application for routers.

include $(TOPDIR)/rules.mk

PKG_NAME:=youtubeUnblock
PKG_VERSION:=0.1
PKG_RELEASE:=1

SOURCE_DIR:=/home/me/youtubeUnblock

include $(INCLUDE_DIR)/package.mk

define Package/youtubeUnblock
        SECTION:=net
        CATEGORY:=Networking
        TITLE:=youtubeUnblock
endef

define Package/youtubeUnblock/description
        Bypasses Googlevideo detection systems that relies on SNI
endef

define Build/Prepare
        mkdir -p $(PKG_BUILD_DIR)
        cp -r $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
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
