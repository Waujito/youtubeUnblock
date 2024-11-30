# This file is used by OpenWRT SDK buildsystem to package the application for routers.
# This file provides the kernel model version of youtubeUnblock

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=youtubeUnblock
PKG_VERSION:=1.0.0
PKG_REV:=7303abdaf2809f0db53efb6ed1b206ab79694a24
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/Waujito/youtubeUnblock.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define KernelPackage/youtubeUnblock
	SECTION:=net
	CATEGORY:=Networking
	TITLE:=kmod youtubeUnblock
	VERSION:=$(LINUX_VERSION)+$(PKG_VERSION)-$(BOARD)-$(PKG_RELEASE)
	FILES:=$(PKG_BUILD_DIR)/kyoutubeUnblock.$(LINUX_KMOD_SUFFIX)
	URL:=https://github.com/Waujito/youtubeUnblock
	MAINTAINER:=Vadim Vetrov <vetrovvd@gmail.com>
endef

define Build/Prepare
	$(Build/Prepare/Default)
	$(Build/Patch)
endef

define Build/Compile
	$(MAKE) -C $(LINUX_DIR) \
		ARCH="$(LINUX_KARCH)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		M="$(PKG_BUILD_DIR)" \
		CONFIG_kyoutubeUnblock=m \
		modules
endef

define KernelPackage/youtubeUnblock/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/kmod_youtubeUnblock $(1)/etc/init.d/kmod_youtubeUnblock
endef

$(eval $(call KernelPackage,youtubeUnblock))
