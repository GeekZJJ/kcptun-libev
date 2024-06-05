include $(TOPDIR)/rules.mk

PKG_NAME:=kcptun-libev
PKG_VERSION:=2.3
PKG_RELEASE:=1

CMAKE_OPTIONS+= -DCMAKE_BUILD_TYPE="Release"

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/kcptun-libev
  SECTION:=net
  CATEGORY:=Network
  TITLE:=kcptun-libev
  DEPENDS:=+libev
endef

define Package/kcptun-libev/description
  A lightweight alternative implementation to kcptun.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/
	$(CP) -R ./src/* $(PKG_BUILD_DIR)/
	$(Build/Patch/Default)
endef

define Package/kcptun-libev/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/kcptun-libev $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/kcptun-libev.config $(1)/etc/config/kcptun-libev

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/kcptun-libev.init $(1)/etc/init.d/kcptun-libev
endef

TARGET_CFLAGS += -flto
TARGET_LDFLAGS += -Wl,--gc-sections,--as-needed

$(eval $(call BuildPackage,$(PKG_NAME)))
