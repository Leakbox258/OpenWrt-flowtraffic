include $(TOPDIR)/rules.mk

PKG_NAME:=flowtraffic_group_1
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME) 
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Simple Flow Monitor
  DEPENDS:=+libpcap +libpthread
endef

define Package/$(PKG_NAME)/description
  A simple flow monitor tool using libpcap.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/$(PKG_NAME) \
		$(PKG_BUILD_DIR)/flowtraffic_group_1.c \
		$(PKG_BUILD_DIR)/flowtraffic_group_1.h \
		-lpcap -lpthread
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/bin/ 
endef

$(eval $(call BuildPackage,flowtraffic_group_1)) 