include $(TOPDIR)/rules.mk

PKG_NAME:=kismet-remote
PKG_VERSION:=2018-08-BETA1
PKG_RELEASE:=0

PKG_SOURCE_PROTO:=git
#PKG_SOURCE_URL:=/home/dragorn/src/kismet

PKG_SOURCE_URL:=https://www.kismetwireless.net/git/kismet.git
PKG_SOURCE_VERSION:=HEAD

#PKG_SOURCE_VERSION:=87e089cb1c0251cc13d8922458ee4f2de41456ca

PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DEPENDS:=+libusb-compat +libpthread +libpcap +libnl-tiny +libprotobuf-c +libcap

define Package/kismet-remote
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Kismet Remote Capture (2018-08-BETA1)
  URL:=https://www.kismetwireless.net/
  DEPENDS:=+libusb-compat +libpthread +libpcap +libnl-tiny +libprotobuf-c +libcap
endef

define Package/kismet-remote/description
 Kismet remote-capture binary for 2018+ Kismet
endef

define Build/Configure
  $(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR)) 
endef

CONFIGURE_ARGS += \
	--bindir=/usr/bin \
	--enable-capture-tools-only \
	--disable-python-tools \
	--with-netlink-tiny \
    --with-protocc=$(STAGING_DIR_HOSTPKG)/bin/protoc-c

# Override libs to force lpthread because we don't detect it properly on openwrt
CONFIGURE_VARS += \
	LIBS="-lpthread" 

TARGET_CFLAGS+=-I$(STAGING_DIR)/usr/include/libnl-tiny
TARGET_CPPFLAGS+=-I$(STAGING_DIR)/usr/include/libnl-tiny

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		LD="$(TARGET_CXX)" \
		datasources
endef

define Package/kismet-remote/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/kismet_cap_pcapfile $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/capture_linux_wifi/kismet_cap_linux_wifi $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/capture_linux_bluetooth/kismet_cap_linux_bluetooth $(1)/usr/bin/
endef

$(eval $(call BuildPackage,kismet-remote))

