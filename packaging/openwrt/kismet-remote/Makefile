include $(TOPDIR)/rules.mk

# This package is primarily designed for the Wi-Fi Pineapple Tetra but can be 
# easily adapted to other OpenWRT builds.

PKG_NAME:=kismet-remote
PKG_VERSION:=2017git
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://www.kismetwireless.net/git/kismet.git
#PKG_SOURCE_URL:=/home/dragorn/src/kismet
PKG_SOURCE_VERSION:=9e0311c52a4547741f81064a8dc808a01192387f
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DEPENDS:=+libpthread +libpcap +libpcre +libmicrohttpd +libnl +libcap +libncurses +libstdcpp

define Package/kismet-remote
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Kismet (2017)
  URL:=https://www.kismetwireless.net/
  DEPENDS:=+libpthread +libpcap +libnl +libcap 
endef

define Package/kismet-remote/description
 Kismet remote-capture binary for 2017+ Kismet
endef

define Build/Configure
  $(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR)) --with-remote-only
endef

CONFIGURE_ARGS += \
	--sysconfdir=/etc/kismet \
	--bindir=/usr/bin \

CONFIGURE_VARS += \
	CXXFLAGS="$$$$CXXFLAGS"  \
	LIBS="-lm" 

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		LD="$(TARGET_CXX)" \
		all
endef

define Package/kismet-remote/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/kismet_cap_pcapfile $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/kismet_cap_linux_wifi $(1)/usr/bin/
endef

$(eval $(call BuildPackage,kismet-remote))

