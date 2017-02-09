include $(TOPDIR)/rules.mk

PKG_NAME:=kismet-new
PKG_VERSION:=2017git
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://www.kismetwireless.net/kismet.git
#PKG_SOURCE_URL:=/home/dragorn/src/kismet
PKG_SOURCE_VERSION:=b831b0b2cb42abceef4239174b11b631a420f0ac
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DEPENDS:=+libpthread +libpcap +libpcre +libmicrohttpd +libnl +libcap +libncurses +libstdcpp

define Package/kismet-new
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Kismet (2017)
  #DESCRIPTION:=This variable is obsolete. use the Package/name/description define instead!
  URL:=https://www.kismetwireless.net/
  DEPENDS:=+libpthread +libpcap +libpcre +libmicrohttpd +libnl +libcap +libstdcpp +libncurses
endef

define Package/kismet-new/description
 Kismet wireless capture and IDS
 Latest web-ui based Kismet
endef

define Build/Configure
  $(call Build/Configure/Default,--with-linux-headers=$(LINUX_DIR))
endef

CONFIGURE_ARGS += \
	--sysconfdir=/etc/kismet \

CONFIGURE_VARS += \
	CXXFLAGS="$$$$CXXFLAGS -fno-rtti"  \
	LIBS="-lm" 

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		LD="$(TARGET_CXX)" \
		all
endef

define Package/kismet-new/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/kismet_server $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/kismet_capture $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/etc/kismet/
	$(INSTALL_CONF) ./files/kismet.conf $(1)/etc/kismet/
	$(INSTALL_CONF) ./files/kismet_httpd.conf $(1)/etc/kismet/
	cp -Rv $(PKG_BUILD_DIR)/http_data $(1)/etc/kismet/
endef

$(eval $(call BuildPackage,kismet-new))

