#!/bin/sh -e

VERSION=$(git rev-parse --short HEAD)

cp kismet kismet_stripped
strip kismet_stripped

sudo fpm -t deb -s dir -n kismet-core-debug -v 2018.git.${VERSION} \
    --replaces kismet \
    --replaces kismet-plugins \
    --deb-recommends kismet-capture-linux-wifi \
    --deb-recommends kismet-capture-linux-bluetooth \
    --deb-recommends kismet-capture-nrf-mousejack \
    --deb-recommends python-kismetcapturertl433 \
    --deb-recommends kismet-logtools \
    --deb-templates packaging/fpm/debian/kismet.templates \
    --deb-config packaging/fpm/debian/kismet.config \
    --depends libmicrohttpd10 \
    --depends zlib1g \
    --depends libpcap0.8 \
    --depends libncurses5 \
    --depends libdw1 \
    --depends libsqlite3-0 \
    --depends libprotobuf10 \
    --depends libprotobuf-c1 \
    --depends libsensors4 \
    ./conf/kismet.conf=/etc/kismet/kismet.conf \
    ./conf/kismet_alerts.conf=/etc/kismet/kismet_alerts.conf \
    ./conf/kismet_httpd.conf=/etc/kismet/kismet_httpd.conf \
    ./conf/kismet_logging.conf=/etc/kismet/kismet_logging.conf \
    ./conf/kismet_memory.conf=/etc/kismet/kismet_memory.conf \
    ./conf/kismet_storage.conf=/etc/kismet/kismet_storage.conf \
    ./conf/kismet_uav.conf=/etc/kismet/kismet_uav.conf \
    ./kismet=/usr/bin/kismet \
    ./kismet_cap_pcapfile=/usr/bin/kismet_cap_pcapfile \
    ./packaging/kismet.pc=/usr/share/pkgconfig/kismet.pc \
    ./http_data/=/usr/share/kismet/httpd 

sudo fpm -t deb -s dir -n kismet-core -v 2018.git.${VERSION} \
    --replaces kismet \
    --replaces kismet-plugins \
    --deb-recommends kismet-capture-linux-wifi \
    --deb-recommends kismet-capture-linux-bluetooth \
    --deb-recommends kismet-capture-nrf-mousejack \
    --deb-recommends python-kismetcapturertl433 \
    --deb-recommends kismet-logtools \
    --depends libmicrohttpd10 \
    --depends zlib1g \
    --depends libpcap0.8 \
    --depends libncurses5 \
    --depends libdw1 \
    --depends libsqlite3-0 \
    --depends libprotobuf10 \
    --depends libprotobuf-c1 \
    --depends libsensors4 \
    ./conf/kismet.conf=/etc/kismet/kismet.conf \
    ./conf/kismet_alerts.conf=/etc/kismet/kismet_alerts.conf \
    ./conf/kismet_httpd.conf=/etc/kismet/kismet_httpd.conf \
    ./conf/kismet_logging.conf=/etc/kismet/kismet_logging.conf \
    ./conf/kismet_memory.conf=/etc/kismet/kismet_memory.conf \
    ./conf/kismet_storage.conf=/etc/kismet/kismet_storage.conf \
    ./conf/kismet_uav.conf=/etc/kismet/kismet_uav.conf \
    ./kismet_stripped=/usr/bin/kismet \
    ./kismet_cap_pcapfile=/usr/bin/kismet_cap_pcapfile \
    ./packaging/kismet.pc=/usr/share/pkgconfig/kismet.pc \
    ./http_data/=/usr/share/kismet/httpd 

sudo fpm -t deb -s dir -n kismet-capture-linux-wifi -v 2018.git.${VERSION} \
    --deb-templates packaging/fpm/debian/kismet.templates \
    --deb-config packaging/fpm/debian/kismet.config \
    --post-install packaging/fpm/debian/kismet_cap_linux_wifi.postinst \
    --depends libnl-3-200 \
    --depends libnl-genl-3-200 \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libpcap0.8 \
    --depends libnm0 \
    --depends libprotobuf-c1 \
    ./capture_linux_wifi/kismet_cap_linux_wifi=/usr/bin/kismet_cap_linux_wifi 

sudo fpm -t deb -s dir -n kismet-capture-linux-bluetooth -v 2018.git.${VERSION} \
    --deb-templates packaging/fpm/debian/kismet.templates \
    --deb-config packaging/fpm/debian/kismet.config \
    --post-install packaging/fpm/debian/kismet_cap_linux_bluetooth.postinst \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libnm0 \
    --depends libprotobuf-c1 \
    ./capture_linux_bluetooth/kismet_cap_linux_bluetooth=/usr/bin/kismet_cap_linux_bluetooth 
    
sudo fpm -t deb -s dir -n kismet-capture-nrf-mousejack -v 2018.git.${VERSION} \
    --deb-templates packaging/fpm/debian/kismet.templates \
    --deb-config packaging/fpm/debian/kismet.config \
    --post-install packaging/fpm/debian/kismet_cap_nrf_mousejack.postinst \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libprotobuf-c1 \
    --depends libusb-1.0-0 \
    ./capture_nrf_mousejack/kismet_cap_nrf_mousejack=/usr/bin/kismet_cap_nrf_mousejack

