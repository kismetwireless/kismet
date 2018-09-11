#!/bin/sh -e

if [ ! -e kismet-fpm-debian ]; then
    git clone https://www.kismetwireless.net/git/kismet.git kismet-fpm-debian
fi

cd kismet-fpm-debian

rm -vf *.deb

if test "$1"x = "rebuild"x; then
    git pull

    # Enable everything
    ./configure --prefix=/usr --sysconfdir=/etc/kismet 

    make -j$(nproc)
fi

VERSION=$(git rev-parse --short HEAD)

cp kismet kismet_stripped
strip kismet_stripped

sudo fpm -t deb -s dir -n kismet-core -v 2018.git.debug.${VERSION} \
    --deb-recommends kismet-capture-linux-wifi \
    --deb-recommends kismet-capture-linux-bluetooth \
    --deb-templates ../debian/kismet.templates \
    --deb-config ../debian/kismet.config \
    --depends libmicrohttpd12 \
    --depends zlib1g \
    --depends libpcap0.8 \
    --depends libncurses5 \
    --depends libdw1 \
    --depends libsqlite3-0 \
    --depends libprotobuf10 \
    --depends libprotobuf-c1 \
    --depends libsensors4 \
    ./conf=/etc/kismet \
    ./kismet=/usr/bin/kismet \
    ./kismet_cap_pcapfile=/usr/bin/kismet_cap_pcapfile \
    ./packaging/kismet.pc=/usr/share/pkgconfig/kismet.pc \
    ./http_data=/usr/share/kismet/httpd 

sudo fpm -t deb -s dir -n kismet-core -v 2018.git.${VERSION} \
    --deb-recommends kismet-capture-linux-wifi \
    --deb-recommends kismet-capture-linux-bluetooth \
    --depends libmicrohttpd12 \
    --depends zlib1g \
    --depends libpcap0.8 \
    --depends libncurses5 \
    --depends libdw1 \
    --depends libsqlite3-0 \
    --depends libprotobuf10 \
    --depends libprotobuf-c1 \
    --depends libsensors4 \
    ./conf=/etc/kismet \
    ./kismet_stripped=/usr/bin/kismet \
    ./kismet_cap_pcapfile=/usr/bin/kismet_cap_pcapfile \
    ./packaging/kismet.pc=/usr/share/pkgconfig/kismet.pc \
    ./http_data=/usr/share/kismet/httpd 

sudo fpm -t deb -s dir -n kismet-capture-linux-wifi -v 2018.git.${VERSION} \
    --deb-templates ../debian/kismet.templates \
    --deb-config ../debian/kismet.config \
    --post-install ../debian/kismet_cap_linux_wifi.postinst \
    --depends libnl-3-200 \
    --depends libnl-genl-3-200 \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libpcap0.8 \
    --depends libnm0 \
    --depends libprotobuf-c1 \
    ./capture_linux_wifi/kismet_cap_linux_wifi=/usr/bin/kismet_cap_linux_wifi 

sudo fpm -t deb -s dir -n kismet-capture-linux-bluetooth -v 2018.git.${VERSION} \
    --deb-templates ../debian/kismet.templates \
    --deb-config ../debian/kismet.config \
    --post-install ../debian/kismet_cap_linux_bluetooth.postinst \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libnm0 \
    --depends libprotobuf-c1 \
    ./capture_linux_bluetooth/kismet_cap_linux_bluetooth=/usr/bin/kismet_cap_linux_bluetooth 
    
sudo fpm -t deb -s dir -n kismet-capture-nrf-mousejack -v 2018.git.${VERSION} \
    --deb-templates ../debian/kismet.templates \
    --deb-config ../debian/kismet.config \
    --post-install ../debian/kismet_cap_nrf_mousejack.postinst \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libprotobuf-c1 \
    --depends libusb-1.0-0 \
    ./capture_nrf_mousejack/kismet_cap_nrf_mousejack=/usr/bin/kismet_cap_nrf_mousejack

