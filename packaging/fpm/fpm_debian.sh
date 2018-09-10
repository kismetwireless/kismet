#!/bin/sh -e

if [ ! -e kismet-fpm-debian ]; then
    git clone https://www.kismetwireless.net/git/kismet.git kismet-fpm-debian
fi

cd kismet-fpm-debian

rm -vf *.deb

if [ "$1"x == "rebuild"x ]; then
    git pull

    # Don't enable the python build for now
    ./configure --prefix=/usr --sysconfdir=/etc/kismet --disable-python-tools

    make -j$(nproc)
fi

VERSION=$(git rev-parse --short HEAD)

BINDIR=pkg_files/usr/bin
ETCDIR=pkg_files/etc/kismet
SHAREDIR=pkg_files/usr/share/kismet
HTTPDIR=$SHAREDIR/httpd
PKGDIR=pkg_files/usr/share/pkgconfig

BINS="kismet kismet_cap_pcapfile"

rm -rf pkg_files/

mkdir -p $BINDIR $ETCDIR $SHAREDIR $PKGDIR $HTTPDIR

chmod 755 pkg_files -Rv

for b in $BINS; do 
    cp -v "$b" $BINDIR
done

for c in conf/*.conf; do
    cp -v "$c" $ETCDIR
done

cp -rv http_data/* $HTTPDIR
cp -v packaging/kismet.pc $PKGDIR


fpm -t deb -s dir -n kismet-core -v 2018.git.${VERSION} \
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
    ./pkg_files/etc/=/etc ./pkg_files/usr/=/usr 

fpm -t deb -s dir -n kismet-capture-linux-wifi -v 2018.git.${VERSION} \
    --depends libnl-3 \
    --depends libnl-genl-3 \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libpcap0.8 \
    --depends libnm0 \
    --depends libprotobuf-c1 \
    ./capture_linux_wifi/kismet_cap_linux_wifi=/usr/bin/kismet_cap_linux_wifi 

fpm -t deb -s dir -n kismet-capture-linux-bluetooth -v 2018.git.${VERSION} \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libnm0 \
    --depends libprotobuf-c1 \
    ./capture_linux_bluetooth/kismet_cap_linux_bluetooth=/usr/bin/kismet_cap_linux_bluetooth 


