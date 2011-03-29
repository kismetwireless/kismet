#!/bin/bash

if [ "$1" == 'amd64' ]; then
	ARCH=amd64
elif [ "$1" == 'i386' ]; then
	ARCH=i386
else
	echo "No arch, expected amd64 or i386, fail"
	exit
fi

rm -rf dpkg

mkdir dpkg
mkdir dpkg/control
mkdir dpkg/data
mkdir -p dpkg/data/usr/bin
mkdir -p dpkg/data/usr/etc
mkdir -p dpkg/data/usr/man/man1
mkdir -p dpkg/data/usr/man/man5
mkdir -p dpkg/data/usr/share/kismet/wav
mkdir -p dpkg/data/usr/share/doc
mkdir -p dpkg/data/usr/lib/kismet
mkdir -p dpkg/data/usr/lib/kismet_client

cp ../kismet_capture dpkg/data/usr/bin/
cp ../kismet_server dpkg/data/usr/bin/
cp ../kismet_client dpkg/data/usr/bin/
cp ../scripts/kismet dpkg/data/usr/bin/
chmod +x dpkg/data/usr/bin/kismet
cp ../kismet_drone dpkg/data/usr/bin/

cp ../man/kismet.1 dpkg/data/usr/man/man1/
cp ../man/kismet_drone.1 dpkg/data/usr/man/man1/

cp ../man/kismet.conf.5 dpkg/data/usr/man/man5/
cp ../man/kismet_drone.conf.5 dpkg/data/usr/man/man5/

cp ../conf/kismet.conf dpkg/data/usr/etc/
cp ../conf/kismet_drone.conf dpkg/data/usr/etc/

cp ../README dpkg/data/usr/share/doc/

cp ../wav/* dpkg/data/usr/share/kismet/wav/

cp ../plugin-btscan/btscan.so dpkg/data/usr/lib/kismet/
cp ../plugin-btscan/btscan_ui.so dpkg/data/usr/lib/kismet_client/

cp ../plugin-spectools/spectool_net.so dpkg/data/usr/lib/kismet/
cp ../plugin-spectools/spectools_ui.so dpkg/data/usr/lib/kismet_client/

strip dpkg/data/usr/bin/kismet_*
strip dpkg/data/usr/lib/kismet/*.so
strip dpkg/data/usr/lib/kismet_client/*.so

md5sum dpkg/data/usr/bin/* | sed -e 's/dpkg\/data\///' > dpkg/control/md5sums
md5sum dpkg/data/usr/man/man1/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums
md5sum dpkg/data/usr/man/man5/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums
md5sum dpkg/data/usr/etc/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums
md5sum dpkg/data/usr/lib/kismet/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums
md5sum dpkg/data/usr/lib/kismet_client/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums
md5sum dpkg/data/usr/share/doc/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums
md5sum dpkg/data/usr/share/kismet/wav/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums

VERSION=`../kismet_server --version | sed -e 's/Kismet \([0-9]*\)-\([0-9]*\)-R\([0-9]*\)/\1.\2.\3/'`

cat > dpkg/control/control <<END
Package: kismet
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Homepage: http://www.kismetwireless.net
Installed-Size: `du -ks dpkg/data/|cut -f 1`
Maintainer: Mike Kershaw/Dragorn <dragorn@kismetwireless.net>
Depends: libc6 (>= 2.4), libcap2 (>= 2.10), libpcap0.8 (>= 1.0.0), debconf (>= 0.5) | debconf-2.0, debconf, libcap2-bin, libpcre3, libncurses5, libstdc++6, libnl2, libbluetooth3
Description: Kismet wireless sniffer and IDS
 Kismet is an 802.11 and other wireless sniffer, logger, and IDS.
 .
 This package provides the most recent version, based on the 'newcore'
 code branch.
END

cp dpkg-config dpkg/control/config
chmod +x dpkg/control/config

cp dpkg-template dpkg/control/templates

cp dpkg-postinst dpkg/control/postinst
chmod +x dpkg/control/postinst

cp dpkg-postrm dpkg/control/postrm
chmod +x dpkg/control/postrm

echo "/usr/etc/kismet.conf" > dpkg/control/conffiles
echo "/usr/etc/kismet_drone.conf" > dpkg/control/conffiles

chown root.root dpkg/ -Rv

( cd dpkg/data; tar czvf ../data.tar.gz . )
( cd dpkg/control; tar zcvf ../control.tar.gz . )

echo '2.0' > dpkg/debian-binary

ar -r kismet-$VERSION.$ARCH.deb dpkg/debian-binary dpkg/control.tar.gz dpkg/data.tar.gz

echo "Build dpkg $VERSION for $ARCH"


