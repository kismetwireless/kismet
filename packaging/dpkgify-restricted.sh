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
mkdir -p dpkg/data/usr/lib/kismet
mkdir -p dpkg/data/usr/lib/kismet_client

cp ../plugin-autowep/autowep-kismet.so dpkg/data/usr/lib/kismet/
cp ../plugin-ptw/aircrack-kismet.so dpkg/data/usr/lib/kismet/

strip dpkg/data/usr/bin/kismet_*
strip dpkg/data/usr/lib/kismet/*.so
strip dpkg/data/usr/lib/kismet_client/*.so

md5sum dpkg/data/usr/lib/kismet/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums
md5sum dpkg/data/usr/lib/kismet_client/* | sed -e 's/dpkg\/data\///' >> dpkg/control/md5sums

VERSION=`../kismet_server --version | sed -e 's/Kismet \([0-9]*\)-\([0-9]*\)-R\([0-9]*\)/\1.\2.\3/'`

cat > dpkg/control/control <<END
Package: kismet-plugins-restricted
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Homepage: http://www.kismetwireless.net
Installed-Size: `du -ks dpkg/data/|cut -f 1`
Maintainer: Mike Kershaw/Dragorn <dragorn@kismetwireless.net>
Depends: libc6 (>= 2.4), libcap2 (>= 2.10), libpcap0.8 (>= 1.0.0), debconf (>= 0.5) | debconf-2.0, debconf, libcap2-bin, libpcre3, libncurses5, libstdc++6, libnl2, kismet (=$VERSION)
Description: Kismet wireless sniffer and IDS, restricted plugins
 Kismet is an 802.11 and other wireless sniffer, logger, and IDS.
 .
 This package contains the 'restricted' plugins, which primarily deal with
 breaking WEP and other 'aggressive' actions.
END

chown root.root dpkg/ -Rv

( cd dpkg/data; tar czvf ../data.tar.gz . )
( cd dpkg/control; tar zcvf ../control.tar.gz . )

echo '2.0' > dpkg/debian-binary

ar -r kismet-$VERSION.plugins-restricted.$ARCH.deb dpkg/debian-binary dpkg/control.tar.gz dpkg/data.tar.gz

echo "Build dpkg $VERSION for $ARCH"


