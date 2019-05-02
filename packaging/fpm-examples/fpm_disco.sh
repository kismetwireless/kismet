#!/bin/sh -e

if test "${CHECKOUT}"x = "HEADx"; then
    GITV="HEAD"
    VERSION="git$(date '+%Y-%m-%d')r$(git rev-parse --short ${GITV})-1"
    PACKAGE="2019+${VERSION}"
else
    PACKAGE="${VERSION}"
fi

cp kismet kismet_stripped
strip kismet_stripped

sudo fpm -t deb -s dir -n kismet-core-debug -v ${PACKAGE} \
    --description "Kismet core, full debug symbols" \
    --replaces kismet \
    --replaces kismet-plugins \
    --deb-recommends kismet-capture-linux-wifi \
    --deb-recommends kismet-capture-linux-bluetooth \
    --deb-recommends kismet-capture-nrf-mousejack \
    --deb-recommends python-kismetcapturertl433 \
    --deb-recommends python-kismetcapturertladsb \
    --deb-recommends python-kismetcapturertlamr \
    --deb-recommends python-kismetcapturefreaklabszigbee \
    --deb-recommends kismet-logtools \
    --deb-templates /scripts/fpm/debian/kismet.templates \
    --deb-config /scripts/fpm/debian/kismet.config \
    --depends libmicrohttpd12 \
    --depends zlib1g \
    --depends libpcap0.8 \
    --depends libdw1 \
    --depends libsqlite3-0 \
    --depends libprotobuf17 \
    --depends libprotobuf-c1 \
    --depends libsensors5 \
    ./conf/kismet.conf=/etc/kismet/kismet.conf \
    ./conf/kismet_alerts.conf=/etc/kismet/kismet_alerts.conf \
    ./conf/kismet_httpd.conf=/etc/kismet/kismet_httpd.conf \
    ./conf/kismet_logging.conf=/etc/kismet/kismet_logging.conf \
    ./conf/kismet_memory.conf=/etc/kismet/kismet_memory.conf \
    ./conf/kismet_storage.conf=/etc/kismet/kismet_storage.conf \
    ./conf/kismet_uav.conf=/etc/kismet/kismet_uav.conf \
    ./conf/kismet_80211.conf=/etc/kismet/kismet_80211.conf \
    ./conf/kismet_filter.conf=/etc/kismet/kismet_filter.conf \
    ./conf/kismet_manuf.txt=/usr/share/kismet/kismet_manuf.txt \
    ./kismet=/usr/bin/kismet \
    ./kismet_cap_pcapfile=/usr/bin/kismet_cap_pcapfile \
    ./kismet_cap_kismetdb=/usr/bin/kismet_cap_kismetdb \
    ./packaging/kismet.pc=/usr/share/pkgconfig/kismet.pc \
    ./packaging/systemd/kismet.service=/lib/systemd/system/kismet.service \
    ./http_data/=/usr/share/kismet/httpd 

sudo fpm -t deb -s dir -n kismet-core -v ${PACKAGE} \
    --description "Kismet core" \
    --replaces kismet \
    --replaces kismet-plugins \
    --deb-recommends kismet-capture-linux-wifi \
    --deb-recommends kismet-capture-linux-bluetooth \
    --deb-recommends kismet-capture-nrf-mousejack \
    --deb-recommends python-kismetcapturertl433 \
    --deb-recommends python-kismetcapturertladsb \
    --deb-recommends python-kismetcapturertlamr \
    --deb-recommends python-kismetcapturefreaklabszigbee \
    --deb-recommends kismet-logtools \
    --deb-templates /scripts/fpm/debian/kismet.templates \
    --deb-config /scripts/fpm/debian/kismet.config \
    --depends libmicrohttpd12 \
    --depends zlib1g \
    --depends libpcap0.8 \
    --depends libdw1 \
    --depends libsqlite3-0 \
    --depends libprotobuf17 \
    --depends libprotobuf-c1 \
    --depends libsensors5 \
    ./conf/kismet.conf=/etc/kismet/kismet.conf \
    ./conf/kismet_alerts.conf=/etc/kismet/kismet_alerts.conf \
    ./conf/kismet_httpd.conf=/etc/kismet/kismet_httpd.conf \
    ./conf/kismet_logging.conf=/etc/kismet/kismet_logging.conf \
    ./conf/kismet_memory.conf=/etc/kismet/kismet_memory.conf \
    ./conf/kismet_storage.conf=/etc/kismet/kismet_storage.conf \
    ./conf/kismet_uav.conf=/etc/kismet/kismet_uav.conf \
    ./conf/kismet_80211.conf=/etc/kismet/kismet_80211.conf \
    ./conf/kismet_filter.conf=/etc/kismet/kismet_filter.conf \
    ./conf/kismet_manuf.txt=/usr/share/kismet/kismet_manuf.txt \
    ./kismet_stripped=/usr/bin/kismet \
    ./kismet_cap_pcapfile=/usr/bin/kismet_cap_pcapfile \
    ./kismet_cap_kismetdb=/usr/bin/kismet_cap_kismetdb \
    ./packaging/kismet.pc=/usr/share/pkgconfig/kismet.pc \
    ./packaging/systemd/kismet.service=/lib/systemd/system/kismet.service \
    ./http_data/=/usr/share/kismet/httpd 

sudo fpm -t deb -s dir -n kismet-capture-linux-wifi -v ${PACKAGE} \
    --description "Kismet Linux Wi-Fi capture helper" \
    --deb-templates /scripts/fpm/debian/kismet.templates \
    --deb-config /scripts/fpm/debian/kismet.config \
    --post-install /scripts/fpm/debian/kismet_cap_linux_wifi.postinst \
    --depends libnl-3-200 \
    --depends libnl-genl-3-200 \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libpcap0.8 \
    --depends libnm0 \
    --depends libprotobuf-c1 \
    ./capture_linux_wifi/kismet_cap_linux_wifi=/usr/bin/kismet_cap_linux_wifi 

sudo fpm -t deb -s dir -n kismet-capture-linux-bluetooth -v ${PACKAGE} \
    --description "Kismet Linux Bluetooth capture helper" \
    --deb-templates /scripts/fpm/debian/kismet.templates \
    --deb-config /scripts/fpm/debian/kismet.config \
    --post-install /scripts/fpm/debian/kismet_cap_linux_bluetooth.postinst \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libnm0 \
    --depends libprotobuf-c1 \
    ./capture_linux_bluetooth/kismet_cap_linux_bluetooth=/usr/bin/kismet_cap_linux_bluetooth 
    
sudo fpm -t deb -s dir -n kismet-capture-nrf-mousejack -v ${PACKAGE} \
    --description "Kismet nRF MouseJack capture helper" \
    --deb-templates /scripts/fpm/debian/kismet.templates \
    --deb-config /scripts/fpm/debian/kismet.config \
    --post-install /scripts/fpm/debian/kismet_cap_nrf_mousejack.postinst \
    --depends libcap2-bin \
    --depends libcap2 \
    --depends libprotobuf-c1 \
    --depends libusb-1.0-0 \
    ./capture_nrf_mousejack/kismet_cap_nrf_mousejack=/usr/bin/kismet_cap_nrf_mousejack

sudo fpm -t deb -s dir -n kismet-logtools -v ${PACKAGE} \
	--description "Kismet kismetdb log tools (kismetdb)" \
	--depends libpcap0.8 \
	--depends libsqlite3-0 \
	./log_tools/kismetdb_strip_packets=/usr/bin/kismetdb_strip_packets \
	./log_tools/kismetdb_to_wiglecsv=/usr/bin/kismetdb_to_wiglecsv \
	./log_tools/kismetdb_statistics=/usr/bin/kismetdb_statistics \
	./log_tools/kismetdb_dump_devices=/usr/bin/kismetdb_dump_devices

sudo fpm -t deb -s empty -n kismet -v ${PACKAGE} \
    --description "Kismet metapackage" \
    --depends kismet-core \
    --depends kismet-capture-linux-wifi \
    --depends kismet-capture-linux-wifi \
    --depends kismet-capture-linux-bluetooth \
    --depends kismet-capture-nrf-mousejack \
    --depends python-kismetcapturertl433 \
    --depends python-kismetcapturertladsb \
    --depends python-kismetcapturertlamr \
    --depends python-kismetcapturefreaklabszigbee \
    --depends kismet-logtools 


