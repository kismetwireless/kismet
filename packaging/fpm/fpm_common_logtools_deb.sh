#!/bin/sh -ex

if test "$1"x != "x"; then
    GITV=$1
else
    GITV="HEAD"
fi

VERSION="$(date '+%Y%m%d').git-$(git rev-parse --short ${GITV})"

sudo fpm -t deb -s dir -n kismet-logtool-kml -v 2018.${GITV}+${VERSION} \
    --architecture all \
    --depends python \
    --depends python-sqlite \
    --depends python-dateutil \
    --depends python-pip \
    ./log_tools/kismet_log_to_kml.py=/usr/bin/kismet_log_to_kml

sudo fpm -t deb -s dir -n kismet-logtool-csv -v 2018.${GITV}+${VERSION} \
    --architecture all \
    --depends python \
    --depends python-sqlite \
    --depends python-dateutil \
    --depends python-pip \
    ./log_tools/kismet_log_to_csv.py=/usr/bin/kismet_log_to_csv

sudo fpm -t deb -s dir -n kismet-logtool-pcap -v 2018.${GITV}+${VERSION} \
    --architecture all \
    --depends python \
    --depends python-sqlite \
    --depends python-dateutil \
    --depends python-pip \
    ./log_tools/kismet_log_to_pcap.py=/usr/bin/kismet_log_to_pcap

sudo fpm -t deb -s dir -n kismet-logtool-json -v 2018.${GITV}+${VERSION} \
    --architecture all \
    --depends python \
    --depends python-sqlite \
    --depends python-dateutil \
    --depends python-pip \
    ./log_tools/kismet_log_devices_to_json.py=/usr/bin/kismet_log_to_json

sudo fpm -t deb -s empty -n kismet-logtools -v 2018.${GITV}+${VERSION} \
    --architecture all \
    --depends kismet-logtool-kml \
    --depends kismet-logtool-csv \
    --depends kismet-logtool-pcap \
    --depends kismet-logtool-json


