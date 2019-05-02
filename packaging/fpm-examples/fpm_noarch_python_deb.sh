#!/bin/sh

if test "${CHECKOUT}"x = "HEADx"; then
    GITV="HEAD"
    VERSION="git$(date '+%Y-%m-%d')r$(git rev-parse --short ${GITV})-1"
    PACKAGE="2019+${VERSION}"
else
    PACKAGE="${VERSION}"
fi

sudo fpm -t deb -s python -v ${PACKAGE} \
    --depends python \
    --depends python-protobuf \
    --depends python-requests \
    --python-setup-py-arguments '--prefix=/usr' \
    --python-install-lib /usr/lib/python2.7/dist-packages \
    ./python_modules/KismetRest

sudo fpm -t deb -s python -v ${PACKAGE} \
    --depends python \
    --depends python-protobuf \
    --python-setup-py-arguments '--prefix=/usr' \
    --python-install-lib /usr/lib/python2.7/dist-packages \
    ./python_modules/KismetExternal

sudo fpm -t deb -s python -v ${PACKAGE} \
    --depends python \
    --depends python-protobuf \
    --depends python-requests \
    --python-setup-py-arguments '--prefix=/usr' \
    --python-install-lib /usr/lib/python2.7/dist-packages \
    ./python_modules/KismetDatabase

sudo fpm -t deb -s python -v ${PACKAGE} \
    --depends python \
    --depends python-protobuf \
    --depends python-usb \
    --depends librtlsdr0 \
    --python-setup-py-arguments '--prefix=/usr' \
    --python-install-lib /usr/lib/python2.7/dist-packages \
    ./capture_sdr_rtl433

sudo fpm -t deb -s python -v ${PACKAGE} \
    --depends python \
    --depends python-protobuf \
    --depends python-usb \
    --depends librtlsdr0 \
    --depends golang \
    --python-setup-py-arguments '--prefix=/usr' \
    --python-install-lib /usr/lib/python2.7/dist-packages \
    ./capture_sdr_rtlamr

sudo fpm -t deb -s python -v ${PACKAGE} \
    --depends python \
    --depends python-protobuf \
    --depends python-usb \
    --depends python-numpy \
    --depends librtlsdr0 \
    --python-setup-py-arguments '--prefix=/usr' \
    --python-install-lib /usr/lib/python2.7/dist-packages \
    ./capture_sdr_rtladsb

sudo fpm -t deb -s python -v ${PACKAGE} \
    --depends python \
    --depends python-protobuf \
    --depends python-usb \
    --python-setup-py-arguments '--prefix=/usr' \
    --python-install-lib /usr/lib/python2.7/dist-packages \
    --python-disable-dependency pyserial \
    ./capture_freaklabs_zigbee

