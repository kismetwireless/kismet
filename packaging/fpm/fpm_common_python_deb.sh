#!/bin/sh

if test "$1"x != "x"; then
    GITV=$1
else
    GITV="HEAD"
fi

VERSION="$(date '+%Y%m%d').git-$(git rev-parse --short ${GITV})"

sudo fpm -t deb -s python -v 2018.${GITV}+${VERSION} \
    --python-setup-py-arguments '--prefix=/usr' \
    ./python_modules/KismetRest

sudo fpm -t deb -s python -v 2018.${GITV}+${VERSION} \
    --python-setup-py-arguments '--prefix=/usr' \
    ./python_modules/KismetExternal

sudo fpm -t deb -s python -v 2018.${GITV}+${VERSION} \
    --python-setup-py-arguments '--prefix=/usr' \
    ./python_modules/KismetLog

sudo fpm -t deb -s python -v 2018.${GITV}+${VERSION} \
    --depends python-usb \
    --depends python-paho-mqtt \
    --depends librtlsdr0 \
    --python-setup-py-arguments '--prefix=/usr' \
    ./capture_sdr_rtl433

