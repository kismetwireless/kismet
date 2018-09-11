#!/bin/sh

WORKDIR=kismet-fpm-python

if [ ! -e ${WORKDIR} ]; then
    git clone https://www.kismetwireless.net/git/kismet.git ${WORKDIR}
fi

cd ${WORKDIR}

rm -vf *.deb

if test "$1"x = "rebuild"x; then
    git pull

    # Enable everything
    ./configure --prefix=/usr --sysconfdir=/etc/kismet 

    make -j$(nproc)
fi

VERSION=$(git rev-parse --short HEAD)

sudo fpm -t deb -s python -v 2018.git.${VERSION} \
    --python-setup-py-arguments '--prefix=/usr' \
    ./python_modules/KismetRest

sudo fpm -t deb -s python -v 2018.git.${VERSION} \
    --python-setup-py-arguments '--prefix=/usr' \
    ./python_modules/KismetExternal

sudo fpm -t deb -s python -v 2018.git.${VERSION} \
    --python-setup-py-arguments '--prefix=/usr' \
    ./python_modules/KismetLog

sudo fpm -t deb -s python -v 2018.git.${VERSION} \
    --depends python-usb \
    --depends python-paho-mqtt \
    --depends librtlsdr0 \
    --python-setup-py-arguments '--prefix=/usr' \
    ./capture_sdr_rtl433

