FROM ubuntu:bionic

COPY build-kismet.sh /opt/build-kismet.sh
COPY kismet_site.conf /usr/local/etc/kismet_site.conf

RUN apt-get update && apt-get install -y \
	sudo \
	build-essential \
	git \
	libmicrohttpd-dev \
	pkg-config \
	zlib1g-dev \
	libnl-3-dev \
	libnl-genl-3-dev \
	libcap-dev \
	libpcap-dev \
	libnm-dev \
	libdw-dev \
	libsqlite3-dev \
	libprotobuf-dev \
	libprotobuf-c-dev \
	protobuf-compiler \
	protobuf-c-compiler \
	libsensors4-dev \
	python3 \
	python3-setuptools \
	python3-protobuf \
    python3-usb \
    python3-numpy \
    python3-dev \
	python3-pip \
    python3-serial \
	librtlsdr0 \
	libusb-1.0-0-dev 

RUN /bin/bash /opt/build-kismet.sh

EXPOSE 2501
EXPOSE 3501

CMD ["/usr/local/bin/kismet", "--no-ncurses-wrapper"]


