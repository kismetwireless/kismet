FROM ubuntu:bionic

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
	python \
	python-setuptools \
	python-protobuf \
	python-sqlite \
	python-requests \
    python-usb \
    python-numpy \
    python-dev \
	librtlsdr0 \
	libusb-1.0-0-dev \
	python-pip 

COPY build-kismet.sh /opt/build-kismet.sh
RUN /bin/bash /opt/build-kismet.sh

COPY kismet_site.conf /usr/local/etc/kismet_site.conf

EXPOSE 2501
EXPOSE 3501

CMD ["/usr/local/bin/kismet", "--no-ncurses"]


