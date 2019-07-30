FROM ubuntu:bionic as build

# Install build deps
RUN apt-get update && apt-get install -y \
	build-essential \
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
	python3 \
	python3-pip \
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

COPY / /opt/kismet/
WORKDIR /opt/kismet/
RUN ./configure
RUN make -j$(nproc)
RUN make install
RUN make forceconfigs

FROM ubuntu:bionic

# Install runtime deps
RUN apt-get update && apt-get install -y \
	libmicrohttpd-dev \
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
	python3 \
	python-protobuf \
	python-sqlite \
	python-requests \
        python-usb \
        python-numpy \
        python-dev \
	librtlsdr0 \
	libusb-1.0-0-dev

COPY --from=build /usr/local /usr/local
COPY /packaging/docker/kismet_site.conf /usr/local/etc/kismet_site.conf

EXPOSE 2501
EXPOSE 3501

VOLUME /root/.kismet/

CMD ["/usr/local/bin/kismet", "--no-ncurses"]
