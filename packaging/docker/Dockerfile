FROM ubuntu:16.04
WORKDIR /opt
RUN apt-get update && \
    apt-get install -y gdb gdbserver \
    pkg-config build-essential git autoconf unzip python \
    libmicrohttpd-dev zlib1g-dev libnl-3-dev libnl-genl-3-dev \
    libcap-dev libpcap-dev libncurses5-dev libnm-dev libdw-dev \
    libsqlite3-dev libprotobuf-dev libprotobuf-c-dev \
    protobuf-compiler protobuf-c-compiler \
    librtlsdr0 && \
    cd /usr/src && \
    git clone https://www.kismetwireless.net/git/kismet.git
CMD bash /usr/src/kismet/packaging/docker/build.sh


