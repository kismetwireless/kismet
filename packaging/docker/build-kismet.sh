#!/bin/bash

set -e

# Comment out if you don't have the RAM to build across all cores
NPROCS="-j $(nproc)"

cd /opt
git clone https://www.kismetwireless.net/git/kismet.git /opt/kismet.git
cd /opt/kismet.git
./configure
make ${NPROCS}
make suidinstall
make forceconfigs
