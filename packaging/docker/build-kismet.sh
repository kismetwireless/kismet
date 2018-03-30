#!/bin/bash

set -e

cd /opt
git clone https://www.kismetwireless.net/git/kismet.git /opt/kismet-2018.git
cd /opt/kismet-2018.git
./configure
make
make suidinstall
make forceconfigs
