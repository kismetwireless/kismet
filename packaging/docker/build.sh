set -e

cd /usr/src/kismet
./configure
make -j4
make suidinstall
