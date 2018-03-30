set -e

rm -rf /usr/src/kismet
git clone https://www.kismetwireless.net/git/kismet /usr/src/kismet
cd /usr/src/kismet
./configure
make -j4
make suidinstall
