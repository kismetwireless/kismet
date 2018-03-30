set -e

cd /usr/src
rm -rf kismet
git clone https://www.kismetwireless.net/git/kismet
./configure
make -j4
make suidinstall
