#!/bin/bash

# Assign a wifi interface to a docker instance so that Kismet can run it
# as if it was a native interface
#
# The docker instance must already be running

if test $# -lt 2; then
    echo "expected $0 [docker name] [interface]"
fi

DOCKER=$1
IFACE=$2

PHY=$(cat /sys/class/net/"$IFACE"/phy80211/name)

PID=$(docker inspect -f '{{.State.Pid}}' $DOCKER)

echo "Found phy $PHY docker pid $PID"

iw phy "$PHY" set netns "$PID"

