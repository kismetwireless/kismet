#!/usr/bin/env python

import sys, KismetRest

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

# Get summary of devices
devices = kr.device_summary()

if len(devices) == 0:
    print "No devices"

# Print the SSID for every device we can.  Stupid print; no comparison
# of the phy type, no handling empty ssid, etc.
for d in devices:
    print "MAC", d['kismet.device.base.macaddr'],
    print "Type", d['kismet.device.base.type'],
    print "Channel",d['kismet.device.base.channel']


