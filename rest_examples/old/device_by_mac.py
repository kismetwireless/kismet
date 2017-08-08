#!/usr/bin/env python

import sys, KismetRest

if len(sys.argv) < 3:
    print "Expected server URI and mac address"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

devices = kr.device_by_mac(sys.argv[2])

if len(devices) == 0:
    print "Nothing matching ", sys.argv[2]

# Print the SSID for every device we can.  Stupid print; no comparison
# of the phy type, no handling empty ssid, etc.
for d in devices:
    print "MAC", d['kismet.device.base.macaddr'],
    print "Type", d['kismet.device.base.type'],
    print "Channel",d['kismet.device.base.channel'],


