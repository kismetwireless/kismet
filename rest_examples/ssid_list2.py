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
    if not d['kismet.device.base.phyname'] == "IEEE802.11":
        continue

    # Dot11 phy now puts this in the summary for us
    # k = d['kismet.device.base.key']
    # ssid = kr.device_field(k, "dot11.device/dot11.device.last_beaconed_ssid")

    if d['dot11.device.last_beaconed_ssid'] == "":
       continue

    print "MAC", d['kismet.device.base.macaddr'],
    print "Type", d['kismet.device.base.type'],
    print "Channel",d['kismet.device.base.channel'],
    print "SSID", d['dot11.device.last_beaconed_ssid']


