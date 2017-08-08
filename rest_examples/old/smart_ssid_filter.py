#!/usr/bin/env python

import sys, KismetRest

# Smart SSID filtering
#
# Fetches a list of devices matching a SSID, and summarizes the objects
# to only contain the fields we need.
#
# Fields are passed the same way as the smart_summary API, and can be
# strings, path strings referring to a nested field, complex objects 
# which return a nested result, and may optionally rename fields by
# passing a rename option.

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

kr.set_debug(True)

# Define fields
fields = [
        'kismet.device.base.macaddr',
        'kismet.device.base.phyname',
        'kismet.device.base.type',
        'kismet.device.base.channel',
        'dot11.device/dot11.device.last_beaconed_ssid',
        [ 'dot11.device/dot11.device.last_probed_ssid_csum', 'dot11.checksum' ]
        ]

# Get summary of devices
devices = kr.device_filtered_dot11_summary(sys.argv[2:], fields)

if len(devices) == 0:
    print "No devices found"
    sys.exit(0)

# Print the SSID for every device we can.  Stupid print; no comparison
# of the phy type, no handling empty ssid, etc.
for d in devices:
    if not d['kismet.device.base.phyname'] == "IEEE802.11":
        continue

    print "MAC", d['kismet.device.base.macaddr'],
    print "Type", d['kismet.device.base.type'],
    print "Channel",d['kismet.device.base.channel'],
    print "SSID", d['dot11.device.last_beaconed_ssid']


