#!/usr/bin/env python

import KismetRest, pprint

kr = KismetRest.Kismet('http://localhost:2501')

# Get system status
status = kr.SystemStatus()

# Get summary of devices
devices = kr.DeviceSummary()

# Fetch the first complete device record
key = devices[0]['kismet.device.base.key']
device = kr.Device(key)

# Print the SSID for every device we can.  Stupid print; no comparison
# of the phy type, no handling empty ssid, etc.
for d in devices:
    k = d['kismet.device.base.key']
    ssid = kr.DeviceField(k, "dot11.device/dot11.device.last_beaconed_ssid")

    print d['kismet.device.base.macaddr'], ssid

