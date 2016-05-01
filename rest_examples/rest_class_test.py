#!/usr/bin/env python

import KismetRest
import pprint
import sys

kr = KismetRest.Kismet('http://localhost:2501')

kr.SetDebug(True)

kr.SetLogin("kismet", "kismet")

svalid = kr.CheckSession();
print "Stored session valid:", svalid

if not svalid:
    print "Logging in:", kr.Login()

# Get system status
status = kr.SystemStatus()

# Get summary of devices
devices = kr.DeviceSummary()

if len(devices) == 0:
    print "No devices - is a source configured in Kismet?"
    sys.exit(1)

# Fetch the first complete device record
key = devices[0]['kismet.device.base.key']
device = kr.Device(key)

# Print the SSID for every device we can.  Stupid print; no comparison
# of the phy type, no handling empty ssid, etc.
for d in devices:
    k = d['kismet.device.base.key']
    ssid = kr.DeviceField(k, "dot11.device/dot11.device.last_beaconed_ssid")

    print d['kismet.device.base.macaddr'], ssid

# Check our session
print "Valid session:", kr.CheckSession()

# Try to set a channel source (invalid, then valid)
print "Trying to set invalid source UUID:", kr.LockOldSource("invalid", False, 0)

print "Trying to set valid (but likely not present) source channel: ", kr.LockOldSource("ef9ac4da-0db8-11e6-b824-6205fb28e301", True, 6)

print "Trying to set web GPS:", kr.SendGps(123.456, 78.910, 123, 3)


