#!/usr/bin/env python

import KismetRest
import pprint
import sys

kr = KismetRest.KismetConnector('http://localhost:2501')

kr.set_debug(True)

kr.set_login("kismet", "kismet")

svalid = kr.check_session();
print "Stored session valid:", svalid

if not svalid:
    print "Logging in:", kr.login()

# Check our session
print "Valid session:", kr.check_session()

# Get system status
status = kr.system_status()

print status

# Get summary of devices
devices = kr.device_summary()

if len(devices) == 0:
    print "No devices - is a source configured in Kismet?"
    sys.exit(1)

# Fetch the first complete device record
key = devices[0]['kismet.device.base.key']
device = kr.device(key)

# Print the SSID for every device we can.  Stupid print; no comparison
# of the phy type, no handling empty ssid, etc.
for d in devices:
    k = d['kismet.device.base.key']
    ssid = kr.device_field(k, "dot11.device/dot11.device.last_beaconed_ssid")

    print d['kismet.device.base.macaddr'], ssid


# Try to set a channel source (invalid, then valid)
print "Trying to set invalid source UUID:", kr.lock_old_source("invalid", False, 0)

print "Trying to set valid (but likely not present) source channel: ", kr.lock_old_source("ef9ac4da-0db8-11e6-b824-6205fb28e301", True, 6)

print "Trying to set web GPS:", kr.send_gps(123.456, 78.910, 123, 3)


