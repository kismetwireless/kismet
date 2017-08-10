#!/usr/bin/env python

"""
A complete basic utility using the python REST API and the KismetRest python
library.

Uses Kismet to monitor:
    - A list of devices identified by MAC address (via --mac option)
    - A list of devices identified by beaconed SSID (via --ssid option)
    - A list of devices identified by probed SSID (via --probed option)
"""

import sys
import KismetRest
import argparse
import time

# Per-device function called for each line in the ekjson.  Notice that we use the
# field simplification system to reduce the number of devices we're looking at.

# We use a global to keep track of the last timestamp devices were seen, so that
# we can over-sample the timeframe in kismet but only print out devices which have
# updated
last_ts_cache = {}
def per_device(d):
    key = d['kismet.device.base.key']

    # Check the cache and don't process devices which haven't updated
    if key in last_ts_cache:
        if last_ts_cache[key] == d['kismet.device.base.last_time']:
            return
    last_ts_cache[key] = d['kismet.device.base.last_time']

    if 'dot11.device.last_beaconed_ssid' in d and not d['dot11.device.last_beaconed_ssid'] == "":
        beaconssid = d['dot11.device.last_beaconed_ssid']
    else:
        beaconssid = "n/a"

    if 'dot11.device.last_probed_ssid' in d and not d['dot11.device.last_probed_ssid'] == "":
        probessid = d['dot11.device.last_probed_ssid']
    else:
        probessid = "n/a"

    print "{} - {} - {} {} {}".format(
            d['kismet.device.base.macaddr'],
            time.ctime(d['kismet.device.base.last_time']),
            d['kismet.common.signal.last_signal_dbm'],
            beaconssid,
            probessid)


uri = "http://localhost:2501"

rate = 5

parser = argparse.ArgumentParser(description='Kismet example')

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--mac', action="append", dest="macs")
parser.add_argument('--ssid', action="append", dest="ssids")
parser.add_argument('--probed', action="append", dest="probed")
parser.add_argument('--rate', action="store", dest="rate")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

if results.macs != None:
    if results.ssids != None or results.probed != None:
        print "Can't combine MAC selection with SSID or Probed SSID, sorry"
        sys.exit(1)

if results.rate != None:
    rate = results.rate

kr = KismetRest.KismetConnector(uri)
kr.set_debug(1)

regex = []

if results.ssids != None:
    for s in results.ssids:
        regex.append(["dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid", s])

if results.probed != None:
    for s in results.probed:
        regex.append(["dot11.device/dot11.device.probed_ssid_map/dot11.probedssid.ssid", s])

if len(regex) != 0:
    print "Matching against {} SSIDs".format(len(regex))
elif results.macs != None and len(results.macs) != 0:
    print "Matching against {} MAC addresses".format(len(results.macs))
    regex = None
else:
    print "Reporting all active devices..."
    regex = None
    results.macs = None

# Simplify the fields to what we want to print out
fields = [
    'kismet.device.base.key',
    'kismet.device.base.macaddr',
    'kismet.device.base.last_time',
    'kismet.device.base.signal/kismet.common.signal.last_signal_dbm',
    'dot11.device/dot11.device.last_beaconed_ssid',
    'dot11.device/dot11.device.last_probed_ssid',
]

while True:
    # Scan for mac addresses individually
    if results.macs != None:
        for m in results.macs:
            # device_by_mac returns a vector, turn that into calls of our 
            # device handling function
            for d in kr.device_by_mac(m, fields):
                per_device(d)
    else:
        # Otherwise, look for devices which have changed, and which optionally match 
        # any of our regexes, within our time range * 2

        # Generate a negative timestamp which is our rate, 
        ts = (rate * 2) * -1

        kr.smart_device_list(callback = per_device, regex = regex, fields = fields, ts = ts)

    time.sleep(rate)


