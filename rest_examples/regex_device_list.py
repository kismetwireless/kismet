#!/usr/bin/env python

"""
More advanced use of the smart_device_list API which uses field simplification,
regex pattern matching of the SSID, and a callback function.  This is the
optimal configuration for large queries.

The callback function per_device(dev) is called for each device in the 
returned list, significantly reducing memory load in high-device-count
environments.

"""

import sys
import KismetRest
import argparse
import time

# Per-device function called for each line in the ekjson.  Notice that with the
# simplified fields our device contains ONLY the macaddr, last beaconed ssid
# (renamed to simple.last_ssid), and the signal records!
def per_device(d):
    print d['kismet.device.base.macaddr'], d['simple.last_ssid']
    # print d

uri = "http://localhost:2501"

parser = argparse.ArgumentParser(description='Kismet example')

parser.add_argument('--uri', action="store", dest="uri")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

kr = KismetRest.KismetConnector(uri)

# Regex is *always* an array.  Each regex is 2 elements, the field and the 
# regex itself.
regex = [
    # Search all advertised SSIDs for something that starts with UES
    ["dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid", "^UES*"],
    # Search the last advertised SSID for an explicit name
    ["dot11.device/dot11.device.last_beaconed_ssid", "^linksys$"],
]

# Simplifying the fields saves us transfer time and processing time on both ends
# of the connection; this is the most efficient way to query devices
fields = [
    # macaddr
    'kismet.device.base.macaddr',
    # Last beaconed SSID, renamed to 'simple.last_ssid'
    ['dot11.device/dot11.device.last_beaconed_ssid', 'simple.last_ssid'],
    # Grab the entire signal sub-record
    'kismet.device.base.signal'
]

kr.smart_device_list(callback = per_device, regex = regex, fields = fields)

