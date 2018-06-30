#!/usr/bin/env python

"""
Example of using regex to search other fields, searching for the OUI
component of a MAC address

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
    print(d['kismet.device.base.macaddr'], d['simple.last_ssid'], "pcre", d['kismet.pcre.match'])
    # print(d)

uri = "http://localhost:2501"
oui = ""

parser = argparse.ArgumentParser(description='Kismet example')

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--oui', action="store", dest="oui")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

if results.oui != None:
    oui = results.oui
else:
    print("Expected --oui")
    sys.exit(1)

kr = KismetRest.KismetConnector(uri)

kr.set_debug(True)

# Regex is *always* an array.  Each regex is 2 elements, the field and the 
# regex itself.
regex = [
    ["kismet.device.base.macaddr", "^{}.*".format(oui)],
]

# Simplifying the fields saves us transfer time and processing time on both ends
# of the connection; this is the most efficient way to query devices
fields = [
    # macaddr
    'kismet.device.base.macaddr',
    # Last beaconed SSID, renamed to 'simple.last_ssid'
    ['dot11.device/dot11.device.last_beaconed_ssid', 'simple.last_ssid'],
    # Grab the entire signal sub-record
    'kismet.device.base.signal',
    # Grab the pcre index we matched
    'kismet.pcre.match',
]

kr.smart_device_list(callback = per_device, regex = regex, fields = fields)

