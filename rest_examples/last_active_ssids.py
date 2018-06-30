#!/usr/bin/env python

"""
Use the Kismet API to show the last active beaconing APs
"""

import sys
import KismetRest
import argparse
import time

def per_device(d):
    print(d['kismet.device.base.macaddr'], d['simple.last_ssid'])

uri = "http://localhost:2501"

parser = argparse.ArgumentParser(description='Kismet demo code')

parser.add_argument('--uri', action="store", dest="uri")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

kr = KismetRest.KismetConnector(uri)

# Regex is *always* an array.  Each regex is 2 elements, the field and the 
# regex itself.
regex = [
    ["dot11.device/dot11.device.last_beaconed_ssid", ".+"],
]

fields = [
    # macaddr
    'kismet.device.base.macaddr',
    # Last beaconed SSID, renamed to 'simple.last_ssid'
    ['dot11.device/dot11.device.last_beaconed_ssid', 'simple.last_ssid'],
    # Grab the entire signal sub-record
    'kismet.device.base.signal',
]

kr.smart_device_list(callback = per_device, ts = -60, fields = fields, regex = regex)

