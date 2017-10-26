#!/usr/bin/env python

"""
Basic use of the device API to pull all devices with a drone ID
"""

import sys
import KismetRest
import argparse
import time

def per_device(d):
    print d['kismet.device.base.macaddr'],
    print d['dot11.device']['dot11.device.last_beaconed_ssid'],
    print d['uav.device']['uav.serialnumber'],
    print d['uav.device']['uav.last_telemetry']['uav.telemetry.location']['kismet.common.location.lat'],
    print d['uav.device']['uav.last_telemetry']['uav.telemetry.location']['kismet.common.location.lon']

uri = "http://localhost:2501"

parser = argparse.ArgumentParser(description='Kismet tool')

parser.add_argument('--uri', action="store", dest="uri")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

kr = KismetRest.KismetConnector(uri)

regex = [
    [ "uav.device/uav.serialnumber", ".+" ]
]

kr.smart_device_list(callback = per_device, regex = regex)

