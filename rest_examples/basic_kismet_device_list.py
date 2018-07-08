#!/usr/bin/env python

"""
Basic use of the smart_device_list API in the KismetRest python library.

The callback function per_device(dev) is called for each device in the 
returned list, significantly reducing memory load in high-device-count
environments.

"""

import sys
import KismetRest
import argparse
import time

def per_device(d):
    print(d['kismet.device.base.macaddr'])

uri = "http://localhost:2501"

parser = argparse.ArgumentParser(description='Kismet demo code')

parser.add_argument('--uri', action="store", dest="uri")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

kr = KismetRest.KismetConnector(uri)

kr.smart_device_list(callback = per_device)

