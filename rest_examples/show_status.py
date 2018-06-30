#!/usr/bin/env python

"""
Very basic introduction to using the KismetRest python library

Queries the status URI for Kismet and prints out some basic information
"""

import sys
import KismetRest
import argparse
import time

uri = "http://localhost:2501"

parser = argparse.ArgumentParser(description='Kismet REST example')

parser.add_argument('--uri', action="store", dest="uri")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

kr = KismetRest.KismetConnector(uri)

kstatus = kr.system_status()

print("Kismet server time: {}".format(time.ctime(kstatus['kismet.system.timestamp.sec'])))
print("Devices seen: {}".format(kstatus['kismet.system.devices.count']))
print("Memory used: {}Kb".format(kstatus['kismet.system.memory.rss']))
