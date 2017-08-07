#!/usr/bin/env python

"""
Example of a completely independent method of extracting a list of all devices
Kismet knows about, using the *streaming method*

This uses a combination of ekjson and the requests streaming API to extract
a list of devices without assembling a complete list of devices in RAM
"""

import json
import requests
import sys
import os

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

uri = sys.argv[1]

r = requests.get('{}/devices/all_devices.ekjson'.format(uri), stream=True)

for line in r.iter_lines():
    if line:
        decoded_line = line.decode('utf-8')
        obj = json.loads(decoded_line)
        print "{} - {} {}".format(obj["kismet.device.base.key"], obj["kismet.device.base.name"], obj["kismet.device.base.phyname"])

