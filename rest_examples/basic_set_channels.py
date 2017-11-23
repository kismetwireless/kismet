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
import string

uri = "http://localhost:2501"

parser = argparse.ArgumentParser(description='Kismet demo code')

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--source', action="store", dest="source")
parser.add_argument('--channels', action="store", dest="channels");

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

kr = KismetRest.KismetConnector(uri)
kr.set_login("kismet", "kismet")
kr.set_debug(True)

kr.config_datasource_set_hop_channels(results.source, 5, string.split(results.channels, ','));

