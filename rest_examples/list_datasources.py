#!/usr/bin/env python

"""
Basic use of the Kismet Python library to list datasources on a Kismet server
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

datasources = kr.datasources()

for ds in datasources:
    print("UUID: {}".format(ds['kismet.datasource.uuid']))
    print("Name: {}".format(ds['kismet.datasource.name']))

    if not ds['kismet.datasource.running']:
        print("Running: FALSE")

    print("Source type: {}".format(ds['kismet.datasource.type_driver']['kismet.datasource.driver.type']))

    if ds['kismet.datasource.remote']:
        print("Remote: True")

    if ds['kismet.datasource.hopping']:
        print("Hopping: True")
    else:
        print("Hopping: False")

    if len(ds['kismet.datasource.hop_channels']):
        print("Channels: {}".format(", ".join(ds['kismet.datasource.hop_channels'])))

    if len(ds['kismet.datasource.channel']):
        print("Channel: {}".format(ds['kismet.datasource.channel']))

    print("Packets: {}".format(ds['kismet.datasource.num_packets']))

    print("")

