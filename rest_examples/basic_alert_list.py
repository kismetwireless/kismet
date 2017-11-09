#!/usr/bin/env python

"""
Basic use of the alerts API
"""

import sys
import KismetRest
import argparse
import time

uri = "http://localhost:2501"

parser = argparse.ArgumentParser(description='Basic alerts')

parser.add_argument('--uri', action="store", dest="uri")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

kr = KismetRest.KismetConnector(uri)

alerts = kr.alerts()

for a in alerts['kismet.alert.list']:
    print a['kismet.alert.header'], a['kismet.alert.text'], a['kismet.alert.transmitter_mac'], a['kismet.alert.source_mac']


