#!/usr/bin/env python

# Simple dumper to extract kismet records and export them as a json
# array

import argparse
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Index
import json
import sqlite3
import string
import sys
import re

def strip_old_empty_trees(obj):
    # Hardcoded list of previously dynamic objects which could be set to 0
    empty_trees = [
        "kismet.device.base.location",
        "kismet.device.base.datasize.rrd",
        "kismet.device.base.location_cloud",
        "kismet.device.base.packet.bin.250",
        "kismet.device.base.packet.bin.500",
        "kismet.device.base.packet.bin.1000",
        "kismet.device.base.packet.bin.1500",
        "kismet.device.base.packet.bin.jumbo",
        "kismet.common.signal.signal_rrd",
        "kismet.common.signal.peak_loc",
        "dot11.client.location",
        "client.location",
        "dot11.client.ipdata",
        "dot11.advertisedssid.location",
        "dot11.probedssid.location",
        "kismet.common.seenby.signal"
        ]

    try:
        for k in obj.keys():
            if k in empty_trees and obj[k] == 0:
                obj.pop(k)
            else:
                obj[k] = strip_old_empty_trees(obj[k])

        return obj
    except Exception as e:
        return obj

def rename_json_keys(obj):
    # ELK doesn't like periods in field names...
    try:
        for k in obj.keys():
            nk = string.replace(k, ".", "_")
            obj[nk] = rename_json_keys(obj[k])
            obj.pop(k)

        return obj
    except Exception as e:
        return obj

parser = argparse.ArgumentParser(description="Kismet to ELK")
parser.add_argument("--in", action="store", dest="infile", help='Input (.kismet) file')

results = parser.parse_args()

if results.infile is None:
    print "Expected --in [file]"
    sys.exit(1)

try:
    db = sqlite3.connect(results.infile)
except Exception as e:
    print "Failed to open kismet logfile: ", e
    sys.exit(1)

try:
    es = Elasticsearch([{"host": 'localhost', "port": 9200}])
except Exception as e:
    print "Failed to connect to elk: ", e
    sys.exit(1)

sql = "SELECT device FROM devices "

c = db.cursor()

for row in c.execute(sql):
    try:
        dev = strip_old_empty_trees(json.loads(str(row[0])))
        dev = rename_json_keys(dev)
        res = es.index(index='kismet', doc_type='device', body=dev)
        print dev['kismet_device_base_key'], res
    
    except TypeError as t:
        print t
        continue
    except KeyError as k:
        print k
        continue

