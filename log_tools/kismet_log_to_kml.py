#!/usr/bin/env python

# Simple dumper to extract kismet records and export them as a json
# array

import argparse
from dateutil import parser as dateparser
import datetime
import json
import struct
import sqlite3
import sys
import simplekml
import re

parser = argparse.ArgumentParser(description="Kismet to KML Log Converter")
parser.add_argument("--in", action="store", dest="infile", help='Input (.kismet) file')
parser.add_argument("--out", action="store", dest="outfile", help='Output filename (optional)')
parser.add_argument("--start-time", action="store", dest="starttime", help='Only list devices seen after given time')
parser.add_argument("--min-signal", action="store", dest="minsignal", help='Only list devices with a best signal higher than min-signal')
parser.add_argument("--strongest-point", action="store_true", dest="strongest", default=False, help='Plot points based on strongest signal')
parser.add_argument("--title", action="store", dest="title", default="Kismet", help='Title embedded in KML file')
parser.add_argument("--ssid", action="store", dest="ssid", help='Only plot networks which match the SSID (or SSID regex)')

results = parser.parse_args()

log_to_single = True

if results.infile is None:
    print "Expected --in [file]"
    sys.exit(1)

try:
    db = sqlite3.connect(results.infile)
except Exception as e:
    print "Failed to open kismet logfile: ", e
    sys.exit(1)

replacements = {}
select = ""

epoch = datetime.datetime.utcfromtimestamp(0)

if results.starttime:
    try:
        st = dateparser.parse(results.starttime, fuzzy = True)
    except ValueError as e:
        print "Could not extract a date/time from start-time argument:", e
        sys.exit(0)

    secs = (st - epoch).total_seconds()

    if select == "":
        select = "first_time > :tsstart"
    else:
        select = select + " AND first_time > :tsstart"

    replacements["tsstart"] = secs

if results.minsignal:
    if select == "":
        select = "max_signal > :signal"
    else:
        select = select + " AND max_signal > :signal"

    replacements["signal"] = results.minsignal

sql = "SELECT device FROM devices "

if select != "":
    sql = sql + " WHERE " + select

logf = None

c = db.cursor()

devs = []

kml = simplekml.Kml()
kml.document.name = results.title

num_plotted = 0

for row in c.execute(sql, replacements):
    try:
        dev = json.loads(row[0])

        # Check for the SSID if we're doing that; allow it to trip
        # a KeyError and jump out of processing this device
        if not results.ssid is None:
            matched = False
            for s in dev['dot11.device']['dot11.device.advertised_ssid_map']:
                if re.match(results.ssid, 
                        dev['dot11.device']['dot11.device.advertised_ssid_map'][s]['dot11.advertisedssid.ssid']):
                    matched = True
                    break

            if not matched:
                continue

        loc = None

        if results.strongest:
            loc = dev['kismet.device.base.signal']['kismet.common.signal.peak_loc']
        else:
            loc = dev['kismet.device.base.location']['kismet.common.location.avg_loc']

        mac = dev['kismet.device.base.macaddr']

        title = ""

        if 'kismet.device.base.name' in dev:
            title = dev['kismet.device.base.name']

        if title is "":
            if 'dot11.device' in dev:
                if 'dot11.device.last_beaconed_ssid' in dev['dot11.device']:
                    title = dev['dot11.device']['dot11.device.last_beaconed_ssid']

        if title is "":
            title = mac

        pt = kml.newpoint(name = title, 
                coords = [(loc['kismet.common.location.lon'], 
                    loc['kismet.common.location.lat'], 
                    loc['kismet.common.location.alt'])])

        num_plotted = num_plotted + 1

    except KeyError:
        continue

kml.save(results.outfile)

print "Exported {} devices to {}".format(num_plotted, results.outfile)
