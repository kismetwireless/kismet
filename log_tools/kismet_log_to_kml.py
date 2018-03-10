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

parser = argparse.ArgumentParser(description="Kismet to KML Log Converter")
parser.add_argument("--in", action="store", dest="infile", help='Input (.kismet) file')
parser.add_argument("--out", action="store", dest="outfile", help='Output filename (optional)')
parser.add_argument("--start-time", action="store", dest="starttime", help='Only list devices seen after given time')
parser.add_argument("--min-signal", action="store", dest="minsignal", help='Only list devices with a best signal higher than min-signal')
parser.add_argument("--strongest-point", action="store_true", dest="strongest", default=False, help='Plot points based on strongest signal')
parser.add_argument("--title", action="store", dest="title", default="Kismet", help='Title embedded in KML file')

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

for row in c.execute(sql, replacements):
    dev = json.loads(row[0])

    avgloc = dev['kismet.device.base.location']['kismet.common.location.avg_loc']
    mac = dev['kismet.device.base.macaddr']

    pt = kml.newpoint(name = mac, 
            coords = [(avgloc['kismet.common.location.lon'], avgloc['kismet.common.location.lat'])])

kml.save(results.outfile)

