#!/usr/bin/env python

# Simple dumper to extract kismet records and export them as a json
# array

import argparse
import datetime
import json
import struct
import sqlite3
import sys

try:
    from dateutil import parser as dateparser
except Exception as e:
    print("kismet_log_to_kml requires dateutil; please install it either via your distribution")
    print("(python-dateutil) or via pip (pip install dateutil)")
    sys.exit(1)

parser = argparse.ArgumentParser(description="Kismet to Pcap Log Converter")
parser.add_argument("--in", action="store", dest="infile", help='Input (.kismet) file')
parser.add_argument("--out", action="store", dest="outfile", help='Output filename (optional)')
parser.add_argument("--start-time", action="store", dest="starttime", help='Only list devices seen after given time')
parser.add_argument("--min-signal", action="store", dest="minsignal", help='Only list devices with a best signal higher than min-signal')

results = parser.parse_args()

log_to_single = True

if results.infile is None:
    print("Expected --in [file]")
    sys.exit(1)

try:
    db = sqlite3.connect(results.infile)
except Exception as e:
    print("Failed to open kismet logfile: ", e)
    sys.exit(1)

replacements = {}
select = ""

epoch = datetime.datetime.utcfromtimestamp(0)

if results.starttime:
    try:
        st = dateparser.parse(results.starttime, fuzzy = True)
    except ValueError as e:
        print("Could not extract a date/time from start-time argument:", e)
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

for row in c.execute(sql, replacements):
    devs.append(json.loads(row[0]))

if results.outfile:
    logf = open(results.outfile, "w")
    logf.write(json.dumps(devs, sort_keys = True, indent = 4, separators=(',', ': ')))
else:
    print(json.dumps(devs, sort_keys = True, indent = 4, separators=(',', ': ')))


