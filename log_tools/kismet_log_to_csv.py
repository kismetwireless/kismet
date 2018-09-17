#!/usr/bin/env python

import argparse
import datetime
import sqlite3
import sys
import csv

try:
    from dateutil import parser as dateparser
except Exception as e:
    print("kismet_log_to_kml requires dateutil; please install it either via your distribution")
    print("(python-dateutil) or via pip (pip install dateutil)")
    sys.exit(1)

parser = argparse.ArgumentParser(description="Kismet to CSV Log Converter")
parser.add_argument("--in", action="store", dest="infile", help='Input (.kismet) file')
parser.add_argument("--out", action="store", dest="outfile", help='Output CSV filename')
parser.add_argument("--table", action="store", dest="srctable", help='Select the table to output')

results = parser.parse_args()
replacements = {}

if results.infile is None:
    print("Expected --in [file]")
    sys.exit(1)



table = ""
if results.srctable is None:
    results.srctable = "devices"
replacements["srctable"] = results.srctable

if results.srctable == "devices":
    replacements["srccolumns"] = "first_time, last_time, devkey, phyname, devmac, strongest_signal, min_lat, min_lon, max_lat, max_lon, avg_lat, avg_lon, bytes_data, type"
elif results.srctable == "packets":
    replacements["srccolumns"] = "ts_sec, ts_usec, phyname, sourcemac, destmac, transmac, frequency, devkey, lat, lon, packet_len, signal, datasource, dlt, error"
elif results.srctable == "datasources":
    replacements["srccolumns"] = "uuid, typestring, definition, name, interface"
elif results.srctable == "alerts":
    replacements["srccolumns"] = "ts_sec, ts_usec, phyname, devmac, lat, lon, header"
else:
    print("Invalid table entered, please retry with either devices, packets, datasources or alerts.")
    sys.exit(1)

if results.outfile is None:
    results.outfile = "{}-{}.csv".format(results.infile, replacements["srctable"])

try:
    db = sqlite3.connect(results.infile)
except Exception as e:
    print("Failed to open kismet logfile: ", e)
    sys.exit(1)

# sql = "SELECT ts_sec, ts_usec, dlt, datasource, packet FROM packets WHERE dlt > 0"
sql = "SELECT {} FROM {}".format(replacements["srccolumns"], replacements["srctable"])

# if select != "":
#     sql = sql + " AND " + select

with open(results.outfile, 'wb') as csvfile:
    csvWriter = csv.writer(csvfile, delimiter='\t')

    c = db.cursor()
    nrows = 0

    for row in c.execute(sql, replacements):
        csvWriter.writerow(row)
        nrows = nrows + 1
        if nrows % 1000 == 0:
            print("Wrote {} rows".format(nrows))
