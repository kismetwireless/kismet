#!/usr/bin/env python

import argparse
from dateutil import parser as dateparser
import datetime
import struct
import sqlite3
import sys

# Write a raw pcap file header
def write_pcap_header(f, dlt):
    hdr = struct.pack('IHHiIII',
            0xa1b2c3d4, # magic
            2, 4, # version
            0, # offset
            0, # sigfigs
            8192, # max packet len
            dlt # packet type
            )

    f.write(hdr)

# Write a specific frame
def write_pcap_packet(f, timeval_s, timeval_us, packet_bytes):
    pkt = struct.pack('IIII',
            timeval_s,
            timeval_us,
            len(packet_bytes),
            len(packet_bytes)
            )
    f.write(pkt)
    f.write(packet_bytes)


parser = argparse.ArgumentParser(description="Kismet to Pcap Log Converter")
parser.add_argument("--in", action="store", dest="infile", help='Input (.kismet) file')
parser.add_argument("--out", action="store", dest="outfile", help='Output filename (when exporting all packets)')
parser.add_argument("--outtitle", action="store", dest="outtitle", help='Output title (when limiting packets per file)')
parser.add_argument('--limit-packets', action="store", dest="limitpackets", help='Generate multiple pcap files, limiting the number of packets per file')
parser.add_argument("--source-uuid", action="append", dest="uuid", help='Limit packets to a specific data source (multiple --source-uuid options will match multiple datasources)')
parser.add_argument("--start-time", action="store", dest="starttime", help='Only convert packets recorded after start-time')
parser.add_argument("--end-time", action="store", dest="endtime", help='Only convert packets recorded before end-time')
parser.add_argument("--silent", action="store", dest="silent", help='Silent operation (no status output)')
parser.add_argument("--min-signal", action="store", dest="minsignal", help='Only convert packets with a signal greater than min-signal')
#parser.add_argument("--device-key", action="append", dest="devicekey", help='Only convert packets which are linked to the specified device key (multiple --device-key options will match multiple devices)')

results = parser.parse_args()

log_to_single = True

if results.infile is None:
    print "Expected --in [file]"
    sys.exit(1)

if results.limitpackets is not None and results.outtitle is None:
    print "Expected --outtitle when using --limit-packets"
    sys.exit(1)
elif results.outfile is None:
    print "Expected --out [file]"
    sys.exit(1)
elif results.limitpackets and results.outtitle:
    print "Limiting to {} packets per file in {}-X.pcap".format(results.limitpackets, results.outtitle)

try:
    db = sqlite3.connect(results.infile)
except Exception as e:
    print "Failed to open kismet logfile: ", e

replacements = {}
select = ""

if results.uuid is not None:
    subsel = ""
    for r in range(len(results.uuid)):
        if r == 0:
            subsel = "(";
        else:
            subsel = subsel +  " OR "
            
        subsel = subsel + "datasource=:uuid{}".format(r)

        replacements["uuid{}".format(r)] = results.uuid[r]

    subsel = "{} )".format(subsel)

    if select == "":
        select = subsel
    else:
        select = select + " AND {}".format(subsel)

epoch = datetime.datetime.utcfromtimestamp(0)

if results.starttime:
    try:
        st = dateparser.parse(results.starttime, fuzzy = True)
    except ValueError as e:
        print "Could not extract a date/time from start-time argument:", e
        sys.exit(0)

    secs = (st - epoch).total_seconds()

    if select == "":
        select = "ts_sec > :tsstart"
    else:
        select = select + " AND ts_sec > :tsstart"

    replacements["tsstart"] = secs

if results.endtime:
    try:
        st = dateparser.parse(results.endtime, fuzzy = True)
    except ValueError as e:
        print "Could not extract a date/time from end-time argument:", e
        sys.exit(0)

    secs = (st - epoch).total_seconds()

    if select == "":
        select = "ts_sec < :tsend"
    else:
        select = select + " AND ts_sec < :tsend"

    replacements["tsend"] = secs

if results.minsignal:
    if select == "":
        select = "signal > :signal"
    else:
        select = select + " AND signal > :signal"

    replacements["signal"] = results.minsignal

sql = "SELECT ts_sec, ts_usec, dlt, datasource, packet FROM packets WHERE dlt > 0"

if select != "":
    sql = sql + " AND " + select

logf = None
lognum = 0

c = db.cursor()

npackets = 0
for row in c.execute(sql, replacements):
    if logf == None:
        if results.silent == None:
            print "Assuming dlt {} for all packets".format(row[2])

        if log_to_single:
            if results.silent == None:
                print "Logging to {}".format(results.outfile)
            logf = open(results.outfile, 'wb')
            write_pcap_header(logf, row[2])
        else:
            if results.silent == None:
                print "Logging to {}-{}.pcap".format(results.outtitle, lognum)
            logf = open("{}-{}.pcap".format(results.outtitle, lognum), 'wb')
            lognum = lognum + 1
            write_pcap_header(logf, row[2])

    write_pcap_packet(logf, row[0], row[1], row[4])
    npackets = npackets + 1

    if not log_to_single:
        if npackets % results.limitpackets == 0:
            logf.close()
            logf = None
    elif results.silent == None:
        if npackets % 1000 == 0:
            print "Converted {} packets...".format(npackets)

if results.silent == None:
    print "Done! Converted {} packets.".format(npackets)

