#!/usr/bin/env python3

# Downloads http://registry.faa.gov/database/ReleasableAircraft.zip and extracts it in ram
# to generate the aircraft ICAO database.
# 
# Primarily used to during kismet release tagging to generate the aircraft db

import csv
import urllib.request
import io
import zipfile

import os
import sys

acft={}
mdl={}
res={}

print("CSV: Fetching zip...");

with urllib.request.urlopen("http://registry.faa.gov/database/ReleasableAircraft.zip") as response, io.BytesIO() as mem_zf, open("KismetCaptureRtladsb/data/aircraft_db.csv", 'w') as outf:
    # Copy into an in-memory zipfile
    data = response.read()
    mem_zf.write(data)

    print("CSV: Opening as zip...")

    # open as a zip
    zipf = zipfile.ZipFile(mem_zf)

    with io.TextIOWrapper(zipf.open('RESERVED.txt', 'r')) as csvfile:
        reserved = csv.reader(csvfile, delimiter=',', quotechar='"')
        next(reserved, None)
        for row in reserved:
            res[row[0]] = row[1]

    with io.TextIOWrapper(zipf.open('ACFTREF.txt', 'r')) as csvfile:
        aircraft = csv.reader(csvfile, delimiter=',', quotechar='"')
        next(aircraft, None)

        for row in aircraft:
            acft[row[0]] = row[1].rstrip() + " " + row[2].rstrip()
            mdl[row[0]] = '"' + row[2].rstrip() + '"'

    num_rows = 0

    with io.TextIOWrapper(zipf.open('MASTER.txt', 'r')) as csvfile:
        airplanes = csv.reader(csvfile, delimiter=',', quotechar='"')
        next(airplanes, None)

        for row in airplanes:
            if row[0] in res.keys():
                outf.write(row[33].rstrip().lower()+','+row[0]+','+mdl[row[2]]+',"' + acft[row[2]] + '","' +res[row[0]].rstrip()+'"' + ','+row[18] +'\n')
            else:
                outf.write(row[33].rstrip().lower()+','+row[0]+','+mdl[row[2]]+',"' + acft[row[2]] + '","' +row[6].rstrip()+'"' + ','+row[18] + '\n')

    print("CSV: Generated!  Added {} rows.".format(num_rows));

