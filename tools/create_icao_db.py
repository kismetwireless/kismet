#!/usr/bin/env python3

# Downloads http://registry.faa.gov/database/ReleasableAircraft.zip and extracts it in ram
# to generate the aircraft ICAO database.
# 
# Used during Kismet release tagging to generate the aircraft db

import csv
import requests
import urllib3
import io
import zipfile

import os
import sys

# Kluge up request lib because the canadian server later in the script has an invalid DH key
requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
except AttributeError:
    pass

acft={}
mdl={}
res={}

#FAA Records Fetch
with requests.get("http://registry.faa.gov/database/ReleasableAircraft.zip") as response, io.BytesIO() as mem_zf:
    # Copy into an in-memory zipfile
    mem_zf.write(response.content)

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
            num_rows = num_rows + 1

            # ICAO, CALL, TYPE, MODEL, OWNER, ATYPE
            try:
                if row[0] in res.keys():
                    print("{}\t{}\t{}\t\"{}\"\t\"{}\"\t{}".format(
                        row[33].rstrip().lower(),
                        row[0],
                        mdl[row[2]],
                        acft[row[2]],
                        res[row[0]].rstrip(),
                        row[18]))
                else:
                    print("{}\t{}\t{}\t\"{}\"\t\"{}\"\t{}".format(
                        row[33].rstrip().lower(),
                        row[0],
                        mdl[row[2]],
                        acft[row[2]],
                        row[6].rstrip(),
                        row[18]))
            except KeyError as ke:
                print("Error processing entry, skipping: {}".format(" ".join(row)), file=sys.stderr)
                pass

#Canada Records Fetch 
owner={}
with requests.get("https://wwwapps.tc.gc.ca/Saf-Sec-Sur/2/CCARCS-RIACC/download/ccarcsdb.zip") as response, io.BytesIO() as mem_zf:
    # Copy into an in-memory zipfile
    mem_zf.write(response.content)

    # open as a zip
    zipf = zipfile.ZipFile(mem_zf)

    with io.TextIOWrapper(zipf.open('carsownr.txt', 'r'), encoding='iso-8859-1') as ownerfile:
        ownerlist = csv.reader(x.replace('\0','') for x in ownerfile)
        for row in ownerlist:
            if (row == []):
                break
            owner[row[0].lstrip()] = row[1]

    with io.TextIOWrapper(zipf.open('carscurr.txt', 'r'), encoding='iso-8859-1') as csvfile:
        airplanes = csv.reader(csvfile, delimiter=',', quotechar='"')

        for row in airplanes:
            if(row == []):
              break

            type=""
            if (row[10] == "Aeroplane"):
                type="4"
            elif (row[10] == "Balloon"):
                type="2"
            elif (row[10] == "Glider"):
                type="1"
            elif (row[10] == "Gyroplane"):
                type="9"
            elif (row[10] == "Helicopter"):
                type="6"
            elif (row[10] == "Ornithopter"):
                type="O"

            print("{}\tC-{}\t{}\t\"{}\"\t\"{}\"\t{}".format(
                    str(hex(int(row[42],2)))[2:],
                    row[0].lstrip(),
                    row[4],
                    row[7],
                    owner[row[0].lstrip()],
                    type))

