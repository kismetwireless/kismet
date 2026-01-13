#!/usr/bin/env python3

# Downloads http://registry.faa.gov/database/ReleasableAircraft.zip and extracts it in ram
# to generate the aircraft ICAO database.
#
# Used during Kismet release tagging to generate the aircraft db

import csv
import gzip
import io
import requests
import sys
import time
import zipfile

if len(sys.argv) < 2:
    print("Expected output file")
    print(f"USAGE: {sys.argv[0]} [output file]")
    sys.exit(1)

icaos = []

# Kluge up request lib because the canadian server later in the script has an invalid DH key
requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
except AttributeError:
    pass

acft = {}
mdl = {}
res = {}

# User agent headers; it looks like faa.gov filters robot downloads, which is totally
# fair, but this triggers so rarely I don't actually feel bad.
headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'
        }

for cnt in range(0, 5):
    print("Fetching US ICAO database...")

    # FAA Records Fetch
    with requests.get("http://registry.faa.gov/database/ReleasableAircraft.zip", timeout=30, headers=headers) as response, io.BytesIO() as mem_zf:
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
                        icaos.append("{}\t{}\t{}\t\"{}\"\t\"{}\"\t{}".format(
                            row[33].rstrip().lower(),
                            row[0],
                            mdl[row[2]],
                            acft[row[2]],
                            res[row[0]].rstrip(),
                            row[18]))
                    else:
                        icaos.append("{}\t{}\t{}\t\"{}\"\t\"{}\"\t{}".format(
                            row[33].rstrip().lower(),
                            row[0],
                            mdl[row[2]],
                            acft[row[2]],
                            row[6].rstrip(),
                            row[18]))
                except KeyError:
                    print("Error processing entry, skipping: {}".format(" ".join(row)), file=sys.stderr)
                    pass

    if len(icaos) > 0:
        break

    print(f"!!! Failed to fetch US ICAO list ({cnt+1}/5)")
    time.sleep(5)

if len(icaos) == 0:
    print("ERROR: Failed to fetch US ICAO list")
    sys.exit(1)

old_len = len(icaos)

for cnt in range(0, 5):
    print("Fetching Canadian ICAO database...")

    # Canada Records Fetch
    owner = {}
    with requests.get("https://wwwapps.tc.gc.ca/Saf-Sec-Sur/2/CCARCS-RIACC/download/ccarcsdb.zip", timeout=30, headers=headers) as response, io.BytesIO() as mem_zf:
        # Copy into an in-memory zipfile
        mem_zf.write(response.content)

        # open as a zip
        zipf = zipfile.ZipFile(mem_zf)

        with io.TextIOWrapper(zipf.open('carsownr.txt', 'r'), encoding='iso-8859-1') as ownerfile:
            ownerlist = csv.reader(x.replace('\0', '') for x in ownerfile)
            for row in ownerlist:
                if (row == []):
                    break
                owner[row[0].lstrip()] = row[1]

        with io.TextIOWrapper(zipf.open('carscurr.txt', 'r'), encoding='iso-8859-1') as csvfile:
            airplanes = csv.reader(csvfile, delimiter=',', quotechar='"')

            for row in airplanes:
                if (row == []):
                    break

                type = ""
                if (row[10] == "Aeroplane"):
                    type = "4"
                elif (row[10] == "Balloon"):
                    type = "2"
                elif (row[10] == "Glider"):
                    type = "1"
                elif (row[10] == "Gyroplane"):
                    type = "9"
                elif (row[10] == "Helicopter"):
                    type = "6"
                elif (row[10] == "Ornithopter"):
                    type = "O"

                ownertxt = "UNKNOWN"
                if row[0].lstrip() in owner:
                    ownertxt = owner[row[0].lstrip()]

                icaos.append("{}\tC-{}\t{}\t\"{}\"\t\"{}\"\t{}".format(
                        str(hex(int(row[42], 2)))[2:],
                        row[0].lstrip(),
                        row[4],
                        row[7],
                        ownertxt,
                        type))

    if len(icaos) != old_len:
        break

    print(f"!!! Failed to fetch Canadian ICAO list ({cnt+1}/5)")
    time.sleep(5)

if len(icaos) == old_len:
    print("ERROR: Failed to fetch Canadian ICAO list")
    sys.exit(1)

icaos.sort()

print(f"Processed {len(icaos)} total ICAO records.")

with gzip.open(sys.argv[1], 'wt') as gzf:
    for m in icaos:
        print(m, file=gzf)

