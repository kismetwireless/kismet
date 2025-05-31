#!/usr/bin/env python3

from __future__ import print_function
import gzip
import time
import sys
import re
import requests

manufs = []

# Original IEEE URI
OUIURI = "http://standards-oui.ieee.org/oui.txt"

if len(sys.argv) < 2:
    print("Expected output file")
    print(f"USAGE: {sys.argv[0]} [output file]")
    sys.exit(1)

for cnt in range(0, 5):
    with requests.get(OUIURI) as r:
        for rl in r.iter_lines():
            ln = rl.decode('UTF-8')
            p = re.compile("([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}) +\(hex\)\t+(.*)")
            m = p.match(ln)

            if m is not None and len(m.groups()) == 2:
                oui = m.group(1).replace("-", ":")
                manufs.append("{}\t{}".format(oui, m.group(2)))

    if len(manufs) != 0:
        break

    print(f"!!! Failed to fetch OUI list ({cnt+1}/5)")
    time.sleep(5)

if len(manufs) == 0:
    print("Failed to fetch OUI list")
    sys.exit(1)

print("Parsed {} manufs".format(len(manufs)), file=sys.stderr)

manufs.sort()

with gzip.open(sys.argv[1], 'wt') as gzf:
    for m in manufs:
        print(m, file=gzf)

