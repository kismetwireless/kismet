#!/usr/bin/env python3

from __future__ import print_function
import os
import sys
import re
import requests

manufs = []

# Original IEEE URI
OUIURI = "https://standards-oui.ieee.org/oui.txt"

# Sanitized and cleaned up maintained version
# OUIURI = "http://linuxnet.ca/ieee/oui.txt"

with requests.get(OUIURI) as r:
    for rl in r.iter_lines():
        l = rl.decode('UTF-8')
        p = re.compile("([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}) +\(hex\)\t+(.*)")
        m = p.match(l)

        if m is not None and len(m.groups()) == 2:
            oui = m.group(1).replace("-", ":")
            manufs.append("{}\t{}".format(oui, m.group(2)))

print("Parsed {} manufs".format(len(manufs)), file=sys.stderr)

manufs.sort()

for m in manufs:
    print(m)

