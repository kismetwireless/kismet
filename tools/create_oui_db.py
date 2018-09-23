#!/usr/bin/env python

from __future__ import print_function
import os
import sys
import re
import requests

manufs = []

with requests.get("http://standards-oui.ieee.org/oui.txt", stream=True) as r:
    for l in r.iter_lines():
        p = re.compile("([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}) +\(hex\)\t+(.*)")
        m = p.match(l)
        
        if m is not None and len(m.groups()) == 2:
            oui = m.group(1).replace("-", ":")
            manufs.append("{}\t{}".format(oui, m.group(2)))

print("Parsed {} manufs".format(len(manufs)), file=sys.stderr)

manufs.sort()

for m in manufs:
    print(m)
    
