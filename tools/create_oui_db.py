#!/usr/bin/env python3
"""
Kismet OUI Database Generator
Fetches from multiple sources and merges into a single sorted database.

Sources:
- IEEE MA-L, MA-M, MA-S, IAB, CID (official registries)
- Wireshark manufacturer database
- Nmap MAC prefixes
"""

from __future__ import print_function
import gzip
import time
import sys
import re
import requests

# Data sources
SOURCES = {
    "IEEE_MAL": "https://standards-oui.ieee.org/oui/oui.txt",
    "IEEE_MAM": "https://standards-oui.ieee.org/oui28/mam.txt",
    "IEEE_MAS": "https://standards-oui.ieee.org/oui36/oui36.txt",
    "IEEE_IAB": "https://standards-oui.ieee.org/iab/iab.txt",
    "IEEE_CID": "https://standards-oui.ieee.org/cid/cid.txt",
    "WIRESHARK": "https://www.wireshark.org/download/automated/data/manuf",
    "NMAP": "https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes",
}

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"}

def fetch_ieee(url, name):
    """Parse IEEE format: XX-XX-XX (hex) Manufacturer"""
    manufs = {}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        for line in r.text.splitlines():
            m = re.match(r"([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)", line)
            if m:
                oui = m.group(1).replace("-", ":").upper()
                if oui not in manufs:
                    manufs[oui] = m.group(2).strip()
        print(f"  {name}: {len(manufs)} entries", file=sys.stderr)
    except Exception as e:
        print(f"  {name}: FAILED ({e})", file=sys.stderr)
    return manufs

def fetch_wireshark(url):
    """Parse Wireshark format: XX:XX:XX ShortName LongName"""
    manufs = {}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        for line in r.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("	")
            if len(parts) >= 2:
                oui = parts[0].upper().strip()
                if len(oui) == 8 and ":" in oui:  # XX:XX:XX format
                    name = parts[2] if len(parts) > 2 else parts[1]
                    if oui not in manufs:
                        manufs[oui] = name.strip()
        print(f"  Wireshark: {len(manufs)} entries", file=sys.stderr)
    except Exception as e:
        print(f"  Wireshark: FAILED ({e})", file=sys.stderr)
    return manufs

def fetch_nmap(url):
    """Parse Nmap format: XXXXXX Manufacturer"""
    manufs = {}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        for line in r.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(" ", 1)
            if len(parts) == 2 and len(parts[0]) == 6:
                oui = f"{parts[0][0:2]}:{parts[0][2:4]}:{parts[0][4:6]}".upper()
                if oui not in manufs:
                    manufs[oui] = parts[1].strip()
        print(f"  Nmap: {len(manufs)} entries", file=sys.stderr)
    except Exception as e:
        print(f"  Nmap: FAILED ({e})", file=sys.stderr)
    return manufs

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Expected output file")
        print(f"USAGE: {sys.argv[0]} [output file]")
        sys.exit(1)

    print("Fetching OUI databases...", file=sys.stderr)

    # Collect from all sources (IEEE takes priority for conflicts)
    all_manufs = {}

    # IEEE sources (highest priority)
    for name, url in SOURCES.items():
        if name.startswith("IEEE"):
            all_manufs.update(fetch_ieee(url, name))

    # Community sources (fill gaps only)
    wireshark = fetch_wireshark(SOURCES["WIRESHARK"])
    for oui, manuf in wireshark.items():
        if oui not in all_manufs:
            all_manufs[oui] = manuf

    nmap = fetch_nmap(SOURCES["NMAP"])
    for oui, manuf in nmap.items():
        if oui not in all_manufs:
            all_manufs[oui] = manuf

    if len(all_manufs) == 0:
        print("Failed to fetch any OUI data", file=sys.stderr)
        sys.exit(1)

    # Sort and write
    sorted_manufs = sorted(all_manufs.items())

    print(f"Total unique OUIs: {len(sorted_manufs)}", file=sys.stderr)

    with gzip.open(sys.argv[1], "wt") as gzf:
        for oui, manuf in sorted_manufs:
            print(f"{oui}\t{manuf}", file=gzf)

    print(f"Written to {sys.argv[1]}", file=sys.stderr)
