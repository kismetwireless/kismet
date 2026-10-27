#!/usr/bin/env python3
"""
Kismet Bluetooth name database generator

Builds the company identifier and 16-bit UUID name tables from the Bluetooth SIG
assigned numbers repository:

  kismet_bluetooth_manuf.txt.gz   company identifiers (manufacturer data)
  kismet_bluetooth_ids.txt.gz     16-bit UUIDs: services, member and SDO UUIDs,
                                  characteristics, descriptors, protocols, ...

Both are sorted 'XXXX<tab>Name' lines.  Entries of the existing tables which the SIG
no longer lists (withdrawn companies, deprecated characteristics) are kept, since older
devices still send them.  Pass a directory to read already downloaded YAML files from
instead of fetching them.
"""

from __future__ import print_function
import gzip
import os
import re
import sys
import requests

BASE = "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/"

COMPANY_SOURCE = "company_identifiers/company_identifiers.yaml"

# Earlier sources win when a UUID is listed twice
UUID_SOURCES = [
    "uuids/service_uuids.yaml",
    "uuids/member_uuids.yaml",
    "uuids/sdo_uuids.yaml",
    "uuids/service_class.yaml",
    "uuids/protocol_identifiers.yaml",
    "uuids/characteristic_uuids.yaml",
    "uuids/descriptors.yaml",
    "uuids/declarations.yaml",
    "uuids/units.yaml",
    "uuids/browse_group_identifiers.yaml",
    "uuids/object_types.yaml",
    "uuids/mesh_profile_uuids.yaml",
]

headers = {"User-Agent": "kismet-create-bt-db"}

KEY_RE = re.compile(r"^\s*-?\s*(value|uuid)\s*:\s*(0x[0-9A-Fa-f]+)\s*$")
NAME_RE = re.compile(r"^\s*name\s*:\s*(.*?)\s*$")

def unquote(v):
    if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
        return v[1:-1].replace("''", "'")
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v

def clean(name):
    name = re.sub(r"\s+", " ", name).strip()
    return "".join(c for c in name if c.isprintable())

def parse(text):
    """The assigned numbers files are flat lists of value/uuid and name pairs"""
    entries = []
    cur = None
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = KEY_RE.match(line)
        if m:
            cur = int(m.group(2), 16)
            continue
        m = NAME_RE.match(line)
        if m and cur is not None:
            name = clean(unquote(m.group(1)))
            if name and cur <= 0xFFFF:
                entries.append((cur, name))
            cur = None
    return entries

def load(path, local_dir):
    if local_dir is not None:
        with open(os.path.join(local_dir, os.path.basename(path)), encoding="utf-8") as f:
            return f.read()
    r = requests.get(BASE + path, headers=headers, timeout=30)
    r.raise_for_status()
    return r.text

def merge(sources, local_dir):
    merged = {}
    for s in sources:
        entries = parse(load(s, local_dir))
        print(f"  {s}: {len(entries)} entries", file=sys.stderr)
        for k, n in entries:
            merged.setdefault(k, n)
    return merged

def keep_old(fname, table):
    """Names from the existing table for ids the SIG dropped"""
    if not os.path.exists(fname):
        return
    kept = 0
    with gzip.open(fname, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            k, _, n = line.rstrip("\n").partition("\t")
            try:
                k = int(k, 16)
            except ValueError:
                continue
            n = clean(n)
            if n and k <= 0xFFFF and k not in table:
                table[k] = n
                kept += 1
    print(f"  kept {kept} entries from {fname}", file=sys.stderr)

def write(fname, table):
    with gzip.open(fname, "wt", encoding="utf-8") as f:
        for k in sorted(table):
            f.write(f"{k:04X}\t{table[k]}\n")
    print(f"Wrote {len(table)} records to {fname}", file=sys.stderr)

def main():
    local_dir = sys.argv[1] if len(sys.argv) > 1 else None
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "conf"

    print("Company identifiers", file=sys.stderr)
    fname = os.path.join(out_dir, "kismet_bluetooth_manuf.txt.gz")
    table = merge([COMPANY_SOURCE], local_dir)
    keep_old(fname, table)
    write(fname, table)

    print("UUIDs", file=sys.stderr)
    fname = os.path.join(out_dir, "kismet_bluetooth_ids.txt.gz")
    table = merge(UUID_SOURCES, local_dir)
    keep_old(fname, table)
    write(fname, table)

if __name__ == "__main__":
    main()
