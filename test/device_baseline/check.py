#!/usr/bin/env python3
# Helpers for run.sh: read and change a test Kismet's devices and baseline filters.
#
#   check.py URL USER:PASS keys                    MAC=key lines for the test devices
#   check.py URL USER:PASS tag KEY NAME [VALUE]    set (or with no value delete) a tag
#   check.py URL USER:PASS state FILE              compare the devices and filters with
#                                                  FILE's expectations; exit 1 on a mismatch
#
# An expectations file holds one check per line:
#   MAC in|out [by=NAME] [hold=NAME|hold=-] [expired=NAME] [ephemeral]
#   filter NAME FIELD=VALUE ...     rules.json fields without the prefix, such as removed=2
#   saved MAC TAG yes|no            whether the tag is in the device_tags table (needs DB=path)

import base64
import json
import os
import sqlite3
import sys
import urllib.parse
import urllib.request

url, auth, cmd = sys.argv[1], sys.argv[2], sys.argv[3]
hdr = {"Authorization": "Basic " + base64.b64encode(auth.encode()).decode()}


def post(path, obj):
    data = urllib.parse.urlencode({"json": json.dumps(obj)}).encode()
    req = urllib.request.Request(url + path, data=data, headers=hdr)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read()


def get(path):
    req = urllib.request.Request(url + path, headers=hdr)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def devices():
    fields = ["kismet.device.base.key", "kismet.device.base.macaddr", "kismet.device.base.tags",
              "kismet.device.base.ephemeral_tags"]
    out = {}
    for d in json.loads(post("/devices/last-time/0/devices.json", {"fields": fields})):
        tags = d.get("kismet.device.base.tags")
        eph = d.get("kismet.device.base.ephemeral_tags")
        out[d["kismet.device.base.macaddr"].lower()] = {
            "key": d["kismet.device.base.key"],
            "tags": tags if isinstance(tags, dict) else {},
            "ephemeral": eph if isinstance(eph, list) else [],
        }
    return out


if cmd == "keys":
    for m, d in sorted(devices().items()):
        print("%s=%s" % (m, d["key"]))
    sys.exit(0)

if cmd == "tag":
    key, name = sys.argv[4], sys.argv[5]
    path = "/devices/by-key/%s/" % urllib.parse.quote(key)
    if len(sys.argv) > 6:
        post(path + "set_tag.cmd", {"tagname": name, "tagvalue": sys.argv[6]})
    else:
        post(path + "delete_tag.cmd", {"tagname": name})
    sys.exit(0)

devs = devices()
rules = {r["kismet.devicerules.rule.name"]: r for r in get("/devices/rules/rules.json")["kismet.devicerules.rules"]}
db = os.environ.get("DB")
bad = 0


def fail(msg):
    global bad
    bad += 1
    print("    " + msg)


for line in open(sys.argv[4]):
    w = line.split()
    if not w or w[0].startswith("#"):
        continue

    if w[0] == "filter":
        r = rules.get(w[1])
        if r is None:
            fail("no filter %s" % w[1])
            continue
        for kv in w[2:]:
            k, v = kv.split("=")
            got = r.get("kismet.devicerules.rule." + k)
            if str(got) != v:
                fail("filter %s: %s is %s, wanted %s" % (w[1], k, got, v))
        continue

    if w[0] == "saved":
        m, tag, want = w[1].lower(), w[2], w[3] == "yes"
        d = devs.get(m)
        if d is None or db is None:
            fail("saved %s: no device or no DB" % m)
            continue
        with sqlite3.connect("file:%s?mode=ro" % db, uri=True) as c:
            n = c.execute("SELECT COUNT(*) FROM device_tags WHERE key = ? AND tag = ?", (d["key"], tag)).fetchone()[0]
        if (n > 0) != want:
            fail("%s: tag %s %s in the database" % (m, tag, "is" if n else "isn't"))
        continue

    m, want_in = w[0].lower(), w[1] == "in"
    d = devs.get(m)
    if d is None:
        fail("%s: no such device" % m)
        continue
    tags = d["tags"]
    if ("baseline" in tags) != want_in:
        fail("%s: %s the baseline (tags %s)" % (m, "in" if "baseline" in tags else "not in", tags))
    for opt in w[2:]:
        if opt == "ephemeral":
            if "baseline" not in d["ephemeral"]:
                fail("%s: baseline tag isn't ephemeral" % m)
            continue
        k, v = opt.split("=")
        tag = {"by": "baseline-by", "hold": "baseline-hold", "expired": "baseline-expired"}[k]
        got = tags.get(tag, "-")
        if got != v:
            fail("%s: %s is %s, wanted %s" % (m, tag, got, v))

sys.exit(1 if bad else 0)
