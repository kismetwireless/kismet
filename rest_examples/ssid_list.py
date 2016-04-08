#!/usr/bin/env python

import msgpack, urllib, sys

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

try:
    packbin = urllib.urlopen("%s/devices/all_devices.msgpack" % sys.argv[1]).read()
except Exception as e:
    print "Failed to get data from server: ", e
    sys.exit(1)

try:
    summary_data = msgpack.unpackb(packbin)[1]
except:
    print "Something went wrong unpacking the data"
    print "Sorry."
    sys.exit()

for di in summary_data:
    try:
        d = di[1]
    except Exception as e:
        print "Couldn't get device sub-rec:", e

    try:
        if not d['kismet.device.base.phyname'][1] == "IEEE802.11":
            continue
    except:
        print "Could not check phy"
        continue

    try:
        ssidbin = urllib.urlopen("%s/devices/%s.msgpack/dot11.device/dot11.device.last_beaconed_ssid" % (sys.argv[1], d['kismet.device.base.key'][1])).read()
    except Exception as e:
        continue

    try:
        ssid = msgpack.unpackb(ssidbin)[1]
    except Exception as e:
        continue

    if ssid == "":
        ssid = "<unknown>"

    print "MAC", d['kismet.device.base.macaddr'][1][0],
    print "Type", d['kismet.device.base.type'][1],
    print "Channel",d['kismet.device.base.channel'][1],
    print "SSID", ssid


