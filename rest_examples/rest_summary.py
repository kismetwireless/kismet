#!/usr/bin/env python

import msgpack, urllib, sys, pprint

try:
    packbin = urllib.urlopen('http://localhost:8080/devices/all_devices.msgpack').read()
except IOError:
    print "Could not connect to Kismet server at localhost:8080"
    print "Sorry."
    sys.exit()

try:
    summary_data = msgpack.unpackb(packbin)[1]
except:
    print "Something went wrong unpacking the data"
    print "Sorry."
    sys.exit()

print "Kismet has", len(summary_data), "devices"

for di in summary_data:
    d = di[1]

    print d['kismet.device.base.key'][1],
    print d['kismet.device.base.name'][1],
    print d['kismet.device.base.type'][1],
    print d['kismet.device.base.channel'][1]

    #pprint.pprint(d)

