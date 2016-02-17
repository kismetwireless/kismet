#!/usr/bin/env python

import msgpack, urllib, sys, pprint

for x in range(1, 1000):
    try:
        packbin = urllib.urlopen('http://localhost:8080/devices/msgpack/all_devices').read()
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

