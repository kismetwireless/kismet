#!/usr/bin/env python

import msgpack, urllib, sys, pprint

try:
    packbin = urllib.urlopen('http://localhost:8080/system/status.msgpack').read()
except IOError:
    print "Could not connect to Kismet server at localhost:8080"
    print "Sorry."
    sys.exit()

try:
    system_data = msgpack.unpackb(packbin)[1]
except:
    print "Something went wrong unpacking the data"
    print "Sorry."
    sys.exit()

pprint.pprint(system_data)

