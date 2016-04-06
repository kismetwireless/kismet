#!/usr/bin/env python

import msgpack, urllib, sys, pprint

try:
    packbin = urllib.urlopen("%s/system/status.msgpack" % sys.argv[1]).read()
except IOError:
    print "Could not connect to Kismet server at %s" % sys.argv[1]
    print "Sorry."
    sys.exit()

try:
    system_data = msgpack.unpackb(packbin)[1]
except:
    print "Something went wrong unpacking the data"
    print "Sorry."
    sys.exit()

pprint.pprint(system_data)

