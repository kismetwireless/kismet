#!/usr/bin/env python

import sys, KismetRest

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

kr.set_debug(True)

kr.set_login("kismet", "kismet")

# Get summary of devices
print "Adding source:", kr.add_old_source(sys.argv[2])

