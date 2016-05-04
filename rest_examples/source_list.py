#!/usr/bin/env python

import sys, KismetRest, pprint

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

# Get sources
sources = kr.old_sources()
pprint.pprint(sources)



