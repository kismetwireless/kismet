#!/usr/bin/env python

import KismetRest, pprint

kr = KismetRest.Kismet('http://localhost:2501')

status = kr.SystemStatus()

pprint.pprint(status)


