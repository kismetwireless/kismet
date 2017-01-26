#!/usr/bin/env python

import sys, KismetRest, time

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

sincets = 0

while 1:

    # Get summary of devices
    devices = kr.device_summary_since(sincets)

    sincets = devices['kismet.devicelist.timestamp']
    
    if len(devices['kismet.device.list']) == 0:
        print "No new devices"
    else:
        print "Devices since {}".format(sincets)
    
    # Print the SSID for every device we can.  Stupid print; no comparison
    # of the phy type, no handling empty ssid, etc.
    for d in devices['kismet.device.list']:
        print "MAC", d['kismet.device.base.macaddr'],
        print "Type", d['kismet.device.base.type'],
        print "Channel",d['kismet.device.base.channel']

    time.sleep(1)
    

