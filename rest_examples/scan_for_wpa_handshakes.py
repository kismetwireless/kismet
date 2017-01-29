#!/usr/bin/env python

import sys, KismetRest, time

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

print "Waiting for devices with WPA handshake packets..."

sincets = 0

while 1:

    # Get summary of devices
    devices = kr.device_summary_since(sincets)

    sincets = devices['kismet.devicelist.timestamp']

    # Print the SSID for every device we can.  Stupid print; no comparison
    # of the phy type, no handling empty ssid, etc.
    for d in devices['kismet.device.list']:
        if 'dot11.device' in d:
            if len(d['dot11.device']['dot11.device.wpa_handshake_list']):

                print d['kismet.device.base.macaddr'].split("/")[0],
                print d['dot11.device']['dot11.device.last_beaconed_ssid'],
                print "{} WPA EAPOL packets".format(len(d['dot11.device']['dot11.device.wpa_handshake_list'])),

                if ((d['dot11.device']['dot11.device.wpa_present_handshake'] & 0x06) == 0x06 or
                        (d['dot11.device']['dot11.device.wpa_present_handshake'] & 0x0C) == 0x0C):
                    print "Complete"
                else:
                    print "Incomplete handshake"

    time.sleep(1)
    

