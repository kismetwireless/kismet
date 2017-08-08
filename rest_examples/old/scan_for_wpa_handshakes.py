#!/usr/bin/env python

import sys, KismetRest, time

# Scan for WPA Handshakes
# A more useful example script that combines the summary API,
# field simplification, regex, and parsing data

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

kr = KismetRest.KismetConnector(sys.argv[1])

print "Looking for devices with WPA handshakes..."

fields = [
        'kismet.device.base.macaddr',
        'dot11.device/dot11.device.last_beaconed_ssid',
        'dot11.device/dot11.device.wpa_present_handshake'
        ]

regex = None

for re in sys.argv[2:]:
    if regex == None:
        regex = []

    regex.append([
        'dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid',
        re
        ])

sincets = 0

while 1:

    # Get summary of devices
    devices = kr.smart_summary_since(sincets, fields, regex)

    sincets = devices['kismet.devicelist.timestamp']

    # Print the SSID for every device we can.  Stupid print; no comparison
    # of the phy type, no handling empty ssid, etc.
    for d in devices['kismet.device.list']:

        if ((d['dot11.device.wpa_present_handshake'] & 0x06) == 0x06 or
                (d['dot11.device.wpa_present_handshake'] & 0x0C) == 0x0C):
            pkts = []
            for i in range(1, 5):
                if d['dot11.device.wpa_present_handshake'] & i:
                    pkts.append(i)

            print d['kismet.device.base.macaddr'].split("/")[0],
            print "'{}'".format(d['dot11.device.last_beaconed_ssid']),
            print "packets {}".format(pkts),
            print "{}/phy/phy80211/handshake/{}/{}-handshake.pcap".format(
                    sys.argv[1], d['kismet.device.base.macaddr'], 
                    d['kismet.device.base.macaddr'])


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
    

