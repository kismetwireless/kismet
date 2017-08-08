#!/usr/bin/env python
import sys, KismetRest, time

# smart_list_delta
#
# Fetches a list of changed devices since the last request, showing how
# to write an event loop processing Kismet data live.
#
# Uses the smart_summary API and requests only the fields specified.
# This is the most efficient method of getting Kismet data rapidly.

if len(sys.argv) < 2:
    print "Expected server URI"
    sys.exit(1)

# Initialize the Kismet connector
kr = KismetRest.KismetConnector(sys.argv[1])

# Start by fetching all devices
sincets = 0

# Specify the fields we want, demonstrating several methods of specifying
# fields.  Fields can be specified as simple names, paths to nested data
# (nested fields will be returned as the final field in the path),
# fields can be renamed on the fly, and can represent complex nest objects,
# where all fields contained will be returned
fields = [ 
        "kismet.device.base.channel", # Standard channel field
        "unknown_field", # Requesting an unknown field will return a field with 0
        "dot11.device/dot11.device.last_beaconed_ssid", # Complex path specification
        ["kismet.device.base.key", "dev.key"], # Fields may be renamed
        "kismet.device.base.packets.rrd" # Fields can be complex objects
        ];

while 1:
    time.sleep(1)
    
    # Get summary of devices
    devices = kr.smart_summary_since(sincets, fields)

    # Remember the ast timestamp
    sincets = devices['kismet.devicelist.timestamp']
    
    if len(devices['kismet.device.list']) == 0:
        print "No new devices"
        continue
    else:
        print "Devices since {}".format(sincets)
   
    # Print some of the fields we fetched
    for d in devices['kismet.device.list']:
        # We use the name alias we requested
        print "Key {}".format(d['dev.key']),

        # Standard field
        print "Channel {}".format(d['kismet.device.base.channel']),

        # If a field doesn't exist, it will be sent as a 0.
        # For example, if we found a non-802.11 device, it won't have
        # a SSID.
        # We refer to it as the last field in the path we requested.
        if d['dot11.device.last_beaconed_ssid'] == 0:
            print "SSID -no such field-",
        else:
            print "SSID '{}'".format(d['dot11.device.last_beaconed_ssid']),

        # Complex fields return complex objects w/ the nested values
        print "RRD", d['kismet.device.base.packets.rrd']['kismet.common.rrd.minute_vec']


