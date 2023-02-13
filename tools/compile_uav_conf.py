#!/usr/bin/env python3

import yaml
import os
import sys

if len(sys.argv) < 1:
    print("Expected source yaml")
    sys.exit(1)

print(sys.argv[1])

with open(sys.argv[1], "r") as stream:
    data_loaded = yaml.load(stream, Loader=yaml.FullLoader)


for e in data_loaded:
    if 'header' in e:
        for l in e['header'].split("\n"):
            print("# {}".format(l))
        print()

    if not 'uav' in e:
        continue

    uav = e['uav']

    if not 'id' in uav:
        print("Expected 'id' in uav block, skipping: ", uav)
        continue

    if not 'name' in uav:
        print("Expected 'name' in uav block, skipping: ", uav)
        continue


    if 'comment' in uav:
        for c in uav['comment'].split('\n'):
            print("# {}".format(c))

    uav["count"] = 1
    confstr = "uav_match={id}"

    if 'mac' in uav and len(uav['mac']) > 1:
        confstr = confstr + "_{count}"
        
    confstr = confstr + ":name=\"{name}\""

    if 'model' in uav:
        confstr = confstr + ",model=\"{model}\""

    if 'ssid' in uav:
        confstr = confstr + ",ssid=\"{ssid}\""

    if 'match_any' in uav:
        confstr = confstr + ",match_any={}"

    if 'mac' in uav:
        confstr = confstr + ",mac={countmac}"
        
        for m in uav['mac']:
            uav['countmac'] = m
            print(confstr.format(**uav))
            uav['count'] = uav['count'] + 1
    else:
        print(confstr.format(**uav))
       
    print()


