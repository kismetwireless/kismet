#!/usr/bin/env python3

import sys, KismetRest
import argparse

uri = "http://localhost:2501"
user = "kismet"
passwd = "kismet"

parser = argparse.ArgumentParser(description='RTL433 to Kismet bridge')

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--user', action="store", dest="user")
parser.add_argument('--passwd', action="store", dest="passwd")
parser.add_argument('--source', action="store", dest="source")
parser.add_argument('--list-available', action="store_true", dest="list_available")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri
if results.user != None:
    user = results.user
if results.passwd != None:
    passwd = results.passwd
if results.source == None and not results.list_available:
    print("Requires --source option")
    sys.exit(1);

kr = KismetRest.KismetConnector(uri)
kr.set_login(user, passwd)
kr.set_debug(True)

if results.list_available:
    interfaces = kr.datasource_list_interfaces()
    for interface in interfaces:
        if interface['kismet.datasource.probed.in_use_uuid'] == '00000000-0000-0000-0000-000000000000':
            in_use = False
        else:
            in_use = True
        print("%s (%s, %s) - %sin use" % (
            interface['kismet.datasource.probed.interface'],
            interface['kismet.datasource.probed.hardware'],
            interface['kismet.datasource.type_driver']['kismet.datasource.driver.type'],
            "not " if not in_use else ''
        ))
    sys.exit()

if not kr.check_session():
    print("Invalid login, specify --user and --password if you have changed your ")
    print("default Kismet config (which you should do)")
    sys.exit(1)

print("adding src ", results.source)
r = kr.add_datasource(results.source)

if r:
    print("Source added successfully")
else:
    print("Error adding source - check Kismet messages")

