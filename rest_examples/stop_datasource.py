#!/usr/bin/env python

import sys, KismetRest
import argparse

uri = "http://localhost:2501"
user = "kismet"
passwd = "kismet"

parser = argparse.ArgumentParser(description='RTL433 to Kismet bridge')

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--user', action="store", dest="user")
parser.add_argument('--passwd', action="store", dest="passwd")
parser.add_argument('--uuid', action="store", dest="uuid")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri
if results.user != None:
    user = results.user
if results.passwd != None:
    passwd = results.passwd
if results.uuid == None:
    print "Requires --uuid option"
    sys.exit(1);

kr = KismetRest.KismetConnector(uri)
kr.set_login(user, passwd)

if not kr.check_session():
    print "Invalid login, specify --user and --password if you have changed your "
    print "default Kismet config (which you should do)"
    sys.exit(1)

(r, v) = kr.get_url("datasource/by-uuid/{}/close_source.cmd".format(results.uuid))

if r:
    print "Source closed successfully: ", v
else:
    print "Error closing source - check Kismet messages"

