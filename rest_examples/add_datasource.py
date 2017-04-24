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
parser.add_argument('--source', action="store", dest="source")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri
if results.user != None:
    user = results.user
if results.passwd != None:
    passwd = results.passwd
if results.source == None:
    print "Requires --source option"
    sys.exit(1);

kr = KismetRest.KismetConnector(uri)
kr.set_login(user, passwd)

if not kr.check_session():
    print "Invalid login, specify --user and --password if you have changed your "
    print "default Kismet config (which you should do)"
    sys.exit(1)

(r, v) = kr.post_url("datasource/add_source.cmd", { "definition": sys.argv[2] })

if r:
    print "Source added successfully"
else:
    print "Error adding source - check Kismet messages"

