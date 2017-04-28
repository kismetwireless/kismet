#!/usr/bin/env python

import sys, KismetRest
import argparse

uri = "http://localhost:2501"
user = "kismet"
passwd = "kismet"

parser = argparse.ArgumentParser(description='Kismet Interface Channel Control')

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--user', action="store", dest="user")
parser.add_argument('--passwd', action="store", dest="passwd")
parser.add_argument('--uuid', action="store", dest="uuid")
parser.add_argument('--channel', action="store", dest="channel")
parser.add_argument('--channels', action="store", dest="channels")
parser.add_argument('--rate', action="store", dest="rate")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri
if results.user != None:
    user = results.user
if results.passwd != None:
    passwd = results.passwd
if results.uuid == None:
    print "Requires --uuid option"
    sys.exit(1)

if results.channels == None and results.channel == None:
    print "Requires either --channel or --channels"
    sys.exit(1)

if (results.channels == None and results.rate == None):
    print "Setting --rate requires --channels"
    sys.exit(1)

kr = KismetRest.KismetConnector(uri)
kr.set_login(user, passwd)
kr.set_debug(1)

if not kr.check_session():
    print "Invalid login, specify --user and --password if you have changed your "
    print "default Kismet config (which you should do)"
    sys.exit(1)

cmd = {}

if not results.channel == None:
    cmd["channel"] = results.channel
else:
    cmd["channels"] = results.channels.split(",")

    if not results.rate == None:
        cmd["rate"] = results.rate

(r, v) = kr.post_msgpack_url("datasource/by-uuid/{}/set_channel.cmd".format(results.uuid), cmd)

if r:
    print "Source set successfully: ", v
else:
    print "Error setting source - check Kismet messages - ", v

