#!/usr/bin/env python

import sys, KismetRest, subprocess
import argparse

uri = "http://localhost:2501"
user = "kismet"
passwd = "kismet"

parser = argparse.ArgumentParser(description='RTL433 to Kismet bridge')

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--user', action="store", dest="user")
parser.add_argument('--passwd', action="store", dest="passwd")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri
if results.user != None:
    user = results.user
if results.passwd != None:
    passwd = results.passwd

kr = KismetRest.KismetConnector(uri)
kr.set_login(user, passwd)

rtl = subprocess.Popen(["rtl_433", "-F", "json"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

if not kr.check_session():
    kr.login()

while True:
    l = rtl.stdout.readline()
    print "Got data: ", l
    print "Post:", kr.post_url("phy/phyRTL433/post_sensor_json.cmd", { "obj": l })

