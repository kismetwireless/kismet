#!/usr/bin/env python3

"""
Very basic introduction to using the KismetRest python library

Queries the status URI for Kismet and prints out some basic information
"""

import sys
import KismetRest
import argparse
import time

uri = "http://localhost:2501"

user = "kismet"
passwd = "kismet"

parser = argparse.ArgumentParser(description='Kismet REST example')

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--user', action="store", dest="user")
parser.add_argument('--pass', action="store", dest="passwd")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri

if results.user != None:
    user = results.user

if results.passwd != None:
    passwd = results.passwd

kr = KismetRest.KismetConnector(uri)
kr.set_login(user, passwd)

print("Defining alert")
kr.define_alert("PYTHONTEST", "An alert generated from a python script based on external conditions")

print("Raising alert")
kr.raise_alert("PYTHONTEST", "This alert was raised from python as an example", channel="6HT40")

