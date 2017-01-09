#!/usr/bin/env python

import sys, KismetRest, subprocess
import argparse
import requests
import paho.mqtt.client as mqtt

def on_msg(client, userkr, msg):
    print "Got data: ", msg.payload
    try:
        print "Post:", userkr.post_url("phy/phyRTL433/post_sensor_json.cmd", { "obj": msg.payload })
    except requests.exceptions.ConnectionError as ce:
        print "Connection error: ce"

parser = argparse.ArgumentParser(description='RTL433 MQTT to Kismet bridge')

uri = "http://localhost:2501"
mqtthost = "localhost"
mqttport = 1883
user = "kismet"
passwd = "kismet"
topic = "raw"

parser.add_argument('--uri', action="store", dest="uri")
parser.add_argument('--mqtt', action="store", dest="mqtthost")
parser.add_argument('--mqtt-port', action="store", dest="mqttport", type=int)
parser.add_argument('--mqtt-topic', action="store", dest="topic")
parser.add_argument('--user', action="store", dest="user")
parser.add_argument('--passwd', action="store", dest="passwd")

results = parser.parse_args()

if results.uri != None:
    uri = results.uri
if results.mqtthost != None:
    mqtthost = results.mqtthost
if results.mqttport != None:
    mqttport = results.mqttport
if results.topic != None:
    topic = results.topic
if results.user != None:
    user = results.user
if results.passwd != None:
    passwd = results.passwd

kr = KismetRest.KismetConnector(uri)

kr.set_login(user, passwd)

if not kr.check_session():
    kr.login()

mq = mqtt.Client("Kismet RTL433")
mq.user_data_set(kr)
mq.on_message = on_msg
mq.connect(mqtthost, mqttport, 60)
mq.subscribe(topic)

while True:
    mq.loop(10)


