#!/usr/bin/env python

import argparse
from datetime import datetime
import json
import os
import requests
import subprocess
import sys
import time
import uuid

try:
    import paho.mqtt.client as mqtt
    has_mqtt = True
    print "MQTT found; enabling MQTT features"
except ImportError:
    print "MQTT not found; to use MQTT features install the Python Paho MQTT library"
    has_mqtt = False

class kismet_rtl433:
    def __init__(self):
        parser = argparse.ArgumentParser(description='RTL433 to Kismet bridge - Creates a rtl433 data source on a Kismet server and passes JSON-based records from the rtl_433 binary',
                epilog='Requires the rtl_433 tool (install your distributions package or compile from https://github.com/merbanan/rtl_433)')
        
        parser.add_argument('--uri', 
                action="store", 
                dest="uri", 
                default="http://localhost:2501",
                help="Kismet REST server to use (default: http://localhost:2501")

        parser.add_argument('--user', 
                action="store", 
                dest="user", 
                default="kismet",
                help="Kismet admin user (default: kismet)")

        parser.add_argument('--password', 
                action="store", 
                dest="password", 
                default="kismet",
                help="Kismet admin password")

        parser.add_argument('--uuid', 
                action="store", 
                dest="uuid",
                help="RTL433 datasource UUID")

        parser.add_argument('--name', 
                action="store", 
                dest="name",
                help="RTL433 datasource name")

        parser.add_argument('--no-reconnect', 
                action="store_false", 
                dest="reconnect", 
                default=True,
                help="Disable re-connection if the rtl_433 binary fails")

        parser.add_argument('--rtl433', 
                action="store", 
                dest="rtlbin", 
                default="rtl_433",
                help="Path to rtl_433 binary (only needed if rtl_433 is not installed in a default system location")

        parser.add_argument('--device', 
                action="store", 
                dest="device",
                help="RTL433 device number (passed as '-d' to rtl_433)")

        parser.add_argument('--gain', 
                action="store", 
                dest="gain",
                help="RTL433 device gain (passed as '-g' to rtl_433)")

        parser.add_argument('--frequency', 
                action="store", 
                dest="frequency",
                help="RTL433 device frequency (passed as '-f' to rtl_433)")

        parser.add_argument('--debug',
                action="store_true",
                dest="debug",
                default=False,
                help="Enable debug mode (print out received messages, etc)")

        if has_mqtt:
            parser.add_argument('--use-mqtt',
                    action="store_true",
                    dest="use_mqtt",
                    default=False,
                    help="Connect to a MQTT channel instead of a physical device")

            parser.add_argument('--mqtt-server',
                    action="store",
                    dest="mqtt_server",
                    help="MQTT server (if in MQTT mode)",
                    default="localhost")

            parser.add_argument('--mqtt-port',
                    action="store",
                    dest="mqtt_port",
                    help="MQTT port (if in MQTT mode)",
                    default="1883")

            parser.add_argument('--mqtt-client-id',
                    action="store",
                    dest="mqtt_client",
                    help="MQTT client name (if in MQTT mode)",
                    default="kismet")

            parser.add_argument('--mqtt-channel',
                    action="store",
                    dest="mqtt_channel",
                    help="MQTT channel to subscribe to (if in MQTT mode)",
                    default="rtl433")
        
        self.config = parser.parse_args()
        
        if not self.config.uuid is None:
            try:
                u = uuid.UUID(self.config.uuid)
                self.config.uuid = u
            except ValueError:
                print "Expected UUID string 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'"
                sys.exit(1)

        self.session = requests.Session()
        self.session.auth = (self.config.user, self.config.password)

    def get_uuid(self):
        return self.config.uuid

    def get_rtlbin(self):
        return self.config.rtlbin

    def get_mqtt(self):
        if not has_mqtt:
            return False
        return self.config.use_mqtt

    def check_login(self):
        try:
            r = self.session.get("{}/session/check_session".format(self.config.uri))
        except requests.exceptions.ConnectionError:
            return False

        if not r.status_code == 200:
            raise RuntimeError("Invalid username/password")

        return True

    def find_datasource(self):
        try:
            r = self.session.get("{}/datasource/all_sources.json".format(self.config.uri))
        except requests.exceptions.ConnectionError:
            return None

        if not r.status_code == 200:
            return None

        sources = json.loads(r.content)

        for s in sources:
            if s['kismet.datasource.type_driver']['kismet.datasource.driver.type'] == 'rtl433':
                return s

        return None

    def check_datasource(self):
        try:
            r = self.session.get("{}/datasource/by-uuid/{}/source.json".format(self.config.uri, self.config.uuid))
        except requests.exceptions.ConnectionError:
            return False

        if not r.status_code == 200:
            return False

        return True

    def create_datasource(self):
        datasource = "rtl433:type=rtl433"

        if not self.config.uuid is None:
            datasource = "{},uuid={}".format(datasource, self.config.uuid)

        if not self.config.name is None:
            datasource = "{},name={}".format(datasource, self.config.name)

        if not self.config.device is None:
            datasource = "{},device={}".format(datasource, self.config.device)

        cmd = {
            "definition": datasource
        }

        pd = {
            "json": json.dumps(cmd)
        }

        try:
            r = self.session.post("{}/datasource/add_source.json".format(self.config.uri), data=pd)
        except requests.exceptions.ConnectionError:
            return False

        if not r.status_code == 200:
            return False

        devobj = json.loads(r.content)

        self.config.uuid = devobj['kismet.datasource.uuid']

        return True

    def has_alert(self):
        try:
            r = self.session.get("{}/alerts/definitions.json".format(self.config.uri))
        except requests.exceptions.ConnectionError:
            return False

        if not r.status_code == 200:
            return False

        alerts = json.loads(r.content)

        for a in alerts:
            if a['kismet.alert.definition.header'] == "RTL433DCON":
                return True

        return False

    def create_alert(self):
        cmd = {
            "name": "RTL433DCON",
            "description": "rtl433 binary has encountered an error",
            "phyname": "RTL433",
            "throttle": "1/sec",
            "burst": "1/sec"
        }

        pd = {
            "json": json.dumps(cmd)
        }

        try:
            r = self.session.post("{}/alerts/definitions/define_alert.json".format(self.config.uri), data=pd)
        except requests.exceptions.ConnectionError:
            return False

        if not r.status_code == 200:
            return False

        return True

    def check_rtl_bin(self):
        try:
            FNULL = open(os.devnull, 'w')
            r = subprocess.check_call([self.config.rtlbin, "--help"], stdout=FNULL, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            return True
        except OSError:
            return False

        return True

    def prep_kismet(self):
        rtl.check_login()

        if not rtl.has_alert():
            rtl.create_alert()
            if self.config.debug:
                print "{} - Defined Kismet alert for RTL errors".format(time.ctime())
        elif self.config.debug:
            print "{} - Kismet RTL alert already defined".format(time.ctime())
   
        d_created = False
        d_present = rtl.check_datasource()
        
        if d_present and self.config.debug:
            print "{} - Kismet RTL datasource '{}' present".format(time.ctime(), self.config.uuid)

        if d_present:
            d_created = True
        else:
            d_created = rtl.create_datasource()

            if not d_created:
                print "ERROR - Could not create rtl433 data source"
                return False
           
        if self.config.debug:
            print "{} - Connected to rtl433 data source {}".format(time.ctime(), self.get_uuid())

        return True

    def handle_json(self, j):
        now = datetime.now()

        pd = {
            "meta": json.dumps({
                "tv_sec": now.second,
                "tv_usec": now.microsecond
            }),
            "device": j
        }

        if self.config.debug:
            print "{} - {}".format(time.ctime(), j)

        try:
            r = self.session.post("{}/datasource/by-uuid/{}/update.json".format(self.config.uri, self.config.uuid), data=pd)
        except requests.exceptions.ConnectionError:
            return False

        if not r.status_code == 200:
            return False

        return True

    def run_rtl(self):
        cmd = [ self.config.rtlbin, '-F', 'json' ]

        if not self.config.device is None:
            cmd.append('-d')
            cmd.append(self.config.device)

        if not self.config.gain is None:
            cmd.append('-g')
            cmd.append(self.config.gain)

        if not self.config.frequency is None:
            cmd.append('-f')
            cmd.append(self.config.frequency)

        seen_any_valid = False

        try:
            FNULL = open(os.devnull, 'w')
            r = subprocess.Popen(cmd, stderr=FNULL, stdout=subprocess.PIPE)

            while True:
                l = r.stdout.readline()
                if len(l) < 5:
                    raise RuntimeError('empty/junk rtl_433 response')

                seen_any_valid = True

                if not self.handle_json(l):
                    raise RuntimeError('could not post data')

        except subprocess.CalledProcessError as ce:
            if self.config.debug:
                print "{} - processing rtl_433 stopped unexpectedly: {}".format(time.ctime(), ce)
        except Exception as e:
            if self.config.debug:
                print "{} - processing rtl_433 stopped unexpectedly: {}".format(time.ctime(), ce)
        finally:
            if not seen_any_valid:
                print "WARNING:  No valid information seen from rtl_433; is your USB device plugged in?  Try running rtl_433 in a terminal and confirm that it can connect to your rtlsdr USB device."

            r.kill()

    def rtl_loop(self):
        while True:
            if self.prep_kismet():
                self.run_rtl()
            
            if not self.config.reconnect:
                break

            time.sleep(1)

    # mqtt helper func, call the handle_json function in our class
    @staticmethod
    def mqtt_on_message(client, user, msg):
        if not user.handle_json(msg.payload):
            raise RuntimeError('could not post data')

    def run_mqtt(self):
        if self.config.debug:
            print "{} - Connecting to MQTT {}:{} @{}".format(time.ctime(), self.config.mqtt_server, self.config.mqtt_port, self.config.mqtt_channel)

        self.mq = mqtt.Client(self.config.mqtt_client)
        self.mq.user_data_set(self)
        self.mq.on_message = kismet_rtl433.mqtt_on_message
        self.mq.connect(self.config.mqtt_server, self.config.mqtt_port, 60)
        self.mq.subscribe(self.config.mqtt_channel)

        if self.config.debug:
            print "{} - Entering MQTT loop".format(time.ctime());

        try:
            self.mq.loop_forever()
        except Exception as e:
            if self.config.debug:
                print "{} - Error processing MQTT data {}".format(time.ctime(), e)
        finally:
            self.mq.loop_stop()

    def mqtt_loop(self):
        while True:
            if self.prep_kismet():
                self.run_mqtt()
            
            if not self.config.reconnect:
                break

            time.sleep(1)

if __name__ == '__main__':
    rtl = kismet_rtl433()

    if rtl.get_mqtt():
        print "Going into MQTT mode"

        rtl.mqtt_loop()

    else:
        if not rtl.check_rtl_bin():
            print "Could not find rtl_433 binary '{}': Check that you installed rtl_433 or use --rtl433 to set it".format(rtl.get_rtlbin())
            sys.exit(1)

        rtl.rtl_loop()
