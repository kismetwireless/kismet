#!/usr/bin/env python2

"""
rtl_433 Kismet data source

Supports both local usb rtlsdr devices via the rtl_433 binary, remote capture
from a usb rtlsdr, and remote capture from a mqtt stream, if paho mqtt is
installed.

Sources are generated as rtl433-XYZ when multiple rtl radios are detected.

Accepts standard options:
    channel=freqMHz   (in mhz)
    channel=freqKHz   (in khz)
    channel=freq      (in raw hz to rtl_433)

    channels="a,b,c"  Pass hopping list to rtl433_bin

Additionally accepts:
    ppm_error         Passed as -p to rtl_433
    gain              Passed as -g to rtl_433

    mqtt              MQTT server
    mqttport          MQTT port (default 1883)
    mqttid            MQTT client id (default Kismet)
    mqttchannel       MQTT channel (default rtl433)

"""

import argparse
import ctypes
from datetime import datetime
import json
import os
import requests
import subprocess
import sys
import time
import uuid

try:
    import KismetExternal
except ImportError:
    print "Could not import the KismetExternal Python code; you need to install this from "
    print "python_modules/KismetExternal/ in the Kismet source directory!"
    sys.exit(0)

try:
    import paho.mqtt.client as mqtt
    has_mqtt = True
except ImportError:
    has_mqtt = False

class kismet_rtl433(object):
    def __init__(self):
        self.rtlbin = "rtl_433"
        self.default_channel = "433.920MHz"
        self.rtl_exec = None
        self.mqtt_mode = False

        # Use ctypes to load librtlsdr and probe for supported USB devices
        try:
            self.rtllib = ctypes.CDLL("librtlsdr.so.0")

            self.rtl_get_device_count = self.rtllib.rtlsdr_get_device_count
            self.rtl_get_device_name = self.rtllib.rtlsdr_get_device_name
            self.rtl_get_device_name.argtypes = [ctypes.c_int]
            self.rtl_get_device_name.restype = ctypes.c_char_p
            self.rtl_get_usb_strings = self.rtllib.rtlsdr_get_device_usb_strings
            self.rtl_get_usb_strings.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        except OSError:
            print "Unable to find librtlsdr; make sure both librtlsdr and "
            print "rtl_433 are installed."

            self.rtllib = None

        parser = argparse.ArgumentParser(description='RTL433 to Kismet bridge - Creates a rtl433 data source on a Kismet server and passes JSON-based records from the rtl_433 binary',
                epilog='Requires the rtl_433 tool (install your distributions package or compile from https://github.com/merbanan/rtl_433)')
        
        parser.add_argument('--in-fd', action="store", type=int, dest="infd")
        parser.add_argument('--out-fd', action="store", type=int, dest="outfd")

        parser.add_argument('--debug',
                action="store_true",
                dest="debug",
                default=False,
                help="Enable debug mode (print out received messages, etc)")
        
        self.config = parser.parse_args()

        self.kismet = KismetExternal.Datasource(self.config.infd, self.config.outfd)

        self.kismet.set_configsource_cb(self.datasource_configure)
        self.kismet.set_listinterfaces_cb(self.datasource_listinterfaces)
        self.kismet.set_opensource_cb(self.datasource_opensource)
        self.kismet.set_probesource_cb(self.datasource_probesource)

        self.kismet.start()

    def get_uuid(self):
        return self.config.uuid

    def get_rtlbin(self):
        return self.config.rtlbin

    def get_rtl_usb_info(self, index):
        # Allocate memory buffers
        usb_manuf = (ctypes.c_char * 256)()
        usb_product = (ctypes.c_char * 256)()
        usb_serial = (ctypes.c_char * 256)()
       
        # Call the library
        self.rtl_get_usb_strings(index, usb_manuf, usb_product, usb_serial)
       
        # If there's a smarter way to do this, patches welcome
        m = bytearray(usb_manuf)
        p = bytearray(usb_product)
        s = bytearray(usb_serial)

        # Return tuple
        return (m.decode('ascii'), p.decode('ascii'), s.decode('ascii'))

    def check_rtl_bin(self):
        try:
            FNULL = open(os.devnull, 'w')
            r = subprocess.check_call([self.rtlbin, "--help"], stdout=FNULL, stderr=FNULL)
        except subprocess.CalledProcessError:
            return True
        except OSError:
            return False

        return True

    def open_rtl(self):
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

    # Implement the listinterfaces callback for the datasource api;
    def datasource_listinterfaces(self, seqno):
        interfaces = []

        if self.rtllib != None:
            for i in range(0, self.rtl_get_device_count()):
                intf = KismetExternal.datasource_pb2.SubInterface()
                intf.interface = "rtl433-{}".format(i)
                intf.flags = ""
                intf.hardware = self.rtl_get_device_name(i)
                interfaces.append(intf)

        self.kismet.send_datasource_interfaces_report(seqno, interfaces)

    # Implement the probesource callback for the datasource api
    def datasource_probesource(self, seqno, source, options):
        # Does the source look like 'rtl433-XYZ'?
        if not source[:7] == "rtl433-":
            self.kismet.send_datasource_probe_report(seqno, success = False)
            return

        hw = None

        if source[7:] == "mqtt":
            if not 'mqtt' in options:
                self.kismet.send_datasource_probe_report(seqno, success = False)
                return
            if not has_mqtt:
                self.kismet.send_datasource_probe_report(seqno, success = False)
                return

            hw = "MQTT"
        else:
            try:
                intnum = int(source[7:])
            except ValueError:
                self.kismet.send_datasource_probe_report(seqno, success = False)
                return

            if intnum >= self.rtl_get_device_count():
                self.kismet.send_datasource_probe_report(seqno, success = False)
                return

            hw = self.rtl_get_device_name(intnum)

        self.kismet.send_datasource_probe_report(seqno, success = True, hardware = hw, channels = [self.default_channel], channel = self.default_channel)

    def datasource_opensource(self, seqno, source, options):
        # Does the source look like 'rtl433-XYZ'?
        if not source[:7] == "rtl433-":
            self.kismet.send_datasource_open_report(seqno, success = False, message = "Could not determine rtlsdr device to use")
            return

        hw = None
        intnum = -1

        if source[7:] == "mqtt":
            if not 'mqtt' in options:
                self.kismet.send_datasource_open_report(seqno, success = False, message = "rtl433-mqtt device specified, but no mqtt= source option")
                return
            if not has_mqtt:
                self.kismet.send_datasource_open_report(seqno, success = False, message = "rtl433-mqtt device specified, but python paho mqtt package not installed")
                return

            hw = "MQTT"

            self.mqtt_mode = True
        else:
            try:
                intnum = int(source[7:])
            except ValueError:
                self.kismet.send_datasource_open_report(seqno, success = False, message = "Could not determine which rtlsdr device to use")
                return

            if intnum >= self.rtl_get_device_count():
                self.kismet.send_datasource_open_report(seqno, success = False, message = "Could not find a rtlsdr device index {}".format(intnum))
                return

            hw = self.rtl_get_device_name(intnum)

            self.mqtt_mode = False

        if self.mqtt_mode:
            # TODO finish mqtt mode
            return

        if not self.check_rtl_bin():
            self.kismet.send_datasource_open_report(seqno, success = False, message = "Could not find rtl_433; make sure you install the rtl_433 tool, see the Kismet README for more information")
            return

        # Get the USB info
        (manuf, product, serial) = self.get_rtl_usb_info(intnum)

        # Hash the slot, manuf, product, and serial, to get a unique ID for the UUID
        devicehash = self.kismet.adler32("{}{}{}{}".format(intnum, manuf, product, serial))
        devicehex = "0000{:02X}".format(devicehash)

        uuid = self.kismet.make_uuid("kismet_cap_sdr_rtl433", devicehex)

        self.kismet.send_datasource_open_report(seqno, success = True, channels = [self.default_channel], channel = self.default_channel, hardware = hw, uuid = uuid)

    def datasource_configure(self, seqno, packet):
        return


if __name__ == '__main__':
    rtl = kismet_rtl433()

    # Go into sleep mode
    while 1:
        time.sleep(1)

    sys.exit(0)

