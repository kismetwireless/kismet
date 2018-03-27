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
    mqtt_port         MQTT port (default 1883)
    mqtt_id           MQTT client id (default Kismet)
    mqtt_channel      MQTT channel (default rtl433)

"""

import argparse
import ctypes
from datetime import datetime
import json
import os
import requests
import subprocess
import sys
import threading
import time
import uuid

import KismetExternal
import sdrrtl433_pb2

try:
    import paho.mqtt.client as mqtt
    has_mqtt = True
except ImportError:
    has_mqtt = False

class KismetRtl433(object):
    def __init__(self):
        self.opts = {}

        self.opts['rtlbin'] = 'rtl_433'
        self.opts['channel'] = "433.920MHz"
        self.opts['frequency'] = None
        self.opts['gain'] = None
        self.opts['device'] = None

        self.mqtt_mode = False

        # Thread that runs the RTL popen
        self.rtl_thread = None
        # The popen'd RTL binary
        self.rtl_exec = None

        # Are we killing rtl because we're reconfiguring?
        self.rtl_reconfigure = False

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

    def is_running(self):
        return self.kismet.is_running()

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
            r = subprocess.check_call([self.opts['rtlbin'], "--help"], stdout=FNULL, stderr=FNULL)
        except subprocess.CalledProcessError:
            return True
        except OSError:
            return False

        return True

    def __rtl_thread(self):
        """ Internal thread for running the rtl binary """
        cmd = [ self.opts['rtlbin'], '-F', 'json' ]

        if not self.opts['device'] is None:
            cmd.append('-d')
            cmd.append("{}".format(self.opts['device']))

        if not self.opts['gain'] is None:
            cmd.append('-g')
            cmd.append("{}".format(self.opts['gain']))

        if not self.opts['frequency'] is None:
            cmd.append('-f')
            cmd.append("{}".format(self.opts['frequency']))

        seen_any_valid = False
        failed_once = False

        try:
            FNULL = open(os.devnull, 'w')
            self.rtl_exec = subprocess.Popen(cmd, stderr=FNULL, stdout=subprocess.PIPE)

            while True:
                l = self.rtl_exec.stdout.readline()

                if not self.handle_json(l):
                    raise RuntimeError('could not process response from rtl_433')

                seen_any_valid = True


        except Exception as e:
            # Catch all errors, but don't die if we're reconfiguring rtl; then we need
            # to relaunch the binary
            if not self.rtl_reconfigure:
                self.kismet.send_datasource_error_report(message = "Unable to process output from rtl_433: {}".format(ce))
        finally:
            if not seen_any_valid and not self.rtl_reconfigure:
                self.kismet.send_datasource_error_report(message = "An error occurred in rtl_433 and no valid devices were seen; is your USB device plugged in?  Try running rtl_433 in a terminal and confirm that it can connect to your device.")
                self.kismet.spindown()

            self.rtl_exec.kill()


    def run_rtl433(self):
        if self.rtl_thread != None:
            # Turn on reconfigure mode
            if self.rtl_exec != None:
                self.rtl_reconfigure = True
                self.rtl_exec.kill(9)

            # Let the thread spin down and turn off reconfigure mode
            self.rtl_thread.join()
            self.rtl_reconfigure = False

        self.rtl_thread = threading.Thread(target=self.__rtl_thread)
        self.rtl_thread.daemon = True
        self.rtl_thread.start()

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

    def __get_mqtt_uuid(self, options):
        for k in ["mqtt", "mqtt_port", "mqtt_id", "mqtt_channel"]:
            options.set_default(k, None)

        mqhash = self.kismet.adler32("{}{}{}{}".format(options['mqtt'], options['mqtt_port'], options['mqtt_id'], options['mqtt_channel']))
        mqhex = "0000{:02X}".format(mqhash)

        return self.kismet.make_uuid("kismet_cap_sdr_rtl433", mqhex)

    def __get_rtlsdr_uuid(self, intnum):
        # Get the USB info
        (manuf, product, serial) = self.get_rtl_usb_info(intnum)

        # Hash the slot, manuf, product, and serial, to get a unique ID for the UUID
        devicehash = self.kismet.adler32("{}{}{}{}".format(intnum, manuf, product, serial))
        devicehex = "0000{:02X}".format(devicehash)

        return self.kismet.make_uuid("kismet_cap_sdr_rtl433", devicehex)

    # Implement the probesource callback for the datasource api
    def datasource_probesource(self, source, options):
        ret = {}

        # Does the source look like 'rtl433-XYZ'?
        if not source[:7] == "rtl433-":
            return None

        if source[7:] == "mqtt":
            if not 'mqtt' in options:
                return None
            if not has_mqtt:
                return None

            ret['hardware'] = "MQTT"
            ret['uuid'] = __get_mqtt_uuid(options)
        else:
            try:
                intnum = int(source[7:])
            except ValueError:
                return None

            if intnum >= self.rtl_get_device_count():
                return None

            ret['hardware'] = self.rtl_get_device_name(intnum)
            ret['uuid'] = self.__get_rtlsdr_uuid(intnum)

        ret['channel'] = self.opts['channel']
        ret['channels'] = [self.opts['channel']]
        ret['success'] = True
        return ret

    def datasource_opensource(self, source, options):
        ret = {}

        # Does the source look like 'rtl433-XYZ'?
        if not source[:7] == "rtl433-":
            ret["success"] = False
            ret["message"] = "Could not parse which rtlsdr device to use"
            return ret

        intnum = -1

        if source[7:] == "mqtt":
            if not 'mqtt' in options:
                ret["success"] = False
                ret["message"] = "MQTT requested, but no mqtt=xyz option in source definition"
                return ret
            if not has_mqtt:
                ret["success"] = False
                ret["message"] = "MQTT requested, but the python paho mqtt package is not installed"
                return ret
            
            ret['hardware'] = "MQTT"
            ret['uuid'] = __get_mqtt_uuid(options)

            self.mqtt_mode = True
        else:
            try:
                intnum = int(source[7:])
            except ValueError:
                ret["success"] = False
                ret["message"] = "Could not parse rtl device"
                return ret

            if intnum >= self.rtl_get_device_count():
                ret["success"] = False
                ret["message"] = "Could not find rtl-sdr device {}".format(intnum)
                return ret

            ret['hardware'] = self.rtl_get_device_name(intnum)
            ret['uuid'] = self.__get_rtlsdr_uuid(intnum)

            self.opts['device'] = intnum

            self.mqtt_mode = False

        if self.mqtt_mode:
            # TODO finish mqtt mode
            return

        if not self.check_rtl_bin():
            ret['success'] = False
            ret['message'] = "Could not find rtl_433 binary; make sure you've installed rtl_433, check the Kismet README for more information."
            return

        ret['success'] = True

        self.run_rtl433()

        return ret

    def datasource_configure(self, seqno, config):
        #print config

        return

    def handle_json(self, injson):
        try:
            j = json.loads(injson)
            r = json.dumps(j)

            report = sdrrtl433_pb2.SdrRtl433DataReport()

            dt = datetime.now()
            report.time_sec = int(time.mktime(dt.timetuple()))
            report.time_usec = int(dt.microsecond)

            report.rtljson = r

            self.kismet.write_ext_packet("RTL433DATAREPORT", report)
        except ValueError as e:
            print e
            self.kismet.send_error_report(message = "Could not parse JSON output of rtl_433")
            return False
        except Exception as e:
            print e
            self.kismet.send_error_report(message = "Could not process output of rtl_433")
            return False

        return True


