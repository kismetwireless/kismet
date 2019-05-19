#!/usr/bin/env python2

"""
rtladsb Kismet data source

Supports both local usb rtlsdr devices via the rtladsb binary, remote capture
from a usb rtlsdr, and remote capture from a mqtt stream, if paho mqtt is
installed.

Sources are generated as rtladsb-XYZ when multiple rtl radios are detected.

Accepts standard options:
    channel=freqMHz   (in mhz)
    channel=freqKHz   (in khz)
    channel=freq      (in raw hz to rtladsb)

    channels="a,b,c"  Pass hopping list to rtladsb_bin

Additionally accepts:
    ppm_error         Passed as -p to rtladsb
    gain              Passed as -g to rtladsb

    mqtt              MQTT server
    mqtt_port         MQTT port (default 1883)
    mqtt_channel      MQTT channel (default rtladsb)

"""

import argparse
import csv
import ctypes
from datetime import datetime
import json
import math

try:
    import numpy as np
except ImportError as e:
    raise ImportError("KismetRtladsb requires numpy!")

import os
import pkgutil
import subprocess
import sys
import threading
import time
import uuid

### THE NEXT CODE BLOCK IS FROM THE WORK OF myModeS AVAILABLE AT      ###
###            https://pypi.org/project/pyModeS/                      ###
### IT IS INCLUDED HERE IN THIS VERSION STRIPPED DOWN AND MODIFIED    ###
### DUE TO UPSTEAM CHANGES IN THE ORIGINAL CODEBASE THAT ARENT NEEDED ###
def hex2bin(hexstr):
    """Convert a hexdecimal string to binary string, with zero fillings. """
    num_of_bits = len(hexstr) * 4
    binstr = bin(int(hexstr, 16))[2:].zfill(int(num_of_bits))
    return binstr

def bin2int(binstr):
    """Convert a binary string to integer. """
    return int(binstr, 2)

def hex2int(hexstr):
    """Convert a hexdecimal string to integer. """
    return int(hexstr, 16)

def bin2np(binstr):
    """Convert a binary string to numpy array. """
    return np.array([int(i) for i in binstr])

def np2bin(npbin):
    """Convert a binary numpy array to string. """
    return np.array2string(npbin, separator='')[1:-1]

def df(msg):
    """Decode Downlink Format vaule, bits 1 to 5."""
    msgbin = hex2bin(msg)
    return min( bin2int(msgbin[0:5]) , 24 )

def crc(msg, encode=False):
    """Mode-S Cyclic Redundancy Check
    Detect if bit error occurs in the Mode-S message
    Args:
        msg (string): 28 bytes hexadecimal message string
        encode (bool): True to encode the date only and return the checksum
    Returns:
        string: message checksum, or partity bits (encoder)
    """

    # the polynominal generattor code for CRC [1111111111111010000001001]
    generator = np.array([1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,0,0,0,0,0,0,1,0,0,1])
    ng = len(generator)

    msgnpbin = bin2np(hex2bin(msg))

    if encode:
        msgnpbin[-24:] = [0] * 24

    # loop all bits, except last 24 piraty bits
    for i in range(len(msgnpbin)-24):
        if msgnpbin[i] == 0:
            continue

        # perform XOR, when 1
        msgnpbin[i:i+ng] = np.bitwise_xor(msgnpbin[i:i+ng], generator)

    # last 24 bits
    reminder = np2bin(msgnpbin[-24:])
    return reminder

def icao(msg):
    """Calculate the ICAO address from an Mode-S message
    with DF4, DF5, DF20, DF21
    Args:
        msg (String): 28 bytes hexadecimal message string
    Returns:
        String: ICAO address in 6 bytes hexadecimal string
    """
    DF = df(msg)

    if DF in (11, 17, 18):
        addr = msg[2:8]
    elif DF in (0, 4, 5, 16, 20, 21):
        c0 = bin2int(crc(msg, encode=True))
        c1 = hex2int(msg[-6:])
        addr = '%06X' % (c0 ^ c1)
    else:
        addr = None

    return addr

def typecode(msg):
    """Type code of ADS-B message
    Args:
        msg (string): 28 bytes hexadecimal message string
    Returns:
        int: type code number
    """
    if df(msg) not in (17, 18):
        return None

    msgbin = hex2bin(msg)
    return bin2int(msgbin[32:37])

def data(msg):
    """Return the data frame in the message, bytes 9 to 22"""
    return msg[8:-6]

def airborne_velocity(msg):
    """Calculate the speed, track (or heading), and vertical rate

    Args:
        msg (string): 28 bytes hexadecimal message string

    Returns:
        (int, float, int, string): speed (kt), ground track or heading (degree),
            rate of climb/descend (ft/min), and speed type
            ('GS' for ground speed, 'AS' for airspeed)
    """

    if typecode(msg) != 19:
        raise RuntimeError("%s: Not a airborne velocity message, expecting TC=19" % msg)

    msgbin = hex2bin(msg)

    subtype = bin2int(msgbin[37:40])

    if bin2int(msgbin[46:56]) == 0 or bin2int(msgbin[57:67]) == 0:
        return None

    if subtype in (1, 2):
        v_ew_sign = -1 if int(msgbin[45]) else 1
        v_ew = bin2int(msgbin[46:56]) - 1       # east-west velocity

        v_ns_sign = -1 if int(msgbin[56]) else 1
        v_ns = bin2int(msgbin[57:67]) - 1       # north-south velocity


        v_we = v_ew_sign * v_ew
        v_sn = v_ns_sign * v_ns

        spd = math.sqrt(v_sn*v_sn + v_we*v_we)  # unit in kts

        trk = math.atan2(v_we, v_sn)
        trk = math.degrees(trk)                 # convert to degrees
        trk = trk if trk >= 0 else trk + 360    # no negative val

        tag = 'GS'
        trk_or_hdg = trk

    else:
        hdg = bin2int(msgbin[46:56]) / 1024.0 * 360.0
        spd = bin2int(msgbin[57:67])

        tag = 'AS'
        trk_or_hdg = hdg

    vr_sign = -1 if int(msgbin[68]) else 1
    vr = (bin2int(msgbin[69:78]) - 1) * 64     # vertical rate, fpm
    rocd = vr_sign * vr

    return int(spd), round(trk_or_hdg, 1), int(rocd), tag

def callsign(msg):
    """Aircraft callsign

    Args:
        msg (string): 28 bytes hexadecimal message string

    Returns:
        string: callsign
    """

    if typecode(msg) < 1 or typecode(msg) > 4:
        raise RuntimeError("%s: Not a identification message" % msg)

    chars = '#ABCDEFGHIJKLMNOPQRSTUVWXYZ#####_###############0123456789######'
    msgbin = hex2bin(msg)
    csbin = msgbin[40:96]

    cs = ''
    cs += chars[bin2int(csbin[0:6])]
    cs += chars[bin2int(csbin[6:12])]
    cs += chars[bin2int(csbin[12:18])]
    cs += chars[bin2int(csbin[18:24])]
    cs += chars[bin2int(csbin[24:30])]
    cs += chars[bin2int(csbin[30:36])]
    cs += chars[bin2int(csbin[36:42])]
    cs += chars[bin2int(csbin[42:48])]

    # clean string, remove spaces and marks, if any.
    # cs = cs.replace('_', '')
    cs = cs.replace('#', '')
    return cs

### END BLOCK ###

from . import kismetexternal

try:
    import paho.mqtt.client as mqtt
    has_mqtt = True
except ImportError:
    has_mqtt = False

class KismetRtladsb(object):
    def __init__(self, mqtt = False):
        self.mqtt_mode = mqtt

        self.opts = {}

        self.opts['rtlbin'] = 'rtl_adsb'
        self.opts['channel'] = "1090.000MHz"
        self.opts['gain'] = None
        self.opts['device'] = None

        # Thread that runs the RTL popen
        self.rtl_thread = None
        # The popen'd RTL binary
        self.rtl_exec = None

        # Are we killing rtl because we're reconfiguring?
        self.rtl_reconfigure = False

        # We're usually not remote
        self.proberet = None

        # Do we have librtl?
        self.have_librtl = False

        if not self.mqtt_mode:
            self.driverid = "rtladsb"
            # Use ctypes to load librtlsdr and probe for supported USB devices
            try:
                self.rtllib = ctypes.CDLL("librtlsdr.so.0")

                self.rtl_get_device_count = self.rtllib.rtlsdr_get_device_count
                self.rtl_get_device_name = self.rtllib.rtlsdr_get_device_name
                self.rtl_get_device_name.argtypes = [ctypes.c_int]
                self.rtl_get_device_name.restype = ctypes.c_char_p
                self.rtl_get_usb_strings = self.rtllib.rtlsdr_get_device_usb_strings
                self.rtl_get_usb_strings.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
                self.have_librtl = True
            except OSError:
                self.have_librtl = False
        else:
            self.driverid = "rtladsbmqtt"

        parser = argparse.ArgumentParser(description='RTLadsb to Kismet bridge - Creates a rtladsb data source on a Kismet server and passes JSON-based records from the rtladsb binary',
                epilog='Requires the rtladsb tool (install your distributions package or compile from https://github.com/bemasher/rtladsb)')
        
        parser.add_argument('--in-fd', action="store", type=int, dest="infd")
        parser.add_argument('--out-fd', action="store", type=int, dest="outfd")
        parser.add_argument('--connect', action="store", dest="connect")
        parser.add_argument("--source", action="store", dest="source")
        
        self.config = parser.parse_args()

        if not self.config.connect == None and self.config.source == None:
            print("You must specify a source with --source when connecting to a remote Kismet server")
            sys.exit(0)

        if not self.config.source == None:
            (source, options) = kismetexternal.Datasource.parse_definition(self.config.source)

            if source == None:
                print("Could not parse the --source option; this should be a standard Kismet source definition.")
                sys.exit(0)

            self.proberet = self.datasource_probesource(source, options)

            if self.proberet == None:
                print("Could not configure local source {}, check your source options and config.")
                sys.exit(0)

            if not "success" in self.proberet:
                print("Could not configure local source {}, check your source options and config.")
                if "message" in self.proberet:
                    print(self.proberet["message"])
                sys.exit(0)

            if not self.proberet["success"]:
                print("Could not configure local source {}, check your source options and config.")
                if "message" in self.proberet:
                    print(self.proberet["message"])
                sys.exit(0)

            print("Connecting to remote server {}".format(self.config.connect))

        self.csv_data = pkgutil.get_data('KismetCaptureRtladsb', 'data/aircraft_db.csv')
        self.csv_file = csv.reader(self.csv_data.splitlines(), delimiter=",")
        self.airplanes = []

        for row in self.csv_file:
            self.airplanes.append(row)

        self.kismet = kismetexternal.Datasource(self.config.infd, self.config.outfd, remote = self.config.connect)

        self.kismet.set_configsource_cb(self.datasource_configure)
        self.kismet.set_listinterfaces_cb(self.datasource_listinterfaces)
        self.kismet.set_opensource_cb(self.datasource_opensource)
        self.kismet.set_probesource_cb(self.datasource_probesource)

        # If we're connecting remote, kick a newsource
        if self.proberet:
            print("Registering remote source {} {}".format(self.driverid, self.config.source))
            self.kismet.send_datasource_newsource(self.config.source, self.driverid, self.proberet['uuid'])

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
        cmd = [ self.opts['rtlbin'] ]

        if self.opts['device'] is not None:
            cmd.append('-d')
	    cmd.append("{}".format(self.opts['device']))

        if self.opts['gain'] is not None:
            cmd.append('-g')
	    cmd.append("{}".format(self.opts['gain']))

        seen_any_valid = False
        failed_once = False

        try:
            FNULL = open(os.devnull, 'w')
            self.rtl_exec = subprocess.Popen(cmd, stderr=FNULL, stdout=subprocess.PIPE)

            while True:
		hex_data = self.rtl_exec.stdout.readline().decode('ascii').strip()[1:-1]
		if crc(hex_data) == "000000000000000000000000":
		    for row in self.airplanes:
		        if hex_data[2:8] == row[0]:
			    msg = { "icao": row[0] , "regid": row[1] , "mdl": row[2] , "type": row[3] , "operator": row[4] }
		    if 1 <= typecode(hex_data) <= 4:
			msg = { "icao": hex_data[2:8], "callsign": callsign(hex_data) }
		    if 5 <= typecode(hex_data) <= 8:
			msg = { "icao": hex_data[2:8], "altitude": altitude(hex_data) }
		    if typecode(hex_data) == 19:
			airborneInfo = airborne_velocity(hex_data)
			msg = { "icao": hex_data[2:8], "speed": airborneInfo[0], "heading": airborneInfo[1], "altitude": airborneInfo[2], "GSAS": airborneInfo[3] }
		    l = json.dumps(msg)

                    if not self.handle_json(l):
                        raise RuntimeError('could not process response from rtladsb')

                    seen_any_valid = True


        except Exception as e:
            # Catch all errors, but don't die if we're reconfiguring rtl; then we need
            # to relaunch the binary
            if not self.rtl_reconfigure:
                self.kismet.send_datasource_error_report(message = "Unable to process output from rtladsb: {}".format(e))
        finally:
            if not seen_any_valid and not self.rtl_reconfigure:
                self.kismet.send_datasource_error_report(message = "An error occurred in rtladsb and no valid devices were seen; is your USB device plugged in?  Try running rtladsb in a terminal and confirm that it can connect to your device.")
                self.kismet.spindown()

            self.rtl_exec.kill()


    def run_rtladsb(self):
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

    def __mqtt_thread(self):
        self.mq.loop_forever()

    def run_mqtt(self, options):
        def on_msg(client, user, msg):
            if not self.handle_json(msg.payload):
                raise RuntimeError('could not post data')

        opts = options
        opts.setdefault("mqtt", 'localhost')
        opts.setdefault("mqtt_port", '1883')
        opts.setdefault("mqtt_channel", 'rtladsb')

        self.mq = mqtt.Client()
        self.mq.on_message = on_msg
        self.mq.connect(opts['mqtt'], int(opts['mqtt_port']))
        self.mq.subscribe(opts['mqtt_channel'])

        self.mq_thread = threading.Thread(target=self.__mqtt_thread)
        self.mq_thread.daemon = True
        self.mq_thread.start()


    # Implement the listinterfaces callback for the datasource api;
    def datasource_listinterfaces(self, seqno):
        interfaces = []

        if not self.check_rtl_bin():
            self.kismet.send_datasource_interfaces_report(seqno, interfaces)
            return

        if self.rtllib != None:
            for i in range(0, self.rtl_get_device_count()):
                intf = kismetexternal.datasource_pb2.SubInterface()
                intf.interface = "rtladsb-{}".format(i)
                intf.flags = ""
                intf.hardware = self.rtl_get_device_name(i)
                interfaces.append(intf)

        self.kismet.send_datasource_interfaces_report(seqno, interfaces)

    def __get_mqtt_uuid(self, options):
        opts = options
        opts.setdefault('mqtt', 'localhost')
        opts.setdefault('mqtt_port', '1883')
        opts.setdefault('mqtt_channel', 'kismet')

        mqhash = kismetexternal.Datasource.adler32("{}{}{}".format(opts['mqtt'], opts['mqtt_port'], opts['mqtt_channel']))
        mqhex = "0000{:02X}".format(mqhash)

        return kismetexternal.Datasource.make_uuid("kismet_cap_sdr_rtladsb", mqhex)

    def __get_rtlsdr_uuid(self, intnum):
        # Get the USB info
        (manuf, product, serial) = self.get_rtl_usb_info(intnum)

        # Hash the slot, manuf, product, and serial, to get a unique ID for the UUID
        devicehash = kismetexternal.Datasource.adler32("{}{}{}{}".format(intnum, manuf, product, serial))
        devicehex = "0000{:02X}".format(devicehash)

        return kismetexternal.Datasource.make_uuid("kismet_cap_sdr_rtladsb", devicehex)

    # Implement the probesource callback for the datasource api
    def datasource_probesource(self, source, options):
        ret = {}

        # Does the source look like 'rtladsb-XYZ'?
        if not source[:8] == "rtladsb-":
            return None

        if source[9:] == "mqtt":
            if not 'mqtt' in options:
                return None
            if not has_mqtt:
                return None

            ret['hardware'] = "MQTT"
            if ('uuid' in options):
                ret['uuid'] = options['uuid']
            else:
                ret['uuid'] = self.__get_mqtt_uuid(options)
        else:
            # Do we have librtl?
            if not self.have_librtl:
                return None

            if self.mqtt_mode:
                return None

            if not self.check_rtl_bin():
                return None

            try:
                intnum = int(source[8:])
            except ValueError:
                return None

            if intnum >= self.rtl_get_device_count():
                return None

            ret['hardware'] = self.rtl_get_device_name(intnum)
            if ('uuid' in options):
                ret['uuid'] = options['uuid']
            else:
                ret['uuid'] = self.__get_rtlsdr_uuid(intnum)

        ret['channel'] = self.opts['channel']
        ret['channels'] = [self.opts['channel']]
        ret['success'] = True
        return ret

    def datasource_opensource(self, source, options):
        ret = {}

        # Does the source look like 'rtladsb-XYZ'?
        if not source[:8] == "rtladsb-":
            ret["success"] = False
            ret["message"] = "Could not parse which rtlsdr device to use"
            return ret

        intnum = -1

        if source[8:] == "mqtt":
            if not 'mqtt' in options:
                ret["success"] = False
                ret["message"] = "MQTT requested, but no mqtt=xyz option in source definition"
                return ret
            if not has_mqtt:
                ret["success"] = False
                ret["message"] = "MQTT requested, but the python paho mqtt package is not installed"
                return ret
            
            ret['hardware'] = "MQTT"
            if ('uuid' in options):
                ret['uuid'] = options['uuid']
            else:
                ret['uuid'] = self.__get_mqtt_uuid(options)

            self.mqtt_mode = True
        else:
            if not self.have_librtl:
                ret["success"] = False
                ret["message"] = "could not find librtlsdr, unable to configure rtlsdr interfaces"
                return ret

            try:
                intnum = int(source[8:])
            except ValueError:
                ret["success"] = False
                ret["message"] = "Could not parse rtl device"
                return ret

            if intnum >= self.rtl_get_device_count():
                ret["success"] = False
                ret["message"] = "Could not find rtl-sdr device {}".format(intnum)
                return ret

            if 'channel' in options:
                self.opts['channel'] = options['channel']

            ret['hardware'] = self.rtl_get_device_name(intnum)
            if ('uuid' in options):
                ret['uuid'] = options['uuid']
            else:
                ret['uuid'] = self.__get_rtlsdr_uuid(intnum)

            self.opts['device'] = intnum

            self.mqtt_mode = False

        if not self.mqtt_mode:
            if not self.check_rtl_bin():
               ret['success'] = False
               ret['message'] = "Could not find rtladsb binary; make sure you've installed rtladsb, check the Kismet README for more information."
               return

        ret['success'] = True

        if self.mqtt_mode:
            self.run_mqtt(options)
        else:
            self.run_rtladsb()

        return ret

    def datasource_configure(self, seqno, config):
        #print(config)

        return {"success": True}

    def handle_json(self, injson):
        try:
            j = json.loads(injson)
            r = json.dumps(j)

            report = kismetexternal.datasource_pb2.SubJson()

            dt = datetime.now()
            report.time_sec = int(time.mktime(dt.timetuple()))
            report.time_usec = int(dt.microsecond)

            report.type = "RTLadsb"
            report.json = r

            # print("python sending json report", r);

            self.kismet.send_datasource_data_report(full_json=report)
        except ValueError as e:
            print(e)
            self.kismet.send_datasource_error_report(message = "Could not parse JSON output of rtladsb")
            return False
        except Exception as e:
            print(e)
            self.kismet.send_datasource_error_report(message = "Could not process output of rtladsb")
            return False

        return True


