"""
rtladsb Kismet data source

Sources are generated as rtladsb-XYZ when multiple rtl radios are detected.

Accepts standard options:
    channel=freqMHz   (in mhz)
    channel=freqKHz   (in khz)
    channel=freq      (in raw hz to rtladsb)

    channels="a,b,c"  Pass hopping list to rtladsb_bin

Additionally accepts:
    ppm_error         Passed as -p to rtladsb
    gain              Passed as -g to rtladsb

"""

from __future__ import print_function

import asyncio
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

from . import kismetexternal

# ADSB parsing functions ported fromthe dump1090 C implementation, MIT licensed
def adsb_crc(data, bits):
    """
    Compute the checksum a message *should* have

    data - bytearray 
    bits - number of bits in message

    return - 24-bit checksum
    """
    modes_checksum_table = [
            0x3935ea, 0x1c9af5, 0xf1b77e, 0x78dbbf, 0xc397db, 0x9e31e9, 
            0xb0e2f0, 0x587178, 0x2c38bc, 0x161c5e, 0x0b0e2f, 0xfa7d13, 
            0x82c48d, 0xbe9842, 0x5f4c21, 0xd05c14, 0x682e0a, 0x341705, 
            0xe5f186, 0x72f8c3, 0xc68665, 0x9cb936, 0x4e5c9b, 0xd8d449,
            0x939020, 0x49c810, 0x24e408, 0x127204, 0x093902, 0x049c81, 
            0xfdb444, 0x7eda22, 0x3f6d11, 0xe04c8c, 0x702646, 0x381323, 
            0xe3f395, 0x8e03ce, 0x4701e7, 0xdc7af7, 0x91c77f, 0xb719bb, 
            0xa476d9, 0xadc168, 0x56e0b4, 0x2b705a, 0x15b82d, 0xf52612,
            0x7a9309, 0xc2b380, 0x6159c0, 0x30ace0, 0x185670, 0x0c2b38, 
            0x06159c, 0x030ace, 0x018567, 0xff38b7, 0x80665f, 0xbfc92b, 
            0xa01e91, 0xaff54c, 0x57faa6, 0x2bfd53, 0xea04ad, 0x8af852, 
            0x457c29, 0xdd4410, 0x6ea208, 0x375104, 0x1ba882, 0x0dd441,
            0xf91024, 0x7c8812, 0x3e4409, 0xe0d800, 0x706c00, 0x383600, 
            0x1c1b00, 0x0e0d80, 0x0706c0, 0x038360, 0x01c1b0, 0x00e0d8, 
            0x00706c, 0x003836, 0x001c1b, 0xfff409, 0x000000, 0x000000, 
            0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000,
            0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 
            0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 
            0x000000, 0x000000, 0x000000, 0x000000 ]

    crc = 0
    offset = 0

    if bits != 112:
        offset = 112 - 56

    for j in range(0, bits):
        byte = int(j / 8)
        bit = j % 8
        bitmask = 1 << (7 - bit)

        if data[byte] & bitmask:
            crc ^= modes_checksum_table[j + offset]

    return crc & 0x00FFFFFF

def adsb_len_by_type(type):
    """
    Get expected length of message in bits based on the type
    """

    if type == 16 or type == 17 or type == 19 or type == 20 or type == 21:
        return 112

    return 56

def adsb_msg_get_crc(data, bits):
    """
    Extract the crc encoded in a message

    data - bytearray of message input
    bits - number of bits in message

    return - 24bit checksum as encoded in message
    """

    crc = (data[int(bits / 8) - 3] << 16)
    crc |= (data[int(bits / 8) - 2] << 8) 
    crc |= (data[int(bits / 8) - 1])

    return crc

def adsb_msg_fix_single_bit(data, bits):
    """
    Try to fix single bit errors using the checksum.  On success
    returns modified bytearray

    data - bytearray of message input
    bits - length in bits
    """

    for j in range(0, bits):
        byte = int(j / 8)
        bitmask = 1 << (7 - (j % 8))

        aux = data[:]

        # Flip the j-th bit
        aux[byte] ^= bitmask

        crc1 = (aux[int(bits / 8) - 3] << 16)
        crc1 |= (aux[int(bits / 8) - 2] << 8) 
        crc1 |= (aux[int(bits / 8) - 1])

        crc2 = adsb_crc(aux, bits)

        if crc1 == crc2:
            # The error is fixed; return the new buffer
            return aux

    return None

def adsb_msg_fix_double_bit(data, bits):
    """
    Try to fix double bit errors using the checksum, like fix_single_bit.
    This is very slow and should only be tried against DF17 messages.
    
    If successful returns the modified bytearray.

    data - bytearray of message input
    bits - length in bits
    """

    for j in range(0, bits):
        byte1 = int(j / 8)
        bitmask1 = 1 << (7 - (j % 8))

        # Don't check the same pairs multiple times, so i starts from j+1
        for i in range(j + 1, bits):
            byte2 = int(i / 8)
            bitmask2 = 1 << (7 - (i % 8))

            aux = data[:]

            # Flip the jth bit
            aux[byte1] ^= bitmask1
            # Flip the ith bit
            aux[byte2] ^= bitmask2

            crc1 = (aux[int(bits / 8) - 3] << 16)
            crc1 |= (aux[int(bits / 8) - 2] << 8) 
            crc1 |= (aux[int(bits / 8) - 1])

            crc2 = adsb_crc(aux, bits)

            if crc1 == crc2:
                # The error is fixed; return the new buffer
                return aux

    return None


    
def adsb_msg_get_type(data):
    """
    Get message type
    """

    return data[0] >> 3

def adsb_msg_get_icao(data):
    """
    Get ICAO
    """
    return data[1:4]

def adsb_msg_get_fs(data):
    """
    Extract flight status from 4, 5, 20, 21
    """
    return data[0] & 7

def adsb_msg_get_me_subme(data):
    """
    Extract message 17 metype and mesub type

    Returns:
    (type,subtype) tuple
    """

    return (data[4] >> 3, data[4] & 7)

def adsb_msg_get_ac13_altitude(data):
    """
    Extract 13 bit altitude (in feet) from 0, 4, 16, 20
    """

    m_bit = data[3] & (1 << 6)
    q_bit = data[3] & (1 << 4)

    if not m_bit:
        if q_bit:
            # N is the 11 bit integer resulting in the removal of bit q and m
            n = (data[2] & 31) << 6
            n |= (data[3] & 0x80) >> 2
            n |= (data[3] & 0x20) >> 1
            n |= (data[3] & 0x15)

            return n * 25 - 1000

    return 0

def adsb_msg_get_ac12_altitude(data):
    """
    Extract 12 bit altitude (in feet) from 17
    """

    q_bit = data[5] & 1

    if q_bit:
        # N is the 11 bit integer resulting from the removal of bit Q
        n = (data[5] >> 1) << 4
        n |= (data[6] & 0xF0) >> 4

        # print("Raw bytes {} {} return {}".format(data[5], data[6], n * 25 - 1000))
        return n * 25 - 1000

    return 0

def adsb_msg_get_flight(data):
    """
    Extract flight name
    """

    ais_charset = "?ABCDEFGHIJKLMNOPQRSTUVWXYZ????? ???????????????0123456789??????"

    flight = ""

    flight += ais_charset[data[5] >> 2]
    flight += ais_charset[((data[5] & 3) << 4) | (data[6] >> 4)]
    flight += ais_charset[((data[6] & 15) << 2) | (data[7] >> 6)]
    flight += ais_charset[data[7] & 63]
    flight += ais_charset[data[8] >> 2]
    flight += ais_charset[((data[8] & 3) << 4) | (data[9] >> 4)]
    flight += ais_charset[((data[9] & 15) << 2) | (data[10] >> 6)]
    flight += ais_charset[data[10] & 63]

    return flight.strip()

def adsb_msg_get_airborne_position(data):
    """
    Airborne position message from message 17

    Return:
    (pair, lat, lon) raw tuple of even (0) or odd (1) and raw lat/lon
    """

    paireven = (data[6] & (1 << 2)) != 0

    lat = (data[6] & 3) << 15
    lat |= data[7] << 7
    lat |= data[8] >> 1

    lon = (data[8] & 1) << 16
    lon |= data[9] << 8
    lon |= data[10]

    return (paireven, lat, lon)

def adsb_msg_get_airborne_velocity(data):
    """
    Airborne velocity from message 17, synthesized from EW/NS velocities
    """

    ew_dir = (data[5] & 4) >> 2
    ew_velocity = ((data[5] & 3) << 8) | data[6]
    ns_dir = (data[7] & 0x80) >> 7
    ns_velocity = ((data[7] & 0x7f) << 3) | ((data[8] & 0xe0) >> 5)

    # Compute velocity from two speed components
    velocity = math.sqrt(ns_velocity * ns_velocity + ew_velocity * ew_velocity)

    return velocity

def adsb_msg_get_airborne_heading(data):
    """
    Airborne heading from message 17, synthesized from EW/NS velocities

    Returns:
        Heading in degrees
    """

    ew_dir = (data[5] & 4) >> 2
    ew_velocity = ((data[5] & 3) << 8) | data[6]
    ns_dir = (data[7] & 0x80) >> 7
    ns_velocity = ((data[7] & 0x7f) << 3) | ((data[8] & 0xe0) >> 5)

    ewv = ew_velocity
    nsv = ns_velocity

    if ew_dir:
        ewv *= -1

    if ns_dir:
        nsv *= -1

    heading = math.atan2(ewv, nsv)

    # Convert to degrees
    heading = heading * 360 / (math.pi * 2)

    if heading < 0:
        heading += 360

    return heading


class KismetRtladsb(object):
    def __init__(self):
        self.opts = {}

        self.opts['rtlbin'] = 'rtl_adsb'
        self.opts['channel'] = "1090.000MHz"
        self.opts['gain'] = None
        self.opts['device'] = None
        self.opts['debug'] = None

        self.kismet = None

        # The subprocess
        self.rtl_proc = None

        # Are we killing rtl because we're reconfiguring?
        self.rtl_reconfigure = False

        # We're usually not remote
        self.proberet = None

        # Do we have librtl?
        self.have_librtl = False

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

            self.rtl_get_index_by_serial = self.rtllib.rtlsdr_get_index_by_serial
            self.rtl_get_index_by_serial.argtypes = [ctypes.c_char_p]
            self.rtl_get_index_by_serial.restype = ctypes.c_int

            self.have_librtl = True
        except OSError:
            self.have_librtl = False

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
        self.csv_file = csv.reader(self.csv_data.decode('utf-8').splitlines(), delimiter=",")
        self.airplanes = []

        for row in self.csv_file:
            self.airplanes.append(row)

    def run(self):
        self.kismet = kismetexternal.Datasource(self.config.infd, self.config.outfd, remote = self.config.connect)

        # self.kismet.debug = True

        self.kismet.set_configsource_cb(self.datasource_configure)
        self.kismet.set_listinterfaces_cb(self.datasource_listinterfaces)
        self.kismet.set_opensource_cb(self.datasource_opensource)
        self.kismet.set_probesource_cb(self.datasource_probesource)

        t = self.kismet.start()

        # If we're connecting remote, kick a newsource
        if self.proberet:
            print("Registering remote source {} {}".format(self.driverid, self.config.source))
            self.kismet.send_datasource_newsource(self.config.source, self.driverid, self.proberet['uuid'])

        self.kismet.run()

    def is_running(self):
        return self.kismet.is_running()

    def __get_rtlsdr_uuid(self, intnum):
        # Get the USB info
        (manuf, product, serial) = self.get_rtl_usb_info(intnum)

        # Hash the slot, manuf, product, and serial, to get a unique ID for the UUID
        devicehash = kismetexternal.Datasource.adler32("{}{}{}{}".format(intnum, manuf, product, serial))
        devicehex = "0000{:02X}".format(devicehash)

        return kismetexternal.Datasource.make_uuid("kismet_cap_sdr_rtladsb", devicehex)

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
        return (m.partition(b'\0')[0].decode('UTF-8'), p.partition(b'\0')[0].decode('UTF-8'), s.partition(b'\0')[0].decode('UTF-8'))

    def check_rtl_bin(self):
        try:
            FNULL = open(os.devnull, 'w')
            r = subprocess.check_call([self.opts['rtlbin'], "--help"], stdout=FNULL, stderr=FNULL)
        except subprocess.CalledProcessError:
            return True
        except OSError:
            return False

        return True

    async def __rtl_adsb_task(self):
        """
        asyncio task that consumes the output from the adsb process
        """

        try:
            # Brute kill any running adsb
            self.kill_adsb()

            cmd = [ self.opts['rtlbin'] ]

            if self.opts['device'] is not None:
                cmd.append('-d')
                cmd.append("{}".format(self.opts['device']))

            if self.opts['gain'] is not None:
                cmd.append('-g')
                cmd.append("{}".format(self.opts['gain']))

            print_stderr = False
            seen_any_valid = False
            failed_once = False

            if self.opts['debug'] is not None and self.opts['debug']:
                print_stderr = True

            self.rtl_proc = await asyncio.create_subprocess_exec(*cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)

            while not self.kismet.kill_ioloop:
                line = await self.rtl_proc.stdout.readline()

                if not line:
                    break

                raw_msg = line.decode('UTF-8').strip()[1:-1]
                msg = bytearray.fromhex(raw_msg)

                output = {}

                msgtype = adsb_msg_get_type(msg)
                msgbits = adsb_len_by_type(msgtype)
                msgcrc = adsb_msg_get_crc(msg, msgbits)
                msgcrc2 = adsb_crc(msg, msgbits)

                output['adsb_msg_type'] = msgtype
                output['adsb_raw_msg'] = raw_msg
                output['crc_valid'] = False

                # Skip invalid CRC types; in the future, add 1bit recovery from dump1090
                if msgcrc != msgcrc2:
                    if msgtype == 11 or msgtype == 17:
                        msg2 = adsb_msg_fix_single_bit(msg, msgbits)

                        if msg2 != None:
                            msg = msg2
                            output['crc_valid'] = True
                            output['crc_recovered'] = 1
                        elif msgtype == 17:
                            msg2 = adsb_msg_fix_double_bit(msg, msgbits)

                            if msg2 != None:
                                msg = msg2
                                output['crc_valid'] = True
                                output['crc_recovered'] = 2

                else:
                    output['crc_valid'] = True

                # Process valid messages
                if output['crc_valid']:
                    output['adsb_msg'] = msg.hex()

                    msgicao = adsb_msg_get_icao(msg).hex()

                    output['icao'] = msgicao

                    # Look up ICAO in the airplane database
                    for row in self.airplanes:
                        if msgicao == row[0]:
                            output['regid'] = row[1]
                            output['mdl'] = row[2]
                            output['type'] = row[3]
                            output['operator'] = row[4]

                    if msgtype == 17:
                        msgme, msgsubme = adsb_msg_get_me_subme(msg)

                        if msgme >= 1 and msgme <= 4:
                            msgflight = adsb_msg_get_flight(msg)
                            output['callsign'] = msgflight

                        if msgme == 19 and (msgsubme >= 1 and msgsubme <= 4):
                            msgpair, msglat, msglon = adsb_msg_get_airborne_position(msg)
                            output['coordpair_even'] = msgpair
                            output['raw_lat'] = msglat
                            output['raw_lon'] = msglon
            
                            msgalt = adsb_msg_get_ac12_altitude(msg)
                            output['altitude'] = msgalt
            
                            if msgsubme == 1 or msgsubme == 2:
                                msgvelocity = adsb_msg_get_airborne_velocity(msg)
                                msgheading = adsb_msg_get_airborne_heading(msg)

                                output['speed'] = msgvelocity
                                output['heading'] = msgheading
            
                    elif msgtype == 0 or msgtype == 4 or msgtype == 16 or msgtype == 20:
                        msgalt = adsb_msg_get_ac13_altitude(msg)
                        output['altitude'] = msgalt

                if print_stderr:
                    print(output, file=sys.stderr)

                l = json.dumps(output)

                if not self.handle_json(l):
                    raise RuntimeError('could not process response from rtladsb')

                seen_any_valid = True

            raise RuntimeError('rtl_adsb process exited')

        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            print("An error occurred in rtl_adsb; is your USB device plugged in?  Try running rtl_adsb in a terminal and confirm it can connect to your device.  Make sure that no other programs are using this rtlsdr radio.", file=sys.stderr);

            self.kismet.send_datasource_error_report(message = "Error handling data from rtladsb: {}".format(e))

        finally:
            self.kill_adsb()
            self.kismet.spindown()
            return

    def kill_adsb(self):
        try:
            if not self.rtl_proc == None:
                # print("killing rtl proc", self.rtl_proc.pid)
                self.rtl_proc.kill()
        except Exception as e:
            pass

    def run_rtladsb(self):
        self.kismet.add_exit_callback(self.kill_adsb)
        self.kismet.add_task(self.__rtl_adsb_task)

    # Implement the listinterfaces callback for the datasource api;
    def datasource_listinterfaces(self, seqno):
        interfaces = []

        if not self.check_rtl_bin():
            self.kismet.send_datasource_interfaces_report(seqno, interfaces)
            return

        if self.rtllib != None:
            for i in range(0, self.rtl_get_device_count()):
                (manuf, product, serial) = self.get_rtl_usb_info(i)

                dev_index = i

                # Block out empty serial numbers, and serial numbers like '1'; it might be total garbage,
                # if so, just use the index
                if len(serial) > 3:
                    dev_index = serial

                intf = kismetexternal.datasource_pb2.SubInterface()
                intf.interface = "rtladsb-{}".format(dev_index)
                intf.flags = ""
                intf.hardware = self.rtl_get_device_name(i)
                interfaces.append(intf)

        self.kismet.send_datasource_interfaces_report(seqno, interfaces)

    # Implement the probesource callback for the datasource api
    def datasource_probesource(self, source, options):
        ret = {}

        # Does the source look like 'rtladsb-XYZ'?
        if not source[:8] == "rtladsb-":
            return None

        # Do we have librtl?
        if not self.have_librtl:
            return None

        if not self.check_rtl_bin():
            return None

        # Device selector could be integer position, or it could be a serial number
        devselector = source[8:]
        found_interface = False
        intnum = -1

        # Try to find the device as an index
        try:
            intnum = int(devselector)

            # Abort if we're not w/in the range
            if intnum >= self.rtl_get_device_count():
                raise ValueError("n/a")

            # Otherwise we've found a device
            found_interface = True

        except ValueError:
            # A value error means we just need to look at it as a device num
            pass
        except:
            # Otherwise something failed in querying the hw at a deeper level
            return None

        # Try it as a serial number
        if not found_interface:
            intnum = self.rtl_get_index_by_serial(devselector.encode('utf-8'))

        # We've failed as both a serial and as an index, give up
        if intnum < 0:
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

        if not self.have_librtl:
            ret["success"] = False
            ret["message"] = "could not find librtlsdr, unable to configure rtlsdr interfaces"
            return ret

        # Device selector could be integer position, or it could be a serial number
        devselector = source[8:]
        found_interface = False
        intnum = -1

        # Try to find the device as an index
        try:
            intnum = int(devselector)

            # Abort if we're not w/in the range
            if intnum >= self.rtl_get_device_count():
                raise ValueError("n/a")

            # Otherwise we've found a device
            found_interface = True

        except ValueError:
            # A value error means we just need to look at it as a device num
            pass
        except:
            # Otherwise something failed in querying the hw at a deeper level
            ret["success"] = False
            ret["message"] = "could not find probe rtlsdr interface"
            return ret

        # Try it as a serial number
        if not found_interface:
            intnum = self.rtl_get_index_by_serial(devselector.encode('utf-8'))

        # We've failed as both a serial and as an index, give up
        if intnum < 0:
            ret['success'] = False
            ret['message'] = "Could not find rtl-sdr device {}".format(devselector)
            return ret

        if 'debug' in options:
            if options['debug'] == 'True' or options['debug'] == 'true':
                self.opts['debug'] = True

        if 'channel' in options:
            self.opts['channel'] = options['channel']

        ret['hardware'] = self.rtl_get_device_name(intnum)
        if ('uuid' in options):
            ret['uuid'] = options['uuid']
        else:
            ret['uuid'] = self.__get_rtlsdr_uuid(intnum)

        self.opts['device'] = intnum

        if not self.check_rtl_bin():
           ret['success'] = False
           ret['message'] = "Could not find the rtl_adsb program; make sure you've installed rtladsb, check the Kismet README for more information."
           return

        ret['success'] = True

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
            self.kismet.send_datasource_error_report(message = "Could not parse JSON output of rtladsb")
            return False
        except Exception as e:
            self.kismet.send_datasource_error_report(message = "Could not process output of rtladsb")
            return False

        return True


