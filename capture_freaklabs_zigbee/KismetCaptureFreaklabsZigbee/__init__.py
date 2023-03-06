"""
freaklabs zigbee sniffer source

(c) 2018 Mike Kershaw / Dragorn
Licensed under GPL2 or above

accepts standard source hop options
accepts additional options:

device=/path/to/serial
baud=baudrate
band=800|900|2400

Based in part on the Sensniff code from:
https://github.com/freaklabs/sensniff-freaklabs.git

Under the following license:

Copyright (c) 2012, George Oikonomou (oikonomou@users.sf.net)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
  * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  * Neither the name of the owner nor the names of its contributors may be
    used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

"""

import argparse
from datetime import datetime
import json
import os

try:
    import serial
except ImportError:
    raise ImportError("KismetCaptureFreaklabsZigbee requires python-serial, please install it!")

import struct
import subprocess
import sys
import threading
import time
import uuid

from . import kismetexternal

LINKTYPE_IEEE802_15_4_NOFCS = 230
LINKTYPE_IEEE802_15_4 = 195
NETWORK = LINKTYPE_IEEE802_15_4_NOFCS

CMD_FRAME = 0x00
CMD_CHANNEL = 0x01
CMD_GET_CHANNEL = 0x81
CMD_SET_CHANNEL = 0x82
SNIFFER_PROTO_VERSION = 1

class FreaklabException(Exception):
    pass

class SerialInputHandler(object):
    def __init__(self, port, baudrate):
        self.__sensniff_magic_legacy = struct.pack('BBBB', 0x53, 0x6E, 0x69, 0x66)
        self.__sensniff_magic = struct.pack('BBBB', 0xC1, 0x1F, 0xFE, 0x72)
        self._current_channel = -1

        try:
            self.port = serial.Serial(port = port,
                                      baudrate = baudrate,
                                      bytesize = serial.EIGHTBITS,
                                      parity = serial.PARITY_NONE,
                                      stopbits = serial.STOPBITS_ONE,
                                      xonxoff = False,
                                      rtscts = False,
                                      timeout = 0.1)
            self.port.flushInput()
            self.port.flushOutput()
        except (serial.SerialException, ValueError, IOError, OSError) as e:
            raise FreaklabException("Could not open freaklabs device: {}".format(e))

    def read_frame(self):
        try:
            # Read the magic + 1 more byte
            b = self.port.read(5)
            size = len(b)
        except (IOError, OSError) as e:
            raise FreaklabException("Error reading port: {}".format(e))

        if size == 0:
            return b
        if size < 5:
            self.port.flushInput()
            return ''

        if b[0:4] not in (self.__sensniff_magic, self.__sensniff_magic_legacy):
            # Peripheral UART output - print it
            per_out = self.port.readline().rstrip()
            return ''

        # If we reach here:
        # Next byte == 1: Proto version 1, header follows
        # Next Byte != 1 && < 128. Old proto version. Frame follows, length == the byte
        b = bytearray(b)
        if b[4] != SNIFFER_PROTO_VERSION:
            # Legacy contiki sniffer support. Will slowly fade away
            size = b[4]
            try:
                b = self.port.read(size)
            except (IOError, OSError) as e:
                raise FreaklabException("Error reading port: {}".format(e))
                return

            if len(b) != size:
                # We got the magic right but subsequent bytes did not match
                # what we expected to receive
                self.port.flushInput()
                return ''

            return b

        # If we reach here, we have a packet of proto ver SNIFFER_PROTO_VERSION
        # Read CMD and LEN
        try:
            b = self.port.read(2)

        except (IOError, OSError) as e:
            raise FreaklabException("Error reading port: {}".format(e))
            return

        if size < 2:
            self.port.flushInput()
            return ''

        b = bytearray(b)
        cmd = b[0]
        length = b[1]

        # Read the frame or command response
        b = self.port.read(length)
        if len(b) != length:
            # We got the magic right but subsequent bytes did not match
            # what we expected to receive
            self.port.flushInput()
            return ''

        # If we reach here, b holds a frame or a command response of length len
        if cmd == CMD_FRAME:
            return b

        # If we reach here, we have a command response
        b = bytearray(b)
        if cmd == CMD_CHANNEL:
             self._current_channel = b[0]
        return ''

    def __write_command(self, cmd):
        self.port.write(self.__sensniff_magic)
        self.port.write(bytearray([SNIFFER_PROTO_VERSION]))
        self.port.write(cmd)
        self.port.flush()

    def set_channel(self, channel):
        self.__write_command(bytearray([CMD_SET_CHANNEL, 1, channel]))
        # this hardware takes 150us for PLL lock and we need enough time to read the success message
        time.sleep (0.003)
        if (channel != self._current_channel):
            raise FreaklabException

    def get_channel(self):
        self.__write_command(bytearray([CMD_GET_CHANNEL]))

class KismetFreaklabsZigbee(object):
    def __init__(self):
        # Frequency map
        self.frequencies = {
            0: 868,
            1: 906,
            2: 908,
            3: 910,
            4: 912,
            5: 914,
            6: 916,
            7: 918,
            8: 920,
            9: 922,
            10: 924,
            11: 2405,
            12: 2410,
            13: 2415,
            14: 2420,
            15: 2425,
            16: 2430,
            17: 2435,
            18: 2440,
            19: 2445,
            20: 2450,
            21: 2455,
            22: 2460,
            23: 2465,
            24: 2470,
            25: 2475,
            26: 2480
        }

        self.band_map = {}
        self.band_map["800"] = ["0"]
        self.band_map["900"] = []
        self.band_map["2400"] = []
        # Freaklabs 900mhz hw can operate down to channel 0, include it in the list
        for c in range(0, 11):
            self.band_map["900"].append("{}".format(c))
        for c in range(11, 27):
            self.band_map["2400"].append("{}".format(c))

        self.defaults = {}

        self.defaults['device'] = "/dev/ttyUSB0"
        self.defaults['baudrate'] = "57600"
        self.defaults['band'] = "auto"
        self.defaults['name'] = None

        self.hop_thread = None
        self.monitor_thread = None

        self.chan_config_lock = threading.RLock()
        self.chan_config = {}
        self.chan_config['chan_pos'] = 0
        self.chan_config['hopping'] = True
        self.chan_config['channel'] = "0"
        self.chan_config['hop_channels'] = []
        self.chan_config['hop_rate'] = 1
        self.chan_config['chan_skip'] = 0
        self.chan_config['chan_offset'] = 0

        self.serialhandler = None

        parser = argparse.ArgumentParser(description='Kismet datasource to capture from Freaklabs Zigbee hardware',
                epilog='Requires Freaklabs hardware (or compatible SenSniff-based device)')
       
        parser = kismetexternal.ExternalInterface.common_getopt(parser)
        
        self.config = parser.parse_args()

        if not self.config.connect == None and self.config.source == None:
            print("You must specify a source with --source when connecting to a remote Kismet server")
            sys.exit(0)

        self.proberet = None

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

    def run(self):
        self.kismet = kismetexternal.Datasource(self.config)

        self.kismet.set_configsource_cb(self.datasource_configure)
        self.kismet.set_listinterfaces_cb(self.datasource_listinterfaces)
        self.kismet.set_opensource_cb(self.datasource_opensource)
        self.kismet.set_probesource_cb(self.datasource_probesource)

        r = self.kismet.start() 

        if r < 0:
            return

        # If we're connecting remote, kick a newsource
        if self.proberet:
            print("Registering remote source {} {}".format('freaklabszigbee', self.config.source))
            self.kismet.send_datasource_newsource(self.config.source, 'freaklabszigbee', self.proberet['uuid'])

        self.kismet.run()

    def is_running(self):
        return self.kismet.is_running()

    def __start_hopping(self):
        def hop_func():
            while self.chan_config['hopping']:
                wait_usec = 1.0 / self.chan_config['hop_rate']

                try:
                    self.chan_config_lock.acquire()
                    c = int(self.chan_config['hop_channels'][self.chan_config['chan_pos'] % len(self.chan_config['hop_channels'])])
                    self.serialhandler.set_channel(c)
                except FreaklabException as e:
                    self.kismet.send_datasource_error_report(message = "Could not tune to {}: {}".format(self.chan_config['chan_pos'], e))
                finally:
                    self.chan_config_lock.release()

                self.chan_config['chan_pos'] = self.chan_config['chan_pos'] + 1

            self.hop_thread = None

        if self.hop_thread:
            return

        self.hop_thread = threading.Thread(target = hop_func)
        self.hop_thread.daemon = True
        self.hop_thread.start()

    def __detect_band(self, device):
        try:
            self.serialhandler.set_channel(2)
            self.kismet.send_message("Found band \'900MHz\' for freaklabs source on \'{}\'".format(device))
            return "900"
        except FreaklabException as e:
            True

        try:
            self.serialhandler.set_channel(13)
            self.kismet.send_message("Found band \'2.4GHz\' for freaklabs source on \'{}\'".format(device))
            return "2400"
        except FreaklabException as e:
            return "unknown"

    def __start_monitor(self):
        def mon_func():
            while self.kismet.is_running():
                try:
                    raw = self.serialhandler.read_frame()
                except FreaklabException as e:
                    self.kismet.send_datasource_error_report(message = "Error reading from zigbee device: {}".format(e))
                    break

                if len(raw) == 0:
                    continue

                packet = kismetexternal.datasource_pb2.SubPacket()
                dt = datetime.now()
                packet.time_sec = int(time.mktime(dt.timetuple()))
                packet.time_usec = int(dt.microsecond)

                packet.dlt = LINKTYPE_IEEE802_15_4_NOFCS

                packet.size = len(raw)
                packet.data = raw

                self.kismet.send_datasource_data_report(full_packet = packet)

            self.monitor_thread = None

        if self.monitor_thread:
            return

        self.monitor_thread = threading.Thread(target = mon_func)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    # We can't really list interfaces other than to guess about serial ports which
    # seems like a bad idea; maybe we do that, eventually
    def datasource_listinterfaces(self, seqno):
        interfaces = []
        self.kismet.send_datasource_interfaces_report(seqno, interfaces)

    def __get_uuid(self, opts):
        if ('uuid' in opts):
            return opts['uuid']

        uhash = kismetexternal.Datasource.adler32("{}{}{}".format(opts['device'], opts['baudrate'], opts['name']))
        uhex = "0000{:02X}".format(uhash)

        return kismetexternal.Datasource.make_uuid("kismet_cap_freaklabs_zigbee", uhex)

    # Implement the probesource callback for the datasource api
    def datasource_probesource(self, source, options):
        ret = {}

        if not source == "freaklabs":
            return None

        opts = options
        for x in self.defaults:
            opts.setdefault(x, self.defaults[x])

        ret['uuid'] = self.__get_uuid(opts)

        try:
            SerialInputHandler(opts['device'], int(opts['baudrate']))
        except FreaklabException as e:
            ret['success'] = False
            ret['message'] = "{}".format(e)
            return ret

        ret['capture_interface'] = opts['device']
        if not opts['band'] == 'auto':
            ret['hardware'] = "freaklabs-{}".format(opts['band'])

        ret['success'] = True
        return ret

    def datasource_opensource(self, source, options):
        ret = {}

        if not source == "freaklabs":
            return None

        opts = options
        for x in self.defaults:
            opts.setdefault(x, self.defaults[x])

        ret['uuid'] = self.__get_uuid(opts)

        try:
            self.serialhandler = SerialInputHandler(opts['device'], int(opts['baudrate']))
            self.serialhandler.get_channel()
        except FreaklabException as e:
            ret['success'] = False
            ret['message'] = "{}".format(e)
            return ret

        # Launch the monitor thread
        self.__start_monitor()

        while True:
            try:
                self.serialhandler.set_channel(2)
                break
            except:
                time.sleep(0.1)

            try:
                self.serialhandler.set_channel(13)
                break
            except:
                time.sleep(0.4)


        if opts['band'] == "auto":
            opts['band'] = self.__detect_band(opts['device'])

        if opts['band'] == "unknown":
            ret['success'] = False
            ret['message'] = "Failed to auto-detect band"
            return ret

        if not opts['band'] in self.band_map:
            ret['success'] = False
            ret['message'] = "Unknown band {}".format(opts['band'])
            return ret

        band = self.band_map[opts['band']]

        ret['phy'] = LINKTYPE_IEEE802_15_4_NOFCS

        ret['channel'] = band[0]
        ret['channels'] = band

        ret['capture_interface'] = opts['device']
        ret['hardware'] = "freaklabs-{}".format(opts['band'])

        ret['success'] = True

        return ret

    def datasource_configure(self, seqno, config):
        ret = {}

        if config.HasField('channel'):
            self.chan_config_lock.acquire()
            self.chan_config['hopping'] = False
            self.chan_config['channel'] = config.channel.channel
            ret['channel'] = config.channel.channel
            self.chan_config_lock.release()
        elif config.HasField('hopping'):
            self.chan_config_lock.acquire()
            if config.hopping.HasField('rate'):
                self.chan_config['hop_rate'] = config.hopping.rate

            if len(config.hopping.channels):
                self.chan_config['hop_channels'] = []
                for c in config.hopping.channels:
                    self.chan_config['hop_channels'].append(c)

                self.chan_config['hopping'] = True

            self.chan_config_lock.release()

            # Echo its config back at it
            ret['full_hopping'] = config.hopping

        ret['success'] = True

        if self.chan_config['hopping'] and not self.hop_thread:
            self.__start_hopping()

        return ret


