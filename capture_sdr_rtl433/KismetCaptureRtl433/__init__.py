"""
rtl_433 Kismet data source

(c) 2018 Mike Kershaw / Dragorn
Licensed under GPL2 or above

Supports both local usb rtlsdr devices via the rtl_433 binary

Sources are generated as rtl433-XYZ when multiple rtl radios are detected.

Accepts standard options:
    channel=freqMHz   (in mhz)
    channel=freqKHz   (in khz)
    channel=freq      (in raw hz to rtl_433)

    channels="a,b,c"  Pass hopping list to rtl433_bin
"""
from __future__ import print_function

import asyncio
import argparse
import ctypes
from datetime import datetime
import json
import os
import subprocess
import sys
import threading
import traceback
import time
import uuid

from . import kismetexternal

class KismetRtl433(object):
    def __init__(self):
        self.opts = {}

        self.opts['rtlbin'] = 'rtl_433'
        self.opts['channel'] = "433.920MHz"
        self.opts['gain'] = None
        self.opts['device'] = None
        self.opts['uuid'] = None
        self.opts['ppm'] = None
        self.opts['debug'] = None

        # The subprocess
        self.rtl_proc = None

        # The task so we can kill it during reconfigure
        self.rtl_task = None

        # Are we killing rtl because we're reconfiguring?
        self.rtl_reconfigure = False

        # We're usually not remote
        self.proberet = None

        # Do we have librtl?
        self.have_librtl = False

        self.driverid = "rtl433"
        # Use ctypes to load librtlsdr and probe for supported USB devices
        try:
            found_lib = False

            try:
                self.rtllib = ctypes.CDLL("librtlsdr.so.0")
                found_lib = True
            except OSError:
                pass

            try:
                if not found_lib:
                    self.rtllib = ctypes.CDLL("librtlsdr.so.2")
                    found_lib = True
            except OSError:
                pass

            try:
                if not found_lib:
                    self.rtllib = ctypes.CDLL("librtlsdr.dylib")
                    found_lib = True
            except OSError:
                pass

            try:
                if not found_lib:
                    self.rtllib = ctypes.CDLL("librtlsdr.dll")
                    found_lib = True
            except OSError:
                pass

            if not found_lib:
                raise OSError("could not find librtlsdr")

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

        parser = argparse.ArgumentParser(description='RTL433 to Kismet bridge - Creates a rtl433 data source on a Kismet server and passes JSON-based records from the rtl_433 binary',
                epilog='Requires the rtl_433 tool (install your distributions package or compile from https://github.com/merbanan/rtl_433)')

        parser = kismetexternal.ExternalInterface.common_getopt(parser)
        
        self.config = parser.parse_args()

        try:
            self.freq_khz = self.__parse_human_frequency(self.opts['channel'])
        except: 
            print("Could not parse the supplied channel, make sure that your channel is of the form nnn.nnKHz, nnn.nnMHz, or nnn.nn for basic hz")
            sys.exit(0)

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
                print(f"Could not configure local source {self.config.source}, check your source options and config.")
                sys.exit(0)

            if not "success" in self.proberet:
                print("Could not configure local source {}, check your source options and config.")
                if "message" in self.proberet:
                    print(self.proberet["message"])
                sys.exit(0)

            if not self.proberet["success"]:
                print("Could not configure local source {}, check your source options and config.")
                if "message" in self.proberet:
                    print(self.proberet["message"].decode('utf-8'))
                sys.exit(0)

            print("Connecting to remote server {}".format(self.config.connect))


    def run(self):
        self.kismet = kismetexternal.Datasource(self.config)

        # self.kismet.debug = True

        self.kismet.set_configsource_cb(self.datasource_configure)
        self.kismet.set_listinterfaces_cb(self.datasource_listinterfaces)
        self.kismet.set_opensource_cb(self.datasource_opensource)
        self.kismet.set_probesource_cb(self.datasource_probesource)

        r = self.kismet.start()

        if r < 0:
            return

        # If we're connecting remote, kick a newsource
        if self.proberet:
            print("Registering remote source {} {}".format(self.driverid, self.config.source))
            self.kismet.send_datasource_newsource(self.config.source, self.driverid, self.proberet['uuid'])

        self.kismet.run()

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

    async def __rtl_433_task(self):
        """
        asyncio task for consuming output from the rtl_433 process
        """

        try:
            self.kill_433()

            cmd = [ self.opts['rtlbin'], '-F', 'json', '-M', 'level' ]

            if self.opts['device'] is not None:
                cmd.append('-d')
                cmd.append("{}".format(self.opts['device']))

            if self.opts['gain'] is not None:
                cmd.append('-g')
                cmd.append("{}".format(self.opts['gain']))

            if self.opts['channel'] is not None:
                cmd.append('-f')
                cmd.append("{}".format(self.opts['channel']))

            if self.opts['ppm'] is not None:
                cmd.append('-p')
                cmd.append("{}".format(self.opts['ppm']))

            seen_any_valid = False
            failed_once = False
            print_stderr = False

            if self.opts['debug'] is not None and self.opts['debug']:
                print_stderr = True

            self.rtl_proc = await asyncio.create_subprocess_exec(*cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)

            while not self.kismet.kill_ioloop:
                line = await self.rtl_proc.stdout.readline()

                if not line:
                    break

                msg = line.decode('UTF-8').strip()

                if print_stderr:
                    print("RTL433", msg, file=sys.stderr)

                if not self.handle_json(msg):
                    raise RuntimeError('could not process response from rtl_433')

                seen_any_valid = True

            raise RuntimeError('rtl_433 process exited')

        except Exception as e:
            if not self.rtl_reconfigure:
                trackeback.print_exc(file=sys.stderr)
                print("An error occurred in rtl_433; is your USB device plugged in?  Try running rtl_433 in a terminal and confirm it can connect to your device.  Make sure that no other programs are using this rtlsdr radio.", file=sys.stderr)

                self.kismet.send_datasource_error_report(message="Error handling data from rtl_433: {}".format(e))

        finally:
            self.kill_433()
            if not self.rtl_configure:
                self.kismet.spindown()

    def kill_433(self):
        try:
            if not self.rtl_proc == None:
                self.rtl_proc.kill()
        except Exception as e:
            pass

    def run_rtl433(self):
        self.kismet.add_exit_callback(self.kill_433)
        self.kismet.add_task(self.__rtl_433_task)

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
                intf.interface = f"rtl433-{dev_index}"
                intf.capinterface = f"rtl-{dev_index}"
                intf.flags = ""
                intf.hardware = self.rtl_get_device_name(i)
                interfaces.append(intf)

        self.kismet.send_datasource_interfaces_report(seqno, interfaces)

    def __parse_human_frequency(self, freq): 
        if "mhz".casefold() == freq[-3:].casefold():
            return float(freq[:-3]) * 1000 
        elif "khz".casefold() == freq[-3:].casefold():
            return float(freq[:-3])
        else:
            return float(freq) / 1000.0


    def __get_rtlsdr_uuid(self, intnum):
        # Get the USB info
        (manuf, product, serial) = self.get_rtl_usb_info(intnum)

        # Hash the slot, manuf, product, and serial, to get a unique ID for the UUID
        devicehash = kismetexternal.Datasource.adler32("{}{}{}{}".format(intnum, manuf, product, serial))
        devicehex = "0000{:02X}".format(devicehash)

        return kismetexternal.Datasource.make_uuid("kismet_cap_sdr_rtl433", devicehex)

    # Implement the probesource callback for the datasource api
    def datasource_probesource(self, source, options):
        ret = {}

        # Does the source look like 'rtl433-XYZ'?
        if not source[:7] == "rtl433-":
            return None

        # Do we have librtl?
        if not self.have_librtl:
            return None

        if not self.check_rtl_bin():
            return None

        # Device selector could be integer position, or it could be a serial number
        devselector = source[7:]
        intnum = -1

        # Try it as a serial number; try this first to deal with serial numbers like 00000000001
        intnum = self.rtl_get_index_by_serial(devselector.encode('utf-8'))

        # Try to find the device as an index
        if intnum < 0:
            try:
                intnum = int(devselector)

                # Abort if we're not w/in the range
                if intnum >= self.rtl_get_device_count():
                    raise ValueError("n/a")

            except ValueError:
                intnum = -1
            except:
                # Otherwise something failed in querying the hw at a deeper level
                return None

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

        # Does the source look like 'rtl433-XYZ'?
        if not source[:7] == "rtl433-" and not source[:4] == "rtl-":
            ret['success'] = False
            ret['message'] = "Could not parse which rtlsdr device to use"
            return ret

        intnum = -1

        if not self.have_librtl:
            ret['success'] = False
            ret['message'] = "could not find librtlsdr, unable to configure rtlsdr interfaces"
            return ret

        # Device selector could be integer position, or it could be a serial number
        devselector = source[7:]
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

        # Do nothing with exceptions; they just mean we need to look at it like a 
        # serial number
        except ValueError:
            pass

        # Try it as a serial number
        if not found_interface:
            intnum = self.rtl_get_index_by_serial(devselector.encode('utf-8'))

        # We've failed as both a serial and as an index, give up
        if intnum < 0:
            ret['success'] = False
            ret['message'] = "Could not find rtl-sdr device {}".format(devselector)
            return ret

        if 'channel' in options:
            self.opts['channel'] = options['channel']
            try:
                self.freq_khz = self.__parse_human_frequency(self.opts['channel'])
            except: 
                ret['success'] = False
                ret['message'] = "Could not parse the supplied channel, make sure that your channel is of the format nnn.nnKhz, nnn.nnMhz, or nnn.nn for basic Hz"
                return ret

        if 'gain' in options:
            self.opts['gain'] = options['gain']

        if 'ppm_error' in options:
            self.opts['ppm'] = options['ppm_error']

        if 'debug' in options:
            if options['debug'] == 'True' or options['debug'] == 'true':
                self.opts['debug'] = True

        ret['hardware'] = self.rtl_get_device_name(intnum)
        if ('uuid' in options):
            ret['uuid'] = options['uuid']
        else:
            ret['uuid'] = self.__get_rtlsdr_uuid(intnum)

        ret['capture_interface'] = f"rtl-{devselector}"

        self.opts['device'] = intnum

        ret['success'] = True

        self.run_rtl433()

        return ret

    def datasource_configure(self, seqno, config):
        return {"success": True}

    def handle_json(self, injson):
        try:
            j = json.loads(injson)
            r = json.dumps(j)

            report = kismetexternal.datasource_pb2.SubJson()

            dt = datetime.now()
            report.time_sec = int(time.mktime(dt.timetuple()))
            report.time_usec = int(dt.microsecond)

            report.type = "RTL433"
            report.json = r

            signal = kismetexternal.datasource_pb2.SubSignal()
            signal.freq_khz = self.freq_khz 
            signal.channel = self.opts['channel']

            # print("python sending json report", r);

            self.kismet.send_datasource_data_report(full_json=report, full_signal=signal)
        except ValueError as e:
            self.kismet.send_datasource_error_report(message = "Could not parse JSON output of rtl_433")
            return False
        except Exception as e:
            self.kismet.send_datasource_error_report(message = "Could not process output of rtl_433")
            return False

        return True
