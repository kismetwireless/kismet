"""
rtlamr Kismet data source

Sources are generated as rtlaamr-XYZ when multiple rtl radios are detected.

Accepts standard options:
    channel=freq      (in raw hz)

Additionally accepts:
    ppm     error offset 
    gain    fixed gain 

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
    raise ImportError("KismetRtlamr requires numpy!")

import os
import pkgutil
import subprocess
import sys
import threading
import time
import uuid

from . import rtlsdr
from . import kismetexternal

class KismetRtlamr(object):
    def __init__(self):
        self.opts = {}

        self.opts['channel'] = "912.600MHz"
        self.opts['gain'] = -1
        self.opts['ppm'] = 0
        self.opts['device'] = None
        self.opts['debug'] = None
        self.opts['biastee'] = -1

        self.kismet = None

        self.frequency = 912600000
        self.rate = 2359000
        self.usb_buf_sz = 16 * 16384

        # At our given rate, we're 72 samples per symbol
        self.symbol_len = 72

        # Messages are 12 bytes
        self.message_len_b = 12

        # With manchester doubling the bits, get the len in samples
        self.message_len_s = 2 * self.message_len_b * self.symbol_len

        # Preamble taken before the manchester decode
        self.scm_preamble = np.array([1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, ])
        self.scm_preamble_len = len(self.scm_preamble)
        self.scm_preamble_len_s = self.scm_preamble_len * self.symbol_len

        # Generate the normalized squares for converting IQ via lookup
        self.square_lut = np.zeros(256)
        for i in range(0, 256):
            self.square_lut[i] = (127.5 - float(i)) / 127.5
            self.square_lut[i] *= self.square_lut[i]

        # BCH checksum polynomial
        self.bch_poly = 0x6F63

        # Generate the polynomial table
        self.bch_table = np.zeros(256).astype(np.uint16)
        for i in range(0, 256):
            crc = i << 8
            for n in range(0, 8):
                if not (crc & 0x8000) == 0:
                    crc = (crc << 1) ^ self.bch_poly
                else:
                    crc = crc << 1

            self.bch_table[i] = int(crc)

        # The higher the decimation the more CPU we save; we decimate AFTER
        # quantization and this seems to be consistently usable with a very high
        # dynamic range of capture
        self.decimation = 24
        self.reduced_w = int(self.symbol_len / self.decimation)
        self.reduced_preamble_l = self.reduced_w * self.scm_preamble_len

        # Expand the preamble to fit the symbol width; we only search for the 
        # first 16 bits then compare the rest
        self.search_preamble = np.repeat(self.scm_preamble[:16], self.reduced_w)

        # We're usually not remote
        self.proberet = None

        # Do we have librtl?
        self.have_librtl = False

        # Asyncio queue we use to post events from the SDR 
        # callback
        self.message_queue = asyncio.Queue()

        self.driverid = "rtlamr"

        try:
            self.rtlsdr = rtlsdr.RtlSdr()
            self.have_librtl = True
        except rtlsdr.RadioMissingLibrtlsdr:
            self.have_librtl = False

        parser = argparse.ArgumentParser(description='RTL-SDR AMR Kismet datasource')
        
        # Append the default args
        parser = kismetexternal.ExternalInterface.common_getopt(parser)
        
        self.config = parser.parse_args()

        if (self.config.infd == None or self.config.outfd == None) and self.config.connect == None:
            print("This tool is launched via Kismet IPC for local capture; see --help and the Kismet documentation to configure it for remote capture.")
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
                print(f"Could not configure local source {config.source}, check your source options and config.")
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
        (manuf, product, serial) = self.rtlsdr.get_rtl_usb_info(intnum)

        # Hash the slot, manuf, product, and serial, to get a unique ID for the UUID
        devicehash = kismetexternal.Datasource.adler32("{}{}{}{}".format(intnum, manuf, product, serial))
        devicehex = "0000{:02X}".format(devicehash)

        return kismetexternal.Datasource.make_uuid("kismet_cap_sdr_rtlamr", devicehex)

    def kill_amr(self):
        try:
            self.rtlsdr.rtl_cancel_async(self.rtlradio)
        except:
            pass

    def run_rtlamr(self):
        self.kismet.add_exit_callback(self.kill_amr)
        self.kismet.add_task(self.__rtl_amr_task)
        # self.open_radio(self.opts['device'])

    # Implement the listinterfaces callback for the datasource api;
    def datasource_listinterfaces(self, seqno):
        interfaces = []

        if self.rtlsdr != None:
            for i in range(0, self.rtlsdr.get_device_count()):
                (manuf, product, serial) = self.rtlsdr.get_rtl_usb_info(i)

                dev_index = i

                # Block out empty serial numbers, and serial numbers like '1'; it might be total garbage,
                # if so, just use the index
                if len(serial) > 3:
                    dev_index = serial

                intf = kismetexternal.datasource_pb2.SubInterface()
                intf.interface = f"rtlamr-{dev_index}"
                intf.capinterface = f"rtl-{dev_index}"
                intf.flags = ""
                intf.hardware = self.rtlsdr.rtl_get_device_name(i)
                interfaces.append(intf)

        self.kismet.send_datasource_interfaces_report(seqno, interfaces)

    # Implement the probesource callback for the datasource api
    def datasource_probesource(self, source, options):
        ret = {}

        # Does the source look like 'rtlamr-XYZ'?
        if not source[:7] == "rtlamr-":
            return None

        # Do we have librtl?
        if not self.have_librtl:
            return None

        # Device selector could be integer position, or it could be a serial number
        devselector = source[7:]
        found_interface = False

        intnum = -1

        # Try it as a serial number; try this first to deal with serial numbers like 00000000001
        intnum = self.rtlsdr.rtl_get_index_by_serial(devselector.encode('utf-8'))

        # Try to find the device as an index
        if intnum < 0:
            try:
                intnum = int(devselector)

                # Abort if we're not w/in the range
                if intnum >= self.rtlsdr.rtl_get_device_count():
                    raise ValueError("n/a")

            except ValueError:
                intnum = -1
            except:
                # Otherwise something failed in querying the hw at a deeper level
                return None

        # We've failed as both a serial and as an index, give up
        if intnum < 0:
            return None

        ret['hardware'] = self.rtlsdr.rtl_get_device_name(intnum)
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

        # Does the source look like 'rtlamr-XYZ'?
        if not source[:7] == "rtlamr-" and not source[:4] == "rtl-":
            ret["success"] = False
            ret["message"] = "Could not parse which rtlsdr device to use"
            return ret

        intnum = -1

        if not self.have_librtl:
            ret["success"] = False
            ret["message"] = "could not find librtlsdr, unable to configure rtlsdr interfaces"
            return ret

        # Device selector could be integer position, or it could be a serial number
        devselector = source[7:]
        found_interface = False
        intnum = -1

        # Try to find the device as an index
        try:
            intnum = int(devselector)

            # Abort if we're not w/in the range
            if intnum >= self.rtlsdr.rtl_get_device_count():
                raise ValueError("n/a")

            # Otherwise we've found a device
            found_interface = True

        except ValueError:
            # A value error means we just need to look at it as a device num
            pass
        except:
            # Otherwise something failed in querying the hw at a deeper level
            ret["success"] = False
            ret["message"] = "could not find rtlsdr device"
            return ret

        # Try it as a serial number
        if not found_interface:
            intnum = self.rtlsdr.rtl_get_index_by_serial(devselector.encode('utf-8'))

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

        if 'ppm' in options:
            self.opts['ppm'] = options['ppm']

        if 'biastee' in options:
            if options['biastee'] == 'True' or options['biastee'] == 'true':
                self.opts['biastee'] = True

        if 'gain' in options:
            self.opts['gain'] = options['gain']

        ret['hardware'] = self.rtlsdr.rtl_get_device_name(intnum)
        if ('uuid' in options):
            ret['uuid'] = options['uuid']
        else:
            ret['uuid'] = self.__get_rtlsdr_uuid(intnum)

        ret['capture_interface'] = f"rtl-{devselector}"

        self.opts['device'] = intnum

        (ret['success'], ret['message']) = self.open_radio(self.opts['device'])

        if not ret['success']:
            return ret

        self.run_rtlamr()

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

            report.type = "RTLamr"
            report.json = r

            # print("python sending json report", r);

            self.kismet.send_datasource_data_report(full_json=report)
        except ValueError as e:
            self.kismet.send_datasource_error_report(message = "Could handle JSON output")
            return False
        except Exception as e:
            self.kismet.send_datasource_error_report(message = "Could not handle output")
            return False

        return True

    def __async_radio_thread(self):
        # This function blocks forever until cancelled
        try:
            self.rtlsdr.read_samples(self.rtl_data_cb, 12, self.usb_buf_sz)
        except rtlsdr.RadioOperationalError as e:
            if not self.kismet.inSpindown():
                self.kismet.send_datasource_error_report(message = f"Error reading from RTLSDR: {e}")
        except Exception as e:
            self.kismet.send_datasource_error_report(message = f"Error reading from RTLSDR: {e}")

        # Always make sure we die
        self.kill_amr()
        self.kismet.spindown()

    def open_radio(self, rnum):
        try:
            self.rtlsdr.open_radio(rnum, self.frequency, self.rate, gain=self.opts['gain'], autogain=True, ppm=self.opts['ppm'], biastee=self.opts['biastee'])
        except Exception as e:
            return [False, f"Error opening RTLSDR device: {e.args[0]}"]

        self.rtl_thread = threading.Thread(target=self.__async_radio_thread)
        self.rtl_thread.daemon = True
        self.rtl_thread.start()

        return [True, ""]

    async def __rtl_amr_task(self):
        """
        asyncio task that consumes the output from the rtl radio
        """
        print_stderr = False

        if self.opts['debug'] is not None and self.opts['debug']:
            print_stderr = True

        try:
            while not self.kismet.kill_ioloop:
                msg = await self.message_queue.get()

                if not msg:
                    break

                if print_stderr:
                    print(msg, file=sys.stderr)

                l = json.dumps(msg)

                if not self.handle_json(l):
                    raise RuntimeError('could not send rtlamr data')
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            print("An error occurred reading from the rtlsdr; is your USB device plugged in?  Make sure that no other programs are using this rtlsdr radio.", file=sys.stderr);

            self.kismet.send_datasource_error_report(message = "Error handling AMR: {}".format(e))

        finally:
            self.kill_amr()
            self.kismet.spindown()
            return

    def rtl_data_cb(self, buf, buflen, ctx):
        if buflen == 0:
            raise RuntimeError("received empty data from rtlsdr")

        nb = np.ctypeslib.as_array(buf, shape=(buflen,)).astype(np.uint8)
        self.process(nb)
        return 

    def bch_checksum(self, buf, init = 0):
        crc = init

        for b in buf:
            crc &= 0xFFFF
            crc = crc << 8 ^ self.bch_table[crc >> 8 ^ b]

        return crc & 0xFFFF

    def cumsum(self, data, w):
        ret = np.cumsum(data)
        ret[w:] = ret[w:] - ret[:-w]
        return ret[w - 1:] / w

    def moving_average(self, data, w):
        return self.cumsum(data, w)

    def _resample_quantize(self, buf):
        # Trim trailing byte if we don't have even I/Q pairs
        if len(buf) % 2 != 0:
            buf = buf[:-1]

        # Compute the magnitude and remove the DC offset using the lookup table;
        # buf is now a real magnitude
        buf = np.add(self.square_lut[buf[::2]], self.square_lut[buf[1::2]])

        # Filter with a sub-width of the message - because we decimate AFTER
        # quantization, we window on the original symbol length
        r = self.moving_average(buf, int(self.symbol_len / 8))

        # Sliding average across the half the message width
        rm = self.moving_average(r, int(self.message_len_s * 0.5) )
        r = (r[:len(rm)] - rm)[:np.newaxis]

        # Quantize
        bits = np.where(r > 0, 1, 0)

        # Fake decimation of the bits themselves after the quanitization
        bits = bits[::self.decimation]

        return bits

    def _power_estimate(self, buf, start_bit, sz_bits):
        # Take a rough power estimate, we get it in dBFS; db relative to full scale.
        # This will get treated as dbm elsewhere in kismet which is fundamentally
        # wrong, but no more wrong than some other power measurements from other 
        # cards.  we do our best.
        bit_offt = start_bit * self.decimation
        bit_len = sz_bits * self.decimation
        powr = np.average(np.add(self.square_lut[buf[start_bit:start_bit + bit_len:2]], self.square_lut[buf[start_bit + 1:start_bit + bit_len:2]]))
        return int(10 * math.log10(powr))

    def _single_manchester(self, a, b, c, d):
        bit_p = a > b
        bit = c > d

        if bit and bit_p and c > b:
            return 1
        if bit and not bit_p and d < b:
            return 1
        if not bit and bit_p and d > b:
            return 0
        if not bit and not bit_p and c < b:
            return 0

        return None

    def corr_preamble(self, buf):
        corr = np.correlate(buf, self.search_preamble)
        return np.argmax(corr)

    def get_bits_as_int(self, buf):
        pad = len(buf) % 8
        if pad != 0:
            padbuf = np.array([0] * (8 - pad))
            buf = np.append(padbuf, buf)

        return int.from_bytes(np.packbits(buf), byteorder='big', signed=False)

    def reduce_bits(self, bits, sz):
        return bits[int(self.reduced_w / 2):(sz * self.reduced_w):self.reduced_w]

    def process(self, buf):
        # 'decimate' and quantize to a stream of bits; the bitstream returned
        # is still expanded by the sample multiplier / the bit width
        rs = self._resample_quantize(buf)

        i = 0
        while True:
            if i + len(self.scm_preamble) >= len(rs):
                break

            # Correlate for preamble; this is one of the most expensive parts of the
            # whole process
            p = self.corr_preamble(rs[i:i + (self.reduced_preamble_l * 4)])

            if p == None:
                break

            p = i + p

            if p + (24 * 8 * self.reduced_w) < len(rs):
                # Convert to one bit per symbol
                bits = self.reduce_bits(rs[p:], (14 * 8 * 2))

                i = p + self.reduced_preamble_l * 4

                # Compare the full preamble since we only match on the first 16 bits
                if not np.array_equal(bits[:self.scm_preamble_len], self.scm_preamble):
                    continue

                if len(bits) % 2 != 0:
                    bits = bits[:-1]

                errors = 0
                msgbuf = np.array([0] * int(len(bits) / 2))
                a = 0
                b = 1

                if len(bits) < (24 * 8):
                    break

                # This is the simplest way to decode manchester with no error awareness
                # but there is no huge benefit to using it, see below
                # msgbuf = np.where(bits[::2] > bits[1::2], 1, 0)

                # This isn't the simplest way to convert to manchester, but testing
                # shows almost no impact on CPU load between this and the simplest
                # non-error-checking encoding method since it's called only on the
                # resolved end-stage signal
                for ix in range(0, len(bits), 2):
                    bit = self._single_manchester(bits[ix], bits[ix+1], a, b)

                    a = bits[ix]
                    b = bits[ix+1]

                    if bit == None:
                        errors = errors + 1

                        if errors > 5:
                            break
                        else:
                            if a > b:
                                bit = 1
                            else:
                                bit = 0

                            a = 0
                            b = 1

                    msgbuf[int(ix / 2)] = bit
                    i = p + ix
               
                # SCM frame format
                # [  0 : 21 ] 21 Sync / RF Preamble 1F2A60
                # [ 21 : 23 ] 2  ID MSB
                # [ 23      ] 1  Reserved
                # [ 24 : 26 ] 2  Physical tamper
                # [ 26 : 30 ] 4  Endpoint type
                # [ 30 : 32 ] 2  Endpoint tamper
                # [ 32 : 56 ] 24 Consumption value
                # [ 56 : 80 ] 24 ID LSB
                # [ 80 : 96 ] 16 Checksum

                msgbuf = msgbuf[1:]
                bytestr = np.packbits(msgbuf);

                report_msg = {
                        "amr_scm": bytearray(bytestr).hex(),
                        "valid": False,
                        "type": "SCM",
                        }

                checksum = self.get_bits_as_int(msgbuf[80:96])

                # Anything with a checksum of 0 is summarily useless, don't even report it, it's
                # a malformed fragment
                if checksum == 0:
                    continue

                calc_checksum = self.bch_checksum(bytestr[2:10])

                # Defer power calc until we know we have something sane-ish
                pwr = self._power_estimate(buf, p, 14*8*2)

                report_msg["signal"] = pwr

                # Bounce invalid messages but report the signal anyhow
                if checksum != calc_checksum:
                    if self.opts['debug']:
                        print(report_msg)
                    self.kismet.add_task(self.message_queue.put, [report_msg])
                    continue

                # Flag as valid and start populating
                report_msg["valid"] = True

                meterid = (self.get_bits_as_int(msgbuf[21:23]) << 24)
                meterid |= self.get_bits_as_int(msgbuf[56:80])

                report_msg["meterid"] = meterid
                report_msg["metertype"] = self.get_bits_as_int(msgbuf[26:30])
                report_msg["consumption"] = self.get_bits_as_int(msgbuf[32:56])
                report_msg["phytamper"] = self.get_bits_as_int(msgbuf[24:26])
                report_msg["endptamper"] = self.get_bits_as_int(msgbuf[30:32])
                
                if self.opts['debug']:
                    print(report_msg)

                self.kismet.add_task(self.message_queue.put, [report_msg])

            else:
                break

