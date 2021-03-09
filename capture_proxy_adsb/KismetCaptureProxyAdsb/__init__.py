"""
ADSB proxy from one kismet server or ADSB hex websocket to another
"""

from __future__ import print_function

import asyncio
import argparse
import ctypes
from datetime import datetime
import json
import math

import os
import pkgutil
import subprocess
import sys
import threading
import time
import uuid

from . import kismetexternal

class KismetProxyAdsb(object):
    def __init__(self):
        self.opts = {}

        self.kismet = None

        self.proxy_ws = None
        self.proberet = None

        self.uri = None

        # Asyncio queue we use to post events from the websocket
        self.message_queue = asyncio.Queue()

        self.driverid = "proxyadsb"

        parser = argparse.ArgumentParser(description='Kismet ADSB proxy datasource')
      
        # Append the default args
        parser = kismetexternal.ExternalInterface.common_getopt(parser)
        
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
        devicehash = kismetexternal.Datasource.adler32(self.uri)
        devicehex = "0000{:02X}".format(devicehash)

        return kismetexternal.Datasource.make_uuid("kismet_cap_proxy_adsb", devicehex)

    async def __adsb_task(self):
        """
        asyncio task that consumes the output from the radio
        """
        print_stderr = False

        if self.opts['debug'] is not None and self.opts['debug']:
            print_stderr = True

        try:
            while not self.kismet.kill_ioloop:
                msg = await self.message_queue.get()

                if not msg:
                    break

                output = {}

                msgtype = self.adsb_msg_get_type(msg)
                msgbits = self.adsb_len_by_type(msgtype)
                msgcrc = self.adsb_msg_get_crc(msg, msgbits)
                msgcrc2 = self.adsb_crc(msg, msgbits)

                output['adsb_msg_type'] = msgtype
                output['adsb_raw_msg'] = msg.hex()
                output['crc_valid'] = False

                if msgcrc != msgcrc2:
                    if msgtype == 11 or msgtype == 17:
                        msg2 = self.adsb_msg_fix_single_bit(msg, msgbits)
     
                        if msg2 != None:
                            msg = msg2
                            output['crc_valid'] = True
                            output['crc_recovered'] = 1
                else:
                    output['crc_valid'] = True

                # Process valid messages
                if output['crc_valid']:
                    output['adsb_msg'] = msg.hex()

                    msgicao = self.adsb_msg_get_icao(msg).hex()

                    output['icao'] = msgicao

                    if msgtype == 17:
                        msgme, msgsubme = self.adsb_msg_get_me_subme(msg)

                        if msgme >= 1 and msgme <= 4:
                            msgflight = self.adsb_msg_get_flight(msg)
                            output['callsign'] = msgflight

                        elif msgme >= 9 and msgme <= 18:
                            msgalt = self.adsb_msg_get_ac12_altitude(msg)
                            output['altitude'] = msgalt

                            msgpair, msglat, msglon = self.adsb_msg_get_airborne_position(msg)
                            output['coordpair_even'] = msgpair
                            output['raw_lat'] = msglat
                            output['raw_lon'] = msglon

                        elif msgme == 19 and (msgsubme >= 1 and msgsubme <= 4):
                            if msgsubme == 1 or msgsubme == 2:
                                msgvelocity = self.adsb_msg_get_airborne_velocity(msg)
                                msgheading = self.adsb_msg_get_airborne_heading(msg)

                                output['speed'] = msgvelocity
                                output['heading'] = msgheading
                            elif msgsubme == 3 or msgsubme == 4:
                                msgheadvalid, msgheading = self.adsb_msg_get_airborne_heading(msg)
                                if msgheadvalid:
                                    out['heading'] = heading
            
                    elif msgtype == 0 or msgtype == 4 or msgtype == 16 or msgtype == 20:
                        msgalt = self.adsb_msg_get_ac13_altitude(msg)
                        output['altitude'] = msgalt

                if print_stderr:
                    print(output, file=sys.stderr)

                l = json.dumps(output)

                if not self.handle_json(l):
                    raise RuntimeError('could not process response from rtladsb')
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            print("An error occurred reading from the proxy websocket")
            self.kismet.send_datasource_error_report(message = "Error handling ADSB: {}".format(e))
        finally:
            self.kill_proxy()
            self.kismet.spindown()
            return

    def kill_proxy(self):
        try:
            self.websocket.close()
        except:
            pass

    def run_proxyadsb(self):
        self.open_radio(self.opts['device'])

    # Implement the listinterfaces callback for the datasource api;
    def datasource_listinterfaces(self, seqno):
        self.kismet.send_datasource_interfaces_report(seqno, [])
        return

    # Implement the probesource callback for the datasource api
    def datasource_probesource(self, source, options):
        return None

    def datasource_opensource(self, source, options):
        ret = {}

        # We don't care what they name it if we're opening explicitly, but we do need the
        # appropriate remote options

        if not 'host' in options:
            ret['success'] = False
            ret['message'] = "'host' required in source options"
            return ret

        if not 'port' in options:
            ret['success'] = False
            ret['message'] = "'port' required in source options"
            return ret

        if not 'apikey' in options:
            ret['success'] = False
            ret['message'] = "'apikey' required in source options"
            return ret

        self.opts['host'] = options['host']
        self.opts['port'] = options['port']
        self.opts['apikey'] = options['apikey']

        if 'debug' in options:
            if options['debug'] == 'True' or options['debug'] == 'true':
                self.opts['debug'] = True

        if 'uri_prefix' in options:
            self.opts['uri_prefix'] = options['uri_prefix']
        else:
            self.opts['uri_prefix'] = ""

        if 'adsb_uuid' in options:
            self.opts['adsb_uuid'] = options['adsb_uuid']
        else:
            self.opts['adsb_uuid'] = None

        if ('uuid' in options):
            ret['uuid'] = options['uuid']
        else:
            ret['uuid'] = self.__get_rtlsdr_uuid(intnum)

        if 'ssl' in options:
            if options['ssl'] == 'true':
                self.opts['proxy_ssl'] = True
            else:
                self.opts['proxy_ssl'] = False
        else:
            self.opts['proxy_ssl'] = False

        # Build the URI with ws/wss, api keys, and uuid selectors if provided
        if self.opts['proxy_ssl']:
            self.uri = f"wss://{self.opts['host']}:{self.opts['port']}/{self.opts['uri_prefix']}"
        else:
            self.uri = f"ws://{self.opts['host']}:{self.opts['port']}/{self.opts['uri_prefix']}"

        if self.opts['adsb_uuid']:
            self.uri = f"{self.uri}/datasource/by-uuid/{self.opts['adsb_uuid']}/adsb_raw.ws"
        else:
            self.uri = f"{self.uri}/phy/RTLADSB/raw.ws"

        self.uri = f"{self.uri}?KISMET=${self.opts['apikey']}"

        ret['hardware'] = 'adsbproxy'
        ret['capture_interface'] = 'adsbproxy'

        ret['success'] = True

        try:
            await self.__ws_client_connect()
        except Exception as e:
            ret['message'] = f"Could not connect to source websocket: {e}"
            ret['success'] = False
            return ret

        self.kismet.add_task(self.__ws_io_loop)

        return ret

    async def __ws_client_connect(self):
        self.websocket = await websockets.connect(self.uri)

    async def __ws_io_loop(self):
        try:
            while not self.kismet.kill_ioloop and not self.websocket == None:
                data = self.websocket.recv()

                if len(data) == 0:
                    raise BufferError("Connection lost to source Kismet server")

                self.__handle_adsb(data)
        except Exception as e:
            print("FATAL:  Encountered an error receiving data from the source Kismet server", e, file=sys.stderr)
            self.kismet.kill()

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

            report.type = "RTLadsb"
            report.json = r

            # print("python sending json report", r);

            self.kismet.send_datasource_data_report(full_json=report)
        except ValueError as e:
            self.kismet.send_datasource_error_report(message = "Could not handle JSON output")
            return False
        except Exception as e:
            self.kismet.send_datasource_error_report(message = "Could not handle output")
            return False

        return True

    def rtl_data_cb(self, buf, buflen, ctx):
        self._iq_magnitude(buf, buflen)
        self._manchester()
        return 

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
        self.kill_adsb()
        self.kismet.spindown()

    def open_radio(self, rnum):
        try:
            self.rtlsdr.open_radio(rnum, self.frequency, self.rate, gain=self.opts['gain'], autogain=True, ppm=self.opts['ppm'], biastee=self.opts['biastee'])
        except Exception as e:
            self.kismet.send_datasource_error_report(message = "Error opening RTLSDR for ADSB: {}".format(e.args[0]))
            self.kill_adsb()
            self.kismet.spindown()

        self.rtl_thread = threading.Thread(target=self.__async_radio_thread)
        self.rtl_thread.daemon = True
        self.rtl_thread.start()

    # ADSB parsing functions ported from the dump1090 C implementation
    def adsb_crc(self, data, bits):
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
    
    def adsb_len_by_type(self, type):
        """
        Get expected length of message in bits based on the type
        """
    
        if type == 16 or type == 17 or type == 19 or type == 20 or type == 21:
            return 112
    
        return 56
    
    def adsb_msg_get_crc(self, data, bits):
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
    
    def adsb_msg_fix_single_bit(self, data, bits):
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
    
            crc2 = self.adsb_crc(aux, bits)
    
            if crc1 == crc2:
                # The error is fixed; return the new buffer
                return aux
    
        return None
    
    def adsb_msg_fix_double_bit(self, data, bits):
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
    
                crc2 = self.adsb_crc(aux, bits)
    
                if crc1 == crc2:
                    # The error is fixed; return the new buffer
                    return aux
    
        return None
    
    
        
    def adsb_msg_get_type(self, data):
        """
        Get message type
        """
    
        return data[0] >> 3
    
    def adsb_msg_get_icao(self, data):
        """
        Get ICAO
        """
        return data[1:4]
    
    def adsb_msg_get_fs(self, data):
        """
        Extract flight status from 4, 5, 20, 21
        """
        return data[0] & 7
    
    def adsb_msg_get_me_subme(self, data):
        """
        Extract message 17 metype and mesub type
    
        Returns:
        (type,subtype) tuple
        """
    
        return (data[4] >> 3, data[4] & 7)
    
    def adsb_msg_get_ac13_altitude(self, data):
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
    
    def adsb_msg_get_ac12_altitude(self, data):
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
    
    def adsb_msg_get_flight(self, data):
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
    
    def adsb_msg_get_airborne_position(self, data):
        """
        Airborne position message from message 17
    
        Return:
        (pair, lat, lon) raw tuple of even (0) or odd (1) and raw lat/lon
        """
    
        paireven = (data[6] & (1 << 2)) == 0
    
        lat = (data[6] & 3) << 15
        lat |= data[7] << 7
        lat |= data[8] >> 1
    
        lon = (data[8] & 1) << 16
        lon |= data[9] << 8
        lon |= data[10]
    
        return (paireven, lat, lon)
    
    def adsb_msg_get_airborne_velocity(self, data):
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
    
    def adsb_msg_get_airborne_heading(self, data):
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
    
    def adsb_msg_get_sub3_heading(self, data):
        """
        Direct heading from msg 17 sub 3 and 4
    
        Returns:
            Heading in degrees
        """
    
        valid = data[5] & (1 << 2)
        heading = (data[5] & 3) << 5
        heading |= data[6] >> 3
        heading = heading * (360.0 / 128)
    
        return valid, heading
    
    def adsb_process_msg(self, msg):
        output = {}
     
        msgtype = self.adsb_msg_get_type(msg)
        msgbits = self.adsb_len_by_type(msgtype)
        msgcrc = self.adsb_msg_get_crc(msg, msgbits)
        msgcrc2 = self.adsb_crc(msg, msgbits)
     
        output['adsb_msg_type'] = msgtype
        output['adsb_raw_msg'] = msg.hex()
        output['crc_valid'] = False
     
        # Skip invalid CRC types; in the future, add 1bit recovery from dump1090
        if msgcrc != msgcrc2:
            if msgtype == 11 or msgtype == 17:
                msg2 = self.adsb_msg_fix_single_bit(msg, msgbits)
     
                if msg2 != None:
                    msg = msg2
                    output['crc_valid'] = True
                    output['crc_recovered'] = 1
     
        else:
            output['crc_valid'] = True
     
        # Process valid messages
        if output['crc_valid']:
            output['adsb_msg'] = msg.hex()
     
            msgicao = self.adsb_msg_get_icao(msg).hex()
     
            output['icao'] = msgicao
     
            if msgtype == 17:
                msgme, msgsubme = self.adsb_msg_get_me_subme(msg)
     
                if msgme >= 1 and msgme <= 4:
                    msgflight = self.adsb_msg_get_flight(msg)
                    output['callsign'] = msgflight
     
                elif msgme >= 9 and msgme <= 18:
                    msgalt = self.adsb_msg_get_ac12_altitude(msg)
                    output['altitude'] = msgalt
     
                    msgpair, msglat, msglon = self.adsb_msg_get_airborne_position(msg)
                    output['coordpair_even'] = msgpair
                    output['raw_lat'] = msglat
                    output['raw_lon'] = msglon
     
                elif msgme == 19 and (msgsubme >= 1 and msgsubme <= 4):
                    msgpair, msglat, msglon = self.adsb_msg_get_airborne_position(msg)
                    output['coordpair_even'] = msgpair
                    output['raw_lat'] = msglat
                    output['raw_lon'] = msglon
     
                    msgalt = self.adsb_msg_get_ac12_altitude(msg)
                    output['altitude'] = msgalt
     
                    if msgsubme == 1 or msgsubme == 2:
                        msgvelocity = self.adsb_msg_get_airborne_velocity(msg)
                        msgheading = self.adsb_msg_get_airborne_heading(msg)
     
                        output['speed'] = msgvelocity
                        output['heading'] = msgheading
                    elif msgsubme == 3 or msgsubme == 4:
                        msgheadvalid, msgheading = self.adsb_msg_get_airborne_heading(msg)
                        if msgheadvalid:
                            out['heading'] = msgheading
     
            elif msgtype == 0 or msgtype == 4 or msgtype == 16 or msgtype == 20:
                msgalt = self.adsb_msg_get_ac13_altitude(msg)
                output['altitude'] = msgalt
     
        if output['crc_valid']:
            print(output, file=sys.stderr)


