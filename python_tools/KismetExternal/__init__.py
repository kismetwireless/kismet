#!/usr/bin/env python2

# Python implementation of the simple API for communicating with Kismet
# via the Kismet External API
#
# (c) 2018 Mike Kershaw / Dragorn
# Licensed under GPL2 or above

import asyncore
import argparse
import errno
import fcntl
import os
import select
import struct
import sys
import threading
import time

import kismet_pb2
import http_pb2
import datasource_pb2

class KismetExternalInterface:
    def __init__(self, infd, outfd):
        self.infd = infd
        self.outfd = outfd

        self.cmdnum = 0

        fl = fcntl.fcntl(infd, fcntl.F_GETFL)
        fcntl.fcntl(infd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        fl = fcntl.fcntl(outfd, fcntl.F_GETFL)
        fcntl.fcntl(outfd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        self.input = os.fdopen(infd, 'rb')
        self.output = os.fdopen(outfd, 'wb')

        self.wbuffer = ""
        self.rbuffer = ""

        self.bufferlock = threading.RLock()

        self.kill_ioloop = False

        self.last_pong = 0

        self.handlers = {}

        self.add_handler("PING", self.handle_ping)
        self.add_handler("PONG", self.handle_pong)

    def __adler32(self, data):
        if len(data) < 4:
            return 0

        s1 = 0
        s2 = 0

        for i in range(0, len(data) - 4, 4):
            s2 += 4 * (s1 + ord(data[i])) + 3 * ord(data[i + 1]) + 2 * ord(data[i + 2]) + ord(data[i + 3])
            s1 += ord(data[i + 0]) + ord(data[i + 1]) + ord(data[i + 2]) + ord(data[i + 3])

        extra = len(data) % 4
        for i in range(len(data) - extra, len(data)):
            s1 += ord(data[i])
            s2 += s1

        return (s1 & 0xFFFF) + (s2 << 16)

    def __io_loop(self):
        while not self.kill_ioloop:
            if not self.last_pong == 0 and time.time() - self.last_pong > 5:
                raise RuntimeError("No PONG from remote system in 5 seconds")

            inputs = [ self.input ]
            outputs = []

            self.bufferlock.acquire()
            try:
                if len(self.wbuffer):
                    outputs = [ self.output ]
            finally:
                self.bufferlock.release()

            (readable, writable, exceptional) = select.select(inputs, outputs, inputs, 1)

            if self.output in outputs:
                self.bufferlock.acquire()
                try:
                    written = os.write(self.outfd, self.wbuffer)
                    self.wbuffer = self.wbuffer[written:]
                except OSError as e:
                    if not e.errno == errno.EAGAIN:
                        raise BufferError("Output buffer error: {}".format(e))
                finally:
                    self.bufferlock.release()

            if self.input in inputs:
                self.bufferlock.acquire()
                try:
                    self.rbuffer = self.rbuffer + os.read(self.infd, 4096)
                    self.__recv_packet()
                except OSError as e:
                    if not e.errno == errno.EAGAIN:
                        raise BufferError("Input buffer error: {}".format(e))
                finally:
                    self.bufferlock.release()

    def __recv_packet(self):
        if len(self.rbuffer) < 12:
            return

        (signature, checksum, sz) = struct.unpack("!III", self.rbuffer[:12])

        if not signature == 0xDECAFBAD:
            raise BufferError("Invalid signature in packet header")

        if len(self.rbuffer) < 12 + sz:
            return

        content = self.rbuffer[12:(12 + sz)]

        calc_csum = self.__adler32(content)

        if not calc_csum == checksum:
            raise BufferError("Invalid checksum in packet header")

        cmd = kismet_pb2.Command()
        cmd.ParseFromString(content)

        if cmd.command in self.handlers:
            self.handlers[cmd.command](cmd.seqno, cmd.content)
        else:
            print "Unhandled", cmd.command

        self.rbuffer = self.rbuffer[12 + sz:]

    def start(self):
        self.iothread = threading.Thread(target=self.__io_loop)
        self.iothread.start()

    def add_handler(self, command, handler):
        self.handlers[command] = handler

    def kill(self):
        self.bufferlock.acquire()
        try:
            self.kill_ioloop = True
        finally:
            self.bufferlock.release()

    def write_raw_packet(self, kedata):
        signature = 0xDECAFBAD
        serial = kedata.SerializeToString()
        checksum = self.__adler32(serial)
        length = len(serial)

        packet = struct.pack("!III", signature, checksum, length)

        self.bufferlock.acquire()
        try:
            self.wbuffer += packet
            self.wbuffer += serial
        finally:
            self.bufferlock.release()

    def write_ext_packet(self, cmdtype, content):
        cp = kismet_pb2.Command()

        cp.command = cmdtype
        cp.seqno = self.cmdnum
        cp.content = content.SerializeToString()

        self.write_raw_packet(cp)

        self.cmdnum = self.cmdnum + 1


    def send_ping(self):
        if self.last_pong == 0:
            self.last_pong = time.time()

        ping = kismet_pb2.Ping()
        self.write_ext_packet("PING", ping)

    def send_pong(self, seqno):
        pong = kismet_pb2.Pong()
        pong.ping_seqno = seqno
        self.write_ext_packet("PONG", pong)

    def handle_ping(self, seqno, packet):
        ping = kismet_pb2.Ping()
        ping.ParseFromString(packet)

        print "PING: ", seqno

    def handle_pong(self, seqno, packet):
        pong = kismet_pb2.Pong()
        pong.ParseFromString(packet)

        self.last_pong = time.time()


if __name__ == "__main__":
    kei = KismetExternalInterface(0, 1)

    # Start the IO loop
    kei.start()

    try:
        if sys.argv[1] == 'a':
            while 1:
                kei.send_ping()
                time.sleep(1)
        else:
            while 1:
                time.sleep(1)
    finally:
        kei.kill()


