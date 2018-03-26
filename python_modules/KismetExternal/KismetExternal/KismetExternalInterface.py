#!/usr/bin/env python2

# Python implementation of the simple API for communicating with Kismet
# via the Kismet External API
#
# (c) 2018 Mike Kershaw / Dragorn
# Licensed under GPL2 or above

"""
Kismet external helper API implementation

Protobuf based communication with the Kismet server for external tools interface,
datasource capture, etc.

Datasources are expanded in KismetDatasource.py
"""

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

class KismetExternalInterface(object):
    """ 
    External interface super-class
    """
    def __init__(self, infd = -1, outfd = -1, remote = None):
        """
        Initialize the external interface; interfaces launched by Kismet are 
        mapped to a pipe passed via --in-fd and --out-fd arguments; remote
        interfaces are initialized with a host:port

        :param infd: input FD, from --in-fd argument
        :param outfd: output FD, from --out-fd argument
        :param report: remote host:port, from --connect argument
        :return: nothing
        """

        self.infd = infd
        self.outfd = outfd

        self.cmdnum = 0

        fl = fcntl.fcntl(infd, fcntl.F_GETFL)
        fcntl.fcntl(infd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        fl = fcntl.fcntl(outfd, fcntl.F_GETFL)
        fcntl.fcntl(outfd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        self.wbuffer = ""
        self.rbuffer = ""

        self.bufferlock = threading.RLock()

        self.kill_ioloop = False

        self.last_pong = 0

        self.running = False

        self.http_auth_callback = None
        self.auth_token = None

        self.handlers = {}

        self.add_handler("HTTPAUTH", self.__handle_http_auth)
        self.add_handler("HTTPREQUEST", self.__handle_http_request)
        self.add_handler("PING", self.__handle_ping)
        self.add_handler("PONG", self.__handle_pong)
        self.add_handler("SHUTDOWN", self.__handle_shutdown)

        self.uri_handlers = {}

        self.MSG_INFO = kismet_pb2.MsgbusMessage.INFO
        self.MSG_ERROR = kismet_pb2.MsgbusMessage.ERROR
        self.MSG_ALERT = kismet_pb2.MsgbusMessage.ALERT
        self.MSG_FATAL = kismet_pb2.MsgbusMessage.FATAL

    def __adler32(self, data):
        if len(data) < 4:
            return 0

        s1 = 0
        s2 = 0

        last_i = 0

        for i in range(0, len(data) - 4, 4):
            s2 += 4 * (s1 + ord(data[i])) + 3 * ord(data[i + 1]) + 2 * ord(data[i + 2]) + ord(data[i + 3])
            s1 += ord(data[i + 0]) + ord(data[i + 1]) + ord(data[i + 2]) + ord(data[i + 3])
            last_i = i + 4

        for i in range(last_i, len(data)):
            s1 += ord(data[i])
            s2 += s1

        return ((s1 & 0xFFFF) + (s2 << 16)) & 0xFFFFFFFF

    def __io_loop(self):
        try:
            while not self.kill_ioloop:
                if not self.last_pong == 0 and time.time() - self.last_pong > 5:
                    raise RuntimeError("No PONG from remote system in 5 seconds")

                inputs = [ self.infd ]
                outputs = []

                self.bufferlock.acquire()
                try:
                    if len(self.wbuffer):
                        outputs = [ self.outfd ]
                finally:
                    self.bufferlock.release()

                (readable, writable, exceptional) = select.select(inputs, outputs, inputs, 1)

                if self.outfd in exceptional or self.infd in exceptional:
                    raise BufferError("Buffer error:  Socket closed")

                if self.outfd in outputs:
                    self.bufferlock.acquire()
                    try:
                        written = os.write(self.outfd, self.wbuffer)

                        if written == 0:
                            raise BufferError("Output connection closed")

                        self.wbuffer = self.wbuffer[written:]
                    except OSError as e:
                        if not e.errno == errno.EAGAIN:
                            raise BufferError("Output buffer error: {}".format(e))
                    finally:
                        self.bufferlock.release()

                if self.infd in inputs:
                    self.bufferlock.acquire()
                    try:
                        readdata = os.read(self.infd, 4096)

                        if len(readdata) == 0:
                            raise BufferError("Input connection closed")

                        self.rbuffer = self.rbuffer + readdata
                        self.__recv_packet()
                    except OSError as e:
                        if not e.errno == errno.EAGAIN:
                            raise BufferError("Input buffer error: {}".format(e))
                    finally:
                        self.bufferlock.release()
        finally:
            self.running = False

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
            print content.encode('hex')
            raise BufferError("Invalid checksum in packet header {} vs {}".format(calc_csum, checksum))

        cmd = kismet_pb2.Command()
        cmd.ParseFromString(content)

        if cmd.command in self.handlers:
            self.handlers[cmd.command](cmd.seqno, cmd.content)
        else:
            print "Unhandled", cmd.command

        self.rbuffer = self.rbuffer[12 + sz:]

    def start(self):
        """
        Start the main service loop; this handles input/out from the Kismet server
        and will call registered callbacks for functions.

        :return: None
        """

        self.running = True
        self.iothread = threading.Thread(target=self.__io_loop)
        self.iothread.start()

    def add_handler(self, command, handler):
        """
        Register a command handler; this handler will be called when a command
        is received.

        :param command: Command (string, case sensitive)
        :param handler: Handler function which will be called with (sequence number, payload)
        :return: None
        """
        self.handlers[command] = handler

    def add_uri_handler(self, method, uri, auth, handler):
        """
        Register a URI handler with Kismet; this will be called whenever that URI is 
        triggered on the Kismet REST interface.  A URI should be a complete path, and
        include the file extension.

        :param method: HTTP method (GET or POST)
        :param uri: Full URI
        :param auth: User login/authentication required?  (Bool)
        :param handler: Handler function, called with http_pb2.HttpRequest object)
        :return: None
        """

        if not method in self.uri_handlers:
            self.uri_handlers[method] = {}

        if not uri in self.uri_handlers[method]:
            self.uri_handlers[method][uri] = handler

        reguri = http_pb2.HttpRegisterUri()
        reguri.method = method
        reguri.uri = uri
        reguri.auth_required = auth

        self.write_ext_packet("HTTPREGISTERURI", reguri)

    def is_running(self):
        """
        Is the external interface service running?

        :return: boolean
        """
        return self.running

    def kill(self):
        """
        Shutdown the external interface service

        :return: None
        """
        self.bufferlock.acquire()
        try:
            self.kill_ioloop = True
        finally:
            self.bufferlock.release()

    def write_raw_packet(self, kedata):
        """
        Wrap a raw piece of data in a Kismet external interface frame and write it; 
        this data must be a serialized kismet_pb2.Command frame.

        :param kedata: Serialized kismet_pb2.Command data

        :return: None
        """
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
        """
        Generate a Kismet external interface command, frame, and transmit it.

        :param cmdtype: Command type string
        :param content: Command content, must be a serializable protobuf object

        :return: None
        """
        cp = kismet_pb2.Command()

        cp.command = cmdtype
        cp.seqno = self.cmdnum
        cp.content = content.SerializeToString()

        self.write_raw_packet(cp)

        self.cmdnum = self.cmdnum + 1

    def send_message(self, message, msgtype = kismet_pb2.MsgbusMessage.INFO):
        """
        Send a message which wil be displayed via the Kismet message bus and in the UI

        :param message: Message text
        :param msgtype: message type, one of MSG_INFO, _ERROR, _ALERT, _FATAL

        :return: None
        """
        msg = kismet_pb2.MsgbusMessage()
        msg.msgtext = message
        msg.msgtype = msgtype
        self.write_ext_packet("MESSAGE", msg)

    def send_ping(self):
        """
        Send a PING

        :return: None
        """
        if self.last_pong == 0:
            self.last_pong = time.time()

        ping = kismet_pb2.Ping()
        self.write_ext_packet("PING", ping)

    def __send_pong(self, seqno):
        pong = kismet_pb2.Pong()
        pong.ping_seqno = seqno
        self.write_ext_packet("PONG", pong)

    def request_http_auth(self, callback = None):
        """
        Request Kismet generate a HTTP session token; this token will be sent
        via a HTTPAUTH message and the callback function will be triggered.

        :param callback: Function to be called when an AUTH result is returned,
        called with no parameters.

        :return: None
        """
        self.http_auth_callback = callback
        auth = http_pb2.HttpAuthTokenRequest()
        self.write_ext_packet("HTTPAUTHREQ", auth)

    def __handle_http_auth(self, seqno, packet):
        auth = http_pb2.HttpAuthToken()
        auth.ParseFromString(packet)
        self.auth_token = auth.token

        if not self.http_auth_callback is None:
            self.http_auth_callback()

    def __handle_http_request(self, seqno, packet):
        request = http_pb2.HttpRequest()
        request.ParseFromString(packet)

        if not request.method in self.uri_handlers:
            raise RuntimeError("No URI handler registered for request {} {}".format(request.method, request.uri))

        if not request.uri in self.uri_handlers[request.method]:
            raise RuntimeError("No URI handler registered for request {} {}".format(request.method, request.uri))

        self.uri_handlers[request.method][request.uri](self, request)

    def send_http_response(self, req_id, data = "", resultcode = 200, stream = False, finished = True):
        """
        Send a HTTP response; this populates a URI when triggered.

        Responses may include the entire data to be sent, or may be streamed (if stream = True).

        This may be called many times for the same req_id, to send large results, or streaming
        results.

        A response is not closed until finished = True.

        :param req_id: HTTP request ID, provided in the HttpRequest message.  This must be sent with
        every response which is part of the same request.
        :param data: HTTP data to be sent.  This may be broken up into multiple response objects
        automatically.
        :param resultcode: HTTP result code; the result code in the final response (finished = True)
        is sent as the final HTTP code.
        :param stream: This response is one of many in a stream, the connection will be held open
        until a send_http_response with finished = False
        """
        resp = http_pb2.HttpResponse()

        # Set the response
        resp.req_id = req_id

        # Break the data into chunks and send each chunk as part of the response
        for block in range(0, len(data), 1024):
            resp.content = data[block:block+1024]
            self.write_ext_packet("HTTPRESPONSE", resp)

        # Do we finish it up?
        if not stream or (stream and finished):
            resp.content = ""
            resp.resultcode = resultcode
            resp.close_response = True
            self.write_ext_packet("HTTPRESPONSE", resp)

    def __handle_ping(self, seqno, packet):
        ping = kismet_pb2.Ping()
        ping.ParseFromString(packet)

        self.__send_pong(seqno)

    def __handle_pong(self, seqno, packet):
        pong = kismet_pb2.Pong()
        pong.ParseFromString(packet)

        self.last_pong = time.time()

    def __handle_shutdown(self, seqno, packet):
        shutdown = kismet_pb2.Shutdown()
        shutdown.ParseFromString(packet)
        self.kill()

