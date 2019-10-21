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

from __future__ import print_function

import asyncio
import errno
import fcntl
import os
import select
import signal
import socket
import struct
import sys
import threading
import traceback
import time

import google.protobuf

if not '__version__' in dir(google.protobuf) and sys.version_info > (3, 0):
    print("It looks like you have Python3 but a very old protobuf library, these are ")
    print("not compatible; please update to python3-protobuf >= 3.0.0")
    sys.exit(1)

from . import kismet_pb2
from . import http_pb2
from . import datasource_pb2

__version__ = "2019.09.03"

class ExternalInterface(object):
    """ 
    External interface super-class
    """
    def __init__(self, infd=-1, outfd=-1, remote=None):
        """
        Initialize the external interface; interfaces launched by Kismet are 
        mapped to a pipe passed via --in-fd and --out-fd arguments; remote
        interfaces are initialized with a host:port

        :param infd: input FD, from --in-fd argument
        :param outfd: output FD, from --out-fd argument
        :param remote: remote host:port, from --connect argument
        :return: nothing
        """

        self.loop = asyncio.get_event_loop()

        # Core task for forced cancelling
        self.main_io_task = None

        # Any additional tasks we cancel as we exit
        self.additional_tasks = []

        # Any additional functions we call as we exit
        self.exit_callbacks = []

        self.infd = infd
        self.outfd = outfd
        self.remote = remote
        self.cmdnum = 0
        self.iothread = None

        self.debug = False

        self.rbuffer = bytearray()

        self.graceful_spindown = False
        self.kill_ioloop = False

        self.last_pong = 0

        self.running = False

        self.http_auth_callback = None
        self.auth_token = None

        self.errorcb = None

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

    async def __async_open_fds(self):
        try:
            r_file = os.fdopen(self.infd, 'rb')
            w_file = os.fdopen(self.outfd, 'wb')

            reader = asyncio.StreamReader(loop=self.loop)
            r_protocol = asyncio.StreamReaderProtocol(reader)

            await self.loop.connect_read_pipe(lambda: r_protocol, r_file)

            w_transport, w_protocol = await self.loop.connect_write_pipe(asyncio.streams.FlowControlMixin, w_file)

            writer = asyncio.StreamWriter(transport=w_transport, reader=None, loop=self.loop, protocol=w_protocol)

            return reader, writer
        except Exception as e:
            print("Failed to open file descriptor pair:", e, file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            self.kill()

    async def __async_open_remote(self, remote):
        try:
            eq = remote.find(":")

            if eq == -1:
                raise RuntimeError("Expected host:port for remote")

            self.remote_host = remote[:eq]
            self.remote_port = int(remote[eq+1:])

            if self.debug:
                print("Opening connection to remote host {}:{}".format(self.remote_host, self.remote_port))

            reader, writer = await asyncio.open_connection(self.remote_host, self.remote_port)

            if self.debug:
                print("Remote connection established.")

            return reader, writer
        except Exception as e:
            print("Failed to connect to remote host:", e, file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            self.kill()

    @staticmethod
    def adler32(data):
        """
        Compute an adler32 checksum

        :param data: Data to be checksummed

        :return: uint32 adler32 checksum
        """
        if len(data) < 4:
            return 0

        s1 = 0
        s2 = 0

        last_i = 0

	# Handle both str and bytearray for when we checksum the name of devices
        if type(data) == type(""):
            for i in range(0, len(data) - 4, 4):
                s2 += 4 * (s1 + ord(data[i])) + 3 * ord(data[i + 1]) + 2 * ord(data[i + 2]) + ord(data[i + 3])
                s1 += ord(data[i + 0]) + ord(data[i + 1]) + ord(data[i + 2]) + ord(data[i + 3])
                last_i = i + 4

            for i in range(last_i, len(data)):
                s1 += ord(data[i])
                s2 += s1
        else:
            for i in range(0, len(data) - 4, 4):
                s2 += 4 * (s1 + data[i]) + 3 * data[i + 1] + 2 * data[i + 2] + data[i + 3]
                s1 += data[i + 0] + data[i + 1] + data[i + 2] + data[i + 3]
                last_i = i + 4

            for i in range(last_i, len(data)):
                s1 += data[i]
                s2 += s1


        return ((s1 & 0xFFFF) + (s2 << 16)) & 0xFFFFFFFF

    async def __io_loop(self):
        # A much simplified rx io loop using asyncio; we look to see if we're
        # shutting down 
        try:
            while not self.kill_ioloop:
                if not self.last_pong == 0 and time.time() - self.last_pont > 5:
                    raise RuntimeError("No PONG from Kismet in 5 seconds")

                if self.graceful_spindown:
                    await self.ext_writer.drain()
                    self.kill_ioloop = True
                    return

                # Read a chunk of data, append it to our buffer
                readdata = await self.ext_reader.read(4096)

                if len(readdata) == 0:
                    raise BufferError("Kismet connection lost")

                self.rbuffer.extend(readdata)

                # Process the packet buffer and see if we've read enough to
                # form a full packet
                self.__recv_packet()
        except Exception as e:
            print("FATAL:  Encountered an error writing to Kismet", e, file=sys.stderr)
            self.kill()
            return
        finally:
            self.running = False
            self.kill()

        return

    def __recv_packet(self):
        if len(self.rbuffer) < 12:
            return

        (signature, checksum, sz) = struct.unpack("!III", self.rbuffer[:12])

        if not signature == 0xDECAFBAD:
            raise BufferError("Invalid signature in packet header")

        if len(self.rbuffer) < 12 + sz:
            return

        content = self.rbuffer[12:(12 + sz)]

        calc_csum = ExternalInterface.adler32(content)

        if not calc_csum == checksum:
            print(content.encode('hex'))
            raise BufferError("Invalid checksum in packet header {} vs {}".format(calc_csum, checksum))

        if not '__version__' in dir(google.protobuf):
            content = str(content)

        cmd = kismet_pb2.Command()
        cmd.ParseFromString(content)

        if self.debug:
            print("KISMETEXTERNAL - CMD {}".format(cmd.command))

        if cmd.command in self.handlers:
            self.handlers[cmd.command](cmd.seqno, cmd.content)
        else:
            print("Unhandled", cmd.command)

        self.rbuffer = self.rbuffer[12 + sz:]

    @staticmethod
    def get_etc():
        """
        Get the etc directory from Kismet by querying the KISMET_ETC env variable

        :return: Path to etc (or blank)
        """
        if "KISMET_ETC" in os.environ:
            return os.environ["KISMET_ETC"]

        return ""

    async def __asyncio_connect(self):
        """
        Connect to the input and output generators/sinks

        :return: None
        """

        if self.infd is not None and self.infd >= 0 and self.outfd is not None and self.outfd >= 0:
            self.ext_reader, self.ext_writer = await self.__async_open_fds()
        elif self.remote is not None:
            if self.debug:
                print("asyncio building connection to remote", self.remote)

            self.ext_reader, self.ext_writer = await self.__async_open_remote(self.remote)
        else:
            raise RuntimeError("Expected descriptor pair or remote connection")


    def run(self):
        """
        Enter a blocking loop until the IO exits
        """

        try:
            # Bring up the IO loop task; it's the only task we absolutely care 
            # about.  Other tasks can come and go, if this one dies, we have 
            # to shut down.

            # From this point onwards we exist inside this asyncio wait

            self.loop.add_signal_handler(signal.SIGINT, self.kill)
            self.loop.add_signal_handler(signal.SIGTERM, self.kill)
            self.loop.add_signal_handler(signal.SIGQUIT, self.kill)

            self.main_io_task = self.loop.create_task(self.__io_loop())

            if self.debug:
                print("kismetexternal api running async loop forever")

            self.loop.run_forever()

            self.running = False

            self.kill()
        except Exception as e:
            if self.running:
                self.kill()

    def start(self):
        """
        Shim around async await
        """

        self.loop.run_until_complete(self.__asyncio_connect())

        return

    def add_task(self, task, args = []):
        """
        Create a task from the provided async function, associating it
        with the main loop and returning the task record.  The task will
        be automatically cancelled when the external interface exits

        :return: asyncio task
        """
        try:
            t = self.loop.create_task(task(*args))
            self.additional_tasks.append(t)
            return t
        except Exception as e:
            print("Failed to add asyncio task:", e)
            traceback.print_exc(file=sys.stderr)
            self.kill()

    def add_exit_callback(self, callback):
        self.exit_callbacks.append(callback)

    def get_loop(self):
        return self.loop

    def add_handler(self, command, handler):
        """
        Register a command handler; this handler will be called when a command
        is received.

        :param command: Command (string, case sensitive)
        :param handler: Handler function which will be called with (sequence number, payload)
        :return: None
        """
        self.handlers[command] = handler

    def add_uri_handler(self, method, uri, handler):
        """
        Register a URI handler with Kismet; this will be called whenever that URI is 
        triggered on the Kismet REST interface.  A URI should be a complete path, and
        include the file extension.

        :param method: HTTP method (GET or POST)
        :param uri: Full URI
        :param handler: Handler function, called with http_pb2.HttpRequest object)
        :return: None
        """

        if method not in self.uri_handlers:
            self.uri_handlers[method] = {}

        if uri not in self.uri_handlers[method]:
            self.uri_handlers[method][uri] = handler

        reguri = http_pb2.HttpRegisterUri()
        reguri.method = method
        reguri.uri = uri

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
        self.kill_ioloop = True
      
        if self.debug:
            print("cancelling tasks", len(self.additional_tasks))
        [task.cancel() for task in self.additional_tasks]

        if self.debug:
            print("calling exit functions", len(self.exit_callbacks))
        [cb() for cb in self.exit_callbacks]

        if not self.main_io_task == None:
            self.main_io_task.cancel()

        # Try to mask python 3.5 signal handling bugs, as per
        # https://github.com/python/asyncio/issues/396
        try:
            self.loop.stop()
        except TypeError:
            pass

    def spindown(self):
        """
        Shutdown the interface service once all pending data has been written

        :return: None
        """
        self.graceful_spindown = True
        try:
            self.loop.run_until_complete(self.ext_writer.drain())
        except Exception as e:
            # Silently ignore any errors draining, we just need to get out and die
            pass

        self.kill()

    def write_raw_packet(self, kedata):
        """
        Wrap a raw piece of data in a Kismet external interface frame and write it; 
        this data must be a serialized kismet_pb2.Command frame.

        :param kedata: Serialized kismet_pb2.Command data

        :return: None
        """

        try:
            signature = 0xDECAFBAD
            serial = bytearray(kedata.SerializeToString())

            checksum = ExternalInterface.adler32(serial)
            length = len(serial)

            packet = bytearray(struct.pack("!III", signature, checksum, length))

            # Drop it on the asyncio writer and queue it to go out
            self.ext_writer.write(packet)
            self.ext_writer.write(serial)
            self.ext_writer.drain()
        except Exception as e:
            # If we failed a low-level write we're just screwed, exit
            print("FATAL:  Encountered error writing to kismet: ", e, file=sys.stderr)
            self.kill()

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

    def send_message(self, message, msgtype=kismet_pb2.MsgbusMessage.INFO):
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

    def request_http_auth(self, callback=None):
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

        if self.http_auth_callback is not None:
            self.http_auth_callback()

    def __handle_http_request(self, seqno, packet):
        request = http_pb2.HttpRequest()
        request.ParseFromString(packet)

        if request.method not in self.uri_handlers:
            raise RuntimeError("No URI handler registered for request {} {}".format(request.method, request.uri))

        if request.uri not in self.uri_handlers[request.method]:
            raise RuntimeError("No URI handler registered for request {} {}".format(request.method, request.uri))
        self.uri_handlers[request.method][request.uri](self, request)

    def send_http_response(self, req_id, data="", resultcode=200, stream=False, finished=True):
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
        :param finished: This is the last response of many in a stream, the connection will be closed.
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
        shutdown = kismet_pb2.ExternalShutdown()
        shutdown.ParseFromString(packet)
        self.kill()


class Datasource(ExternalInterface):
    """ 
    Datasource implementation
    """
    def __init__(self, infd=-1, outfd=-1, remote=None):
        super(Datasource, self).__init__(infd=infd, outfd=outfd, remote=remote)

        self.listinterfaces = None
        self.probesource = None
        self.opensource = None
        self.configuresource = None

        self.add_handler("KDSCONFIGURE", self.__handle_kds_configure)
        self.add_handler("KDSLISTINTERFACES", self.__handle_kds_listinterfaces)
        self.add_handler("KDSOPENSOURCE", self.__handle_kds_opensource)
        self.add_handler("KDSPROBESOURCE", self.__handle_kds_probesource)

    @staticmethod
    def make_uuid(driver, address):
        """
        Generate a UUID

        :param driver: Driver component, will be hashed
        :param address: Address component, must be 6 bytes of hex (12 characters)

        :return: UUID string
        """
        driverhex = "{:02X}".format(ExternalInterface.adler32(bytearray(driver, 'utf-8')))
        return "{}-0000-0000-0000-{}".format(driverhex[:8], address[:12])

    def set_listinterfaces_cb(self, cb):
        """
        Set callback to support datasource listsources command

        :param cb: Callback function, taking seqno, source definition, option map

        :return: None
        """
        self.listinterfaces = cb

    def set_probesource_cb(self, cb):
        """
        Set callback for datasource probing

        :param cb: Callback function, taking seqno, source definition, option map

        :return: None
        """
        self.probesource = cb

    def set_opensource_cb(self, cb):
        """
        Set callback for datasource opening

        :param cb: Callback function, taking seqno, source definition, option map

        :return: None
        """
        self.opensource = cb

    def set_configsource_cb(self, cb):
        """
        Set callback for source configuring

        :param cb: Callback function, taking seqno and datasource_pb2.Configure record

        :return: None
        """
        self.configuresource = cb

    @staticmethod
    def parse_definition(definition):
        """
        Parse a Kismet definition into a (source, optionsmap) tuple

        :param definition: Kismet source definition

        :return: (source, options{} dictionary) as tuple
        """
        options = {}
    
        colon = definition.find(':')
    
        if colon == -1:
            return definition, {}
    
        source = definition[:colon]
        right = definition[colon + 1:]
    
        while len(right):
            eqpos = right.find('=')
            if eqpos == -1:
                return None, None
    
            key = right[:eqpos]
            right = right[eqpos + 1:]
    
            # If we're quoted
            if right[0] == '"':
                right = right[1:]
                endq = right.find('"')
    
                if endq == -1:
                    return None, None
    
                val = right[:endq]
                options[key] = val
                right = right[endq + 1:]
            else:
                endcomma = right.find(',')

                if endcomma == -1:
                    endcomma = len(right)
    
                val = right[:endcomma]
                options[key] = val
                right = right[endcomma + 1:]
    
        return source, options

    def __handle_kds_configure(self, seqno, packet):
        conf = datasource_pb2.Configure()
        conf.ParseFromString(packet)

        if self.configuresource is None:
            self.send_datasource_configure_report(seqno, success=False,
                                                  message="helper does not support source configuration")
            self.spindown()
            return
           
        try:
            opts = self.configuresource(seqno, conf)
        except Exception as e:
            print("Unhandled exception in configuresource callback", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            self.send_datasource_configure_report(seqno, success=False,
                    message="unhandled exception {} in configuresource callback".format(e))
            self.spindown()
            return

        
        if opts is None:
            self.send_datasource_configure_report(seqno, success=False,
                                                  message="helper does not support source configuration")
            self.spindown()
            return

        self.send_datasource_configure_report(seqno, **opts)

    def __handle_kds_opensource(self, seqno, packet):
        opensource = datasource_pb2.OpenSource()
        opensource.ParseFromString(packet)

        (source, options) = self.parse_definition(opensource.definition)

        if self.opensource is None:
            self.send_datasource_open_report(seqno, success=False,
                                             message="helper does not support opening sources")
            self.spindown()
            return

        try:
            opts = self.opensource(source, options)
        except Exception as e:
            print("Unhandled exception in opensource callback", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            self.send_datasource_open_report(seqno, success=False,
                    message="unhandled exception {} in opensource callback".format(e))
            self.spindown()
            return


        if opts is None:
            self.send_datasource_open_report(seqno, success=False,
                                             message="helper does not support opening sources")

        self.send_datasource_open_report(seqno, **opts)

    def __handle_kds_probesource(self, seqno, packet):
        probe = datasource_pb2.ProbeSource()
        probe.ParseFromString(packet)

        (source, options) = self.parse_definition(probe.definition)

        if source is None:
            self.send_datasource_probe_report(seqno, success=False)
            self.spindown()
            return

        if self.probesource is None:
            self.send_datasource_probe_report(seqno, success=False)
            self.spindown()
            return

        try:
            opts = self.probesource(source, options)
        except Exception as e:
            print("Unhandled exception in probesource callback", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            self.send_probesource_data_report(seqno, success=False)
            self.spindown()
            return

        if opts is None:
            self.send_datasource_probe_report(seqno, success=False)
            self.spindown()
            return

        self.send_datasource_probe_report(seqno, **opts)

        self.spindown()

    def __handle_kds_listinterfaces(self, seqno, packet):
        cmd = datasource_pb2.ListInterfaces()
        cmd.ParseFromString(packet)

        if self.listinterfaces is None:
            self.send_datasource_interfaces_report(seqno, success=True)
            self.spindown()
            return

        try:
            self.listinterfaces(seqno)
        except Exception as e:
            print("Unhandled exception in listinterfaces callback", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            self.send_datasource_interfaces_report(seqno, success=True)
            self.spindown()
            return

        self.spindown()

    def send_datasource_error_report(self, seqno=0, message=None):
        """
        When acting as a Kismet datasource, send a source error.  This can be in response
        to a specific command, or a runtime failure.

        :param seqno: Command which failed, or 0
        :param message: Optional user message

        :return: None
        """

        report = datasource_pb2.ErrorReport()

        report.success.success = False
        report.success.seqno = seqno

        if message is not None:
            report.message.msgtext = message
            report.message.msgtype = self.MSG_ERROR

        self.write_ext_packet("KDSERROR", report)

        # self.spindown()

    def send_datasource_interfaces_report(self, seqno, interfaces=None, success=True, message=None):
        """
        When acting as a Kismet datasource, send a list of supported interfaces.  This
        should be called from a child implementation of this class which implements the
        datasource_listinterfaces function.

        :param seqno: Sequence number of the interface list request
        :param interfaces: Array of datasource_pb.SubInterface responses
        :param success: Successful completion of request; a source with no interfaces is not
        a failure, and should return an empty interfaces list.
        :param message: Optional user message

        :return: None
        """
        report = datasource_pb2.InterfacesReport()

        report.success.success = success
        report.success.seqno = seqno

        if message is not None:
            report.message.msgtext = message
            if success:
                report.message.msgtype = self.MSG_INFO
            else:
                report.message.msgtype = self.MSG_ERROR

        if interfaces is not None:
            report.interfaces.extend(interfaces)

        self.write_ext_packet("KDSINTERFACESREPORT", report)

    def send_datasource_newsource(self, definition, sourcetype, uuid):
        """
        When acting as a Kismet datasource, via a remote TCP connection, datasources must
        tell Kismet the type of source to create via a Newsource command.

        :param definition: Source definition line
        :param sourcetype: Source driver type
        :param uuid: Source UUID

        :return: None
        """
        newsource = datasource_pb2.NewSource()

        newsource.definition = definition
        newsource.sourcetype = sourcetype
        newsource.uuid = uuid

        self.write_ext_packet("KDSNEWSOURCE", newsource)

    def send_datasource_configure_report(self, seqno, success=False, channel=None, hop_rate=None,
                                         hop_channels=None, spectrum=None, message=None,
                                         full_hopping=None, warning=None, **kwargs):
        """
        When acting as a Kismet datasource, send a response to a configuration request.  This
        is called with the response to the open datasource command.

        :param seqno: Sequence number of open source command
        :param success: Source configuration success
        :param channel: Optional source single-channel configuration
        :param hop_rate: Optional source hop speed, if hopping
        :param hop_channels: Optional vector of string channels, if hopping
        :param message: Optional message
        :param full_hopping: Optional full datasource_pb2.SubChanset
        :param warning: Optional warning text to be set in datasource detailed info
        :param spectrum: Optional spectral data
        :param kwargs: Unused additional arguments

        :return: None
        """

        report = datasource_pb2.ConfigureReport()

        report.success.success = success
        report.success.seqno = seqno

        if message:
            report.message.msgtext = message
            if success:
                report.message.msgtype = self.MSG_INFO
            else:
                report.message.msgtype = self.MSG_ERROR

        if hop_channels:
            report.hopping.channels.extend(hop_channels)

        if hop_rate:
            report.hopping.hop_rate = hop_rate

        if channel:
            report.channel.channel = channel

        if full_hopping:
            report.hopping.CopyFrom(full_hopping)

        if spectrum:
            report.spectrum.CopyFrom(spectrum)

        if warning:
            report.warning = warning

        self.write_ext_packet("KDSCONFIGUREREPORT", report)


    def send_datasource_open_report(self, seqno, success=False, dlt=0, capture_interface=None, channels=None,
                                    channel=None, hop_config=None, hardware=None, message=None, spectrum=None,
                                    uuid=None, warning=None, **kwargs):
        """
        When acting as a Kismet datasource, send a response to an open source request.  This is
        called with the response to the open datasource command.

        :param seqno: Sequence number of open source command
        :param success: Source open success
        :param dlt: DLT/Data link type of packets from source
        :param capture_interface: Optional interface for capture, if not the same as specified in open
        :param channels: Optional array of channel supported channels
        :param channel: Optional single channel source will tune to
        :param hop_config: datasource_pb2.SubChanhop record of initial hopping configuration
        :param hardware: Optional hardware/chipset information
        :param message: Optional user message
        :param spectrum: Optional datasource_pb2.SubSpecset initial spectrum configuration
        :param uuid: Optional UUID
        :param warning: Optional warning
        :param kwargs: Unused additional arguments

        :return: None
        """

        report = datasource_pb2.OpenSourceReport()

        report.success.success = success
        report.success.seqno = seqno

        if message is not None:
            report.message.msgtext = message
            if success:
                report.message.msgtype = self.MSG_INFO
            else:
                report.message.msgtype = self.MSG_ERROR

        if channels is not None:
            report.channels.channels.extend(channels)

        if channel is not None:
            report.channel.channel = channel

        if spectrum is not None:
            report.spectrum.CopyFrom(spectrum)

        if hardware is not None:
            report.hardware = hardware

        report.dlt = dlt

        if capture_interface is not None:
            report.capture_interface = capture_interface

        if hop_config is not None:
            report.hop_config.CopyFrom(hop_config)

        if uuid is not None:
            report.uuid = uuid

        if warning is not None:
            report.warning = warning

        self.write_ext_packet("KDSOPENSOURCEREPORT", report)

    def send_datasource_probe_report(self, seqno, success=False, message=None, channels=None, channel=None,
                                     spectrum=None, hardware=None, **kwargs):
        """
        When operating as a Kismet datasource, send a probe source report; this is used to
        determine the datasource driver.  This should be called by child implementations
        of this class from the datasource_probesource function.

        :param seqno: Sequence number of PROBESOURCE command
        :param success: Successful probing of source; sources which cannot be probed
        should return False here.
        :param message: Optional user message; typically sources should not need to send
        a message in a failure condition as they may be probing multiple source types.
        :param channels: Optional list of supported channels
        :param channel: Optional single supported channel
        :param spectrum: Optional datasource_pb2.SubSpecset spectrum support
        :param hardware: Optional hardware/chipset information
        :param **kwargs: Extraneous command options

        :return: None
        """

        report = datasource_pb2.ProbeSourceReport()

        report.success.success = success
        report.success.seqno = seqno

        if message is not None:
            report.message.msgtext = message
            if success:
                report.message.msgtype = self.MSG_INFO
            else:
                report.message.msgtype = self.MSG_ERROR

        if channels is not None:
            report.channels.channels.extend(channels)

        if channel is not None:
            report.channel.channel = channel

        if spectrum is not None:
            report.spectrum.CopyFrom(spectrum)

        if hardware is not None:
            report.hardware = hardware

        self.write_ext_packet("KDSPROBESOURCEREPORT", report)

    def send_datasource_warning_report(self, seqno, warning):
        """
        When operating as a Kismet datasource, set a warning message; this is shown in the
        Datasources display, and indicates a non-fatal but otherwise "bad" condition.

        :param seqno: (unused) sequence number
        :param warning: Warning message

        :return: None
        """

        report = datasource_pb2.WarningReport()
        report.warning = warning

        self.write_ext_packet("KDSWARNINGREPORT", report)

    def send_datasource_data_report(self, message=None, warning=None, full_gps=None, full_signal=None, full_packet=None,
                                    full_spectrum=None, full_json=None, full_buffer=None, **kwargs):
        """
        When operating as a Kismet datasource, send a data frame

        :param message: Optional message
        :param warning: Optional warning to be included in the datasource details
        :param full_gps: Optional full datasource_pb2.SubGps record
        :param full_signal: Optional full datasource_pb2.SubSignal record
        :param full_spectrum: Optional full datasource_pb2 SubSpectrum record
        :param full_packet: Optional full datasource_pb2.SubPacket record
        :param full_json: Optional JSON record
        :param full_buffer: Optional protobuf packed buffer

        :return: None
        """

        report = datasource_pb2.DataReport()

        if message is not None:
            report.message.msgtext = message
            report.message.msgtype = self.MSG_INFO

        if full_gps:
            report.gps.CopyFrom(full_gps)

        if full_signal:
            report.signal.CopyFrom(full_signal)

        if full_spectrum:
            report.signal.CopyFrom(full_spectrum)

        if full_packet:
            report.packet.CopyFrom(full_packet)

        if full_json:
            report.json.CopyFrom(full_json)

        if full_buffer:
            report.buffer.CopyFrom(full_buffer)

        if warning:
            report.warning = warning

        self.write_ext_packet("KDSDATAREPORT", report)
