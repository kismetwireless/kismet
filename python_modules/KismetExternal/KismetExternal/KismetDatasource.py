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
import datasource_pb2

class KismetDatasource(KismetExternalInterface):
    """ 
    Datasource implementation
    """
    def __init__(self, infd = -1, outfd = -1, remote = None):
        super(KismetDatasource, self).__init__(infd, outfd, remote)

        self.add_handler("KDSCONFIGURE", self.__handle_kds_configure)
        self.add_handler("KDSLISTINTERFACES", self.__handle_kds_listinterfaces)
        self.add_handler("KDSOPENSOURCE", self.__handle_kds_opensource)
        self.add_handler("KDSPROBESOURCE", self.__handle_kds_probesource)

    def __kds_parse_definition(self, definition):
        source = ""
        options = {}
    
        colon = definition.find(':')
    
        if colon == -1:
            return (definition, {})
    
        source = definition[:colon]
        right = definition[colon + 1:]
    
        while len(right):
            eqpos = right.find('=')
            if eqpos == -1:
                return (None, None)
    
            key = right[:eqpos]
            right = right[eqpos + 1:]
    
            print key, right
    
            # If we're quoted
            if right[0] == '"':
                right = right[1:]
                endq = right.find('"')
    
                if endq == -1:
                    return (None, None)
    
                val = right[:endq]
                options[key] = val
                right = right[endq + 1:]
            else:
                endcomma = right.find(',')
    
                val = right[:endcomma]
                options[key] = val
                right = right[endcomma + 1:]
    
        return (source, options)


    def __handle_kds_configure(self, seqno, packet):
        conf = datasource_pb2.Configure()
        conf.ParseFromString(packet)

        try:
            self.datasource_configure(seqno, conf)
        except AttributeError:
            self.send_datasource_configure_response(seqno, success = False, message = "helper does not support source configuration")

    def __handle_kds_opensource(self, seqno, packet):
        opensource = datasource_pb2.OpenSource()
        opensource.ParseFromString(packet)

        (source, options) = self.__kds_parse_definition(opensource.definition)

        try:
            self.datasoure_opensource(seqno, source, options)
        except AttributeError:
            self.send_datasource_open_report(seqno, success = False, message = "helper does not support opening sources")

    def __handle_kds_probesource(self, seqno, packet):
        probe = datasource_pb2.ProbeSource()
        probe.ParseFromString(packet)

        (source, options) = self.__kds_parse_definition(probe.definition)

        if source == None:
            self.send_datasource_probe_report(seqno, success = False)
            return

        try:
            self.datasource_probesource(seqno, source, options)
        except AttributeError:
            self.send_datasource_probe_report(seqno, success = False)

    def __handle_kds_listinterfaces(self, seqno, packet):
        cmd = datasource_pb2.ListInterfaces()
        cmd.ParseFromString(packet)

        try:
            self.datasource_listinterfaces(seqno)
        except AttributeError:
            self.send_datasource_interfaces_report(seqno, success = True)

    def send_datasource_error_report(self, seqno = 0, message = None):
        """
        When acting as a Kismet datasource, send a source error.  This can be in response
        to a specific command, or a runtime failure.

        :param seqno: Command which failed, or 0
        :param message: Optional user message

        :return: None
        """

        report = datasource_pb2.ErrorReport()

        report.success.success = success
        report.success.seqno = seqno

        if not message == None:
            report.message.msgtext = message
            if success:
                report.message.msgtype = self.MSG_INFO
            else:
                report.message.msgtype = self.MSG_ERROR

        self.write_ext_packet("KDSERROR", report)

    def send_datasource_interfaces_report(self, seqno, interfaces = [], success = True, message = None):
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

        if not message == None:
            report.message.msgtext = message
            if success:
                report.message.msgtype = self.MSG_INFO
            else:
                report.message.msgtype = self.MSG_ERROR

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

    def send_datasource_open_report(self, seqno, success = False, dlt = 0, capture_interface = None, channels = [], channel = None, hop_config = None, hardware = None, message = None, spectrum = None, uuid = None, warning = None):
        """
        When acting as a Kismet datasource, send a response to an open source request.  This
        should be called from a child implementation of this class which implements the
        datasource_opensource function.

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

        :return: None
        """

        report = datasource_pb2.OpenSourceReport()

        report.success.success = success
        report.success.seqno = seqno

        if not message == None:
            report.message.msgtext = message
            if success:
                report.message.msgtype = self.MSG_INFO
            else:
                report.message.msgtype = self.MSG_ERROR

        report.channels.channels.extend(channels)

        if not channel == None:
            report.channel.channel = channel

        if not spectrum == None:
            report.spectrum.CopyFrom(spectrum)

        if not hardware == None:
            report.hardware = hardware

        report.dlt = dlt

        if not capture_interface == None:
            report.capture_interface = capture_interface

        if not hop_config == None:
            report.hop_config.CopyFrom(hop_config)

        if not uuid == None:
            report.uuid = uuid

        if not warning == None:
            report.warning = warning

        self.write_ext_packet("KDSOPENSOURCEREPORT", report)

    def send_datasource_probe_report(self, seqno, success = False, message = None, channels = [], channel = None, spectrum = None, hardware = None):
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

        :return: None
        """

        report = datasource_pb2.ProbeSourceReport()

        report.success.success = success
        report.success.seqno = seqno

        if not message == None:
            report.message.msgtext = message
            if success:
                report.message.msgtype = self.MSG_INFO
            else:
                report.message.msgtype = self.MSG_ERROR

        report.channels.channels.extend(channels)

        if not channel == None:
            report.channel.channel = channel

        if not spectrum == None:
            report.spectrum.CopyFrom(spectrum)

        if not hardware == None:
            report.hardware = hardware

        self.write_ext_packet("KDSPROBESOURCEREPORT", report)

    def send_datasource_warning_report(self, seqno, warning):
        """
        When operating as a Kismet datasource, set a warning message; this is shown in the
        Datasources display, and indicates a non-fatal but otherwise "bad" condition.

        :param warning: Warning message

        :return: None
        """

        report = datasource_pb2.WarningReport()
        report.warning = warning

        self.write_ext_packet("KDSWARNINGREPORT", report)

