#!/usr/bin/env python3

# Directly derived from Killerzee, https://github.com/joswr1ght/killerzee

import sys
import binascii
import signal
import traceback
import KismetRest
import argparse
import json

from rflib import *

PREAMBLE="01"*8
SFD="11110000"

# Taken from http://wiki.micasaverde.com/index.php/ZWave_Command_Classes
COMMAND_CLASS_NO_OPERATION = 0x00 
COMMAND_CLASS_BASIC = 0x20  
COMMAND_CLASS_CONTROLLER_REPLICATION = 0x21  
COMMAND_CLASS_APPLICATION_STATUS = 0x22  
COMMAND_CLASS_ZIP_SERVICES = 0x23  
COMMAND_CLASS_ZIP_SERVER = 0x24  
COMMAND_CLASS_SWITCH_BINARY = 0x25  
COMMAND_CLASS_SWITCH_MULTILEVEL = 0x26  
COMMAND_CLASS_SWITCH_MULTILEVEL_V2 = 0x26  
COMMAND_CLASS_SWITCH_ALL = 0x27  
COMMAND_CLASS_SWITCH_TOGGLE_BINARY = 0x28  
COMMAND_CLASS_SWITCH_TOGGLE_MULTILEVEL = 0x29  
COMMAND_CLASS_CHIMNEY_FAN = 0x2A  
COMMAND_CLASS_SCENE_ACTIVATION = 0x2B  
COMMAND_CLASS_SCENE_ACTUATOR_CONF = 0x2C  
COMMAND_CLASS_SCENE_CONTROLLER_CONF = 0x2D  
COMMAND_CLASS_ZIP_CLIENT = 0x2E  
COMMAND_CLASS_ZIP_ADV_SERVICES = 0x2F  
COMMAND_CLASS_SENSOR_BINARY = 0x30  
COMMAND_CLASS_SENSOR_MULTILEVEL = 0x31  
COMMAND_CLASS_SENSOR_MULTILEVEL_V2 = 0x31  
COMMAND_CLASS_METER = 0x32  
COMMAND_CLASS_ZIP_ADV_SERVER = 0x33  
COMMAND_CLASS_ZIP_ADV_CLIENT = 0x34  
COMMAND_CLASS_METER_PULSE = 0x35  
COMMAND_CLASS_METER_TBL_CONFIG = 0x3C  
COMMAND_CLASS_METER_TBL_MONITOR = 0x3D  
COMMAND_CLASS_METER_TBL_PUSH = 0x3E  
COMMAND_CLASS_THERMOSTAT_HEATING = 0x38  
COMMAND_CLASS_THERMOSTAT_MODE = 0x40  
COMMAND_CLASS_THERMOSTAT_OPERATING_STATE = 0x42  
COMMAND_CLASS_THERMOSTAT_SETPOINT = 0x43  
COMMAND_CLASS_THERMOSTAT_FAN_MODE = 0x44  
COMMAND_CLASS_THERMOSTAT_FAN_STATE = 0x45  
COMMAND_CLASS_CLIMATE_CONTROL_SCHEDULE = 0x46  
COMMAND_CLASS_THERMOSTAT_SETBACK = 0x47  
COMMAND_CLASS_DOOR_LOCK_LOGGING = 0x4C  
COMMAND_CLASS_SCHEDULE_ENTRY_LOCK = 0x4E  
COMMAND_CLASS_BASIC_WINDOW_COVERING = 0x50  
COMMAND_CLASS_MTP_WINDOW_COVERING = 0x51  
COMMAND_CLASS_MULTI_CHANNEL_V2 = 0x60  
COMMAND_CLASS_MULTI_INSTANCE = 0x60  
COMMAND_CLASS_DOOR_LOCK = 0x62  
COMMAND_CLASS_USER_CODE = 0x63  
COMMAND_CLASS_CONFIGURATION = 0x70   
COMMAND_CLASS_CONFIGURATION_V2 = 0x70   
COMMAND_CLASS_ALARM = 0x71   
COMMAND_CLASS_MANUFACTURER_SPECIFIC = 0x72   
COMMAND_CLASS_POWERLEVEL = 0x73   
COMMAND_CLASS_PROTECTION = 0x75   
COMMAND_CLASS_PROTECTION_V2 = 0x75   
COMMAND_CLASS_LOCK = 0x76   
COMMAND_CLASS_NODE_NAMING = 0x77   
COMMAND_CLASS_FIRMWARE_UPDATE_MD = 0x7A   
COMMAND_CLASS_GROUPING_NAME = 0x7B   
COMMAND_CLASS_REMOTE_ASSOCIATION_ACTIVATE = 0x7C   
COMMAND_CLASS_REMOTE_ASSOCIATION = 0x7D   
COMMAND_CLASS_BATTERY = 0x80   
COMMAND_CLASS_CLOCK = 0x81   
COMMAND_CLASS_HAIL = 0x82   
COMMAND_CLASS_WAKE_UP = 0x84   
COMMAND_CLASS_WAKE_UP_V2 = 0x84   
COMMAND_CLASS_ASSOCIATION = 0x85   
COMMAND_CLASS_ASSOCIATION_V2 = 0x85   
COMMAND_CLASS_VERSION = 0x86   
COMMAND_CLASS_INDICATOR = 0x87   
COMMAND_CLASS_PROPRIETARY = 0x88   
COMMAND_CLASS_LANGUAGE = 0x89   
COMMAND_CLASS_TIME = 0x8A   
COMMAND_CLASS_TIME_PARAMETERS = 0x8B   
COMMAND_CLASS_GEOGRAPHIC_LOCATION = 0x8C   
COMMAND_CLASS_COMPOSITE = 0x8D   
COMMAND_CLASS_MULTI_CHANNEL_ASSOCIATION_V2 = 0x8E   
COMMAND_CLASS_MULTI_INSTANCE_ASSOCIATION = 0x8E   
COMMAND_CLASS_MULTI_CMD = 0x8F   
COMMAND_CLASS_ENERGY_PRODUCTION = 0x90   
COMMAND_CLASS_MANUFACTURER_PROPRIETARY = 0x91   
COMMAND_CLASS_SCREEN_MD = 0x92   
COMMAND_CLASS_SCREEN_MD_V2 = 0x92   
COMMAND_CLASS_SCREEN_ATTRIBUTES = 0x93   
COMMAND_CLASS_SCREEN_ATTRIBUTES_V2 = 0x93   
COMMAND_CLASS_SIMPLE_AV_CONTROL = 0x94   
COMMAND_CLASS_AV_CONTENT_DIRECTORY_MD = 0x95   
COMMAND_CLASS_AV_RENDERER_STATUS = 0x96   
COMMAND_CLASS_AV_CONTENT_SEARCH_MD = 0x97   
COMMAND_CLASS_SECURITY = 0x98   
COMMAND_CLASS_AV_TAGGING_MD = 0x99   
COMMAND_CLASS_IP_CONFIGURATION = 0x9A   
COMMAND_CLASS_ASSOCIATION_COMMAND_CONFIGURATION = 0x9B   
COMMAND_CLASS_SENSOR_ALARM = 0x9C   
COMMAND_CLASS_SILENCE_ALARM = 0x9D   
COMMAND_CLASS_SENSOR_CONFIGURATION = 0x9E   
COMMAND_CLASS_MARK = 0xEF   
COMMAND_CLASS_NON_INTEROPERABLE = 0xF0    

COMMAND_CLASSES = {
    COMMAND_CLASS_NO_OPERATION: "COMMAND_CLASS_NO_OPERATION",
    COMMAND_CLASS_BASIC: "COMMAND_CLASS_BASIC",
    COMMAND_CLASS_CONTROLLER_REPLICATION: "COMMAND_CLASS_CONTROLLER_REPLICATION",
    COMMAND_CLASS_APPLICATION_STATUS: "COMMAND_CLASS_APPLICATION_STATUS",
    COMMAND_CLASS_ZIP_SERVICES: "COMMAND_CLASS_ZIP_SERVICES",
    COMMAND_CLASS_ZIP_SERVER: "COMMAND_CLASS_ZIP_SERVER",
    COMMAND_CLASS_SWITCH_BINARY: "COMMAND_CLASS_SWITCH_BINARY",
    COMMAND_CLASS_SWITCH_MULTILEVEL: "COMMAND_CLASS_SWITCH_MULTILEVEL",
    COMMAND_CLASS_SWITCH_MULTILEVEL_V2: "COMMAND_CLASS_SWITCH_MULTILEVEL_V2",
    COMMAND_CLASS_SWITCH_ALL: "COMMAND_CLASS_SWITCH_ALL",
    COMMAND_CLASS_SWITCH_TOGGLE_BINARY: "COMMAND_CLASS_SWITCH_TOGGLE_BINARY",
    COMMAND_CLASS_SWITCH_TOGGLE_MULTILEVEL: "COMMAND_CLASS_SWITCH_TOGGLE_MULTILEVEL",
    COMMAND_CLASS_CHIMNEY_FAN: "COMMAND_CLASS_CHIMNEY_FAN",
    COMMAND_CLASS_SCENE_ACTIVATION: "COMMAND_CLASS_SCENE_ACTIVATION",
    COMMAND_CLASS_SCENE_ACTUATOR_CONF: "COMMAND_CLASS_SCENE_ACTUATOR_CONF",
    COMMAND_CLASS_SCENE_CONTROLLER_CONF: "COMMAND_CLASS_SCENE_CONTROLLER_CONF",
    COMMAND_CLASS_ZIP_CLIENT: "COMMAND_CLASS_ZIP_CLIENT",
    COMMAND_CLASS_ZIP_ADV_SERVICES: "COMMAND_CLASS_ZIP_ADV_SERVICES",
    COMMAND_CLASS_SENSOR_BINARY: "COMMAND_CLASS_SENSOR_BINARY",
    COMMAND_CLASS_SENSOR_MULTILEVEL: "COMMAND_CLASS_SENSOR_MULTILEVEL",
    COMMAND_CLASS_SENSOR_MULTILEVEL_V2: "COMMAND_CLASS_SENSOR_MULTILEVEL_V2",
    COMMAND_CLASS_METER: "COMMAND_CLASS_METER",
    COMMAND_CLASS_ZIP_ADV_SERVER: "COMMAND_CLASS_ZIP_ADV_SERVER",
    COMMAND_CLASS_ZIP_ADV_CLIENT: "COMMAND_CLASS_ZIP_ADV_CLIENT",
    COMMAND_CLASS_METER_PULSE: "COMMAND_CLASS_METER_PULSE",
    COMMAND_CLASS_METER_TBL_CONFIG: "COMMAND_CLASS_METER_TBL_CONFIG",
    COMMAND_CLASS_METER_TBL_MONITOR: "COMMAND_CLASS_METER_TBL_MONITOR",
    COMMAND_CLASS_METER_TBL_PUSH: "COMMAND_CLASS_METER_TBL_PUSH",
    COMMAND_CLASS_THERMOSTAT_HEATING: "COMMAND_CLASS_THERMOSTAT_HEATING",
    COMMAND_CLASS_THERMOSTAT_MODE: "COMMAND_CLASS_THERMOSTAT_MODE",
    COMMAND_CLASS_THERMOSTAT_OPERATING_STATE: "COMMAND_CLASS_THERMOSTAT_OPERATING_STATE",
    COMMAND_CLASS_THERMOSTAT_SETPOINT: "COMMAND_CLASS_THERMOSTAT_SETPOINT",
    COMMAND_CLASS_THERMOSTAT_FAN_MODE: "COMMAND_CLASS_THERMOSTAT_FAN_MODE",
    COMMAND_CLASS_THERMOSTAT_FAN_STATE: "COMMAND_CLASS_THERMOSTAT_FAN_STATE",
    COMMAND_CLASS_CLIMATE_CONTROL_SCHEDULE: "COMMAND_CLASS_CLIMATE_CONTROL_SCHEDULE",
    COMMAND_CLASS_THERMOSTAT_SETBACK: "COMMAND_CLASS_THERMOSTAT_SETBACK",
    COMMAND_CLASS_DOOR_LOCK_LOGGING: "COMMAND_CLASS_DOOR_LOCK_LOGGING",
    COMMAND_CLASS_SCHEDULE_ENTRY_LOCK: "COMMAND_CLASS_SCHEDULE_ENTRY_LOCK",
    COMMAND_CLASS_BASIC_WINDOW_COVERING: "COMMAND_CLASS_BASIC_WINDOW_COVERING",
    COMMAND_CLASS_MTP_WINDOW_COVERING: "COMMAND_CLASS_MTP_WINDOW_COVERING",
    COMMAND_CLASS_MULTI_CHANNEL_V2: "COMMAND_CLASS_MULTI_CHANNEL_V2",
    COMMAND_CLASS_MULTI_INSTANCE: "COMMAND_CLASS_MULTI_INSTANCE",
    COMMAND_CLASS_DOOR_LOCK: "COMMAND_CLASS_DOOR_LOCK",
    COMMAND_CLASS_USER_CODE: "COMMAND_CLASS_USER_CODE",
    COMMAND_CLASS_CONFIGURATION: "COMMAND_CLASS_CONFIGURATION",
    COMMAND_CLASS_CONFIGURATION_V2: "COMMAND_CLASS_CONFIGURATION_V2",
    COMMAND_CLASS_ALARM: "COMMAND_CLASS_ALARM",
    COMMAND_CLASS_MANUFACTURER_SPECIFIC: "COMMAND_CLASS_MANUFACTURER_SPECIFIC",
    COMMAND_CLASS_POWERLEVEL: "COMMAND_CLASS_POWERLEVEL",
    COMMAND_CLASS_PROTECTION: "COMMAND_CLASS_PROTECTION",
    COMMAND_CLASS_PROTECTION_V2: "COMMAND_CLASS_PROTECTION_V2",
    COMMAND_CLASS_LOCK: "COMMAND_CLASS_LOCK",
    COMMAND_CLASS_NODE_NAMING: "COMMAND_CLASS_NODE_NAMING",
    COMMAND_CLASS_FIRMWARE_UPDATE_MD: "COMMAND_CLASS_FIRMWARE_UPDATE_MD",
    COMMAND_CLASS_GROUPING_NAME: "COMMAND_CLASS_GROUPING_NAME",
    COMMAND_CLASS_REMOTE_ASSOCIATION_ACTIVATE: "COMMAND_CLASS_REMOTE_ASSOCIATION_ACTIVATE",
    COMMAND_CLASS_REMOTE_ASSOCIATION: "COMMAND_CLASS_REMOTE_ASSOCIATION",
    COMMAND_CLASS_BATTERY: "COMMAND_CLASS_BATTERY",
    COMMAND_CLASS_CLOCK: "COMMAND_CLASS_CLOCK",
    COMMAND_CLASS_HAIL: "COMMAND_CLASS_HAIL",
    COMMAND_CLASS_WAKE_UP: "COMMAND_CLASS_WAKE_UP",
    COMMAND_CLASS_WAKE_UP_V2: "COMMAND_CLASS_WAKE_UP_V2",
    COMMAND_CLASS_ASSOCIATION: "COMMAND_CLASS_ASSOCIATION",
    COMMAND_CLASS_ASSOCIATION_V2: "COMMAND_CLASS_ASSOCIATION_V2",
    COMMAND_CLASS_VERSION: "COMMAND_CLASS_VERSION",
    COMMAND_CLASS_INDICATOR: "COMMAND_CLASS_INDICATOR",
    COMMAND_CLASS_PROPRIETARY: "COMMAND_CLASS_PROPRIETARY",
    COMMAND_CLASS_LANGUAGE: "COMMAND_CLASS_LANGUAGE",
    COMMAND_CLASS_TIME: "COMMAND_CLASS_TIME",
    COMMAND_CLASS_TIME_PARAMETERS: "COMMAND_CLASS_TIME_PARAMETERS",
    COMMAND_CLASS_GEOGRAPHIC_LOCATION: "COMMAND_CLASS_GEOGRAPHIC_LOCATION",
    COMMAND_CLASS_COMPOSITE: "COMMAND_CLASS_COMPOSITE",
    COMMAND_CLASS_MULTI_CHANNEL_ASSOCIATION_V2: "COMMAND_CLASS_MULTI_CHANNEL_ASSOCIATION_V2",
    COMMAND_CLASS_MULTI_INSTANCE_ASSOCIATION: "COMMAND_CLASS_MULTI_INSTANCE_ASSOCIATION",
    COMMAND_CLASS_MULTI_CMD: "COMMAND_CLASS_MULTI_CMD",
    COMMAND_CLASS_ENERGY_PRODUCTION: "COMMAND_CLASS_ENERGY_PRODUCTION",
    COMMAND_CLASS_MANUFACTURER_PROPRIETARY: "COMMAND_CLASS_MANUFACTURER_PROPRIETARY",
    COMMAND_CLASS_SCREEN_MD: "COMMAND_CLASS_SCREEN_MD",
    COMMAND_CLASS_SCREEN_MD_V2: "COMMAND_CLASS_SCREEN_MD_V2",
    COMMAND_CLASS_SCREEN_ATTRIBUTES: "COMMAND_CLASS_SCREEN_ATTRIBUTES",
    COMMAND_CLASS_SCREEN_ATTRIBUTES_V2: "COMMAND_CLASS_SCREEN_ATTRIBUTES_V2",
    COMMAND_CLASS_SIMPLE_AV_CONTROL: "COMMAND_CLASS_SIMPLE_AV_CONTROL",
    COMMAND_CLASS_AV_CONTENT_DIRECTORY_MD: "COMMAND_CLASS_AV_CONTENT_DIRECTORY_MD",
    COMMAND_CLASS_AV_RENDERER_STATUS: "COMMAND_CLASS_AV_RENDERER_STATUS",
    COMMAND_CLASS_AV_CONTENT_SEARCH_MD: "COMMAND_CLASS_AV_CONTENT_SEARCH_MD",
    COMMAND_CLASS_SECURITY: "COMMAND_CLASS_SECURITY",
    COMMAND_CLASS_AV_TAGGING_MD: "COMMAND_CLASS_AV_TAGGING_MD",
    COMMAND_CLASS_IP_CONFIGURATION: "COMMAND_CLASS_IP_CONFIGURATION",
    COMMAND_CLASS_ASSOCIATION_COMMAND_CONFIGURATION: "COMMAND_CLASS_ASSOCIATION_COMMAND_CONFIGURATION",
    COMMAND_CLASS_SENSOR_ALARM: "COMMAND_CLASS_SENSOR_ALARM",
    COMMAND_CLASS_SILENCE_ALARM: "COMMAND_CLASS_SILENCE_ALARM",
    COMMAND_CLASS_SENSOR_CONFIGURATION: "COMMAND_CLASS_SENSOR_CONFIGURATION",
    COMMAND_CLASS_MARK: "COMMAND_CLASS_MARK",
    COMMAND_CLASS_NON_INTEROPERABLE: "COMMAND_CLASS_NON_INTEROPERABLE"
}

# "\x00\x7a\x74\x9d\xef\x41\x00\x0c\x01\x27\x04" CHK=0xec
# "\x00\x7a\x74\x9d\xef\x41\x00\x0c\x01\x27\x05" CHK=0xed

def calcchksum(mpdu):
    checksum = 0xff
    for i in range(len(mpdu)):
        checksum ^= ord(mpdu[i])
    return checksum

def str_to_binary(s):
    return ''.join(['%08d'%int(bin(ord(i))[2:]) for i in s])

# Assumes first bit is starting (no leading 0 suppression)
def binary_to_hex(b):
    sb = (b[i:i+8] for i in range(0, len(b), 8)) # 8-bit blocks
    return ''.join(chr(int(char, 2)) for char in sb)

def hexdump(s):
    return "".join(x.encode('hex') for x in s)

def sighandler(signal, frame):
    global sigstop
    sigstop=1

# Returns a string describing the payload attributes
def payloaddecode(payload):
    if len(payload) == 0:
        return ""

    commandclass = ord(payload[0])
    try:
        desc = COMMAND_CLASSES[commandclass];
    except KeyError:
        desc = "COMMAND_CLASS_UNKNOWN_0X" + payload[0].encode('hex')

    if len(payload) == 1:
        return desc

    # Processing payload data that we know a little more about
    commandclasscmd = ord(payload[1])
    payloadmsg = ""

    # Wow.  This is hideous.
    if commandclass == COMMAND_CLASS_SWITCH_ALL:
        if commandclasscmd == 1:
            desc += " SwitchAllCmd_Set"
        elif commandclasscmd == 2:
            desc += " SwitchAllCmd_Get"
        elif commandclasscmd == 3:
            desc += " SwitchAllCmd_Report"
        elif commandclasscmd == 4:
            desc += " SwitchAllCmd_On"
        elif commandclasscmd == 5:
            desc += " SwitchAllCmd_Off"
        else:
            desc += " InvalidSwitchAllCmd"
    elif commandclass == COMMAND_CLASS_CLOCK:
        if commandclasscmd == 4:
            desc += " ClockCmd_Set"
        elif commandclasscmd == 5:
            desc += " ClockCmd_Get"
        elif commandclasscmd == 6:
            desc += " ClockCmd_Report"
        else:
            desc += " InvalidClockCmd"
    elif commandclass == COMMAND_CLASS_THERMOSTAT_MODE:
        if commandclasscmd == 1:
            desc += " ThermostatModeCmd_Set"
        elif commandclasscmd == 2:
            desc += " ThermostatModeCmd_Get"
        elif commandclasscmd == 3:
            desc += " ThermostatModeCmd_Report"
        elif commandclasscmd == 4:
            desc += " ThermostatModeCmd_SupportedGet"
        elif commandclasscmd == 5:
            desc += " ThermostatModeCmd_SupportedReport"
        else:
            desc += " InvalidThermostatModeCmd"
    elif commandclass == COMMAND_CLASS_BASIC:
        if commandclasscmd == 1:
            desc += " BasicModeCmd_Set"
        elif commandclasscmd == 2:
            desc += " BasicModeCmd_Get"
        elif commandclasscmd == 3:
            desc += " BasicModeCmd_Report"
        else:
            desc += " InvalidBasicModeCmd"
        if len(payload) > 2 and commandclass == 1:
            eventcmd = ord(payload[2])
            if (eventcmd == 0):
                desc += " Off"
            else:
                desc += " On"
    elif commandclass == COMMAND_CLASS_SWITCH_MULTILEVEL_V2:
        if commandclasscmd == 1:
            desc += " SwitchMultiLevelModeCmd_Set"
        elif commandclasscmd == 2:
            desc += " SwitchMultiLevelModeCmd_Get"
        elif commandclasscmd == 3:
            desc += " SwitchMultiLevelModeCmd_Report"
        else:
            desc += " InvalidSwitchMultiLevelModeCmd"
        if len(payload) > 2 and commandclass == 1:
            eventcmd = ord(payload[2])
            if (eventcmd == 0):
                desc += " Off"
            else:
                desc += " On"

    return desc

if __name__ == "__main__":
    uri = "http://localhost:2501"
    user = "kismet"
    passwd = "kismet"
    frequency = 908419830
    
    parser = argparse.ArgumentParser(description='Killerzee to Kismet bridge')
    
    parser.add_argument('--uri', action="store", dest="uri")
    parser.add_argument('--user', action="store", dest="user")
    parser.add_argument('--passwd', action="store", dest="passwd")
    parser.add_argument('--frequency', action="store", dest="freq")
    
    results = parser.parse_args()
    
    if results.uri != None:
        uri = results.uri
    if results.user != None:
        user = results.user
    if results.passwd != None:
        passwd = results.passwd
    if results.freq != None:
        frequency = results.frequency
    
    kr = KismetRest.KismetConnector(uri)
    kr.set_login(user, passwd)
    
    pktflen = 54

    sigstop=0

    d = RfCat(0, debug=False)
    d.setFreq(frequency)
    d.setMdmModulation(MOD_2FSK)
    d.setMdmSyncWord(0x55f0)
    d.setMdmDeviatn(19042.969)
    d.setMdmChanSpc(199951.172)
    d.setMdmChanBW(101562.5)
    d.setMdmDRate(19191.7)
    d.makePktFLEN(pktflen)
    d.setEnableMdmManchester(True)
    #d.setMdmSyncMode(SYNCM_CARRIER)
    d.setMdmSyncMode(SYNCM_CARRIER_15_of_16)

    signal.signal(signal.SIGINT, sighandler)
    while(not sigstop):
        try:
            packet = d.RFrecv()[0] # Just the data, no timestamp
        except ChipconUsbTimeoutException:
            continue

        try:
            homeid=packet[0:4]
            source=packet[4]
            fc=packet[5:7]

            # Check for multicast frame, changes packet format
            if (ord(fc[0]) & 0x0F) == 2:
                mcastpacket=True
            else:
                mcastpacket=False

            plen=(ord(packet[7]))
            if plen < 9:
                print "RX packet length too small, skipping (%d)"%plen
                continue
            if plen > 54:
                print "RX packet length too large, skipping (%d)"%plen
                continue

            dest=packet[8]
            mpdu=packet[:plen]
            if plen > pktflen:
                print "Received packet is length (%d) is longer than specified capture frame length (%d), skipping."%(plen,pktflen)
                continue
            chksum=mpdu[-1]

            if not mcastpacket:
                payload=mpdu[9:-1]
            else:
                mcastdest=ord(packet[9])
                mcastaddroffset = (mcastdest & 0b11100000) >> 5
                mcastnummaskbytes = (mcastdest & 0b00011111)
                payload=mpdu[9+mcastnummaskbytes:-1]

            calcchk = calcchksum(mpdu[:-1])
            if calcchk != ord(chksum):
                print "Bad checksum"
                continue

            obj = {
                    'home_id': hexdump(homeid),
                    'source': ord(source),
                    'dest': ord(dest),
                    'freq_khz': frequency / 1000,
                    'payload': hexdump(packet),
                    'datasize': plen,
                    }

            print "Posting: ", json.dumps(obj)

            try:
                if not kr.check_session():
                    kr.login()

                print "Post:", kr.post_url("phy/phyZwave/post_zwave_json.cmd", 
                        { "obj": json.dumps(obj) });
            except Exception as e:
                print "Post failed: ", e

            continue

            print hexdump(packet)
            print "Home ID:  ", hexdump(homeid)
            print "Source:   ", hexdump(source)
            print "Dest:     ", hexdump(dest)

            fcdesc=""
            fcint = int(binascii.hexlify(fc), 16)
            fctype = (fcint & 0b0000111100000000) >> 8
            if fctype == 1:
                fcdesc += "Type Singlecast "
            elif fctype == 2:
                fcdesc += "Type Multicast "
            elif fctype == 3:
                fcdesc += "Type ACK "
            elif fctype == 8:
                fcdesc += "Type Routed "
            else:
                fcdesc += "Reserved Type "
            if fcint & 0b1000000000000000:
                fcdesc += "Routed "
            if fcint & 0b0100000000000000:
                fcdesc += "ACK Reqd "
            if fcint & 0b0010000000000000:
                fcdesc += "Low Power "
            if fcint & 0b0001000000000000:
                fcdesc += "Speed Modified "
            if fcint & 0b0000000010000000:
                fcdesc += "Reserved Bit1 "
            if (fcint & 0b0000000011000000) != 0:
                fcdesc += "Beam Wakeup "
            if fcint & 0b0000000000010000:
                fcdesc += "Reserved Bit2 "
            fcseqnum = fcint & 0b0000000000001111
            fcdesc += "Seq# %d"%fcseqnum
            print "FC:       ", hexdump(fc), "(" + fcdesc + ")"

            print "Len:      ", plen

            if mcastpacket:
                print "Multicast:", "%02x"%mcastdest,
                print "(Offset %d, Mask Byte Count %d)"%(mcastaddroffset, mcastnummaskbytes)

            print "Payload:  ", hexdump(payload), payloaddecode(payload)

            calcchk = calcchksum(mpdu[:-1])
            if calcchk != ord(chksum):
                print "Checksum: ", hexdump(chksum), "(Incorrect)"
            else:
                print "Checksum: ", hexdump(chksum), "(Correct)"

        except (TypeError,IndexError) as e:
            #print traceback.format_exc()
            print "Bad packet, skipping"
        print


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
