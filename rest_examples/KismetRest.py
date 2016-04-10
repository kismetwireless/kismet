#/usr/bin/env python

import msgpack, urllib

"""
Kismet-handling python class

Uses msgpack and urllib
"""
class Kismet(object):
    """
    Kismet rest API
    """
    def __init__(self, hosturi):
        """ 
        KismetRest(hosturi) -> KismetRest

        hosturi: URI including protocol, host, and port

        Example:
        rest = KismetRest('https://localhost:2501/')

        """
        self.hosturi = hosturi

        self.TRACKER_STRING = 0
        self.TRACKER_INT8 = 1
        self.TRACKER_UINT8 = 2
        self.TRACKER_INT16 = 3
        self.TRACKER_UINT16 = 4
        self.TRACKER_INT32 = 5
        self.TRACKER_UINT32 = 6
        self.TRACKER_INT64 = 7
        self.TRACKER_UINT64 = 8
        self.TRACKER_FLOAT = 9
        self.TRACKER_DOUBLE = 10
        self.TRACKER_MAC = 11
        self.TRACKER_UUID = 12
        self.TRACKER_VECTOR = 13
        self.TRACKER_MAP = 14
        self.TRACKER_INTMAP = 15
        self.TRACKER_MACMAP = 16
        self.TRACKER_STRINGMAP = 17
        self.TRACKER_DOUBLEMAP = 18


    def Simplify(self, unpacked):
        """
        Simplify(unpacked_object) -> Python object
        Strip out Kismet type data and return a simplified Python
        object

        unpacked: Python object unpacked from Kismet message
        """

        if unpacked[0] == self.TRACKER_VECTOR:
            retarr = []

            for x in range(0, len(unpacked[1])):
                retarr.append(self.Simplify(unpacked[1][x]))

            return retarr

        if (unpacked[0] == self.TRACKER_MAP or unpacked[0] == self.TRACKER_INTMAP or
                unpacked[0] == self.TRACKER_MACMAP or 
                unpacked[0] == self.TRACKER_STRINGMAP or
                unpacked[0] == self.TRACKER_DOUBLEMAP):

            retdict = {}

            for k in unpacked[1].keys():
                retdict[k] = self.Simplify(unpacked[1][k])

            return retdict

        if unpacked[0] == self.TRACKER_MAC:
            return unpacked[1][0]

        return unpacked[1]

    def UnpackUrl(self, url):
        """
        UnpackUrl(url) -> Unpacked Object

        Unpacks a msgpack object at a given URL, inside the provided host URI
        """
        try:
            url = urllib.urlopen("%s/%s" % (self.hosturi, url))
            if not url.getcode() == 200:
                print "Did not get 200 OK"
                return None
            urlbin = url.read()
        except Exception as e:
            print "Failed to get status object: ", e
            return None

        try:
            obj = msgpack.unpackb(urlbin)
        except Exception as e:
            print "Failed to unpack status object: ", e
            return None

        return obj

    def UnpackSimpleUrl(self, url):
        """
        UnpackSimpleUrl(url) -> Python Object

        Unpacks a msgpack object and returns the simplified python object
        """
        cobj = self.UnpackUrl(url)

        if cobj == None:
            return None

        return self.Simplify(cobj)

    def SystemStatus(self):
        """
        SystemStatus() -> Status object

        Return fetch the system status
        """
        return self.UnpackSimpleUrl("system/status.msgpack")

    def DeviceSummary(self):
        """
        DeviceSummary() -> Device summary list

        Return summary of all devices
        """
        return self.UnpackSimpleUrl("devices/all_devices.msgpack")

    def Device(self, key):
        """
        Device(key) -> Device object

        Return complete device object of device referenced by key
        """
        return self.UnpackSimpleUrl("devices/%s.msgpack" % key)

    def DeviceField(self, key, field):
        """
        DeviceField(key, path) -> Field object

        Return specific field of a device referenced by key.

        field: Kismet tracked field path, ex:
            dot11.device/dot11.device.last_beaconed_ssid
        """
        return self.UnpackSimpleUrl("devices/%s.msgpack/%s" % (key, field))

