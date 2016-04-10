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
            return unpacked[1][1]

        return unpacked[1]

    def SystemStatus(self):
        try:
            statusbin = urllib.urlopen("%s/system/status.msgpack" % self.hosturi).read()
        except Exception as e:
            print "Failed to get status object: ", e
            return None

        try:
            statusobj = msgpack.unpackb(statusbin)
        except Exception as e:
            print "Failed to unpack status object: ", e
            return None

        return self.Simplify(statusobj)

