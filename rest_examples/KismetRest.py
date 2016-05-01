#/usr/bin/env python

import msgpack
import urllib
import requests
import base64
import os

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

        self.username = "unknown"
        self.password = "nopass"

        self.session = requests.Session()

        # Set the default path for storing sessions
        self.SetSessionCache("~/.kismet/pykismet_session")

    def SetLogin(self, user, passwd):
        """
        SetLogin(user, passwd) -> None

        Logs in (and caches login credentials).  Required for administrative
        behavior.
        """
        self.session.auth = (user, passwd)

        return 

    def SetSessionCache(self, path):
        """
        SetSessionCache(self, path) -> None

        Set a cache file for HTTP sessions
        """
        self.sessioncache_path = os.path.expanduser(path)

        # If we already have a session cache file here, load it
        if os.path.isfile(self.sessioncache_path):
            try:
                lcachef = open(self.sessioncache_path, "r")
                cookie = lcachef.read()

                # Add the session cookie
                requests.utils.add_dict_to_cookiejar(self.session.cookies, 
                        {"KISMET": cookie})

                lcachef.close()
            except Exception as e:
                print "Failed to read session cache:", e
                x = 1

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
            r = self.session.get("%s/%s" % (self.hosturi, url))
            if not r.status_code == 200:
                print "Did not get 200 OK"
                return None
            urlbin = r.content
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

    def Login(self):
        """
        Login() -> Boolean

        Logs in (and caches login credentials).  Required for administrative
        behavior.
        """
        r = self.session.get("%s/session/create_session" % self.hosturi)

        if not r.status_code == 200:
            return False

        # Save the session
        try:
            lcachef = open(self.sessioncache_path, "w")
            cd = requests.utils.dict_from_cookiejar(self.session.cookies)
            cookie = cd["KISMET"]
            lcachef.write(cookie)
            lcachef.close()
            print "Saved session"
        except Exception as e:
            print "Failed to save session:", e
            x = 1

        return True

    def Logout(self):
        """
        Logout() -> Boolean

        Clears the local session values
        """
        requests.utils.add_dict_to_cookiejar(self.session.cookies, 
                {"KISMET":"INVALID"})

    def CheckSession(self):
        """
        CheckSession() -> Boolean

        Checks if a session is valid / session is logged in
        """

        r = self.session.get("%s/session/check_session" % self.hosturi)

        if not r.status_code == 200:
            return False

        return True

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

    def OldSources(self):
        """
        OldSources() -> Packetsource list

        Return list of all configured devices, using the soon-to-be-deprecated
        PacketSource mechanism
        """
        return self.UnpackSimpleUrl("packetsource/all_sources.msgpack")

    def LockOldSource(self, uuid, channel):
        """
        LockOldSource(uuid, channel) -> Boolean

        Locks an old-style PacketSource to an 802.11 channel or frequency.
        Channel should be integer (ie 6, 11, 53).

        Requires valid login.

        Returns success or failure.
        """
        cmd = {
                "cmd": "lock",
                "uuid": uuid,
                "channel": channel
                }

        try:
            postdata = {
                    "msgpack": base64.b64encode(msgpack.packb(cmd))
                    }
        except Exception as e:
            print "Failed to encode post data:", e
            return False

        r = self.session.post("%s/packetsource/config/channel.cmd" % self.hosturi, 
                data=postdata)

        # Login required
        if r.status_code == 401:
            # Can we log in?
            if not self.Login():
                print "Cannot log in"
                return False

            # Try again after we log in
            r = self.session.post("%s/packetsource/config/channel.cmd" % self.hosturi, 
                data=postdata)

        # Did we succeed?
        if not r.status_code == 200:
            print "Channel lock failed:", r.content
            return False

        return True


