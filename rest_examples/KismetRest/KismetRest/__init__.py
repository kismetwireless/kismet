#!/usr/bin/env python

import json
import requests
import os

"""
The field simplification and pathing options are best described in the 
developer docs for Kismet under docs/dev/webui_rest.md ; basically, they
allow for selecting specific fields from the tree and returning ONLY those
fields, instead of the entire object.

This will increase the speed of searches of large sets of data, and decrease
the time it takes for Kismet to return them.

Whenever possible this API will use the 'ekjson' format for multiple returned
objects - this places a JSON object for each element in an array/vector response
as a complete JSON record followed by a newline; this allows for parsing the
JSON response without allocating the entire vector object in memory first, and 
enables streamed-base parsing of very large responses.

Field Simplification Specification:

    Several endpoints in Kismet take a field filtering object.  These
    use a common specification:

    [
        field1,
        ...
        fieldN
    ]

    where a field may be a single-element string, consisting of a
    field name -or- a field path, such as:
        'kismet.device.base.channel'
        'kismet.device.base.signal/kismet.common.signal.last_signal_dbm'

    OR a field may be a two-value array, consisting of a field name or
    path, and a target name the field will be aliased to:

        ['kismet.device.base.channel', 'base.channel']
        ['kismet.device.base.signal/kismet.common.signal.last_signal_dbm', 
            'last.signal']

    The fields in the returned device will be inserted as their final
    name - that is, from the first above example, the device will contain
        'kismet.device.base.channel' and 'kismet.common.signal.last_signal_dbm'
    and from the second example:
        'base.channel' and 'last.signal'

Filter Specification:

    Several endpoints in Kismet take a regex object.  These use a common
    specification:

    [
        [ multifield, regex ],
        ...
        [ multifield, regex ]
    ]

    Multifield is a field path specification which will automatically expand
    value-maps and vectors found in the path.  For example, the multifield
    path:
        'dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid'
    
    would apply to all 'dot11.advertisedssid.ssid' fields in the ssid_map 
    automatically.

    Regex is a basic string containing a regular expression, compatible with
    PCRE.

    To match on SSIDs:

    regex = [
        [ 'dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid',
            '^SomePrefix.*' ]
        ]

    A device is included in the results if it matches any of the regular 
    expressions.

"""


class KismetConnectorException(Exception):
    pass

class KismetLoginException(KismetConnectorException):
    def __init__(self, message, rcode):
        super(Exception, self).__init__(message)
        self.rcode = rcode

class KismetRequestException(KismetConnectorException):
    def __init__(self, message, rcode):
        super(Exception, self).__init__(message)
        self.rcode = rcode

class KismetConnector:
    """
    Kismet rest API
    """
    def __init__(self, host_uri='http://127.0.0.1:2501'):
        """ 
        KismetRest(hosturi) -> KismetRest

        hosturi: URI including protocol, host, and port

        Example:
        rest = KismetRest('https://localhost:2501/')

        """
        self.debug = False

        self.host_uri = host_uri

        self.username = "unknown"
        self.password = "nopass"

        self.session = requests.Session()

        # Set the default path for storing sessions
        self.sessioncache_path = None
        self.set_session_cache("~/.pykismet_session")

    def set_debug(self, debug):
        """
        SetDebug(debug) -> None

        Set debug mode (more verbose output)
        """
        self.debug = debug

    def set_login(self, user, passwd):
        """
        SetLogin(user, passwd) -> None

        Logs in (and caches login credentials).  Required for administrative
        behavior.
        """
        self.session.auth = (user, passwd)

        return 

    def set_session_cache(self, path):
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
                requests.utils.add_dict_to_cookiejar(
                    self.session.cookies, {"KISMET": cookie})

                lcachef.close()
            except Exception as e:
                if self.debug:
                    print "Failed to read session cache:", e

    def __update_session(self):
        """
        __update_session() -> None

        Internal utility function for extracting an updated session key, if one is
        present, from the connection.  Typically called after fetching any URI.
        """
        try:
            cd = requests.utils.dict_from_cookiejar(self.session.cookies)
            cookie = cd["KISMET"]
            if (len(cookie) != 0):
                lcachef = open(self.sessioncache_path, "w")
                lcachef.write(cookie)
                lcachef.close()
        except KeyError as e:
            pass
        except Exception as e:
            if self.debug:
                print "DEBUG - Failed to save session:", e

    def __process_json_stream(self, r, callback, args = None):
        """
        __process_json_stream(httpresult, callback)

        Process a response as a JSON object stream - this may be an ekjson style
        response with multiple objects or it may be a single traditional JSON
        response.

        If callback is provided and is not None, callback is called for each 
        object in the stream and an empty vector object is returned; otherwise each
        object in the stream is added to the vector and returned.

        A vector object in the stream is not converted into multiple callbacks - 
        if a URI does not return an ekjson style vector split into multiple objects,
        it will not be split into multiple objects here.
        """

        ret = []
        for line in r.iter_lines():
            try:
                # filter out keep-alive new lines
                if line:
                    decoded_line = line.decode('utf-8')

                    obj = json.loads(decoded_line)

                    if callback != None:
                        if args == None:
                            args = []
                        callback(obj, *args)
                    else:
                        ret.append(obj)
            except Exception as e:
                if self.debug:
                    print "Failed to parse JSON: {}, {}, {}".format(r.url, e.message, line)

                raise KismetRequestException("Unable to parse JSON on req {}: {}".format(r.url, e.message), r.status_code)

        return ret

    def __get_json_url(self, url, callback = None, cbargs = None):
        """
        __get_json_url(url, callback) -> [result code, Unpacked Object]

        Internal function for unpacking a json/ekjson GET url, with optional callback
        called for each object in an ekjson.

        Returns a tuple of the HTTP result code and:

            a) None, if unable to fetch or parse a result
            b) None, if a callback is provided
            c) A vector of objects, if callback is provided

        """
        try:
            r = self.session.get("%s/%s" % (self.host_uri, url), stream=True)
        except Exception as e:
            if self.debug:
                print "Failed to get object: ", e
            raise KismetRequestException("Failed to get object: {}".format(e.message), -1)

        # login required
        if r.status_code == 401:
            if self.debug:
                print "DEBUG - Login required & no valid login provided"

            raise KismetLoginException("Login required for {}".format(url), r.status_code);

        # Did we succeed?
        if not r.status_code == 200:
            if self.debug:
                print "Request failed:", r.status_code

            raise KismetRequestException("Request failed {} {}".format(url, r.status_code), r.status_code)

        # Update our session
        self.__update_session()

        # Process our stream
        return (r.status_code, self.__process_json_stream(r, callback, cbargs))

    def __get_string_url(self, url):
        """
        __get_string_url(url) -> (result, string)

        Internal function to perform a simple fetch of a URL and return it as an
        unprocessed string object
        """
        try:
            r = self.session.get("%s/%s" % (self.host_uri, url))
        except Exception as e:
            if self.debug:
                print "Failed to get object: ", e
            raise KismetRequestException("Failed to get object: {}".format(e.message), r.status_code)

        # login required
        if r.status_code == 401:
            if self.debug:
                print "DEBUG - Login required & no valid login provided"

            raise KismetLoginException("Login required for {}".format(url), r.status_code);

        # Did we succeed?
        if not r.status_code == 200:
            if self.debug:
                print "Request failed:", r.status_code

            raise KismetRequestException("Request failed {} {}".format(url, r.status_code), r.status_code)

        # Update our session
        self.__update_session()

        return r.content

    def __post_json_url(self, url, postdata, callback = None, cbargs = None):
        """
        __post_json_url(url, postdata, callback) -> [result code, Unpacked Object]

        Internal function for unpacking a json/ekjson POST url, with the same
        semantics as __get_json_url internally.  POSTDATA is a standard python
        object which is then JSON encoded.
        """
        try:
            if postdata != None:
                pd = json.dumps(postdata)
            else:
                pd = ""

            fd = {
                "json": pd
            }

            r = self.session.post("%s/%s" % (self.host_uri, url), data = fd, stream=True)
        except Exception as e:
            if self.debug:
                print "Failed to POST object: ", e
            raise KismetRequestException("Failed to POST to {} {}".format(url, e.message), -1)

        # login required
        if r.status_code == 401:
            if self.debug:
                print "DEBUG - Login required & no valid login provided"

            raise KismetLoginException("Login required for POST {}".format(url), r.status_code);

        # Did we succeed?
        if not r.status_code == 200:
            if self.debug:
                print "Request failed:", r.status_code

            raise KismetRequestException("Request failed for POST {} {}".format(url, r.status_code), r.status_code)

        # Update our session
        self.__update_session()

        # Process our stream
        return (r.status_code, self.__process_json_stream(r, callback, cbargs))

    def __post_string_url(self, url, postdata):
        """
        __post_string_url(url, postdata) -> (result, string)

        Internal function to perform a simple fetch of a URL and return it as an
        unprocessed string object
        """
        try:
            if postdata != None:
                pd = json.dumps(postdata)
            else:
                pd = ""

            fd = {
                "json": pd
            }

            r = self.session.post("%s/%s" % (self.host_uri, url), data = fd)
        except Exception as e:
            if self.debug:
                print "Failed to POST object: ", e
            raise KismetRequestException("Failed to POST object: {}".format(e.message), -1)

        # login required
        if r.status_code == 401:
            if self.debug:
                print "DEBUG - Login required & no valid login provided"

            raise KismetLoginException("Login required for POST {}".format(url), r.status_code);

        # Did we succeed?
        if not r.status_code == 200:
            if self.debug:
                print "Request failed:", r.status_code

            raise KismetRequestException("Request failed for POST {} {}".format(url, r.status_code), r.status_code)

        # Update our session
        self.__update_session()

        return (r.status_code, r.content)

    def login(self):
        """
        login() -> Boolean

        Logs in (and caches login credentials).  Required for administrative
        behavior.
        """
        r = self.session.get("%s/session/check_session" % self.host_uri)

        if not r.status_code == 200:
            print "Invalid session"
            return False

        self.__update_session()

        return True

    def check_session(self):
        """
        check_session() -> Boolean

        Checks if a session is valid / session is logged in
        """

        r = self.session.get("%s/session/check_session" % self.host_uri)

        if not r.status_code == 200:
            return False

        self.__update_session()

        return True

    def system_status(self):
        """
        system_status() -> Status object

        Return fetch the system status
        """
        (r, status) = self.__get_json_url("system/status.json")

        return status[0]

    def device_summary(self, callback = None, cbargs = None):
        """
        device_summary([callback, cbargs]) -> device list

        Deprecated API - now referenced as device_list(..)
        """
        
        return self.device_list(callback, cbargs)

    def device_list(self, callback = None, cbargs = None):
        """
        device_list([callback, cbargs]) -> device list

        Return all fields of all devices.  This may be extremely memory and CPU
        intensive and should be avoided.  Memory use can be reduced by providing a
        callback, which will be invoked for each device.

        In general THIS API SHOULD BE AVOIDED.  There are several potentially serious
        repercussions in querying all fields of all devices in a very high device count
        environment.

        It is strongly recommended that you use smart_device_list(...)
        """

        (r, devices) = self.__get_json_url("devices/all_devices.ekjson", callback, cbargs)

        return devices

    def device_summary_since(self, ts = 0, fields = None, callback = None, cbargs = None):
        """
        device_summary_since(ts, [fields, callback, cbargs]) -> device summary list 

        Deprecated API - now referenced as smart_device_list(...)

        Return object containing summary of devices added or changed since ts
        and ts info
        """
        return self.smart_device_list(ts = ts, fields = fields, callback = callback, cbargs = cbargs)

    def smart_summary_since(self, ts = 0, fields = None, regex = None, callback = None, cbargs = None):
        """
        smart_summary_since([ts, fields, regex, callback, cbargs]) -> device summary list

        Deprecated API - now referenced as smart_device_list(...)
        """
        return self.smart_device_list(ts = ts, fields = fields, regex = regex, callback = callback, cbargs = cbargs)

    def smart_device_list(self, ts = 0, fields = None, regex = None, callback = None, cbargs = None):
        """
        smart_device_list([ts, fields, regex, callback, cbargs])

        Perform a 'smart' device list.  The device list can be manipulated in
        several ways:

            1.  Devices active since last timestamp.  By setting the 'ts' parameter,
                only devices which have been active since that timestamp will be 
                returned.
            2.  Devices which match a regex, as defined by the regex spec above
            3.  Devices can be simplified to reduce the amount of work being done
                and number of fields being returned.

        If a callback is given, it will be called for each device in the result.
        If no callback is provided, the results will be returned as a vector.
        """

        cmd = { }

        if not fields == None:
            cmd["fields"] = fields

        if not regex == None:
            cmd["regex"] = regex;

        (r, v) = self.__post_json_url("devices/last-time/{}/devices.ekjson".format(ts), cmd, callback, cbargs)

        # Always return a vector
        return v

    def device(self, key):
        """
        device(key) -> device object

        Deprecated, prefer device_by_key
        """
        return self.device_by_key(key)

    def device_field(self, key, field):
        """
        device_field(key, path) -> Field object

        Deprecated, prefer device_by_key with field
        """
        return self.device_by_key(key, field = field)

    def device_by_key(self, key, field = None, fields = None):
        """
        device_by_key(key) -> device object

        Fetch a complete device record by the Kismet key (unique key per Kismet session)
        or fetch a specific sub-field by path.

        If a field simplification set is passed in 'fields', perform a simplification
        on the result
        """

        if fields == None:
            if not field == None:
                field = "/" + field

            (r, v) = self.__get_json_url("devices/by-key/{}/device.json{}".format(key, field))
        else:
            cmd = {
                "fields": fields
            }

            (r, v) = self.__post_json_url("devices/by-key/{}/device.json".format(key), cmd)

        # Single entity so pop out of the vector
        return v[0]

    def device_by_mac(self, mac, fields = None):
        """
        device_by_mac(mac) -> vector of device objects

        Return a vector of all devices in all phy types matching the supplied MAC
        address; typically this will return a vector of a single device, but MAC addresses
        could overlap between phy types.

        If a field simplification set is passed in 'fields', perform a simplification
        on the result
        """

        if fields == None:
            (r, v) = self.__get_json_url("devices/by-mac/{}/devices.json".format(mac))
        else:
            cmd = {
                "fields": fields
            }

            (r, v) = self.__post_json_url("devices/by-mac/{}/devices.json".format(mac), cmd)

        # Single-entity request, pop out vector
        return v[0]

    def datasources(self):
        """
        datasources() -> Datasource list
        
        Return list of all datasources
        """

        (r, v) = self.__get_json_url("datasource/all_sources.json")

        return v[0]

    def config_datasource_set_channel(self, uuid, channel):
        """
        config_datasource_set_channel(uuid, hop, channel) -> Boolean

        Locks an data source to an 802.11 channel or frequency.  Channel
        may be complex channel such as "6HT40+".

        Requires valid login.
        """

        cmd = {
            "channel": channel
        }

        (r, v) = self.__post_string_url("datasource/by-uuid/{}/set_channel.cmd".format(uuid), cmd)

        return r == 200

    def config_datasource_set_hop_rate(self, uuid, rate):
        """
        config_datasource_set_hop_rate(uuid, rate)

        Configures the hopping rate of a data source, while not changing the
        channels used for hopping.

        Requires valid login
        """

        cmd = {
            "hoprate": rate
        }

        (r, v) = self.__post_string_url("datasource/by-uuid/{}/set_channel.cmd".format(uuid), cmd)

        return r == 200


    def config_datasource_set_hop_channels(self, uuid, rate, channels):
        """
        config_datasource_set_hop(uuid, rate, channels)

        Configures a data source for hopping at 'rate' over a vector of
        channels.
        
        Requires valid login
        """

        cmd = {
            "hoprate": rate,
            "channels": channels
        }

        (r, v) = self.__post_string_url("datasource/by-uuid/{}/set_channel.cmd".format(uuid), cmd)

        return r == 200

    def config_datasource_set_hop(self, uuid):
        """
        config_datasource_set_hop(uuid)

        Configure a source for hopping; uses existing source hop / channel list / etc
        attributes.

        Requires valid login
        """

        cmd = {
            "hop": True
        }

        (r, v) = self.__post_string_url("datasource/by-uuid/{}/set_hop.cmd".format(uuid), cmd)

        return r == 200

    def add_datasource(self, source):
        """
        add_datasource(sourceline) -> Boolean

        Add a new source to kismet.  sourceline
        is a standard source definition.

        Requires valid login.

        Returns success
        """

        cmd = {
            "definition": source
        }

        (r, v) = self.__post_string_url("datasource/add_source.cmd", cmd)

        return r == 200

    def device_filtered_dot11_summary(self, pcre, fields = None, callback = None, cbargs = None, ts = 0):
        """
        device_filtered_dot11_summary(pcre, [fields, ts, callback, cbargs]) -> device list, filtered by dot11 ssid

        Deprecated API, this can now be handled by smart_device_list, which
        this function uses.

        """

        regex = []

        # Split the incoming PCRE into SSID matches
        for p in pcre:
            regex.append(['dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid', pcre])

        return self.smart_device_list(callback = callback, cbargs = cbargs, regex = regex, fields = fields, ts = ts)

    def device_filtered_dot11_probe_summary(self, pcre, fields = None, callback = None, cbargs = None, ts = 0):
        """
        device_filtered_dot11_probe_summary(pcre, [fields, ts, callback, cbargs]) -> device summary list, filtered by dot11 ssid

        Deprecated API, this can now be handled by smart_device_list, which
        this function uses
        """

        regex = []

        # Split the incoming PCRE into SSID matches
        for p in pcre:
            regex.append(['dot11.device/dot11.device.probed_ssid_map/dot11.probedssid.ssid', pcre])

        return self.smart_device_list(callback = callback, cbargs = cbargs, regex = regex, fields = fields, ts = ts)

    def define_alert(self, name, description, rate = "10/min", burst = "1/sec", phyname = None):
        """
        define_alert(name, description, rate, burst) -> Boolean

        LOGIN REQUIRED

        Define a new alert.  This alert can then be triggered on external
        conditions via raise_alert(...)

        Phyname is optional, and links the alert to a specific PHY type.

        Rate and Burst are optional rate and burst limits.
        """

        cmd = {
            "name": name,
            "description": description,
            "throttle": rate,
            "burst": burst
        }

        if not phyname == None:
            cmd["phyname"] = phyname

        (r, v) = self.__post_string_url("alerts/definitions/define_alert.cmd", cmd)

        return r == 200


    def raise_alert(self, name, text, bssid = None, source = None, dest = None, other = None, channel = None):
        """
        raise_alert(name, text, bssid, source, dest, other, channel)

        LOGIN REQUIRED

        Trigger an alert; the alert can be one defined via define_alert(...) or an alert
        built into the system.

        The alert name and content of the alert are required, all other fields are optional.
        """

        cmd = {
            "name": name,
            "text": text
        }

        if not bssid == None:
            cmd["bssid"] = bssid

        if not source == None:
            cmd["source"] = source

        if not dest == None:
            cmd["dest"] = dest

        if not other == None:
            cmd["other"] = other

        if not channel == None:
            cmd["channel"] = channel

        (r, v) = self.__post_string_url("alerts/raise_alert.cmd", cmd)

        return r == 200

if __name__ == "__main__":
    x = KismetConnector()
    print x.system_status()
