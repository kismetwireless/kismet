# Extending Kismet - REST Web Server Endpoints

Table of Contents
=================

* [Exploring the REST system](#exploring-the-rest-system)
* [Serialization Types](#serialization-types)
  * [JSON](#json)
  * [MSGPACK](#msgpack)
  * [EKJSON](#ekjson)
  * [PRETTYJSON](#prettyjson)
* [Logins and Sessions](#logins-and-sessions)
* [Commands](#commands)
  * [Field Specifications](#field-specifications)
  * [Filter Specifications](#filter-specifications)
    * [multifield](#multifield)
    * [regex](#regex)
    * [Example](#example)
* [REST Endpoints](#rest-endpoints)
  * [System Status](#system-status)
      * [/system/status /system/status.msgpack, <code>/system/status.json</code>](#systemstatus-systemstatusmsgpack-systemstatusjson)
      * [/system/timestamp /system/timestamp.msgpack, <code>/system/timestamp.json</code>](#systemtimestamp-systemtimestampmsgpack-systemtimestampjson)
      * [/system/tracked_fields /system/tracked_fields.html](#systemtracked_fields-systemtracked_fieldshtml)
  * [Device Handling](#device-handling)
      * [POST /devices/summary/devices /devices/summary/devices.msgpack, <code>/devices/summary/devices.json</code>](#post-devicessummarydevices-devicessummarydevicesmsgpack-devicessummarydevicesjson)
      * [/devices/all_devices.ekjson](#devicesall_devicesekjson)
      * [POST /devices/last-time/[TS]/devices /devices/last-time/[TS]/devices.msgpack, <code>devices/last-time/[TS]/devices.json</code>, <code>devices/last-time/[TS]/devices.ekjson</code>](#post-deviceslast-timetsdevices-deviceslast-timetsdevicesmsgpack-deviceslast-timetsdevicesjson-deviceslast-timetsdevicesekjson)
      * [/devices/last-time/[TS]/devices /devices/last-time/[TS]/devices.msgpack, <code>devices/last-time/[TS]/devices.json</code>, <code>devices/last-time/[TS]/devices.ekjson</code>](#deviceslast-timetsdevices-deviceslast-timetsdevicesmsgpack-deviceslast-timetsdevicesjson-deviceslast-timetsdevicesekjson)
      * [/devices/by-key/[DEVICEKEY]/device /devices/by-key/[DEVICEKEY]/device.msgpack, <code>/devices/by-key/[DEVICEKY]/device.json</code>](#devicesby-keydevicekeydevice-devicesby-keydevicekeydevicemsgpack-devicesby-keydevicekydevicejson)
      * [POST /devices/by-key/[DEVICEKEY]/device /devices/by-key/[DEVICEKEY]/device.msgpack, <code>/devices/by-key/[DEVICEKY]/device.json</code>](#post-devicesby-keydevicekeydevice-devicesby-keydevicekeydevicemsgpack-devicesby-keydevicekydevicejson)
      * [/devices/by-key/[DEVICEKEY]/device[/path/to/subkey] /devices/by-key/[DEVICEKEY]/device.msgpack[/path/to/subkey], <code>/devices/by-key/[DEVICEKEY]/device.json[/path/to/subkey]</code>](#devicesby-keydevicekeydevicepathtosubkey-devicesby-keydevicekeydevicemsgpackpathtosubkey-devicesby-keydevicekeydevicejsonpathtosubkey)
      * [/devices/by-mac/[DEVICEMAC]/devices /devices/by-mac/[DEVICEMAC]/devices.msgpack, <code>/devices/by-mac/[DEVICEMAC]/devices.json</code>](#devicesby-macdevicemacdevices-devicesby-macdevicemacdevicesmsgpack-devicesby-macdevicemacdevicesjson)
      * [POST /devices/by-mac/[DEVICEMAC]/devices /devices/by-mac/[DEVICEMAC]/devices.msgpack, <code>/devices/by-mac/[DEVICEMAC]/devices.json</code>](#post-devicesby-macdevicemacdevices-devicesby-macdevicemacdevicesmsgpack-devicesby-macdevicemacdevicesjson)
      * [POST /devices/by-phy/[PHYNAME]/devices /devices/by-phy/[PHYNAME]/devices.msgpack, <code>/devices/by-phy/[PHYNAME]/devices.json</code>, <code>/devices/by-phy/[PHYNAME]/devices.ekjson</code>](#post-devicesby-phyphynamedevices-devicesby-phyphynamedevicesmsgpack-devicesby-phyphynamedevicesjson-devicesby-phyphynamedevicesekjson)
  * [Device Editing](#device-editing)
      * [/devices/by-key/[key]/set_name /device/by-key/[key]/set_name.cmd](#devicesby-keykeyset_name-deviceby-keykeyset_namecmd)
      * [/devices/by-key/[key]/set_tag /dev/by-key/[key]/set_tag.cmd](#devicesby-keykeyset_tag-devby-keykeyset_tagcmd)
  * [Phy Handling](#phy-handling)
      * [/phy/all_phys /phy/all_phys.msgpack, <code>/phy/all_phys.json</code>](#phyall_phys-phyall_physmsgpack-phyall_physjson)
  * [Sessions and Logins](#sessions-and-logins)
      * [/session/check_session](#sessioncheck_session)
      * [/session/check_login](#sessioncheck_login)
  * [Messages](#messages)
      * [/messagebus/all_messages /messagebus/all_messages.msgpack, <code>/messagebus/all_messages.json</code>](#messagebusall_messages-messagebusall_messagesmsgpack-messagebusall_messagesjson)
      * [/messagebus/last-time/[TS]/messages /messagebus/last-time/[TS]/messages.msgpack, <code>/messagebus/last-time/[TS]/messages.json</code>](#messagebuslast-timetsmessages-messagebuslast-timetsmessagesmsgpack-messagebuslast-timetsmessagesjson)
  * [Alerts](#alerts)
      * [/alerts/definitions /alerts/definitions.msgpack, <code>/alerts/definitions.json</code>](#alertsdefinitions-alertsdefinitionsmsgpack-alertsdefinitionsjson)
      * [/alerts/all_alerts /alerts/all_alerts.msgpack, <code>/alerts/all_alerts.json</code>](#alertsall_alerts-alertsall_alertsmsgpack-alertsall_alertsjson)
      * [/alerts/last-time[TS]/alerts /alerts/last-time/[TS]/alerts.msgpack, <code>/alerts/last-time/[TS]/alerts.json</code>](#alertslast-timetsalerts-alertslast-timetsalertsmsgpack-alertslast-timetsalertsjson)
      * [POST /alerts/definitions/define_alert.cmd](#post-alertsdefinitionsdefine_alertcmd)
      * [POST /alerts/raise_alert.cmd](#post-alertsraise_alertcmd)
  * [Channels](#channels)
      * [/channels/channels /channels/channels.msgpack, <code>/channels/channels.json</code>](#channelschannels-channelschannelsmsgpack-channelschannelsjson)
  * [Datasources](#datasources)
    * [Querying data sources](#querying-data-sources)
      * [/datasource/all_sources /datasource/all_sources.msgpack, <code>/datasource/all_sources.json</code>](#datasourceall_sources-datasourceall_sourcesmsgpack-datasourceall_sourcesjson)
      * [/datasource/types /datasource/types.msgpack, <code>/datasource/types.json</code>](#datasourcetypes-datasourcetypesmsgpack-datasourcetypesjson)
      * [/datasource/defaults /datasource/defaults.msgpack, <code>/datasource/defaults.json</code>](#datasourcedefaults-datasourcedefaultsmsgpack-datasourcedefaultsjson)
      * [/datasource/list_interfaces /datasource/list_interfaces.msgpack, <code>/datasource/list_interfaces.json</code>](#datasourcelist_interfaces-datasourcelist_interfacesmsgpack-datasourcelist_interfacesjson)
      * [/datasource/by-uuid/[uuid]/source /datasource/by-uuid/[uuid]/source.msgpack, <code>/datasource/by-uuid/[uuid]/source.json</code>](#datasourceby-uuiduuidsource-datasourceby-uuiduuidsourcemsgpack-datasourceby-uuiduuidsourcejson)
    * [Controlling data sources](#controlling-data-sources)
      * [/datasource/add_source.cmd /datasource/add_source.cmd](#datasourceadd_sourcecmd-datasourceadd_sourcecmd)
      * [POST /datasource/by-uuid/[uuid]/set_channel /datasource/by-uuid/[uuid]/set_channel.cmd, <code>/datasource/by-uuid/[uuid]/set_channel.jcmd</code>](#post-datasourceby-uuiduuidset_channel-datasourceby-uuiduuidset_channelcmd-datasourceby-uuiduuidset_channeljcmd)
      * [POST /datasource/by-uuid/[uuid]/set_hop /datasource/by-uuid/[uuid]/set_hop.cmd, `/datasource/by-uuid/[uuid]/set_channel.jcmd]](#post-datasourceby-uuiduuidset_hop-datasourceby-uuiduuidset_hopcmd-datasourceby-uuiduuidset_channeljcmd)
      * [/datasource/by-uuid/[uuid]/close_source /datasource/by-uuid/[uuid]/close_source.cmd](#datasourceby-uuiduuidclose_source-datasourceby-uuiduuidclose_sourcecmd)
      * [/datasource/by-uuid/[uuid]/open_source /datasource/by-uuid/[uuid]/open_source.cmd](#datasourceby-uuiduuidopen_source-datasourceby-uuiduuidopen_sourcecmd)
      * [/datasource/by-uuid/[uuid]/disable_source /datasource/by-uuid/[uuid]/disable_source.cmd](#datasourceby-uuiduuiddisable_source-datasourceby-uuiduuiddisable_sourcecmd)
      * [/datasource/by-uuid/[uuid]/enable_source /datasource/by-uuid/[uuid]/enable_source.cmd](#datasourceby-uuiduuidenable_source-datasourceby-uuiduuidenable_sourcecmd)
      * [/datasource/by-uuid/[uuid]/pause_source /datasource/by-uuid/[uuid]/pause_source.cmd](#datasourceby-uuiduuidpause_source-datasourceby-uuiduuidpause_sourcecmd)
      * [/datasource/by-uuid/[uuid]/pause_source /datasource/by-uuid/[uuid]/resume_source.cmd](#datasourceby-uuiduuidpause_source-datasourceby-uuiduuidresume_sourcecmd)
  * [GPS](#gps)
      * [/gps/drivers /gps/drivers.json <code>/gps/drivers.msgpack</code>](#gpsdrivers-gpsdriversjson-gpsdriversmsgpack)
      * [/gps/all_gps /gps/all_gps.json <code>/gps/all_gps.msgpack</code>](#gpsall_gps-gpsall_gpsjson-gpsall_gpsmsgpack)
      * [/gps/location /gps/location.json <code>/gps/location.msgpack</code>](#gpslocation-gpslocationjson-gpslocationmsgpack)
      * [/gps/web/update.cmd](#gpswebupdatecmd)
  * [Packet Capture](#packet-capture)
      * [/pcap/all_packets.pcapng](#pcapall_packetspcapng)
      * [/datasource/pcap/all_sources.pcapng](#datasourcepcapall_sourcespcapng)
      * [/datasource/pcap/by-uuid/[uuid]/[uuid].pcapng](#datasourcepcapby-uuiduuiduuidpcapng)
      * [/devices/by-key/[key]/pcap/[key].pcapng](#devicesby-keykeypcapkeypcapng)
  * [Plugins](#plugins)
      * [/plugins/all_plugins /plugins/all_plugins.msgpack, <code>/plugins/all_plugins.json</code>](#pluginsall_plugins-pluginsall_pluginsmsgpack-pluginsall_pluginsjson)
  * [Streams](#streams)
      * [/streams/all_streams /streams/all_streams.msgpack, <code>/streams/all_streams.json</code>](#streamsall_streams-streamsall_streamsmsgpack-streamsall_streamsjson)
      * [/streams/by-id/[id]/stream_info /streams/by-id/[id]/stream_info.msgpack, <code>/streams/by-id/[id]/stream_info.json</code>](#streamsby-ididstream_info-streamsby-ididstream_infomsgpack-streamsby-ididstream_infojson)
      * [/streams/by-id/[id]/close_stream.cmd](#streamsby-ididclose_streamcmd)
  * [Logging](#logging)
      * [/logging/drivers /logging/drivers.msgpack, <code>/logging/drivers.json</code>](#loggingdrivers-loggingdriversmsgpack-loggingdriversjson)
      * [/logging/active /logging/active.msgpack, <code>/logging/active.json</code>](#loggingactive-loggingactivemsgpack-loggingactivejson)
      * [/logging/by-class/[class]/start /logging/by-class/[class]/start.cmd, <code>/logging/by-class/[class]/start.jcmd</code>](#loggingby-classclassstart-loggingby-classclassstartcmd-loggingby-classclassstartjcmd)
      * [POST /logging/by-class/[class]/start /logging/by-class/[class]/start.cmd, <code>/logging/by-class/[class]/start.jcmd</code>](#post-loggingby-classclassstart-loggingby-classclassstartcmd-loggingby-classclassstartjcmd)
      * [/logging/by-uuid/[uuid]/stop /logging/by-uuid/[uuid]/stop.cmd, <code>/logging/by-uuid/[uuid]/stop.jcmd</code>](#loggingby-uuiduuidstop-loggingby-uuiduuidstopcmd-loggingby-uuiduuidstopjcmd)
  * [Phy-Specific:  phy80211 (Wi-Fi)](#phy-specific--phy80211-wi-fi)
      * [/phy/phy80211/by-key/[key]/pcap/[key]-handshake.pcap](#phyphy80211by-keykeypcapkey-handshakepcap)
      * [/phy/phy80211/by-bssid/[MAC]/pcap/[MAC].pcapng](#phyphy80211by-bssidmacpcapmacpcapng)
  * [Phy-Specific: phyuav (UAV / Drones)](#phy-specific-phyuav-uav--drones)
      * [/phy/phyuav/manuf_matchers /phy/phyuav/manuf_matchers.json <code>/phy/phyuav/manuf_matchers.msgpack</code>](#phyphyuavmanuf_matchers-phyphyuavmanuf_matchersjson-phyphyuavmanuf_matchersmsgpack)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)

=========================

Kismet uses a REST-like interface on the embedded web server for providing data and accepting commands.  Generally, data is fetched via HTTP GET and commands are sent via HTTP POST.  Whenever possible, parameters are sent via the GET URI, but for more complex features, command arguments are sent via POST.

*Broadly speaking*, nearly all endpoints in Kismet should support all output and serialization methods.  By default, these are JSON and Msgpack, but additional output serializers may be added in the future or added by plugins.  Some unique endpoints are available only under specific output methods, typically these take advantage of features found only in that output type.

## Exploring the REST system

The easiest way to explore the REST system, aside from the docs, is to query the JSON endpoints directly.  You can use `curl` and `python` to quickly grab output and format the JSON to be human readable:

```
$ curl http://localhost:2501/datasource/all_sources.json | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 36274  100 36274    0     0   761k      0 --:--:-- --:--:-- --:--:--  770k
[
    {
        "kismet.datasource.capture_interface": "wlp3s0mon",
        "kismet.datasource.channel": "",
        "kismet.datasource.channels": [
            "1",
            "1HT40+",
            "2",
            "3",
            "4",
            "5",
            "6",
            "6HT40-",
            "6HT40+",
            "7",
            "8",
            "9",
            "10",
            "11",
            "11HT40-"
        ],
        "kismet.datasource.definition": "wlp3s0",
        "kismet.datasource.dlt": 127,
        "kismet.datasource.error": 0,
        "kismet.datasource.error_reason": "",
        "kismet.datasource.hop_channels": [
....
```

Similarly, POST data can be sent via curl; for example to test creating an alert via the dynamic alerts endpoint:

```bash
$ curl -d 'json={"name": "JSONALERT", "description": "Dynamic alert added at runtime", "throttle": "10/min", "burst": "1/sec"}' http://kismet:kismet@localhost:2501/alerts/definitions/define_alert.cmd
```

which passes the parameters in the `json=` variable, and the login and password in the URI (kismet:kismet in this example).

More information about each field can be found in the `/system/tracked_fields.html` URI by visiting `http://localhost:2501/system/tracked_fields.html` in your browser.  This will show the field names, descriptions, and data types, for every known entity.

For even more information, almost every REST endpoint can be requested using the `{foo}.prettyjson` format; this JSON output is styled for ease of readability and includes additional metadata to help understand the format; for example:

```
$ curl http://localhost:2501/system/status.prettyjson
 {
 "description.kismet.device.packets_rrd": "string, RRD of total packets seen",
 "kismet.device.packets_rrd":
  {
  "description.kismet.common.rrd.last_time": "uint64_t, last time udpated",
  "kismet.common.rrd.last_time": 1506473162,
...
 "description.kismet.system.battery.percentage": "int32_t, remaining battery percentage",
 "kismet.system.battery.percentage": 96,

 "description.kismet.system.battery.charging": "string, battery charging state",
 "kismet.system.battery.charging": "discharging",

 "description.kismet.system.battery.ac": "uint8_t, on AC power",
 "kismet.system.battery.ac": 0,

 "description.kismet.system.battery.remaining": "uint32_t, battery remaining in seconds",
 "kismet.system.battery.remaining": 0,

 "description.kismet.system.timestamp.sec": "uint64_t, system timestamp, seconds",
 "kismet.system.timestamp.sec": 1506473162,
 }
}
```

For each defined field, Kismet will include a metadata field, `description.whatever.field.name`, which gives the type (for instance, uint32_t for a 32bit unsigned int), and the description, for instance 'battery remaining in seconds'.

While the `prettyjson` format is well suited for learning about Kismet and developing tools to interface with the REST API, the `json` format should be used for final code; it is significantly faster than `prettyjson` and is optimized for processing time and space.

`prettyjson` should work with nearly all REST endpoints which return JSON records, but will *NOT* work with `ekjson`-only endpoints (which are relatively rare, and documented accordingly below in the REST docs).

## Serialization Types

Kismet can export data as several different formats; generally these formats are indicated by the type of endpoint being requested (such as foo.msgpack or foo.json)

### JSON

Kismet will export objects in traditional JSON format suitable for consumption in javascript or any other language with a JSON interpreter.

### MSGPACK

Kismet can export objects in binary msgpack format, which may in some instances offer an advantage in parsing time over stock JSON.  The format of the msgpack and json objects will be identical.

### EKJSON

"EK" JSON is modeled after the Elastic Search JSON format, where a complete JSON object is found on each line of the output.

Kismet supports ekjson on any REST UI which returns a vector/list/array of results.  The results will be the same as standard JSON, however each item in the list will be a discrete JSON object.

The primary advantage of the ekjson format is the ability to process it *as a stream* instead of as a single giant object - this reduces the client-side memory requirements of searches with a large number of devices drastically.

### PRETTYJSON

"Pretty" JSON is optimized for human readability and includes metadata fields describing what Kismet knows about each field in the JSON response.  For more information, see the previous section, `Exploring the REST system`.

"Pretty" JSON should only be used for learning about Kismet and developing; for actual use of the REST API standard "JSON" or "EKJSON" endpoints should be used as they are significantly faster and optimized.

## Logins and Sessions

Kismet uses session cookies to maintain a login session.  Typically GET requests which do not reveal sensitive configuration data do not require a login, while POST commands which change configuration or GET commands which might return parts of the Kismet configuration values will require the user to login with the credentials in the `kismet_httpd.conf` config file.

Sessions are created via HTTP Basic Auth.  A session will be created for any valid login passed to a page requiring authentication.  Logins may be validated directly against the `/session/check_session` endpoint by passing HTTP Basic Auth to it.

Session IDs are returned in the `KISMET` session cookie.  Clients which interact with logins should retain this session cookie and use it for future communication.

## Commands

Commands are sent via HTTP POST.  Currently, a command should be a base64-encoded msgpack string dictionary containing key:value pairs, sent under the `msgpack` or `json` POST fields.  This may be subject to change as the HTTP interface evolves.

Commands should always be sent using the `x-www-form-encoded` content type; if your API does not do this by default, you may need to specify:

```
Content-Type: application/x-www-form-urlencoded; charset=utf-8
```

as part of the requests you send.


For instance, a command created in Python might look like:

```python
# Build the dictionary
cmd = {
    "cmd": "lock",
    "channel": "6",
    "uuid": "aaa:bbb:cc:dd:ee:ff:gg"
}

# Encode msgpack binary
cmdbin = msgpack.packb(cmd)

# Encode as base64
cmdencoded = base64.b64encode(cmdbin)

# Set up the POST dictionary
post = {
    "msgpack": cmdencoded
}
```

A similar command generated in Javascript might be:

```javascript
var json = {
    "cmd": "lock",
    "channel": "6",
    "uuid": "aaa:bbb:cc:dd:ee:ff:gg"
};

var postdata = "json=" + JSON.stringify(json);

$.post("/some/endpoint", data = postdata, dataType = "json");
```

Commands are encoded as dictionaries to allow flexibility across calling platforms, as well as forward-compatibility as endpoints evolve.  Adding additional keys to an options dictionary should not cause an older version of the server code to return an error.

Dictionary key values are case sensitive.

### Field Specifications

Several endpoints in Kismet take a field specification for limiting the fields returned - this allows scripts which query Kismet rapidly to request only the fields they need, and are strongly recommended.

Field specification objects take the format of a vector/array containing multiple field definitions:

```python
[
    field1,
    ...
    fieldN
]
```

where a field may be a single element string, defining a field name or a field path, such as:

* `'kismet.device.base.channel'`
* `'kismet.device.base.signal/kismet.common.signal.last_signal_dbm'`

*or* a field may be a two-element array, consisting of a field name or path, and a target name the field will be aliased as, for example:

* `[kismet.device.base.channel', 'base.channel']`
* `[kismet.device.base.signal/kismet.common.signal.last_signal_dbm', 'base.last.signal']`

Fields will be returned in the device as their final path name:  that is, from the above example, the device would contain:

`['kismet.device.base.channel', 'kismet.common.signal.last_signal_dbm']`

And from the second example, it would contain:

`['base.channel', 'base.last.signal']`

When requesting multiple fields from different paths with the same name - for instance, multiple signal paths provide the `kismet.common.signal.last_signal_dbm` - it is important to provide an alias.  Fields which resolve to the same name will only be present in the results once, and the order is undefined.

### Filter Specifications

Some endpoints in Kismet take a regex object.  These endpoints use a common format, which allows for multiple regular expressions to be mapped to multiple fields.  A device is considered to match if *any* of the regular expression terms are true.

If the Kismet server was compiled without libpcre support, passing a regular expression to an endpoint will cause the endpoint to return an error.

```python
[
    [ multifield, regex ],
    ...
    [ multifield, regex ]
]
```

#### `multifield`

`multifield` is a standard field path, but it will be automatically expanded to match all values if a vector or value-map field is encountered in the path.  For example, the multifield path:

`'dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid'`

will be expanded to include all `dot11.advertisedssid` objects in the `advetised_ssid_map` dictionary, and will apply to the `dot11.advertisedssid.ssid` field in each.  Similarly, vectors, intmaps, doublemaps, macmaps, and so forth will be expanded, allowing matching against nested fields.

The field is expected to resolve as a string:  if it is not a string, the regex will be considered to not match.

#### `regex`

`regex` is a simple string containing a PCRE-compatible regular expression.

#### Example

For example, to match on SSIDs, a regex object might be:

```python
regex = [
    [ 'dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid', '^SomePrefix.*' ],
    [ 'dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid', '^Linksys$' ]
]
```

## REST Endpoints

### System Status

##### /system/status `/system/status.msgpack`, `/system/status.json`

Dictionary of system status, including uptime, battery, and memory use.

##### /system/timestamp `/system/timestamp.msgpack`, `/system/timestamp.json`

Dictionary of system timestamp as second, microsecond; can be used to synchronize timestamps.

##### /system/tracked_fields `/system/tracked_fields.html`
Human-readable table of all registered field names, types, and descriptions.  While it cannot represent the nested features of some data structures, it will describe every allocated field.  This endpoint returns a HTML document for ease of use.


### Device Handling

A device is the central record of a tracked entity in Kismet.  Clients, bridges, access points, wireless sensors, and any other type of entity seen by Kismet will be a device.  For complex relationships (such as 802.11 Wi-Fi), a list of related devices describes the access point-client relationship.

All devices will have a basic set of records (held in the `kismet.base.foo` group of fields, generally) and sub-trees of records attached by the phy-specific handlers.  A device may have multiple phy-specific records, for instance a device may contain both a `device.dot11` record and a `device.uav` record if it is seen to be a Wi-Fi based UAV/Drone device.

The preferred method of retrieving device lists is to use the POST URI `/devices/summary/` or `/devices/last-time` with a list of fields provided.  Whenever possible, limiting the fields requested and the time range requested will reduce the load on the Kismet server *and* the client consuming the data.

##### POST /devices/summary/devices `/devices/summary/devices.msgpack`, `/devices/summary/devices.json`

A POST endpoint which returns a summary of all devices.  This endpoint expects a variable containing a dictionary which defines the fields to include in the results; only these fields will be sent.

Optionally, a regex dictionary may be provided to filter the devices returned.

Additionally, a wrapper may be specified, which indicates a transient dictionary object which should contain these values; This is used by dataTables to wrap the initial query in an `aaData` object required for that API.

The command dictionary should be passed as either JSON in the `json` POST variable, or as base64-encoded msgpack in the `msgpack` variable, and is expected to contain:

| Key     | Value               | Type                      | Desc                                     |
| ------- | ------------------- | ------------------------- | ---------------------------------------- |
| fields  | Field specification | field specification array | Optional, simplified field listing.      |
| regex   | Regex specification | regular expression array  | Optional, array of field path and regular expressions |
| wrapper | "foo"               | string                    | Optional, wrapper dictionary to surround the data |

##### /devices/all_devices.ekjson

Special endpoint generating EK (elastic-search) style JSON.  On this endpoint, each device is returned as a JSON object, one JSON record per line.

This can be useful for incrementally parsing the results or feeding the results to another tool like elasticsearch.

##### POST /devices/last-time/[TS]/devices `/devices/last-time/[TS]/devices.msgpack`, `devices/last-time/[TS]/devices.json`, `devices/last-time/[TS]/devices.ekjson`

List containing the list of all devices which are new or have been modified since the server timestamp `[TS]`.

If `[TS]` is negative, it will be translated to be `[TS]` seconds before the current server timestamp; a client may therefor request all devices modified in the past 60 seconds by passing a `[TS]` of `-60`.

This endpoint is most useful for clients and scripts which need to monitor the state of *active* devices.

This endpoint accepts a field simplification dictionary which defines the fields to include in the results; only these fields will be sent.

Optionally, a regex dictionary may be provided to filter the devices returned.

The command dictionary should be passed as either JSON in the `json` POST variable, or as base64-encoded msgpack in the `msgpack` variable, and is expected to contain:

| Key    | Value               | Type                      | Desc                                     |
| ------ | ------------------- | ------------------------- | ---------------------------------------- |
| fields | Field specification | Field specification array | Optional, field listing                  |
| regex  | Regex specification | Regular expression array  | Optional, array of field paths and regular expressions |

##### /devices/last-time/[TS]/devices `/devices/last-time/[TS]/devices.msgpack`, `devices/last-time/[TS]/devices.json`, `devices/last-time/[TS]/devices.ekjson`

List containing the list of all devices which are new or have been modified since the server timestamp `[TS]`.

If `[TS]` is negative, it will be translated to be `[TS]` seconds before the current server timestamp; a client may therefor request all devices modified in the past 60 seconds by passing a `[TS]` of `-60`.

This endpoint is most useful for clients and scripts which need to monitor the state of *active* devices.

The device list may be further refined by using the `POST` equivalent of this URI.

##### /devices/by-key/[DEVICEKEY]/device `/devices/by-key/[DEVICEKEY]/device.msgpack`, `/devices/by-key/[DEVICEKY]/device.json`

Complete dictionary object containing all information about the device referenced by [DEVICEKEY].

##### POST /devices/by-key/[DEVICEKEY]/device `/devices/by-key/[DEVICEKEY]/device.msgpack`, `/devices/by-key/[DEVICEKY]/device.json`

Dictionary object of device, simplified by the `fields` argument in accordance to the field simplification rules described above.

The command dictionary should be passed as either JSON in the `json` POST variable, or as base64-encoded msgpack in the `msgpack` variable, and is expected to contain:

| Key    | Value               | Type                      | Desc                                |
| ------ | ------------------- | ------------------------- | ----------------------------------- |
| fields | Field specification | Field specification array | Optional, array of fields to return |

##### /devices/by-key/[DEVICEKEY]/device[/path/to/subkey] `/devices/by-key/[DEVICEKEY]/device.msgpack[/path/to/subkey]`, `/devices/by-key/[DEVICEKEY]/device.json[/path/to/subkey]`

Dictionary containing all the device data referenced by `[DEVICEKEY]`, in the sub-tree `[path/to/subkey]`.  Allows fetching single fields or objects from the device tree without fetching the entire device record.

##### /devices/by-mac/[DEVICEMAC]/devices `/devices/by-mac/[DEVICEMAC]/devices.msgpack`, `/devices/by-mac/[DEVICEMAC]/devices.json`

Array/list of all devices matching `[DEVICEMAC]` across all PHY types.  It is possible (though not likely) that there can be a MAC address collision between different PHY types, especially types which synthesize false MAC addresses when no official address is available.

##### POST /devices/by-mac/[DEVICEMAC]/devices `/devices/by-mac/[DEVICEMAC]/devices.msgpack`, `/devices/by-mac/[DEVICEMAC]/devices.json`

Dictionary object of device, simplified by the `fields` argument in accordance to the field simplification rules described above.

The command dictionary should be passed as either JSON in the `json` POST variable, or as base64-encoded msgpack in the `msgpack` variable, and is expected to contain:

| Key    | Value               | Type                      | Desc                                |
| ------ | ------------------- | ------------------------- | ----------------------------------- |
| fields | Field specification | Field specification array | Optional, array of fields to return |

##### POST /devices/by-phy/[PHYNAME]/devices `/devices/by-phy/[PHYNAME]/devices.msgpack`, `/devices/by-phy/[PHYNAME]/devices.json`, `/devices/by-phy/[PHYNAME]/devices.ekjson`

List of devices, belonging to the phy `PHYNAME`.  The request can be filtered by regex and time, and simplified by the field simplification system.

The command dictionary should be passed as either JSON in the `json` POST variable, or as base64-encoded msgpack in the `msgpack` variable, and is expected to contain:

| Key       | Value                           | Type    | Desc                                     |
| --------- | ------------------------------- | ------- | ---------------------------------------- |
| fields    | Field specification             | Array   | Optional, field specification array listing fields and mappings |
| regex     | Regex specification             | Array   | Optional, regex specification array listing fields and regex values |
| last_time | Timestamp or relative timestamp | Integer | Optional, timestamp.  If negative, treated as a relative timestamp (N seconds prior to now), if positive, treated as an absolute unix timestamp.  For example, `'last_time': -60` would return all devices in the past minute. |

### Device Editing

Some device attributes (such as the device name and notes fields) can be set from the REST API.

##### /devices/by-key/[key]/set_name `/device/by-key/[key]/set_name.cmd`  

*REQUIRES LOGIN*

Sets the 'username' field of the target device.

Expects a command dictionary including:

| Key      | Value    | Type   | Desc                |
| -------- | -------- | ------ | ------------------- |
| username | New name | String | New name for device |

##### /devices/by-key/[key]/set_tag `/dev/by-key/[key]/set_tag.cmd`

*REQUIRES LOGIN*

Set an arbitrary tag in the 'tags collection' of the target device.  The tags collection is returned in the `kismet.device.base.tags` field of the device, and can be used to store persistent notes and other data.

Expects a command dictionary including:

| Key     | Value    | Type   | Desc                          |
| ------- | -------- | ------ | ----------------------------- |
| tagname | Tag name | String | Name of tag; arbitrary string |
| tagvalue | Tag value | String | Content of tag |

### Phy Handling

A PHY handler processes a specific type of radio physical layer - 802.11, Bluetooth, and so on.  A PHY is often, but not always, linked to specific types of hardware and specific packet link types.

##### /phy/all_phys `/phy/all_phys.msgpack`, `/phy/all_phys.json`

Array of all PHY types and statistics

### Sessions and Logins

##### `/session/check_session`

Check if a login/session cookie is valid.  Login will only be consulted if the session cookie is not present or is invalid.

Returns 200 OK if session is valid, basic auth prompt if invalid.

##### `/session/check_login`

Check if a login is valid.  Login will always be checked, any session cookies will be ignored.

Returns 200 OK if login is valid, 403 Unauthorized if login is invalid.

### Messages

Kismet uses the `messagebus` as in internal system for displaying message to the user.  The messagebus is used to pass error and state messages, as well as notifications about detected devices, etc.

##### /messagebus/all_messages `/messagebus/all_messages.msgpack`, `/messagebus/all_messages.json`

Vector of the last 50 messages stored in Kismet

##### /messagebus/last-time/[TS]/messages `/messagebus/last-time/[TS]/messages.msgpack`, `/messagebus/last-time/[TS]/messages.json`

Dictionary containing a list of all messages since server timestamp `[TS]`, and a timestamp record indicating the time of this report.  This can be used to fetch only new messages since the last time messages were fetched.

### Alerts

Kismet provides alerts via the `/alert/` REST collection.  Alerts are generated as messages and as alert records with machine-processable details.  Alerts can be generated for critical system states, or by the WIDS system.

##### /alerts/definitions `/alerts/definitions.msgpack`, `/alerts/definitions.json`

All defined alerts, including descriptions, time and burst limits, and current alert counts and states for each type.

##### /alerts/all_alerts `/alerts/all_alerts.msgpack`, `/alerts/all_alerts.json`

List of the alert backlog.  The size of the backlog is configurable via the `alertbacklog` option in kismet.conf

##### /alerts/last-time[TS]/alerts `/alerts/last-time/[TS]/alerts.msgpack`, `/alerts/last-time/[TS]/alerts.json`

Dictionary containing a list of alerts since Kismet double-precision timestamp `[TS]`, and a timestamp record indicating the time of this report.  This can be used to fetch only new alerts since the last time alerts were requested.

Double-precision timestamps include the microseconds in the decimal value.  A pure second-precision timestamp may be provided, but could cause some alerts to be missed if they occurred in the fraction of the second after the request.

##### POST /alerts/definitions/define_alert.cmd

*LOGIN REQUIRED*

Define and activate a new alert.  This alert can then be raised via the `raise_alert.cmd` URI.

Expects a command dictionary including:

| Key         | Value               | Type   | Desc                                     |
| ----------- | ------------------- | ------ | ---------------------------------------- |
| name        | Alert name          | String | Simple alert name/identifier             |
| description | Alert description   | String | Alert explanation / definition displayed to the user |
| phyname     | Name of phy type    | String | (Optional) name of phy this alert is associated with.  If not provided, alert will apply to all phy types.  If provided, the defined phy *must* be found or the alert will not be defined. |
| throttle    | Alert throttle rate | String | Maximum number of alerts per time period, as defined in kismet.conf.  Time period may be 'sec', 'min', 'hour', or 'day', for example '10/min' |
| burst       | Alert burst rate    | String | Maximum number of sequential alerts per time period, as defined in kismet.conf.  Time period may be 'sec', 'min', 'hour', or 'day'.  Alerts will be throttled to this burst rate even when the overall limit has not been hit.  For example, '1/sec' |

##### POST /alerts/raise_alert.cmd

*LOGIN REQUIRED*

Trigger an alert.  This generates a standard Kismet alert of the specified type and parameters.

Expects a command dictionary including:

| Key     | Value         | Type   | Desc                                     |
| ------- | ------------- | ------ | ---------------------------------------- |
| name    | Alert name    | String | Alert name/identifier.  Must be a defined alert name. |
| text    | Alert content | String | Human-readable text for alert            |
| bssid   | MAC address   | String | (optional) MAC address of the BSSID, if Wi-Fi, related to this alert |
| source  | MAC address   | String | (optional) MAC address the source device which triggered this alert |
| dest    | MAC address   | String | (optional) MAC address of the destination device which triggered this alert |
| other   | MAC address   | String | (optional) Related other MAC address of the event which triggered this alert |
| channel | Channel       | String | (optional) Phy-specific channel definition of the event which triggered this alert |

### Channels

##### /channels/channels `/channels/channels.msgpack`, `/channels/channels.json`

Channel usage and monitoring data.

### Datasources

Kismet uses data sources to capture information - typically packets, but sometimes complete device or event records.  Data sources are defined in the Kismet config file via the `source=...` config option, or on the Kismet command line with the `-c` option as in `kismet -c wlan1`.

#### Querying data sources

##### /datasource/all_sources `/datasource/all_sources.msgpack`, `/datasource/all_sources.json`

List containing all data sources and the current information about them

##### /datasource/types `/datasource/types.msgpack`, `/datasource/types.json`

List containing all defined datasource types & basic information about them

##### /datasource/defaults `/datasource/defaults.msgpack`, `/datasource/defaults.json`

Default settings for new data sources

##### /datasource/list_interfaces `/datasource/list_interfaces.msgpack`, `/datasource/list_interfaces.json`

Query all possible data source drivers and return a list of auto-detected interfaces that could be used to capture.

##### /datasource/by-uuid/[uuid]/source `/datasource/by-uuid/[uuid]/source.msgpack`, `/datasource/by-uuid/[uuid]/source.json`

Return information about a specific data source, specified by the source UUID `[uuid]`

#### Controlling data sources

##### /datasource/add_source.cmd `/datasource/add_source.cmd`

*LOGIN REQUIRED*.

Dynamically add a new source to Kismet.

Expects a string variable named 'definition'.  This value is identical to the `source=interface:flags` format passed in the Kismet config file or via the `-c` command line option.

`add_source.cmd` will return a successful HTTP code when the *source is successfully added*.  This may not equate to a source which is *successfully running* due to automatic re-opening of sources and other Kismet behavior.  The caller can check the returned UUID to query the status of the source.  If the source cannot be created, HTTP 500 is returned.

`add_source.cmd` will block until the source add is completed; this may be up to several seconds but typically will be nearly instant.

##### POST /datasource/by-uuid/[uuid]/set_channel `/datasource/by-uuid/[uuid]/set_channel.cmd`, `/datasource/by-uuid/[uuid]/set_channel.jcmd`

*LOGIN REQUIRED*.

Change the channel configuration of the source identified by `[uuid]` - can be used to set a fixed channel or to control channel hopping.

`set_channel.cmd` will return a successful HTTP code when the *channel is successfully set*.  If the channel or hopping pattern cannot be set, HTTP 500 is returned.

`set_channel.cmd` will block until the source channel set is complete; this may be up to several seconds but typically will be nearly instant.

Expects a command dictionary including:

| Key      | Value                 | Type              | Desc                                     |
| -------- | --------------------- | ----------------- | ---------------------------------------- |
| channel  | Single channel        | String            | Single channel; This disables channel hopping and sets a specific channel.  Channel format depends on the source. |
| hoprate  | Channel hopping speed | Double            | Channel hopping speed, as channels per second.  For timing greater than a second, rate can be calculated with the formula `hoprate = 1 / (6 / N)` where N is the number of hops per minute. |
| channels | List of channels      | Vector of strings | The list of channel strings to use in hopping |
| shuffle  | 0 / 1                 | Integer           | Treated as boolean, tells the source to shuffle the channel list |

* If `channel` is present, `hoprate`, `channels`, and `shuffle` should not be included, and will be ignored if present.  The source will be locked to a single channel.
* If `channel` is not present, the remaining fields may be specified.
* If `channels` is present, `hoprate` and `shuffle` are optional.  If they are not present, the current values for the source will be used.
* If `channel` is not present, `channels` is not present, and `hoprate` is set, only the channel hopping rate will be changed.

Examples:

* `{'channel': "6HT40"}` will lock to Wi-Fi channel 6, HT40+ mode
* `{'channels': ["1", "2", "6HT40+", "6HT40-"]}` will change the channel hopping list but retain the hopping rate and shuffle
* `{'channels': ["1", "2", "3", "4", "5"], 'hoprate': 1}` will change the channel hopping rate to once per second over the given list
* `{'hoprate': 5}` will set the hop rate to 5 channels per second, using the existing channels list in the datasource

##### POST /datasource/by-uuid/[uuid]/set_hop `/datasource/by-uuid/[uuid]/set_hop.cmd`, `/datasource/by-uuid/[uuid]/set_channel.jcmd]

*LOGIN REQUIRED*

Set hopping on the source indicated by `[uuid]`, using the sources existing information for hopping rate, channels, etc.

This can be teamed with `/datasource/by-uuid/[uuid]/set_channel` for simple locking/hopping behavior.

##### /datasource/by-uuid/[uuid]/close_source `/datasource/by-uuid/[uuid]/close_source.cmd`

*LOGIN REQUIRED*.

Close a source.  This puts the source into closed state, stops all packet capture, and terminates the capture binary.

The source will remain in the sources list once closed.

Closed sources will not attempt to re-open.

##### /datasource/by-uuid/[uuid]/open_source `/datasource/by-uuid/[uuid]/open_source.cmd`

*LOGIN REQUIRED*.

Re-open a closed source; this uses the same definition as the existing closed source.

##### /datasource/by-uuid/[uuid]/disable_source `/datasource/by-uuid/[uuid]/disable_source.cmd`

*LOGIN REQUIRED*.

Alias for `close_source`, stops a source (if running) and cancels reconnect attempts.

##### /datasource/by-uuid/[uuid]/enable_source `/datasource/by-uuid/[uuid]/enable_source.cmd`

*LOGIN REQUIRED*.

Alias for `open_source`, re-opens a defined source.

##### /datasource/by-uuid/[uuid]/pause_source `/datasource/by-uuid/[uuid]/pause_source.cmd`

*LOGIN REQUIRED*.

Pauses a source - the source will remain open, but no packets will be processed.  Any packets received from the source while it is paused will be lost.

##### /datasource/by-uuid/[uuid]/pause_source `/datasource/by-uuid/[uuid]/resume_source.cmd`

*LOGIN REQUIRED*.

Resumes (un-pauses) the specified source.  Packet processing will be resumed, but any packets seen while the source was paused will be lost.

### GPS

Kismet now supports multiple simultaneous GPS devices, and can select the 'best' quality device based on priority and GPS signal.

##### /gps/drivers `/gps/drivers.json` `/gps/drivers.msgpack`

Returns a list of all supported GPS driver types

##### /gps/all_gps `/gps/all_gps.json` `/gps/all_gps.msgpack`

Returns a list of all GPS devices

##### /gps/location `/gps/location.json` `/gps/location.msgpack`

Returns the current optimum location (as determined by the priority of connected GPS devices)

##### `/gps/web/update.cmd`

*LOGIN REQUIRED*.

This API allows browsers and browser-like clients to set the GPS coordinates over POST.  This is most likely useful when using a mobile device with a GPS of its own as the front-end and can use the standard browser location API.

Requires that the Kismet server has the 'web' GPS driver enabled via kismet.conf: `gps=web:name=webgps`.

Expects a command dictionary including:

| Key  | Value                | Type   | Desc                                    |
| ---- | -------------------- | ------ | --------------------------------------- |
| lat  | latitude             | double | GPS latitude                            |
| lon  | longitude            | double | GPS longitude                           |
| alt  | altitude (in Meters) | double | GPS altitude in meters (optional)       |
| spd  | speed (kph)          | double | Speed in kilometers per hour (optional) |

### Packet Capture

Kismet can export packets in the pcap-ng format; this is a standard, extended version of the traditional pcap format.  Tools such as Wireshark (and tshark) can process complete pcapng frames, while tcpdump and other libpcap based tools (currently including Kismet) can process the simpler version of pcapng.

##### /pcap/all_packets.pcapng 

*LOGIN REQUIRED*

Returns a stream of all packets seen by Kismet, in pcap-ng multi-interface format.

The pcap-ng format allows for multiple interfaces with multiple link types in a single pcapng file.  This format can be read and processed by Wireshark and tshark, but may not be compatible with all traditional libpcap based tools.

For compatibility with all libpcap tools, it may be necessary to post-process this file.  Alternatively, a device-specific libpcap will return a single interface and linktype.

This URI will stream indefinitely as packets are received.

##### /datasource/pcap/all_sources.pcapng

*LOGIN REQUIRED*

Returns a stream of all packets seen by Kismet, in pcap-ng multi-interface format.

The pcap-ng format allows for multiple interfaces with multiple link types in a single pcapng file.  This format can be read and processed by Wireshark and tshark, but may not be compatible with all traditional libpcap based tools.

For compatibility with all libpcap tools, it may be necessary to post-process this file.  Alternatively, a device-specific libpcap will return a single interface and linktype.

This URI will stream indefinitely as packets are received.

##### /datasource/pcap/by-uuid/[uuid]/[uuid].pcapng

*LOGIN REQUIRED*

Returns a stream of all packets seen by Kismet on a *specific datasource*, in pcap-ng format.

Nearly all tools which support libpcap should be able to read a single-interface single-linktype pcapng file, including tcpdump and Kismet itself.  It should not be necessary to post-process this file to use on libpcap-based tools.

To capture *all* packets from *all* interfaces, use the `/datasource/pcap/all_sources.pcapng` URI.

This URI will stream stream indefinitely as packets are received.

##### /devices/by-key/[key]/pcap/[key].pcapng

*LOGIN REQUIRED*

Returns a stream in pcap-ng format of all packets, from all interfaces, associated with the device specified by `[key]`; This stream will only include packets from the specified device (it will not include packets communicating *with* this device, only packets tagged as *originating with* this device.

This URI will stream indefinitely as packets are received.

### Plugins

Kismet plugins may be active C++ code (loaded as a plugin.so shared object file) or they may be web content only which is loaded into the UI without requiring additional back-end code.

##### /plugins/all_plugins `/plugins/all_plugins.msgpack`, `/plugins/all_plugins.json`

Returns a vector of all activated Kismet plugins.

### Streams

A Kismet stream is any continually exporting entity - it can be a pcap file logged to disk, other disk logs, or logs streaming over the web interface.

##### /streams/all_streams `/streams/all_streams.msgpack`, `/streams/all_streams.json`

Returns a vector of all active Kismet streams.

##### /streams/by-id/[id]/stream_info `/streams/by-id/[id]/stream_info.msgpack`, `/streams/by-id/[id]/stream_info.json`

Returns information about a specific stream, indicated by `[id]`

##### /streams/by-id/[id]/close_stream.cmd

*LOGIN REQUIRED*

Closes the stream (ending the log) specified by `[id]`

### Logging

Kismet has a centralized logging architecture which can report what logs are enabled, and what logs are possible.

##### /logging/drivers `/logging/drivers.msgpack`, `/logging/drivers.json`

Return a vector of all possible log drivers.  This provides the logging class/type, description, and other attributes of potential log outputs.

##### /logging/active `/logging/active.msgpack`, `/logging/active.json`

Return a vector of all active log files.

##### /logging/by-class/[class]/start `/logging/by-class/[class]/start.cmd`, `/logging/by-class/[class]/start.jcmd` 

*LOGIN REQUIRED*

Start a new log file of type `[class]`.  If successful, returns the log object denoting the UUID, path, and other information about the new log.

##### POST /logging/by-class/[class]/start `/logging/by-class/[class]/start.cmd`, `/logging/by-class/[class]/start.jcmd` 

*LOGIN REQUIRED*

Start a new log file of the type `[class]`.  If successful, returns the log object denoting the UUID, path, and other information about the new log.

Expects a command dictionary including:

| Key   | Value     | Type   | Description                              |
| ----- | --------- | ------ | ---------------------------------------- |
| title | log title | string | Alternate log title; This is substituted into the logging path in place of the `log_title=` in the Kismet config |

##### /logging/by-uuid/[uuid]/stop `/logging/by-uuid/[uuid]/stop.cmd`, `/logging/by-uuid/[uuid]/stop.jcmd`

*LOGIN REQUIRED*

Stop, and close, the logfile specified by `[uuid]`.  The log file must be open.

### Phy-Specific:  phy80211 (Wi-Fi)

The 802.11 Wi-Fi phy defines extra endpoints for extracting packets from dot11-specific devices:

##### /phy/phy80211/by-key/[key]/pcap/[key]-handshake.pcap

*LOGIN REQUIRED*

Retrieve a pcap file of WPA EAPOL key packets seen by the 802.11 access point specified by `[key]`.  If there are no WPA handshake packets, an empty pcap file will be returned.

This pcap file is not streamed, it is a single pcap of the handshake packets only.

##### /phy/phy80211/by-bssid/[MAC]/pcap/[MAC].pcapng

*LOGIN REQUIRED*

Returns a stream in pcap-ng format of all packets, from all interfaces, associated with the 802.11 BSSID `[MAC]`.  This stream will include packets to and from the target BSSID.

This URI will stream indefinitely as packets are received.

### Phy-Specific: phyuav (UAV / Drones)

The UAV/Drone phy defines extra endpoints for matching UAVs based on manufacturer and SSID:

##### /phy/phyuav/manuf_matchers `/phy/phyuav/manuf_matchers.json` `/phy/phyuav/manuf_matchers.msgpack`

Returns a vector of the manufacturer matches for UAVs and drones; these matches allow the UAV phy to flag devices based on OUI and SSID.
