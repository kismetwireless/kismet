# Extending Kismet - Webserver Endpoints

Kismet uses a REST-like interface on the embedded webserver for providing data and accepting commands.  Generally, data is fetched via HTTP GET and commands are sent via HTTP POST.

*Broadly speaking*, nearly all endpoints in Kismet should support all loaded output methods.  By default, these are JSON and Msgpack, but additional output serializers may be added in the future or added by plugins.

Data returned by JSON serializers will transform field names to match the path delimiters used in many JS implementations - specifically, all instances of '.' will be transformed to '_'.

## Logins and Sessions

Kismet uses session cookies to maintain a login session.  Typically GET requests which do not reveal sensitive configuration data do not require a login, while POST commands which change configuration or GET commands which might return parts of the Kismet configuration values will require the user to login with the credentials in the `kismet_httpd.conf` config file.

Sessions are created via HTTP Basic Auth.  A session will be created for any valid login passed to a page requiring authentication.  Logins may be validated directly against the `/session/check_session` endpoint by passing HTTP Basic Auth to it.

Session IDs are returned in the `KISMET` session cookie.  Clients which interact with logins should retain this session cookie and use it for future communication.

## Commands

Commands are sent via HTTP POST.  Currently, a command should be a base64-encoded msgpack string dictionary containing key:value pairs, sent under the `msgpack` or `json` POST fields.  This may be subject to change as the HTTP interface evolves.

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

### Data types

### System Status

##### /system/status `/system/status.msgpack`, `/system/status.json`

Dictionary of system status, including battery and memory use.

##### /system/tracked_fields `/system/tracked_fields.html`
Human-readable table of all registered field names, types, and descriptions.  While it cannot represent the nested features of some data structures, it will describe every allocated field.

### Device Handling

A device is the central record of a tracked entity in Kismet.  Clients, bridges, access points, wireless sensors, and any other type of entity seen by Kismet will be a device.  For complex relationships (such as 802.11 Wi-Fi), mappings will be provided to link client devices with their behavior on the respective access points.

All devices will have a basic set of records (held in the `kismet.base.foo` group of fields, generally) and then sub-trees of records attached by the phy-specific handlers.

The preferred method of retrieving device lists is to use the POST URI `/devices/summary/` or `/devices/last-time` with a list of fields provided.

##### POST /devices/summary/devices `/devices/summary/devices.msgpack`, `/devices/summary/devices.json`

A POST endpoint which returns a summary of all devices.  This endpoint expects a variable containing a dictionary which defines the fields to include in the results; only these fields will be sent.

Optionally, a regex dictionary may be provided to filter the devices returned.

Additionally, a wrapper may be specified, which indicates a transient dictionary object which should contain these values - specifically, this can be used by dataTables to wrap the initial query in an `aaData` object required for that API.

The command dictionary should be passed as either JSON in the `json` POST variable, or as base64-encoded msgpack in the `msgpack` variable, and is expected to contain:

| Key | Value | Type | Desc |
| --- | ----- | ---- | ---- |
| fields | Field specification | field specification array listing fields and mappings |
| regex | Regex specification | Optional, regular expression filter |
| wrapper | "foo" | string | Optional, wrapper dictionary to surround the data |

##### POST /devices/last-time/[TS]/devices `/devices/last-time/[TS]/devices.msgpack`, `devices/last-time/[TS]/devices.json`

Dictionary containing the list of all devices new or modified since the server timestamp `[TS]`, a flag indicating that the device list has drastically changed indicating that the entire device list should be re-loaded, and a timestamp record indicating the server time this report was generated.

This endpoint is most useful for clients and scripts which need to monitor the state of *active* devices.  This is used by the Kismet Web UI to update changed devices.

This endpoint expects a variable containing a dictionary which defines the fields to include in the results; only these fields will be sent.

Optionally, a regex dictionary may be provided to filter the devices returned.

The command dictionary should be passed as either JSON in the `json` POST variable, or as base64-encoded msgpack in the `msgpack` variable, and is expected to contain:

| Key | Value | Type | Desc |
| --- | ----- | ---- | ---- |
| fields | Field specification | field specification array listing fields and mappings |
| regex | Regex specification | Optional, regular expression filter |

##### /devices/all_devices `/devices/all_devices.msgpack`, `/devices/all_devices.json`

Array of complete device records.  This may incur a significant load on both the Kismet server and on the receiving system, depending on the number of devices tracked.

##### /devices/last-time/[TS]/devices `/devices/last-time/[TS]/devices.msgpack`, `devices/last-time/[TS]/devices.json`

Dictionary containing the list of all devices new or modified since the server timestamp `[TS]`, a flag indicating that the device list has drastically changed indicating that the entire device list should be re-loaded, and a timestamp record indicating the server time this report was generated.

This endpoint is most useful for clients and scripts which need to monitor the state of *active* devices.  This is used by the Kismet Web UI to update changed devices.

##### /devices/by-key/[DEVICEKEY]/device `/devices/by-key/[DEVICEKEY]/device.msgpack`, `/devices/by-key/[DEVICEKY]/device.json`

Complete dictionary object containing all information about the device referenced by [DEVICEKEY].

##### /devices/by-key/[DEVICEKEY]/device[/path/to/subkey] `/devices/by-key/[DEVICEKEY]/device.msgpack[/path/to/subkey]`, `/devices/by-key/[DEVICEKEY]/device.json[/path/to/subkey]`

Dictionary containing all the device data referenced by `[DEVICEKEY]`, in the sub-tree `[path/to/subkey]`.  Allows fetching single fields or objects from the device tree without fetching the entire device record.

##### /devices/by-mac/[DEVICEMAC]/devices `/devices/by-mac/[DEVICEMAC]/devices.msgpack`, `/devices/by-mac/[DEVICEMAC]/devices.json`

Array/list of all devices matching `[DEVICEMAC]` across all PHY types.  It is possible (though not likely) that there can be a MAC address collision between different PHY types, especially types which synthesize false MAC addresses when no official address is available.

## Phy Handling

A PHY handler processes a specific type of radio physical layer - 802.11, Bluetooth, and so on.  A PHY is often, but not always, linked to specific types of hardware and specific packet link types.

##### /phy/all_phys `/phy/all_phys.msgpack`, `/phy/all_phys.json`

Array of all PHY types and statistics

## Sessions and Logins

##### `/session/create_session`

Initiate a login via HTTP Basic Auth

##### `/session/check_session`

Return if a login session is valid

## Messages

Kismet uses the `messagebus` as in internal system for displaying message to the user.  The messagebus is used to pass error and state messages, as well as notifications about detected devices, etc.

##### /messagebus/all_messages `/messagebus/all_messages.msgpack`, `/messagebus/all_messages.json`

Vector of the last 50 messages stored in Kismet

##### /messagebus/last-time/[TS]/messages `/messagebus/last-time/[TS]/messages.msgpack`, `/messagebus/last-time/[TS]/messages.json`

Dictionary containing a list of all messages since server timestamp `[TS]`, and a timestamp record indicating the time of this report.  This can be used to fetch only new messages since the last time messages were fetched.

## Alerts

Kismet provides alerts via the `/alert/` REST collection.  Alerts are generated as messages and as alert records with machine-processable details.  Alerts can be generated for critical system states, or by the WIDS system.

##### /alerts/definitions `/alerts/definitions.msgpack`, `/alerts/definitions.json`

All defined alerts, including descriptions, time and burst limits, and current alert counts and states for each type.

##### /alerts/all_alerts `/alerts/all_alerts.msgpack`, `/alerts/all_alerts.json`

List of the alert backlog.  The size of the backlog is configurable via the `alertbacklog` option in kismet.conf

##### /alerts/last-time[TS]/alerts `/alerts/last-time/[TS]/alerts.msgpack`, `/alerts/last-time/[TS]/alerts.json`

Dictionary containing a list of alerts since Kismet timestamp `[TS]`, and a timestamp record indicating the time of this report.  This can be used to fetch only new alerts since the last time alerts were requested.

## Channels

##### /channels/channels `/channels/channels.msgpack`, `/channels/channels.json`

Channel usage and monitoring data.

## Datasources

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

`add_source.cmd` will return a successful HTTP code when the *source is successfully added*.  This may not equate to a source which is *successfully running* due to automatic re-opening of sources and other Kismet behavior.  The caller can check the returned UUID to query the status of the source.

## GPS

Kismet now supports multiple simultaneous GPS devices, selecting the "best" quality device.

##### `/gps/web/update.cmd`

*LOGIN REQUIRED*.

This API allows browsers and browser-like clients to set the GPS coordinates over POST.  This is most likely useful when using a mobile device with a GPS of its own as the front-end and can use the standard browser location API.

Requires that the Kismet server has the 'web' GPS driver enabled via kismet.conf: `gps=web:name=webgps`.

Expects a command dictionary including:

| Key | Value | Type | Desc |
| --- | ----- | ---- | ---- |
| lat | latitude | double | GPS latitude |
| lon | longitude | double | GPS longitude |
| alt | altitude (in Meters) | double | GPS altitude in meters (optional) |
| spd | speed (kph) | double | Speed in kilometers per hour (optional) |


## 802.11 Specific

##### POST /phy/phy80211/ssid_regex `/phy/phy80211/ssid_regex.cmd`, `/phy/phy80211/ssid_regex.jcmd`

*LOGIN _NOT_ REQUIRED*

Retrieve an array of device summaries based on the supplied PCRE-compatible regular expression.  Devices are matched on advertised SSIDs or probe response SSIDs.

This API requires a Kismet server that has been compiled with libpcre support.

Multiple PCRE terms may be supplied.  The response will include devices which match *any* of the supplied terms.

Expects a command dictionary including:

| Key | Value | Type | Desc |
| --- | ----- | ---- | ---- |
| essid | ["one", "two", "three", ... ] | array of string | Array of PCRE regex filters |
| fields | ["field1", "field2", ..., ["fieldN", "renameN"], ... ] | array of string and string-pairs | Array of fields to be included in the summary.  If this is omitted, the entire device record is transmitted.  Fields may be a single field string, a complex field path string, or a rename pair - when renamed, fields are transmitted as the renamed value |

##### POST /phy/phy80211/probe_regex `/phy/phy80211/probe_regex.cmd`, `/phy/phy80211/probe_regex.jcmd`

*LOGIN _NOT_ REQUIRED*

Retrieve an array of device summaries based on the supplied PCRE-compatible regular expression.  Devices are matched on *requested* SSIDs from probe request fields.

This API requires a Kismet server that has been compiled with libpcre support.

Multiple PCRE terms may be supplied.  The response will include devices which match *any* of the supplied terms.

Expects a command dictionary including:

| Key | Value | Type | Desc |
| --- | ----- | ---- | ---- |
| essid | ["one", "two", "three" ] | array of string | Array of PCRE regex filters |
| fields | ["field1", "field2", ..., ["fieldN", "renameN"], ... ] | array of string and string-pairs | Array of fields to be included in the summary.  If this is omitted, the entire device record is transmitted.  Fields may be a single field string, a complex field path string, or a rename pair - when renamed, fields are transmitted as the renamed value |

##### Examples

To match a single SSID, using start-and-end markers,
```python
{
    "essid": [ "^linksys$" ]
}
```

To match on a single explicit SSID or any ssid ending in 'foo':
```python
{
    "essid": [ "^single$", ".*foo$" ]
}
```

##### /phy/phy80211/handshake/[MAC]/[MAC]-handshake.pcap `/phy/phy80211/handshake/[MAC]/[MAC]-handshake.pcap` 

Retrieve a pcap file of WPA EAPOL key packets seen by the 802.11 access point with the BSSID `[MAC]`.  If there are no WPA handshake packets, an empty pcap file will be returned.

