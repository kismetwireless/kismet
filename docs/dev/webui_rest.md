# Extending Kismet - Webserver Endpoints

Kismet uses a REST-like interface on the embedded webserver for providing data and accepting commands.  Generally, data is fetched via HTTP GET and commands are sent via HTTP POST.

Kismet can, in general, return data as a binary msgpack-formatted blob (for more information, see the docs about [serialization](serialization.html)) or as standard JSON.  Where multiple formats are supported, the documentation will show both endpoints.

## Logins and Sessions

Kismet uses session cookies to maintain a login session.  Typically GET requests which do not reveal sensitive configuration data do not require a login, while POST commands which change configuration or GET commands which might return parts of the Kismet configuration values will require the user to login with the credentials in the `kismet_httpd.conf` config file.

Sessions are created via HTTP Basic Auth to the `/session/create_session` endpoint and are stored in the `KISMET` session cookie for future page requests.

Endpoints which require authentication but do not have a valid session return HTTP 401 "Unauthorized".

## Commands

Commands are sent via HTTP POST.  Currently, a command should be a base64-encoded msgpack string dictionary containing key:value pairs, send under the `msgpack` POST field.  This may be subject to change as the HTTP interface evolves.

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

Commands are encoded as dictionaries to allow flexibility across calling platforms, as well as forward-compatibility as endpoints evolve.  Adding additional keys to an options dictionary should not cause an older version of the server code to return an error.

Dictionary key values are case sensitive.

## REST Endpoints

### System Status

* `/system/status.msgpack` Msgpack-formatted dictionary of system status, including battery charge level, discharge rate, etc.
* `/system/status.json` JSON-formatted dictionary of system status

* `/system/tracked_fields.html` Human-readable table of all registered field names, types, and descriptions.  While it cannot represent the nested features of some data structures, it will describe every allocated field.

### Device Handling

A device is the central record of a tracked entity in Kismet.  Clients, bridges, access points, wireless sensors, and any other type of entity seen by Kismet will be a device.  For complex relationships (such as 802.11 Wi-Fi), mappings will be provided to link client devices with their behavior on the respective access points.

All devices will have a basic set of records (held in the `kismet.base.foo` group of fields, generally) and then sub-trees of records attached by the phy-specific handlers.

* `/devices/all_devices.msgpack` Msgpack-formatted array of device summary records, a subset of the entire device record kept for each device.
* `/devices/all_devices.json` JSON-formatted array of device summary records.
* `/devices/all_devices_dt.json` JSON-formatted array of device summary records, contained in a dictionary under the key `aaData`, which supports direct loading into a jQuery DataTable element.

* `/devices/last-time/[TS]/devices.msgpack` Msgpack dictionary containing a list of devices modified since unix timestamp `[TS]`, a flag indicating the device structure has changed and the entire device list should be reloaded, and a timestamp record indicating the time of this report.
* `/devices/last-time/[TS]/devices.json` JSON dictionary containing the equivalent data, for optimized performance of the WebUI refreshing only networks which have changed.

* `/devices/by-key/[DEVICEKEY]/device.msgpack` Msgpack dictionary of complete device record, including all nested records, referenced by `[DEVICEKEY]`.
* `/devices/by-key/[DEVICEKEY]/device.json` JSON dictionary of complete device record and all nested records referenced by `[DEVICEKEY]`.

* `/devices/by-key/[DEVICEKEY]/device.msgpack/[path/to/subkey]` Msgpack dictionary of a sub-component of the device referenced by `[DEVICEKEY]`.  The subkey path allows selection of single keys or complete objects in the device tree.
* `/devices/by-key/[DEVICEKEY]/device.json/[path/to/subkey]` JSON equivalent dictionary of the sub-component of the device.

* `/devices/by-mac/[DEVICEMAC]/devices.msgpack` Msgpack array of all devices matching `[DEVICEMAC]` across all PHYs.  It is possible (though not often likely) that there is a MAC address collision between different PHYs, in which case multiple devices will be returned in the array.
* `/devices/by-mac/[DEVICEMAC]/devices.json` JSON equivalent MAC-based device list.

## Phy Handling

A phy handler processes a specific type of radio physical layer - 802.11, Bluetooth, and so on.  A phy is often, but not always, linked to specific types of hardware and specific packet link types.

* `/phy/all_phys.msgpack` Msgpack array of phy descriptions and packet counts.
* `/phy/all_phys.json` JSON array of phy descriptions and packet counts.
* `/phy/all_phys_dt.json` JSON array of phy information contained in a dictionary under the `aaData` key for easy use with jQuery DataTables.

## Sessions and Logins

* `/session/create_session` handle login via HTTP Basic Auth

* `/session/check_session` determine if a login session is valid

## Channels

* `/channels/channels.msgpack` Msgpack object of channel and frequency usage and historical data.
* `/channels/channels.json` JSON object of channel and frequency data.

## Data Sources (new)

Kismet is replacing the old PacketSource code with Data Sources.  Once this is complete, the PacketSource options will be deprecated, but development of DataSources is still ongoing.

* `/datasource/all_sources.msgpack` Msgpack array of all defined data sources.

* `/datasource/supported_sources.msgpack` Msgpack array of all supported sources (even those not configured with an interface).

* `/datasource/error_sources.msgpack` Msgpack array of defined sources which are currently in an error state.

## Packet Sources (old)

Kismet is replacing the old PacketSource code with Data Sources.  Once this is complete, the PacketSource options will be deprecated, but development of DataSources is still ongoing.  Until such time as DataSources are complete, the PacketSources API will be used.

* `/packetsource/all_sources.msgpack` Msgpack array of all packet sources.

* `/packetsource/config/channel.cmd` *LOGIN REQUIRED*.  Set the channel of a packet source.  This command is limited as it is due to be replaced with the more featureful DataSource API.
