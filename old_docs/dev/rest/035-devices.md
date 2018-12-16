---
title: "Devices"
permalink: /docs/devel/webui_rest/devices/
toc: true
---

A device is the central record of a tracked entity in Kismet.  Clients, bridges, access points, wireless sensors, and any other type of entity seen by Kismet will be a device.  For complex relationships (such as 802.11 Wi-Fi), a list of related devices describes the access point-client relationship.

All devices will have a basic set of records (held in the `kismet.base.foo` group of fields, generally) and sub-trees of records attached by the phy-specific handlers.  A device may have multiple phy-specific records, for instance a device may contain both a `device.dot11` record and a `device.uav` record if it is seen to be a Wi-Fi based UAV/Drone device.

The preferred method of retrieving device lists is to use the POST URI `/devices/summary/` or `/devices/last-time` with a list of fields provided.  Whenever possible, limiting the fields requested and the time range requested will reduce the load on the Kismet server *and* the client consuming the data.

## Summarization & display
The device summarization endpoint is the primary interface for clients to access the device list.  It is used heavily by the Kismet UI for the main device list table.

The device summarization is best utilized when applying a view window via the `start` and `length` variables.

* URL \\
        /devices/summary/devices.json

* Methods \\
        `POST`

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key     | Description                                           |
| ------- | ----------------------------------------------------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |
| regex   | Optional, [regular expression filter](/docs/devel/webui_rest/commands/#regex-filters) |
| colmap  | Optional column correlation info inserted by the Kismet Datatable UI for mapping jquery-datatables column information for proper ordering and sorting. |
| datatable | Optional, inserted by the Kismet Datatable UI to enable datatable mode which wraps the output in a container suitable for consumption by jquery-datatables. |

Additionally, when in datatables mode, the following HTTP POST variables are used:

| Key | Description |
| --- | ---- |
| start  | Data view window start position |
| length | Datatable window end |
| draw   | Datatable draw value |
| search[value] | Search term, applied to all fields in the summary vector |
| order\[0\]\[column\] | Display column number for sorting, indexed with colmap data |
| order\[0\]\[dir\] | Sort order direction from jquery-datatables |

* Results \\
        Summarized vector of devices.  


## Bulk device list
A special `ekjson`-only endpoint which provides a dump of all devices.  This endpoint *only* returns ekjson-formatted data.

This endpoint is most useful for extracting bulk data and passing it to another tool like Elasticsearch.

* URL \\
        /devices/all_devices.ekjson

* Methods \\
        `GET` `POST`

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key    | Description                              |
| ------ | ---------------------------------------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |

* Results \\
        Each device is returned as a JSON object, one JSON record per line.


## Activity & timestamp
Fetch devices which have been active since the supplied timestamp.  This endpoint is typically used by scripted clients to monitor currently active devices.

* URL \\
        /devices/last-time/*[TIMESTAMP]*/devices.json \\
        /devices/last-time/*[TIMESTAMP]*/devices.ekjson

* Methods \\
        `GET` `POST`

* URL parameters \\

| *[TIMESTAMP]* | Relative or absolute [timestamp](/docs/devel/webui_rest/commands/#timestamp) |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key    | Description                              |
| ------ | ---------------------------------------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |
| regex   | Optional, [regular expression filter](/docs/devel/webui_rest/commands/#regex-filters) |

* Results \\
        Vector of (optionally summarized and filtered) devices active since *TS*

## Device by key
Fetch devices by the Kismet device key.

* URL \\
        /devices/by-key/*[DEVICEKEY]*/device.json

* Methods \\
        `GET` `POST`

* URL parameters 

| Key    | Description |
| ------ | ----------- |
| *[DEVICEKEY]* | Kismet unique device key to match |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key    | Description                         |
| ------ | ----------------------------------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |

* Results \\
        Device record, with optional simplification of the fields, matching *DEVICEKEY*

## Device by MAC
Fetch devices which match the supplied MAC address.  It is possible (though usually not likely) that there may be MAC address collisions between different PHY types.  This becomes more likely when using non-Wi-Fi capture types which synthesize false MAC addresses because no official address is available, such as RTL-433, Mousejack, and other SDR-based datasources.

This API will always return a vector of devices, even when only one device matches the MAC address.

* URL \\
        /devices/by-mac/*[MACADDRESS]*/devices.json

* Methods \\
        `GET` `POST`

* URL Parameters

| Key    | Description |
| ------ | ----------- |
| *[MACADDRESS]* | Device MAC address to match |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key    | Description                         |
| ------ | ----------------------------------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |

* Results \\
        Array of all devices with the supplied MAC address, optionally simplified by `fields` parameter.

## Multiple devices by MAC
Fetch devices matching any of multiple MAC addresses (or partial MAC addresses).  Typically used to monitor the presence of target devices.

This API will always return a vector of devices, even when only one device is matched.

The supplied MAC addresses can either be complete MACs (`aa:bb:cc:dd:ee:ff`), or partial-match masked MACs; for instance to match only the OUI `00:aa:bb`, a masked MAC address of `00:aa:bb:00:00:00/ff:ff:ff:00:00:00` can be supplied.

* URL \\
        /devices/multimac/devices.json

* Methods \\
        `POST`

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key    | Desc                                |
| ------ | ----------------------------------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |
| regex   | Optional, [regular expression filter](/docs/devel/webui_rest/commands/#regex-filters) |

* Results \\
Array of all devices matching any of the supplied MAC addresses.


## Devices by PHY
Devices can be fetched by PHY type.  The phy type is determined by the capture datasource and may be extended by plugins.

* URL \\
        /devices/by-phy/*[PHYNAME]*/devices.json \\
        /devices/by-phy/*[PHYNAME]*/devices.ekjson

* Methods \\
        `GET` `POST`

* URL Parameters

| Key    | Description |
| ------ | ----------- |
| *[PHYNAME]* | Kismet phy name to match |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key    | Desc                                |
| ------ | ----------------------------------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |
| last_time | Optional, relative or absolute [timestamp](/docs/devel/webui_rest/commands/#timestamp) |
| regex   | Optional, [regular expression filter](/docs/devel/webui_rest/commands/#regex-filters) |

* Results \\
        Array of all devices present in the specified PHY, optionally filtered by the regex and last_time parameters and simplified by the fields parameter.

## Editing - device names
Devices can have an arbitrary user-supplied name.

__LOGIN REQUIRED__

* URL \\
        /devices/by-key/*[DEVICEKEY]*/set_name.cmd

* Methods \\
        `POST`

* URL Parameters

| Key    | Description |
| ------ | ----------- |
| *[DEVICEKEY]* | Key of device to edit |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| username | New name for device |

* Results \\
        `HTTP 200` on success \\
        HTTP error on failure

## Editing - device tags
Devices contain a collection of arbitrary tags which are held in the `kismet.device.base.tags` tree of the device record.  These tags can be used to store persistent notes or other user-supplied or auto-generated data, and are keyed by the string tag name.

__LOGIN REQUIRED__

* URL \\
        /devices/by-key/*[DEVICEKEY]*/set_tag.cmd

* Methods \\
        `POST`

* URL Parameters

| Key    | Description |
| ------ | ----------- |
| *[DEVICEKEY]* | Key of device to edit |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| tagname | Tag being altered |
| tagvalue | Tag value being set |

* Results \\
        `HTTP 200` on success \\
        HTTP error on failure

