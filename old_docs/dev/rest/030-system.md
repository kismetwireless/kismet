---
title: "System status"
permalink: /docs/devel/webui_rest/system_status/
toc: true
---

## System status
* URL \\
        /system/status.json

* Methods \\
        `GET` `POST`

* POST parameters

| Key | Description |
| --- | ----------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |

* Result \\
        Dictionary of Kismet system-level status, including update, battery, memory, and thermal data, optionally simplified.

## Timestamp
* URL \\
        /system/timestamp.json

* Methods \\
        `GET`

* Result \\
        Dictionary of system timestamp as second, microsecond; can be used to synchronize timestamps and as a keep-alive check.

## Tracked fields
* URL \\
        /system/tracked_fields.html

* Methods \\
        `GET`

* Result \\
        Human-readable table of all registered field names, types, and descriptions.  While it cannot represent the nested features of some data structures, it will describe every allocated field.  This endpoint returns a HTML document for ease of use.
