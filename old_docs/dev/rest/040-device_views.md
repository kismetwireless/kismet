---
title: "Devices"
permalink: /docs/devel/webui_rest/device_views/
toc: true
---

## Device views
Device views are optimized subsets of the global device list.  Device views can be defined by PHY handlers, plugins, as part of the base Kismet code, or user-supplied data.

All device views respond to the same common API; any code which access a specific device view should be portable across multiple views.

### View list
The view list shows all defined device views and a summary of the number of devices in each.

* URL \\
        /devices/views/all_views.json

* Methods \\
        `GET`

* Results \\
        Array of device views and device counts per view.

### View-based summarization and display
Mirroring the [base summarization & display endpoint](/docs/devel/webui_reset/devices/#summarization--display) API, the view summarization endpoint is the primary interface for clients to access the device list and for scripts to retrieve lists of devices.

The device summarization is best utilized when applying a view window via the `start` and `length` variables.

* URL \\
        /devices/views/*[VIEWID]*/devices.json

* Methods \\
`POST`

* URL parameters

| Key | Description |
| --- | ----------- |
| *[VIEWID]* | Kismet view ID |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key     | Description                                           |
| ------- | ----------------------------------------------------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |
| regex   | Optional, [regular expression filter](/docs/devel/webui_rest/commands/#regex-filters) |
| colmap  | Optional, inserted by the Kismet Datatable UI for mapping column information for proper ordering and sorting. |
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
        Summarized array of devices.  

### Devices by view & time
Mirroring the [Activity & timestamp](/docs/devel/webui_rest/devices/#activity--timestamp) API, fetches devices from a specified view which have been active since the supplied timestamp.  This endpoint is typically used by scripted clients to monitor active devices within a view.

* URL \\
        /devices/views/*[VIEWID]*/last-time/*[TIMESTAMP]*/devices.json

* Methods \\
        `GET` `POST`

* URL parameters

| Key | Description |
| --- | ----------- |
| *[VIEWID]* | Kismet view ID |
| *[TIMESTAMP]* | Relative or absolute [timestamp](/docs/devel/webui_rest/commands/#timestamp) |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |

* Results \\
        Array of devices in view *VIEWID* with activity more recent than *TIMESTAMP* with optional field simplification.

