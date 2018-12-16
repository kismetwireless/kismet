---
title: "Alerts"
permalink: /docs/devel/webui_rest/alerts/
toc: true
---
Kismet alerts notify the user of critical Kismet events and wireless intrusion events.  Alerts are generated as messages (sent via [the messagebus](/docs/devel/webui_rest/messages/)) and as alert records.

## Alert configuration
Kismet exposes the full alert system configuration, including currently supported alert types, full descriptions of alert content, and time and burst-rate delivery limiting.

* URL \\
        /alerts/definitions.json

* Methods \\
        `GET`

* Result \\
        Array of all alert records.

## All alerts
Kismet retains the past *N* alerts, as defined in `kismet_alert.conf`.  By default, Kismet retains 50 alert records.

* URL \\
        /alerts/all_alerts.json

* Methods \\
        `GET`

* Result \\
        Array of all currently stored alerts

## Recent alerts
Alerts can be fetched by timestamp, returning only new alerts.  This API takes a specialized timestamp value which includes microsecond precision.

This endpoint returns the exact timestamp, with microsecond precision, of the returned alerts; this allows a client UI to accurately display only the new alerts.

* URL \\
        /alerts/last-time/*[TIMESTAMP.UTIMESTAMP]*/alerts.json

* Methods \\
        `GET`

* URL parameters

| Key | Description |
| --- | ----------- |
| *[TIMESTAMP.UTIMESTAMP]* | A double-precision timestamp of the Unix epochal second timestamp *and* a microsecond precision sub-second timestamp. |

* Result \\
        A *dictionary* containing an array of alerts since *TIMESTAMP.UTIMESTAMP* and a double-precision timestamp second and microsecond timestamp of the current server time.

## Defining alerts
New alerts can be defined runtime, and triggered by external tools via the REST API.

__LOGIN REQUIRED__

* URL \\
        /alerts/definitions/define_alert.cmd

* Methods \\
        `POST`

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key         | Description                              |
| ----------- | ---------------------------------------- |
| name        | Simple alert name/identifier             |
| description | Alert explanation / definition displayed to the user |
| phyname     | (Optional) name of phy this alert is associated with.  If not provided, alert will apply to all phy types.  If provided, the defined phy *must* be found or the alert will not be defined. |
| throttle    | Maximum number of alerts per time period, as defined in kismet.conf.  Time period may be 'sec', 'min', 'hour', or 'day', for example '10/min' |
| burst       | Maximum number of sequential alerts per time period, as defined in kismet.conf.  Time period may be 'sec', 'min', 'hour', or 'day'.  Alerts will be throttled to this burst rate even when the overall limit has not been hit.  For example, '1/sec' |

* Results \\
        `HTTP 200` on success \\
        HTTP error on failure

## Raising alerts
Alerts can be triggered by external tools; the alert must be defined, first.

__LOGIN REQUIRED__

* URL \\
        /alerts/raise_alerts.cmd

* Methods \\
        `POST`

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key     | Description                              |
| ------- | ---------------------------------------- |
| name    | Alert name/identifier.  Must be a defined alert name. |
| text    | Human-readable text for alert            |
| bssid   | (optional) MAC address of the BSSID, if Wi-Fi, related to this alert |
| source  | (optional) MAC address the source device which triggered this alert |
| dest    | (optional) MAC address of the destination device which triggered this alert |
| other   | (optional) Related other MAC address of the event which triggered this alert |
| channel | (optional) Phy-specific channel definition of the event which triggered this alert |

* Result \\
        `HTTP 200` on success \\
        HTTP error on failure

