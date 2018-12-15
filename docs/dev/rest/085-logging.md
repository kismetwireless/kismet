---
title: "Logging"
permalink: /docs/devel/webui_rest/logging/
toc: true
---
Kismet uses a centralized logging architecture which manages enabling and tracking the status of logs.  The logging system integrates with the [streaming sytem](/docs/devel/webui_rest/streams/) for long-running log files.

## Log drivers
Log drivers handle a specific type of logfile.

* URL \\
        /logging/drivers.json

* Methods \\
        `GET`

* Result \\
        Array of supported log types

## Active logs
Not all drivers are activated depending on the Kismet config optins.

* URL \\
        /logging/active.json

* Methods \\
        `GET`

* Result \\
        Array of activated logs.

## Enabling logs
Logs can be enabled run-time.

__LOGIN REQUIRED__

* URL \\
        /logging/by-class/*[LOGCLASS]*/start.cmd

* Methods \\
        `GET` `POST`

* URL parameters

| Key | Description |
| --- | ----------- |
| *[LOGCLASS]* | Kismet log class to enable |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| title | Alternate log title, overriding the `kismet.conf` config for `log_title=`

* Results \\
        `HTTP 200` and log object for newly created log on success
        HTTP error on failure

## Stopping logs
Logs can be stopped run-time.  The log must be open and running to be stopped.

__LOGIN REQUIRED__

* URL \\
        /logging/by-uuid/*[LOGUUID]*/stop.cmd

* Methods \\
        `GET`

* URL parameters

| Key | Description |
| --- | ----------- |
| *[LOGUUID]* | Kismet log UUID to stop |

* Results \\
        `HTTP 200` on success
        HTTP error on failure

