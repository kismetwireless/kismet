---
title: "Streams"
permalink: /docs/devel/webui_rest/streams/
toc: true
---
A Kismet stream is linked to an export of data of prolonged length; for instance, packet capture logs to disk or streamed over the web API.

Streams can be monitored and managed; a privileged user can close existing sterams.

## Streams list

* URL \\
        /streams/all_streams.json

* Methods \\
        `GET`

* Result \\
        Array of active streams

## Stream details

* URL \\
        /streams/by-id/*[STREAMID]*/stream_info.json

* Methods \\
        `GET`

* URL parameters 

| Key | Description |
| --- | ----------- |
| *[STREAMID]* | ID of stream to examine |

* Results \\
        Returns detailed stream information object

## Closing a stream
Closing a stream cancels any data being transferred or stored.

__LOGIN REQUIRED__

* URL \\
        /streams/by-id/*[STREAMID]*/close_stream.cmd

* Methods \\
        `GET`

* URL parameters

| Key | Description |
| --- | ----------- |
| *[STREAMID]* | ID of stream to close |

* Results \\
        `HTTP 200` on successful stream closure
        HTTP error on failure

