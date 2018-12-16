---
title: "KismetDB logs"
permalink: /docs/devel/webui_rest/kismetdb/
toc: true
---
If the Kismet Databaselog is enabled, Kismet will expose an API for extracting historic data.  If the databaselog is not enabled, these APIs will not be available and will return an error.

## Packet filtering
The `filter` options in are treated as logical `AND` statements:  To match a packet, the packet must match *all* of the filter options passed in the command dictionary.  In other words, a filter by time, datasource, and type, would *only* return packets within that time range, from that datasource, and of that type.

Filter options should be sent as GET parameters URL-encoded, when using the GET REST endpoint, and in a command dictionary under the `filter` key when using the POST endpoint.

### Filter options:

1. Time window
   Packets can be selected by a time window which may either be closed (both start and end times specified) or open (only start or end time specified).

   | Key             | Type   | Description                                                  |
   | --------------- | ------ | ------------------------------------------------------------ |
   | timestamp_start | double | Posix timestamp as double-precision value (seconds.microseconds) |
   | timestamp_end   | double | Posix timestamp as double-precision value (seconds.microseconds) |

2. Datasource

   Packets may be limited to a single data source, specified by UUID

   | Key        | Type      | Description                       |
   | ---------- | --------- | --------------------------------- |
   | datasource | text UUID | UUID string of capture datasource |

3. Kismet device

   Packets may be limited to the specific Kismet device ID they belong to

   | Key       | Type    | Description      |
   | --------- | ------- | ---------------- |
   | device_id | text ID | Kismet device ID |

4. Data type
   Limit matching to a specific data type / DLT (Data Link Type).  This numeric DLT matches the libpcap link types and describes the physical frame type of the packet.

   | Key  | Type    | Description |
   | ---- | ------- | ----------- |
   | dlt  | integer | PCAP DLT    |

5. Frequency

   Match only packets on the given frequency, if frequency information is available from the data source.  Data sources which cannot report frequency will report as `0`.

   | Key       | Type   | Description      |
   | --------- | ------ | ---------------- |
   | frequency | double | Frequency in KHz |
   | frequency_min | double | Minimum frequency in KHz |
   | frequency_max | double | Maximum frequency in KHz |

7. Signal window

   Limit matching to a range of signal levels, which may be open (only min/max signal provided) or closed (min and max specified).  Packets which have no signal data (such as packets captured by source types which do not support signal records) will have a reported signal of `0`.

   | Key        | Type | Description             |
   | ---------- | ---- | ----------------------- |
   | signal_min | int  | Minimum signal (in dBm) |
   | signal_max | int  | Maximum signsl (in dBm) |

8. Device addresses
   Limit matching by decoded device address, if available.  Not all capture phys report device addresses as MAC addresses, however the majority do.

   | Key            | Type     | Description                                    |
   | -------------- | -------- | ---------------------------------------------- |
   | address_source | text MAC | Source MAC address                             |
   | address_dest   | text MAC | Destination MAC address                        |
   | address_trans  | text MAC | Transmitter MAC address (such as the AP BSSID) |

9. Location window
   Limit matching by location.  Location windows should always be bounded rectangles of minimum and maximum coordinates.  Coordinates are in decimal floating-point format (LL.LLLLL) and will be converted to the normalized non-floating internal values automatically.

   | Key              | Type   | Description              |
   | ---------------- | ------ | ------------------------ |
   | location_lat_min | double | Minimum corner latitude  |
   | location_lon_min | double | Minimum corner longitude |
   | location_lat_max | double | Maximum corner latitude  |
   | location_lon_max | double | Maximum corner longitude |

10. Packet size window

   Limit matching by packet size.  Size windows can define minimum and maximum or only minimum or maximum ranges.

   | Key      | Type | Description                   |
   | -------- | ---- | ----------------------------- |
   | size_min | int  | Minimum packet size, in bytes |
   | size_max | int  | Maximum packet size, in bytes |

11. Result limiting

   Limit total packets returned.

   | Key      | Type | Description                   |
   | -------- | ---- | ----------------------------- |
   | limit    | int  | Maximum results to return     |

## Fetching historic packets
Packets can be fetched from the `kismetdb`, for all packets stored in the current session `kismetdb` log.

__LOGIN REQUIRED__

* URL \\
        /logging/kismetdb/pcap/*[TITLE]*.pcapng \\
        /logging/kismetdb/pcap/*[TITLE]*.pcapng?option1=...&option2=...

* Methods \\
        `GET` `POST` 

* URL parameters

| Key | Description |
| --- | ----------- |
| *[TITLE]*  | File download title, does not impact pcap file generation. |

Additionally, when using the `GET` URI, the [filter options](#filter-options) defined above are accepted as `HTTP GET` URL-encoded variables.

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| filter | A dictionary of the [filter options](#filter-options) defined above |

* Result \\
        `HTTP 500` error if the `kismet` log type is not enabled. \\
        A pcapng stream will be generated of packets, if any, matching the filter options.  This stream will be buffered at the rate that the client is able to download it, and the stream will be closed at the end of the query.

* Notes \\
        If the `kismet` log is not enabled, this endpoint will return an error.

