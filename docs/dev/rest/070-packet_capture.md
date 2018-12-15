---
title: "Packet capture"
permalink: /docs/devel/webui_rest/packet_capture/
toc: true
---
Kismet can export packets in the pcap-ng format; this is a standard, extended version of the traditional pcap format.  Tools such as Wireshark (and tshark) can process complete pcapng frames, while tcpdump and other libpcap based tools (currently including Kismet) can process the simpler version of pcapng.

The pcap-ng format allows for multiple interfaces and linktypes to be stored in a single file.  This format can be read and processed by [Wireshark and tshark](https://www.wireshark.org) but may not be compatible with all traditional libpcap-based tools.  Typically, libpcap based tools can easily process a pcap-ng file with a *single source* but may have difficulty processing files with multiple sources.

The pcap-ng file can be post-processed with `tshark` or `wireshark` to strip it to a single interface if necessary.

## All packets
Kismet can provide a live stream, in pcap-ng format, of all packets *since the time of this request* seen by Kismet from all datasources.

To access packets *previously seen* by Kismet, look at the [Databaselog endpoints](/docs/devel/webui_rest/databaselog/).

__LOGIN REQUIRED__

* URL \\
        /pcap/all_packets.pcapng
        /datasource/pcap/all_sources.pcapng

* Methods \\
        `GET`

* Results \\
        A pcap-ng stream of packets which will stream indefinitely as packets are received.

## Packets by datasource
The packet stream may be limited to packets captured by a single datasource, indicated by the datasource UUID.

__LOGIN REQUIRED__

* URL \\
        /datasource/pcap/by-uuid/*[UUID]*/*[UUID]*.pcapng

* Methods \\
        `GET`

* URL parameters:

| Key | Description |
| --- | ----------- |
| *[UUID]* | Datasource UUID |

* Results \\
        A pcap-ng stream of packets which will stream indefinitely as packets are received.

## Packets by device
The packet stream may be limited to packets captured and associated with a specific device by Kismet, indicated by the Kismet device key.

__LOGIN REQUIRED__

* URL \\
        /devices/by-key/*[KEY]*/pcap/*[KEY]*.pcapng

* Methods \\
        `GET`

* URL parameters:

| Key | Description |
| --- | ----------- |
| *[KEY]* | Device key |

* Results \\
        A pcap-ng stream of packets which will stream indefinitely as packets are received.

