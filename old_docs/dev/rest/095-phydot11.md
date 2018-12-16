---
title: "Phy80211 Wi-Fi"
permalink: /docs/devel/webui_rest/phy80211/
toc: true
---
The 802.11 Wi-Fi phy defines extra endpoints for manipulating Wi-Fi devices seen by Kismet, and for extracting packets of special types.

## WPA Handshakes
The WPA handshake is vital for extracking the WPA key of an encrypted WPA or WPA2 session.  Kismet will retain the handshake packets from an access point, and can provide them as a PCAP file.

__LOGIN REQUIRED__

* URL \\
        /phy/phy80211/by-key/*[DEVICEKEY]*/*[DEVICEKEY]*-handshake.pcap

* Methods \\
        `GET`

* URL parameters

| Key | Desription |
| --- | ---------- |
| *[DEVICEKEY]* | Kismet device key of target device |

* Result \\
        PCAP file of WPA handshake packets associated with the device.

## Wi-Fi per-device pcap stream
Kismet can provide a streaming pcap-ng log of all packets, from all interfaces, associated with a given Wi-Fi BSSID.  Packets are streamed _starting when this endpoint is opened_, for past packtes, use the [KismetDB log API](/docs/devel/webui_rest/kismetdb/).

__LOGIN REQUIRED__

* URL \\
        /phy/phy80211/by-bssid/*[BSSID]*/*[BSSID]*.pcapng

* Methods \\
        `GET`

* URL parameters

| Key | Description |
| - | - |
| *[BSSID]* | BSSID retrieve packets from |

* Results \\
        A pcap-ng stream of packets which will stream indefinitely as packets are received.

* Notes \\
        See the [packet capture API](/docs/devel/webui-rest/packet_capture/) for more information about pcap-ng streams

## Wi-Fi clients
Kismet tracks client association with access points.  This information is available as a list of the device keys in the access point device record, but it is also available through the clients API which will return the complete device record of the associated client.

* URL \\
        /phy/phy80211/clients-of/*[DEVICEKEY]*/clients.json

* Methods \\
        `GET` `POST`

* URL parameters

| Key | Description |
| - | - |
| *[DEVICEKEY]* | Device to fetch clients of |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| fields  | Optional, [field simplification](/docs/devel/webui_rest/commands/#field-specifications) |

* Results \\
        An array of device records of associated clients.

## Access points only view
The 802.11 subsystem uses [device views](/docs/devel/webui_rest/device_views/) to provide a list of Wi-Fi access points.

* URL \\
        /devices/views/phydot11_accesspoints/...
        /devices/views/phydot11_accesspoints/devices.json
        /devices/views/phydot11_accesspoints/last-time/*[TIMESTAMP]*/devices.json

* Notes \\
        See the [views api](/docs/devel/webui_rest/device_views/) for more information

