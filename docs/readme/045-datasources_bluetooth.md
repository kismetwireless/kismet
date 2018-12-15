---
title: "Bluetooth sources"
permalink: /docs/readme/datasources_bluetooth/
excerpt: "Bluetooth datasources"
toc: true
---

## Bluetooth
Bluetooth uses a frequency-hopping system with dynamic MAC addresses and other oddities - this makes sniffing it not as straightforward as capturing Wi-Fi.

Currently the only implemention of Bluetooth scanning in Kismet uses the Linux HCI layer to perform active device scans.

Support for Bluetooth capture using the Ubertooth One hardware will be forthcoming.

### Datasource: Linux Bluetooth
Currently the Kismet implementation of Bluetooth discovery uses the Linux HCI layer to perform device scans to detect dicoverable Bluetooth Classic devices and BTLE devices; this is an active scan, not passive monitoring.

The Linux Bluetooth source will auto-detect supported interfaces by querying the bluetooth interface list.  It can be manually specified with `type=linuxbluetooth`.

The Linux Bluetooth capture uses the 'kismet_cap_linux_bluetooth' tool, and should typically be installed suid-root:  Linux requires root to manipulate the `rfkill` state and the management socket of the Bluetooth interface.

#### Example source
```
source=hci0:name=linuxbt
```

#### Supported Hardware

For simply identifying Bluetooth (and BTLE) devices, the Linux Bluetooth datasource can use any standard Bluetooth interface supported by Linux.

This includes almost any built-in Bluetooth interface, as well as external USB interfaces such as the Sena UD100.

#### Service Scanning

By default, the Kismet Linux Bluetooth data source turns on the Bluetooth interface and enables scanning mode.  This allows it to see broadcasting Bluetooth (and BTLE) devices and some basic information such as the device name, but does not allow it to index services on the device.

Complex service scanning and enumeration will be coming in a future revision.

#### Bluetooth Source Parameters
Linux Bluetooth sources support all the common configuration options such as name, information elements, and UUID.

