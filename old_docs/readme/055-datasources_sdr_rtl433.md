---
title: "SDR rtl433 sources"
permalink: /docs/readme/datasources_sdr_rtl433/
excerpt: "SDR-based rtl433 sources"
toc: true
---

## SDR
SDR, or software-defined radio, uses special generic hardware to capture radio signals, and performs signal processing in software.

SDR is extremely powerful, but also often extremely brittle - configuring SDR hardware and software to work reliably can be quite difficult.  Kismet is able to use external SDR tools to interface with hardware and utilize some of the power of SDR.

### Datasource - SDR RTL433
The rtl-sdr radio is an extremely cheap USB SDR (software defined radio).  While very limited, it is still capable of performing some useful monitoring.

Kismet is able to process data from the rtl_433 tool, which can read the broadcasts of an multitude of wireless thermometer, weather, electrical, tire pressure, and other sensors.

To use the rtl433 capture, you must have a rtl-sdr USB device; this cannot be done with normal Wi-Fi hardware because a Wi-Fi card is not able to tune to the needed frequencies, and cannot report raw radio samples that are not Wi-Fi packets.

More information about the rtl-sdr is available at: https://www.rtl-sdr.com

The rtl_433 tool can be downloaded from: https://github.com/merbanan/rtl_433 or as a package in your distribution.

The Kismet rtl_433 interface uses librtlsdr, rtl_433, and Python; rtl433 sources will show up as normal Kismet sources using the rtl433-X naming.

For more information about the rtl433 support, see the README in the  capture_sdr_rtl433 directory.
