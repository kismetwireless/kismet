---
title: "Git and Beta"
permalink: /docs/readme/git_and_beta/
excerpt: "Git and Beta Versions"
---

## MAJOR KISMET UPDATE

Welcome to the new, MAJOR rewrite of Kismet!  This version changes almost everything, hopefully for the better, including:

* Web-based UI allowing for much simpler presentation of data and compatibility with mobile devices

* Standard JSON-based data export for easy scripting against Kismet instances

* Support for wireless protocols beyond Wi-Fi, like basic Bluetooth scanning, thermometer and weather station detection with the RTL-SDR hardware, and more on the way

* New remote-capture code optimized for binary size and RAM, allowing extremely low-end embedded devices to be used for packet capture

* New logging format which can encapsulate complex information about devices, system state, alerts, messages, and packets in a single file with simple tools for extracting standard formats

* Pcap-NG multi-interface logs with complete original headers, readable by Wireshark and other tools

Please remember that as a pre-release, there is still some to be done and warts to be taken care of, but the codebase has been under development and in use for several years and has been performing well.

Setting up the new Kismet is generally simpler than the older versions, keep reading for more information!

At the *very least* you will need to uninstall any old versions of Kismet, and you will need to install the new config files with `make forceconfigs`.  Read on for more info!

