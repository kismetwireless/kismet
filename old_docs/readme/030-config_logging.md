---
title: "Logging"
permalink: /docs/readme/logging/
excerpt: "Kismet logging options"
toc: true
---

## Logging

Kismet supports logging to multiple file types:

* `kismet` is the primary log format now used by Kismet.  This log combines all the data Kismet is able to gather - packets, device records, alerts, system messages, GPS location, non-packet received data, and more.  This file can be manipulated with the tools in the `log_tools/` directory.  Under the covers, a `kismet` log is a sqlite3 database.
* `pcapppi` is the legacy pcap format using the PPI headers.  This format saves Wi-Fi packets, GPS information, and *some* (but not all) of the signal information per packet.  Information about which datasource captured a packet is not preserved.
* `pcapng` is the modern pcap format.  While not all tools support it, Wireshark and TShark have excellent support.  Most tools written using libpcap can read pcap-ng files with a *single* data source.  When using pcap-ng, Kismet can log packets from multiple sources, preserving the datasource information and the original, complete, per-packet signal headers. 

### Picking a log format

Kismet can log to multiple logs simultaneously, configured in the `kismet_logging.conf` config file (or in the `kismet_site.conf` override configuration).  Logs are configured by the `log_types=` config option, and multiple types can be specified:

```
log_types=kismet,pcapng
```

### Log names and locations

Log naming and location is configured in `kismet_logging.conf` (or `kismet_site.conf` for overrides).  Logging can be disabled entirely with:

```
logging_enabled=false
```

or it can be disabled at launch time by launching Kismet with `-n`:

```bash
$ kismet -n ...
```



The default log title is 'Kismet'.  This can be changed using the `log_title=` option:

```
log_title=SomeCustomName
```

or it can be changed at launch time by running Kimet with `-t ...`:

```bash
$ kismet -t SomeCustomeName ...
```



Kismet stores logs in the directory it is launched from.  This can be changed using the `log_prefix=` option; this is most useful when launching Kismet as a service from systemd or similar when the directory it is being launched from may not be where you want to store logs:

```
log_prefix=/tmp/kismet
```

### Kismet log journal files

The `kismet` log format uses sqlite3 to create a dynamic random-access file.  If Kismet exits abnormally (such as running out of RAM or the power to the device failing), it may leave behind a `...-journal` file.  

This file is part of the sqlite3 integrity protection, and contains partial data which was not written to the database.

The journal file will be automatically merged when the log file is opened, or you can manually merge them with sqlite command line tools:

```bash
$ sqlite3 Kismet-foo-whatever.kismet 'VACUUM;'
```
