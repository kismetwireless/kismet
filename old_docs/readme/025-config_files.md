---
title: "Config Files"
permalink: /docs/readme/config_files/
excerpt: "Kismet configuration files"
toc: true
---

## Configuring Kismet

Kismet is primarily configured through a set of configuration text files.  By default these are installed into `/usr/local/etc/`. The config files are broken into several smaller files for readability:

* `kismet.conf`
   The master config file which loads all other configuration files, and contains most of the system-wide options

* `kismet_alerts.conf`
   Alert / WIDS configuration, which includes rules for alert matching, rate limits on alerts, and other IDS/problem detection options

* `kismet_httpd.conf`
   Webserver configuration

* `kismet_memory.conf`
   Memory consumption and system tuning options.  Typically unneeded, but if you have a massive number of devices or an extremely resource-limited system, how Kismet uses memory can be tuned here.

* `kismet_storage.conf`
   Kismet persistent storage configuration

* `kismet_logging.conf`
   Log file configuration

* `kismet_uav.conf`
   Parsing rules for detecting UAV / Drones or similar devices; compiled from the `kismet_uav.yaml` file

* `kismet_80211.conf`
   Configuration settings for Wi-Fi (IEEE80211) specific options

* `kismet_site.conf`
   Optional configuration override; Kismet will load any options in the `kismet_site.conf` file last and they will take precedence over all other configs.

### Configuration Format

Configuration files are plain text.  Lines beginning with a `#` are comments, and are ignored.

Configuration options all take the form of:
   `option=value`

Some configuration options support repeated definitions, such as the 
`source` option which defines a Kismet datasource:
   `source=wlan0`
   `source=wlan1`

Kismet supports importing config files.  This is used by Kismet itself to
split the config files into more readable versions, but can also be used
for including custom options.

* `include=/path/to/file`
   Include a config file; this file is parsed immediately, and the file **must** exist or Kismet will exit with an error.
* `opt_include=/path/to/file`
   Include an **optional** config file.  If this file does not exist, Kismet will generate a warning, but continue working.
* `opt_override=/path/to/file`
   Include an **optional OVERRIDE** config file.  This is a special file which is loaded at the **end** of all other configuration.  Any configuration options found in an override file **replace all other instances of those configurations**.  This is a very powerful mechanism for provisioning multiple Kismet servers or making a config which survives an upgrade and update to the newest configuration files when running from git.

### Configuration Override Files - `kismet_site.conf`
Most users installing Kismet will likely edit the configuration files
directly.  This file is not needed by most users, and can be ignored, however if you are configuring Kismet on multiple systems, this may be useful.

When Kismet frequently from source (for instance, testing Git) or preparing Kismet server deployments across multiple systems presents other challenges.

By default, Kismet will look for an optional override file in the default
configuration directory (/usr/local/etc by default) named `kismet_site.conf`.

This file is specified as an OVERRIDE FILE.  Any options placed in kismet_site.conf will REPLACE ANY OPTIONS OF THE SAME NAME.

This mechanism allows a site configuration to override any default config
options, while not making changes to any configuration file installed by
Kismet.  This allows new installations of Kismet to replace the config files with impunity while preserving a custom configuration.

Typical uses of this file might include changing the http data directory,
defining sources and memory options, forcing or disabling logging, and so on; a `kismet_site.conf` file might look like:
```
server_name=Some server
server_description=Building 2 floor 3

gps=serial:device=/dev/ttyACM0,name=laptop

remote_capture_listen=0.0.0.0
remote_capture_port=3501

source=wlan1
source=wlan2
```
