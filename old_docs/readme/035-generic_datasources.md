---
title: "Data sources"
permalink: /docs/readme/datasources/
excerpt: "Data capture sources"
toc: true
---

## Kismet Data Sources

Kismet gets data (which can be packets, devices, or other information) from "data sources".

Data sources can be created several ways:
* `source=foo` in kismet.conf
* `-c foo` on the command line when starting Kismet
* via the web interface
* scriptable via the REST api

Source definitions look like:
```
source=[interface]:[option, option, option]
```

For example to capture from a Linux Wi-Fi device on `wlan1` with no special options:
   ```
   source=wlan1
   ```

To capture from a Linux Wi-Fi device on wlan1 while setting some special options, like telling it to not change channels and to capture from channel 6:
   ```
   source=wlan1:channel_hop=false,channel=6
   source=wlan1:channel_hop=false,channel=11HT-
   ```

Different data sources have different options, read on for more information about the different capture sources Kismet supports.

When no options are provided for a data source, the defaults are controlled by settings in kismet.conf; these defaults are applied to all new datasources:

* `channel_hop=true | false`
   Determine if datasources enable channel hopping.  Because radios can only tune to a single channel at a time (typically, the exceptions are weird enough that you'll only encounter them on specialized non Wi-Fi hardware), Kismet needs to jump the data source around different channels.
   Typically, channel hopping should be turned on.  You can disable it for specific data sources if you want to zero in on a specific channel with known traffic on it.

* `channel_hop_speed=channels/sec | channels/min`
   The channel hop speed controls how quickly Kismet hops through the channels.
   Finding the right balance of channel hop speed can depend on your environment, hardware, and goals.
   The faster you change channels, the more likely you are to see devices, but the less likely you are to capture useful data streams from them.  Conversely, a slower hopping rate can yield more data, but miss devies which have a very short duty cycle.
   By default, Kismet hops at 5 channels a second.
   Examples:
   ```
   channel_hop_speed=5/sec
   channel_hop_speed=10/min
   ```

* `split_source_hopping=true | false`
   Kismet supports capturing from multiple data sources at once - for instance, two, three, or a dozen Wi-Fi cards.  Typically it does not make sense to have multiple data sources capturing on the same channel at the same time.
   With split-hopping, Kismet will take the channel list for devices of the same type and divide it among the number of datasources available, maximizing channel coverage.
   Generally there is no reason to disable this option.

* `randomized_hopping=true | false`
   Generally, data sources retreive the list of channels in sequential order.  On some data source types (like Wi-Fi), channels can overlap; hopping in a semi-random order increases the channel coverage by leveraging channel overlap to observe adjacent channels whenever possible.
   Generally, there is no reason to turn this off.

    randomized_hopping=true | false


* `retry_on_source_error=true | false`
   Kismet will try to re-open a source which is in an error state after five seconds.  This helps Kismet re-open sources which are disconnected or have a driver error.
   There is generally no reason to turn this off.

* `timestamp=true | false`
   Typically, Kismet will override the timestamp of the packet with the local timestamp of the server; this is the default behavior for remote data sources, but it can be turned off either on a per-source basis or in `kismet.conf` globabally.
   Generally the defaults have the proper behavior, especially for remote data sources which may not be NTP time synced with the Kismet server.

### Naming and describing data sources

Datasources allow for annotations; these have no role in how Kismet operates, but the information is stored alongside the source definition and is available in the Kismet logs and in the web interface.

The following information can be set in a source, but is not required:

* `name=arbitrary name`
   Give the source a human-readable name.  This name shows up in the web UI and the Kismet log files.  This can be extremely useful when running remote capture where multiple sensors might all have `wlan0`, or simply to give interfaces a more descriptive name.
   ```
   source=wlan0:name=foobar_some_sensor
   ```

* `info_antenna_type=arbitrary antenna type`
   Give the source a human-readable antenna type.  This type shows up in the logs.
   ```
   source=wlan0:name=foobar,info_antenna_type=omni
   ```

* `info_antenna_gain=value in dB`
   Antenna gain in dB.  This gain is saved in the Kismet logs that describe the datasources.
   ```
   source=wlan0:name=foobar,info_antenna_type=omni,info_antenna_gain=5.5
   ```
   
* `info_antenna_orientation=degrees`
   Antenna orientation, in degrees.  This is useful for a fixed antenna deployment where different sources have physical coverage areas.
   ```
   source=wlan0:name=foobar,info_antenna_orientation=180
   ```
   
* `info_antenna_beamwidth=width in degrees`
   Antenna beamwidth in degrees.  This is useful for annotating sources with fixed antennas with specific beamwidths, like sector antennas.
   ```
   source=wlan0:info_antenna_type=sector,info_antenna_beamwidth=30
   ```
   
* `info_amp_type=amplifier type`
   Arbitrary human-readable type of amplifier, if one is present:
   ```
   source=wlan0:info_amp_type=custom_duplex
   ```

* `info_amp_gain=gain in dB`
   Amplifier gain, if any:
   ```
   source=wlan0:info_amp_type=custom_duplex,info_amp_gain=20
   ```

#### Setting source IDs
Typically Kismet generates a UUID based on attributes of the source - the interface MAC address if the datasource is linked to a physical interface, the devices position in the USB bus, or some other consistent identifier.
To override the UUID generation, the `uuid=...` parameter can be set:
```
source=wlan0:name=foo,uuid=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
```
If you are assigning custom UUIDs, you **must ensure** that every UUID is **unique**.  Each data source **must have** its own unique identifier.

### Multiple Kismet Datasources

Kismet will attempt to open all the sources defined on the command line (with the `-c` option), or if no sources are defined on the command line, all the sources defined in the Kismet config files.
​    
If a source has no functional type and encounters an error on startup, it will be ignored - for instance if a source is defined as:
   ```
   source=wlx4494fcf30eb3
   ```
and that device is not connected when Kismet is started, it will raise an error but will be ignored.

To force Kismet to try to open a device which could not be found at startup, you will need to provide the source type; for instance, the same source defined with the type field:
   ```
   source=wlx4494fcf30eb3:type=linuxwifi
   ```
will continually try to re-open the device.
