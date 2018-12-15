---
title: "Performance and Memory Tuning"
permalink: /docs/readme/performance_and_memory/
excerpt: "Tuning options for performance and memory"
toc: true
---

## Kismet Memory and Processor Tuning
Kismet has several options which control how much memory and processing it uses.  These are found in `kismet_memory.conf`.  Generally it is not necessary to tune these values unless you are running on extremely limited hardware or have a very large number of devices (over 10,000) detected.

* `tracker_device_timeout=seconds`
   Kismet will forget devices which have been idle for more than the specified time, in seconds.

   Kismet will also forget links between devices (such as access points and clients) when the device has been idle for more than the specified time.

   This is primarily useful on long-running fixed Kismet installs.

* `tracker_max_devices=devices`
   Kismet will start forgetting the oldest devices when more than the specified number of devices are seen.

   There is no terribly efficient way to handle this, so typically, leaving this option unset is the right idea.  Memory use can be tuned over time using the `tracker_device_timeout` option.

* `keep_location_cloud_history=true|false`
   Kismet can track a 'cloud' style history of locations around a device; Similar to a RRD (round robin database), the precision of the records decreases over time.

   The location cloud can be useful for plotting devices on a map, but also takes more memory per device.

* `keep_datasource_signal_history=true|false`
   Kismet can keep a record of the signal levels of each device, as seen by each data source.  This is used for tracking signal levels across many sensors, but uses more memory.

* `alertbacklog=number`
   The number of alerts Kismet saves for displaying to new clients; setting this too low can prevent clients from seeing alerts but saves memory.

   Alerts will still be logged.

* `packet_dedup_size=packets`
   When using multiple datasources, Kismet keeps a list of the checksums of previous packets; this prevents multiple copies of the same packet triggering alerts.

* `packet_backlog_warning=packets`
   Kismet will start raising warnings when the number of packets waiting to be processed is over this number; no action will be taken, but an alert will be generated.

   This can be set to zero to disable these warnings; Kismet defaults to zero.  Disabling these warnings will NOT disable the backlog limit warnings.

* `packet_backlog_limit=packets`
   This is a *hard limit*.  If the packet processing thread is not able to process packets fast enough, new packets will be dropped over this limit.

   This can be set to 0; Kismet will never drop packets.  This may lead to a runaway memory situation, however.

* `ulimit_mbytes=ram_in_megabytes`
   Kismet can hard-limit the amount of memory it is allowed to use via the 'ulimit' system; this could be set via a launch/setup script using the at startup. 

   If Kismet runs out of ram, it *will exit immediately* as if the system had encountered an out-of-memory error.

   This setting should ONLY be combined with a restart script that relaunches Kismet, and typically should only be used on long-running WIDS-style installs of Kismet.

   If this value is set too low, Kismet may fail to start the webserver correctly or perform other startup tasks.  This value should typically only be used to control unbounded growth on long-running installs.

   The memory value is specified in *megabytes of ram*

   Some older kernels (such as those found on some Debian and Ubuntu versions still in LTS, such as Ubuntu 14.04) do not properly calculate memory used by modern allocation systems and will not count the memory consumed.  On these systems, it may be necessary to use externally-defined `cgroup` controls.

### Extremely large numbers of data sources

Using extremely large numbers of local data sources (in excess of 16 devices) can introduce a new set of instabilities and concerns; depending on the devices used, the kernel version, and if using an out-of-kernel driver such as the RTL8812AU driver set, the driver version.

While *reading* packets from a capture interface is generally very cheap (a bulk transfer operation), configuring an interface or changing the channel may be quite expensive, in terms of work done by the kernel and driver.

Some drivers and kernels seem especially impacted when first setting a very large number of interfaces to monitor mode; this can lead to timeouts or even kernel crashes on some drivers.  Kismet provides a set of tuning knobs in `kismet.conf`:

* `source_stagger_threshold=[number]`
  This determines when Kismet will start staggering local source bring-up - if you have more than this number of sources defined, Kismet will slow down the startup process.
* `source_launch_group=[number]`
  This determines how many sources will be bought up at a time.
* `source_launch_delay=[seconds]`
  The number of seconds between launching each group of sources.

While the default values may be sane for your application, adding this many local sources to Kismet implies an advanced configuration - you may find benefit to tuning these options for your specific configuration.

You may also find it necessary to decrease the channel hopping speed to alleviate contention in the kernel.

When running an extremely large number of sources, remember also that Kismet will likely require a significant amount of CPU and RAM for the additional data being gathered.

