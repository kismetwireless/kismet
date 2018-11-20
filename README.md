# Kismet 2018-08-GIT

https://www.kismetwireless.net

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



------
[TOC]


## Compiling: Quick Setup

Kismet has many configuration knobs and options; but for the quickest way to get the basics working:

1. Uninstall any existing Kismet installs.  If you installed Kismet using a package from your distribution, uninstall it the same way; if you compiled it yourself, be sure to remove it

2. Install dependencies.  Kismet needs a number of libraries and  development headers to compile; these should be available in nearly all distributions.

   *Ubuntu/Debian/Kali/Mint*

   ```bash
   $ sudo apt-get install build-essential git libmicrohttpd-dev pkg-config zlib1g-dev libnl-3-dev libnl-genl-3-dev libcap-dev libpcap-dev libncurses5-dev libnm-dev libdw-dev libsqlite3-dev libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler libsensors4-dev
   ```

   On some older versions, `libprotobuf-c-dev` may be called `libprotobuf-c0-dev`.
   
   For the Python add-ons, you will also need the following Python2 libraries.  The `protobuf` tool currently does not appear to agree with the changes in python3, so python2 is required:

   ```bash
   $ sudo apt-get install python2 python-setuptools python-protobuf python-requests
   ```

   You can also use the `pip` equivalents of the python libraries, so long as they're installed in a location your normal Python interpreter can find them.

   For rtlsdr rtl_433 support, you will also need:

   ```bash
   $ sudo apt-get install librtlsdr0 python-usb python-paho-mqtt
   ```
   as well as the rtl_433 tool from https://github.com/merbanan/rtl_433 if it is not otherwise provided by your distribution.

   For Mousejack/nRF support and other USB based tools, you will need `libusb`:

   ```bash
   $ sudo apt-get install libusb-1.0-0-dev
   ```

   *Fedora (and related)*

   ```bash
   $ sudo dnf install make automake gcc gcc-c++ kernel-devel git libmicrohttpd-devel pkg-config zlib-devel libnl3-devel libcap-devel libpcap-devel ncurses-devel NetworkManager-libnm-devel libdwarf libdwarf-devel elfutils-devel libsqlite3x-devel protobuf-devel protobuf-c-devel protobuf-compiler protobuf-c-compiler lm_sensors-devel libusb-devel fftw-devel
   ```

   You will also need the related python2 packages.

3. Clone Kismet from git.  If you haven't cloned Kismet before:
   ```bash
    $ git clone https://www.kismetwireless.net/git/kismet.git
   ```

    If you have a Kismet repo already:

    ```bash
   $ cd kismet
   $ git pull
    ```

4. Run configure.  This will find all the specifics about your system and prepare Kismet for compiling.  If you have any missing dependencies or incompatible library versions, they will show up here.
   ```bash
   $ cd kismet
   $ ./configure
   ```

   Pay attention to the summary at the end and look out for any warnings! The summary will show key features and raise warnings for missing dependencies which will drastically affect the compiled Kismet.

5. Compile Kismet.
   ```bash
   $ make
   ```

   You can accelerate the process by adding `-j #`, depending on how many CPUs you have.  To automatically compile on all the available cores:
   ```bash
   $ make -j$(nproc)
   ```

   C++ uses quite a bit of RAM to compile, so depending on the RAM available on your system you may need to limit the number of processes you run simultaneously.

6.  Install Kismet.  Generally, you should install Kismet as suid-root; Kismet will automatically add a group and install the capture binaries accordingly.

   When installed suid-root, Kismet will launch the binaries which control the channels and interfaces with the needed privileges, but will keep the packet decoding and web interface running without root privileges.
   ```bash
   $ sudo make suidinstall
   ```

7.  Add your user to the `kismet` group.
   ```bash
   $ sudo usermod -aG kismet $USER
   ```
   This will add your current logged in user to the `kismet` group.

8.  Log out and back in.  Linux does not update groups until you log in; if you have just added yourself to the Kismet group you will have to re-log in.

9.  Check that you are in the Kismet group with:
   ```bash
   $ groups
   ```
   If you are not in the `kismet` group, you should log out entirely, or reboot.

10.  You're now ready to run Kismet!  Point it at your network interface... Different distributions (and kernel versions, and distribution versions) name interfaces differently; your interface may be `wlan0` or `wlan1`, or it may be named something like `wlp0s1`, or it may be named using the MAC address of the card and look like `wlx00c0ca8d7f2e`.

   You can now start Kismet with something like:
   ```bash
   $ kismet -c wlan0
   ```

   *or*, you can just launch Kismet and then use the new web UI to select the card you want to use, by launching it with just:
   ```bash
   $ kismet
   ```

   Remember, until you add a data source, Kismet will not be capturing any packets!

   *THE FIRST TIME YOU RUN KISMET*, it will generate a new, random password for your web interface.

   This password can be found in the config file: `~/.kismet/kismet_httpd.conf` which is in the *home directory of the user* starting Kismet.

   If you start Kismet as or via sudo (or via a system startup script where it runs as root), this will be in *roots* home directory: `/root/.kismet/kismet_httpd.conf`

  You will need this password to control Kismet from the web page - without it you can still view information about devices, view channel allocations, and most other actions, but you CAN NOT control Kismet data sources, view pcaps, or perform other actions.

11.  Point your browser at http://localhost:2501

   You will be prompted to do basic configuration - Kismet has many options in the web UI which can be tweaked.

   To use all the features of the Kismet web UI, put in the password found in the `kismet_httpd.conf` config file above.

## Debugging Kismet

Kismet (especially in beta) is in a state of rapid development - this means that bad things can creep into the code.  Sorry about that!

If you're interested in helping debug problems with Kismet, here's the most useful way to do so:

1. Compile Kismet from source (per the quick start guide above)

2. Install Kismet (typically via `sudo make suidinstall`)

3. Run Kismet, *FROM THE SOURCE DIRECTORY*, in `gdb`:

  ```bash
  $ gdb ./kismet
  ```

  This loads a copy of Kismet with all the debugging info intact; the copy of Kismet which is installed system-wide usually has this info removed; the installed version is 1/10th the size, but also lacks a lot of useful information which we need for proper debugging.

4. Tell GDB to ignore the PIPE signal 

   ```
   (gdb) handle SIGPIPE nostop noprint pass
   ```

   This tells GDB not to intercept the SIGPIPE signal (which can be generated, among other times, when a data source has a problem)

5. Configure GDB to log to a file

  ```
  (gdb) set logging on
  ```

  This saves all the output to `gdb.txt`

5. Run Kismet - *in debug mode*

  ```
  (gdb) run --debug [any other options]
  ```

  This turns off the internal error handlers in Kismet; they'd block gdb from seeing what happened.  You can specify any other command line options after --debug; for instance:

  ````
  (gdb) run --debug -n -c wlan1
  ````

6.  Wait for Kismet to crash

7.  Collect a backtrace
   ```
   (gdb) bt
   ```

   This shows where Kismet crashed.

8.  Collect thread info
   ```
   (gdb) info threads
   ```

   This shows what other threads were doing, which is often critical for debugging.

9.  Collect per-thread backtraces
   ```
   (gdb) thread apply all bt full
   ```

   This generates a dump of all the thread states

10. Send us the gdb log and any info you have about when the crash occurred; dragorn@kismetwireless.net or swing by IRC or the Discord channel (info available about these on the website, https://www.kismetwireless.net)

#### Advanced debugging

If you're familiar with C++ development and want to help debug even further, Kismet can be compiled using the ASAN memory analyzer; to rebuild it with the analyser options:

```
    $ make clean
    $ CC=clang CXX=clang++ ./configure --enable-asan
```

ASAN has a performance impact and uses significantly more RAM, but if you are able to recreate a memory error inside an ASAN instrumented Kismet, that will be very helpful.

## Upgrading & Using Kismet Git-Master (or beta)

The safest route is to remove any old Kismet version you have installed - by uninstalling the package if you installed it via your distribution, or by removing it manually if you installed it from source (specifically, be sure to remove the binaries `kismet_server`, `kismet_client`,  and `kismet_capture`, by default found in `/usr/local/bin/` and the config file `kismet.conf`, by default in `/usr/local/etc/`.

You can then configure, and install, the new Kismet per the quickstart guide above.

While heavy development is underway, the config file may change; generally breaking changes will be mentioned on Twitter and in the git commit logs.

Sometimes the changes cause problems with Git - such as when temporary files are replaced with permanent files, or when the Makefile removes files that are now needed.  If there are problems compiling, the easiest first step is to remove the checkout of directory and clone a new copy (simply do a `rm -rf` of the copy you checked out, and `git clone` a new copy)

## Installing Kismet - Suid vs Normal

It is **strongly** recommended that Kismet never be run as root; instead use the Kismet suid-root installation method; when compiling from source it can be installed via:
```
$ ./configure
$ make
$ sudo make suidinstall
```

Nearly all packages of Kismet *should* support the suid-root install method as well.

This will create a new group, `kismet`, and install capture tools which need root access as suid-root but only runnable by users in the `kismet` group.

This will allow anyone in the Kismet group to change the configuration of wireless interfaces on the system, but will prevent Kismet from running as root.

#### Why does Kismet need root?

Controlling network interfaces on most systems requires root, or super-user access.

While written with security strongly in mind, Kismet is a large and complex program, which handles possibly hostile data from the world.  This makes it a very bad choice to run as root.

To mitigate this, Kismet uses separate processes to control the network interfaces and capture packets.  These capture programs are much smaller than Kismet itself, and do minimal (or no) processing on the contents of the packets they receive.

## Starting Kismet

Kismet can be started normally from the command line, and will run in a small ncurses-based wrapper which will show the most recent server output, and a redirect to the web-based interface.

Kismet can also be started as a service; typically in this usage you should also pass `--no-ncurses` to prevent the ncurses wrapper from loading.

An example systemd script is in the `packaging/systemd/` directory of the Kismet source; if you are installing from source this can be copied to `/etc/systemd/system/kismet.service`, and packages should automatically include this file.

When starting Kismet via systemd, you should install kismet as suidroot, and use `systemctl edit kismet.service` to set the following:

```
[Service]
user=your-unprivileged-user
group=kismet
```

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

* `kismet_site.conf`
   Optional configuration override; Kismet will load any options in the `kismet_site.conf` file last and they will take precedence over all other configs.

#### Configuration Format

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

#### Configuration Override Files - `kismet_site.conf`
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

### Wi-Fi

#### Wi-Fi Channels

Wi-Fi channels in Kismet define both the basic channel number, and extra channel attributes such as 802.11N 40MHz channels, 802.11AC 80MHz and 160MHz channels, and non-standard half and quarter rate channels at 10MHz and 5MHz.
​    
Kismet will auto-detect the supported channels on most Wi-Fi cards.  Monitoring on HT40, VHT80, and VHT160 requires support from your card.
​    
Channels can be defined by number or by frequency.

| Definition | Interpretation                                               |
| ---------- | ------------------------------------------------------------ |
| xx         | Basic 20MHz channel, such as `6` or `153`                    |
| xxxx       | Basic 20MHz frequency, such as `2412`                        |
| xxHT40+    | 40MHz 802.11n with upper secondary channel, such as `6HT40+` |
| xxHT40-    | 40MHz 802.11n with lower secondary channel, such as `6HT40-` |
| xxVHT80    | 80MHz 802.11ac channel, such as `116VHT80`                   |
| xxVHT160   | 160MHz 802.11ac channel, such as `36VHT160`                  |
| xxW10      | 10MHz half-channel, a non-standard channel type supported on some Atheros devices.  This cannot be automatically detected, you must manually add it to the channel list for a source. |
| xxW5       | 5MHz quater-channel, a non-standard channel type supported on some Atheros devices.  This cannot be automatically detected, you must manually add it to the channel list for a source. |

#### Datasource: Linux Wi-Fi

Most likely this will be the main data source most people use when capturing with Kismet.

The Linux Wi-Fi data source handles capturing from Wi-Fi interfaces using the two most recent Linux standards:  The new netlink/mac80211 standard present since approximately 2007, and the legacy ioctl-based IW extensions system present since approximately 2002.

Packet capture on Wi-Fi is accomplished via "monitor mode", a special mode where the card is told to report all packets seen, and to report them at the 802.11 link layer instead of emulating an Ethernet device.

The Linux Wi-Fi source will auto-detect supported interfaces by querying the network interface list and checking for wireless configuration APIs.  It can be manually specified with `type=linuxwifi`:
```
source=wlan1:type=linuxwifi
```

The Linux Wi-Fi capture uses the 'kismet_cap_linux_wifi' tool, and should
typically be installed suid-root:  Linux requires root to manipulate the
network interfaces and create new ones.

Example source definitions:
```
source=wlan0
source=wlan1:name=some_meaningful_name
```

#### Supported Hardware

Not all hardware and drivers support monitor mode, but the majority do.  Typically any driver shipped with the Linux kernel supports monitor mode, and does so in a standard way Kismet understands.  If a specific piece of hardware does not have a Linux driver yet, or does not have a standard driver with monitor mode support, Kismet will not be able to use it.

The Linux Wi-Fi source is known to support, among others:
* All Atheros-based cards (ath5k, ath9k, ath10k with some restrictions,  USB-based atheros cards like the AR9271) (* Some issues)
* Modern Intel-based cards (all supported by the iwlwifi driver including the 3945, 4965, 7265, 8265 and similar) (* Some issues)
* Realtek USB devices (rtl8180 and rtl8187, such as the Alfa AWUS036H)
* Realtek USB 802.11AC (rtl8812au, rtl8814), with *the proper drivers*.  There are no in-kernel drivers for these cards.  There are multiple forks of the out-of-kernel tree, with varying levels of support for monitor mode and injection; the most likely to work is the variant maintained by the Aircrack-NG team, which can be found at https://github.com/aircrack-ng/rtl8812au.git
* RALink rt2x00 based devices
* ZyDAS cards
* Broadcom cards such as those found in the Raspberry Pi 3 and Raspberry Pi 0W, *if you are using the nexmon drivers*.  It is not posisble to use Kismet with the *default drivers* from Raspbian or similar distributions.
   The Kali distribution for the Raspberry Pi *includes the nexmon patches already* and will work.
   To patch your own distribution with nexmon, consult the nexmon site at: https://github.com/seemoo-lab/nexmon
* Almost all drivers shipped with the Linux kernel

Devices known to have issues:
* ath9k Atheros 802.11abgn cards are typically the most reliable, however they appear to return false packets with valid checksums on very small packets such as phy/control and powersave control packets.  This may lead Kismet to detect spurious devices not actually present.
* ath10k Atheros 802.11AC cards have many problems, including floods of spurious packets in monitor mode.  These packets carry 'valid' checksum flags, making it impossible to programmatically filter them.  Expect large numbers of false devices.  It appears this will require a fix to the closed-source Atheros firmware to resolve.
* iwlwifi Intel cards appear to have errors when tuning to HT40 and VHT channels, leading to microcode/firmware crashes and resets of the card. Kismet works around this by disabling HT and VHT channels and only tuning to basic channels.  This means you will miss data packets from 11n and 11ac networks.

Kismet generally *will not work* with most other out-of-kernel (drivers not shipped with Linux itself), specifically drivers such as the SerialMonkey RTL drivers used for many of the cheap, tiny cards shipped with devices like the Raspberry Pi and included in distributions like Raspbian.  Some times it's possible to find other, supported drivers for the same hardware, however some cards have no working solution.

Many more devices should be supported - if yours isn't listed and works, let us know via Twitter (@kismetwireless).

##### Linux Wi-Fi Source Parameters
Linux Wi-Fi sources accept several options in the source definition, in addition to the common name, informational, and UUID elements:

* `add_channels="channel1,channel2,channel3"`
   A comma-separated list of channels *that will be appended* to the detected list of channels on a data source.  Kismet will autodetect supported channels, then include channels in this list.
   The list of channels *must be enclosed in quotes*, as in:
   ```
   source=wlan0:add_channels="1W5,6W5,36W5",name=foo
   ```
   If you are configuring the list of Kismet sources from the command line, you will need to escape the quotes or the shell will try to interpret them incorrectly:
   ```bash
   $ kismet -c wlan0:add_channels=\"1W5,6W5\",name=foo
   ```
   This option is most useful for including special channels which are not auto-detected, such as the 5MHz and 10MHz custom Atheros channels.

* `channel=channel definition`
   When channel hopping is disabled, set the channel the card monitors.
   ```
   source=wlan0:name=foo,channel=6
   ```

* `channels="channel,channel,channel"`
   Override the autodetected channel list and provide a fixed list.  Unlike `add_channels` this *replaces* the list of channels Kismet would normally use.
   This must be quoted, as in:
   ```
   source=wlan0:name=foo,channels="1,6,36,11HT40-"
   ```
   If you are defining the Kismet sources from the command line, you will need to escape the quotes or the shell will try to interpret them incorrectly:
   ```bash
   $ kismet -c wlan0:name="foo",channels=\"1,6,36,11HT40-\"
   ```

* `channel_hop=true | false`
   Enable or disable channel hopping on this source only.  If this option is omitted, Kismet will use the default global channel hopping configuration.

* `channel_hoprate=channels/sec | channels/min`
   Control the per-source channel hop rate.  If this option is omitted, Kismet will use the default global channel hop rate.

* `fcsfail=true | false`
   Wi-Fi packets contain a `frame checksum` or `FCS`.  Some drivers report this as the FCS bytes, while others report it as a flag in the capture headers which indicates if the packet was received correctly.
   Generally packets which fail the FCS checksum are garbage - they are packets which are corrupted, usually due to in-air collisions with other packets.  These can be extremely common in busy wireless environments.
   Usually there is no reason to set this option unless you are doing specific research on non-standard packets and hope to glean some information from corrupted packets.

* `ht_channels=true | false`
   Kismet will detect and tune to HT40 channels when available; to disable this, set `ht_channels=false` on your source definition.
   Kismet will automatically disable HT channels on some devices such as the Intel iwlwifi drivers because it is known to cause problems; if you want to force Kismet to attempt HT tuning on these devices, set `ht_channels=true` to force it.  **WARNING**: This causes firmware crashes currently on all tested Intel cards.
   See the `vht_channels` option for similar control over 80MHz and 160MHz VHT channels.

* `ignoreprimary=true | false`
   Linux mac80211 drivers use `virtual interfaces` or `VIFs` to set different interface modes and behaviors:  A single Wi-Fi card might have `wlan0` as the "normal" (or "managed") Wi-Fi interface; Kismet would then create `wlan0mon` as the monitor-mode capture interface.
   Typically, all non-monitor interfaces must be disabled (set to `down` state) for capture to work reliably and for channel setting (and channel hopping) to function.
   In the rare case where you are attempting to run Kismet on the same interface as an access point or client, you will want to leave the base interface configured and running (while losing the ability to channel hop); by settng `ignoreprimary=true` on your Kismet source line, Kismet will no longer bring down any related interface on the same Wi-Fi card.
   This **almost always** must be combined with also setting `hop=false` because channel control is not possible in this configuration, and depending on the Wi-Fi card type, may prevent proper data capture.

* `plcpfail=true | false`
   Some drivers have the ability to report data that *looked* like a packet, but which have invalid radio-level packet headers (the Wi-Fi `PLCP` which is not typically exposed to the capture layer).  Generally these events have no meaning, and few drivers are able to report them.
   Usually there is no good reason to turn this on, unless you are doing research attempting to capture Wi-Fi-like data.

* `vif=foo`
   Many drivers use `virtual interfaces` or `VIFs` to control behavior.  Kismet will make a monitor mode virtual interface (vif) automatically, named after some simple rules:
   * If the interface given to Kismet on the source definition is already in monitor mode, Kismet will use that interface and not create a VIF
   * If the interface name is too long, such as when some distributions use the entire MAC address as the interface name, Kismet will make a new interface named `kismonX`
   * Otherwise, Kismet will add `mon` to the interface; ie given an interface `wlan0`, Kismet will create `wlan0mon`
   
   The `vif=` option allows setting a custom name which will be used instead of generating the monitor interface name.
   
* `vht_channels=true | false`
   Kismet will tune to VHT80 and VHT160 channels when available; `vht_channels=false` will exclude them from this list.
   Kismet will automatically exclude VHT channels from devices known to have probems tuning to them, specifically the Intel `iwlwifi` drivers will crash when tuning to VHT channels.  To *force* Kismet to include VHT channels on these devices, set `vht_channels=true` on your source.  **WARNING**: This will cause firmware resets on all currently tested Intel Wi-Fi cards!
   See the ht_channels option for similar control over HT40 channels.
   
* `retry=true | false`
   Automatically try to re-open this interface if an error occurs.  If the capture source encounters a fatal error, Kismet will try to re-open it in five seconds.  If this is omitted, the source will use the global retry option.

##### Special Linux Wi-Fi Drivers
Some drivers require special behavior - whenever possible, Kismet will detect these drivers and "do the right thing".

* The rtl8812 and rtl8814 drivers (available at https://github.com/aircrack-ng/rtl8812au.git) support monitor mode, however they do not properly implement the mac80211 control layer; while they support creating VIFs for monitor mode, they do not actualy provide packets.  Kismet will detect the `8812au` and `8814` drivers and configure the base interface in monitor mode using legacy ioctls.
* The nexmon driver patches for Broadcom devices do not enter monitor mode normally; Kismet will detect the drivers and use the nexmon-custom ioctls.

#### Data source: OSX Wifi
Kismet can use the built-in Wi-Fi on a Mac, but ONLY the built-in Wi-Fi; Unfortunately currently there appear to be no drivers for OSX for USB devices which support monitor mode.

Kismet uses the `kismet_cap_osx_corewlan_wifi` tool for capturing on OSX.

##### OSX Wi-fi Parameters

OSX Wi-Fi sources support the standard options supported by all sources (such as name, uuid, and informational elements) as well as:
* `channels="channel,channel,channel"`
   Override the autodetected channel list and provide a fixed list.  Unlike `add_channels` this *replaces* the list of channels Kismet would normally use.
   This must be quoted, as in:
   ```
   source=wlan0:name=foo,channels="1,6,36,11HT40-"
   ```
   If you are defining the Kismet sources from the command line, you will need to escape the quotes or the shell will try to interpret them incorrectly:
   ```bash
   $ kismet -c wlan0:name="foo",channels=\"1,6,36,11HT40-\"
   ```

* `channel_hop=true | false`
   Enable or disable channel hopping on this source only.  If this option is omitted, Kismet will use the default global channel hopping configuration.

* `channel_hoprate=channels/sec | channels/min`
   Control the per-source channel hop rate.  If this option is omitted, Kismet will use the default global channel hop rate.

### Tuning Wi-Fi Packet Capture
Kismet has a number of tuning options to handle quirks in different types packet captures.  These options can be set in the kismet.conf config file to control how Kismet behaves in some situations:

* `dot11_process_phy=[true|false]`
   802.11 Wi-Fi networks have three basic packet classes - Management, Phy, and Data.  The Phy packet type is the shortest, and caries the least amount of information - it is used to acknowledge packet reception and controls the packet collision detection CTS/RTS system.  These packets can be useful, however they are also the most likely to become corrupted and still pass checksum.
   Kismet turns off processing of Phy packets by default because they can lead to spurious device detection, especially in high-data captures.  For complete tracking and possible detection of hidden-node devices, it can be set to 'true'.


### Bluetooth
Bluetooth uses a frequency-hopping system with dynamic MAC addresses and other oddities - this makes sniffing it not as straightforward as capturing Wi-Fi.

Currently the only implemention of Bluetooth scanning in Kismet uses the Linux HCI layer to perform active device scans.

Support for Bluetooth capture using the Ubertooth One hardware will be forthcoming.

#### Datasource: Linux Bluetooth
Currently the Kismet implementation of Bluetooth discovery uses the Linux HCI layer to perform device scans to detect dicoverable Bluetooth Classic devices and BTLE devices; this is an active scan, not passive monitoring.

The Linux Bluetooth source will auto-detect supported interfaces by querying the bluetooth interface list.  It can be manually specified with `type=linuxbluetooth`.

The Linux Bluetooth capture uses the 'kismet_cap_linux_bluetooth' tool, and should typically be installed suid-root:  Linux requires root to manipulate the `rfkill` state and the management socket of the Bluetooth interface.

##### Example source
```
source=hci0:name=linuxbt
```

##### Supported Hardware

For simply identifying Bluetooth (and BTLE) devices, the Linux Bluetooth datasource can use any standard Bluetooth interface supported by Linux.

This includes almost any built-in Bluetooth interface, as well as external USB interfaces such as the Sena UD100.

##### Service Scanning

By default, the Kismet Linux Bluetooth data source turns on the Bluetooth interface and enables scanning mode.  This allows it to see broadcasting Bluetooth (and BTLE) devices and some basic information such as the device name, but does not allow it to index services on the device.

Complex service scanning and enumeration will be coming in a future revision.

##### Bluetooth Source Parameters
Linux Bluetooth sources support all the common configuration options such as name, information elements, and UUID.

### Replaying data
Kismet can replay recorded data in the `pcap` and `pcap-ng` formats.  Pcap files are commonly generated by tools like `tcpdump`, `wireshark`, `tshark`, and Kismet itself.

Kismet can replay a pcapfile for testing, debugging, demo, or reprocessing.

#### Datasource - Pcapfile

The Pcapfile datasource will auto-detect pcap files and paths to files:
```bash
$ kismet -c /tmp/foo.pcap
```

It can be manually specified with `type=pcapfile`

The pcapfile capture uses the 'kismet_cap_pcapfile' tool which does not need special privileges.

Currently Kismet supports pcap-ng files with a single interface in the capture; multi-interface captures will appear as coming from a single data source - that of the pcapfile itself.

##### Pcapfile Options
In addition to the normal options supported by all sources (name, information elements, UUID, etc) the pcapfile source can also support:

* `pps=rate`
   Normally, pcapfiles are replayed as quickly as possible.  On larger pcaps this can lead to CPU and RAM contention, and dropped packets.  Specifying a packets-per-second rate throttles processing of the packet to a more sustainable speed.
   This option cannot be combined with the `realtime` option.

* `realtime=true | false`
   Normall, pcapfiles are replayed as quickly as possible.  On larger pcaps this can lead to CPU and RAM contention, and dropped packets.  Specying `realtime=true` in your source definition will reduce the packet processing rate to the original capture rate, and the packets will be processed with real-time delays equal to how they were received.

### SDR
SDR, or software-defined radio, uses special generic hardware to capture radio signals, and performs signal processing in software.

SDR is extremely powerful, but also often extremely brittle - configuring SDR hardware and software to work reliably can be quite difficult.  Kismet is able to use external SDR tools to interface with hardware and utilize some of the power of SDR.

#### Datasource - SDR RTL433
The rtl-sdr radio is an extremely cheap USB SDR (software defined radio).  While very limited, it is still capable of performing some useful monitoring.

Kismet is able to process data from the rtl_433 tool, which can read the broadcasts of an multitude of wireless thermometer, weather, electrical, tire pressure, and other sensors.

To use the rtl433 capture, you must have a rtl-sdr USB device; this cannot be done with normal Wi-Fi hardware because a Wi-Fi card is not able to tune to the needed frequencies, and cannot report raw radio samples that are not Wi-Fi packets.

More information about the rtl-sdr is available at: https://www.rtl-sdr.com

The rtl_433 tool can be downloaded from: https://github.com/merbanan/rtl_433 or as a package in your distribution.

The Kismet rtl_433 interface uses librtlsdr, rtl_433, and Python; rtl433 sources will show up as normal Kismet sources using the rtl433-X naming.

For more information about the rtl433 support, see the README in the  capture_sdr_rtl433 directory.

### Mousejack / nRF

The NordicRF nRF chip is a common chip used in wireless keyboards, mice, and presentation tools, which are frequently found in non-Bluetooth wireless input devices.

The Mousejack firmware developed by Bastille (https://www.mousejack.com/) runs on a number of commodity USB nRF devices (such as the Sparkfun nRF and the CrazyPA).

#### Datasource - nRF Mousejack

Kismet must be compiled with support for libusb to use Mousejack; you will need libusb-1.0-dev, and you will need to make sure that the `nRF Mousejack` option is enabled in the output from `./configure`.

To use the mousejack capture, you must have a supported nRF USB device; this includes any device listed on the Bastille Mousejack site:

- CrazyRadio PA USB dongle
- SparkFun nRF24LU1+ breakout board
- Logitech Unifying dongle (model C-U0007, Nordic Semiconductor based)

You will also need to flash your device with the Bastille Mousejack firmware; the firmware is available from https://github.com/BastilleResearch/mousejack and the instructions are in the README.

##### Mousejack Interfaces

Mousejack interfaces can be referred to as simply `mousejack`:

```bash
$ kismet -c mousejack
```

Multiple interfaces can be identified by their location on the USB bus; this can be detected automatically by Kismet as a supported interface, or specified manually.  To find the location on the USB bus, look at the output of `lsusb`:

```bash
$ lsusb
Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 003 Device 008: ID 1915:0102 Nordic Semiconductor ASA 
```

In this instance the device is on `bus 3` and `device 8`; we can specify this specific device in Kismet by using:

```bash
$ kismet -c mousejack-3-8
```

##### Channel Hopping

The nRF protocol as used by Mousejack covers 82 channels, each 1MHz wide.

To cover this spectrum rapidly, it is recommended that you increase the hop rate for nRF interfaces:

```bash
$ kismet -c mousejack-3-8:hop_rate=100/sec
```

This can be specified in the `kismet.conf` the same way:

```
source=mousejack:name=nRF,hop_rate=100/sec
```

## Remote Packet Capture
Kismet can capture from a remote source over a TCP connection.

Kismet remote packet feeds are initiated by the same tools that Kismet uses to configure a local source; for example if Kismet is running on a host on IP 192.168.1.2, to capture from a Linux Wi-Fi device on another device you would use:
```bash
# /usr/local/bin/kismet_cap_linux_wifi --connect 192.168.1.2:3501 --source=wlan1
```

Specifically, this uses the `kismet_cap_linux_wifi` tool, which is by default installed in `/usr/local/bin/`, to connect to the IP `192.168.1.2` port 3501.

The --source=... parameter is the same as you would use in a `source=` Kismet configuration file entry, or as `-c` to Kismet itself. 

Source definitions of a remote capture are controlled the same way as `source=` definitions in the Kismet config, and can take the same options:
```bash
# /usr/local/bin/kismet_cap_linux_wifi --connect 192.168.1.2:3501 --source=wlan1:name=sensor_foo_wlan1,add_channels=\"6W5,36W5\",info_antenna_type=omni
```

### Any-to-Any

Kismet is designed to allow any source to function as a remote capture, and to function cross-platform.  It is completely reasonable, for instance, to use an OpenWRT sensor running Linux to provide packets to a Kismet server running on OSX or Windows 10 under the WSL.

### Controlling access to remote capture

For security reasons, by default Kismet only remote sensor connections from the localhost IP (`127.0.0.1`).  To connect remote sensors, you must either:

1. Set up a tunnel from the remote sensor to your Kismet server, for example using SSH port forwarding.  This is very simple to do, and adds encryption transparently to the remote packet stream.  This can be done as simply as:
   ```bash
   # ssh someuser@192.168.1.2 -L 3501:localhost:3501
   ```
   This sets up a SSH tunnel from `localhost` port 3501 to `192.168.1.2` port 3501.  Then in a second terminal running the Kismet remote capture, using `localost:3501` as the destination:
   ```
   # /usr/local/bin/kismet_cap_linux_wifi --connect localhost:3501 --source=wlan1
   ```

   Other, more elegant solutions exist for building the SSH tunnel, such as `autossh` which can be used to automatically maintain the tunnel and start it on boot.

2.  Kismet can be configured to accept connections on a specific interface, or from all IP addresses, by changing the `remote_capture_listen=` line in `kismet.conf` or `kismet_site.conf` as an override.  To enable listening on ALL network interfaces:
   ```
   remote_capture_listen=0.0.0.0
   ```

   Or a single specific network interface:
   ```
   remote_capture_listen=192.168.1.2
   ```

   Remote capture *should only be enabled on interfaces on a protected LAN*.

### Additional remote capture options
Kismet capture tools also support the following options:

* `--connect=[host]:[port]`
   Connects to a remote Kismet server on [host] and port [port].  When using `--connect=...` you MUST specify a `--source=...` option

* `--source=[source definition]`
   Define a source; this is used only in remote connection mode.  The source definition is the same as defining a local source for Kismet via `-c` or the `source=` config file option.

* `--disable-retry`
   By default, a remote source will attempt to reconnect if the connection to the Kismet server is lost.

* `--daemonize`
   Places the capture tool in the background and daemonizes it.

* `--fixed-gps [lat,lon,alt] or [lat,lon]`
   Set the GPS location of the remote capture source; this will tag any packets from this source with a static, fixed GPS location.

* `--gps-name [name]`
   Rename the virtual GPS reported on this source; otherwise the capture name "fixed-remote" is used.

### Compiling Only the Capture Tools
Typically, you will want to compile all of Kismet.  If you're doing specific remote-capture installs, however, you may wish to compile only the binaries used by Kismet to enable capture mode and pass packets to a full Kismet server.

To compile ONLY the capture tools:

Tell configure to only configure the capture tools; this will allow you to configure without installing the server dependencies such as C++, microhttpd, protobuf-C++, etc.  You will still need to install dependencies such as protobuf-c, build-essentials, and similar:
```bash
$ ./configure --enable-capture-tools-only
```

Once configure has completed, compile the capture tools:
```bash
$ make datasources
```

You can now copy the compiled datasources to your target.

## Kismet Webserver
Kismet now integrates a webserver which serves the web-based UI and data to external clients.

**THE FIRST TIME YOU RUN KISMET**, it will generate a **RANDOM** password.  This password is stored in `~/.kismet/kismet_httpd.conf` which is in the home directory of **the user which started Kismet**.

You will need this password to log into Kismet for the first time.

The webserver is configured via the `kismet_httpd.conf` file.  These options may be included in the base kismet.conf file, but are broken out for clarity.  These options may be overridden in `kismet_site.conf` for pre-configured installs.

By default, Kismet does not run in SSL mode.  If you provide a certificate and key file in PEM format, Kismet supports standard SSL / HTTPS.  For more information on creating a SSL certificate, look at `README.SSL`

HTTP configuration options:

* `httpd_username=username`
   Set the username.  This is required for any actions which can change configuration (adding / removing data sources, changing server-side configuration data, downloading packet captures, etc).
   The default user is `kismet`, and by default, the `httpd_username=` and `httpd_password=` configuration options are stored in the users home directory, in `~/.kismet/kismet_httpd.conf`.

* `httpd_password=password`
   Set the password.  The first time you run Kismet, it will auto-generate a random password and store it in `~/.kismet/kismet_httpd.conf`.
   It is generally preferred to keep the username and password in the per-user configuration file, however they may also be set in the global config.
   If `httpd_username` or `httpd_password` is found in the global config, it is used instead of the per-user config value.

* `httpd_port=port`
   Sets the port for the webserver to listen to.  By default, this is port 2501, the port traditionally used by the Kismet client/server protocol.
   Kismet typically should not be started as root, so will not be able to bind to ports below 1024.  If you want to run Kismet on, for instance, port 80, this can be done with a proxy or a redirector, or via DNAT rewriting on the host.

* `httpd_ssl=true|false`
   Turn on SSL.  If this is turned on, you must provide a SSL certificate and key in PEM format with the `httpd_ssl_cert=` and `httpd_ssl_key=` configuration options.

   See README.SSL for more information about SSL certificates.

* `httpd_ssl_cert=/path/to/cert.pem`
   Path to a PEM-format SSL certificate.

   This option is ignored if Kismet is not running in SSL mode.

   Logformat escapes can be used in this.  Specifically, "%S" will automatically expand to the system install data directory, and "%h" will expand to the home directory of the user running Kismet:
   ```
   httpd_ssl_cert=%h/.kismet/kismet.pem
   ```

* `httpd_ssl_key=/path/to/key.pem`
   Path to a PEM-format SSL key file.  This file should not have a password set as currently Kismet does not have a password prompt system.

   This option is ignored if Kismet is not running in SSL mode.

   Logformat escapes can be used in this.  Specifically, "%S" will automatically expand to the system install data directory, and "%h" will expand to the home directory of the user running Kismet:
   ```
   httpd_ssl_key=%h/.kismet/kismet.key
   ```

* `httpd_home=/path/to/httpd/data`
   Path to static content web data to be served by Kismet.  This is typically set automatically to the directory installed by Kismet in the installation prefix.
   Typically the only reason to change this directory is to replace the Kismet web UI with alternate code.

* `httpd_user_home=/path/to/user/httpd/data`
   Path to static content stored in the home directory of the user running Kismet.  This is typically set to the httpd directory inside the users .kismet directory.

   This allows plugins installed to the user directory to install web UI components.

   Typically there is no reason to change this directory.

   If you wish to disable serving content from the user directory entirely, comment this configuration option out.

* `httpd_session_db=/path/to/session/db`
   Path to save HTTP sessions to.  This allows Kismet to remember valid browser login sessions over restarts of kismet_server. 

   If you want to refresh the logins (and require browsers to log in again after each restart), comment this option.

   Typically there is no reason to change this option.
   
* `httpd_mime=extension:mimetype`
   Kismet supports MIME types for most standard file formats, however if you are serving custom content with a MIME type not correctly set, additional MIME types can be defined here.
   Multiple httpd_mime lines may be used to add multiple mime types:
   ```
   httpd_mime=html:text/html
   httpd_mime=svg:image/svg+xml
   ```
   Typically, MIME types do not need to be added.


## GPS
Kismet can integrate with a GPS device to provide geolocation coordinates for devices.

GPS data is included in the log files, in PPI pcap files, and exported over the REST interface.
​    
Kismet can not use GPS to determine the absolute location of the device; it can only use it to determine the location of the receiver.  The location estimate of a device can be improved by circling the suspected location.
​    
In addition to logging GPS data on a per-packet basis, Kismet maintains a running average of device locations which are exported as the average location in the Kismet UI and in device summaries.  Because the running average can be heavily influenced by the sensors position, this running average may not be very accurate.

Multiple GPS devices can be defined at once, however only the highest priority active device is used.
​    
GPS is configured via the `gps=` configuration option.  GPS options are passed on the configuration line:
```
gps=type:option1=val1,option2=val2
```

### Supported GPS types
* serial (High priority)
   Locally-connected serial NMEA GPS device.  This supports most USB and Bluetooth (rfcomm/spp) connected GPS devices.  This does not support the few GPS devices which output proprietary binary

   Options:
   * `name=foo`
      Arbitrary name to identify this GPS
   * `device=path/to/device`
      Path to the serial device.  The user Kismet is running as must have read access to this device.
   * `reconnect=true | false`
      Automatically attempt to re-open the serial port if there is a problem or the GPS is not connected.
   * `baud=rate`
      Specify a non-standard baud rate for the serial port.  Most GPS devices operate at 4800, which Kismet uses by default.

   Example:
   ```
   gps=serial:device=/dev/ttyACM0,reconnect=true,name=LaptopSerial
   ```

* tcp (High priority)
   Network-connected raw NMEA stream.  Typically this is served by a smartphone app like "BlueNMEA" on Android or "NMEA GPS" on iPhone.  For GPSD-based network GPS connections, use the "gpsd" GPS in Kismet.

   Options:
   * `name=foo`
      Arbitrary name to identify this GPS
   * `host=ip-or-name`
      IP or hostname of the server running the NMEA TCP server
   * `port=port number`
      Port number the NMEA server is listening on
   * `reconnect=true | false`
      Automatically attempt to re-open the serial port if there is a problem or the GPS is not connected.

   Example:
   ```
   gps=tcp:host=10.10.100.100,port=3999
   ```

* gpsd (High priority)
   A GPSD server.  GPSD (http://www.catb.org/gpsd/) parses GPS data from multiple GPS vendors (including proprietary binary) and makes it available over a standard TCP/IP connection.

   There are multiple GPSD versions with various levels of support and incompatible protocols.  Kismet supports the older-style GPSD text protocol as well as the new GPSD3 JSON protocol.

   Options:
   * `name=foo`
      Arbitrary name to identify this GPS
   * `host=ip-or-name`
      IP or hostname of the server running the GPSD server
   * `port=port number`
      Port number the GPSD server is listening on; GPSD listens on port 2947 by default.
   * `reconnect=true | false`
      Automatically attempt to re-open the serial port if there is a problem or the GPS is not connected.

   Example:
   ```
   gps=gpsd:host=localhost,port=2947,reconnect=true
   ```

* web (Medium priority)
   A web-based client with a modern web browser and location hardware (such as a phone) can supply their GPS location.  This is only available to logged-in users on the Kismet web UI, but can turn a generic phone and web browser into a location source.

   Typically browsers cannot supply speed or other options, and the precision of this GPS source will be reduced because it may not be updated as frequently as a locally connected GPS.

   Options:
   * `name=foo`
      Arbitrary name to identify this GPS

* virtual (lowest priority)
   A virtual GPS always reports a static location.  The virtual gps injects location information on stationary sensor or drone.

   Options:
   * `name=foo`
      Arbitrary name to identify this GPS
   * `lat=coordinate`
      Latitude coordinate.
   * `lon=coordinate`
      Longitude coordinate.
   * `alt=altitude`
      Altitude, in meters.

   Example:
   ```
   gps=virtual:lat=123.4566,lon=40.002,alt=23.45
   ```

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




## SIEM support

Kismet is natively compatible with the Prelude SIEM event management system (https://www.prelude-siem.org) and can send Kismet alerts to Prelude.

To enable communication with a Prelude SIEM sensor, support must be enabled at compile time by adding --enable-prelude to any other options passed to the configure script:
```bash
$ ./configure --enable-prelude
```

## Integrated libraries

Kismet uses several libraries which are part of the Kismet source code; Without the open source community this wouldn't be possible.

* boost::geometry (https://www.boost.org):  Boost header-only geometry library
* boost::mpl (https://www.boost.org): Boost header-only MPL metaprogramming library
* fmtlib (https://github.com/fmtlib/fmt): C++ string formatting for faster message generation with fewer temporary variables.
* jsoncpp (http://jsoncpp.sourceforge.net/): JSON parser
* kaitai (https://kaitai.io): Binary parser generator and stream library
* microhttpd (https://www.gnu.org/software/libmicrohttpd/): Webserver
* nlohmann json (https://github.com/nlohmann/json): JSON sanitization
* radiotap (http://radiotap.org): Radiotap header definitions
* xxhash32 (https://github.com/Cyan4973/xxHash): Fast 32bit hashing algorithm

