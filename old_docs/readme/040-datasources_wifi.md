---
title: "Wi-Fi sources"
permalink: /docs/readme/datasources_wifi/
excerpt: "Wi-Fi (802.11) data sources"
toc: true
---

## Wi-Fi

### Wi-Fi Channels

Wi-Fi channels in Kismet define both the basic channel number, and extra channel attributes such as 802.11N 40MHz channels, 802.11AC 80MHz and 160MHz channels, and non-standard half and quarter rate channels at 10MHz and 5MHz.

Kismet will auto-detect the supported channels on most Wi-Fi cards.  Monitoring on HT40, VHT80, and VHT160 requires support from your card.

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

### Datasource: Linux Wi-Fi

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

### Supported Hardware

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

#### Linux Wi-Fi Source Parameters
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

#### Special Linux Wi-Fi Drivers
Some drivers require special behavior - whenever possible, Kismet will detect these drivers and "do the right thing".

* The rtl8812 and rtl8814 drivers (available at https://github.com/aircrack-ng/rtl8812au.git) support monitor mode, however they do not properly implement the mac80211 control layer; while they support creating VIFs for monitor mode, they do not actualy provide packets.  Kismet will detect the `8812au` and `8814` drivers and configure the base interface in monitor mode using legacy ioctls.
* The nexmon driver patches for Broadcom devices do not enter monitor mode normally; Kismet will detect the drivers and use the nexmon-custom ioctls.

### Data source: OSX Wifi
Kismet can use the built-in Wi-Fi on a Mac, but ONLY the built-in Wi-Fi; Unfortunately currently there appear to be no drivers for OSX for USB devices which support monitor mode.

Kismet uses the `kismet_cap_osx_corewlan_wifi` tool for capturing on OSX.

#### OSX Wi-fi Parameters

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

