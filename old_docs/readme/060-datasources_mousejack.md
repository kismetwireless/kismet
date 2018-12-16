---
title: "nRF Mousejack sources"
permalink: /docs/readme/datasources_nrf_mousejack/
excerpt: "nRF Mosuejack based sources"
toc: true
---

## Mousejack / nRF

The NordicRF nRF chip is a common chip used in wireless keyboards, mice, and presentation tools, which are frequently found in non-Bluetooth wireless input devices.

The Mousejack firmware developed by Bastille (https://www.mousejack.com/) runs on a number of commodity USB nRF devices (such as the Sparkfun nRF and the CrazyPA).

### Datasource - nRF Mousejack

Kismet must be compiled with support for libusb to use Mousejack; you will need `libusb-1.0-dev` (or the equivalent for your distribution), and you will need to make sure that the `nRF Mousejack` option is enabled in the output from `./configure`.

To use the mousejack capture, you must have a supported nRF USB device; this includes any device listed on the Bastille Mousejack site, including:
- CrazyRadio PA USB dongle
- SparkFun nRF24LU1+ breakout board
- Logitech Unifying dongle (model C-U0007, Nordic Semiconductor based)

You will need to flash your device with the Bastille Mousejack firmware; the firmware is available at [https://github.com/BastilleResearch/mousejack](https://github.com/bastilleresearch/mousejack) by following the instructions in the [Mousejack README](https://github.com/BastilleResearch/mousejack/blob/master/readme.md).

#### Mousejack interfaces

Mousejack datasources in Kismet can be referred to as simply `mousejack`:

```bash
$ kismet -c mousejack
```

When using multiple Mousejack radios, they can be specified by their location in the USB bus; this can be detected automatically by Kismet as a supported interface in the web UI, or specified manually.  To find the location on the USB bus, look at the output of the command `lsusb`:

```bash
$ lsusb
...
Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 003 Device 008: ID 1915:0102 Nordic Semiconductor ASA 
Bus 003 Device 010: ID 1915:0102 Nordic Semiconductor ASA 
...
```

In this instance the first device is on `bus 003` and `device 008` and the second device is on `bus 003` and `device 010`; we can specify this specific first device in Kismet by using:

```bash
$ kismet -c mousejack-3-8
```

#### Channel Hopping

The nRF protocol as used by Mousejack covers 82 channels, each 1MHz wide.

To cover this spectrum rapidly, it is recommended that you increase the hop rate for nRF interfaces:

```bash
$ kismet -c mousejack-3-8:hop_rate=100/sec
```

This can also be specified in the `kismet.conf` or `kismet_site.conf` config files:

```
source=mousejack:name=nRF,hop_rate=100/sec
```


