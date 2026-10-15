# Morse Micro MM8108 USB 802.11ah (Wi-Fi HaLow) capture

A userspace libusb driver for MM8108 USB HaLow adapters (USB ID `325b:8100`), ported
from the Morse Micro Linux driver (https://github.com/MorseMicro/morse_driver, GPL-2.0)
and reduced to what's needed for monitor-mode capture. This will become a Kismet
datasource; for now it builds a standalone test tool.

## Layout

- `libmm8108/`: the driver
  - `mm_usb.c`: USB transport; chip memory access over bulk endpoints
  - `mm_hw.c`: registers, memory access restriction, chip ID, OTP, digital reset
  - `mm_fw.c`: firmware and BCF (board config) loading and boot
  - `mm_yaps.c`: YAPS, the frame and command transport through chip memory
  - `mm_cmd.c`: firmware commands
  - `mm_channels.c`: 802.11ah channel plans per region
  - `mm_radiotap.c`: radiotap with the S1G field and exact frequency
- `mm8108_halow_test.c`: boots the radio, enters monitor mode, hops channels, writes a
  pcap and prints packet counts

## Firmware

Firmware and BCF files are not included. They're distributed by Morse Micro under their
own license at https://github.com/MorseMicro/morse-firmware. Point `--fw-dir` at a checkout
of that repository or at a directory holding the files (`/lib/firmware/morse` by default).
The firmware is chosen by chip revision (`mm8108b2-rl.bin`) and the BCF by the board type
in the chip's OTP (`bcf_boardtype_XXXX.bin`).

## Usage

    make
    ./mm8108_halow_test --fw-dir ~/src/morse-firmware --info
    ./mm8108_halow_test --fw-dir ~/src/morse-firmware --pcap halow.pcap --dwell 500
    ./mm8108_halow_test --fw-dir ~/src/morse-firmware --channels 27,30 --duration 60

On Linux the tool detaches the `morse_usb` kernel driver if it's bound, and needs
permission to access the USB device.

## Status

Boot, commands, monitor mode and channel hopping work on an MM8108B2 adapter. Captured
frames haven't been verified yet because no HaLow network was in range during testing.
NDP frames are counted but not written to the pcap.
