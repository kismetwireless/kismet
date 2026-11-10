# Userspace USB Wi-Fi drivers

Linux USB Wi-Fi drivers built unmodified in userspace on libusb, for monitor-mode capture
on platforms with no kernel driver (macOS) or without kernel monitor support.  Imported
from Kismet's `capture_userspace_usb_wifi` as a standalone tool, `uwifi`.

All driver and shim code derived from the Linux kernel.

On macOS, these tools give you access to the wireless NIC for pcap capture and
basic transmit.  On Linux, they get you that - plus integration with
`mac80211_hwsim`, the Wi-Fi interface simulation layer, presenting a full Linux
wireless interface.

Why would you want such a thing?  For starters, some Wi-Fi drivers are pretty
crappy (looking at you, Realtek 88xx series).  This lets you jail them in
userspace where it's simpler to restart the service if it goes wrong.  The other
reason you might want this is because the Linux kernel can move pretty quickly,
and distributions don't.  If you're testing with some bleeding-edge Wi-Fi cards
which can be ported to this framework, you can continue running an older kernel
and load the new Wi-Fi code fully in userspace.

These drivers are bundled directly into Kismet in the `usbwifi` datasource.  If
all you want to do is monitor mode capture in Kismet, you're already covered!

## Building

Requires libusb-1.0 and pkg-config; libzstd and liblzma are used when present, to load
compressed linux-firmware.

    make
    sudo make install       # uwifi to $(PREFIX)/bin, firmware to $(PREFIX)/share/uwifi/firmware

## Usage

    ./uwifi list
    ./uwifi info
    ./uwifi info --probe-channels -b 6
    ./uwifi capture -b 2,5 -W 20,40,80 -t 250 -w capture.pcap
    ./uwifi capture -c 1,6,11,36VHT80,6g:37HE80 -T 60
    ./uwifi inject -c 6 -n 100 -i 20                  # broadcast probe requests
    ./uwifi inject -c 6 -a 00:11:22:33:44:55 -R 24    # unicast, at 24 Mbps, counting ACKs
    ./uwifi inject -c 36 -r frames.pcap               # replay an 802.11 or radiotap pcap

Channels use Kismet's notation (`6`, `6HT40+`, `36VHT80`); 6GHz channels take a `6g:`
prefix.  Firmware is searched in `--fw-dir`, `./firmware`, the install firmware directory,
Kismet's share directory, then on Linux the system firmware directories in the kernel's
search order (`firmware_class.path`, `/lib/firmware/updates`, `/lib/firmware`).  On Linux, run as root or give the user
access to the USB device; only the Wi-Fi interface is detached from the kernel driver,
which rebinds when `uwifi` exits.

## Transmit

Frames are injected as on a Linux monitor interface: a radiotap header and the 802.11
frame go through mac80211's monitor transmit path (`mac80211/tx.c`, ported from
`net/mac80211/tx.c`) into the driver's own `tx` op and USB transmit code.  Radiotap flags,
TX flags (no-ACK, no sequence number), legacy rate, HT MCS, VHT, data retries and antenna
are honoured as mac80211 honours them; whether the chip uses an injected rate is up to the
driver, as in the kernel.  Tested on air:


| Driver | Transmits | Injected rate | ACK in TX status |
|---|---|---|---|
| mt76x2u | yes | yes (legacy, MCS) | no: frames sent without a vif don't match a station entry |
| mt7921u, mt7925u | yes | no: the connac firmware picks the rate | no: retries, the firmware doesn't take ACKs in monitor mode |
| rtw88 (8814AU) | yes, 2.4 and 5GHz | no for management frames | yes |
| mm8108 | yes | yes (MCS and width from VHT) | no: the firmware's monitor interface doesn't take ACKs; frames sent through hwsim are acknowledged |


## Linux Wi-Fi device (mac80211_hwsim)

On Linux, `uwifi hwsim` turns an adapter into an ordinary kernel Wi-Fi interface.  It
creates a mac80211_hwsim radio with the adapter's MAC address and acts as its medium, as
wmediumd does: frames the kernel sends are transmitted by the adapter on the frame's
channel, and received frames are handed to the radio with their channel, rate and signal.
The adapter follows the radio's operating channel, so `iw`, wpa_supplicant and hostapd work
on it unchanged.

    sudo modprobe mac80211_hwsim radios=0
    sudo ./uwifi hwsim -d 0 -C US        # -N wiphy name, -T status interval in seconds

The radio is removed when `uwifi` exits.  The adapter also carries an unassociated station
interface with the radio's address so that it ACKs frames sent to it.

Until the radio is connected, the adapter also hops its channels on its own, and the latest
beacon and probe response of each BSS it hears are replayed to the radio, which keeps the
ones on the channel it is scanning: a passive scan, as on DFS channels, sends nothing to
follow.


| Driver | Scan | Connect (WPA2) and IP traffic |
|---|---|---|
| rtw88 (8814AU) | yes | yes |
| mt76x2u | yes | yes |
| mt7921u, mt7925u | yes | no: the firmware doesn't ACK frames in this mode, so authentication times out |
| mm8108 | yes (802.11ah, see below) | yes, WPA3-SAE |


## 802.11ah (HaLow): MM8108

mac80211 has no usable sub-GHz band (mac80211_hwsim can't carry S1G frames from a userspace
medium), so the MM8108 driver presents its 802.11ah channels as 5GHz channels, as Morse
Micro's own Linux driver does.  Each S1G channel maps to a 5GHz channel of 20 times the
width, nested the same way:


| S1G width | 5GHz width | US example |
|---|---|---|
| 1MHz | 20MHz | S1G 27 (915.5MHz) is 5GHz 112 |
| 2MHz | 40MHz | S1G 26 (915MHz) is 5GHz 110 |
| 4MHz | 80MHz | S1G 24 (914MHz) is 5GHz 106 |
| 8MHz | 160MHz | S1G 28 (916MHz) is 5GHz 114 |


`uwifi info`, `capture` and `hwsim` print the full table for the adapter's region when it
starts; channels the board config disables are marked.  The region is the one programmed in
the adapter, or US.  Tuning a 20MHz channel listens on its 1MHz channel as the primary of the
widest channel containing it, so wider BSSs with that primary are heard.

    ./uwifi capture -d 1 -b 5 -W 20 -w halow.pcap      # every 1MHz channel
    ./uwifi capture -d 1 -c 112,112VHT160              # S1G 27, then S1G 28 at 8MHz

Captured frames are 802.11ah frames as sent; the radiotap channel is the mapped 5GHz one.
Through `uwifi hwsim`, frames are converted to and from the 802.11n/ac frames mac80211
expects: S1G beacons become beacons, and beacons, probe and association responses gain HT,
VHT and WMM elements describing the BSS's mapped channel; probe and association requests
carry S1G capabilities instead of HT/VHT/HE.  Block ack setup is dropped, as S1G uses NDP
block acks.  `iw scan` then shows a HaLow AP on its mapped channel and width.

Firmware and board configs are in `firmware/morse/`, from Morse Micro's morse-firmware.
The firmware is the chip revision's (`mm8108b2-rl.bin`), or linux-firmware's
`mm8108.bin`; the board config is the one for the board type in the adapter's OTP.
Adapters without a known board type use the MM8108 reference board config
`bcf_mf15457.bin`, then the system's `bcf_default.bin`, with a warning.  Each is looked for
in the firmware directories under `morse/`, at the top, or in a morse-firmware checkout's
layout (`firmware/`, `bcf/morsemicro/`), then in the system directories under
`morsemicro/mm81x/v57/` and `morse/`.  `--firmware` and `--boardfile` choose other files by
name:

    ./uwifi info --boardfile bcf_mm8108_m20_us.bin
    ./uwifi hwsim -F ~/src/morse-firmware --firmware mm8108b2-rl.bin

## Layout

- `drivers/<driver>/`: Linux driver sources copied unmodified from the kernel; `UPSTREAM`
  records the commit.
- `drivers/<driver>_glue.c`: the few functions the vendored code needs from kernel files
  that aren't vendored.
- `kcompat/`: the Linux kernel API the drivers build against: header forwarders in
  `include/`, unmodified kernel wireless headers in `upstream/`, and the runtime (threads,
  timers, USB core on libusb, skb and page handling) in `src/`.
- `mac80211/`: a minimal mac80211.  Drivers register an `ieee80211_hw` as usual; received
  frames get radiotap built by mac80211's own code, and injected frames take mac80211's
  monitor transmit path.
- `common/`: driver-independent interface: listing and opening adapters, capabilities,
  channel specs and hop lists, pcap, firmware files.
- `tools/uwifi.c`: the command-line tool.
- `firmware/`: firmware from linux-firmware, redistributable under the included licenses.

## Drivers

| Driver | Source | Devices |
|---|---|---|
| mt7921u | Linux v7.3-rc7 mt76 | MediaTek MT7921AU (0e8d:7961) and the other mt7921u IDs |
| mt7925u | Linux v7.3-rc7 mt76 | MediaTek MT7925 (0e8d:7925, 0e8d:6639), Netgear A8500 (0846:9050) and A9000 (0846:9072) |
| mt76x2u | Linux v7.3-rc7 mt76 | MediaTek MT7612U / MT7632U, such as the ALFA AWUS036ACM |
| rtw88 USB | Linux v7.3-rc7 rtw88 plus two lwfinger/rtw88 fixes | RTL8812AU/8811AU, RTL8821AU, RTL8814AU, RTL8812BU/8822BU, RTL8812CU/8822CU, RTL8811CU/8821CU, RTL8723DU |
| mm8108 | Kismet's libmm8108 (from morse_driver), with mac80211 glue | Morse Micro MM8108 802.11ah (325b:8100) |


## Adding a driver

Copy the driver's kernel sources into `drivers/<name>/`, add them to the Makefile, and
build.  Missing kernel APIs show up as compile or link errors; add them to `kcompat` or
`mac80211` rather than editing the driver.

If you need a specific driver and aren't up for doing the port, let me know, I
may be able to add it quickly.
