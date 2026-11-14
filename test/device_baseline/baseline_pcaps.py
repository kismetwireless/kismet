#!/usr/bin/env python3
# Test capture (DLT 105, no radiotap) for the baseline filters.  Addresses are locally
# administered or in the documentation block 00:00:5e:00:53:xx; nothing real.
#
#   AP1 02:00:00:00:b1:01  sends DEAUTHCODEINVALID (EXPLOIT) and BCASTDISCON (DENIAL)
#   AP2 02:00:00:00:b1:02  sends LONGSSID (EXPLOIT)
#   AP3 02:00:00:00:b1:03  no alerts
#   AP4 02:00:00:00:b1:04  sends only BCASTDISCON (DENIAL)
#   CL  00:00:5e:00:53:99  probes; named by AP1's deauth, sends nothing that alerts
#   R1  06:00:00:00:c1:20  randomized address, a few probes
#   R2  06:00:00:00:c1:21  randomized address, a few probes
#
# Usage: baseline_pcaps.py out.pcap

import struct
import sys
import time


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


BC = mac("ff:ff:ff:ff:ff:ff")
AP1, AP2, AP3, AP4 = (mac("02:00:00:00:b1:0%d" % i) for i in (1, 2, 3, 4))
CL = mac("00:00:5e:00:53:99")
R1 = mac("06:00:00:00:c1:20")
R2 = mac("06:00:00:00:c1:21")
RATES = b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
# Recent enough that the devices are current, old enough that one-off-random's
# idle test passes at once
T0 = int(time.time()) - 30


def hdr(fc, a1, a2, a3, seq):
    return struct.pack("<BBH", fc, 0, 0) + a1 + a2 + a3 + struct.pack("<H", (seq & 0xfff) << 4)


def beacon(ap, ssid, seq):
    return (hdr(0x80, BC, ap, ap, seq) + struct.pack("<QHH", seq * 102400, 100, 0x0411) +
            b"\x00" + bytes([len(ssid)]) + ssid + RATES + b"\x03\x01\x06")


def probe_req(src, seq):
    return hdr(0x40, BC, src, BC, seq) + b"\x00\x00" + RATES


def deauth(src, dst, reason, seq):
    return hdr(0xc0, dst, src, src, seq) + struct.pack("<H", reason)


frames = []
t = 0
for i in range(20):
    frames.append((t, beacon(AP1, b"baselinetest-one", i)))
    frames.append((t + 1000, beacon(AP3, b"baselinetest-three", i)))
    frames.append((t + 1500, beacon(AP4, b"baselinetest-four", i)))
    frames.append((t + 2000, probe_req(CL, i)))
    if i < 3:
        frames.append((t + 2500, probe_req(R1, i)))
        frames.append((t + 3000, probe_req(R2, i)))
    t += 102400
for i in range(5):
    frames.append((t, beacon(AP2, b"A" * 40, i)))
    t += 102400
# An invalid reason code (EXPLOIT), then broadcast disconnects (DENIAL)
frames.append((t, deauth(AP1, CL, 99, 100)))
t += 102400
frames.append((t, deauth(AP1, BC, 3, 101)))
t += 102400
frames.append((t, deauth(AP4, BC, 3, 102)))
t += 102400
for i in range(20, 30):
    frames.append((t, beacon(AP1, b"baselinetest-one", i)))
    frames.append((t + 1000, beacon(AP3, b"baselinetest-three", i)))
    frames.append((t + 1500, beacon(AP4, b"baselinetest-four", i)))
    t += 102400

with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
    for us, fr in frames:
        f.write(struct.pack("<IIII", T0 + us // 1_000_000, us % 1_000_000, len(fr), len(fr)) + fr)
