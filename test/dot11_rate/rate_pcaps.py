#!/usr/bin/env python3
"""Writes radiotap and PPI pcaps covering every PHY rate decoder (dot11_phy_rate.cc) for the
cross-check against tshark: HT MCS 0-32 and unequal modulation, VHT widths/MCS/NSS/GI and a
two-user MU frame, HE widths and RUs/MCS/GI/NSTS/DCM, EHT with U-SIG widths/RUs/MCS/GI/NSS,
S1G widths/MCS/NSS/GI, legacy rates, a bad PLCP frame, and PPI 802.11n MAC+PHY.

Each frame is a QoS data frame between locally administered addresses.  Writes
<out>/rate_radiotap.pcap, <out>/rate_ppi.pcap, <out>/rate_ppi_ht40.pcap (HT40 frames only)
and <out>/rate_cases.tsv (frame, case name).

    python3 -I test/dot11_rate/rate_pcaps.py <out dir>
"""

import os
import struct
import sys

DLT_RADIOTAP = 127
DLT_PPI = 192

# QoS data, to DS, between 02: addresses
FRAME = (bytes([0x88, 0x01, 0x00, 0x00]) +
         bytes.fromhex("020000000001") + bytes.fromhex("020000000002") + bytes.fromhex("020000000003") +
         bytes([0x10, 0x00, 0x00, 0x00]) + bytes(16))

# Radiotap field bit: (align, size)
LAYOUT = {1: (1, 1), 2: (1, 1), 3: (2, 4), 5: (1, 1), 14: (2, 2), 19: (1, 3), 21: (2, 12), 23: (2, 12)}


def radiotap(fields, tlvs=()):
    """fields: list of (bit, bytes) in bit order; tlvs: list of (type, bytes)"""
    present = 0
    for bit, _ in fields:
        present |= 1 << bit
    if tlvs:
        present |= 1 << 28

    body = bytearray()
    base = 8
    for bit, data in fields:
        align, size = LAYOUT[bit]
        assert len(data) == size
        while (base + len(body)) % align:
            body.append(0)
        body += data

    if tlvs:
        while (base + len(body)) % 4:
            body.append(0)
        for t, data in tlvs:
            body += struct.pack("<HH", t, len(data)) + data + bytes((4 - len(data) % 4) % 4)

    hdr = struct.pack("<BBHI", 0, 0, base + len(body), present) + bytes(body)
    return hdr


def common_fields(freq=5180):
    # flags, channel, dBm signal
    return [(1, b"\0"), (3, struct.pack("<HH", freq, 0x0140)), (5, struct.pack("<b", -40))]


def with_rx(fields, rx_flags):
    out = [f for f in fields if f[0] < 14] + [(14, struct.pack("<H", rx_flags))] + [f for f in fields if f[0] > 14]
    return out


def ht_field(idx, bw40, sgi):
    known = 0x01 | 0x02 | 0x04
    flags = (1 if bw40 else 0) | (0x04 if sgi else 0)
    return (19, bytes([known, flags, idx]))


def vht_field(bw_code, users, sgi, group=0):
    known = 0x0004 | 0x0040 | 0x0080
    mcs_nss = bytes((m << 4) | n for m, n in users) + bytes(4 - len(users))
    return (21, struct.pack("<HBB", known, 0x04 if sgi else 0, bw_code) + mcs_nss + bytes([0, group]) + b"\0\0")


def he_field(code, mcs, gi, nsts, dcm=False):
    d1 = 0x0020 | 0x0040 | 0x4000
    d2 = 0x0002
    d3 = (mcs << 8) | (0x1000 if dcm else 0)
    d5 = code | (gi << 4)
    return (23, struct.pack("<HHHHHH", d1, d2, d3, 0, d5, nsts))


def eht_tlvs(bw_code, mcs, nss, gi, ru=None):
    known = 0x00000004 | (0x00400000 if ru is not None else 0)
    data = [gi << 7, ru if ru is not None else 0] + [0] * 7
    user = 0x02 | 0x04 | 0x10 | 0x80 | (mcs << 20) | ((nss - 1) << 24)
    eht = struct.pack("<I", known) + struct.pack("<9I", *data) + struct.pack("<I", user)
    usig = struct.pack("<III", 0x00000002 | (bw_code << 15), 0, 0)
    return [(33, usig), (34, eht)]


def s1g_tlv(bw_code, mcs, nss, sgi):
    known = 0x0001 | 0x0004 | 0x0008 | 0x0010 | 0x0020
    d1 = 2 | (0x20 if sgi else 0) | ((nss - 1) << 6) | (bw_code << 8) | (mcs << 12)
    return [(32, struct.pack("<HHH", known, d1, 0))]


def ppi(common_rate, macphy=None, mac=None):
    common = struct.pack("<HH", 2, 20) + struct.pack("<QHHHHBBbb", 0, 0, common_rate, 5180, 0x0140, 0, 0, -40, -95)
    fields = common
    if mac is not None:
        body = struct.pack("<IIBBBB", mac, 0, 0, 0, 0, 0)
        fields += struct.pack("<HH", 3, len(body)) + body
    if macphy is not None:
        flags, mcs = macphy
        body = struct.pack("<IIBBBB", flags, 0, 0, mcs, 0, 0) + bytes(8) + struct.pack("<HH", 0, 0) + bytes(8) + bytes(16)
        fields += struct.pack("<HH", 4, len(body)) + body
    return struct.pack("<BBHI", 0, 0, 8 + len(fields), 105) + fields


def write_pcap(path, dlt, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, dlt))
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)

    rt = []
    cases = []

    def add(name, hdr):
        rt.append(hdr + FRAME)
        cases.append(("radiotap", len(rt), name))

    for rate in (2, 4, 11, 12, 22, 108, 0x80 | 12):
        add("legacy %d" % rate, radiotap(common_fields()[:1] + [(2, bytes([rate]))] + common_fields()[1:]))

    for idx in list(range(0, 33)) + [33, 50, 76, 77]:
        for bw40 in (False, True):
            for sgi in (False, True):
                add("ht %d %d %d" % (idx, bw40, sgi), radiotap(common_fields() + [ht_field(idx, bw40, sgi)]))

    for bw_code in (0, 1, 2, 4, 5, 7, 11, 12, 14, 18, 26):
        for mcs in range(0, 12):
            for nss in (1, 2, 3, 4, 8):
                for sgi in (False, True):
                    add("vht %d %d %d %d" % (bw_code, mcs, nss, sgi),
                        radiotap(common_fields() + [vht_field(bw_code, [(mcs, nss)], sgi)]))
    add("vht mu", radiotap(common_fields() + [vht_field(4, [(5, 1), (7, 2)], False, 5)]))

    for code in range(0, 12):
        for mcs in range(0, 12):
            for gi in range(0, 4):
                for nsts in (1, 2, 4):
                    add("he %d %d %d %d" % (code, mcs, gi, nsts), radiotap(common_fields() + [he_field(code, mcs, gi, nsts)]))
        add("he dcm %d" % code, radiotap(common_fields() + [he_field(code, 1, 0, 1, True)]))

    for bw_code in range(0, 6):
        for mcs in list(range(0, 14)) + [14, 15]:
            for nss in (1, 2):
                for gi in range(0, 3):
                    add("eht %d %d %d %d" % (bw_code, mcs, nss, gi), radiotap(common_fields(), eht_tlvs(bw_code, mcs, nss, gi)))
    for ru in range(0, 16):
        add("eht ru %d" % ru, radiotap(common_fields(), eht_tlvs(4, 7, 1, 0, ru)))

    for bw_code in range(0, 5):
        for mcs in range(0, 11):
            for nss in (1, 2):
                for sgi in (False, True):
                    add("s1g %d %d %d %d" % (bw_code, mcs, nss, sgi),
                        radiotap(common_fields(freq=5745), s1g_tlv(bw_code, mcs, nss, sgi)))

    add("badplcp ht", radiotap(with_rx(common_fields() + [ht_field(7, False, False)], 0x0002)))
    # A rate field of 0 is no legacy rate
    for rate in (0, 0x80):
        add("rate %d ht" % rate, radiotap(common_fields()[:1] + [(2, bytes([rate]))] + common_fields()[1:] +
                                         [ht_field(7, False, False)]))

    pp = []
    for flags in (0, 2, 4, 6, 1):
        for mcs in list(range(0, 33)) + [255]:
            pp.append(ppi(0, (flags, mcs)) + FRAME)
            cases.append(("ppi", len(pp), "ppi11n %d %d" % (flags, mcs)))
    for rate in (2, 12, 108):
        pp.append(ppi(rate) + FRAME)
        cases.append(("ppi", len(pp), "ppi legacy %d" % rate))
    # 802.11n MAC without MAC+PHY: HT without a rate, not the common legacy rate
    for flags in (0, 2):
        for rate in (0, 12):
            pp.append(ppi(rate, mac=flags) + FRAME)
            cases.append(("ppi", len(pp), "ppi11n mac %d %d" % (flags, rate)))

    write_pcap(os.path.join(out, "rate_radiotap.pcap"), DLT_RADIOTAP, rt)
    write_pcap(os.path.join(out, "rate_ppi.pcap"), DLT_PPI, pp)
    # HT40 frames only, for the device's carrier set
    write_pcap(os.path.join(out, "rate_ppi_ht40.pcap"), DLT_PPI,
               [ppi(0, (flags, mcs)) + FRAME for flags in (2, 6) for mcs in range(0, 16)])
    with open(os.path.join(out, "rate_cases.tsv"), "w") as f:
        for kind, n, name in cases:
            f.write("%s\t%d\t%s\n" % (kind, n, name))

    print("rate_pcaps: %d radiotap, %d PPI frames" % (len(rt), len(pp)))


if __name__ == "__main__":
    main()
