# Test pcap (DLT 256, BTLE_RADIO) with BTLE location tracker advertisements.  Every address
# and payload is synthetic.  Usage: tracker_pcaps.py <outfile>
#
# Advertisers, all with random static addresses (TxAdd=1) and ADV_IND, every 2 s for 60 s:
#   c2:00:00:5a:fd:01  Samsung SmartTag, overmature offline (3), battery full, no UWB
#   c2:00:00:5a:fd:02  Samsung SmartTag, connected (5), battery low, UWB
#   c2:00:00:5a:fd:03  FD5A service data with a different frame id: not a SmartTag
#   c2:00:00:4c:00:01  Apple Find My, AirTag, separated frame, battery medium
#   c2:00:00:4c:00:02  Apple Find My, AirPods, near-owner frame, battery full
#   c2:00:00:4c:00:03  Apple Find My frame from an Apple device (type 0): not a tracker
#   c2:00:00:aa:fe:01  Google FMDN, unwanted tracking protection mode, 160-bit, hashed flags
#   c2:00:00:aa:fe:02  Eddystone UID frame in FEAA: not FMDN
#   c2:00:00:b2:fc:01  DULT only, separated, network ID 7, proprietary payload
#   c2:00:00:b2:fc:02  Google FMDN (normal) and DULT (separated, network ID 2) in turns
#   c2:00:00:00:00:99  plain advertiser with a name and no service data
import struct, sys

AA = 0x8E89BED6
T0 = 1_790_000_000

def crc24(data, init=0xAAAAAA):
    """BLE CRC, reflected LFSR as in kis_btle_phy::ble_crc24"""
    lfsr = init & 0xFFFFFF
    for b in data:
        for _ in range(8):
            bit = (b ^ lfsr) & 1
            lfsr >>= 1
            b >>= 1
            if bit:
                lfsr ^= 0xDA6000
    return lfsr

def ad(t, body): return bytes([len(body) + 1, t]) + body

def smarttag(byte0, aging, privacy_id, flags):
    payload = bytes([byte0]) + struct.pack("<I", aging)[:3] + privacy_id + bytes([flags])
    payload += bytes(3) + bytes.fromhex("a1b2c3d4")
    assert len(payload) == 20
    return ad(0x16, struct.pack("<H", 0xFD5A) + payload)

def findmy(separated, status):
    if separated:
        frame = bytes([0x12, 0x19, status]) + bytes(range(0xa0, 0xa0 + 22)) + b"\x02\x00"
    else:
        frame = bytes([0x12, 0x02, status, 0x01])
    return ad(0xFF, struct.pack("<H", 0x004C) + frame)

def fmdn(frame, eid_len, flags):
    payload = bytes([frame]) + bytes(range(0x10, 0x10 + eid_len)) + (b"\x5c" if flags else b"")
    return ad(0x16, struct.pack("<H", 0xFEAA) + payload)

def dult(network_id, status, extra):
    return ad(0x16, struct.pack("<H", 0xFCB2) + bytes([network_id, status]) + extra)

def adv_ind(addr, advdata):
    assert len(advdata) <= 31
    adva = bytes.fromhex(addr.replace(":", ""))[::-1]
    pdu = bytes([0x40, len(adva) + len(advdata)]) + adva + advdata    # ADV_IND, TxAdd random
    crc = crc24(pdu)
    return struct.pack("<I", AA) + pdu + bytes([crc & 0xff, (crc >> 8) & 0xff, crc >> 16])

def btle_rf(signal, frame):
    # channel 37, signal valid, CRC checked and valid
    return struct.pack("<BbbBIH", 0, signal, 0, 0, 0, (1 << 1) | (1 << 10) | (1 << 11)) + frame

FLAGS = ad(0x01, b"\x06")
EDDYSTONE_UID = ad(0x16, struct.pack("<H", 0xFEAA) + b"\x00\xee" + bytes(range(16)) + b"\x00\x00")

# Each advertiser cycles through its advertisements, one per round
ADVERTISERS = [
    ("c2:00:00:5a:fd:01", [FLAGS + smarttag(0x13, 0x0102, bytes.fromhex("1122334455667788"), 0x03)]),
    ("c2:00:00:5a:fd:02", [FLAGS + smarttag(0x15, 0x0a0b0c, bytes.fromhex("8877665544332211"), 0x05)]),
    ("c2:00:00:5a:fd:03", [FLAGS + smarttag(0x23, 0x0102, bytes.fromhex("1122334455667788"), 0x03)]),
    ("c2:00:00:4c:00:01", [findmy(True, 0x50)]),
    ("c2:00:00:4c:00:02", [FLAGS + findmy(False, 0x30)]),
    ("c2:00:00:4c:00:03", [findmy(True, 0x00)]),
    ("c2:00:00:aa:fe:01", [FLAGS + fmdn(0x41, 20, True)]),
    ("c2:00:00:aa:fe:02", [FLAGS + EDDYSTONE_UID]),
    ("c2:00:00:b2:fc:01", [FLAGS + dult(0x07, 0x00, bytes.fromhex("01020304"))]),
    ("c2:00:00:b2:fc:02", [FLAGS + fmdn(0x40, 20, False), FLAGS + dult(0x02, 0x00, b"")]),
    ("c2:00:00:00:00:99", [FLAGS + ad(0x09, b"tracker-test")]),
]

def main():
    with open(sys.argv[1], "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 256))
        for n in range(30):
            for i, (addr, advs) in enumerate(ADVERTISERS):
                # vary the signal so the repeated advertisements are not byte-identical
                pkt = btle_rf(-50 - (n % 10), adv_ind(addr, advs[n % len(advs)]))
                t = T0 + 2 * n
                f.write(struct.pack("<IIII", t, i * 1000, len(pkt), len(pkt)) + pkt)

main()
