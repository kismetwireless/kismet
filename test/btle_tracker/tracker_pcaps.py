# Test pcap (DLT 256, BTLE_RADIO) with BTLE location tracker advertisements.  Every address
# and payload is synthetic.  Usage: tracker_pcaps.py <outfile>
#
# Advertisers, all with random static addresses (TxAdd=1) and ADV_IND, every 2 s for 60 s:
#   c2:00:00:5a:fd:01  Samsung SmartTag, overmature offline (3), battery full, no UWB
#   c2:00:00:5a:fd:02  Samsung SmartTag, connected (5), battery low, UWB
#   c2:00:00:5a:fd:03  FD5A service data with a different frame id: not a SmartTag
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

def adv_ind(addr, advdata):
    adva = bytes.fromhex(addr.replace(":", ""))[::-1]
    pdu = bytes([0x40, len(adva) + len(advdata)]) + adva + advdata    # ADV_IND, TxAdd random
    crc = crc24(pdu)
    return struct.pack("<I", AA) + pdu + bytes([crc & 0xff, (crc >> 8) & 0xff, crc >> 16])

def btle_rf(signal, frame):
    # channel 37, signal valid, CRC checked and valid
    return struct.pack("<BbbBIH", 0, signal, 0, 0, 0, (1 << 1) | (1 << 10) | (1 << 11)) + frame

FLAGS = ad(0x01, b"\x06")
ADVERTISERS = [
    ("c2:00:00:5a:fd:01", FLAGS + smarttag(0x13, 0x0102, bytes.fromhex("1122334455667788"), 0x03)),
    ("c2:00:00:5a:fd:02", FLAGS + smarttag(0x15, 0x0a0b0c, bytes.fromhex("8877665544332211"), 0x05)),
    ("c2:00:00:5a:fd:03", FLAGS + smarttag(0x23, 0x0102, bytes.fromhex("1122334455667788"), 0x03)),
    ("c2:00:00:00:00:99", FLAGS + ad(0x09, b"tracker-test")),
]

def main():
    with open(sys.argv[1], "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 256))
        for n in range(30):
            for i, (addr, advdata) in enumerate(ADVERTISERS):
                # vary the signal so the repeated advertisements are not byte-identical
                pkt = btle_rf(-50 - (n % 10), adv_ind(addr, advdata))
                t = T0 + 2 * n
                f.write(struct.pack("<IIII", t, i * 1000, len(pkt), len(pkt)) + pkt)

main()
