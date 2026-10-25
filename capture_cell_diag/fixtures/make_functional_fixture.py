#!/usr/bin/env python3
"""Generate the canned raw-HDLC replay fixture `standalone.mk check-native` replays.

    python3 fixtures/make_functional_fixture.py --out fixtures/functional.hdlc

Why this file exists
--------------------
Anyone should be able to run the tree's own proof and see it decode something
without access to a private capture collection. A fixture-backed test that
skips for lack of a capture proves nothing, so the tree carries its own.

This generator is committed beside the bytes it produces so the fixture is
auditable rather than opaque: a reader can see exactly which fields are set to
which values and regenerate the file, rather than trust 2 KB of binary.

The fixture is synthesised, not scrubbed
----------------------------------------
The bytes below were never emitted by a modem. Every identity in them is an
invented constant chosen for being *obviously* invented, so the fixture is
free of personal data by construction rather than by inspection. A scrubbed
real capture is only as clean as the scrubber's coverage; here there is
nothing to miss.

Concretely:
  * IMEI is stamped by the helper at replay time, not by this file, and
    check-native passes the all-zero synthetic IMEI 000000000000000.
  * PCI / EARFCN are round decimal placeholders (111, 222, 333, 444; EARFCN
    2600 and 900), not values copied off a real cell.
  * No GNSS record is present at all, so the fixture carries no coordinate.

What it emits
-------------
Four DIAG `0xB193` records (LTE ML1 Serving Cell Meas Response), subpacket
version 36 -- the SDX20 layout (Telit LM960 / Quectel EG18-NA):

  * it is a common layout in real captures, not an exotic corner;
  * its per-cell geometry is well grounded (F3 log pairing, concurrent AT
    readings, and a 3GPP TS 36.214 closure onto exact RB counts). A fixture built on an ungrounded layout
    would assert numbers nobody trusts;
  * single-cell records carry a decodable RSRP *and* RSRQ, so the expected
    output pins real decoded values rather than only an identity.

Four records, not one, and the count is structural rather than cosmetic. A
capture-format sniffer that classifies a stream as raw HDLC from its head
window commonly wants at least four `0x7E` delimiters there, so a three-frame
fixture can be refused as "not a DIAG capture" even though every frame in it is
CRC-valid. The leading idle flag byte (real DIAG streams open with one) plus
four frames clears that floor with margin. Do not trim this fixture to "one
record is enough to prove decode".

Framing
-------
Each record is a DIAG_LOG_F (opcode 0x10) frame, HDLC-escaped, CRC-16 tailed and
0x7E-terminated -- the same wire the C helper's `replay=` deframes:

    [0]      u8   0x10        cmd
    [1]      u8   0x00        pending
    [2:4]    u16  outer_len   == len(frame) - 4
    [4:6]    u16  inner_len   == outer_len (the redundant duplicate)
    [6:8]    u16  log_code
    [8:16]   u64  ts64
    [16:]         payload

Both length fields matter. A deframer may reject a frame whose `outer_len`
disagrees with its true length, and a fixture that gets this wrong decodes to
zero records while every byte still looks plausible -- the silent-empty
outcome check-native's replay exists to rule out.

The CRC is the reflected CRC-16-CCITT Qualcomm DIAG uses (poly 0x8408, register
seeded 0xFFFF, LSB-first, output XOR 0xFFFF). It is implemented inline, so this
generator runs on a bare python3 with no dependency at all.
"""
from __future__ import annotations

import argparse
import struct
import sys

# ── the DIAG CRC-16, inline (see the module docstring on why not imported) ────
_RPOLY = 0x8408
_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ _RPOLY if (_c & 1) else (_c >> 1)
    _CRC_TABLE.append(_c)


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc = _CRC_TABLE[b ^ (crc & 0xFF)] ^ (crc >> 8)
    return crc ^ 0xFFFF


def hdlc_escape(frame: bytes) -> bytes:
    """0x7D / 0x7E -> 0x7D + (byte XOR 0x20), the inverse of hdlc_unescape."""
    out = bytearray()
    for b in frame:
        if b in (0x7D, 0x7E):
            out.append(0x7D)
            out.append(b ^ 0x20)
        else:
            out.append(b)
    return bytes(out)


def log_f_frame(log_code: int, ts64: int, payload: bytes) -> bytes:
    """Wrap ``payload`` as a CRC-tailed, 0x7E-terminated DIAG_LOG_F frame."""
    inner = bytearray(b"\x10\x00\x00\x00\x00\x00")
    inner += struct.pack("<H", log_code)
    inner += struct.pack("<Q", ts64)
    inner += payload
    struct.pack_into("<H", inner, 2, len(inner) - 4)   # outer_len
    struct.pack_into("<H", inner, 4, len(inner) - 4)   # inner_len duplicate
    body = bytes(inner)
    return hdlc_escape(body + struct.pack("<H", crc16_ccitt(body))) + b"\x7e"


# ── the 0xB193 subpacket-version-36 payload ──────────────────────────────────
_B193_PAYLOAD_LEN = 528      # the fixed v36 payload size observed on SDX20
_SUBPACKET_ID = 25
_SUBPACKET_VERSION = 36
_RSRP_OFF, _RSRQ_OFF = 20, 36        # over the 8-byte carrier base
_RSRP_BASE, _RSRQ_BASE = -180.0, -30.0


def b193_v36(earfcn: int, pci: int, rsrp_dbm: float, rsrq_db: float,
             counter: int) -> bytes:
    """One single-cell v36 payload.

    Single-cell on purpose. The parser gates rsrp/rsrq to None on multi-cell
    v36 records -- the x16 scale was grounded only on single-cell ones -- so a
    multi-cell fixture would pin an expected output of `null` signal and prove
    less while looking like it proves more.
    """
    p = bytearray(_B193_PAYLOAD_LEN)
    p[0] = 1                                            # version
    p[1] = 1                                            # num_subpackets
    struct.pack_into("<H", p, 2, counter)               # outer counter
    p[4] = _SUBPACKET_ID
    p[5] = _SUBPACKET_VERSION
    struct.pack_into("<H", p, 6, _B193_PAYLOAD_LEN - 4)  # subpacket_size
    sp = 8
    struct.pack_into("<I", p, sp + 0, earfcn)           # u32, low 18 bits read
    struct.pack_into("<H", p, sp + 4, 1)                # num_cells
    struct.pack_into("<H", p, sp + 6, 2)                # num_rx_antennas
    cell = sp + 8                                       # carrier header is 8 B
    struct.pack_into("<I", p, cell + 0, pci)            # u32, low 9 bits read
    struct.pack_into("<H", p, cell + _RSRP_OFF, round((rsrp_dbm - _RSRP_BASE) * 16))
    struct.pack_into("<H", p, cell + _RSRQ_OFF, round((rsrq_db - _RSRQ_BASE) * 16))
    return bytes(p)


#: (earfcn, pci, rsrp_dbm, rsrq_db). Values are exact multiples of the 1/16 dB
#: quantum so the decode is bit-exact and the expected file needs no tolerance.
#: The spread is deliberate -- a fixture where every record decodes to the same
#: number cannot tell "the parser read the field" from "the parser read a
#: constant".
RECORDS = [
    (2600, 111, -85.00, -10.00),
    (2600, 222, -97.50, -12.50),
    (2600, 333, -105.25, -14.75),
    (900,  444, -70.75, -8.25),
]

#: Monotonic synthetic DIAG ticks. Arbitrary but FIXED, so the generator is
#: deterministic -- regenerating must produce a byte-identical file or the
#: round-trip test in tests/test_functional_fixture.py fails.
_TS0 = 1000
_COUNTER0 = 44084


def build() -> bytes:
    # Leading idle flag: real DIAG streams open with one, and it is also what
    # puts the delimiter count at 5 rather than 4 (see the module docstring).
    out = bytearray(b"\x7e")
    for i, (earfcn, pci, rsrp, rsrq) in enumerate(RECORDS):
        out += log_f_frame(
            0xB193, _TS0 + i,
            b193_v36(earfcn, pci, rsrp, rsrq, _COUNTER0 + i))
    return bytes(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="path to write the fixture to")
    args = ap.parse_args(argv)
    data = build()
    with open(args.out, "wb") as fh:
        fh.write(data)
    print(f"wrote {args.out}: {len(data)} bytes, {len(RECORDS)} records, "
          f"{data.count(0x7e)} delimiters", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
