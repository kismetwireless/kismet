# SPDX-License-Identifier: Apache-2.0
"""Two raw DIAG slices whose CRC32s collide must BOTH reach the kismetdb.

## The hazard

Kismet's packetchain de-duplicates packets by the CRC32 of the whole link frame
against the last 1024 packets (``packetchain.cc``). A DLT-147 raw DIAG slice is
unique by construction -- its header carries the stream offset -- but a CRC32
collision with an EARLIER, different slice would mark the later one ``duplicate``:

* with ``kis_log_duplicate_packets=false`` the later slice is not logged at all;
* with the default ``true`` the dedup path may copy the earlier packet's shared
  components over it, so the kismetdb logs the EARLIER bytes a second time.

Either way one DIAG frame is gone, no RawDiagDrop/RawDiagAbort row records it,
and the reader flags a gap (plus an overlap in the second case). On a
million-packet drive a collision is expected, so raw DIAG slices are exempt.

## What this file runs

The REAL ``kismet`` server with a celldiag ``replay=`` source. The replay is two
8 KiB frames, so the slicer (12 KiB cap, cut at the last 0x7E) makes exactly
two slices at offsets 0 and 8192. The second frame's last four bytes are FORGED
so the two slices' CRC32s are equal. The forge does not need the session id the
helper stamps into both headers: for equal-length messages
``crc32(a) ^ crc32(b)`` depends only on ``a ^ b``, and the session id is the
same in both, so it cancels. ``test_the_forge_collides_for_any_session_id``
pins that, and the kismetdb ``hash`` column proves the server saw the collision.
"""
from __future__ import annotations

import sqlite3
import sys
import struct
import time
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_celldiag_raw_abort_server import (  # noqa: E402
    _DEPS, HDR, IMEI, _await, _reader)
from test_celldiag_server_routes import KP_ROOT, SERVER  # noqa: E402
from test_graceful_close_server import LoggingKismetServer  # noqa: E402

FRAME = 8192          # > DIAG_RAWPKT_PAYLOAD_MAX / 2, so one frame per slice
HDR_LEN = 24

#: The raw-abort dependency map plus the packetchain the exemption lives in: a server older
#: than any of these measures code nobody compiled -- skip, naming the rebuild.
_DEPS_4839 = {**_DEPS, SERVER: (*_DEPS[SERVER], "packetchain.cc", "packet.h", "packet.cc")}


def _built_or_skip() -> None:
    for binary, deps in _DEPS_4839.items():
        if not binary.is_file():
            pytest.skip(f"no {binary.name} at {binary} -- build it in {KP_ROOT}")
        mtime = binary.stat().st_mtime
        stale = [d for d in deps if (KP_ROOT / d).stat().st_mtime > mtime]
        if stale:
            pytest.skip(f"{binary.name} is older than {', '.join(stale)} -- rebuild it")


def _slice(session: int, offset: int, payload: bytes) -> bytes:
    """A data slice exactly as diag_rawpkt.c builds it (version 1, flags 0)."""
    return HDR.pack(b"CDRH", 1, 0, HDR_LEN, session, offset) + payload


def _filler(seed: int, n: int) -> bytes:
    """n bytes with no 0x7E / 0x7D, so the only frame terminator is the one we add."""
    out = bytearray()
    x = seed
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        b = (x >> 16) & 0xFF
        if b not in (0x7E, 0x7D):
            out.append(b)
    return bytes(out)


def _forge4(prefix: bytes, suffix: bytes, target: int) -> bytes:
    """4 bytes X with crc32(prefix + X + suffix) == target. X enters the CRC
    affinely over GF(2), so solve the 32x32 system built from the unit vectors."""
    def g(x: int) -> int:
        return zlib.crc32(prefix + x.to_bytes(4, "little") + suffix) ^ target

    base = g(0)
    cols = [g(1 << i) ^ base for i in range(32)]     # L(e_i)
    basis: list[tuple[int, int]] = []
    for v, m in ((cols[i], 1 << i) for i in range(32)):
        for bv, bm in basis:
            if v ^ bv < v:
                v, m = v ^ bv, m ^ bm
        if v:
            basis.append((v, m))
            basis.sort(reverse=True)
    v, m = base, 0
    for bv, bm in basis:
        if v ^ bv < v:
            v, m = v ^ bv, m ^ bm
    assert v == 0, "CRC32 forge unsolvable -- 4 consecutive bytes always are"
    x = m.to_bytes(4, "little")
    assert zlib.crc32(prefix + x + suffix) == target
    return x


def _forge(f0: bytes, f1_prefix: bytes) -> bytes:
    """X such that slice(0, f0) and slice(FRAME, f1_prefix+X+7E) collide. The
    session id is arbitrary here: it cancels (module doc)."""
    session = 0x1234_5678_9ABC_DEF0
    return _forge4(_slice(session, FRAME, b"")[:HDR_LEN] + f1_prefix, b"\x7e",
                   zlib.crc32(_slice(session, 0, f0)))


def _collision_pair() -> tuple[bytes, bytes]:
    f0 = _filler(1, FRAME - 1) + b"\x7e"
    prefix = _filler(2, FRAME - 5)
    f1 = prefix + _forge(f0, prefix) + b"\x7e"
    assert len(f0) == len(f1) == FRAME and f0 != f1
    return f0, f1


def test_the_forge_collides_for_any_session_id():
    """The positive control for the server test: the two slices the helper will
    build collide whatever session id it stamps, and differ in content."""
    f0, f1 = _collision_pair()
    for session in (0, 1, 1_790_000_000_123_456_789, (1 << 64) - 1):
        a, b = _slice(session, 0, f0), _slice(session, FRAME, f1)
        assert a != b
        assert zlib.crc32(a) == zlib.crc32(b), hex(session)
    # ...and only because of the forge: the unforged neighbour does not collide.
    other = f1[:-5] + b"\x00\x00\x00\x00\x7e"
    assert zlib.crc32(_slice(7, 0, f0)) != zlib.crc32(_slice(7, FRAME, other))


def _slices(db: Path) -> list[tuple[int, bytes, int]]:
    """(offset, payload, hash) of every DLT-147 data slice."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT packet, hash FROM packets WHERE dlt = 147").fetchall()
    finally:
        con.close()
    out = []
    for blob, h in rows:
        blob = bytes(blob)
        _magic, _ver, flags, hlen, _session, offset = HDR.unpack_from(blob)
        if not flags & 0x02:                           # skip END
            out.append((offset, blob[hlen:], h))
    return sorted(out)


@pytest.mark.parametrize("log_dups", ["false", "true"])
def test_colliding_raw_slices_both_reach_the_kismetdb_with_their_own_bytes(
        tmp_path, log_dups):
    """``false`` makes the pre-fix loss deterministic (the "duplicate" is not
    logged); ``true`` is the shipped default the live drive ran with."""
    _built_or_skip()
    f0, f1 = _collision_pair()
    replay = tmp_path / "collide4839.hdlc"
    replay.write_bytes(f0 + f1)
    srcdef = (f"celldiag-{IMEI}:replay={replay},retry=false,stats_interval=0")
    with LoggingKismetServer(tmp_path, srcdef,
                             extra=(f"kis_log_duplicate_packets={log_dups}",)) as srv:
        _await(lambda: "END at offset" in srv.tail(20000), 30, "the replay's END", srv)
        time.sleep(2)                                  # let the db writer commit
    db = srv.kismetdb()

    got = _slices(db)
    # Pre-fix: [0] (the "duplicate" not logged) or [0, 0] (logged with the
    # first slice's bytes -- its header included, so its offset reads 0 too).
    assert [o for o, _p, _h in got] == [0, FRAME], [(o, len(p)) for o, p, _h in got]
    # The collision really happened inside the server: equal stored hashes.
    assert got[0][2] == got[1][2], [h for _o, _p, h in got]
    # ...and neither slice was lost or overwritten.
    assert got[0][1] == f0, "the first slice's bytes changed"
    assert got[1][1] == f1, "the second slice carries the FIRST slice's bytes"

    r = _reader("-i", db, "-o", tmp_path / "a.hdlc", "--strict")
    assert r.returncode == 0, (r.returncode, r.stderr)
    assert (tmp_path / "a.hdlc").read_bytes() == replay.read_bytes()


SESSION = 1_790_000_000_483_900_000   # pinned via CELLDIAG_RAWPKT_SESSION_ID
OTHER_DLT = 148                       # LINKTYPE_USER1: "some other phy's frame"


def _pcap(path: Path, frame: bytes, dlt: int) -> None:
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, dlt)
    rec = struct.pack("<IIII", 1_790_000_000, 0, len(frame), len(frame))
    path.write_bytes(hdr + rec + frame)


def test_a_raw_slice_colliding_with_another_sources_packet_is_not_a_duplicate(
        tmp_path, monkeypatch):
    """The other half of the exemption: a slice must not MATCH an earlier,
    non-exempt packet either. A pcapfile source replays one DLT-148 frame whose
    CRC32 equals the first slice's; only then is the celldiag replay added. Pre-
    fix (or with the match-loop check removed) the slice is a "duplicate" of that
    frame and, with kis_log_duplicate_packets=false, never reaches the db."""
    _built_or_skip()
    f0, f1 = _collision_pair()
    slice0 = _slice(SESSION, 0, f0)
    head = b"OTHERPHY" + bytes(range(64))
    other = head + _forge4(head, b"", zlib.crc32(slice0))
    assert zlib.crc32(other) == zlib.crc32(slice0) and other != slice0
    pcap = tmp_path / "other4839.pcap"
    _pcap(pcap, other, OTHER_DLT)
    replay = tmp_path / "collide4839.hdlc"
    replay.write_bytes(f0 + f1)
    monkeypatch.setenv("CELLDIAG_RAWPKT_SESSION_ID", str(SESSION))

    with LoggingKismetServer(tmp_path, f"{pcap}:type=pcapfile,name=other4839",
                             extra=("kis_log_duplicate_packets=false",
                                    f"helper_binary_path={KP_ROOT}")) as srv:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            rows = srv.get("datasource/all_sources.json")
            if any(r.get("kismet.datasource.num_packets", 0) >= 1 for r in rows):
                break
            time.sleep(0.25)
        else:
            raise AssertionError(f"the pcap frame never arrived\n{srv.tail(4000)}")
        status, _ = srv.post("datasource/add_source.cmd", {"definition": (
            f"celldiag-{IMEI}:replay={replay},retry=false,stats_interval=0")})
        assert status == 200
        _await(lambda: "END at offset" in srv.tail(40000), 30, "the replay's END", srv)
        time.sleep(2)
    db = srv.kismetdb()

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        others = [bytes(r[0]) for r in con.execute(
            "SELECT packet FROM packets WHERE dlt = ?", (OTHER_DLT,))]
    finally:
        con.close()
    assert others == [other], "the premise: the colliding frame is in the db"
    got = _slices(db)
    assert [o for o, _p, _h in got] == [0, FRAME], [(o, len(p)) for o, p, _h in got]
    assert got[0][1] == f0 and got[1][1] == f1
    # kismetdb stores the hash as a SIGNED 32-bit int.
    assert got[0][2] & 0xFFFFFFFF == zlib.crc32(other), "the premise: the server saw the collision"
