# SPDX-License-Identifier: Apache-2.0
"""``kismetdb_to_hdlc`` rebuilds a celldiag stream from the kismetdb ``packets``
table: the parse side of the DLT-147 slices celldiag emits
(``capture_cell_diag/diag_rawpkt.h``).

Each packet is a 24-byte ``CDRH`` header (version, flags, header_len,
session_id, offset) and then a slice of the stream as read from the port. For
one (datasource, session), the slices sorted by ``offset`` and concatenated are
the stream, byte for byte the same as a ``rawlog=`` tee. So the fixtures
check two things:

* Nothing but ``offset`` orders the output. Kismet inserts rows from random
  worker threads and overwrites a remote source's timestamps. So the fixtures
  insert rows shuffled, with timestamps that run BACKWARDS against the offsets.
* Every integrity problem the offsets can reveal is reported, and ``--strict``
  refuses it. That covers gaps (dropped slices), overlaps, malformed or
  truncated rows, and unflagged slices that do not end on a frame.

The last test replays a stream through the REAL emitter over the datasource
IPC harness and reads its packets back, which pins the contract end to end.
"""
from __future__ import annotations

import json
import random
import sqlite3
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

_KP = Path(__file__).resolve().parents[2]
_READER = _KP / "log_tools" / "kismetdb_to_hdlc"
_SOURCE = _KP / "log_tools" / "kismetdb_to_hdlc.cc"

DLT = 147
HDR = struct.Struct("<4sBBHQQ")        # magic, version, flags, header_len, session, offset
FRAGMENT = 0x01
END = 0x02                             # empty payload, offset = final length
SESSION = 1_790_028_000_123_456_789    # CLOCK_REALTIME ns at stream start
SESSION2 = 1_790_031_600_000_000_001   # an hour later: the source reopened

#: Placeholder IMEIs that cannot be mistaken for devices: any other Luhn-valid
#: 15 digits reads as a real device.
NAME_A = "celldiag-123456789012345"
NAME_B = "celldiag-000000000000000"
UUID_A = "00000000-0000-0000-0000-00000000000a"
UUID_B = "00000000-0000-0000-0000-00000000000b"
UUID_WIFI = "00000000-0000-0000-0000-00000000f1f1"
UUID_OTHER = "00000000-0000-0000-0000-0000000000ee"


def _reader_or_skip() -> str:
    if not _READER.exists():
        pytest.skip(f"{_READER} not built (make log_tools/kismetdb_to_hdlc)")
    if _SOURCE.stat().st_mtime > _READER.stat().st_mtime:
        pytest.fail(f"{_READER} is STALE (older than {_SOURCE.name}); rebuild: "
                    f"(cd {_KP} && make log_tools/kismetdb_to_hdlc)")
    return str(_READER)


def _utc(session: int) -> str:
    return datetime.fromtimestamp(session // 10**9, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stream(seed: int, n_frames: int = 60) -> bytes:
    """Raw HDLC: 0x7E-terminated frames with NULs and escaped bytes, so any
    text-based blob handling, lost slice, or leftover header shows up."""
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(n_frames):
        body = bytes(rng.choice([b for b in range(256) if b != 0x7E])
                     for _ in range(rng.randrange(3, 60)))
        out += b"\x00" + body + b"\x7d\x5e\x7d\x5d\x7e"
    return bytes(out)


def _slices(stream: bytes, seed: int) -> list[tuple[int, int, bytes]]:
    """Cut the stream the way the emitter does: whole frames per slice, each
    ending right after a 0x7E. Returns (offset, flags, payload)."""
    rng = random.Random(seed)
    ends = [i + 1 for i, b in enumerate(stream) if b == 0x7E]
    out, start, k = [], 0, 0
    while k < len(ends):
        k = min(len(ends), k + rng.randrange(1, 5))
        out.append((start, 0, stream[start:ends[k - 1]]))
        start = ends[k - 1]
    assert start == len(stream), "the fixture stream must end on a frame"
    return out


def _pkt(session, offset, payload, *, flags=0, version=1, magic=b"CDRH", extra=b""):
    return HDR.pack(magic, version, flags, HDR.size + len(extra), session, offset) \
        + extra + payload


def _new_db(path: Path, data_table: bool = True) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    if data_table:
        # kis_databaselogfile.cc's `data` table, where RawDiagDrop rows land.
        db.execute("CREATE TABLE data (ts_sec INT, ts_usec INT, phyname TEXT, "
                   "devmac TEXT, lat REAL, lon REAL, alt REAL, speed REAL, "
                   "heading REAL, datasource TEXT, type TEXT, json BLOB, signal INT)")
    db.execute("CREATE TABLE KISMET (kismet_version TEXT, db_version INT, "
               "db_module TEXT)")
    db.execute("INSERT INTO KISMET VALUES ('2026.09.0', 10, 'kismetlog')")
    db.execute("CREATE TABLE datasources (uuid TEXT, typestring TEXT, "
               "definition TEXT, name TEXT, interface TEXT, json BLOB, "
               "UNIQUE(uuid) ON CONFLICT REPLACE)")
    db.execute("CREATE TABLE packets (ts_sec INT, ts_usec INT, phyname TEXT, "
               "sourcemac TEXT, destmac TEXT, transmac TEXT, frequency REAL, "
               "devkey TEXT, lat REAL, lon REAL, alt REAL, speed REAL, "
               "heading REAL, packet_len INT, signal INT, datasource TEXT, "
               "dlt INT, packet BLOB, error INT, tags TEXT, datarate REAL, "
               "hash INT, packetid INT, packet_full_len INT)")
    return db


def _add_source(db, uuid, typestring, name, rawlog=None):
    definition = name + (f":diagport=/dev/ttyUSB0,rawlog={rawlog}" if rawlog else "")
    db.execute("INSERT INTO datasources VALUES (?,?,?,?,?,?)",
               (uuid, typestring, definition, name, name, b"{}"))


def _rows(uuid, packets, *, dlt=DLT, full_len=None):
    """(ts_sec, ts_usec, uuid, dlt, blob, full_len) per packet. The timestamps
    run BACKWARDS against the send order: a reader that trusted them would
    reverse the stream."""
    n = len(packets)
    return [(1790028000 + (n - i), 0, uuid, dlt, p,
             len(p) if full_len is None else full_len(i, p))
            for i, p in enumerate(packets)]


def _insert(db, rows, seed=None):
    """With a seed the rows go in shuffled, so rowid is not send order either."""
    rows = list(rows)
    if seed is not None:
        random.Random(seed).shuffle(rows)
    for n, (s, us, uuid, dlt, blob, full) in enumerate(rows):
        db.execute("INSERT INTO packets (ts_sec, ts_usec, phyname, datasource, "
                   "dlt, packet, packet_len, packet_full_len, error, packetid) "
                   "VALUES (?,?,?,?,?,?,?,?,0,?)",
                   (s, us, "unknown", uuid, dlt, blob, len(blob), full, n + 1))


def _db_with(tmp_path, *sources, rows, seed=None, drops=(), aborts=(), data_table=True) -> Path:
    """`drops` / `aborts`: (datasource uuid, json text) RawDiagDrop / RawDiagAbort
    rows for the data table."""
    path = tmp_path / "d.kismet"
    db = _new_db(path, data_table=data_table)
    for src in sources:
        _add_source(db, *src)
    _insert(db, rows, seed=seed)
    for uuid, js in drops:
        db.execute("INSERT INTO data (ts_sec, ts_usec, phyname, datasource, type, json) "
                   "VALUES (1790028000, 0, 'unknown', ?, 'RawDiagDrop', ?)",
                   (uuid, js.encode()))
    for uuid, js in aborts:
        db.execute("INSERT INTO data (ts_sec, ts_usec, phyname, datasource, type, json) "
                   "VALUES (1790028000, 0, 'unknown', ?, 'RawDiagAbort', ?)",
                   (uuid, js.encode()))
    db.commit()
    db.close()
    return path


def _packets(stream, seed, session=SESSION):
    return [_pkt(session, off, pl, flags=fl) for off, fl, pl in _slices(stream, seed)]


def _end(session, offset):
    """The END slice: empty, at the stream's final length."""
    return _pkt(session, offset, b"", flags=END)


def _drop(session, offset, length, schema="raw-diag-drop/1"):
    """A RawDiagDrop row's JSON, as diag_rawpkt_drop_json() writes it."""
    return (f'{{"schema":"{schema}","session_id":{session},'
            f'"first_drop_offset":{offset},"first_drop_len":{length}}}')


def _abort(session, delivered_end, slices, reason="IPC connection closed",
           schema="raw-diag-abort/1"):
    """A RawDiagAbort row's JSON, as the celldiag datasource's
    witness_raw_abort() writes it when a source dies mid-session."""
    return (f'{{"schema":"{schema}","session_id":{session},'
            f'"delivered_end":{delivered_end},"slices":{slices},"reason":"{reason}"}}')


def _run(args):
    return subprocess.run([_reader_or_skip(), *map(str, args)],
                          capture_output=True, timeout=60)


# --------------------------------------------------------------------------
# The core guarantee: offset order, header stripped, byte-identical
# --------------------------------------------------------------------------

def test_one_session_reassembles_byte_for_byte_by_offset_alone(tmp_path):
    stream = _stream(1)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 2)), seed=3)
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == stream


def test_a_longer_v1_header_is_skipped_by_its_header_len(tmp_path):
    """header_len exists so a later v1 may append fields; the payload starts
    after header_len bytes, not after 24."""
    stream = _stream(4)
    pkts = [_pkt(SESSION, off, pl, extra=b"\xee" * 8) for off, _, pl in _slices(stream, 5)]
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), rows=_rows(UUID_A, pkts), seed=6)
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == stream


def test_dir_mode_writes_one_file_per_modem_named_like_a_rawlog_tee(tmp_path):
    sa, sb = _stream(10), _stream(11)
    kdb = _db_with(tmp_path,
                   (UUID_A, "celldiag", NAME_A), (UUID_B, "celldiag", NAME_B),
                   (UUID_WIFI, "linuxwifi", "wlan1"),
                   # DLT 147 is the private-use range: another plugin may use it,
                   # even with a header that parses. Only celldiag's are DIAG.
                   (UUID_OTHER, "otherplugin", "other0"),
                   rows=(_rows(UUID_A, _packets(sa, 12)) +
                         _rows(UUID_B, _packets(sb, 13, session=SESSION2)) +
                         _rows(UUID_WIFI, [b"\x80\x00wifi-beacon"] * 7, dlt=127) +
                         _rows(UUID_OTHER, [_pkt(SESSION, 0, b"\x01\x7e")])),
                   seed=14)
    outdir = tmp_path / "out"
    outdir.mkdir()
    r = _run(["-i", kdb, "-O", outdir, "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    fa = f"{NAME_A}-{_utc(SESSION)}.hdlc"
    fb = f"{NAME_B}-{_utc(SESSION2)}.hdlc"
    assert sorted(p.name for p in outdir.iterdir()) == sorted([fa, fb])
    assert (outdir / fa).read_bytes() == sa
    assert (outdir / fb).read_bytes() == sb


def test_a_reopened_source_is_two_streams(tmp_path):
    s1, s2 = _stream(20), _stream(21)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(s1, 22) + _packets(s2, 23, session=SESSION2)),
                   seed=24)

    out = tmp_path / "x.hdlc"
    r = _run(["-i", kdb, "-o", out])
    assert r.returncode == 1
    err = r.stderr.decode()
    assert str(SESSION) in err and str(SESSION2) in err
    assert not out.exists()

    r = _run(["-i", kdb, "-o", out, "-S", SESSION2])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == s2

    outdir = tmp_path / "out"
    outdir.mkdir()
    r = _run(["-i", kdb, "-O", outdir])
    assert r.returncode == 0, r.stderr.decode()
    assert (outdir / f"{NAME_A}-{_utc(SESSION)}.hdlc").read_bytes() == s1
    assert (outdir / f"{NAME_A}-{_utc(SESSION2)}.hdlc").read_bytes() == s2


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------

@pytest.fixture
def two_modems(tmp_path):
    sa, sb = _stream(30), _stream(31)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), (UUID_B, "celldiag", NAME_B),
                   rows=_rows(UUID_A, _packets(sa, 32)) + _rows(UUID_B, _packets(sb, 33)),
                   seed=34)
    return kdb, sa, sb


def test_single_file_mode_refuses_to_merge_two_modems(two_modems, tmp_path):
    kdb, _, _ = two_modems
    out = tmp_path / "x.hdlc"
    r = _run(["-i", kdb, "-o", out])
    assert r.returncode == 1
    err = r.stderr.decode()
    assert UUID_A in err and UUID_B in err
    assert not out.exists()


def test_source_by_uuid_selects_exactly_that_modem(two_modems, tmp_path):
    kdb, _, sb = two_modems
    out = tmp_path / "b.hdlc"
    r = _run(["-i", kdb, "-o", out, "-s", UUID_B])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == sb


def test_source_by_name_selects_that_modem(two_modems, tmp_path):
    kdb, sa, _ = two_modems
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "-s", NAME_A])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == sa


def test_list_mode_reports_every_stream_with_its_counts(two_modems):
    kdb, sa, sb = two_modems
    r = _run(["-i", kdb, "-l"])
    assert r.returncode == 0, r.stderr.decode()
    text = r.stdout.decode()
    for uuid, s, seed in ((UUID_A, sa, 32), (UUID_B, sb, 33)):
        (line,) = [l for l in text.splitlines() if uuid in l]
        assert f"session={SESSION} ({_utc(SESSION)})" in line
        assert f"slices={len(_slices(s, seed))} bytes={len(s)} gaps=0" in line


def test_list_mode_names_the_rawlog_spec_and_a_source_with_no_packets(tmp_path):
    kdb = _db_with(tmp_path,
                   (UUID_A, "celldiag", NAME_A, "/cap/drive/celldiag-%m-%i-%t.hdlc"),
                   (UUID_B, "celldiag", NAME_B),
                   rows=_rows(UUID_A, _packets(_stream(40), 41)))
    r = _run(["-i", kdb, "-l"])
    assert r.returncode == 0, r.stderr.decode()
    text = r.stdout.decode()
    (a,) = [l for l in text.splitlines() if UUID_A in l]
    assert a.endswith(" rawlog=/cap/drive/celldiag-%m-%i-%t.hdlc")
    (b,) = [l for l in text.splitlines() if UUID_B in l]
    assert "sessions=0" in b


def test_other_dlts_from_the_source_are_ignored_and_listed(tmp_path):
    stream = _stream(50)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=(_rows(UUID_A, _packets(stream, 51)) +
                         _rows(UUID_A, [b"not-a-slice"] * 3, dlt=148)),
                   seed=52)
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == stream
    r = _run(["-i", kdb, "-l"])
    assert "dlt148_rows=3" in r.stdout.decode()


# --------------------------------------------------------------------------
# Integrity: reported every time, and --strict refuses before writing
# --------------------------------------------------------------------------

def _strict_refuses(kdb, tmp_path):
    out = tmp_path / "strict.hdlc"
    r = _run(["-i", kdb, "-o", out, "--strict"])
    assert r.returncode == 3, r.stderr.decode()
    assert not out.exists() and not Path(str(out) + ".partial").exists()


def test_a_dropped_slice_is_a_gap_of_exactly_its_bytes(tmp_path):
    stream = _stream(60)
    sl = _slices(stream, 61)
    off, _, lost = sl[len(sl) // 2]
    kept = [_pkt(SESSION, o, p) for o, _, p in sl if o != off]
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), rows=_rows(UUID_A, kept), seed=62)

    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out])
    assert r.returncode == 0, r.stderr.decode()
    err = r.stderr.decode()
    assert f"1 gap(s), {len(lost)} byte(s) never delivered" in err, err
    assert out.read_bytes() == stream[:off] + stream[off + len(lost):]
    r = _run(["-i", kdb, "-l"])
    assert f"gaps=1 gap_bytes={len(lost)}" in r.stdout.decode()
    _strict_refuses(kdb, tmp_path)


def test_a_missing_first_slice_is_a_gap_too(tmp_path):
    stream = _stream(63)
    sl = _slices(stream, 64)
    kept = [_pkt(SESSION, o, p) for o, _, p in sl[1:]]
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), rows=_rows(UUID_A, kept), seed=65)
    r = _run(["-i", kdb, "-l"])
    assert f"gaps=1 gap_bytes={len(sl[0][2])}" in r.stdout.decode()
    _strict_refuses(kdb, tmp_path)


def test_malformed_rows_are_skipped_reported_and_refused_by_strict(tmp_path):
    stream = _stream(70)
    pkts = _packets(stream, 71)
    bad = [_pkt(SESSION, 0, b"\x7e", magic=b"XXXX"),
           _pkt(SESSION, 0, b"\x7e", version=2),
           b"CDRH\x01\x00"]                                      # shorter than a header
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, pkts + bad), seed=72)
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out])
    assert r.returncode == 0, r.stderr.decode()
    assert "3 DLT-147 row(s) are not valid slices" in r.stderr.decode()
    assert out.read_bytes() == stream
    _strict_refuses(kdb, tmp_path)


def test_a_header_len_past_the_packet_is_malformed(tmp_path):
    stream = _stream(73)
    bogus = HDR.pack(b"CDRH", 1, 0, 4000, SESSION, len(stream)) + b"\x7e"
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 74) + [bogus]), seed=75)
    r = _run(["-i", kdb, "-l"])
    assert "malformed=1" in r.stdout.decode()


def test_truncated_rows_are_reported_and_refused_by_strict(tmp_path):
    stream = _stream(80)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 81),
                              full_len=lambda i, p: len(p) + (9 if i == 2 else 0)),
                   seed=82)
    r = _run(["-i", kdb, "-o", tmp_path / "a.hdlc"])
    assert r.returncode == 0, r.stderr.decode()
    assert "1 truncated packet(s)" in r.stderr.decode()
    _strict_refuses(kdb, tmp_path)


def test_a_flagged_fragment_tail_is_fine_but_an_unflagged_one_is_not(tmp_path):
    stream = _stream(90)
    tail = b"\x10\x00partial-frame-at-stream-end"
    pkts = _packets(stream, 91)
    flagged = pkts + [_pkt(SESSION, len(stream), tail, flags=FRAGMENT)]
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), rows=_rows(UUID_A, flagged), seed=92)
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == stream + tail

    unflagged = pkts + [_pkt(SESSION, len(stream), tail)]
    (tmp_path / "u").mkdir()
    kdb = _db_with(tmp_path / "u", (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, unflagged), seed=93)
    r = _run(["-i", kdb, "-o", tmp_path / "u" / "a.hdlc"])
    assert r.returncode == 0, r.stderr.decode()
    assert "not flagged FRAGMENT do not end in 0x7E" in r.stderr.decode()
    _strict_refuses(kdb, tmp_path / "u")


def test_an_overlapping_slice_is_skipped_and_refused_by_strict(tmp_path):
    stream = _stream(100)
    sl = _slices(stream, 101)
    off, _, pl = sl[3]
    rows = _rows(UUID_A, _packets(stream, 101))
    # Inserted last (highest rowid), so the real slice at this offset wins.
    rows += _rows(UUID_A, [_pkt(SESSION, off + 1, b"\xaa" * len(pl))])
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), rows=rows)
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out])
    assert r.returncode == 0, r.stderr.decode()
    assert "1 overlapping slice(s) skipped" in r.stderr.decode()
    assert out.read_bytes() == stream
    _strict_refuses(kdb, tmp_path)


# --------------------------------------------------------------------------
# The end of a stream: END, tail loss, and the RawDiagDrop witness
# --------------------------------------------------------------------------

def _cut_tail(stream, seed, n_lost):
    """The slices with the last `n_lost` dropped: (kept packets, delivered end)."""
    sl = _slices(stream, seed)
    kept = sl[:-n_lost]
    return [_pkt(SESSION, o, p) for o, _, p in kept], kept[-1][0] + len(kept[-1][2])


def test_an_end_at_the_final_length_confirms_the_stream(tmp_path):
    stream = _stream(110)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 111) + [_end(SESSION, len(stream))]),
                   seed=112)
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "--strict", "--require-end"])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == stream
    assert b"NOTE" not in r.stderr and b"WARNING" not in r.stderr, r.stderr.decode()
    line = _run(["-i", kdb, "-l"]).stdout.decode()
    # END is not a data slice: the count is the data slices alone.
    assert f"slices={len(_slices(stream, 111))} bytes={len(stream)} gaps=0" in line
    assert f"end={len(stream)}" in line and "tail_gap_bytes" not in line, line


def test_a_dropped_tail_before_end_is_measured_and_refused(tmp_path):
    """Tail loss with END: the last slices were dropped, so no later slice shows
    the hole -- END's offset does, and exactly."""
    stream = _stream(120)
    kept, delivered = _cut_tail(stream, 121, 2)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, kept + [_end(SESSION, len(stream))]), seed=122)
    lost = len(stream) - delivered
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out])
    assert r.returncode == 0, r.stderr.decode()
    err = r.stderr.decode()
    assert f"the stream's last {lost} byte(s) were never delivered" in err, err
    assert out.read_bytes() == stream[:delivered]
    line = _run(["-i", kdb, "-l"]).stdout.decode()
    assert "gaps=0 gap_bytes=0" in line, "a tail loss is not an interior gap"
    assert f"end={len(stream)} tail_gap_bytes={lost}" in line, line
    _strict_refuses(kdb, tmp_path)


def test_a_reported_drop_with_no_gap_is_tail_loss_and_refused(tmp_path):
    """Tail loss on a Kismet-stopped live drive: no END (the stop kills the
    source before teardown), the tail slices dropped, the offsets contiguous.
    The offsets alone would pass --strict. The source's RawDiagDrop row is the
    witness -- and it is attributed by datasource: source B's clean stream in
    the same db must not inherit A's loss."""
    stream, clean = _stream(130), _stream(131)
    kept, delivered = _cut_tail(stream, 132, 3)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), (UUID_B, "celldiag", NAME_B),
                   rows=_rows(UUID_A, kept) + _rows(UUID_B, _packets(clean, 133)),
                   drops=[(UUID_A, _drop(SESSION, delivered, 77))], seed=134)

    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "-s", UUID_A])
    assert r.returncode == 0, r.stderr.decode()
    err = r.stderr.decode()
    assert f"reported dropping slices (first at offset {delivered}, 77 byte(s))" in err, err
    assert "tail loss no gap shows" in err, err
    assert out.read_bytes() == stream[:delivered]
    lines = _run(["-i", kdb, "-l"]).stdout.decode().splitlines()
    (a,) = [l for l in lines if UUID_A in l]
    assert "gaps=0 gap_bytes=0" in a and f"end=none drop_reported_at={delivered}" in a, a
    (b,) = [l for l in lines if UUID_B in l]
    assert "drop_reported_at" not in b, b

    r = _run(["-i", kdb, "-o", tmp_path / "strict.hdlc", "-s", UUID_A, "--strict"])
    assert r.returncode == 3, r.stderr.decode()
    assert not (tmp_path / "strict.hdlc").exists()
    r = _run(["-i", kdb, "-o", tmp_path / "b.hdlc", "-s", UUID_B, "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    assert (tmp_path / "b.hdlc").read_bytes() == clean


def test_a_session_that_lost_every_slice_is_still_reported(tmp_path):
    """A RawDiagDrop row for a session with no delivered slice: nothing to write
    for it, but the loss is reported -- and it belongs to THAT session only."""
    stream = _stream(135)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 136)),
                   drops=[(UUID_A, _drop(SESSION2, 0, 500))], seed=137)
    line = [l for l in _run(["-i", kdb, "-l"]).stdout.decode().splitlines()
            if f"session={SESSION2}" in l]
    assert line and "slices=0 bytes=0" in line[0] and "drop_reported_at=0" in line[0], line
    r = _run(["-i", kdb, "-o", tmp_path / "x.hdlc", "-S", SESSION, "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    assert (tmp_path / "x.hdlc").read_bytes() == stream
    outdir = tmp_path / "out"
    outdir.mkdir()
    r = _run(["-i", kdb, "-O", outdir, "--strict"])
    assert r.returncode == 3, r.stderr.decode()
    assert f"session {SESSION2}: the source reported dropping" in r.stderr.decode()


def test_no_end_is_a_note_not_a_strict_failure_unless_required(tmp_path):
    """A Kismet-stopped drive recorded without the graceful close
    lacks END, and so does a close out of its grace: failing --strict on it
    would fail every such drive. It is a NOTE, and --require-end makes it fatal.
    (A source that DIED is not this case: see the RawDiagAbort tests below.)"""
    stream = _stream(140)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 141)), seed=142)
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    err = r.stderr.decode()
    assert "NOTE:" in err and "end is unconfirmed" in err, err
    # It must not read as a clean bill: a Kismet-stopped tail can be short (the
    # reads at the close; ~1 s from a helper without the commit wakeup).
    assert "the tail may be short" in err, err
    assert "out-ring wakeup" in err, err
    assert "no ring-full drop was reported" in err, err
    assert out.read_bytes() == stream
    assert "end=none" in _run(["-i", kdb, "-l"]).stdout.decode()

    r = _run(["-i", kdb, "-o", tmp_path / "req.hdlc", "--strict", "--require-end"])
    assert r.returncode == 3, r.stderr.decode()
    assert "WARNING:" in r.stderr.decode()
    assert not (tmp_path / "req.hdlc").exists()


def test_without_a_data_table_no_drop_is_not_claimed_absent(tmp_path):
    """No `data` table, no place for a RawDiagDrop row: "the source reported no
    drop" would be a claim nothing could have contradicted."""
    stream = _stream(145)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 146)), data_table=False)
    r = _run(["-i", kdb, "-o", tmp_path / "a.hdlc"])
    assert r.returncode == 0, r.stderr.decode()
    err = r.stderr.decode()
    assert "no ring-full drop was reported" not in err and "no data table" in err, err


def test_an_end_that_cannot_be_believed_is_refused(tmp_path):
    stream = _stream(150)
    pkts = _packets(stream, 151)
    # END short of the delivered data, and a second END: neither is a
    # believable end, so neither may confirm the stream.
    for name, extra in (("short", [_end(SESSION, len(stream) - 5)]),
                        ("twice", [_end(SESSION, len(stream)), _end(SESSION, len(stream))])):
        d = tmp_path / name
        d.mkdir()
        kdb = _db_with(d, (UUID_A, "celldiag", NAME_A), rows=_rows(UUID_A, pkts + extra),
                       seed=152)
        r = _run(["-i", kdb, "-o", d / "a.hdlc"])
        assert r.returncode == 0, r.stderr.decode()
        assert "the stream's end is not believable" in r.stderr.decode(), (name, r.stderr)
        assert "end_bad=" in _run(["-i", kdb, "-l"]).stdout.decode()
        _strict_refuses(kdb, d)


def test_an_end_with_a_payload_is_malformed(tmp_path):
    stream = _stream(155)
    bogus = _pkt(SESSION, len(stream), b"\x01\x7e", flags=END)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 156) + [bogus]), seed=157)
    r = _run(["-i", kdb, "-l"])
    assert "malformed=1" in r.stdout.decode() and "end=none" in r.stdout.decode()
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out])
    assert out.read_bytes() == stream, "an END's payload leaked into the stream"
    _strict_refuses(kdb, tmp_path)


def test_a_drop_row_that_does_not_parse_is_refused_not_ignored(tmp_path):
    """A row the tool cannot read is still a drop the source reported. Covers bad
    JSON, a foreign schema, and a number sent as a string (which nlohmann's get<>
    would THROW on, crashing the reader, if the type were not checked first)."""
    stream = _stream(160)
    bad = ['{"schema":"raw-diag-drop/1",',
           _drop(SESSION, 0, 1, schema="raw-diag-drop/9"),
           '{"schema":"raw-diag-drop/1","session_id":"1","first_drop_offset":0,'
           '"first_drop_len":1}',
           '{"schema":7,"session_id":1,"first_drop_offset":0,"first_drop_len":1}']
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 161)),
                   drops=[(UUID_A, js) for js in bad], seed=162)
    r = _run(["-i", kdb, "-l"])
    assert r.returncode == 0, r.stderr.decode()
    assert "bad_drop_rows=4" in r.stdout.decode(), r.stdout.decode()
    r = _run(["-i", kdb, "-o", tmp_path / "a.hdlc"])
    assert r.returncode == 0, r.stderr.decode()
    assert "4 RawDiagDrop row(s) do not parse" in r.stderr.decode()
    _strict_refuses(kdb, tmp_path)


# --------------------------------------------------------------------------
# A source that DIED mid-stream: the server's RawDiagAbort witness
# --------------------------------------------------------------------------

def test_a_source_that_died_mid_stream_is_refused_by_strict(tmp_path):
    """A helper killed by the 15 s PING watchdog during a server stall:
    no END, no gap, no RawDiagDrop -- the offsets read whole, so they alone
    would pass --strict. The server's RawDiagAbort row is the witness, attributed by source
    AND session: A's re-opened session and B's clean stream keep their verdicts."""
    first, second, clean = _stream(170), _stream(171), _stream(172)
    rows = (_rows(UUID_A, _packets(first, 173))
            + _rows(UUID_A, _packets(second, 174, session=SESSION2)
                    + [_end(SESSION2, len(second))])
            + _rows(UUID_B, _packets(clean, 175) + [_end(SESSION, len(clean))]))
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), (UUID_B, "celldiag", NAME_B),
                   rows=rows, seed=176, aborts=[(UUID_A, _abort(SESSION, len(first), 17))])

    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out, "-s", UUID_A, "-S", SESSION])
    assert r.returncode == 0, r.stderr.decode()
    err = r.stderr.decode()
    assert "the source DIED mid-stream (IPC connection closed)" in err, err
    assert f"through offset {len(first)} (17 slice(s)) and no END" in err, err
    # The death explains the missing END: no second, softer note on top.
    assert "no END slice" not in err, err
    assert out.read_bytes() == first, "what did arrive must still reassemble exactly"

    lines = _run(["-i", kdb, "-l"]).stdout.decode().splitlines()
    (died,) = [l for l in lines if UUID_A in l and f"session={SESSION} " in l]
    assert f"end=none died_after={len(first)}" in died, died
    assert not [l for l in lines if "died_after" in l and l is not died], lines

    r = _run(["-i", kdb, "-o", tmp_path / "strict.hdlc", "-s", UUID_A, "-S", SESSION,
              "--strict"])
    assert r.returncode == 3, r.stderr.decode()
    assert not (tmp_path / "strict.hdlc").exists()
    for args in (["-s", UUID_A, "-S", SESSION2], ["-s", UUID_B]):
        r = _run(["-i", kdb, "-o", tmp_path / "ok.hdlc", *args, "--strict"])
        assert r.returncode == 0, (args, r.stderr.decode())
        (tmp_path / "ok.hdlc").unlink()


def test_without_its_abort_row_the_same_stream_passes_strict(tmp_path):
    """The control that gives the test above its meaning: the same slices with
    no RawDiagAbort row are a blind spot -- a NOTE, and --strict
    passes. The row is the whole difference."""
    first = _stream(170)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(first, 173)), seed=176)
    r = _run(["-i", kdb, "-o", tmp_path / "a.hdlc", "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    assert "NOTE:" in r.stderr.decode() and "DIED" not in r.stderr.decode()


def test_an_abort_row_for_a_session_whose_END_arrived_is_only_a_note(tmp_path):
    """The server never writes the row once END is in; if one shows up anyway,
    END wins -- the stream reached its teardown."""
    stream = _stream(177)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 178) + [_end(SESSION, len(stream))]),
                   aborts=[(UUID_A, _abort(SESSION, len(stream), 9))])
    r = _run(["-i", kdb, "-o", tmp_path / "a.hdlc", "--strict"])
    assert r.returncode == 0, r.stderr.decode()
    err = r.stderr.decode()
    assert "NOTE:" in err and "its END arrived, so the stream is confirmed" in err, err
    assert (tmp_path / "a.hdlc").read_bytes() == stream


def test_an_abort_row_for_a_session_with_no_slices_is_still_reported(tmp_path):
    stream = _stream(179)
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 180) + [_end(SESSION, len(stream))]),
                   aborts=[(UUID_A, _abort(SESSION2, 0, 0, reason="no ping"))])
    line = [l for l in _run(["-i", kdb, "-l"]).stdout.decode().splitlines()
            if f"session={SESSION2}" in l]
    assert line and "slices=0 bytes=0" in line[0] and "died_after=0" in line[0], line
    outdir = tmp_path / "out"
    outdir.mkdir()
    r = _run(["-i", kdb, "-O", outdir, "--strict"])
    assert r.returncode == 3, r.stderr.decode()
    assert f"session {SESSION2}: the source DIED mid-stream (no ping)" in r.stderr.decode()


def test_an_abort_row_that_does_not_parse_is_refused_not_ignored(tmp_path):
    """Bad JSON, a foreign schema, a string where a number goes, a negative
    number, a missing reason: each is a death the server recorded that this
    tool cannot place. Refused, never ignored -- and never a crash (nlohmann's
    get<> throws on a type mismatch unless the type is checked first)."""
    stream = _stream(181)
    good = _abort(SESSION, len(stream), 3)
    bad = ['{"schema":"raw-diag-abort/1",',
           _abort(SESSION, len(stream), 3, schema="raw-diag-abort/9"),
           good.replace(f'"session_id":{SESSION}', '"session_id":"1"'),
           good.replace('"slices":3', '"slices":-3'),
           good.replace(',"reason":"IPC connection closed"', "")]
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A),
                   rows=_rows(UUID_A, _packets(stream, 182) + [_end(SESSION, len(stream))]),
                   aborts=[(UUID_A, js) for js in bad], seed=183)
    r = _run(["-i", kdb, "-l"])
    assert r.returncode == 0, r.stderr.decode()
    assert "bad_abort_rows=5" in r.stdout.decode(), r.stdout.decode()
    r = _run(["-i", kdb, "-o", tmp_path / "a.hdlc"])
    assert r.returncode == 0, r.stderr.decode()
    assert "5 RawDiagAbort row(s) do not parse" in r.stderr.decode()
    _strict_refuses(kdb, tmp_path)


# --------------------------------------------------------------------------
# A drive from before the emitter existed: say so, don't write an empty file
# --------------------------------------------------------------------------

def test_a_celldiag_source_without_packets_is_a_clear_no_data_exit(tmp_path):
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), rows=[])
    out = tmp_path / "a.hdlc"
    r = _run(["-i", kdb, "-o", out])
    assert r.returncode == 2
    assert "no diag packets" in r.stderr.decode().lower()
    assert not out.exists()


# --------------------------------------------------------------------------
# An input .kismet is an artifact of record
# --------------------------------------------------------------------------

def test_input_is_never_modified_and_output_is_never_clobbered(two_modems, tmp_path):
    kdb, sa, _ = two_modems
    before = (kdb.stat().st_mtime_ns, kdb.stat().st_size, kdb.read_bytes())
    out = tmp_path / "a.hdlc"
    out.write_bytes(b"keep me")
    r = _run(["-i", kdb, "-o", out, "-s", UUID_A])
    assert r.returncode == 1
    assert out.read_bytes() == b"keep me"
    r = _run(["-i", kdb, "-o", out, "-s", UUID_A, "-f"])
    assert r.returncode == 0, r.stderr.decode()
    assert out.read_bytes() == sa
    assert (kdb.stat().st_mtime_ns, kdb.stat().st_size, kdb.read_bytes()) == before


# --------------------------------------------------------------------------
# End to end: the REAL emitter's packets, read back by the reader
# --------------------------------------------------------------------------

def test_a_replay_through_the_real_emitter_reads_back_as_the_file_and_the_tee(tmp_path):
    """Replay a stream through kismet_cap_cell_diag over the datasource IPC
    harness and collect the DLT-147 packets it sends. Store them the way the
    server would (shuffled rows, one datasource), then read them back. The
    output must equal the replay file and the source's own rawlog= tee.

    This is what ties the reader's header parse to diag_rawpkt.c. The unit
    tests above build headers from diag_rawpkt.h's documented layout; this
    test reads what the emitter actually produces."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from fake_diag_modem import hdlc_frame
    from celldiag_run import CellDiagRun, _binary_or_skip

    binary = _binary_or_skip()
    rng = random.Random(4646)
    data = bytearray()
    while len(data) < 200_000:
        data += hdlc_frame(bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 6000))))
    data = bytes(data)
    replay = tmp_path / "in.hdlc"
    replay.write_bytes(data)
    tee = tmp_path / "tee.hdlc"
    definition = (f"{NAME_A}:replay={replay},stats_interval=0,"
                  f"rawlog={tee}")

    run = CellDiagRun(binary, definition, timeout=30.0).run()
    pkts = [p["content"] for p in run.raw_packets if p["dlt"] == DLT]
    assert len(pkts) > 1, (run.errors, run.messages)      # more than one slice to order

    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), rows=_rows(UUID_A, pkts), seed=4646)
    out = tmp_path / "out.hdlc"
    # --require-end: a replay reaches teardown, so the emitter's END must be
    # there and must agree with the reader's arithmetic.
    r = _run(["-i", kdb, "-o", out, "--strict", "--require-end"])
    assert r.returncode == 0, r.stderr.decode()
    got = out.read_bytes()
    assert got == data, f"read back {len(got)} B != the {len(data)}-byte replay"
    assert got == tee.read_bytes(), "the read-back stream and the rawlog= tee disagree"


def test_a_live_flood_through_the_real_emitter_is_refused_by_strict(tmp_path):
    """Tail loss end to end, whatever the host's speed. A live flood stopped the
    Kismet way (no teardown, so no END) loses slices; stored as the server
    stores them -- the DLT-147 packets plus the RawDiagDrop row -- the stream
    must NOT pass --strict. When the drops are the tail the offsets alone are
    contiguous, so only the RawDiagDrop row reveals the loss."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from test_celldiag_raw_packets import _flood_run

    run, teed = _flood_run(tmp_path)
    pkts = [p["content"] for p in run.raw_packets if p["dlt"] == DLT]
    assert pkts and run.raw_diag_drops, (len(pkts), run.raw_diag_drops, run.messages[-3:])
    drop = run.raw_diag_drops[0]
    kdb = _db_with(tmp_path, (UUID_A, "celldiag", NAME_A), rows=_rows(UUID_A, pkts),
                   drops=[(UUID_A, drop)], seed=4665)

    out = tmp_path / "extracted.hdlc"     # not flood.hdlc: that is _flood_run's tee
    r = _run(["-i", kdb, "-o", out, "--strict"])
    assert r.returncode == 3, r.stderr.decode()
    assert "reported dropping slices" in r.stderr.decode(), r.stderr.decode()
    assert not out.exists()

    # Without --strict it still writes what was delivered, and that is the tee's
    # bytes wherever it has them (offset-for-offset up to the first drop).
    r = _run(["-i", kdb, "-o", out])
    assert r.returncode == 0, r.stderr.decode()
    first = json.loads(drop)["first_drop_offset"]
    assert out.read_bytes()[:first] == teed[:first]
