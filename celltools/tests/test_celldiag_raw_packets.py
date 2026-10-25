"""celldiag emits the raw DIAG stream as DLT 147 packets, end to end.

The raw stream goes to the server as ``cf_send_data`` packets -- the path the
kismetdb logs into its ``packets`` table -- as offset-stamped slices whose
contract lives in ``capture_cell_diag/diag_rawpkt.h``. These tests drive the
REAL binary over the datasource IPC (replay, and a live pty modem) and read the
packets it actually sent.

**The byte-identity assertion is the load-bearing one.** Slices sorted by
their header ``offset`` and concatenated must BE the stream -- the replay file,
and the ``rawlog=`` tee of the same run -- so a kismetdb's packets can be turned
back into an equivalent ``.hdlc`` capture. Counting packets proves only that
something was sent.

**The full-ring test needs its positive control.** A replay must be lossless:
a full output ring waits instead of dropping. The test slows the harness to fill
the ring on purpose, and asserts the binary REPORTS having waited before it
trusts "nothing was dropped" -- a ring that never filled would pass the
no-drop assertion vacuously.
"""

from __future__ import annotations

import json
import random
import re
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import kismet_capture_ipc  # noqa: E402
from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem, hdlc_frame  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

#: A placeholder IMEI that cannot be mistaken for a device: any OTHER
#: Luhn-valid 15 digits in a publishable file reads as a real IMEI.
IMEI = "123456789012345"
FIRMWARE = "RM520NGLAAR03A03M4G"

DLT = 147
HDR = struct.Struct("<4sBBHQQ")        # magic, version, flags, header_len, session, offset
FRAGMENT = 0x01
END = 0x02                             # empty payload, offset = final length

TREE = Path(__file__).resolve().parents[2]


def _c_define(rel: str, name: str) -> int:
    """An integer #define out of a header in this tree -- the SOURCE is the
    authority, so a copy of the number here cannot silently drift from it."""
    text = (TREE / rel).read_text(errors="replace")
    hit = re.search(rf"^#define\s+{name}\s+\(?\s*(\d+)u?\s*\)?", text, re.M)
    assert hit, f"#define {name} not found in {rel}"
    return int(hit.group(1))


PAYLOAD_MAX = _c_define("capture_cell_diag/diag_rawpkt.h", "DIAG_RAWPKT_PAYLOAD_MAX")
#: Everything in a raw-slice IPC frame that is not payload, generously: the v3
#: header, the msgpack map and packet block (~30 B), the 24-byte slice header,
#: and cf_send_data's optional fixed-GPS block with a caller-chosen name. 1 KiB
#: is several times the measured non-GPS overhead.
FRAME_OVERHEAD_BUDGET = 1024


def test_the_harness_enforces_the_servers_frame_limit():
    """The harness's frame cap IS kis_external.h's -- a harness laxer than the
    server would pass slices the server kills the source over."""
    assert kismet_capture_ipc.MAX_EXTERNAL_FRAME_LEN == _c_define(
        "kis_external.h", "MAX_EXTERNAL_FRAME_LEN")


def test_a_full_slice_fits_one_server_frame_with_headroom():
    """A cap-length slice plus every non-payload byte must fit the server's
    frame limit, or the largest slice a busy stream produces errors the source."""
    server_max = _c_define("kis_external.h", "MAX_EXTERNAL_FRAME_LEN")
    hdr = _c_define("capture_cell_diag/diag_rawpkt.h", "DIAG_RAWPKT_HDR_LEN")
    assert PAYLOAD_MAX + hdr + FRAME_OVERHEAD_BUDGET <= server_max, (
        f"a {PAYLOAD_MAX}-byte slice leaves {server_max - PAYLOAD_MAX - hdr} B for "
        f"framing + GPS, budget {FRAME_OVERHEAD_BUDGET}")
    # ...and it must still hold the largest DIAG frame seen in real captures
    # (8,050 B) whole, or real frames would be split as fragments.
    assert PAYLOAD_MAX >= 8192

SUMMARY_RE = re.compile(
    r"raw DIAG into the packets table \(DLT 147\): (\d+) slice\(s\), (\d+) B delivered; "
    r"(\d+) slice\(s\) / (\d+) B dropped; (\d+) fragment\(s\); (\d+) ring-full wait\(s\)")
SUMMARY_END_RE = re.compile(r"END at offset (\d+) (delivered|DROPPED)")


def _stream(n_bytes: int, seed: int = 4641) -> bytes:
    """HDLC frames of 1..6000-byte bodies (real captures top out at 8,050 B),
    random content -- so escapes, and 0x7E inside bodies, are everywhere."""
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < n_bytes:
        out += hdlc_frame(bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 6000))))
    return bytes(out)


def _slices(run: CellDiagRun) -> list[dict]:
    """Parse every DLT-147 packet's header; fail loudly on anything else."""
    out = []
    for p in run.raw_packets:
        assert p["dlt"] == DLT, f"a raw packet with dlt {p['dlt']}, want {DLT}"
        c = p["content"]
        assert c is not None and len(c) >= HDR.size, "a raw packet with no slice header"
        magic, ver, flags, hlen, session, offset = HDR.unpack_from(c)
        assert (magic, ver, hlen) == (b"CDRH", 1, 24), (magic, ver, hlen)
        assert p["length"] == len(c), "LENGTH field disagrees with the content"
        assert not flags & ~(FRAGMENT | END), f"unknown flag bits 0x{flags:02x}"
        out.append({"flags": flags, "session": session, "offset": offset,
                    "payload": c[hlen:], "ts_s": p["ts_s"], "end": bool(flags & END)})
    return out


def _data(slices: list[dict]) -> list[dict]:
    return [s for s in slices if not s["end"]]


def _reassemble(slices: list[dict]) -> bytes:
    """Sort the DATA slices by offset, require contiguity from 0, concatenate.
    An END slice, if any, must be the only one, empty, and at exactly the
    reassembled length -- a whole stream's END leaves no tail gap."""
    assert len({s["session"] for s in slices}) == 1, "slices from more than one session"
    at = 0
    out = bytearray()
    for s in sorted(_data(slices), key=lambda s: s["offset"]):
        assert s["offset"] == at, f"gap or overlap: slice at {s['offset']}, expected {at}"
        assert 0 < len(s["payload"]) <= PAYLOAD_MAX
        if not s["flags"] & FRAGMENT:
            assert s["payload"][-1] == 0x7E, "an unflagged slice that does not end on a frame"
        out += s["payload"]
        at += len(s["payload"])
    ends = [s for s in slices if s["end"]]
    assert len(ends) <= 1, f"{len(ends)} END slices in one stream"
    for e in ends:
        assert e["payload"] == b"" and e["flags"] == END, "END with a payload or other flags"
        assert e["offset"] == at, f"END at {e['offset']}, stream ends at {at}: a tail gap"
    return bytes(out)


def _end_of(slices: list[dict]) -> int | None:
    """The END slice's offset, or None when the stream carries no END."""
    ends = [s["offset"] for s in slices if s["end"]]
    assert len(ends) <= 1, ends
    return ends[0] if ends else None


def _summary(run: CellDiagRun):
    for m in run.messages:
        hit = SUMMARY_RE.search(m)
        if hit:
            return tuple(int(g) for g in hit.groups())
    return None


def _summary_end(run: CellDiagRun):
    """(END offset, "delivered"|"DROPPED") from the totals line, or None."""
    for m in run.messages:
        if SUMMARY_RE.search(m):
            hit = SUMMARY_END_RE.search(m)
            return (int(hit.group(1)), hit.group(2)) if hit else None
    return None


def _replay_def(replay: Path, **flags) -> str:
    parts = [f"replay={replay}", "stats_interval=0"]
    parts += [f"{k}={v}" for k, v in flags.items()]
    return f"celldiag-{IMEI}:" + ",".join(parts)


def test_a_replay_arrives_as_slices_that_reassemble_to_the_file(tmp_path):
    binary = _binary_or_skip()
    data = _stream(300_000)
    replay = tmp_path / "in.hdlc"
    replay.write_bytes(data)
    tee = tmp_path / "tee.hdlc"

    run = CellDiagRun(binary, _replay_def(replay, rawlog=tee), timeout=30.0).run()

    slices = _slices(run)
    assert slices, (run.errors, run.messages)
    got = _reassemble(slices)
    assert got == data, f"reassembled {len(got)} B != the {len(data)}-byte replay"
    assert got == tee.read_bytes(), "the in-db stream and the rawlog= tee disagree"
    # A replay reaches teardown, so it closes with END at the file's length:
    # the positive control for "no END" meaning "unconfirmed", not "normal".
    assert _end_of(slices) == len(data), f"END {_end_of(slices)}, want {len(data)}"
    assert _summary_end(run) == (len(data), "delivered"), _summary_end(run)
    data_slices = _data(slices)
    # A 300 KB file read 64 KiB at a time is cut at the payload cap, never
    # per-frame: one row per frame is the 2-8x storage shape the design avoids.
    assert len(data_slices) < 40, f"{len(data_slices)} slices for 300 KB -- per-frame emission?"
    assert not any(s["flags"] & FRAGMENT for s in slices), "a whole-frame file produced a fragment"
    now = time.time()
    assert all(abs(s["ts_s"] - now) < 120 for s in slices), "slice timestamps are not host time"
    summ = _summary(run)
    assert summ is not None, f"no end-of-stream summary line: {run.messages}"
    delivered, dbytes, dropped, _, frags, _ = summ
    # END is not counted as a delivered slice: the totals stay data.
    assert (delivered, dbytes, dropped, frags) == (len(data_slices), len(data), 0, 0), summ
    assert run.raw_diag_drops == [], "a lossless replay sent a RawDiagDrop row"


def test_a_replay_waits_for_a_full_ring_instead_of_dropping(tmp_path):
    """6 MiB of slices against a 4 MiB output ring and a harness that reads
    slowly: the ring fills, and a replay must wait, not drop."""
    binary = _binary_or_skip()
    data = _stream(6 * 1024 * 1024, seed=7)
    replay = tmp_path / "big.hdlc"
    replay.write_bytes(data)

    run = CellDiagRun(binary, _replay_def(replay), timeout=90.0,
                      drain_pause_s=0.05).run()

    summ = _summary(run)
    assert summ is not None, f"no end-of-stream summary line: {run.messages[-5:]}"
    delivered, dbytes, dropped, dropped_b, _, waits = summ
    # Positive control: the ring really filled. Without it, "0 dropped" below
    # would be true of a run that never exercised the full-ring branch at all.
    assert waits > 0, f"the ring never filled ({summ}) -- the test did not reach its branch"
    assert (dropped, dropped_b) == (0, 0), f"a replay dropped slices: {summ}"
    slices = _slices(run)
    assert _reassemble(slices) == data
    assert (delivered, dbytes) == (len(_data(slices)), len(data)), summ
    # END waited through the same full ring and still landed.
    assert _end_of(slices) == len(data), f"END {_end_of(slices)}, want {len(data)}"


def test_rawpackets_off_sends_no_packets(tmp_path):
    binary = _binary_or_skip()
    data = _stream(50_000)
    replay = tmp_path / "in.hdlc"
    replay.write_bytes(data)
    tee = tmp_path / "tee.hdlc"

    run = CellDiagRun(binary, _replay_def(replay, rawlog=tee, rawpackets="off"),
                      timeout=15.0).run()

    # Positive control: the replay really streamed (the tee got every byte), so
    # "no packets" is a property of the knob, not of a source that never ran.
    assert tee.read_bytes() == data, (run.errors, run.messages)
    assert run.raw_packets == []
    assert _summary(run) is None


def test_an_invalid_rawpackets_value_refuses_the_open(tmp_path):
    binary = _binary_or_skip()
    replay = tmp_path / "in.hdlc"
    replay.write_bytes(_stream(1000))

    run = CellDiagRun(binary, _replay_def(replay, rawpackets="maybe"), timeout=6.0).run()

    assert run.open_code == 0, f"rawpackets=maybe should fail open; got {run.open_code}"
    assert run.raw_packets == []
    assert run.open_message and "rawpackets" in run.open_message and "maybe" in run.open_message, (
        run.open_message)


def _flood_run(tmp_path: Path) -> tuple[CellDiagRun, bytes]:
    """A live port producing faster than a slow harness drains, stopped the way
    Kismet stops a source (pipe close + SIGTERM, no teardown) as soon as the
    drop notice arrives. Returns the run and the rawlog= tee's bytes. Shared
    with test_kismetdb_to_hdlc, which reads the same flood back."""
    binary = _binary_or_skip()
    tee = tmp_path / "flood.hdlc"
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(filler_hz=400, filler_pad=4000) as dg:
        definition = (f"celldiag-{IMEI}:atport={at.port},diagport={dg.port},nomask=true,"
                      f"defer=false,stats_interval=0,rawlog={tee}")
        run = CellDiagRun(binary, definition, timeout=45.0, drain_pause_s=0.1,
                          stop_when=lambda r: any("DROPPED" in m for m in r.messages)).run()
    return run, tee.read_bytes()


def test_a_live_flood_drops_slices_says_so_and_keeps_the_tee_whole(tmp_path):
    """A live port producing faster than the server drains: the in-db copy
    DROPS (the port cannot be paused), says so on the bus AND in a RawDiagDrop
    row, and every slice it did deliver is still exactly the tee's bytes at its
    offset -- nothing around the hole is corrupted.

    The ERROR line is sent at the one moment the ring is full, so a notice
    marked "sent" before the send succeeds is lost with the slices -- and the
    operator's only warning of a holed stream never arrives.

    WHERE the drop lands depends on host speed, so nothing here may depend on
    it. The run stops at the notice, and on a slower host the dropped slices
    are the LAST ones, which no later slice can expose as an offset gap. The
    RawDiagDrop row places the loss in both shapes: before the delivered end
    (a gap shows it too) or at/after it (only the row shows it)."""
    run, teed = _flood_run(tmp_path)

    dropped = [(m, f) for m, f in zip(run.messages, run.message_flags) if "DROPPED" in m]
    assert dropped, f"no drop notice reached the bus: {run.messages[-4:]}"
    assert dropped[0][1] & 4, "the drop notice must be an ERROR (MSGFLAG_ERROR)"

    # The row is sent BEFORE the notice, so having the notice means having it.
    assert len(run.raw_diag_drops) == 1, f"want one RawDiagDrop row: {run.raw_diag_drops}"
    row = json.loads(run.raw_diag_drops[0])
    slices = sorted(_data(_slices(run)), key=lambda s: s["offset"])
    assert slices
    assert row["schema"] == "raw-diag-drop/1", row
    assert row["session_id"] == slices[0]["session"], "the row names another session"
    first, first_len = row["first_drop_offset"], row["first_drop_len"]
    assert first_len > 0 and first + first_len <= len(teed), (
        f"the dropped slice [{first}, +{first_len}) is not inside the {len(teed)}-byte tee")
    assert first not in {s["offset"] for s in slices}, "the 'dropped' slice was delivered"

    ends = [s["offset"] + len(s["payload"]) for s in slices]
    gaps = (slices[0]["offset"] != 0) + sum(
        1 for prev_end, s in zip(ends, slices[1:]) if s["offset"] != prev_end)
    delivered_end = max(ends)
    assert gaps > 0 or first >= delivered_end, (
        f"the row puts the first drop at {first}, inside the contiguous delivered "
        f"range [0, {delivered_end}) -- the row and the offsets disagree")
    for s in slices:
        assert teed[s["offset"]:s["offset"] + len(s["payload"])] == s["payload"], (
            f"slice at {s['offset']} is not the tee's bytes there")


def test_a_live_modem_streams_what_it_reads_as_slices(tmp_path):
    """The live path: bytes read from a DIAG pty (filler LOG frames + the
    capture's own DIAG_TS_F reply) arrive as slices whose reassembly is a
    prefix of the same run's rawlog= tee -- the tee is written first, so it can
    only ever be ahead."""
    binary = _binary_or_skip()
    tee = tmp_path / "live.hdlc"
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(filler_hz=200) as dg:
        definition = (f"celldiag-{IMEI}:atport={at.port},diagport={dg.port},nomask=true,"
                      f"defer=false,stats_interval=0,rawlog={tee}")
        # Stop on BYTES as well as slices. With the framework's commit wakeup
        # each 200 Hz frame is its own slice and arrives at once, so 30 slices
        # are only ~900 B.
        run = CellDiagRun(binary, definition, timeout=20.0,
                          stop_when=lambda r: len(r.raw_packets) >= 30 and sum(
                              len(p["content"] or b"") - HDR.size
                              for p in r.raw_packets) > 1500).run()
        replies = list(dg.replies)

    slices = _slices(run)
    assert len(slices) >= 30, (len(slices), run.errors, run.messages[-5:])
    got = _reassemble(slices)
    teed = tee.read_bytes()
    assert teed.startswith(got), "the live slices are not the bytes the tee recorded"
    assert len(got) > 1000
    # The START anchor's reply is in the stream: the slices carry what the port
    # produced, including answers to the capture's own requests.
    assert replies, "setup: the fake modem never answered DIAG_TS_F"
    assert b"\x1d" in got
    assert any("DLT 147" in m for m in run.messages), (
        f"no announcement of the raw packet stream: {run.messages}")
