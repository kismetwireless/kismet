"""The canned replay fixture and check-native's expectation for it.

These tests need no decoder and no network: they pin the fixture's own
properties and the committed expectation, both of which are pure logic. The
end-to-end decode claim is `standalone.mk check-native`'s job, and it is
deliberately not duplicated here.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
FIXTURES = HERE / "fixtures"
FIXTURE = FIXTURES / "functional.hdlc"
GENERATOR = FIXTURES / "make_functional_fixture.py"

sys.path.insert(0, str(FIXTURES))
import make_functional_fixture as gen  # noqa: E402


# ── the fixture itself ───────────────────────────────────────────────────────

def test_the_committed_fixture_matches_its_generator_byte_for_byte():
    """The generator is the fixture's documentation, so drift between them
    would make the documentation wrong in the one way nobody checks. Bytes,
    not a record count: a regenerated fixture with the same shape and different
    contents would pass a count-based test and invalidate the expectation."""
    assert FIXTURE.read_bytes() == gen.build()


def test_the_fixture_clears_the_hdlc_detector_delimiter_floor():
    """Regression guard.

    A capture-format sniffer that classifies a stream as raw HDLC from its head
    window commonly wants several ``0x7E`` delimiters there; a 3-frame version
    of this fixture can be refused as "not a DIAG capture" even though every
    frame in it is CRC-valid. Keeping at least 4 delimiters keeps the fixture
    usable with such tools, so the floor is asserted here rather than left in
    a comment."""
    assert FIXTURE.read_bytes().count(0x7E) >= 4


def test_every_record_is_a_crc_valid_log_f_frame():
    """Walks the fixture the way the deframer does. This is what makes the
    generator's framing arithmetic -- the two length fields especially -- a
    checked claim rather than an assumption: a frame whose ``outer_len``
    disagrees with its true length is dropped as desynced, and the capture
    would decode to zero records with every byte still looking plausible."""
    data = FIXTURE.read_bytes()
    segments = [s for s in data.split(b"\x7e") if s]
    assert len(segments) == len(gen.RECORDS)
    for seg in segments:
        frame = _unescape(seg)
        assert frame[0] == 0x10, "not a DIAG_LOG_F frame"
        body, crc = frame[:-2], int.from_bytes(frame[-2:], "little")
        assert gen.crc16_ccitt(body) == crc, "CRC mismatch"
        # The two length fields of a LOG_F frame duplicate each other.
        assert int.from_bytes(frame[2:4], "little") == len(frame) - 2 - 4
        assert int.from_bytes(frame[4:6], "little") == len(frame) - 2 - 4


def _unescape(seg: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(seg):
        if seg[i] == 0x7D and i + 1 < len(seg):
            out.append(seg[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(seg[i])
            i += 1
    return bytes(out)


def test_the_records_do_not_all_decode_to_the_same_values():
    """A fixture whose every record carries identical fields cannot separate
    "the parser read the field" from "the parser returned a constant"."""
    assert len({r[1] for r in gen.RECORDS}) == len(gen.RECORDS), "PCIs repeat"
    assert len({r[2] for r in gen.RECORDS}) > 1, "RSRP is constant"


# ── the native expectation (standalone.mk check-native) ────────────────────

NATIVE_EXPECTED = FIXTURES / "functional.native.ndjson"


def _native_rows() -> list[dict]:
    return [json.loads(line) for line in NATIVE_EXPECTED.read_text().splitlines()]


def test_the_native_expectation_agrees_with_the_generator():
    """check-native byte-compares the binary's canonical NDJSON with
    functional.native.ndjson. That file is only as good as its agreement with
    the values the generator wrote into the capture, so the two are pinned to
    each other row by row: regenerating the fixture without regenerating the
    expectation cannot leave check-native asserting yesterday's answer."""
    rows = _native_rows()
    assert rows, "an empty expectation asserts nothing"
    assert len(rows) == len(gen.RECORDS)
    for row, (earfcn, pci, rsrp, rsrq) in zip(rows, gen.RECORDS):
        assert set(row) == {"gps", "obs"}
        assert row["gps"] is None, "the fixture carries no GNSS record"
        obs = row["obs"]
        assert obs["pci"] == pci
        assert obs["earfcn"] == earfcn
        assert obs["rsrp"] == pytest.approx(rsrp)
        assert obs["rsrq"] == pytest.approx(rsrq)
        assert obs["prov"].get("log_tick") is not None


def test_the_native_expectation_is_in_the_drivers_canonical_form():
    """check-native compares BYTES with what celldiag_replay_ndjson prints:
    sorted keys, no whitespace, one row per line. A hand-edited row with a space
    in it would fail there for a reason that has nothing to do with decode."""
    text = NATIVE_EXPECTED.read_text()
    assert text.endswith("\n") and not text.endswith("\n\n")
    for line in text.splitlines():
        assert line == json.dumps(json.loads(line), sort_keys=True,
                                  separators=(",", ":")), line


def test_the_native_expectation_carries_no_real_identity():
    """The fixture is synthesised, not scrubbed; this asserts that stays true.
    The IMEI must be the all-zero synthetic one, and there must be no
    coordinate anywhere: a high-precision bare decimal is the field class most
    likely to leak a location."""
    for row in _native_rows():
        assert row["obs"]["prov"]["imei"] == "0" * 15
        assert "captured_at" not in row["obs"]["prov"]
        for key in ("lat", "lon", "latitude", "longitude", "alt"):
            assert key not in row["obs"]
