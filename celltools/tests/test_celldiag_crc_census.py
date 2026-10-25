"""celldiag counts the DIAG frames that fail CRC, and says so when a stream is
losing bytes.

A USB-serial DIAG stream can lose byte runs (for example when the read loop
falls behind the decoder during a burst). Every other integrity check on the
Kismet path still passes, because the kismetdb faithfully holds what the
helper read; a frame that fails CRC is the only trace. So the native decoder's
stream counts CRC failures on every frame, the helper records the census, and
raises an error when the damage crosses a floor.

These tests drive the real binary over the datasource IPC with replays whose
damage is known exactly: a byte run cut from the middle of a frame, which is
how real loss presents (the damaged frame's length disagrees with its header).
The delimiter survives, so the frame count does not change and each cut is
exactly one CRC-bad frame.

The clean replay is the positive control. A census that never counts
anything would pass every "no alert" assertion vacuously, so the clean run must
show every frame CHECKED, and the damaged runs must show the exact count cut.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_diag_modem import hdlc_frame  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

IMEI = "123456789012345"   # a placeholder, never a real device
MSGFLAG_ERROR = 4
N_FRAMES = 400
FLOOR = 10                 # CRC_DAMAGE_ALERT_FRAMES in capture_cell_diag.c


def _replay(tmp_path: Path, damaged: int, seed: int = 4934) -> Path:
    """N_FRAMES whole frames, `damaged` of them with 8 bytes cut from the middle
    of the escaped frame (never the trailing 0x7E, which escaping keeps unique)."""
    rng = random.Random(seed)
    frames = [hdlc_frame(bytes(rng.getrandbits(8) for _ in range(rng.randint(40, 600))))
              for _ in range(N_FRAMES)]
    for i in rng.sample(range(N_FRAMES), damaged):
        f = frames[i]
        mid = len(f) // 2
        frames[i] = f[:mid - 4] + f[mid + 4:]
        assert frames[i].count(b"\x7e") == 1 and frames[i].endswith(b"\x7e")
    path = tmp_path / f"replay_{damaged}.hdlc"
    path.write_bytes(b"".join(frames))
    return path


def _run(binary: str, replay: Path, **flags) -> CellDiagRun:
    parts = [f"replay={replay}", "stats_interval=0"]
    parts += [f"{k}={v}" for k, v in flags.items()]
    run = CellDiagRun(binary, f"celldiag-{IMEI}:" + ",".join(parts), timeout=60.0).run()
    assert run.control, (run.errors, run.messages)
    return run


def _last_stats(run: CellDiagRun) -> dict:
    stats = [json.loads(c) for c in run.control if '"diag_stats"' in c.replace(" ", "")]
    assert stats, f"no diag_stats line: {run.control}"
    return stats[-1]


def _row(run: CellDiagRun) -> dict:
    assert len(run.crc_census) == 1, f"want ONE DiagCrcCensus row, got {run.crc_census}"
    row = json.loads(run.crc_census[0])
    assert row["schema"] == "diag-crc-census/1", row
    return row


def _loss_alerts(run: CellDiagRun) -> list[tuple[int, str]]:
    return [(f, m) for f, m in zip(run.message_flags, run.messages)
            if "losing bytes" in m]


def test_a_clean_stream_is_checked_frame_by_frame_and_raises_nothing(tmp_path):
    binary = _binary_or_skip()
    run = _run(binary, _replay(tmp_path, 0))

    st = _last_stats(run)
    # The positive control: every frame reached the CRC check.
    assert (st.get("crc_checked"), st.get("crc_ok"), st.get("crc_bad")) == (
        N_FRAMES, N_FRAMES, 0), st
    assert st.get("crc_damage_alerts") == 0, st
    row = _row(run)
    assert (row["crc_checked"], row["crc_ok"], row["crc_bad"]) == (N_FRAMES, N_FRAMES, 0), row
    # The native decoder's own stream is the counter: one pass over the bytes.
    assert row["counter"] == "native", row
    assert row["damage_alerts"] == 0, row
    assert _loss_alerts(run) == [], _loss_alerts(run)


def test_a_stream_losing_byte_runs_is_counted_exactly_and_raises_an_error(tmp_path):
    binary = _binary_or_skip()
    run = _run(binary, _replay(tmp_path, 25))

    st = _last_stats(run)
    assert (st.get("crc_checked"), st.get("crc_ok"), st.get("crc_bad")) == (
        N_FRAMES, N_FRAMES - 25, 25), st
    # stats_interval=0: no cadence ran, so only the final check can have judged
    # this stream. Without it a replay -- or a burst after the last tick -- is
    # counted and never reported.
    assert st.get("crc_damage_alerts") == 1, st
    row = _row(run)
    assert (row["crc_bad"], row["damage_alerts"]) == (25, 1), row

    alerts = _loss_alerts(run)
    assert len(alerts) == 1, alerts
    flag, text = alerts[0]
    assert flag == MSGFLAG_ERROR, f"a loss alert at severity {flag}, not ERROR: {text}"
    assert "25 CRC-bad frame(s)" in text and "checked this session" in text, text


def test_damage_below_the_floor_is_counted_but_not_alarmed(tmp_path):
    binary = _binary_or_skip()
    run = _run(binary, _replay(tmp_path, FLOOR - 1))

    st = _last_stats(run)
    assert st.get("crc_bad") == FLOOR - 1, st
    assert st.get("crc_damage_alerts") == 0, st
    assert _row(run)["crc_bad"] == FLOOR - 1
    assert _loss_alerts(run) == [], _loss_alerts(run)


def test_the_floor_itself_alarms(tmp_path):
    binary = _binary_or_skip()
    run = _run(binary, _replay(tmp_path, FLOOR))
    assert _last_stats(run).get("crc_damage_alerts") == 1
    assert len(_loss_alerts(run)) == 1


def test_the_row_is_sent_after_the_final_flush_so_a_torn_last_frame_counts(tmp_path):
    """A live stop almost always ends mid-frame: the partial last frame is one
    of the two edge frames every healthy capture carries. It exists only once
    the stream's residual is flushed at end-of-stream, so a row sent BEFORE that
    flush under-counts."""
    binary = _binary_or_skip()
    whole = _replay(tmp_path, 3).read_bytes()
    torn = whole + hdlc_frame(bytes(range(64)))[:40]   # no trailing 0x7E
    replay = tmp_path / "torn.hdlc"
    replay.write_bytes(torn)
    row = _row(_run(binary, replay))
    assert (row["frames"], row["crc_bad"]) == (N_FRAMES + 1, 3 + 1), row
