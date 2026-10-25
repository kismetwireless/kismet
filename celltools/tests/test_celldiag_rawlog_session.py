"""A reopen never shrinks a ``rawlog=`` tee -- one tee per capture session.

Every reopen of a celldiag source (a restart-to-apply toggle, the whole-modem
switch, Kismet's automatic error reopen) is a new helper process. If each one
opened the tee ``O_TRUNC``, a fixed ``rawlog=`` path would silently hold only
the last session beside a kismetdb holding all of them. A session that finds
the path already holding an earlier session diverts to a stamped sibling and
says so.

These tests drive the REAL binary over the datasource IPC in replay mode, the
same path a live source's tee takes (the open-time ``rawlog=`` sink is opened by
the capture thread for replay and live alike). Each session replays DIFFERENT
bytes, so "the file equals session N's input" can only be true of the file that
session wrote.

The assertions are on content, not on the diverted file names: sessions run
back to back can share a UTC second, and the name then counts (``-2``) rather
than stamps. The C unit test (``test_diag_rawlog.c``) pins the naming.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_diag_modem import hdlc_frame  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

IMEI = "123456789012347"


def _replay(tmp_path: Path, name: str, n: int, width: int) -> Path:
    """A replay input distinguishable from its siblings by length AND bytes."""
    p = tmp_path / name
    p.write_bytes(b"".join(hdlc_frame(bytes((0x10, 0x00)) + bytes([width]) * width)
                           for _ in range(n)))
    return p


def _session(binary: str, replay: Path, out: Path) -> CellDiagRun:
    run = CellDiagRun(binary,
                      f"celldiag-{IMEI}:replay={replay},"
                      f"rawlog={out}",
                      timeout=5.0).run()
    time.sleep(0.2)
    return run


def _tees(out: Path) -> list[Path]:
    """Every tee in the directory: the operator's path and its stamped siblings,
    never the ``.capture_meta.json`` / ``.clock_anchor.jsonl`` companions."""
    return sorted(p for p in out.parent.iterdir()
                  if p.name.startswith(out.stem) and p.suffix == out.suffix)


def test_three_sessions_on_one_fixed_path_keep_every_session(tmp_path):
    binary = _binary_or_skip()
    inputs = [_replay(tmp_path, "a.in", 50, 20),
              _replay(tmp_path, "b.in", 30, 24),
              _replay(tmp_path, "c.in", 70, 12)]
    out = tmp_path / "tees" / "cap.hdlc"
    out.parent.mkdir()

    runs = [_session(binary, r, out) for r in inputs]

    # Positive control: session 1 wrote the operator's own path -- the first
    # open of a source is never diverted.
    assert out.read_bytes() == inputs[0].read_bytes(), (runs[0].errors,
                                                        runs[0].messages)
    tees = _tees(out)
    assert len(tees) == 3, [p.name for p in tees]
    # Each session's bytes survive in exactly one file of their own.
    contents = sorted(p.read_bytes() for p in tees)
    assert contents == sorted(r.read_bytes() for r in inputs)


def test_a_diverted_session_says_so_and_its_companion_follows(tmp_path):
    binary = _binary_or_skip()
    first = _replay(tmp_path, "a.in", 50, 20)
    second = _replay(tmp_path, "b.in", 30, 24)
    out = tmp_path / "cap.hdlc"

    _session(binary, first, out)
    run = _session(binary, second, out)

    notes = [m for m in run.messages if "already holds an earlier session" in m]
    assert len(notes) == 1, run.messages
    (sibling,) = [p for p in _tees(out) if p != out]
    assert str(sibling) in notes[0] and str(out) in notes[0], notes[0]
    assert sibling.read_bytes() == second.read_bytes()
    # The "teeing to" line names where the bytes actually went.
    assert any(f"teeing raw DIAG stream to {sibling}" in m for m in run.messages), \
        run.messages
    # Each session has its own companion; the first one's is not rewritten.
    first_meta = Path(f"{out}.capture_meta.json")
    second_meta = Path(f"{sibling}.capture_meta.json")
    assert first_meta.is_file() and second_meta.is_file()
    assert sibling.name in second_meta.read_text()
    assert sibling.name not in first_meta.read_text()


def test_an_empty_existing_file_is_reused_not_diverted(tmp_path):
    """``touch cap.hdlc`` before a drive is not an earlier session."""
    binary = _binary_or_skip()
    src = _replay(tmp_path, "a.in", 50, 20)
    out = tmp_path / "cap.hdlc"
    out.touch()

    run = _session(binary, src, out)

    assert out.read_bytes() == src.read_bytes(), (run.errors, run.messages)
    assert _tees(out) == [out]
    assert not any("already holds" in m for m in run.messages), run.messages
