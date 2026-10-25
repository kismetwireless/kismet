"""cellat ``qmifeed=auto``: the QMI feed that ships in this tree.

``qmifeed=<command>`` runs any feed command; ``qmifeed=auto`` needs nothing
outside the source tree. The feed ships as ``capture_cell_at/qmifeed/`` (standard library only), and ``qmifeed=auto`` finds
it beside the binary.

Pinned here, end to end through the compiled binary, a fake AT modem and a fake
``qmicli`` on ``$PATH``, with the binary COPIED into a bare tree so nothing
outside that tree can be what answered:

* ``auto`` runs the tree's own feed with the system ``python3`` -- no venv, no
  ``PYTHONPATH`` -- and its cells arrive as QMI observations;
* arguments after ``auto`` reach the feed;
* a tree without the feed refuses ``auto`` with the fix in the message, and the
  AT survey carries on.

The resolver's walk and shell quoting are C-tested in
``capture_cell_at/test_cellat_qmifeed.c``.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun
from installed_datadir import forget_installed_datadir
from test_cellat_ipc import _binary_or_skip
from test_qmifeed_kismet_qmi_feed import CELL_EM9291, IDS_EM9291, SIGNAL_EM9291

IMEI = "351234567890123"
FEED_SRC = Path(__file__).resolve().parents[2] / "capture_cell_at" / "qmifeed"


def _tree(tmp_path: Path, *, feed: bool) -> Path:
    """A bare tree: the binary, and (optionally) the feed package beside it."""
    capdir = tmp_path / "tree" / "capture_cell_at"
    capdir.mkdir(parents=True)
    shutil.copy2(_binary_or_skip(), capdir / "kismet_cap_cell_at")
    # A bare tree is judged by its tree: not by an installed qmifeed/.
    forget_installed_datadir(capdir / "kismet_cap_cell_at")
    if feed:
        shutil.copytree(FEED_SRC, capdir / "qmifeed",
                        ignore=shutil.ignore_patterns("__pycache__"))
    return capdir / "kismet_cap_cell_at"


def _fake_qmicli(tmp_path: Path) -> Path:
    """A ``qmicli`` answering from canned output, for the fake modem's IMEI."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fx = tmp_path / "fx"
    fx.mkdir()
    (fx / "ids").write_text(IDS_EM9291.replace("359876543210987", IMEI))
    (fx / "cell").write_text(CELL_EM9291)
    (fx / "sig").write_text(SIGNAL_EM9291)
    q = bindir / "qmicli"
    q.write_text("#!/bin/sh\nfor a; do case $a in\n"
                 f"--dms-get-ids) cat {fx}/ids;;\n"
                 f"--nas-get-cell-location-info) cat {fx}/cell;;\n"
                 f"--nas-get-signal-info) cat {fx}/sig;;\nesac; done\n")
    q.chmod(0o755)
    return bindir


def _qmi(run: CaptureRun) -> "list[dict]":
    return [d for d in map(json.loads, run.observations)
            if d.get("prov", {}).get("src") == "qmi"]


def _at(run: CaptureRun) -> "list[dict]":
    return [d for d in map(json.loads, run.observations)
            if d.get("prov", {}).get("src") != "qmi"]


def _run(binary: Path, qmifeed: str, stop_when, monkeypatch, tmp_path) -> CaptureRun:
    # A stranger's environment: no venv, no import path into anything else.
    for k in ("PYTHONPATH", "VIRTUAL_ENV", "PYTHONHOME", "CELLAT_IMEI"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PATH", f"{_fake_qmicli(tmp_path)}:/usr/bin:/bin")
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        definition = f"cellat-{IMEI}:atport={modem.port},debug=false,qmifeed={qmifeed}"
        return CaptureRun(str(binary), definition, timeout=30.0,
                          stop_when=stop_when).run()


def test_auto_runs_the_trees_own_feed(tmp_path, monkeypatch):
    binary = _tree(tmp_path, feed=True)
    run = _run(binary, "auto -d /dev/fake --interval 1",
               lambda r: len(_qmi(r)) >= 1 and len(_at(r)) >= 1,
               monkeypatch, tmp_path)
    assert run.open_code == 1, run.open_message
    started = [m for m in run.messages if "qmifeed started" in m]
    assert started, run.messages
    script = binary.parent / "qmifeed" / "kismet_qmi_feed.py"
    # The system python3 on the tree's own file, with auto's arguments passed on.
    assert f"exec python3 '{script}' -d /dev/fake --interval 1" in started[0]
    cells = _qmi(run)
    assert cells, run.messages
    assert all(c["prov"]["imei"] == IMEI for c in cells)
    assert any(c.get("is_serving") and c.get("pci") == 242 for c in cells), cells
    assert _at(run), "AT observations stopped when the feed was added"


def test_auto_without_the_feed_refuses_and_at_polling_continues(tmp_path, monkeypatch):
    binary = _tree(tmp_path, feed=False)
    run = _run(binary, "auto", lambda r: len(_at(r)) >= 2, monkeypatch, tmp_path)
    assert run.open_code == 1, run.open_message
    refused = [m for m in run.messages if "qmifeed=auto" in m]
    assert refused, run.messages
    assert "qmifeed/kismet_qmi_feed.py" in refused[0]
    assert "qmifeed=<command>" in refused[0]
    assert not any("qmifeed started" in m for m in run.messages)
    assert _qmi(run) == []
    assert len(_at(run)) >= 2
