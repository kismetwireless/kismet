# SPDX-License-Identifier: Apache-2.0
"""A disabled celldiag source says "disabled", not that its decoder died.

``enabled=false`` leaves a celldiag source defined, open and idle: no port, no
handshake, no decoder started. Kismet shows it as **running**, because its open
succeeded. Without a ``diag_stats`` JSON line (the server's fields are set from
it, not from the human ``stats:`` text line), ``helper_alive`` would sit at its
default 0 and the panel would render an intentionally idle source as a red
"decoder dead -- observations have stopped".

So the idle loop sends ``{"helper_alive":0,"mask_preset":"disabled"}``
at once (not a 30 s ``stats_interval`` later) and on the cadence after, and
the panel renders a neutral "capture disabled". Both facts are true
measurements; no counter is sent, because nothing was measured and zeros would
read as "running and seeing nothing".
"""
from __future__ import annotations

import json
import time

from kismet_capture_ipc import CaptureRun
from celldiag_run import CellDiagRun, _binary_or_skip
from test_celldiag_server_routes import KismetServer, _server_or_skip

IMEI = "000000000000000"
DEF = f"celldiag-{IMEI}:enabled=false"


def _disabled_lines(run: CaptureRun) -> "list[dict]":
    out = []
    for s in run.control:
        d = json.loads(s)
        if d.get("type") == "diag_stats" and d.get("mask_preset") == "disabled":
            out.append(d)
    return out


def test_a_disabled_source_reports_disabled_at_once_with_no_counters():
    binary = _binary_or_skip()
    t0 = time.monotonic()
    run = CellDiagRun(binary, DEF, timeout=6.0,
                      stop_when=lambda r: bool(_disabled_lines(r))).run()
    elapsed = time.monotonic() - t0
    assert run.open_code in (1, None), (run.open_code, run.errors)
    lines = _disabled_lines(run)
    assert lines, (
        "a disabled source sent no structured stats line, so the server keeps "
        f"helper_alive=0 with nothing saying why. control={run.control}")
    assert elapsed < 5.0, (
        f"the first disabled line took {elapsed:.1f}s -- it must go out at "
        "once, not after a stats_interval")
    d = lines[0]
    assert d["helper_alive"] == 0, d
    for k in ("obs_total", "bytes_read", "obs_per_sec", "last_obs_epoch"):
        assert k not in d, (k, d)
    assert run.observations == []


def test_the_server_reports_the_disabled_preset(tmp_path):
    server = _server_or_skip()
    # The line comes from the helper binary the server runs, so the helper
    # must be present for this to mean anything.
    _binary_or_skip()
    with KismetServer(tmp_path, DEF) as ks:
        deadline = time.monotonic() + 30
        row = None
        while time.monotonic() < deadline:
            row = ks.source()
            if row and row.get("kismet.datasource.celldiag.mask_preset") == "disabled":
                break
            time.sleep(0.5)
        assert row and row.get("kismet.datasource.celldiag.mask_preset") == "disabled", (
            f"mask_preset never reached 'disabled': "
            f"{ {k: v for k, v in (row or {}).items() if 'celldiag' in k} }\n{ks.tail()}")
        assert row["kismet.datasource.celldiag.helper_alive"] == 0
        assert row["kismet.datasource.running"], (
            "the premise: Kismet shows a disabled source as RUNNING, which is "
            "why the panel needs the preset to tell it apart")
    assert server
