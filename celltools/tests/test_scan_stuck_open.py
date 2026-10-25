# SPDX-License-Identifier: Apache-2.0
"""A scan probe's open() is bounded: a tty still closing does not cost ~30 s.

## The hazard

A scan probe writes ``AT\\r\\n`` into every candidate tty. On a function that
never reads its input -- the non-target Foxconn T99W175's NMEA tty -- the bytes
stay unsent, and the last ``close()`` waits out the port's 30 s ``closing_wait``.
That close runs on a detached thread, so the prober itself does not wait. But
the tty stays in its final close for those 30 s, and Linux's ``tty_open()``
retries a tty in that state instead of failing it, ``O_NONBLOCK`` or not. So the
next ``open()`` of the port blocks: a sibling source's scan, or the same
helper's own rescan. Unbounded, that costs a cellat source Kismet's whole 30 s
command deadline.

The bound: both scanners' ``serial_open()`` open through ``diag_probe_open()``,
which runs the ``open()`` on a worker thread and gives up at
``DIAG_PROBE_OPEN_DEADLINE_MS`` (1000 ms) with ``ETIMEDOUT``.

## How a stuck open is built offline

No fd a test can make reproduces a tty in its final close (a pty never waits in
close). What CAN be reproduced is its only effect on the scanner: an ``open()`` of
one path that does not return. ``stuck_open.so``, compiled here and injected with
``LD_PRELOAD``, sleeps ``STUCK_OPEN_MS`` inside ``open()`` of ``STUCK_OPEN_PATH``
and then performs the real open. Everything else in the binary is real.

The stuck path is a SILENT ``FakeAtModem`` (openable, never answers AT), so that
a regressed binary, which waits out the sleep and then really opens it, still
finds no modem there -- and the test can only pass on timing and on the message.

## What each test pins

* ``test_the_shim_blocks_open_of_exactly_the_named_path`` -- the positive control:
  the gauge reads positive on a known input, and leaves every other path alone.
* ``test_celldiag_scan_skips_a_port_whose_open_does_not_return`` -- the bound, in
  celldiag's real IMEI scan: the target behind the stuck port resolves in well
  under the stall, the port is named ``open-timeout``, and no rescan is spent.
* ``test_a_timed_out_open_is_not_busy_and_earns_no_rescan`` -- the gate: with no
  target to find, the skipped port must not earn a busy-port rescan.
* ``test_cellat_serial_open_gives_up_at_its_deadline`` -- the same bound in
  cellat's copy of ``serial_open()`` (``at_serial.inc``), through
  ``cellat_serial_probe``. cellat's scan cannot be driven offline without also
  AT-probing this host's real modems (``CELLAT_EXTRA_PORTS`` ADDS to the scan),
  so this is the cellat-side proof.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
IMEI = "353456789047380"
FIRMWARE = "RM500QAEAAR11A03M4G"

#: How long the shim holds the stuck open shut. Far past the 1000 ms deadline and
#: far short of the harness timeouts, so "bounded" and "waited it out" cannot be
#: confused: a regressed scan takes >= this, a fixed one ~1 s plus the AT dialogue.
STALL_MS = 8000

#: What the scan says about a port it skipped at the open deadline.
OPEN_TIMEOUT_NOTE = "open() gave up at 1000 ms and skipped them"

SHIM_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void stall_if_stuck(const char *path) {
    const char *stuck = getenv("STUCK_OPEN_PATH");
    const char *ms = getenv("STUCK_OPEN_MS");
    if (!stuck || !ms || !path || strcmp(path, stuck) != 0)
        return;
    long n = atol(ms);
    struct timespec ts = { n / 1000, (n % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0)
        ;
}

#define OPEN_SHIM(name)                                                    \
    int name(const char *path, int flags, ...) {                           \
        static int (*real)(const char *, int, ...);                        \
        mode_t mode = 0;                                                   \
        if (flags & (O_CREAT | O_TMPFILE)) {                               \
            va_list ap;                                                    \
            va_start(ap, flags);                                           \
            mode = (mode_t)va_arg(ap, int);                                \
            va_end(ap);                                                    \
        }                                                                  \
        if (!real)                                                         \
            real = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, #name); \
        stall_if_stuck(path);                                              \
        return real(path, flags, mode);                                    \
    }

OPEN_SHIM(open)
OPEN_SHIM(open64)
"""


@pytest.fixture(scope="module")
def shim(tmp_path_factory) -> Path:
    # Before cc: the shim is not portable (O_TMPFILE, -ldl), and LD_PRELOAD does
    # not apply off Linux anyway -- dyld uses DYLD_INSERT_LIBRARIES, which SIP
    # strips. A skip, not a port. On Linux a compile failure stays
    # an ERROR: there it is a real breakage.
    if not sys.platform.startswith("linux"):
        pytest.skip(f"LD_PRELOAD interposition is Linux-only; this host is {sys.platform}")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler to build the LD_PRELOAD open() shim")
    d = tmp_path_factory.mktemp("stuck_open")
    src, so = d / "stuck_open.c", d / "stuck_open.so"
    src.write_text(SHIM_C)
    subprocess.run([cc, "-shared", "-fPIC", "-o", str(so), str(src), "-ldl"],
                   check=True, capture_output=True)
    return so


def _stuck_env(shim: Path, path: str, ms: int = STALL_MS) -> dict:
    env = dict(os.environ)
    env.update(LD_PRELOAD=str(shim), STUCK_OPEN_PATH=path, STUCK_OPEN_MS=str(ms))
    return env


def _serial_probe_or_fail() -> Path:
    """cellat_serial_probe, required FRESH: a binary older than the code it is
    meant to prove would pass or fail for reasons unrelated to that code."""
    b = ROOT / "capture_cell_at" / "cellat_serial_probe"
    if not b.exists():
        pytest.skip(f"{b} not built (make -C capture_cell_at)")
    sources = [ROOT / "capture_cell_at" / "at_serial.inc",
               ROOT / "capture_cell_at" / "cellat_serial_probe.c",
               ROOT / "capture_cell_diag" / "diag_probeclose.c",
               ROOT / "capture_cell_diag" / "diag_probeclose.h"]
    newest = max(sources, key=lambda p: p.stat().st_mtime)
    if newest.stat().st_mtime > b.stat().st_mtime:
        pytest.fail(f"{b.name} is older than {newest.name}; rebuild it "
                    f"(make -C capture_cell_at) -- a stale probe measures old code")
    return b


def test_the_shim_blocks_open_of_exactly_the_named_path(shim, tmp_path):
    """Positive control: the shim stalls open() of STUCK_OPEN_PATH and nothing else.

    Without it, a fast scan below could mean "the shim never engaged" rather than
    "the deadline skipped a stuck port"."""
    stuck, other = tmp_path / "stuck", tmp_path / "other"
    stuck.write_text("")
    other.write_text("")
    code = ("import os,sys,time\n"
            "for p in sys.argv[1:]:\n"
            "    t=time.monotonic(); os.close(os.open(p, os.O_RDONLY))\n"
            "    print(p, int((time.monotonic()-t)*1000))\n")
    out = subprocess.run([sys.executable, "-c", code, str(other), str(stuck)],
                         env=_stuck_env(shim, str(stuck), 600),
                         capture_output=True, text=True, check=True).stdout
    ms = {Path(ln.split()[0]).name: int(ln.split()[1]) for ln in out.splitlines()}
    assert ms["stuck"] >= 550, f"the shim did not stall the named path: {ms}"
    assert ms["other"] < 300, f"the shim stalled a path it was not given: {ms}"


def test_celldiag_scan_skips_a_port_whose_open_does_not_return(shim, monkeypatch):
    """The bound, in celldiag's real IMEI scan.

    The scan meets the stuck port FIRST (``CELLDIAG_SCAN_PORTS`` keeps its order
    for paths with no USB topology), then the target. Without the bound the
    scan sits in open() for the whole stall, so the model resolves only after
    >= STALL_MS and no port is ever named.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeAtModem(imei="353456789047398", firmware="X", silent=True) as nmea, \
            FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", f"{nmea.port} {at.port}")
        for k, v in _stuck_env(shim, nmea.port).items():
            monkeypatch.setenv(k, v)
        definition = (f"celldiag-{IMEI}:diagport={dg.port},nomask=true,"
                      f"stats_interval=0")
        resolved_at: list[float] = []
        t0 = time.monotonic()

        def resolved(run: CellDiagRun) -> bool:
            done = any(f"{FIRMWARE} IMEI:{IMEI} DIAG opened" in m
                       for m in run.messages)
            if done and not resolved_at:
                resolved_at.append(time.monotonic() - t0)
            return done or any("bring-up failed" in m for m in run.messages)

        run = CellDiagRun(binary, definition, timeout=40.0,
                          stop_when=resolved).run()
        at_cmds, nmea_cmds = list(at.commands), list(nmea.commands)
        stuck_name = Path(nmea.port).name   # inside: the PTY closes with the block

    assert resolved_at, (
        f"the target behind the stuck port never resolved; messages={run.messages!r}")
    assert resolved_at[0] < STALL_MS / 1000 - 2, (
        f"the scan resolved the target only after {resolved_at[0]:.1f} s -- it "
        f"waited out the {STALL_MS} ms stall instead of skipping the port at the "
        f"deadline")
    notes = [m for m in run.messages if OPEN_TIMEOUT_NOTE in m]
    assert len(notes) == 1 and f"{stuck_name}(open-timeout)" in notes[0], (
        f"the skipped port must be named once as open-timeout; got {notes!r}")
    assert not any("rescanning once in" in m for m in run.messages), (
        "a timed-out open is not a busy port and must not earn a rescan")
    assert nmea_cmds == [], (
        f"the stuck port was written to after all: {nmea_cmds!r}")
    assert "AT+CGSN" in at_cmds, at_cmds


def test_a_timed_out_open_is_not_busy_and_earns_no_rescan(shim, monkeypatch):
    """The gate: a port skipped at the open deadline is a tty mid-close, never a
    modem another source is probing -- so a scan that finds nothing ELSE must not
    spend a busy-port rescan on it (a rescan would only pay the deadline again).

    The target is absent on purpose: the rescan runs only when the scan came back
    empty, so the test above -- which finds its target -- cannot see this gate.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei="353456789047398", firmware="X", silent=True) as nmea, \
            FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", nmea.port)
        for k, v in _stuck_env(shim, nmea.port).items():
            monkeypatch.setenv(k, v)
        definition = (f"celldiag-{IMEI}:diagport={dg.port},nomask=true,"
                      f"stats_interval=0")

        def brought_up(run: CellDiagRun) -> bool:
            return any(("Cell DIAG source" in m and "opened (live" in m)
                       or "bring-up failed" in m for m in run.messages)

        run = CellDiagRun(binary, definition, timeout=40.0,
                          stop_when=brought_up).run()
        stuck_name = Path(nmea.port).name

    assert any(OPEN_TIMEOUT_NOTE in m and f"{stuck_name}(open-timeout)" in m
               for m in run.messages), (
        f"positive control: the port must have hit the open deadline; "
        f"messages={run.messages!r}")
    assert not any("rescanning once in" in m for m in run.messages), (
        f"a timed-out open counted as a busy port and earned a rescan: "
        f"{[m for m in run.messages if 'rescan' in m]!r}")
    assert run.open_code == 1, (run.open_code, run.open_message)


def test_cellat_serial_open_gives_up_at_its_deadline(shim):
    """cellat's copy of serial_open() (at_serial.inc) is bounded the same way.

    Unbounded, the probe sits in open() for the whole stall, then opens
    the port -- exit 0 or an AT failure after >= STALL_MS, never ETIMEDOUT."""
    probe = _serial_probe_or_fail()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at:
        t0 = time.monotonic()
        proc = subprocess.run([str(probe), at.port, "AT+CGSN"],
                              env=_stuck_env(shim, at.port),
                              capture_output=True, text=True, timeout=30)
        took = time.monotonic() - t0
        cmds = list(at.commands)
    assert proc.returncode == 1, (proc.returncode, proc.stderr)
    assert "Connection timed out" in proc.stderr, (
        f"serial_open() must fail with ETIMEDOUT at its deadline; "
        f"stderr={proc.stderr!r}")
    assert 0.9 <= took < 3.0, (
        f"the open gave up after {took:.2f} s; expected ~1 s, not the "
        f"{STALL_MS} ms stall")
    assert cmds == [], f"a port that never opened was written to: {cmds!r}"
