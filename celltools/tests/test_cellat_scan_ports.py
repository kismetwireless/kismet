# SPDX-License-Identifier: Apache-2.0
"""cellat's real IMEI scan, driven offline against PTY fakes only.

## Why ``CELLAT_SCAN_PORTS``

celldiag has ``CELLDIAG_SCAN_PORTS``, which replaces its scan universe, so its
tests point the real scan at a PTY fake modem and nothing else. cellat's
``CELLAT_EXTRA_PORTS`` adds to ``/dev/ttyUSB*`` + ``/dev/ttyACM*`` + the non-USB AT
nodes, so a test built on it would write ``AT`` into every real modem on the
host. ``CELLAT_SCAN_PORTS`` is the replacing twin, and this file uses it to test
the scan's own behaviour (the open deadline, the busy-port rescan, and the
window between "found" and "opened for use") through the compiled binary with
no host tty touched.

## How "no host tty is opened" is measured, not assumed

``scan_shim.so``, compiled here and injected with ``LD_PRELOAD``, appends the path
of every ``open()`` under ``/dev/`` to ``OPEN_LOG``. Every test asserts that no
logged path is a host modem node, and the positive control asserts the log DID
record the fake's PTY -- a gauge that has never read positive cannot be read as
negative.

The same shim carries the two faults a scan meets in the field:

* ``STUCK_OPEN_PATH`` / ``STUCK_OPEN_MS`` -- ``open()`` of one path does not
  return for a while: a tty still in its final close after a sibling's probe.
* ``CLAIM_PATH`` / ``CLAIM_ON_OPEN_N`` / ``CLAIM_HOLD_MS`` -- on the Nth
  ``open()`` of the path, a forked child takes the port's exclusive ``flock``
  from outside the helper (a real second process, the same claim a sibling
  source's probe takes) and holds it for ``CLAIM_HOLD_MS``. The helper's own
  open proceeds only once the child holds the claim, so the kernel refuses the
  helper's ``flock`` with ``EWOULDBLOCK`` as it would on real hardware.

## Why the identify-to-open test needs the Nth open

cellat's scan identifies the modem on the first open of the port, releases it,
then opens it again for ongoing use. A sibling's scan can take the claim in
that window, failing the launch with ``Failed to open /dev/ttyUSB5: Resource
temporarily unavailable``. ``CLAIM_ON_OPEN_N=2`` puts a real claim exactly
there, every time.
"""
from __future__ import annotations

import fcntl
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from test_cellat_ipc import CellAtRun, _binary_or_skip, _opened  # noqa: E402

IMEI = "351234567847530"
OTHER_IMEI = "359876543247531"
FIRMWARE = "RM500QAEAAR11A03M4G"

#: Any logged open of one of these is a host modem node the scan must not touch.
HOST_MODEM_NODE = re.compile(r"^/dev/(ttyUSB|ttyACM|wwan|mhi_)")

#: What the scan says about a port skipped at the open deadline.
OPEN_TIMEOUT_NOTE = "open() gave up at 1000 ms and skipped them"

#: Far past the 1000 ms open deadline and far short of the harness timeouts.
STALL_MS = 8000

SHIM_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

typedef int (*open_fn)(const char *, int, ...);
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int claim_opens_seen;

static void sleep_ms(long n) {
    struct timespec ts = { n / 1000, (n % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0)
        ;
}

static void log_open(open_fn real, const char *path) {
    const char *log = getenv("OPEN_LOG");
    if (!log || !path || strncmp(path, "/dev/", 5) != 0)
        return;
    int fd = real(log, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
        return;
    char line[512];
    int n = snprintf(line, sizeof(line), "%s\n", path);
    if (n > 0)
        (void)!write(fd, line, (size_t)n);
    close(fd);
}

static void stall_if_stuck(const char *path) {
    const char *stuck = getenv("STUCK_OPEN_PATH");
    const char *ms = getenv("STUCK_OPEN_MS");
    if (stuck && ms && path && strcmp(path, stuck) == 0)
        sleep_ms(atol(ms));
}

/* On the CLAIM_ON_OPEN_N-th open of CLAIM_PATH, a forked child claims the port
 * and holds it; this open continues only once the claim is held. */
static void claim_if_due(open_fn real, const char *path) {
    const char *target = getenv("CLAIM_PATH");
    const char *nth = getenv("CLAIM_ON_OPEN_N");
    const char *hold = getenv("CLAIM_HOLD_MS");
    if (!target || !nth || !hold || !path || strcmp(path, target) != 0)
        return;
    pthread_mutex_lock(&mu);
    int n = ++claim_opens_seen;
    pthread_mutex_unlock(&mu);
    if (n != atoi(nth))
        return;
    int p[2];
    if (pipe(p) != 0)
        return;
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        int fd = real(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
        char ok = (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0) ? '1' : '0';
        (void)!write(p[1], &ok, 1);
        close(p[1]);
        sleep_ms(atol(hold));
        _exit(0);
    }
    close(p[1]);
    char ok = '0';
    if (pid > 0)
        (void)!read(p[0], &ok, 1);
    close(p[0]);
    const char *log = getenv("CLAIM_LOG");
    if (log) {
        int fd = real(log, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
        if (fd >= 0) {
            char line[512];
            int m = snprintf(line, sizeof(line), "claimed open#%d held=%c\n", n, ok);
            if (m > 0)
                (void)!write(fd, line, (size_t)m);
            close(fd);
        }
    }
}

#define OPEN_SHIM(name)                                                    \
    int name(const char *path, int flags, ...) {                           \
        static open_fn real;                                               \
        mode_t mode = 0;                                                   \
        if (flags & (O_CREAT | O_TMPFILE)) {                               \
            va_list ap;                                                    \
            va_start(ap, flags);                                           \
            mode = (mode_t)va_arg(ap, int);                                \
            va_end(ap);                                                    \
        }                                                                  \
        if (!real)                                                         \
            real = (open_fn)dlsym(RTLD_NEXT, #name);                       \
        log_open(real, path);                                              \
        stall_if_stuck(path);                                              \
        claim_if_due(real, path);                                          \
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
        pytest.skip("no C compiler to build the LD_PRELOAD scan shim")
    d = tmp_path_factory.mktemp("scan_shim")
    src, so = d / "scan_shim.c", d / "scan_shim.so"
    src.write_text(SHIM_C)
    subprocess.run([cc, "-shared", "-fPIC", "-o", str(so), str(src), "-ldl",
                    "-pthread"], check=True, capture_output=True)
    return so


@pytest.fixture
def scan(shim, tmp_path, monkeypatch):
    """Arm the shim for one run; returns a function giving back the opened paths."""
    open_log = tmp_path / "opens.log"
    claim_log = tmp_path / "claims.log"
    monkeypatch.setenv("LD_PRELOAD", str(shim))
    monkeypatch.setenv("OPEN_LOG", str(open_log))
    monkeypatch.setenv("CLAIM_LOG", str(claim_log))

    class _Scan:
        def ports(self, *paths: str) -> None:
            monkeypatch.setenv("CELLAT_SCAN_PORTS", " ".join(paths))

        def stuck(self, path: str, ms: int = STALL_MS) -> None:
            monkeypatch.setenv("STUCK_OPEN_PATH", path)
            monkeypatch.setenv("STUCK_OPEN_MS", str(ms))

        def claim(self, path: str, on_open: int, hold_ms: int) -> None:
            monkeypatch.setenv("CLAIM_PATH", path)
            monkeypatch.setenv("CLAIM_ON_OPEN_N", str(on_open))
            monkeypatch.setenv("CLAIM_HOLD_MS", str(hold_ms))

        @staticmethod
        def opened() -> list[str]:
            return open_log.read_text().split() if open_log.exists() else []

        @staticmethod
        def claims() -> list[str]:
            return claim_log.read_text().splitlines() if claim_log.exists() else []

    # The binary's EXTRA knob must not leak in from the operator's shell: it adds.
    monkeypatch.delenv("CELLAT_EXTRA_PORTS", raising=False)
    return _Scan()


def _host_nodes(opened: list[str]) -> list[str]:
    return sorted({p for p in opened if HOST_MODEM_NODE.match(p)})


def _run(binary: str, timeout: float = 30.0) -> CellAtRun:
    return CellAtRun(binary, f"cellat-{IMEI}", timeout=timeout,
                     stop_when=_opened).run()


# ── the replacing scan universe ─────────────────────────────────────────────────


def test_the_scan_reaches_a_pty_named_by_CELLAT_SCAN_PORTS_and_no_host_tty(scan):
    """Positive control: the fake saw the identify dialogue, the source opened,
    and the open log recorded the PTY -- the gauge reads positive.

    This test cannot catch a universe that leaks (CELLAT_SCAN_PORTS adding to
    the host scan instead of replacing it): its target is found on the first
    named port and the scan stops there. The absent-target and busy-target
    tests below catch that mutation, because their scan walks past every named
    port. Every test asserts no host node was opened; those are the ones where
    the assertion has teeth.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, extra=QENG_SERVING) as at:
        scan.ports(at.port)
        run = _run(binary)
        port, cmds = at.port, list(at.commands)
    opened = scan.opened()
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert "AT+CGSN" in cmds, f"the scan never probed the named PTY: {cmds!r}"
    assert port in opened, (
        f"positive control: the open log never recorded the fake's PTY, so its "
        f"silence about host ttys means nothing. Logged: {opened!r}")
    assert _host_nodes(opened) == [], (
        f"CELLAT_SCAN_PORTS must REPLACE the universe; the scan opened host "
        f"modem nodes: {_host_nodes(opened)!r}")
    assert not any("rescan" in m for m in run.messages), run.messages


def test_a_path_named_twice_is_scanned_once(scan):
    """The universe is a set: naming the target twice probes it once."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=OTHER_IMEI, firmware=FIRMWARE) as other:
        scan.ports(other.port, other.port)
        run = _run(binary)
        cmds = list(other.commands)
    assert run.open_code == 0, (run.open_code, run.open_message)
    assert cmds.count("AT+CGSN") == 1, (
        f"a path named twice was probed {cmds.count('AT+CGSN')} times: {cmds!r}")
    # An empty scan must say not found, not "Failed to open <garbage>": the
    # result buffer of find_port_by_imei() must be initialized.
    assert f"Modem IMEI {IMEI} not found" in (run.open_message or ""), (
        run.open_message)
    assert _host_nodes(scan.opened()) == []


def test_the_scan_skips_a_stuck_port_at_the_open_deadline(scan):
    """The open deadline in cellat's real scan: the port whose open() does not
    return is named ``open-timeout`` once, the target behind it resolves well
    inside the stall, and no rescan is spent on it. cellat_serial_probe covers
    the open alone; this covers the scan."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=OTHER_IMEI, firmware="X", silent=True) as nmea, \
            FakeAtModem(imei=IMEI, firmware=FIRMWARE, extra=QENG_SERVING) as at:
        scan.ports(nmea.port, at.port)
        scan.stuck(nmea.port)
        t0 = time.monotonic()
        run = _run(binary)
        took = time.monotonic() - t0
        stuck_name = Path(nmea.port).name
        nmea_cmds = list(nmea.commands)
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert took < STALL_MS / 1000 - 2, (
        f"the open took {took:.1f} s -- it waited out the {STALL_MS} ms stall")
    notes = [m for m in run.messages if OPEN_TIMEOUT_NOTE in m]
    assert len(notes) == 1 and f"{stuck_name}(open-timeout)" in notes[0], notes
    assert not any("rescan" in m for m in run.messages), (
        "a timed-out open is not a busy port and must not earn a rescan")
    assert nmea_cmds == [], f"the stuck port was written to: {nmea_cmds!r}"
    assert _host_nodes(scan.opened()) == []


def test_a_port_busy_through_both_passes_costs_one_rescan_and_is_never_written(scan):
    """The busy-port rescan in cellat's real scan: the target's claim is held
    from outside for the whole run. One rescan, the busy count, and the held
    port is skipped -- never shared, never written to."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, extra=QENG_SERVING) as at:
        scan.ports(at.port)
        fd = os.open(at.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            run = _run(binary)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        cmds = list(at.commands)
    notices = [m for m in run.messages if "held by another process; rescanned" in m]
    assert len(notices) == 1, notices
    assert "1 port(s) were held" in notices[0] and "still not found" in notices[0]
    assert run.open_code == 0 and "not found" in (run.open_message or "")
    assert cmds == [], f"a held port was written to: {cmds!r}"
    assert _host_nodes(scan.opened()) == []


def test_a_port_busy_in_the_first_pass_is_found_by_the_rescan(scan):
    """The claim is taken on the scan's FIRST open and released before the
    rescan (which waits >= 250 ms), so the rescan finds the modem."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, extra=QENG_SERVING) as at:
        scan.ports(at.port)
        scan.claim(at.port, on_open=1, hold_ms=100)
        run = _run(binary)
        port = at.port
    assert scan.claims() == ["claimed open#1 held=1"], scan.claims()
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert any(f"1 port(s) were held by another process; rescanned: {port}" in m
               for m in run.messages), run.messages


# ── found, then claimed by a sibling's probe before the ongoing open ─────────────


def test_a_claim_taken_between_identify_and_the_ongoing_open_is_waited_out(scan):
    """The found port's claim is held from outside at the moment of the
    capture's own open, and the source opens anyway.

    Without the wait the open fails with ``Failed to open <pty>: Resource
    temporarily unavailable``, and Kismet's 5 s source retry is the only
    recovery.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, extra=QENG_SERVING) as at:
        scan.ports(at.port)
        scan.claim(at.port, on_open=2, hold_ms=400)
        run = _run(binary)
        port, cmds = at.port, list(at.commands)
    assert scan.claims() == ["claimed open#2 held=1"], (
        f"positive control: the claim must have been taken at the ongoing open; "
        f"claims={scan.claims()!r}")
    assert run.open_code == 1, (
        f"the source lost its found port to a sibling's claim: "
        f"{run.open_code} {run.open_message!r}")
    waits = [m for m in run.messages if "held by another process when the "
             "capture opened it" in m]
    assert len(waits) == 1 and port in waits[0], (
        f"the wait must be reported once, naming the port; messages={run.messages!r}")
    assert "AT+CGMI" in cmds, "the ongoing session never reached the modem"
    assert _host_nodes(scan.opened()) == []


def test_a_claim_held_past_the_budget_still_fails_and_says_why(scan):
    """The bound: a port claimed for longer than the wait budget is a real
    conflict (a second source on one modem), not a sibling's probe. The open
    fails, inside Kismet's 30 s command window, naming the wait."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, extra=QENG_SERVING) as at:
        scan.ports(at.port)
        scan.claim(at.port, on_open=2, hold_ms=15000)
        t0 = time.monotonic()
        run = _run(binary)
        took = time.monotonic() - t0
    assert scan.claims() == ["claimed open#2 held=1"], scan.claims()
    assert run.open_code == 0, (run.open_code, run.open_message)
    msg = run.open_message or ""
    assert "Resource temporarily unavailable" in msg and "another process" in msg, msg
    assert took < 10.0, f"the bounded wait took {took:.1f} s"
