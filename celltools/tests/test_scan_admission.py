# SPDX-License-Identifier: Apache-2.0
"""The port scans open only suspected cell modems, and leave the line
settings of what they do open as they found them.

## The hazard

Both scanners -- cellat's (open-time IMEI scan, rescans, ``--list``) and
celldiag's IMEI scan -- AT-probe candidate ``/dev/ttyUSB*`` and ``/dev/ttyACM*``
ports. A probe sets 115200 raw 8N1, flushes both queues and writes
``AT\\r\\n``. On Linux termios belongs to the tty, not the fd, so a probe that
closes without restoring termios leaves every other reader at 115200: a GNSS
receiver on a CH340 bridge, read at 460800 by a reader that takes no ``flock``,
turns into line noise.

Two rules, each pinned here through the compiled binaries:

* **Which ports are opened at all.** A globbed ttyUSB/ttyACM is admitted
  only when sysfs says "suspected cell modem" (a cellular usb-serial driver, or
  cdc_acm on a cellular vendor id). Anything else is never opened. An
  operator-named port (``CELLAT_SCAN_PORTS`` / ``CELLDIAG_SCAN_PORTS``) is
  admitted as named: that is the escape hatch.
* **What a probe leaves behind.** The probe keeps the termios it found
  and puts it back before it closes.

## How the scan is driven with no host tty touched

``scan_glob_shim.so`` (``LD_PRELOAD``) answers the scans' own device globs:
``/dev/ttyUSB*`` gets the paths in ``SHIM_TTYUSB`` (a PTY) and ``/dev/ttyACM*``,
``/dev/wwan*`` and ``/dev/mhi_*`` get no match -- so the real scan code runs over
a candidate list holding only our PTY, and never reaches a real modem. Every
``open()`` under ``/dev/`` is logged to ``OPEN_LOG``.

A PTY has no ``/sys/class/tty/<name>`` entry, so the real sysfs refuses a
globbed PTY as "no sysfs device" -- exactly the verdict a CH340 bridge gets, one
rule earlier. Each negative is paired with a positive control on the SAME PTY:
named via ``*_SCAN_PORTS`` it IS opened and DOES receive ``AT\\r\\n``. A gauge that
has never read positive cannot be read as negative.
"""
from __future__ import annotations

import os
import re
import select
import shutil
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from test_cellat_ipc import _binary_or_skip as _cellat_or_skip  # noqa: E402
from celldiag_run import _binary_or_skip as _celldiag_or_skip  # noqa: E402

#: Any logged open of one of these is a host modem node the scan must not touch.
HOST_NODE = re.compile(r"^/dev/(ttyUSB|ttyACM|wwan|mhi_)")

IMEI = "351234567848226"
FIRMWARE = "EG25GGBR07A08M2G"

#: Darwin's termios module does not export B460800 (the Python twin of the
#: C side's fallback). Read it here, never in a def or class body, where a
#: missing attribute is an import-time ERROR that interrupts a multi-file run.
B460800 = getattr(termios, "B460800", None)

SHIM_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <glob.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int (*open_fn)(const char *, int, ...);

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
        return real(path, flags, mode);                                    \
    }

OPEN_SHIM(open)
OPEN_SHIM(open64)

/* The scans' device globs get a fake universe; every other pattern (the PTY a
 * test NAMES in *_SCAN_PORTS, which the scan globs too) goes to the real glob.
 * Returns -1 for "not ours". glob and glob64 differ only in the type of their
 * glob_t (the readdir/stat hooks, unused here), so one body serves both. */
#define FAKE_GLOB(fname, gtype)                                            \
    static int fname(const char *pattern, gtype *g) {                      \
        const char *list = NULL;                                           \
        if (strcmp(pattern, "/dev/ttyUSB*") == 0)                          \
            list = getenv("SHIM_TTYUSB");                                  \
        else if (strcmp(pattern, "/dev/ttyACM*") != 0 &&                   \
                 strcmp(pattern, "/dev/wwan*") != 0 &&                     \
                 strcmp(pattern, "/dev/mhi_*") != 0)                       \
            return -1;                                                     \
        memset(g, 0, sizeof(*g));                                          \
        if (!list || !*list)                                               \
            return GLOB_NOMATCH;                                           \
        char *copy = strdup(list), *save = NULL;                           \
        size_t n = 0;                                                      \
        g->gl_pathv = calloc(16, sizeof(char *));                          \
        for (char *t = strtok_r(copy, " ", &save); t && n < 15;            \
             t = strtok_r(NULL, " ", &save))                               \
            g->gl_pathv[n++] = strdup(t);                                  \
        g->gl_pathc = n;                                                   \
        free(copy);                                                        \
        return n ? 0 : GLOB_NOMATCH;                                       \
    }

FAKE_GLOB(fake_glob, glob_t)
FAKE_GLOB(fake_glob64, glob64_t)

#define GLOB_SHIM(name, gtype, fake)                                       \
    int name(const char *pattern, int flags,                               \
             int (*errfunc)(const char *, int), gtype *g) {                \
        int rc = fake(pattern, g);                                         \
        if (rc != -1)                                                      \
            return rc;                                                     \
        typedef int (*real_fn)(const char *, int,                          \
                               int (*)(const char *, int), gtype *);       \
        static real_fn real;                                               \
        if (!real)                                                         \
            real = (real_fn)dlsym(RTLD_NEXT, #name);                       \
        return real(pattern, flags, errfunc, g);                           \
    }

GLOB_SHIM(glob, glob_t, fake_glob)
GLOB_SHIM(glob64, glob64_t, fake_glob64)
"""


@pytest.fixture(scope="module")
def shim(tmp_path_factory) -> Path:
    # Platform first, before cc: LD_PRELOAD does not apply off Linux.
    if not sys.platform.startswith("linux"):
        pytest.skip("the scans' sysfs admission and this LD_PRELOAD shim are "
                    f"Linux-only; this host is {sys.platform}")
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler to build the LD_PRELOAD glob shim")
    d = tmp_path_factory.mktemp("scan_glob_shim")
    src, so = d / "scan_glob_shim.c", d / "scan_glob_shim.so"
    src.write_text(SHIM_C)
    subprocess.run([cc, "-shared", "-fPIC", "-o", str(so), str(src), "-ldl"],
                   check=True, capture_output=True)
    return so


class Port:
    """A PTY standing in for a device on a USB serial bridge, with its OWNER.

    The owner holds the slave open at ``speed`` in raw mode -- a GNSS reader
    such as str2str at 460800, which takes no ``flock``. Holding it open is what
    makes the damage observable: termios belongs to the tty, so a probe's
    115200 is exactly what the owner's fd reads afterwards (and a pty's termios
    would be reset on the LAST close anyway). ``written`` collects every byte a
    probe writes into the port, read off the master.
    """

    def __init__(self, speed: int | None = B460800) -> None:
        if speed is None:
            pytest.skip(f"termios.B460800 is not exported on {sys.platform}")
        self.master, self.owner = os.openpty()
        self.path = os.ttyname(self.owner)
        attrs = termios.tcgetattr(self.owner)
        attrs[0] = 0                     # iflag: raw
        attrs[1] = 0                     # oflag
        attrs[3] = 0                     # lflag: not canonical, no echo
        attrs[4] = attrs[5] = speed      # ispeed / ospeed
        termios.tcsetattr(self.owner, termios.TCSANOW, attrs)
        self.before = termios.tcgetattr(self.owner)
        self.written = b""

    def drain(self) -> bytes:
        while select.select([self.master], [], [], 0.05)[0]:
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                break
            if not chunk:
                break
            self.written += chunk
        return self.written

    def attrs(self) -> list:
        return termios.tcgetattr(self.owner)

    def close(self) -> None:
        for fd in (self.owner, self.master):
            try:
                os.close(fd)
            except OSError:
                pass


@pytest.fixture
def port():
    p = Port()
    yield p
    p.close()


@pytest.fixture
def env(shim, tmp_path, monkeypatch):
    """The shim armed, the operator's own scan knobs cleared."""
    open_log = tmp_path / "opens.log"
    monkeypatch.setenv("LD_PRELOAD", str(shim))
    monkeypatch.setenv("OPEN_LOG", str(open_log))
    for k in ("CELLAT_SCAN_PORTS", "CELLAT_EXTRA_PORTS", "CELLDIAG_SCAN_PORTS",
              "SHIM_TTYUSB"):
        monkeypatch.delenv(k, raising=False)

    class _Env:
        @staticmethod
        def opened() -> list[str]:
            return open_log.read_text().split() if open_log.exists() else []

    return _Env()


def _list(binary: str, port: Port | None = None, timeout: float = 60.0) -> str:
    """``<binary> --list``, draining the port's master while it runs so a probe's
    write never blocks on a full pty buffer. Returns stdout+stderr."""
    proc = subprocess.Popen([binary, "--list"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + timeout
    while proc.poll() is None and time.monotonic() < deadline:
        if port is not None:
            port.drain()
        time.sleep(0.02)
    if proc.poll() is None:
        proc.kill()
        pytest.fail(f"{binary} --list did not finish in {timeout}s")
    out, err = proc.communicate()
    if port is not None:
        port.drain()
    return out + err


def _host_nodes(opened: list[str]) -> list[str]:
    return sorted({p for p in opened if HOST_NODE.match(p)})


# ── A globbed tty sysfs does not admit is NEVER opened ────────────────────────


@pytest.mark.parametrize("which", ["cellat", "celldiag"])
def test_a_globbed_tty_that_sysfs_does_not_admit_is_never_opened(which, env, port,
                                                                  monkeypatch):
    """The scan's own ``/dev/ttyUSB*`` glob returns the PTY; sysfs has no entry
    for it, so the scan refuses it BEFORE open(): not in the open log, not one
    byte written into it, its speed untouched -- and the refusal is logged with
    its evidence and the escape hatch."""
    binary = _cellat_or_skip() if which == "cellat" else _celldiag_or_skip()
    monkeypatch.setenv("SHIM_TTYUSB", port.path)
    out = _list(binary, port)
    assert port.path not in env.opened(), (
        f"{which} opened a globbed tty sysfs does not admit: {env.opened()}")
    assert port.written == b"", f"{which} wrote into it: {port.written!r}"
    assert port.attrs() == port.before, "its termios changed without an open?"
    assert f"{which}: skip {port.path}: no-driver no-usb-id, not a suspected " \
           "cell modem" in out, out
    assert _host_nodes(env.opened()) == [], env.opened()


@pytest.mark.parametrize("which", ["cellat", "celldiag"])
def test_positive_control_the_same_tty_named_by_the_operator_is_probed(which, env, port,
                                                                       monkeypatch):
    """The gauge reads positive: the SAME PTY, named in ``*_SCAN_PORTS``, is
    opened and receives the probe's ``AT\\r\\n``. So the negative above is the
    admission rule refusing, not a harness that cannot see an open."""
    binary = _cellat_or_skip() if which == "cellat" else _celldiag_or_skip()
    knob = "CELLAT_SCAN_PORTS" if which == "cellat" else "CELLDIAG_SCAN_PORTS"
    monkeypatch.setenv(knob, port.path)
    _list(binary, port)
    assert port.path in env.opened(), env.opened()
    assert b"AT\r" in port.written, port.written
    assert _host_nodes(env.opened()) == [], env.opened()


# ── What a probe opens, it leaves as it found it ──────────────────────────────


@pytest.mark.parametrize("which", ["cellat", "celldiag"])
def test_a_probed_tty_that_does_not_answer_keeps_its_460800(which, env, port,
                                                           monkeypatch):
    """Through each binary: a silent tty (a GNSS receiver) at 460800 raw,
    probed because the operator named it, must not read 115200 afterwards.
    Every termios field is back as found -- speed, raw
    mode, VMIN/VTIME -- and the write proves the probe really ran."""
    binary = _cellat_or_skip() if which == "cellat" else _celldiag_or_skip()
    knob = "CELLAT_SCAN_PORTS" if which == "cellat" else "CELLDIAG_SCAN_PORTS"
    monkeypatch.setenv(knob, port.path)
    _list(binary, port)
    assert b"AT\r" in port.written, "the probe never wrote -- nothing was measured"
    after = port.attrs()
    assert after[4] == B460800 and after[5] == B460800, (
        f"{which} left the port at speed {after[4]} (B460800={B460800}, "
        f"B115200={termios.B115200})")
    assert after == port.before, (port.before, after)
    assert _host_nodes(env.opened()) == [], env.opened()


def test_an_identified_modem_port_is_left_as_found_too(env, monkeypatch):
    """A port that DID answer -- the modem --list reports -- is also a probe
    close, and is restored the same way. Its owner here holds it at 57600 in
    canonical mode (unlike the raw GNSS case), so the raw mode the probe set is
    visible if it survives."""
    binary = _cellat_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer="Quectel") as at:
        owner = os.open(at.port, os.O_RDWR | os.O_NOCTTY)
        try:
            attrs = termios.tcgetattr(owner)
            attrs[4] = attrs[5] = termios.B57600
            attrs[3] |= termios.ICANON
            termios.tcsetattr(owner, termios.TCSANOW, attrs)
            before = termios.tcgetattr(owner)
            monkeypatch.setenv("CELLAT_SCAN_PORTS", at.port)
            out = _list(binary)
            assert f"cellat-{IMEI}" in out, out
            assert "AT+CGSN" in at.commands, at.commands
            after = termios.tcgetattr(owner)
        finally:
            os.close(owner)
    assert after[4] == termios.B57600, f"speed {after[4]} after --list"
    assert after[3] & termios.ICANON, "the probe's raw mode outlived it"
    assert after == before
    assert _host_nodes(env.opened()) == [], env.opened()
