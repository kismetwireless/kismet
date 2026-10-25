# SPDX-License-Identifier: Apache-2.0
"""A PTY-backed scripted AT responder, so cellat's open path is testable.

## Why this exists

``capture_cell_diag`` can be driven offline because DIAG is a **byte stream**: a
``replay=<file>`` option hands the helper a recorded capture and everything
downstream is real code on real bytes. ``capture_cell_at`` cannot be driven that
way, because AT is a **request/response dialogue** — there is nothing to replay,
only something to answer, so cellat needs a live responder to be tested offline.

A pseudo-terminal provides one. The harness holds the **master**; the capture binary
opens the **slave** path exactly as it would open ``/dev/ttyUSB2``, including the
real ``serial_open`` → ``tcsetattr`` → ``poll``-driven ``at_command`` path in
``at_serial.inc``. Nothing in the binary is stubbed, mocked or conditionally
compiled: the only fiction is which process is on the other end of the wire.

## What it deliberately does NOT model

This is not a modem simulator, and a test must not read it as one. It
answers the commands it was handed and returns ``ERROR`` to everything else. It
carries no cell state, no registration state, and no timing behaviour beyond
the delays a test scripts explicitly with ``pace=`` — so it can
verify *dialogue and control flow* (which port got opened, which commands were
sent to it, what the helper did with the answers) and it can NOT verify decode of
a real modem's cell reports. Those need real captures and real hardware.

A silent responder is a first-class case, not a degenerate one. A DIAG port
and an NMEA port both exist, are openable, and never answer ``AT`` — that is
precisely how a typo'd ``atport=`` fails in the field, so ``silent=True`` is what
pins the "did not respond to AT identification" branch.

## Usage

    with FakeAtModem(imei="123456789012345", firmware="RM520NGLAAR03A03M4G") as m:
        run = CellAtRun(binary, f"cellat-{m.imei}:atport={m.port}").run()
        assert "AT+CGSN" in m.commands
"""
from __future__ import annotations

import os
import re
import select
import threading
import time

#: Terminal AT responses ``at_command_log()`` in ``at_serial.inc`` breaks on.
#: Anything a response does not end with leaves the helper polling to its
#: per-command deadline, which is a *slow* test rather than a failing one, so
#: the responder appends ``OK`` itself unless the scripted answer already
#: terminates.
_TERMINATORS = ("OK", "ERROR")

#: How often the responder thread re-checks ``_stop`` while the port is idle.
_POLL_S = 0.05

#: The bound on stopping the responder, beyond its own pacing sleeps.
_STOP_GRACE_S = 2.0


class FakeModemStuck(AssertionError):
    """The responder thread did not stop, so its fds were NOT closed.

    An AssertionError so pytest reports it as a FAILED test naming the step,
    rather than the process wedging in close() -- see ``_stop_responder``.
    """

#: A real ``AT+QENG="servingcell"`` reply — RM520N-GL on Verizon B66, the same
#: transcript ``capture_cell_at/test_cellat_qeng.c`` anchors its decode on.
#:
#: Lives here so every cellat test uses ONE responder, and is passed
#: EXPLICITLY via ``extra=`` by each test that needs the open to SUCCEED. It is
#: deliberately **not** a default of ``FakeAtModem``: cellat probes for QENG
#: rather than assuming it from the vendor string, and a responder that answered
#: it by default would let a test pass against code that assumes a capability
#: instead of asking for it.
QENG_SERVING = {
    'AT+QENG="servingcell"':
        '+QENG: "servingcell","NOCONN","LTE","FDD",311,480,BBB320,221,66536,'
        '66,5,5,BBB,-96,-11,-56,14,0,-,29',
}

#: The AT+QSCAN=? test-form answer, verbatim from an RM500Q-AE R11A03.
#: cellat PROBES the full-scan capability with it -- the firmware string no
#: longer decides -- so a fake that should full-scan must script it, and for the
#: reason above it is not defaulted in either.
QSCAN_CAPABLE = {"AT+QSCAN=?": "+QSCAN: (1-3)"}


def _terminated(body: str) -> bool:
    last = [ln.strip() for ln in body.strip().splitlines() if ln.strip()]
    if not last:
        return False
    return last[-1] in _TERMINATORS or last[-1].startswith("+CME ERROR")


class FakeAtModem:
    """A scripted AT responder on a pseudo-terminal.

    :param imei: answered to ``AT+CGSN`` — the value cellat's ``atport=`` override
        re-verifies against the source definition's IMEI.
    :param firmware: answered to ``AT+CGMR``. ``identify_modem`` FAILS on an empty
        firmware, so a modem that answers ``AT`` but has no ``+CGMR`` is a real
        rejection path, reachable by passing ``firmware=""``.
    :param manufacturer: answered to ``AT+CGMI``; drives ``detect_vendor``.
    :param extra: additional ``{command: response_body}`` pairs, matched exactly
        after stripping the trailing ``\\r``/``\\n``.
    :param silent: answer nothing at all — models a DIAG or NMEA port.
    :param unknown_response: what an unscripted command gets. ``ERROR`` is what a
        real modem sends; ``None`` means "no answer", i.e. let it time out.
    :param hang: commands answered with NOTHING, even if scripted -- the helper
        waits out that command's own timeout. Models a long network scan
        (``AT+QSCAN=3,1`` blocks the capture thread up to 120 s) without making
        every other unscripted command time out too, which is what
        ``unknown_response=None`` would do.
    :param pace: ``{command: (think_s, transfer_s)}``. The answer to a paced
        command starts ``think_s`` after the command arrives, and its terminal
        line (``OK``/``ERROR``) follows the rest ``transfer_s`` later -- a
        known think-time and transfer time for the RawAT instants to be
        measured against. Unpaced commands answer at once.
    :param echo: echo every command line back before answering, as a real
        modem does until ``ATE0``. Off by default;
        an echo arrives before any think-time, which is what a test of "the
        echo does not start the response" needs on the wire.
    :param unterminated: commands answered with their value and NO final
        ``OK`` -- what a Foxconn T99W175 does for every info read (AT+CGMR /
        +CGSN / +CGMI / +CGMM). Without this the responder
        appends ``OK`` to every answer, so the shape could not be built.
    :param sequence: ``{command: [first_body, second_body, ...]}`` -- successive
        answers to the SAME command, consumed in order; once exhausted, the
        command falls back to its ordinary script. Models a reply that is wrong
        once and right on the retry, e.g. a stale ``AT+CGMI`` line taken as the
        ``AT+CGSN`` answer. Stateful: ``response_for`` consumes it.
    """

    def __init__(self, *, imei: str = "000000000000000",
                 firmware: str = "RM520NGLAAR03A03M4G",
                 manufacturer: str = "Quectel",
                 extra: "dict[str, str] | None" = None,
                 silent: bool = False,
                 unknown_response: "str | None" = "ERROR",
                 hang: "set[str] | frozenset[str]" = frozenset(),
                 pace: "dict[str, tuple[float, float]] | None" = None,
                 echo: bool = False,
                 unterminated: "set[str] | frozenset[str]" = frozenset(),
                 sequence: "dict[str, list[str]] | None" = None) -> None:
        self.imei = imei
        self.unterminated = frozenset(unterminated)
        self.hang = frozenset(hang)
        self.pace = dict(pace or {})
        self.echo = echo
        self.firmware = firmware
        self.manufacturer = manufacturer
        self.silent = silent
        self.unknown_response = unknown_response
        #: Every command line received, in order. The ground truth for "was this
        #: the port that actually got opened" -- an assertion that no amount of
        #: reading the source can substitute for.
        self.commands: list[str] = []

        self._script: dict[str, str] = {}
        if firmware:
            self._script["AT+CGMR"] = firmware
        self._script["AT+CGSN"] = imei
        self._script["AT+CGMI"] = manufacturer
        self._script["AT"] = ""            # bare OK
        self._script["ATE0"] = ""
        self._script.update(extra or {})
        self._sequence: dict[str, list[str]] = {
            k: list(v) for k, v in (sequence or {}).items()}

        self._master = -1
        self._slave = -1
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    # ── lifecycle ──────────────────────────────────────────────────────────────
    def __enter__(self) -> "FakeAtModem":
        self._master, self._slave = os.openpty()
        # The slave fd stays OPEN and is never READ. Closing it would make the
        # master read EIO before the capture binary gets a chance to open the
        # path; reading it would race the binary for its own input.
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop_responder("__exit__")
        for fd in (self._master, self._slave):
            try:
                os.close(fd)
            except OSError:
                pass
        self._master = self._slave = -1

    def _stop_responder(self, step: str) -> None:
        """Stop the responder thread BEFORE any of its fds is closed.

        The order matters. Linux lets a close race a blocked read; Darwin's
        close() waits for the read in flight on that fd to drain, and with the
        capture binary gone nothing ever writes to the master again -- so
        closing the master while ``_serve`` sits in ``os.read(master)`` wedges
        pytest in close() in the uninterruptible ``U`` state, ignoring SIGTERM.

        ``_serve`` waits in ``select()`` with a short timeout and re-checks
        ``_stop``, so it leaves on its own. If it does not within the bound, the
        fds are deliberately LEFT OPEN and the test FAILS naming the step: a
        leaked fd is recoverable, a process stuck in close() is not.
        """
        self._stop.set()
        t = self._thread
        if t is None or t is threading.current_thread():
            return
        pacing = max((sum(v) for v in self.pace.values()), default=0.0)
        t.join(timeout=_STOP_GRACE_S + pacing)
        if t.is_alive():
            raise FakeModemStuck(
                f"FakeAtModem.{step}: the responder thread did not stop within "
                f"{_STOP_GRACE_S + pacing:.1f} s; its pty fds were left open "
                f"rather than closed under a live read")
        self._thread = None

    @property
    def port(self) -> str:
        """The slave device path — what goes in ``atport=``."""
        if self._slave < 0:
            raise RuntimeError("FakeAtModem used outside its `with` block")
        return os.ttyname(self._slave)

    def unplug(self) -> None:
        """Yank the wire: close the master so the binary's next read errors.

        This is the only hardware-free route to a post-open failure in cellat.
        celldiag can reach that class with ``replay=<missing file>``,
        because DIAG is a byte stream and the open answers before the file is
        touched. AT has no equivalent: every cheap failure this responder can
        script — a wrong IMEI, an empty ``+CGMR``, ``silent=True`` — is
        rejected inside ``open_callback``, and open-path errors ride the open
        report's return code, so a test built on one never exercises the
        post-open error path.

        Unplugging after the open succeeds is what reaches ``capture_thread``'s
        error sites. It is also the honest model of the field failure: a modem
        that enumerates, identifies, and then drops off the bus mid-survey (USB
        reset, thermal cutout, a yanked cable).

        The SLAVE fd stays open deliberately — see ``__enter__``. Closing the
        master alone is what makes the slave read fail; closing both would race
        the binary's own open. Idempotent, and ``__exit__`` still runs.
        """
        # Same ordering rule as __exit__: the responder is blocked
        # reading the master, and closing it under that read wedges Darwin.
        self._stop_responder("unplug")
        if self._master >= 0:
            try:
                os.close(self._master)
            except OSError:
                pass
            self._master = -1

    # ── the responder ──────────────────────────────────────────────────────────
    def response_for(self, cmd: str) -> "str | None":
        """The bytes-worth of answer for ``cmd``, or None for "say nothing".

        Split out from the I/O loop so a test can assert what the script would do
        without standing up a pty.
        """
        if self.silent or cmd in self.hang:
            return None
        if self._sequence.get(cmd):
            body = self._sequence[cmd].pop(0)
        elif cmd in self._script:
            body = self._script[cmd]
        else:
            if self.unknown_response is None:
                return None
            body = self.unknown_response
        if not _terminated(body) and cmd not in self.unterminated:
            body = (body + "\r\n" if body else "") + "OK"
        return "\r\n" + body.replace("\n", "\r\n").replace("\r\r", "\r") + "\r\n"

    def _serve(self) -> None:
        buf = b""
        while not self._stop.is_set():
            # Wait in select(), not in read(): a thread parked in read() on the
            # master can only be released by input or by closing the fd, and
            # closing it under the read wedges Darwin.
            try:
                ready, _, _ = select.select([self._master], [], [], _POLL_S)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                chunk = os.read(self._master, 4096)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            # AT terminates on CR; tolerate LF and CRLF so a hand-written probe
            # in a future test is not silently ignored.
            while True:
                m = re.search(rb"[\r\n]", buf)
                if not m:
                    break
                line, buf = buf[:m.start()], buf[m.end():]
                cmd = line.decode("utf-8", "replace").strip()
                if not cmd:
                    continue
                with self._lock:
                    self.commands.append(cmd)
                resp = self.response_for(cmd)
                try:
                    if self.echo and not self.silent:
                        # The line as typed, with its CR; the reply's own
                        # leading CRLF follows (response_for).
                        os.write(self._master, (cmd + "\r").encode())
                    if resp is None:
                        continue
                    think, transfer = self.pace.get(cmd, (0.0, 0.0))
                    if think:
                        time.sleep(think)
                    # Split off the terminal line so `transfer` separates the
                    # body's first byte from the end of the reply. A bare OK has
                    # no body to split from and goes out whole.
                    head, _, term = resp.rstrip("\r\n").rpartition("\r\n")
                    if transfer and head.strip():
                        os.write(self._master, (head + "\r\n").encode())
                        time.sleep(transfer)
                        os.write(self._master, (term + "\r\n").encode())
                    else:
                        os.write(self._master, resp.encode())
                except OSError:
                    return
