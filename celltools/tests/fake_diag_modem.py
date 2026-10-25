"""A scripted DIAG responder on a pseudo-terminal.

``fake_at_modem.FakeAtModem`` made cellat's open path testable offline; this is
its DIAG sibling. ``capture_cell_diag`` reads its DIAG port as a raw byte stream
and writes HDLC-framed commands into it, so a pty that deframes what it is sent
and answers in HDLC is, from the binary's side, indistinguishable from a modem
on ``diagport=`` -- with ``nomask=true`` there is no LOG_CONFIG handshake to
script, and ``atport=`` a :class:`FakeAtModem` supplies the AT identity.

What it answers is deliberately narrow: ``DIAG_TS_F`` (opcode ``0x1D``, empty
body), the one command a running capture issues on its own (the clock
anchor). Every other command is recorded in :attr:`commands` and ignored, like
a modem whose response is being dropped.

The reply is the real wire shape (as sent by a DW5821e / SDX20)::

    0x1D  <8-byte little-endian ts64>  <crc16 LE>  0x7E

``ts64`` here is computed from the HOST clock -- GPS time in the Q16 1.25 ms
tick (``TS64_TICK_S``) plus ``offset_s`` -- so a test can check the consumer's
UTC reprojection against a known skew rather than against the fake's own output.

It can also stream filler LOG_F frames between anchors (``filler_hz``) whose
payload deliberately carries ``0x7E`` / ``0x7D`` bytes, so the anchor has to be
fished out of a stuffed, interleaved stream exactly as it is on real hardware.
"""

from __future__ import annotations

import os
import select
import struct
import threading
import time

from fake_at_modem import _POLL_S, _STOP_GRACE_S, FakeModemStuck

#: One Q16 ts64 tick: 1.25 ms / 65536.
TS64_TICK_S = 1.25e-3 / 65536
#: 1980-01-06T00:00:00Z as a Unix epoch -- the GPS epoch ts64 counts from.
GPS_EPOCH_UNIX = 315964800
#: GPS - UTC, seconds (the leap-second offset in force since 2017).
GPS_UTC_LEAP_S = 18

DIAG_TS_F = 0x1D
DIAG_BAD_CMD_F = 0x13


def crc16_x25(data: bytes) -> int:
    """CRC-16/X-25 -- the DIAG HDLC CRC (diag_hdlc.c ``diag_hdlc_crc16``)."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def hdlc_frame(body: bytes) -> bytes:
    """escape(body || crc16_le(body)) || 0x7E."""
    raw = body + struct.pack("<H", crc16_x25(body))
    out = bytearray()
    for b in raw:
        if b in (0x7E, 0x7D):
            out += bytes((0x7D, b ^ 0x20))
        else:
            out.append(b)
    out.append(0x7E)
    return bytes(out)


def hdlc_unescape(frame: bytes) -> bytes:
    out = bytearray()
    esc = False
    for b in frame:
        if esc:
            out.append(b ^ 0x20)
            esc = False
        elif b == 0x7D:
            esc = True
        else:
            out.append(b)
    return bytes(out)


def unix_to_ts64(unix_s: float) -> int:
    """Host Unix time -> the modem's GPS-epoch Q16 ts64 (leap-uncorrected GPS)."""
    return int(round((unix_s - GPS_EPOCH_UNIX + GPS_UTC_LEAP_S) / TS64_TICK_S))


def ts64_to_unix(ts64: int) -> float:
    return ts64 * TS64_TICK_S + GPS_EPOCH_UNIX - GPS_UTC_LEAP_S


class FakeDiagModem:
    """A DIAG port on a pty that answers ``DIAG_TS_F``.

    :param offset_s: modem clock minus host clock, in seconds. The ts64 in every
        reply encodes ``host_now + offset_s``.
    :param answer: ``"ts"`` (reply with a timestamp), ``"reject"`` (reply
        ``0x13 0x1D`` -- DIAG_BAD_CMD_F echoing the opcode, what a part without
        the command sends), or ``"silent"`` (never reply).
    :param filler_hz: rate of interleaved filler LOG_F frames; 0 = none.
    :param reply_delay_s: hold each reply this long, to model a response queued
        behind log traffic (the RTT the anchor record reports).
    :param filler_pad: extra payload bytes per filler frame, so a test can make
        the port produce MB/s -- enough to outrun a slow server and fill the
        capture's output ring (the live drop path). 0 = the small frame.
    :param echo_opcodes: opcodes whose commands are answered by echoing the
        command's own payload back, the shape of a modem's ack. Empty (the
        default) keeps every non-``DIAG_TS_F`` command unanswered. A capture that
        waits for an ack (``qsh=on`` arms three things, each with a 20 s read
        deadline) needs this to open in test time.
    :param filler_max: stop the filler after this many frames, so the port goes
        QUIET at a known moment (:attr:`filler_last_wall`); 0 = never stop. A
        stop taken a fixed time after the last frame is how a test tells "the
        capture delivered everything it read" from "it was still holding the
        tail".
    :param scripted: exact command payload -> reply payload, answered before
        ``echo_opcodes`` is consulted. For a reply whose shape is not an echo --
        the qsh=on DIAGID-table request answered with a real table.
    :param reject_opcodes: opcodes whose commands are answered ``0x13`` +
        the command echoed -- DIAG_BAD_CMD_F, what a part without the command
        sends (the EG25-G to all three ``qsh=on`` requests).
        Consulted after ``scripted`` and before ``echo_opcodes``.
    """

    def __init__(self, *, offset_s: float = 0.0, answer: str = "ts",
                 filler_hz: float = 0.0, reply_delay_s: float = 0.0,
                 filler_pad: int = 0, filler_max: int = 0,
                 echo_opcodes: "frozenset[int] | set[int]" = frozenset(),
                 scripted: "dict[bytes, bytes] | None" = None,
                 reject_opcodes: "frozenset[int] | set[int]" = frozenset()) -> None:
        if answer not in ("ts", "reject", "silent"):
            raise ValueError(f"answer={answer!r}")
        self.offset_s = offset_s
        self.answer = answer
        self.filler_hz = filler_hz
        self.filler_pad = filler_pad
        self.filler_max = filler_max
        #: Filler frames written so far, and the host wall clock of the last one.
        self.filler_sent = 0
        self.filler_last_wall: "float | None" = None
        #: The exact framed bytes of every padded filler frame (``filler_pad``),
        #: so a test can count them in a capture. b"" until sent.
        self.filler_frame = b""
        self.reply_delay_s = reply_delay_s
        self.echo_opcodes = frozenset(echo_opcodes)
        self.scripted = dict(scripted or {})
        self.reject_opcodes = frozenset(reject_opcodes)
        #: Every deframed, CRC-valid command body received, in order.
        self.commands: list[bytes] = []
        #: The ts64 of every DIAG_TS_F reply sent, in order -- the ground truth a
        #: test compares the anchor rows' ``source_clock_value`` against.
        self.replies: list[int] = []
        self._master = -1
        self._slave = -1
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    # ── lifecycle ──────────────────────────────────────────────────────────────
    def __enter__(self) -> "FakeDiagModem":
        self._master, self._slave = os.openpty()
        # Raw mode on the slave side: the binary opens the NAME and configures
        # its own termios, but until it does a cooked line discipline would
        # echo/translate our HDLC bytes.
        import tty
        tty.setraw(self._slave)
        # Non-blocking MASTER, so neither thread can park in the kernel on it:
        # _serve waits in select() and _write loops on writability, both
        # re-checking _stop. A blocking write with the slave's buffer full
        # (nobody reads it once the binary exits) never returns, and closing
        # the fd under it -- or under a blocked read -- wedges Darwin's close().
        os.set_blocking(self._master, False)
        for target in (self._serve, self._filler):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)
        return self

    def __exit__(self, *_exc) -> None:
        # Threads FIRST, fds after -- see FakeAtModem._stop_responder. On Darwin
        # a close waits on _serve's in-flight read forever and wedges pytest in
        # `U` state.
        self._stop.set()
        bound = _STOP_GRACE_S + self.reply_delay_s
        for t in self._threads:
            t.join(timeout=bound)
        stuck = [t.name for t in self._threads if t.is_alive()]
        if stuck:
            raise FakeModemStuck(
                f"FakeDiagModem.__exit__: {stuck} did not stop within "
                f"{bound:.1f} s; the pty fds were left open rather than closed "
                f"under a live read or write")
        for fd in (self._master, self._slave):
            try:
                os.close(fd)
            except OSError:
                pass
        self._master = self._slave = -1

    @property
    def port(self) -> str:
        return os.ttyname(self._slave)

    def ts_f_requests(self) -> int:
        with self._lock:
            return sum(1 for c in self.commands if c == bytes((DIAG_TS_F,)))

    # ── I/O ────────────────────────────────────────────────────────────────────
    def _write(self, data: bytes) -> None:
        """All of ``data``, back-pressured by the slave's buffer, unless stopped.

        The master is non-blocking, so a full buffer is a wait in
        select() that re-checks ``_stop`` -- never a write parked in the kernel.
        """
        view = memoryview(data)
        with self._lock:
            while view and not self._stop.is_set():
                try:
                    _, ready, _ = select.select([], [self._master], [], _POLL_S)
                    if not ready:
                        continue
                    n = os.write(self._master, view)
                except BlockingIOError:
                    continue
                except (OSError, ValueError):
                    return
                view = view[n:]

    def _serve(self) -> None:
        buf = bytearray()
        while not self._stop.is_set():
            # select(), not a parked read: see __enter__.
            try:
                ready, _, _ = select.select([self._master], [], [], _POLL_S)
                if not ready:
                    continue
                chunk = os.read(self._master, 4096)
            except BlockingIOError:
                continue
            except (OSError, ValueError):
                return
            if not chunk:
                return
            buf += chunk
            while True:
                end = buf.find(0x7E)
                if end < 0:
                    break
                raw = bytes(buf[:end])
                del buf[:end + 1]
                body = hdlc_unescape(raw)
                if len(body) < 3:
                    continue
                payload, crc = body[:-2], struct.unpack("<H", body[-2:])[0]
                if crc16_x25(payload) != crc:
                    continue
                with self._lock:
                    self.commands.append(payload)
                if payload == bytes((DIAG_TS_F,)):
                    self._answer_ts_f()
                elif payload in self.scripted:
                    self._write(hdlc_frame(self.scripted[payload]))
                elif payload[0] in self.reject_opcodes:
                    self._write(hdlc_frame(bytes((DIAG_BAD_CMD_F,)) + payload))
                elif payload[0] in self.echo_opcodes:
                    self._write(hdlc_frame(payload))

    def _answer_ts_f(self) -> None:
        if self.answer == "silent":
            return
        if self.answer == "reject":
            self._write(hdlc_frame(bytes((DIAG_BAD_CMD_F, DIAG_TS_F))))
            return
        # Stamp BEFORE the delay: the modem reads its clock when it services the
        # command, and a reply queued behind log traffic arrives later with the
        # same value. That is exactly the asymmetry the anchor's RTT bounds.
        ts64 = unix_to_ts64(time.time() + self.offset_s)
        if self.reply_delay_s:
            time.sleep(self.reply_delay_s)
        with self._lock:
            self.replies.append(ts64)
        self._write(hdlc_frame(bytes((DIAG_TS_F,)) + struct.pack("<Q", ts64)))

    def _filler(self) -> None:
        if self.filler_hz <= 0:
            return
        period = 1.0 / self.filler_hz
        n = 0
        padded = None
        while not self._stop.wait(period):
            # A LOG_F (0x10) frame for an unassigned code, payload stuffed with
            # both HDLC special bytes. Nothing decodes it; it exists to sit
            # between the request and the reply on the wire.
            n += 1
            body = (bytes((0x10, 0x00)) + struct.pack("<HH", 20, 20)
                    + struct.pack("<H", 0x0FFF) + struct.pack("<Q", n)
                    + bytes((0x7E, 0x7D, 0x1D, 0x7E, 0x00, 0x7D, 0x5E, 0x1D)))
            if self.filler_pad:
                # hdlc_frame/crc16_x25 are per-byte Python loops: framing a
                # fresh multi-KB frame per tick caps the rate far below what a
                # ring-filling test needs. One frame, framed once, resent.
                if padded is None:
                    padded = hdlc_frame(body + bytes(i & 0xFF for i in range(self.filler_pad)))
                    self.filler_frame = padded
                self._write(padded)
            else:
                self._write(hdlc_frame(body))
            self.filler_last_wall = time.time()
            self.filler_sent = n
            if self.filler_max and n >= self.filler_max:
                return
