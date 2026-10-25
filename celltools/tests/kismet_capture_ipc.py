# SPDX-License-Identifier: Apache-2.0
"""Source-agnostic offline driver for a Kismet capture binary.

## Why this is its own module

The driver fork/execs a capture binary and speaks just enough of the Kismet
``kismet_external`` **v3** datasource protocol to open a source and collect
what it relays. Every offline ``f3=``, ``rawlog=``, ``gsmtap=`` and
inventory test of the celldiag helper runs through it, and so does every
offline test of cellat's open path (for example, that ``atport=`` with a
mismatched IMEI is refused).

Nothing in the driver is celldiag-specific. It speaks the datasource IPC
protocol, not anything about DIAG: the framing, the msgpack subset, the
mandatory PING keepalive and the OPENREPORT/MESSAGE/ERROR collection are all
properties of *being a Kismet capture binary*. Source-specific routing, such
as splitting celldiag's ``diag_stats`` control objects out of the observation
relay, goes through an override point (:meth:`CaptureRun._on_json`).

So this module holds the protocol and :class:`CaptureRun`; ``CellDiagRun``
subclasses it for the ``diag_stats`` split, and ``CellAtRun`` (in
``test_cellat_ipc.py``) subclasses it for nothing at all.

## Why a capture source needs an offline harness at all

The typical failure mode of a capture source is **silence** — a source that
stops emitting looks exactly like "no cells in range". Without an offline
harness, the only alternatives are unit-testing extracted helpers or running
against real hardware.

## Wire spec

All resolved against this tree's ``kis_external_packet.h`` /
``capture_framework.c``:

* frame header = 20 bytes, big-endian, ``>IHHIHHI``:
  signature ``0xDECAFBAD``, v3_sentinel ``0xA9A9``, v3_version ``3``,
  length (payload only), pkt_type, code, seqno; msgpack map payload follows.
* pkt_type: PING=2 PONG=3 SHUTDOWN=4 MESSAGE=5 ERROR=6 OPENREQ=12
  OPENREPORT=13 PACKET=16.
* OPENREQ payload: ``{1: "<definition>"}`` (seqno in the header).
* PACKET payload: ``{5: {1:"<klass>", 2:ts_s, 3:ts_us, 4:<json>}}`` — the
  relayed JSON is at ``map[5][4]``. A raw packet (``cf_send_data``) is instead
  ``{4: {1:dlt, 2:ts_s, 3:ts_us, 4:length, 6:<bin content>}}``.
* PING keepalive is mandatory: a capture binary FATAL-exits if it sees no frame
  for >15 s, so the harness pings while pumping.
"""
from __future__ import annotations

import os
import selectors
import struct
import subprocess
import time
from typing import Callable


# ── v3 kismet_external framing ─────────────────────────────────────────────────
SIG = 0xDECAFBAD
V3_SENTINEL = 0xA9A9
V3_VERSION = 3
_HDR = struct.Struct(">IHHIHHI")   # sig, sentinel, version, length, pkt_type, code, seqno
HDR_LEN = _HDR.size                # 20

#: The SERVER's cap on one IPC frame (kis_external.h MAX_EXTERNAL_FRAME_LEN).
#: kis_external.cc packet_read() refuses a frame whose
#: ``data_sz + sizeof(v3 header) - sizeof(stub header)`` exceeds it -- and does
#: not skip the frame: it errors the whole SOURCE ("external packet too large
#: for buffer"), which Kismet then re-opens every 5 s, forever.
#:
#: The harness must not be MORE permissive than the server it stands in for: a
#: helper sending oversized frames would pass every harness test and be killed
#: by a real Kismet server on the first one. Enforced in ``_drain_frames``;
#: pinned to the header by test_celldiag_raw_packets.
MAX_EXTERNAL_FRAME_LEN = 16384
_V3_MINUS_STUB = HDR_LEN - 12          # sizeof(v3 header) - sizeof(frame stub)

PKT_PING = 2
PKT_PONG = 3
PKT_MESSAGE = 5
PKT_ERROR = 6
PKT_OPENREQ = 12
PKT_OPENREPORT = 13
PKT_PACKET = 16
# The CONFIGURE round-trip — Kismet's only generic RUNTIME setter for a
# datasource. The server reaches it via
# `POST /datasource/by-uuid/:uuid/set_channel`; on the wire it is this frame
# pair, and a capture binary only answers it if it registered BOTH the
# chantranslate and chancontrol callbacks.
PKT_CONFIGREQ = 17
PKT_CONFIGREPORT = 18
# The graceful close: the SERVER asks the helper to finish up -- run its
# teardown (END clock anchor, END raw slice, QSH disarm), drain its out-ring,
# then exit on its own. Without it the server's only stop is pipe-close + an
# immediate SIGTERM, which no teardown survives.
PKT_CLOSEREQ = 20
CONFIGREQ_FIELD_CHANNEL = 1
CONFIGREPORT_FIELD_SEQNO = 1
CONFIGREPORT_FIELD_CHANNEL = 2
CONFIGREPORT_FIELD_MSG = 4

DATAREPORT_FIELD_JSONBLOCK = 5
SUB_JSON_FIELD_TYPE = 1
SUB_JSON_FIELD_JSON = 4
# The DATAREPORT's GPS sub-block (``kis_external_packet.h``). This is how a
# capture source geo-tags the device its observation builds. A driver that read
# only the JSON block could not tell "the observation was emitted" from "the
# observation was emitted WITH a position": a change that drops every geo-tag
# while leaving the observation count unchanged would pass every count A/B.
DATAREPORT_FIELD_GPSBLOCK = 1
SUB_GPS_FIELD_LAT = 1
SUB_GPS_FIELD_LON = 2
SUB_GPS_FIELD_FIX = 4
# The DATAREPORT's PACKET sub-block: a raw link-layer packet with a DLT, the
# cf_send_data() path. celldiag sends the raw DIAG stream this way -- DLT 147
# slices the server logs into the kismetdb `packets` table. A harness that read
# only the JSON block would report a source that sent no raw bytes and one that
# sent all of them identically.
DATAREPORT_FIELD_PACKETBLOCK = 4
SUB_PACKET_FIELD_DLT = 1
SUB_PACKET_FIELD_TS_S = 2
SUB_PACKET_FIELD_TS_US = 3
SUB_PACKET_FIELD_LENGTH = 4
SUB_PACKET_FIELD_CONTENT = 6
# OPENREPORT (KismetExternal OpenSourceReport) message field — carries the
# open_callback failure text (e.g. "Unknown mask preset 'bogus' ...") when a
# source definition is rejected. Distinct from a MESSAGE-frame status line.
OPENREPORT_FIELD_HARDWARE = 7   # KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_HARDWARE
OPENREPORT_FIELD_MESSAGE = 9
OPENREPORT_FIELD_CHAN_LIST = 4   # KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CHAN_LIST
OPENREPORT_FIELD_CHANNEL = 5     # KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CHANNEL
# The helper's graceful-close grace, in ms. Present only when the helper
# opted in (cf_handler_set_close_grace); its absence is how the server knows to
# keep the old hard close for every other helper.
OPENREPORT_FIELD_CLOSEGRACE = 11


def _frame(pkt_type: int, seqno: int, payload: bytes = b"", code: int = 0) -> bytes:
    return _HDR.pack(SIG, V3_SENTINEL, V3_VERSION, len(payload),
                     pkt_type, code, seqno) + payload


# ── minimal msgpack (encoder: map/uint/str; decoder: full enough for reports) ──
# Hand-rolled so the harness needs no third-party dependency at all: this
# directory runs on a fresh checkout with nothing but pytest.
def _mp_uint(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return b"\xcc" + bytes([n])
    if n <= 0xFFFF:
        return b"\xcd" + struct.pack(">H", n)
    if n <= 0xFFFFFFFF:
        return b"\xce" + struct.pack(">I", n)
    return b"\xcf" + struct.pack(">Q", n)


def _mp_str(s: str) -> bytes:
    b = s.encode("utf-8")
    n = len(b)
    if n < 0x20:
        return bytes([0xA0 | n]) + b
    if n <= 0xFF:
        return b"\xd9" + bytes([n]) + b
    if n <= 0xFFFF:
        return b"\xda" + struct.pack(">H", n) + b
    return b"\xdb" + struct.pack(">I", n) + b


def _mp_map(pairs: dict) -> bytes:
    n = len(pairs)
    if n < 0x10:
        out = bytes([0x80 | n])
    elif n <= 0xFFFF:
        out = b"\xde" + struct.pack(">H", n)
    else:
        out = b"\xdf" + struct.pack(">I", n)
    for k, v in pairs.items():
        out += _mp_uint(k) if isinstance(k, int) else _mp_str(k)
        if isinstance(v, str):
            out += _mp_str(v)
        elif isinstance(v, int):
            out += _mp_uint(v)
        elif isinstance(v, dict):
            out += _mp_map(v)
        else:  # pragma: no cover - not needed by the harness
            raise TypeError(f"unsupported msgpack value: {v!r}")
    return out


def _mp_unpack(buf: bytes, off: int = 0):
    """Return (obj, next_off). Covers the subset Kismet v3 reports emit."""
    b = buf[off]
    off += 1
    if b < 0x80:                    # positive fixint
        return b, off
    if b >= 0xE0:                   # negative fixint
        return b - 0x100, off
    if 0x80 <= b <= 0x8F:           # fixmap
        return _mp_read_map(buf, off, b & 0x0F)
    if 0x90 <= b <= 0x9F:           # fixarray
        return _mp_read_array(buf, off, b & 0x0F)
    if 0xA0 <= b <= 0xBF:           # fixstr
        n = b & 0x1F
        return buf[off:off + n].decode("utf-8", "replace"), off + n
    if b == 0xC0:
        return None, off
    if b == 0xC2:
        return False, off
    if b == 0xC3:
        return True, off
    if b == 0xCC:
        return buf[off], off + 1
    if b == 0xCD:
        return struct.unpack_from(">H", buf, off)[0], off + 2
    if b == 0xCE:
        return struct.unpack_from(">I", buf, off)[0], off + 4
    if b == 0xCF:
        return struct.unpack_from(">Q", buf, off)[0], off + 8
    if b == 0xD0:
        return struct.unpack_from(">b", buf, off)[0], off + 1
    if b == 0xD1:
        return struct.unpack_from(">h", buf, off)[0], off + 2
    if b == 0xD2:
        return struct.unpack_from(">i", buf, off)[0], off + 4
    if b == 0xD3:
        return struct.unpack_from(">q", buf, off)[0], off + 8
    if b == 0xCA:
        return struct.unpack_from(">f", buf, off)[0], off + 4
    if b == 0xCB:
        return struct.unpack_from(">d", buf, off)[0], off + 8
    if b in (0xD9, 0xDA, 0xDB):     # str8/16/32
        n, off = _mp_read_len(buf, off, {0xD9: 1, 0xDA: 2, 0xDB: 4}[b])
        return buf[off:off + n].decode("utf-8", "replace"), off + n
    if b in (0xC4, 0xC5, 0xC6):     # bin8/16/32
        n, off = _mp_read_len(buf, off, {0xC4: 1, 0xC5: 2, 0xC6: 4}[b])
        return buf[off:off + n], off + n
    if b in (0xDE, 0xDF):           # map16/32
        n, off = _mp_read_len(buf, off, 2 if b == 0xDE else 4)
        return _mp_read_map(buf, off, n)
    if b in (0xDC, 0xDD):           # array16/32
        n, off = _mp_read_len(buf, off, 2 if b == 0xDC else 4)
        return _mp_read_array(buf, off, n)
    raise ValueError(f"unhandled msgpack byte 0x{b:02x} at off {off - 1}")


def _mp_read_len(buf, off, width):
    fmt = {1: ">B", 2: ">H", 4: ">I"}[width]
    return struct.unpack_from(fmt, buf, off)[0], off + width


def _mp_read_map(buf, off, count):
    out = {}
    for _ in range(count):
        k, off = _mp_unpack(buf, off)
        v, off = _mp_unpack(buf, off)
        out[k] = v
    return out, off


def _mp_read_array(buf, off, count):
    out = []
    for _ in range(count):
        v, off = _mp_unpack(buf, off)
        out.append(v)
    return out, off


# ── the offline datasource driver ──────────────────────────────────────────────
class CaptureRun:
    """One offline run of a Kismet capture binary; collects what it relays.

    Subclass and override :meth:`_on_json` to route the relayed JSON stream;
    the base class treats every relayed object as an observation.

    ``stop_when``: celldiag replays a file and **exits**, so waiting for
    process exit is a fine stop condition. cellat opens a modem and surveys
    **forever**, so a harness with no early stop would burn its whole
    ``timeout`` on every test. The predicate is
    checked after each drained batch and receives the run.
    """

    def __init__(self, binary: str, definition: str, timeout: float = 30.0,
                 stop_when: "Callable[[CaptureRun], bool] | None" = None,
                 configure: "list[tuple[Callable[[CaptureRun], bool], str]] | None" = None,
                 graceful_close_s: float = 0.0, drain_pause_s: float = 0.0,
                 poll_s: float = 0.5,
                 close_when: "Callable[[CaptureRun], bool] | None" = None,
                 preexec_fn: "Callable[[], None] | None" = None,
                 env: "dict[str, str] | None" = None):
        self.binary = binary
        #: The binary's WHOLE environment, or None to inherit this process's.
        #: An allow-list beats scrubbing named variables: nothing ambient on the
        #: host can steer the run, and the test never has to name what it keeps
        #: out.
        self.env = env
        #: Run in the forked child before the binary is exec'd. Default None.
        #: Used to start the binary in a suid install's id state
        #: (real = the caller, effective/saved = root) without a suid file.
        self.preexec_fn = preexec_fn
        #: How long the pump waits for output before re-checking ``stop_when``
        #: and ``configure`` while the binary is silent. The 0.5 s default is
        #: fine for predicates about WHAT arrived; one about WHEN (stop N ms
        #: after the port went quiet) needs a finer grain, or the stop
        #: lands anywhere in the following half second.
        self.poll_s = poll_s
        #: Seconds to sleep after each read of the binary's output -- a slow
        #: server. Default 0. Positive values let a test fill the binary's
        #: 4 MiB output ring on purpose, which is the only way to reach its
        #: "ring full" branches offline (a replay must not drop).
        self.drain_pause_s = drain_pause_s
        self.definition = definition
        self.timeout = timeout
        self.stop_when = stop_when
        #: Seconds to let the binary exit ON ITS OWN after the harness closes the
        #: IPC pipe, before SIGTERM. Default 0 terminates at once, which is also
        #: what Kismet does: close_impl() closes the pipes
        #: and kill(SIGTERM)s in the same call, and the framework leaves SIGTERM
        #: at its default disposition, so a Kismet-driven stop runs NO teardown.
        #: A positive value models the stop that does reach teardown -- pipe EOF
        #: alone, as a remote (--connect) capture sees when its server goes away
        #: (the END clock anchor is only reachable on that path).
        self.graceful_close_s = graceful_close_s
        #: ``returncode`` once the process is gone: negative means the harness had
        #: to signal it, so a graceful-close test can tell "exited on EOF" apart
        #: from "was SIGTERMed after the grace period ran out".
        self.exit_code: "int | None" = None
        #: Runtime settings to push mid-capture, as
        #: ``(when_predicate, knob_string)``. Each fires ONCE, the first time its
        #: predicate holds, and lands as a CONFIGURE frame — the same frame the
        #: server's ``set_channel`` endpoint produces.
        #:
        #: It is a PREDICATE and not a delay on purpose. "Send it after 2
        #: seconds" makes a test that is green on a fast host and flaky on a
        #: loaded one, and the interesting assertions here are all of the form
        #: "the counter moved AFTER the knob was applied" — which needs the knob
        #: to land at a known point in the stream, not a known wall-clock.
        self.configure = list(configure or [])
        self._configure_done: list[bool] = [False] * len(self.configure)
        #: ``(success, msg)`` per CONFIGREPORT, in arrival order. ``success`` is
        #: the frame's header code: 1 applied, 0 refused.
        self.config_results: "list[tuple[int, str]]" = []
        #: Parallel to ``config_results``: the CHANNEL each CONFIGREPORT carried,
        #: or ``None`` when it carried none. It is what the server stores as
        #: ``kismet.datasource.channel`` -- and replays with set_channel after an
        #: error re-open -- so it is how a test sees whether a runtime SETTING
        #: was recorded as the source's channel.
        self.config_channels: "list[str | None]" = []
        self.observations: list[str] = []   # raw JSON strings, in relay order
        #: Parallel to ``observations``: the GPS sub-block each was relayed
        #: with, or ``None`` for an ungeotagged one. Kept as its own list, and
        #: appended by the SAME code path that appends the observation, so the
        #: two cannot drift out of alignment as they would if the caller had to
        #: remember to record both.
        self.observation_gps: "list[dict | None]" = []
        #: The GPS block of the packet currently being routed. Set before
        #: ``_on_json`` so an override can decide whether the object it just
        #: classified was an observation and record the position accordingly.
        self._packet_gps: "dict | None" = None
        # Control objects sharing the observation relay but intercepted by the
        # datasource rather than devicified — on celldiag, `diag_stats`. Kept separate so observation A/B comparisons stay decode-only.
        # Declared here rather than in the subclass so a caller can read it
        # unconditionally; the base class never puts anything in it.
        self.control: list[str] = []
        #: type="ClockAnchor" rows (celldiag and cellat): the host<->source
        #: clock pairs. Routed by the packet's JSON TYPE field, not
        #: by sniffing the body -- a clock-anchor/1 record carries no "type" key,
        #: so a body match would send it to `observations`, where every A/B and
        #: count assertion would read a clock pair as a cell.
        self.clock_anchors: list[str] = []
        #: type="RawAT" rows: cellat's raw AT transcript, one row per
        #: exchange -- including the probe exchanges of an open that is then
        #: REFUSED. Routed by type for the same reason as clock_anchors: counted
        #: as observations, a refused source's transcript would read as relayed
        #: observations.
        self.raw_at: list[str] = []
        #: type="RawDiagDrop" rows: celldiag's record of its first
        #: dropped raw-DIAG slice. Routed by type like the two above: it is a
        #: loss witness, and read as an observation it would be a phantom cell.
        self.raw_diag_drops: list[str] = []
        #: celldiag's DiagCrcCensus rows: one per session, at end-of-stream.
        self.crc_census: list[str] = []
        #: type="cellat_stats" rows: cellat's datasource-field readback, which
        #: the server intercepts before phy_cell. Routed by type like the three
        #: above -- counted as observations, every cellat test that asserts an
        #: observation COUNT would read stats lines as cells.
        self.cellat_stats: list[str] = []
        #: type="ModemIdentity" rows: each helper's record of the modem
        #: it opened (make / model / firmware / IMEI, capture_cell_diag/
        #: diag_modemident.h). Routed by type like the rows above: one per open,
        #: and counted as an observation it would be a phantom cell in every
        #: A/B and count assertion.
        self.modem_identities: list[str] = []
        #: OPENREPORT's hardware string; None until the open report.
        self.open_hardware: "str | None" = None
        #: OPENREPORT's channel list and current channel: what the
        #: server shows as kismet.datasource.channels / .channel. None = absent.
        self.open_channels: "list[str] | None" = None
        self.open_channel: "str | None" = None
        #: DATAREPORT packet blocks (cf_send_data), in arrival order, as dicts
        #: ``{dlt, ts_s, ts_us, length, content}`` -- ``content`` is bytes. On
        #: celldiag these are the raw-stream slices; a packet also carrying
        #: a JSON block is recorded here AND routed as JSON.
        self.raw_packets: list[dict] = []
        #: Host wall clock (``time.time()``) when the read that completed the
        #: current frame returned -- copied into each raw packet as
        #: ``recv_wall``. A raw slice's ``ts_s``/``ts_us`` is the capture's own
        #: gettimeofday() at the port read, on the same host clock, so
        #: ``recv_wall - ts`` is how long the frame sat in the capture's output
        #: ring before reaching the pipe (up to the 500 ms select timeout).
        self._chunk_wall: "float | None" = None
        self.messages: list[str] = []
        # Parallel to `messages`: the MSGFLAG bitmask of each. Kept as its own list
        # rather than tuples so every existing `in run.messages` assertion keeps
        # working unchanged. MSGFLAG_INFO == 2, MSGFLAG_ERROR == 4.
        self.message_flags: list[int] = []
        self.errors: list[str] = []
        self.open_code: int | None = None
        self.open_message: str | None = None
        #: OPENREPORT field 11; None = the helper did not opt in.
        self.close_grace_ms: "int | None" = None
        #: A server-initiated graceful close: once ``close_when`` holds,
        #: send ONE CLOSEREQ and keep pumping -- never close the pipe -- until
        #: the helper exits by itself. ``close_sent_mono`` / ``exit_mono`` time
        #: it, so a test can assert the helper finished inside its grace.
        self.close_when = close_when
        self.close_sent_mono: "float | None" = None
        self.exit_mono: "float | None" = None
        #: Why the pump stopped: ``"eof"`` (the binary closed its output),
        #: ``"exit"`` (the process was seen gone), ``"stop_when"``, or
        #: ``"timeout"``. A run cut by its timeout returns the same kind of
        #: result as one that finished, only shorter, so a caller comparing two
        #: runs must check this.
        self.ended_by: "str | None" = None

    @property
    def timed_out(self) -> bool:
        """True when the pump gave up at ``timeout`` rather than the run ending."""
        return self.ended_by == "timeout"

    def run(self) -> "CaptureRun":
        # pipe A: harness -> binary (binary reads a_r); pipe B: binary -> harness.
        a_r, a_w = os.pipe()
        b_r, b_w = os.pipe()
        proc = subprocess.Popen(
            [self.binary, f"--in-fd={a_r}", f"--out-fd={b_w}"],
            pass_fds=(a_r, b_w),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=self.preexec_fn,
            env=self.env,
        )
        os.close(a_r)
        os.close(b_w)
        try:
            self._pump(proc, in_fd=a_w, out_fd=b_r)
        finally:
            for fd in (a_w, b_r):
                try:
                    os.close(fd)
                except OSError:
                    pass
            if proc.poll() is None and self.graceful_close_s > 0:
                try:
                    proc.wait(timeout=self.graceful_close_s)
                except subprocess.TimeoutExpired:
                    pass
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    proc.kill()
                    proc.wait()
            self.exit_code = proc.returncode
        return self

    def _pump(self, proc, in_fd: int, out_fd: int):
        seqno = 1
        os.write(in_fd, _frame(PKT_OPENREQ, seqno,
                               _mp_map({1: self.definition})))
        deadline = time.monotonic() + self.timeout
        next_ping = time.monotonic() + 5.0
        in_open = True

        sel = selectors.DefaultSelector()
        sel.register(out_fd, selectors.EVENT_READ)
        buf = bytearray()

        while time.monotonic() < deadline:
            now = time.monotonic()
            if in_open and now >= next_ping:
                # mandatory <15s keepalive so the binary doesn't FATAL-exit
                try:
                    os.write(in_fd, _frame(PKT_PING, 0))
                except BrokenPipeError:  # pragma: no cover
                    pass
                next_ping = now + 5.0

            for _key, _mask in sel.select(timeout=self.poll_s):
                try:
                    chunk = os.read(out_fd, 65536)
                except OSError:  # pragma: no cover
                    chunk = b""
                if not chunk:                      # binary drained + exited
                    if self.exit_mono is None:
                        self.exit_mono = time.monotonic()
                    self.ended_by = "eof"
                    return
                self._chunk_wall = time.time()
                buf.extend(chunk)
                self._drain_frames(buf)
                if self.drain_pause_s > 0:
                    time.sleep(self.drain_pause_s)

            # Checked after each drained batch, so a predicate written against
            # observations/messages sees the same state an assertion would.
            for i, (when, knob) in enumerate(self.configure):
                if self._configure_done[i] or not when(self):
                    continue
                seqno += 1
                self._configure_done[i] = True
                try:
                    os.write(in_fd, _frame(PKT_CONFIGREQ, seqno,
                                           _mp_map({CONFIGREQ_FIELD_CHANNEL: knob})))
                except BrokenPipeError:  # pragma: no cover
                    pass

            if (self.close_when is not None and self.close_sent_mono is None
                    and self.close_when(self)):
                seqno += 1
                self.close_sent_mono = time.monotonic()
                try:
                    os.write(in_fd, _frame(PKT_CLOSEREQ, seqno))
                except BrokenPipeError:  # pragma: no cover
                    pass

            if self.stop_when is not None and self.stop_when(self):
                self.ended_by = "stop_when"
                return

            if proc.poll() is not None:
                if self.exit_mono is None:
                    self.exit_mono = time.monotonic()
                # process exited; consume any final buffered frames then stop
                try:
                    while True:
                        chunk = os.read(out_fd, 65536)
                        if not chunk:
                            break
                        self._chunk_wall = time.time()
                        buf.extend(chunk)
                except OSError:
                    pass
                self._drain_frames(buf)
                self.ended_by = "exit"
                return
        self.ended_by = "timeout"

    # ── override points ────────────────────────────────────────────────────────
    def _on_json(self, js: str) -> None:
        """Route one relayed JSON object. Default: it is an observation.

        celldiag overrides this because two streams share the relay and
        conflating them is a bug — see ``CellDiagRun``.

        An override that appends to ``observations`` MUST call
        ``_record_observation`` instead, or ``observation_gps`` silently falls
        out of step and every position assertion reads the wrong packet's fix.
        """
        self._record_observation(js)

    def _record_observation(self, js: str) -> None:
        """Append an observation and the GPS block it arrived with, together.

        One method for the pair so the two lists cannot drift: the failure mode
        of two separate appends is an off-by-one that makes every geo-tag
        assertion read a neighbouring packet's position, which is worse than
        not asserting at all because it is confidently wrong.
        """
        self.observations.append(js)
        self.observation_gps.append(self._packet_gps)

    def _drain_frames(self, buf: bytearray):
        while len(buf) >= HDR_LEN:
            sig, sent, ver, length, pkt_type, _code, _seq = _HDR.unpack_from(buf, 0)
            if sig != SIG or sent != V3_SENTINEL:
                raise AssertionError(
                    f"frame desync: sig=0x{sig:08x} sentinel=0x{sent:04x}")
            if length + _V3_MINUS_STUB > MAX_EXTERNAL_FRAME_LEN:
                raise AssertionError(
                    f"pkt_type {pkt_type} frame of {length + _V3_MINUS_STUB} B exceeds "
                    f"the server's MAX_EXTERNAL_FRAME_LEN ({MAX_EXTERNAL_FRAME_LEN}); "
                    f"a real Kismet server would error the source on it")
            if len(buf) < HDR_LEN + length:
                return                              # wait for the rest
            payload = bytes(buf[HDR_LEN:HDR_LEN + length])
            del buf[:HDR_LEN + length]
            self._handle(pkt_type, _code, payload)

    def _handle(self, pkt_type: int, code: int, payload: bytes):
        if pkt_type == PKT_PACKET:
            top, _ = _mp_unpack(payload) if payload else ({}, 0)
            packetblock = top.get(DATAREPORT_FIELD_PACKETBLOCK)
            if isinstance(packetblock, dict):
                content = packetblock.get(SUB_PACKET_FIELD_CONTENT)
                self.raw_packets.append({
                    "dlt": packetblock.get(SUB_PACKET_FIELD_DLT),
                    "ts_s": packetblock.get(SUB_PACKET_FIELD_TS_S),
                    "ts_us": packetblock.get(SUB_PACKET_FIELD_TS_US),
                    "length": packetblock.get(SUB_PACKET_FIELD_LENGTH),
                    "content": bytes(content) if isinstance(content, (bytes, bytearray)) else None,
                    "recv_wall": self._chunk_wall,
                })
            jsonblock = top.get(DATAREPORT_FIELD_JSONBLOCK)
            if isinstance(jsonblock, dict):
                js = jsonblock.get(SUB_JSON_FIELD_JSON)
                if isinstance(js, str):
                    gpsblock = top.get(DATAREPORT_FIELD_GPSBLOCK)
                    # Set BEFORE routing: `_on_json` (or an override) is what
                    # decides this object was an observation, and the position
                    # has to be in hand by then.
                    self._packet_gps = gpsblock if isinstance(gpsblock, dict) else None
                    try:
                        jtype = jsonblock.get(SUB_JSON_FIELD_TYPE)
                        if jtype == "ClockAnchor":
                            self.clock_anchors.append(js)
                        elif jtype == "RawAT":
                            self.raw_at.append(js)
                        elif jtype == "RawDiagDrop":
                            self.raw_diag_drops.append(js)
                        elif jtype == "DiagCrcCensus":
                            # celldiag's end-of-stream CRC census row. A
                            # type this driver does not route reaches _on_json,
                            # and CellDiagRun would count it as a cell OBSERVATION
                            # -- one extra row in every replay A/B comparison.
                            self.crc_census.append(js)
                        elif jtype == "cellat_stats":
                            self.cellat_stats.append(js)
                        elif jtype == "ModemIdentity":
                            self.modem_identities.append(js)
                        else:
                            self._on_json(js)
                    finally:
                        self._packet_gps = None
        elif pkt_type == PKT_OPENREPORT:
            self.open_code = code
            top, _ = _mp_unpack(payload) if payload else ({}, 0)
            m = top.get(OPENREPORT_FIELD_MESSAGE)
            if isinstance(m, str):
                self.open_message = m
            g = top.get(OPENREPORT_FIELD_CLOSEGRACE)
            if isinstance(g, int):
                self.close_grace_ms = g
            # The hardware label the helper reported at open -- the one
            # string Kismet stored per source before the ModemIdentity record.
            hw = top.get(OPENREPORT_FIELD_HARDWARE)
            if isinstance(hw, str):
                self.open_hardware = hw
            chans = top.get(OPENREPORT_FIELD_CHAN_LIST)
            if isinstance(chans, list):
                self.open_channels = [c for c in chans if isinstance(c, str)]
            ch = top.get(OPENREPORT_FIELD_CHANNEL)
            if isinstance(ch, str):
                self.open_channel = ch
        elif pkt_type == PKT_MESSAGE:
            top, _ = _mp_unpack(payload) if payload else ({}, 0)
            s = top.get(2)
            if isinstance(s, str):
                self.messages.append(s)
                # Field 1 is the MSGFLAG severity bitmask. The capture helper
                # escalates the diag_inventory census line from INFO to ERROR
                # when it has something to flag (`unrecognized` or `silent`);
                # a harness that kept only the string could not test that.
                self.message_flags.append(
                    top.get(1) if isinstance(top.get(1), int) else 0)
        elif pkt_type == PKT_CONFIGREPORT:
            top, _ = _mp_unpack(payload) if payload else ({}, 0)
            m = top.get(CONFIGREPORT_FIELD_MSG)
            # The MESSAGE is what carries the *reason*; the header code only
            # says yes/no. A test that asserts on the code alone cannot tell
            # "unknown key" from "recognised but open-time only".
            self.config_results.append((code, m if isinstance(m, str) else ""))
            ch = top.get(CONFIGREPORT_FIELD_CHANNEL)
            self.config_channels.append(ch if isinstance(ch, str) else None)
        elif pkt_type == PKT_ERROR:
            top, _ = _mp_unpack(payload) if payload else ({}, 0)
            s = top.get(1)
            if isinstance(s, str):
                self.errors.append(s)
        # PONG (3) and anything else: ignore.

