#!/usr/bin/env python3
"""QMI → Kismet cell_observation NDJSON feed — the poll loop.

``kismet_cell_bridge`` turns ONE parsed ``nas-get-cell-location-info`` into
cell_observation dicts. This is the process that runs it on a cadence: poll
``qmicli`` for cell-location-info (+ signal-info), convert, and write one JSON
object per line to stdout, flushed per poll.

Who reads stdout: ``kismet_cap_cell_at`` capture child, when its source
carries ``qmifeed=<command>``. The child spawns this command, reads its stdout
line by line, and forwards every line to the Kismet server as a ``CellModem``
KDS record — the same record type its own AT observations ride — so
``datasource_cell_at`` / ``phy_cell`` merge QMI cells with the AT and DIAG ones
per tower via ``prov.src`` (``"qmi"`` here). Kismet itself never reads NDJSON;
the capture child is the adapter.

Usage (standalone smoke, or as the ``qmifeed=`` command)::

    python3 capture_cell_at/qmifeed/kismet_qmi_feed.py           # autodetect, 5 s cadence
    python3 capture_cell_at/qmifeed/kismet_qmi_feed.py -d /dev/cdc-wdm0 --interval 2
    python3 capture_cell_at/qmifeed/kismet_qmi_feed.py --once    # one poll, then exit

Contract with the reader (``cellat_qmifeed.c``):

* stdout carries ONLY complete JSON objects, one per line, each flushed.
* Diagnostics go to stderr, never stdout.
* A failed poll (qmicli error, timeout, no serving cell) emits nothing and the
  loop continues — a modem that is briefly out of service is not a reason for
  the feed to die. Only "no QMI device at all" exits non-zero.
* EOF / SIGPIPE on stdout (the reader went away) ends the loop quietly.
* So does a change of parent pid. A modem with no cell in range writes
  nothing, so a dead reader would never surface as EPIPE; and PDEATHSIG from
  the capture child reaches only its direct child (often ``sh -c``), leaving
  this process orphaned. Checked once per poll.

Which modem: ``kismet_cap_cell_at`` exports ``CELLAT_IMEI`` -- the
IMEI its source verified on the AT port. When it is set, the feed polls only a
QMI device whose ``--dms-get-ids`` IMEI equals it: ``-d`` is tried first, then
every detected device, and a ``-d`` on another modem is re-routed with a loud
stderr note (``cdc-wdm`` numbering is not stable across replugs). No match
exits 3; the capture child also drops any line stamped with another IMEI.

Raw log: ``--qmilog <path | dir/ | template>`` tees every qmicli
call -- argv, rc, stdout, stderr, host-monotonic instants -- to JSONL, the QMI
sibling of the capture helper's ``atlog=``. Each record is written BEFORE its output is parsed,
so a parser bug never costs the input. ``--qmilog-wire`` adds ``--verbose-full``
and keeps each QMUX frame's full bytes (plain ``--verbose`` truncates them);
that mode's records carry personal info (IMEI etc.), like ``atlog=``'s.

In-band: when the capture child exports
``CELLAT_QMIFEED_PROTO=2`` it reads two TAGGED stdout lines besides the
observations. Every qmicli call's record -- the very dict ``--qmilog`` writes --
also goes out as ``#rawqmi {json}`` and becomes a ``RawQMI`` row in the
``.kismet``, so a drive keeps its QMI input with no file tee at all. Every
operator note also goes out as ``#msg info|error <text>`` and reaches Kismet's
message bus (stderr still gets it, for the console log). Without that variable
-- run by hand, or under an older capture helper -- stdout stays observation-only.

Always opens the device with ``--device-open-proxy`` (via
:meth:`QMIDevice.qmicli_args`) so the feed shares the control port with
ModemManager or any other QMI client instead of stealing it.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Optional, TextIO

if __package__ in (None, ""):
    # Run by path, as the qmifeed= command is (``python3 <tree>/capture_cell_at/
    # qmifeed/kismet_qmi_feed.py``). Make this directory's parent importable and
    # claim the package name, so the relative imports below resolve with
    # nothing installed and no PYTHONPATH.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "qmifeed"

from .kismet_cell_bridge import (  # noqa: E402
    cell_location_to_observations,
    observations_to_ndjson,
)
from .parse import (  # noqa: E402
    parse_cell_location_info,
    parse_signal_info,
)

DEFAULT_INTERVAL_S = 5.0
QMICLI_TIMEOUT_S = 15.0

# (argv) -> (returncode, combined output). Injected by tests.
Runner = Callable[[list[str]], tuple[int, str]]

_IMEI_RE = re.compile(r"IMEI:\s*'(\d{14,16})'")
_IMEI_ONLY_RE = re.compile(r"\d{14,16}")

IMEI_ENV = "CELLAT_IMEI"
PROTO_ENV = "CELLAT_QMIFEED_PROTO"
# The largest ``#rawqmi`` JSON payload the reader forwards. The helper exports
# it. It is not the helper's 64 KiB READ buffer: the Kismet server errors the
# whole source over any frame past 16 KiB. The default is for a capture helper
# that exports nothing: its server has that same 16 KiB frame, and 12 KiB leaves
# the envelope room, as the helper's own CELLAT_ROW_JSON_MAX does.
RAWQMI_MAX_ENV = "CELLAT_QMIFEED_RAWQMI_MAX"
RAWQMI_MAX_DEFAULT = 12288
EXIT_NO_DEVICE = 2
EXIT_WRONG_MODEM = 3
DMS_ATTEMPTS = 3
DMS_RETRY_S = 2.0


class DeviceMismatch(RuntimeError):
    """No QMI device reports the IMEI the cellat source verified."""


# (argv) -> (returncode, stdout, stderr, err-or-None): one qmicli call, unmerged.
RawRunner = Callable[[list[str]], tuple[int, str, str, Optional[str]]]


def run_qmicli_raw(argv: list[str], timeout: float = QMICLI_TIMEOUT_S
                   ) -> tuple[int, str, str, Optional[str]]:
    """Run one qmicli invocation, keeping stdout and stderr apart.

    A timeout (rc 124) or a missing binary (rc 127) is a failed call with
    ``err`` saying why, never an exception.
    """
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        def _s(v):
            return v.decode(errors="replace") if isinstance(v, bytes) else (v or "")
        return 124, _s(e.stdout), _s(e.stderr), \
            f"qmicli timed out after {timeout:.0f}s: {' '.join(argv)}"
    except OSError as e:
        return 127, "", "", f"cannot run {argv[0]}: {e}"
    return proc.returncode, proc.stdout, proc.stderr, None


def _merged(raw: tuple[int, str, str, Optional[str]]) -> tuple[int, str]:
    rc, out, err_text, err = raw
    return rc, err if err is not None else out + err_text


def run_qmicli(argv: list[str], timeout: float = QMICLI_TIMEOUT_S) -> tuple[int, str]:
    """Run one qmicli invocation; a timeout reads as a failed call, not a crash."""
    return _merged(run_qmicli_raw(argv, timeout))


# ---- raw QMI log ------------------------------------------------

_DEBUG_LINE_RE = re.compile(r"^(<<<<<<|\[\d{1,2} \w{3} \d{4}, \d\d:\d\d:\d\d\] \[Debug\])")
_WIRE_DIR_RE = re.compile(r"\] (sent|received) message\.\.\.$")
_WIRE_LEN_RE = re.compile(r"^<<<<<<\s+length = (\d+)$")
_WIRE_DATA_RE = re.compile(r"^<<<<<<\s+data\s+= ([0-9A-Fa-f:]*)(\.\.\.)?$")


def parse_wire(text: str) -> list[dict]:
    """QMUX frames from ``qmicli --verbose-full`` output: [{dir, len, hex}].

    A frame whose hex is shorter than its stated length (``--verbose`` without
    ``-full`` truncates with ``...``) is kept and marked ``"truncated": true``,
    never passed off as whole.
    """
    frames: list[dict] = []
    direction = None
    length = None
    for line in text.splitlines():
        m = _WIRE_DIR_RE.search(line)
        if m:
            direction = "tx" if m.group(1) == "sent" else "rx"
            length = None
            continue
        m = _WIRE_LEN_RE.match(line)
        if m and direction:
            length = int(m.group(1))
            continue
        m = _WIRE_DATA_RE.match(line)
        if m and direction and length is not None:
            hexs = m.group(1).replace(":", "").upper()
            frame = {"dir": direction, "len": length, "hex": hexs}
            if len(hexs) != 2 * length or m.group(2):
                frame["truncated"] = True
            frames.append(frame)
            direction = length = None
    return frames


def strip_debug(text: str) -> str:
    """qmicli output with its --verbose debug lines removed (they share stdout)."""
    kept = [l for l in text.splitlines(keepends=True) if not _DEBUG_LINE_RE.match(l)]
    return "".join(kept).lstrip("\n")


def _utc_iso(wall: float) -> str:
    return _dt.datetime.fromtimestamp(wall, _dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_qmilog_path(spec: str, imei: Optional[str], wall: float) -> Path:
    """The file for ``spec``, templated like the capture helper's ``atlog=``.

    A spec ending in ``/`` (or naming an existing directory) becomes
    ``<dir>/qmilog-<imei>-<UTC>.jsonl``. Otherwise ``%i`` -> IMEI (``unknown``
    when there is none), ``%t`` -> UTC ``YYYYmmddTHHMMSSZ``, ``%%`` -> ``%``.
    """
    stamp = _dt.datetime.fromtimestamp(wall, _dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    who = imei or "unknown"
    if spec.endswith("/") or Path(spec).is_dir():
        return Path(spec) / f"qmilog-{who}-{stamp}.jsonl"
    out, i = [], 0
    while i < len(spec):
        if spec[i] == "%" and i + 1 < len(spec):
            out.append({"i": who, "t": stamp, "%": "%"}.get(spec[i + 1], spec[i:i + 2]))
            i += 2
        else:
            out.append(spec[i])
            i += 1
    return Path("".join(out))


def rawqmi_max(env=os.environ) -> int:
    """The payload bound the capture exported; the default when it did not."""
    try:
        n = int(env.get(RAWQMI_MAX_ENV, ""))
    except ValueError:
        return RAWQMI_MAX_DEFAULT
    return n if n > 0 else RAWQMI_MAX_DEFAULT


def tagged_protocol(env=os.environ) -> bool:
    """True when the reader understands ``#rawqmi`` / ``#msg`` lines."""
    try:
        return int(env.get(PROTO_ENV, "0")) >= 2
    except ValueError:
        return False


class TaggedOut:
    """Writes the capture helper's tagged stdout lines."""

    def __init__(self, out: TextIO, raw_max: Optional[int] = None):
        self.out = out
        self.raw_max = raw_max if raw_max is not None else rawqmi_max()
        self.raw = 0
        self.raw_trimmed = 0
        self.raw_skipped = 0
        self.notes = 0

    def _line(self, line: str) -> None:
        self.out.write(line + "\n")
        self.out.flush()

    def rawqmi(self, rec: dict) -> None:
        payload = json.dumps(rec, separators=(",", ":"))
        if len(payload.encode()) > self.raw_max:
            # qmicli's verbose text is the bulk; the QMUX frames and the rest
            # are kept, and the record says what was cut. (The --qmilog file
            # tee, if armed, keeps the whole record.)
            rec = dict(rec, stdout="", stdout_trimmed=len(rec.get("stdout") or ""))
            payload = json.dumps(rec, separators=(",", ":"))
            if len(payload.encode()) > self.raw_max:
                self.raw_skipped += 1
                return
            self.raw_trimmed += 1
        self._line("#rawqmi " + payload)
        self.raw += 1

    def note(self, level: str, text: str) -> None:
        text = " ".join(text.split())
        if text:
            self._line(f"#msg {level} {text}")
            self.notes += 1


class NoteLog:
    """A ``log=`` stream that also forwards each complete line as a ``#msg``.

    stderr keeps every note (the Kismet console log); the bus copy drops the
    ``kismet_qmi_feed:`` prefix, since the capture helper prefixes the source's own name.
    """

    PREFIX = "kismet_qmi_feed: "

    def __init__(self, tagged: Optional[TaggedOut], level: str,
                 err: Optional[TextIO] = None):
        self.tagged = tagged
        self.level = level
        self.err = err
        self._buf = ""

    def write(self, s: str) -> int:
        (self.err or sys.stderr).write(s)
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if self.tagged is not None:
                self.tagged.note(self.level, line[len(self.PREFIX):]
                                 if line.startswith(self.PREFIX) else line)
        return len(s)

    def flush(self) -> None:
        (self.err or sys.stderr).flush()


class QmiLog:
    """JSONL tee of every qmicli call the feed makes.

    ``wrap(raw)`` returns a :data:`Runner` that records each call and then
    returns its merged output, so the record is on disk before anything parses
    it. Calls made before :meth:`open` (device selection, which decides the
    IMEI the path may need) are held and written first.
    """

    SCHEMA = 1

    def __init__(self, spec: Optional[str], *, wire: bool = False,
                 sink: Optional[Callable[[dict], None]] = None,
                 clock_ns: Callable[[], int] = time.monotonic_ns,
                 wall: Callable[[], float] = time.time):
        self.spec = spec            # None: in-band only (no file tee)
        self.wire = wire
        self.sink = sink            # the #rawqmi writer
        self.clock_ns = clock_ns
        self.wall = wall
        self.path: Optional[Path] = None
        self.records = 0
        self._fh: Optional[TextIO] = None
        self._pending: list[dict] = []

    def open(self, imei: Optional[str]) -> Path:
        self.path = resolve_qmilog_path(self.spec, imei, self.wall())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8")
        for rec in self._pending:
            self._write(rec)
        self._pending.clear()
        return self.path

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def _write(self, rec: dict) -> None:
        self._fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        self._fh.flush()
        self.records += 1

    def record(self, rec: dict) -> None:
        if self.sink is not None:
            self.sink(rec)
        if self.spec is None:
            return
        if self._fh is None:
            self._pending.append(rec)
        else:
            self._write(rec)

    def wrap(self, raw: RawRunner) -> Runner:
        def run(argv: list[str]) -> tuple[int, str]:
            call = argv + (["--verbose-full"] if self.wire else [])
            wall = self.wall()
            t0 = self.clock_ns()
            rc, out, err_text, err = raw(call)
            t1 = self.clock_ns()
            rec = {"schema": self.SCHEMA, "ts_mono_ns": t0, "ts_utc": _utc_iso(wall),
                   "rx_done_ns": t1, "duration_ms": round((t1 - t0) / 1e6, 3),
                   "argv": call, "rc": rc, "stdout": out, "stderr": err_text, "err": err}
            if self.wire:
                rec["qmux"] = parse_wire(out + err_text)
                out = strip_debug(out)
            self.record(rec)
            return _merged((rc, out, err_text, err))
        return run


def read_imei(base: list[str], run: Runner) -> Optional[str]:
    """IMEI via ``--dms-get-ids``; None when the modem will not say."""
    rc, out = run(base + ["--dms-get-ids"])
    if rc != 0:
        return None
    m = _IMEI_RE.search(out)
    return m.group(1) if m else None


def poll_once(base: list[str], run: Runner, *, imei: Optional[str],
              with_signal: bool = True,
              now: Callable[[], float] = time.time,
              log: TextIO = sys.stderr) -> list[dict]:
    """One poll: cell-location-info (+ signal-info) → observation dicts.

    Returns [] on any failure, after saying why on ``log``.
    """
    captured_at = now()
    rc, out = run(base + ["--nas-get-cell-location-info"])
    if rc != 0:
        print(f"kismet_qmi_feed: cell-location-info failed (rc={rc}): "
              f"{out.strip().splitlines()[0] if out.strip() else ''}",
              file=log, flush=True)
        return []
    cell = parse_cell_location_info(out)
    if cell.error:
        print(f"kismet_qmi_feed: cell-location-info error: {cell.error}",
              file=log, flush=True)
        return []

    signal = None
    if with_signal:
        src, sout = run(base + ["--nas-get-signal-info"])
        if src == 0:
            parsed = parse_signal_info(sout)
            signal = None if parsed.error else parsed

    return cell_location_to_observations(
        cell, imei=imei, captured_at=captured_at, signal=signal)


def emit(observations: list[dict], out: TextIO) -> None:
    """Write observations as NDJSON and flush — one poll is one flush."""
    if not observations:
        return
    out.write(observations_to_ndjson(observations) + "\n")
    out.flush()


def parent_gone(parent: int, getppid: Callable[[], int] = os.getppid) -> bool:
    """True once we have been reparented, i.e. whoever spawned us is gone."""
    return getppid() != parent


def expected_imei(env=os.environ) -> Optional[str]:
    """The source's verified IMEI from ``CELLAT_IMEI``, or None.

    Junk and the all-zeros unknown-IMEI sentinel read as None: an identity
    nobody verified is not something to match against.
    """
    v = env.get(IMEI_ENV, "")
    if not _IMEI_ONLY_RE.fullmatch(v) or set(v) == {"0"}:
        return None
    return v


def _base(device: str) -> list[str]:
    base = ["qmicli", "-d", device, "--device-open-proxy"]
    # A cdc-wdm port may be QMI or MBIM, and libqmi tells them apart. It cannot
    # tell anything about a port outside that subsystem -- the Quectel PCIe
    # driver's /dev/mhi_QMI0 fails "unexpected port subsystem" and is never
    # opened -- and such a port is QMI, so say so.
    if not os.path.basename(device).startswith("cdc-wdm"):
        base.append("--device-open-qmi")
    return base


def _detected_devices() -> list[str]:
    from .detect import detect_qmi_devices
    return [d.device for d in detect_qmi_devices()]


def select_device(explicit: Optional[str], expected: Optional[str], run: Runner, *,
                  detect: Callable[[], list[str]] = _detected_devices,
                  log: TextIO = sys.stderr,
                  attempts: int = DMS_ATTEMPTS, retry_s: float = DMS_RETRY_S,
                  sleep: Callable[[float], None] = time.sleep,
                  ) -> Optional[tuple[list[str], Optional[str]]]:
    """(qmicli base argv, DMS IMEI) for the device to poll, or None if none exists.

    Without ``expected``: ``explicit`` or the
    first detected device, and whatever IMEI it reports (possibly None).

    With ``expected``, only a device whose DMS IMEI equals it is returned.
    ``explicit`` is asked first, then every detected device. A device that did
    not answer is asked again, up to ``attempts`` rounds; one that answered
    with another IMEI is not. Raises :class:`DeviceMismatch` when nothing matches.
    """
    if expected is None:
        dev = explicit or next(iter(detect()), None)
        if dev is None:
            return None
        base = _base(dev)
        return base, read_imei(base, run)

    candidates: list[str] = []
    for d in ([explicit] if explicit else []) + detect():
        if d not in candidates:
            candidates.append(d)
    if not candidates:
        return None

    seen: dict[str, Optional[str]] = {}
    for attempt in range(attempts):
        for dev in candidates:
            if seen.get(dev) is not None:
                continue            # answered with another modem's IMEI
            imei = read_imei(_base(dev), run)
            seen[dev] = imei
            if imei == expected:
                if explicit and dev != explicit:
                    print(f"kismet_qmi_feed: -d {explicit} is modem {seen[explicit] or '(no answer)'}, "
                          f"not this source's {expected}; polling {dev} instead",
                          file=log, flush=True)
                return _base(dev), imei
        if all(v is not None for v in seen.values()) or attempt == attempts - 1:
            break
        sleep(retry_s)
    detail = ", ".join(f"{d} -> {v or 'no answer'}" for d, v in seen.items())
    raise DeviceMismatch(
        f"no QMI device reports IMEI {expected} (the cellat source's modem): {detail}")


def main(argv: Optional[list[str]] = None) -> int:
    """Run the feed. The reader closing our stdout is a normal stop, wherever it lands.

    ``BrokenPipeError`` is caught here, not only in the poll loop: device
    selection writes too (its ``#rawqmi`` rows and ``#msg`` notes), and a source
    failing its bring-up is killed exactly then, which would otherwise print a
    traceback on every teardown of a reopen loop.
    """
    try:
        return _main(argv)
    except BrokenPipeError:
        # The reader (kismet_cap_cell_at) closed our stdout. Point stdout at
        # devnull so interpreter shutdown does not re-raise while flushing it.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


def _main(argv: Optional[list[str]]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-d", "--device",
                    help="QMI/MBIM control device (default: first detected)")
    ap.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_S,
                    help=f"seconds between polls (default {DEFAULT_INTERVAL_S:g})")
    ap.add_argument("--once", action="store_true", help="poll once and exit")
    ap.add_argument("--imei", help="IMEI for prov (default: read via --dms-get-ids)")
    ap.add_argument("--no-signal", action="store_true",
                    help="skip the nas-get-signal-info backfill poll")
    ap.add_argument("--qmilog", metavar="SPEC",
                    help="raw QMI log: a .jsonl path, a dir/ (qmilog-<imei>-<UTC>.jsonl), "
                         "or a template with %%i / %%t")
    ap.add_argument("--qmilog-wire", action="store_true",
                    help="add --verbose-full and keep each QMUX frame's bytes, in the "
                         "--qmilog file and/or the in-band RawQMI rows")
    args = ap.parse_args(argv)
    if args.interval <= 0:
        ap.error("--interval must be > 0")
    tagged = TaggedOut(sys.stdout) if tagged_protocol() else None
    if args.qmilog_wire and not (args.qmilog or tagged):
        ap.error("--qmilog-wire needs --qmilog (or a capture child that reads "
                 f"RawQMI lines, which sets {PROTO_ENV}=2)")
    info = NoteLog(tagged, "info")
    error = NoteLog(tagged, "error")

    qmilog = (QmiLog(args.qmilog, wire=args.qmilog_wire,
                     sink=tagged.rawqmi if tagged else None)
              if (args.qmilog or tagged) else None)
    run = qmilog.wrap(run_qmicli_raw) if qmilog else run_qmicli

    expected = expected_imei()
    if args.imei and expected and args.imei != expected:
        print(f"kismet_qmi_feed: --imei {args.imei} contradicts the source's verified "
              f"IMEI {expected} ({IMEI_ENV}); refusing to stamp it",
              file=error, flush=True)
        return EXIT_WRONG_MODEM
    if args.imei:
        # An operator assertion: no DMS read, no device check.
        dev = args.device or next(iter(_detected_devices()), None)
        sel = None if dev is None else (_base(dev), args.imei)
    else:
        try:
            sel = select_device(args.device, expected, run, log=info)
        except DeviceMismatch as e:
            print(f"kismet_qmi_feed: {e}", file=error, flush=True)
            if qmilog and qmilog.spec:  # the rejected DMS answers are the evidence
                qmilog.open(expected)
                qmilog.close()
            return EXIT_WRONG_MODEM
    if sel is None:
        print("kismet_qmi_feed: no QMI/MBIM control device found", file=error, flush=True)
        return EXIT_NO_DEVICE
    base, imei = sel
    print(f"kismet_qmi_feed: polling {base[2]} every {args.interval:g}s "
          f"(imei={imei or 'unknown'})", file=info, flush=True)

    if qmilog and qmilog.spec:
        print(f"kismet_qmi_feed: raw QMI log -> {qmilog.open(imei)}"
              f"{' (with QMUX bytes)' if qmilog.wire else ''}", file=info, flush=True)
    parent = os.getppid()
    try:
        while True:
            if parent_gone(parent):
                print("kismet_qmi_feed: parent exited; stopping", file=sys.stderr)
                return 0
            t0 = time.monotonic()
            emit(poll_once(base, run, imei=imei,
                           with_signal=not args.no_signal, log=error), sys.stdout)
            if args.once:
                return 0
            time.sleep(max(0.0, args.interval - (time.monotonic() - t0)))
    except KeyboardInterrupt:
        return 0
    finally:
        if qmilog:
            qmilog.close()


if __name__ == "__main__":
    sys.exit(main())
