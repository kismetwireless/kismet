#!/usr/bin/env python3
"""Tests for qmifeed.kismet_qmi_feed — the qmicli poll loop behind qmifeed=.

The runner is injected, so every test is offline. Fixtures are real qmicli
output captured from a Sierra EM9291 over QMI-over-MBIM.
"""

import io
import json
import os
import subprocess
import sys
import time
import unittest
import unittest.mock
from pathlib import Path

from qmifeed import kismet_qmi_feed as feed

BASE = ["qmicli", "-d", "/dev/cdc-wdm0", "--device-open-proxy"]

# EM9291 live capture (idle on 310-026, band 3 serving).
CELL_EM9291 = """\
[/dev/cdc-wdm0] Successfully got cell location info
Intrafrequency LTE Info
\tUE In Idle: 'yes'
\tPLMN: '310026'
\tTracking Area Code: '6699'
\tGlobal Cell ID: '11259362'
\tEUTRA Absolute RF Channel Number: '1250' (E-UTRA band 3: 1800+)
\tServing Cell ID: '242'
\tCell Reselection Priority: '6'
\tS Non Intra Search Threshold: '2'
\tServing Cell Low Threshold: '0'
\tS Intra Search Threshold: '46'
\tCell [0]:
\t\tPhysical Cell ID: '242'
\t\tRSRQ: '-15.0' dB
\t\tRSRP: '-108.2' dBm
\t\tRSSI: '-71.0' dBm
\t\tCell Selection RX Level: '15'
Interfrequency LTE Info
\tUE In Idle: 'yes'
\tFrequency [0]:
\t\tEUTRA Absolute RF Channel Number: '900' (E-UTRA band 2: 1900 PCS)
\t\tSelection RX Level Low Threshold: '0'
\t\tCell Selection RX Level High Threshold: '8'
\t\tCell Reselection Priority: '5'
LTE Timing Advance: 'unavailable'
"""

SIGNAL_EM9291 = """\
[/dev/cdc-wdm0] Successfully got signal info
LTE:
\tRSSI: '-74 dBm'
\tRSRQ: '-16 dB'
\tRSRP: '-109 dBm'
\tSNR: '3.4 dB'
"""

IDS_EM9291 = """\
[/dev/cdc-wdm0] Device IDs retrieved:
\t    ESN: '0'
\t   IMEI: '359876543210987'
\t   MEID: 'unknown'
"""


class FakeRunner:
    """Maps the trailing qmicli command flag to a canned (rc, output)."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        return self.table[argv[-1]]


def _poll(table, **kw):
    log = io.StringIO()
    run = FakeRunner(table)
    obs = feed.poll_once(BASE, run, imei=kw.pop("imei", "359876543210987"),
                         now=lambda: 1758800000.5, log=log, **kw)
    return obs, run, log.getvalue()


class TestPollOnce(unittest.TestCase):
    def test_serving_cell_emitted_with_qmi_prov(self):
        obs, _, _ = _poll({
            "--nas-get-cell-location-info": (0, CELL_EM9291),
            "--nas-get-signal-info": (0, SIGNAL_EM9291),
        })
        serving = [o for o in obs if o["is_serving"]]
        self.assertEqual(len(serving), 1)
        s = serving[0]
        self.assertEqual((s["mcc"], s["mnc"], s["tac"], s["cell_id"], s["pci"]),
                         ("310", "260", 6699, 11259362, 242))   # T-Mobile (310-026 is nibble-swapped BCD)
        self.assertEqual(s["rsrp"], -108)   # per-cell measurement wins over signal-info
        self.assertEqual(s["prov"]["src"], "qmi")
        self.assertEqual(s["prov"]["imei"], "359876543210987")
        self.assertEqual(s["prov"]["captured_at"], 1758800000.5)
        self.assertNotIn("band", s)         # never a band for QMI cells

    def test_unmeasured_inter_frequency_is_not_a_cell(self):
        # The EM9291's idle inter-freq block lists reselection FREQUENCIES with
        # no Cell [N] measurements. No PCI means no tower, so nothing is emitted
        # for EARFCN 900 -- only the serving cell reaches Kismet.
        obs, _, _ = _poll({
            "--nas-get-cell-location-info": (0, CELL_EM9291),
            "--nas-get-signal-info": (0, SIGNAL_EM9291),
        })
        self.assertEqual(len(obs), 1)
        self.assertNotIn(900, [o.get("earfcn") for o in obs])

    def test_no_signal_skips_the_second_qmicli_call(self):
        _, run, _ = _poll({"--nas-get-cell-location-info": (0, CELL_EM9291)},
                          with_signal=False)
        self.assertEqual([c[-1] for c in run.calls], ["--nas-get-cell-location-info"])

    def test_failed_signal_poll_still_emits_the_cell(self):
        obs, _, _ = _poll({
            "--nas-get-cell-location-info": (0, CELL_EM9291),
            "--nas-get-signal-info": (1, "error: couldn't get signal info"),
        })
        self.assertTrue(any(o["is_serving"] for o in obs))

    def test_nonzero_rc_emits_nothing_and_says_why(self):
        obs, run, log = _poll({"--nas-get-cell-location-info":
                               (1, "error: couldn't create client for the 'nas' service")})
        self.assertEqual(obs, [])
        self.assertIn("rc=1", log)
        self.assertEqual(len(run.calls), 1)   # no signal poll after a failed cell poll

    def test_qmicli_error_text_with_rc0_emits_nothing(self):
        obs, _, log = _poll({"--nas-get-cell-location-info":
                             (0, "error: couldn't get cell location info: Operation failed")})
        self.assertEqual(obs, [])
        self.assertIn("error", log)

    def test_every_call_uses_the_proxy_base(self):
        _, run, _ = _poll({
            "--nas-get-cell-location-info": (0, CELL_EM9291),
            "--nas-get-signal-info": (0, SIGNAL_EM9291),
        })
        for call in run.calls:
            self.assertEqual(call[:len(BASE)], BASE)


class TestBase(unittest.TestCase):
    def test_a_cdc_wdm_port_keeps_transport_autodetect(self):
        # A cdc-wdm port may be MBIM (the EM9190's is), so no mode is forced.
        self.assertEqual(feed._base("/dev/cdc-wdm1"),
                         ["qmicli", "-d", "/dev/cdc-wdm1", "--device-open-proxy"])

    def test_an_mhi_port_is_opened_explicitly_in_qmi_mode(self):
        # libqmi cannot tell the transport of the Quectel PCIe driver's
        # /dev/mhi_QMI0 ("unexpected port subsystem") and refuses to open it,
        # so every RM520N-GL call fails rc=1 without it. Forcing QMI mode is
        # what qmicli accepts on it.
        for dev in ("/dev/mhi_QMI0", "/dev/wwan0qmi0"):
            self.assertEqual(feed._base(dev), ["qmicli", "-d", dev,
                                               "--device-open-proxy",
                                               "--device-open-qmi"], dev)


class TestEmit(unittest.TestCase):
    def test_one_json_object_per_line_newline_terminated(self):
        obs, _, _ = _poll({
            "--nas-get-cell-location-info": (0, CELL_EM9291),
            "--nas-get-signal-info": (0, SIGNAL_EM9291),
        })
        out = io.StringIO()
        feed.emit(obs, out)
        text = out.getvalue()
        # The capture helper's reader splits on '\n' and forwards only complete lines, so
        # the last observation MUST be newline-terminated or it is held back.
        self.assertTrue(text.endswith("\n"))
        lines = text.splitlines()
        self.assertEqual(len(lines), len(obs))
        for line in lines:
            self.assertTrue(line.startswith("{") and line.endswith("}"))
            json.loads(line)

    def test_empty_poll_writes_nothing(self):
        out = io.StringIO()
        feed.emit([], out)
        self.assertEqual(out.getvalue(), "")   # not even a blank line


class TestReadImei(unittest.TestCase):
    def test_imei_parsed(self):
        run = FakeRunner({"--dms-get-ids": (0, IDS_EM9291)})
        self.assertEqual(feed.read_imei(BASE, run), "359876543210987")

    def test_imei_failure_is_none(self):
        run = FakeRunner({"--dms-get-ids": (1, "error")})
        self.assertIsNone(feed.read_imei(BASE, run))


def _ids(imei):
    return (0, f"[/dev/x] Device IDs retrieved:\n\t   IMEI: '{imei}'\n")


class DeviceRunner:
    """--dms-get-ids answers keyed by the -d device in argv."""

    def __init__(self, by_device):
        self.by_device = by_device
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        dev = argv[argv.index("-d") + 1]
        ans = self.by_device.get(dev, (1, "error: couldn't open the QmiDevice"))
        return ans.pop(0) if isinstance(ans, list) else ans


SRC = "351234567890123"     # the cellat source's AT-verified IMEI
OTHER = "359876543210987"


class TestSelectDevice(unittest.TestCase):
    """Pick the cdc-wdm whose DMS IMEI is CELLAT_IMEI."""

    def _sel(self, explicit, expected, by_device, detected, **kw):
        log = io.StringIO()
        run = DeviceRunner(by_device)
        res = feed.select_device(explicit, expected, run,
                                 detect=lambda: list(detected), log=log,
                                 sleep=lambda s: None, **kw)
        return res, run, log.getvalue()

    def test_no_expectation_keeps_the_old_behaviour(self):
        (base, imei), _, _ = self._sel("/dev/cdc-wdm1", None,
                                       {"/dev/cdc-wdm1": _ids(OTHER)}, [])
        self.assertEqual(base[2], "/dev/cdc-wdm1")
        self.assertEqual(imei, OTHER)

    def test_explicit_device_that_matches_is_used(self):
        (base, imei), run, log = self._sel(
            "/dev/cdc-wdm0", SRC, {"/dev/cdc-wdm0": _ids(SRC)},
            ["/dev/cdc-wdm0", "/dev/cdc-wdm1"])
        self.assertEqual((base[2], imei), ("/dev/cdc-wdm0", SRC))
        self.assertEqual(len(run.calls), 1)   # no need to look further
        self.assertEqual(log, "")

    def test_explicit_device_on_another_modem_is_rerouted_loudly(self):
        # -d names another modem's cdc-wdm (numbering
        # is not stable across replugs); the feed moves to the right one.
        (base, imei), _, log = self._sel(
            "/dev/cdc-wdm0", SRC,
            {"/dev/cdc-wdm0": _ids(OTHER), "/dev/cdc-wdm1": _ids(SRC)},
            ["/dev/cdc-wdm0", "/dev/cdc-wdm1"])
        self.assertEqual((base[2], imei), ("/dev/cdc-wdm1", SRC))
        self.assertIn(OTHER, log)
        self.assertIn("/dev/cdc-wdm1", log)

    def test_autodetect_picks_the_matching_device_not_the_first(self):
        (base, imei), _, _ = self._sel(
            None, SRC,
            {"/dev/cdc-wdm0": _ids(OTHER), "/dev/cdc-wdm1": _ids(SRC)},
            ["/dev/cdc-wdm0", "/dev/cdc-wdm1"])
        self.assertEqual((base[2], imei), ("/dev/cdc-wdm1", SRC))

    def test_no_matching_device_refuses_and_names_what_it_saw(self):
        with self.assertRaises(feed.DeviceMismatch) as cm:
            self._sel("/dev/cdc-wdm0", SRC, {"/dev/cdc-wdm0": _ids(OTHER)},
                      ["/dev/cdc-wdm0"])
        self.assertIn(OTHER, str(cm.exception))
        self.assertIn(SRC, str(cm.exception))

    def test_a_silent_dms_is_retried_before_refusing(self):
        # A modem busy at start answers on the second try.
        (base, imei), run, _ = self._sel(
            "/dev/cdc-wdm0", SRC,
            {"/dev/cdc-wdm0": [(1, "busy"), _ids(SRC)]}, ["/dev/cdc-wdm0"])
        self.assertEqual(imei, SRC)
        self.assertEqual(len(run.calls), 2)

    def test_a_dms_that_never_answers_refuses(self):
        with self.assertRaises(feed.DeviceMismatch) as cm:
            self._sel("/dev/cdc-wdm0", SRC, {}, ["/dev/cdc-wdm0"], attempts=2)
        self.assertIn("no answer", str(cm.exception))

    def test_nothing_detected_and_nothing_named_is_none(self):
        res, _, _ = self._sel(None, SRC, {}, [])
        self.assertIsNone(res)


class TestExpectedImei(unittest.TestCase):
    def test_env_value_is_used(self):
        self.assertEqual(feed.expected_imei({"CELLAT_IMEI": SRC}), SRC)

    def test_absent_or_junk_is_none(self):
        self.assertIsNone(feed.expected_imei({}))
        self.assertIsNone(feed.expected_imei({"CELLAT_IMEI": ""}))
        self.assertIsNone(feed.expected_imei({"CELLAT_IMEI": "000000000000000"}))
        self.assertIsNone(feed.expected_imei({"CELLAT_IMEI": "abc"}))


class TestMainRefusals(unittest.TestCase):
    def test_imei_override_contradicting_the_source_is_refused(self):
        # --imei would otherwise stamp an unverified identity over the check.
        err = io.StringIO()
        with unittest.mock.patch.dict(os.environ, {"CELLAT_IMEI": SRC}), \
                unittest.mock.patch("sys.stderr", err):
            rc = feed.main(["-d", "/dev/null", "--imei", OTHER, "--once"])
        self.assertEqual(rc, 3)
        self.assertIn(SRC, err.getvalue())


# qmicli --verbose-full: debug lines interleaved on STDOUT with the result.
# Frames from an EG25-G: the proxy-open request and
# the NAS cell-location request, abbreviated to two frames.
VERBOSE_FULL = """\
[25 Sep 2026, 13:02:26] [Debug] [/dev/cdc-wdm3] opening device with flags 'proxy, auto'...
[25 Sep 2026, 13:02:26] [Debug] [/dev/cdc-wdm3] sent message...
<<<<<< RAW:
<<<<<<   length = 28
<<<<<<   data   = 01:1B:00:00:00:00:00:01:00:FF:10:00:01:0D:00:2F:64:65:76:2F:63:64:63:2D:77:64:6D:33

[25 Sep 2026, 13:02:26] [Debug] [/dev/cdc-wdm3] sent generic request (translated)...
<<<<<< QMUX:
<<<<<<   length  = 27

[25 Sep 2026, 13:02:26] [Debug] [/dev/cdc-wdm3] received message...
<<<<<< RAW:
<<<<<<   length = 19
<<<<<<   data   = 01:12:00:80:00:00:01:01:00:FF:07:00:02:04:00:00:00:00:00

""" + CELL_EM9291


class RawRunner:
    """(argv) -> (rc, stdout, stderr, err), keyed on the qmicli action flag."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        flag = next(a for a in argv if a.startswith("--") and a not in
                    ("--device-open-proxy", "--verbose-full"))
        return self.table[flag]


def _read(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines()]


class TestQmiLog(unittest.TestCase):
    """The raw QMI tee, the QMI sibling of atlog=."""

    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.ticks = iter(range(10**9, 10**12, 10**6))   # 1 ms per clock read

    def _log(self, spec=None, **kw):
        return feed.QmiLog(spec or str(self.tmp) + "/",
                           clock_ns=lambda: next(self.ticks),
                           wall=lambda: 1758805346.412887, **kw)

    def test_dir_spec_names_the_file_by_imei_and_utc(self):
        log = self._log()
        log.open("352222222222222")
        self.assertEqual(log.path.parent, self.tmp)
        self.assertEqual(log.path.name, "qmilog-352222222222222-20250925T130226Z.jsonl")

    def test_template_expands_i_t_and_percent(self):
        log = self._log(str(self.tmp / "sub" / "q-%i-%t-100%%.jsonl"))
        log.open(None)
        self.assertEqual(log.path, self.tmp / "sub" / "q-unknown-20250925T130226Z-100%.jsonl")

    def test_one_record_per_call_with_the_raw_answer(self):
        log = self._log()
        run = log.wrap(RawRunner({"--dms-get-ids": (0, IDS_EM9291, "", None)}))
        log.open("359876543210987")
        rc, out = run(BASE + ["--dms-get-ids"])
        log.close()
        self.assertEqual((rc, out), (0, IDS_EM9291))
        [rec] = _read(log.path)
        self.assertEqual(rec["argv"], BASE + ["--dms-get-ids"])
        self.assertEqual((rec["rc"], rec["stdout"], rec["stderr"], rec["err"]),
                         (0, IDS_EM9291, "", None))
        self.assertEqual(rec["ts_mono_ns"], 10**9)          # taken BEFORE the call
        self.assertEqual(rec["rx_done_ns"], 10**9 + 10**6)  # and after it
        self.assertEqual(rec["duration_ms"], 1.0)
        self.assertEqual(rec["ts_utc"], "2025-09-25T13:02:26.412887Z")

    def test_failed_and_timed_out_calls_are_recorded(self):
        log = self._log()
        run = log.wrap(RawRunner({
            "--nas-get-cell-location-info": (1, "", "error: boom", None),
            "--nas-get-signal-info": (124, "", "", "qmicli timed out after 15s")}))
        log.open("x")
        run(BASE + ["--nas-get-cell-location-info"])
        run(BASE + ["--nas-get-signal-info"])
        log.close()
        a, b = _read(log.path)
        self.assertEqual((a["rc"], a["stderr"]), (1, "error: boom"))
        self.assertEqual((b["rc"], b["err"]), (124, "qmicli timed out after 15s"))

    def test_calls_before_open_are_kept_and_flushed_first(self):
        # Device selection runs DMS before the IMEI (and so the path) is known.
        log = self._log()
        run = log.wrap(RawRunner({"--dms-get-ids": (0, IDS_EM9291, "", None),
                                  "--nas-get-signal-info": (0, SIGNAL_EM9291, "", None)}))
        run(BASE + ["--dms-get-ids"])
        log.open("359876543210987")
        run(BASE + ["--nas-get-signal-info"])
        log.close()
        self.assertEqual([r["argv"][-1] for r in _read(log.path)],
                         ["--dms-get-ids", "--nas-get-signal-info"])

    def test_the_raw_record_survives_a_parse_that_raises(self):
        log = self._log()
        run = log.wrap(RawRunner({"--nas-get-cell-location-info": (0, CELL_EM9291, "", None)}))
        log.open("x")
        with unittest.mock.patch.object(feed, "parse_cell_location_info",
                                        side_effect=ValueError("parser bug")):
            with self.assertRaises(ValueError):
                feed.poll_once(BASE, run, imei="x", with_signal=False, log=io.StringIO())
        log.close()
        [rec] = _read(log.path)
        self.assertEqual(rec["stdout"], CELL_EM9291)

    def test_wire_mode_adds_verbose_full_keeps_frames_and_parses_clean(self):
        log = self._log(wire=True)
        raw = RawRunner({"--nas-get-cell-location-info": (0, VERBOSE_FULL, "", None)})
        run = log.wrap(raw)
        log.open("x")
        obs = feed.poll_once(BASE, run, imei="x", with_signal=False, log=io.StringIO())
        log.close()
        self.assertIn("--verbose-full", raw.calls[0])
        self.assertTrue(any(o["is_serving"] for o in obs), obs)   # debug lines stripped
        [rec] = _read(log.path)
        self.assertEqual(rec["stdout"], VERBOSE_FULL)             # raw keeps everything
        self.assertEqual(rec["qmux"], [
            {"dir": "tx", "len": 28,
             "hex": "011B00000000000100FF1000010D002F6465762F6364632D77646D33"},
            {"dir": "rx", "len": 19, "hex": "011200800000010100FF070002040000000000"},
        ])

    def test_wire_mode_failure_message_names_the_error_not_a_debug_line(self):
        # poll_once reports the FIRST line of a failed call. With --verbose-full
        # that line would be "[Debug] opening device..." -- callers must get
        # qmicli's result, not its debug log. (Parsing alone cannot see this:
        # parse.py reads the same cell either way on real output.)
        failed = ("[25 Sep 2026, 13:02:26] [Debug] [/dev/cdc-wdm3] opening device...\n"
                  "<<<<<< RAW:\n<<<<<<   length = 1\n<<<<<<   data   = 01\n"
                  "error: couldn't get cell location info: QMI protocol error (15): 'NotProvisioned'\n")
        log = self._log(wire=True)
        run = log.wrap(RawRunner({"--nas-get-cell-location-info": (1, failed, "", None)}))
        log.open("x")
        msg = io.StringIO()
        self.assertEqual(feed.poll_once(BASE, run, imei="x", with_signal=False, log=msg), [])
        log.close()
        self.assertIn("NotProvisioned", msg.getvalue())
        self.assertNotIn("[Debug]", msg.getvalue())

    def test_wire_frame_whose_length_disagrees_is_flagged(self):
        frames = feed.parse_wire("[x] [Debug] [d] sent message...\n<<<<<< RAW:\n"
                                 "<<<<<<   length = 5\n<<<<<<   data   = 01:02\n")
        self.assertEqual(frames, [{"dir": "tx", "len": 5, "hex": "0102", "truncated": True}])


class TestQmiLogMain(unittest.TestCase):
    """End to end through main() with a fake qmicli on PATH."""

    def _fake_qmicli(self, tmp):
        bindir = tmp / "bin"
        bindir.mkdir()
        fx = tmp / "fx"
        fx.mkdir()
        (fx / "ids").write_text(IDS_EM9291)
        (fx / "cell").write_text(CELL_EM9291)
        (fx / "sig").write_text(SIGNAL_EM9291)
        q = bindir / "qmicli"
        q.write_text("#!/bin/sh\nfor a; do case $a in\n"
                     f"--dms-get-ids) cat {fx}/ids;;\n"
                     f"--nas-get-cell-location-info) cat {fx}/cell;;\n"
                     f"--nas-get-signal-info) cat {fx}/sig;;\nesac; done\n")
        q.chmod(0o755)
        return bindir

    def test_a_refused_start_still_logs_the_answers_that_refused_it(self):
        # The feed is on the wrong modem and exits 3 -- the DMS
        # answer that proved it is exactly what the raw log is for.
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        bindir = self._fake_qmicli(tmp)
        env = {"PATH": f"{bindir}:{os.environ['PATH']}", "CELLAT_IMEI": SRC}
        with unittest.mock.patch.dict(os.environ, env), \
                unittest.mock.patch.object(feed, "_detected_devices", lambda: []), \
                unittest.mock.patch("sys.stderr", io.StringIO()):
            rc = feed.main(["-d", "/dev/fake", "--once", "--qmilog", f"{tmp}/logs/"])
        self.assertEqual(rc, 3)
        [path] = list((tmp / "logs").glob(f"qmilog-{SRC}-*.jsonl"))
        recs = _read(path)
        self.assertEqual({r["argv"][-1] for r in recs}, {"--dms-get-ids"})
        self.assertIn("359876543210987", recs[0]["stdout"])

    def test_once_writes_dms_cell_and_signal_records(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        bindir = tmp / "bin"
        bindir.mkdir()
        fx = tmp / "fx"
        fx.mkdir()
        (fx / "ids").write_text(IDS_EM9291)
        (fx / "cell").write_text(CELL_EM9291)
        (fx / "sig").write_text(SIGNAL_EM9291)
        q = bindir / "qmicli"
        q.write_text("#!/bin/sh\nfor a; do case $a in\n"
                     f"--dms-get-ids) cat {fx}/ids;;\n"
                     f"--nas-get-cell-location-info) cat {fx}/cell;;\n"
                     f"--nas-get-signal-info) cat {fx}/sig;;\nesac; done\n")
        q.chmod(0o755)
        out = io.StringIO()
        env = {"PATH": f"{bindir}:{os.environ['PATH']}"}
        with unittest.mock.patch.dict(os.environ, env), \
                unittest.mock.patch("sys.stdout", out), \
                unittest.mock.patch("sys.stderr", io.StringIO()):
            os.environ.pop("CELLAT_IMEI", None)     # restored by patch.dict
            rc = feed.main(["-d", "/dev/fake", "--once", "--qmilog", f"{tmp}/logs/"])
        self.assertEqual(rc, 0)
        [path] = list((tmp / "logs").glob("qmilog-359876543210987-*.jsonl"))
        self.assertEqual([r["argv"][-1] for r in _read(path)],
                         ["--dms-get-ids", "--nas-get-cell-location-info",
                          "--nas-get-signal-info"])
        self.assertIn('"src":"qmi"', out.getvalue())


class TestTaggedProtocol(unittest.TestCase):
    """#rawqmi and #msg lines, only when the capture helper asks."""

    def _run(self, argv, *, proto="2", imei=None):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        bindir = TestQmiLogMain._fake_qmicli(self, tmp)
        out, err = io.StringIO(), io.StringIO()
        env = {"PATH": f"{bindir}:{os.environ['PATH']}"}
        with unittest.mock.patch.dict(os.environ, env), \
                unittest.mock.patch.object(feed, "_detected_devices", lambda: []), \
                unittest.mock.patch("sys.stdout", out), \
                unittest.mock.patch("sys.stderr", err):
            for k, v in ((feed.PROTO_ENV, proto), ("CELLAT_IMEI", imei)):
                if v is None:
                    os.environ.pop(k, None)      # restored by patch.dict
                else:
                    os.environ[k] = v
            rc = feed.main([a.replace("{tmp}", str(tmp)) for a in argv])
        return rc, out.getvalue().splitlines(), err.getvalue(), tmp

    @staticmethod
    def _raw(lines):
        return [json.loads(l[len("#rawqmi "):]) for l in lines if l.startswith("#rawqmi ")]

    def test_every_qmicli_call_goes_in_band_without_a_file_tee(self):
        rc, lines, _, tmp = self._run(["-d", "/dev/fake", "--once"])
        self.assertEqual(rc, 0)
        self.assertEqual([r["argv"][-1] for r in self._raw(lines)],
                         ["--dms-get-ids", "--nas-get-cell-location-info",
                          "--nas-get-signal-info"])
        self.assertTrue(any(l.startswith("{") and '"src":"qmi"' in l for l in lines))
        self.assertFalse(list(tmp.glob("**/qmilog-*.jsonl")))

    def test_the_in_band_record_is_the_file_record(self):
        rc, lines, _, tmp = self._run(["-d", "/dev/fake", "--once", "--qmilog", "{tmp}/logs/"])
        self.assertEqual(rc, 0)
        [path] = list((tmp / "logs").glob("qmilog-*.jsonl"))
        self.assertEqual(self._raw(lines), _read(path))

    def test_notes_reach_the_bus_and_stderr(self):
        rc, lines, err, _ = self._run(["-d", "/dev/fake", "--once"])
        self.assertEqual(rc, 0)
        notes = [l for l in lines if l.startswith("#msg ")]
        self.assertIn("#msg info polling /dev/fake every 5s (imei=359876543210987)", notes)
        self.assertIn("kismet_qmi_feed: polling /dev/fake", err)

    def test_a_refused_start_says_why_as_an_error_and_keeps_the_dms_answer(self):
        rc, lines, _, _ = self._run(["-d", "/dev/fake", "--once"], imei=SRC)
        self.assertEqual(rc, 3)
        errors = [l for l in lines if l.startswith("#msg error ")]
        self.assertEqual(len(errors), 1, lines)
        self.assertIn(SRC, errors[0])
        self.assertEqual({r["argv"][-1] for r in self._raw(lines)}, {"--dms-get-ids"})

    def test_without_the_protocol_stdout_stays_observation_only(self):
        for proto in (None, "1", "junk"):
            rc, lines, _, _ = self._run(["-d", "/dev/fake", "--once"], proto=proto)
            self.assertEqual(rc, 0)
            self.assertTrue(lines, proto)
            self.assertFalse([l for l in lines if l.startswith("#")], proto)

    def test_wire_mode_needs_a_file_or_the_protocol(self):
        with unittest.mock.patch("sys.stderr", io.StringIO()), \
                self.assertRaises(SystemExit):
            self._run(["-d", "/dev/fake", "--once", "--qmilog-wire"], proto=None)


class TestTaggedOut(unittest.TestCase):
    def test_an_oversize_record_is_trimmed_to_fit_then_skipped(self):
        out = io.StringIO()
        t = feed.TaggedOut(out)
        t.rawqmi({"argv": ["qmicli"], "stdout": "x" * 70000, "qmux": [{"hex": "01"}]})
        [line] = out.getvalue().splitlines()
        rec = json.loads(line[len("#rawqmi "):])
        self.assertEqual((rec["stdout"], rec["stdout_trimmed"], rec["qmux"]),
                         ("", 70000, [{"hex": "01"}]))
        self.assertLessEqual(len(line[len("#rawqmi "):].encode()), t.raw_max)
        t.rawqmi({"argv": ["qmicli"], "stderr": "y" * 70000})
        self.assertEqual((t.raw, t.raw_trimmed, t.raw_skipped), (1, 1, 1))
        self.assertEqual(len(out.getvalue().splitlines()), 1)

    def test_the_bound_is_the_one_the_capture_exported(self):
        # The capture helper exports the largest payload it forwards. A bound copied
        # here could drift to the helper's 64 KiB read buffer while the server frame is 16.
        self.assertEqual(feed.rawqmi_max({feed.RAWQMI_MAX_ENV: "9000"}), 9000)
        for env in ({}, {feed.RAWQMI_MAX_ENV: "junk"}, {feed.RAWQMI_MAX_ENV: "0"}):
            self.assertEqual(feed.rawqmi_max(env), feed.RAWQMI_MAX_DEFAULT, env)
        # An older capture helper exports nothing, and its server still refuses frames
        # past 16 KiB: the default must fit one with the envelope.
        self.assertLessEqual(feed.RAWQMI_MAX_DEFAULT + 4096, 16384)

    def test_a_live_size_wire_record_is_trimmed_to_the_bound_keeping_its_bytes(self):
        # A real-size record: --nas-get-cell-location-info
        # --verbose-full on an SDX55 runs to ~19.5 KB, 17.7 KB of it stdout
        # and 1.5 KB the QMUX frames. Trimmed, it fits; the frames survive.
        out = io.StringIO()
        t = feed.TaggedOut(out, raw_max=12288)
        qmux = [{"dir": "rx", "len": 700, "hex": "AB" * 700}]
        t.rawqmi({"argv": ["qmicli", "--verbose-full"], "stdout": "v" * 17700,
                  "qmux": qmux})
        [line] = out.getvalue().splitlines()
        payload = line[len("#rawqmi "):]
        self.assertLessEqual(len(payload.encode()), 12288)
        rec = json.loads(payload)
        self.assertEqual((rec["qmux"], rec["stdout_trimmed"]), (qmux, 17700))
        self.assertEqual((t.raw, t.raw_trimmed, t.raw_skipped), (1, 1, 0))
        # A record that already fits is written untouched.
        t.rawqmi({"argv": ["qmicli"], "stdout": "ok"})
        self.assertEqual(json.loads(out.getvalue().splitlines()[1][len("#rawqmi "):]),
                         {"argv": ["qmicli"], "stdout": "ok"})

    def test_a_note_is_one_line_with_the_prefix_dropped(self):
        out, err = io.StringIO(), io.StringIO()
        log = feed.NoteLog(feed.TaggedOut(out), "error", err=err)
        print("kismet_qmi_feed: two\n   lines", file=log)
        self.assertEqual(out.getvalue(), "#msg error two\n#msg error lines\n")
        self.assertEqual(err.getvalue(), "kismet_qmi_feed: two\n   lines\n")


class TestRunQmicli(unittest.TestCase):
    def test_missing_binary_reads_as_failure(self):
        rc, out = feed.run_qmicli(["/nonexistent/qmicli-xyz"])
        self.assertEqual(rc, 127)
        self.assertIn("cannot run", out)

    def test_timeout_reads_as_failure(self):
        rc, out = feed.run_qmicli(["sleep", "5"], timeout=0.2)
        self.assertEqual(rc, 124)
        self.assertIn("timed out", out)


class TestParentWatch(unittest.TestCase):
    def test_same_parent_is_not_gone(self):
        self.assertFalse(feed.parent_gone(4242, getppid=lambda: 4242))

    def test_reparented_is_gone(self):
        # PDEATHSIG from kismet_cap_cell_at reaches only its direct child (sh);
        # this process learns of it by being reparented.
        self.assertTrue(feed.parent_gone(4242, getppid=lambda: 1))

    def test_orphaned_feed_exits_on_its_own(self):
        # End to end: a middle process starts the feed and dies; the feed must
        # exit within about one --interval, not poll forever as an orphan.
        script = Path(feed.__file__).resolve()
        mid = subprocess.Popen(
            ["/bin/sh", "-c",
             f"{sys.executable} {script} -d /nonexistent-cdc-wdm --interval 0.2 "
             f"--imei 0 --no-signal & echo $!; sleep 1"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        pid = int(mid.stdout.readline())
        # The middle shell lives ~1 s so the feed records IT as its parent
        # (in production that parent is the long-lived capture child), then dies.
        mid.wait(timeout=10)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            with open(f"/proc/{pid}/stat") as f:
                if f.read().split(")")[-1].split()[0] == "Z":
                    break
            time.sleep(0.1)
        else:
            os.kill(pid, 9)
            self.fail(f"orphaned feed {pid} kept running")


class TestReaderGone(unittest.TestCase):
    """The capture child going away is a normal stop, at ANY point.

    No ``BrokenPipeError`` traceback (from ``TaggedOut._line`` -> ``flush()``)
    may escape. The poll loop catches it; the writes most at risk are the ones
    made BEFORE the loop -- the
    ``#rawqmi`` rows and ``#msg`` notes of device selection -- which is exactly
    where a failing source in a 5 s reopen loop gets killed.
    """

    def _run_reader_gone(self, extra_env):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        bindir = TestQmiLogMain._fake_qmicli(self, tmp)
        r, w = os.pipe()
        os.close(r)             # the reader is gone before the feed writes a byte
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
                   **{feed.PROTO_ENV: "2"}, **extra_env)
        try:
            proc = subprocess.run(
                [sys.executable, str(Path(feed.__file__).resolve()),
                 "-d", "/dev/fake", "--interval", "0.2"],
                stdout=w, stderr=subprocess.PIPE, text=True, env=env, timeout=30)
        finally:
            os.close(w)
        return proc

    def test_a_reader_gone_during_device_selection_is_a_quiet_stop(self):
        proc = self._run_reader_gone({})
        self.assertNotIn("Traceback", proc.stderr)
        self.assertNotIn("BrokenPipeError", proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_reader_gone_before_a_refused_start_is_quiet_too(self):
        # The wrong-modem refusal writes a #msg error on its way out.
        proc = self._run_reader_gone({"CELLAT_IMEI": SRC})
        self.assertNotIn("Traceback", proc.stderr)
        self.assertNotIn("BrokenPipeError", proc.stderr)


class TestRunByPath(unittest.TestCase):
    def test_help_runs_by_path_outside_the_package(self):
        # The capture helper's qmifeed= runs this file BY PATH from Kismet's cwd, not as -m.
        script = Path(feed.__file__).resolve()
        proc = subprocess.run([sys.executable, str(script), "--help"],
                              capture_output=True, text=True, cwd="/", timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--interval", proc.stdout)

    def test_nonpositive_interval_rejected(self):
        with self.assertRaises(SystemExit) as cm:
            feed.main(["--interval", "0", "-d", "/dev/null"])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
