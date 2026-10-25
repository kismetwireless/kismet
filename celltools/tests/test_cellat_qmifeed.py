"""cellat ``qmifeed=``: a QMI cell feed relayed as CellModem records.

``capture_cell_at/qmifeed/kismet_qmi_feed.py`` (``qmifeed=auto``) polls qmicli and writes one
build_cell_json-shaped observation per stdout line, stamped
``{"prov":{"src":"qmi",...}}``. ``qmifeed=auto`` (here run against a test feed; see fake_qmifeed) makes
``kismet_cap_cell_at`` spawn that command and forward each line to the server
as a ``CellModem`` record -- the record type its own AT observations ride -- so
``phy_cell`` merges QMI, AT and DIAG sightings of one tower via ``prov.src``.

What is pinned here, end to end through the compiled binary and a fake modem
(the spawn / framing / fd-hygiene / group-kill units are C-tested in
``capture_cell_at/test_cellat_qmifeed.c``):

* feed lines arrive verbatim as observations, beside the AT ones, and a
  non-JSON banner line does not;
* ``qmifeed=`` is a known option (no unknown-option "IGNORED" warning);
* a feed that exits is reported, and AT polling carries on;
* the feed does not outlive the capture child: Kismet's CLOSEREQ stop
  kills the feed's whole process group -- including a grandchild of
  ``sh -c`` -- and a capture child killed outright, which runs no teardown,
  still takes a writing feed with it (PDEATHSIG + SIGPIPE; see the layers in
  ``cellat_qmifeed.h``).

The feed is a script file, not an inline command: ``cf_find_flag`` splits the
definition on commas and ends a quoted value at the next ``"``, so a command
that prints JSON cannot be written inline. Operators hit the same rule; the
real feed's command line (``python .../kismet_qmi_feed.py --interval 5``) has
neither character.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from fake_at_modem import QENG_SERVING, FakeAtModem
from fake_qmifeed import feed_tree
from kismet_capture_ipc import CaptureRun
from test_cellat_ipc import _binary_or_skip

IMEI = "351234567890123"

QMI_SERVING = {
    "rat": "LTE", "mcc": "310", "mnc": "026", "cell_id": 11259362, "pci": 242,
    "tac": 6699, "earfcn": 1250, "rsrp": -109, "observation_type": "serving",
    "is_serving": True,
    "prov": {"src": "qmi", "origin": "nas-get-cell-location-info",
             "imei": IMEI, "earfcn_ambiguous": True},
}
QMI_NEIGHBOUR = {
    "rat": "LTE", "pci": 17, "earfcn": 900, "rsrp": -118,
    "observation_type": "observation", "is_serving": False,
    "prov": {"src": "qmi", "origin": "nas-get-cell-location-info", "imei": IMEI},
}


def _script(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "feed.sh"
    p.write_text(body)
    return p


def _qmi(run: CaptureRun) -> "list[dict]":
    out = []
    for js in run.observations:
        d = json.loads(js)
        if d.get("prov", {}).get("src") == "qmi":
            out.append(d)
    return out


def _at(run: CaptureRun) -> "list[dict]":
    return [d for d in map(json.loads, run.observations)
            if d.get("prov", {}).get("src") != "qmi"]


def _run(tmp_path: Path, feed_body: "str | None", stop_when, **kw) -> CaptureRun:
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        definition = f"cellat-{IMEI}:atport={modem.port},debug=false"
        if feed_body is not None:
            binary = str(feed_tree(tmp_path, binary, _script(tmp_path, feed_body)))
            definition += ",qmifeed=auto"
        return CaptureRun(binary, definition, timeout=25.0,
                          stop_when=stop_when, **kw).run()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); it is dead for our purposes.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def test_feed_lines_arrive_verbatim_as_observations(tmp_path):
    body = ("echo 'kismet_qmi_feed: polling /dev/cdc-wdm0'\n"
            f"echo '{json.dumps(QMI_SERVING)}'\n"
            f"echo '{json.dumps(QMI_NEIGHBOUR)}'\n"
            "exec sleep 30\n")
    run = _run(tmp_path, body,
               stop_when=lambda r: len(_qmi(r)) >= 2 and len(_at(r)) >= 1)
    assert run.open_code == 1, run.open_message   # harness: 1 = opened
    assert _qmi(run) == [QMI_SERVING, QMI_NEIGHBOUR]
    # The AT survey is untouched: its own observations still arrive, as "at".
    assert _at(run), "AT observations stopped when the feed was added"
    # The banner is not JSON: never relayed.
    assert not any("polling" in js for js in run.observations)
    assert any("qmifeed started" in m for m in run.messages), run.messages


def test_qmifeed_is_a_known_option(tmp_path):
    run = _run(tmp_path, f"echo '{json.dumps(QMI_SERVING)}'\nexec sleep 30\n",
               stop_when=lambda r: len(_qmi(r)) >= 1)
    assert not any("qmifeed" in m and ("unknown" in m.lower() or "IGNORED" in m)
                   for m in run.messages), run.messages


def test_no_qmifeed_no_qmi_observations(tmp_path):
    run = _run(tmp_path, None, stop_when=lambda r: len(_at(r)) >= 1)
    assert run.open_code == 1, run.open_message
    assert _qmi(run) == []
    assert not any("qmifeed" in m for m in run.messages)


def test_a_feed_that_exits_is_reported_and_at_polling_continues(tmp_path):
    body = f"echo '{json.dumps(QMI_SERVING)}'\nexit 3\n"

    def done(r):
        return (any("qmifeed exited" in m for m in r.messages)
                and len(_at(r)) >= 2)

    run = _run(tmp_path, body, stop_when=done)
    exited = [m for m in run.messages if "qmifeed exited" in m]
    assert exited, run.messages
    # The status itself is often "unknown": the framework's signal thread
    # reaps any child (waitpid(-1)) and can collect the feed first.
    assert "1 line" in exited[0], exited[0]
    assert _qmi(run) == [QMI_SERVING]
    assert len(_at(run)) >= 2


# A feed line reporting the writer's pid ($$, expanded by the feed's shell).
# It carries the source's IMEI because an unstamped line is dropped.
PID_LINE = ('{\\"pid\\":$$,\\"prov\\":{\\"src\\":\\"qmi\\",'
            f'\\"imei\\":\\"{IMEI}\\"}}}}')


def _gone_within(pid: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return not _pid_alive(pid)


def _grandchild_pid(run: CaptureRun) -> int:
    pids = [json.loads(js)["pid"] for js in run.observations if '"pid"' in js]
    assert pids, run.observations
    return pids[0]


def _saw_pid(run: CaptureRun) -> bool:
    return any('"pid"' in js for js in run.observations)


def test_kismet_close_stops_the_whole_feed_group(tmp_path):
    """CLOSEREQ -> teardown -> kill(-pgid). The watched process is a
    GRANDCHILD (sh -c -> sh feed.sh -> exec sleep), which PDEATHSIG alone
    would orphan -- only the group kill reaches it."""
    body = f'echo "{PID_LINE}"\nexec sleep 60\n'
    run = _run(tmp_path, body, stop_when=None, close_when=_saw_pid)
    pid = _grandchild_pid(run)
    try:
        assert run.exit_mono is not None, "helper did not exit on CLOSEREQ"
        assert _gone_within(pid, 5.0), f"qmifeed grandchild {pid} outlived a Kismet close"
    finally:
        if _pid_alive(pid):
            os.kill(pid, 9)


def test_an_abruptly_killed_capture_child_takes_a_writing_feed_with_it(tmp_path):
    """Kill the capture child with no teardown (harness default: pipe closed +
    SIGTERM). A feed that keeps writing -- as the real one does each poll --
    must end once its reader is gone. (The child's signal-mask reset is pinned
    by test_cellat_qmifeed.c, not here: dash's echo ends the script on EPIPE
    even with SIGPIPE blocked, so this test cannot see it.)"""
    body = (f'while :; do echo "{PID_LINE}"; sleep 0.2; done\n')
    run = _run(tmp_path, body, stop_when=_saw_pid)
    pid = _grandchild_pid(run)
    try:
        assert _gone_within(pid, 5.0), f"writing feed {pid} survived its reader"
    finally:
        if _pid_alive(pid):
            os.kill(pid, 9)


# ---- whose cells these are -------------------------------------------------

OTHER_IMEI = "352222222222222"   # a second modem (fake, not Luhn-valid)


def _stamped(obs: dict, imei: "str | None") -> dict:
    d = json.loads(json.dumps(obs))
    if imei is None:
        d["prov"].pop("imei", None)
    else:
        d["prov"]["imei"] = imei
    return d


def test_a_line_stamped_with_another_modems_imei_is_dropped_and_said(tmp_path):
    # The feed emits a mismatched prov.imei: the line is NOT relayed, and a
    # warning IS. The matching line after it still flows.
    wrong = _stamped(QMI_NEIGHBOUR, OTHER_IMEI)
    body = (f"echo '{json.dumps(wrong)}'\n"
            f"echo '{json.dumps(wrong)}'\n"
            f"echo '{json.dumps(QMI_SERVING)}'\n"
            "exec sleep 30\n")
    run = _run(tmp_path, body, stop_when=lambda r: len(_qmi(r)) >= 1)
    assert _qmi(run) == [QMI_SERVING], _qmi(run)
    warn = [m for m in run.messages if "qmifeed" in m and OTHER_IMEI in m]
    assert len(warn) == 1, run.messages          # once, not once per line
    assert IMEI in warn[0] and "DROPPED" in warn[0], warn[0]


def test_a_line_with_no_imei_stamp_is_dropped_and_said(tmp_path):
    body = (f"echo '{json.dumps(_stamped(QMI_NEIGHBOUR, None))}'\n"
            f"echo '{json.dumps(_stamped(QMI_NEIGHBOUR, ''))}'\n"
            f"echo '{json.dumps(QMI_SERVING)}'\n"
            "exec sleep 30\n")
    run = _run(tmp_path, body, stop_when=lambda r: len(_qmi(r)) >= 1)
    assert _qmi(run) == [QMI_SERVING], _qmi(run)
    warn = [m for m in run.messages if "no prov.imei" in m]
    assert len(warn) == 1, run.messages


def test_the_feed_is_told_the_sources_verified_imei(tmp_path):
    # The child environment carries CELLAT_IMEI, so the real feed can
    # pick the matching cdc-wdm instead of trusting its -d.
    body = ('printf \'{"prov":{"src":"qmi","imei":"%s"},"rat":"LTE","pci":1,'
            '"observation_type":"observation","is_serving":false}\\n\' "$CELLAT_IMEI"\n'
            "exec sleep 30\n")
    run = _run(tmp_path, body, stop_when=lambda r: len(_qmi(r)) >= 1)
    got = _qmi(run)
    assert len(got) == 1 and got[0]["prov"]["imei"] == IMEI, got
