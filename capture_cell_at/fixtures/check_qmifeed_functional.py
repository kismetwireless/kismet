# SPDX-License-Identifier: Apache-2.0
"""cellat's own functional self-test: ``qmifeed=auto`` delivers a QMI cell.

Run by ``make -f standalone.mk functional`` in this directory, which can be run
in a sandbox that holds only this source tree. The claim:

    the baseline binary this tree builds, pointed at a modem, finds the QMI
    feed that ships beside it and relays at least one ``src:qmi`` cell

with no venv, no ``PYTHONPATH`` and no file from outside the tree. The modem is
the tree's own fake AT responder on a pty, and ``qmicli`` is a shell stub on
``$PATH`` answering canned EM9291 output. Both ship here, so anyone can re-run
this and get the same answer. The harness supplies no input of its own: if it
did, a pass would prove only that the harness plus the tree works.

Standard library only, and run under the system ``python3``. A venv with extra
decoders on a ``.pth`` would still pass this particular check (the feed imports
nothing outside ``qmifeed/``), but the discipline matches capture_cell_diag's
``functional`` so the two self-tests cannot drift apart on which interpreter
they measure.

Usage: ``python3 fixtures/check_qmifeed_functional.py <kismet_cap_cell_at>``.
Exit 0 on a pass, 1 with the reason on a failure.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CELLAT = HERE.parent
TESTS = CELLAT.parent / "celltools" / "tests"
for _p in (str(TESTS), str(CELLAT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from kismet_capture_ipc import CaptureRun  # noqa: E402
from test_qmifeed_kismet_qmi_feed import (  # noqa: E402
    CELL_EM9291, IDS_EM9291, SIGNAL_EM9291)

#: Luhn-invalid on purpose: a synthetic IMEI in a file that ships publicly.
IMEI = "351234567890123"
#: The IMEI the canned ``--dms-get-ids`` answer carries, rewritten to ``IMEI``
#: so the feed's identity check (it refuses a device whose IMEI differs from
#: the source's) passes.
CANNED_IMEI = "359876543210987"
TIMEOUT_S = 30.0


def _fake_qmicli(root: Path) -> Path:
    bindir = root / "bin"
    fx = root / "fx"
    bindir.mkdir()
    fx.mkdir()
    (fx / "ids").write_text(IDS_EM9291.replace(CANNED_IMEI, IMEI))
    (fx / "cell").write_text(CELL_EM9291)
    (fx / "sig").write_text(SIGNAL_EM9291)
    q = bindir / "qmicli"
    q.write_text("#!/bin/sh\nfor a; do case $a in\n"
                 f"--dms-get-ids) cat {fx}/ids;;\n"
                 f"--nas-get-cell-location-info) cat {fx}/cell;;\n"
                 f"--nas-get-signal-info) cat {fx}/sig;;\nesac; done\n")
    q.chmod(0o755)
    return bindir


def _split(run: CaptureRun) -> "tuple[list[dict], list[dict]]":
    obs = [json.loads(o) for o in run.observations]
    qmi = [d for d in obs if d.get("prov", {}).get("src") == "qmi"]
    at = [d for d in obs if d.get("prov", {}).get("src") != "qmi"]
    return qmi, at


def check(binary: Path) -> "list[str]":
    """Every reason the proof failed; empty on a pass."""
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return [f"{binary} is not an executable -- build `baseline` first"]
    # A stranger's environment: nothing that could reach another tree.
    for k in ("PYTHONPATH", "VIRTUAL_ENV", "PYTHONHOME", "CELLAT_IMEI"):
        os.environ.pop(k, None)
    with tempfile.TemporaryDirectory(prefix="cellat-functional-") as tmp:
        bindir = _fake_qmicli(Path(tmp))
        os.environ["PATH"] = f"{bindir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
        with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
            definition = (f"cellat-{IMEI}:atport={modem.port},debug=false,"
                          f"qmifeed=auto --interval 1")
            run = CaptureRun(
                str(binary), definition, timeout=TIMEOUT_S,
                # Both kinds arrived, or auto was refused: nothing more to wait for.
                stop_when=lambda r: all(_split(r)) or any(
                    "qmifeed=auto:" in m for m in r.messages)).run()
    qmi, at = _split(run)
    errs = []
    if run.open_code != 1:
        errs.append(f"the source did not open: {run.open_message!r}")
    started = [m for m in run.messages if "qmifeed started" in m]
    if not started:
        errs.append("qmifeed=auto did not start the tree's own feed; messages: "
                    + "; ".join(run.messages[-5:]))
    elif str(CELLAT / "qmifeed" / "kismet_qmi_feed.py") not in started[0]:
        errs.append(f"the feed that started is not this tree's: {started[0]!r}")
    if not qmi:
        errs.append(f"no src:qmi observation within {TIMEOUT_S:.0f} s")
    elif not any(c.get("is_serving") and c.get("pci") == 242 for c in qmi):
        errs.append(f"no serving PCI 242 cell among the QMI observations: {qmi!r}")
    elif any(c["prov"].get("imei") != IMEI for c in qmi):
        errs.append("a QMI observation carries the wrong IMEI")
    if not at:
        errs.append("no AT observation: adding the feed stopped the AT survey")
    if not errs:
        print(f"    {len(qmi)} QMI + {len(at)} AT observation(s), "
              f"feed {started[0].split('exec ', 1)[-1]}")
    return errs


def main(argv: "list[str]") -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    errs = check(Path(argv[1]).resolve())
    for e in errs:
        print(f"FAIL: functional (qmifeed) -- {e}", file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
