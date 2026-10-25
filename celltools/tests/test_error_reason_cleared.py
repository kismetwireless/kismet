# SPDX-License-Identifier: Apache-2.0
"""A healthy re-opened source reports no error reason.

Kismet has two "off" routes. ``disable_source.cmd`` is ``disable_source()``,
which sets ``error = true`` and ``error_reason = "Source disabled"``.
``close_source.cmd`` is ``stop_source()``, which closes without touching either.
Every cell panel toggle uses the second (``close_source -> update_definition ->
open_source``: the Capture switch, the celldiag mask/F3 selectors), so it never
plants the string. A source that WAS disabled must still lose it on a
successful re-open, as well as the ``error`` boolean, or a flowing source
reports "Source disabled" for the rest of the run and the field a person reads
contradicts the field a script reads.

The string is cleared in the v3 open-report handler, which is where a cell
source's open lands. Clearing it only in the passive-capable open and
``connect_remote`` is not enough: neither is reached by a helper opening over
IPC.
"""
from __future__ import annotations

import time

from fake_at_modem import QENG_SERVING, FakeAtModem
from test_cellat_server_fields import F, IMEI, _await, _fresh_server_or_skip
from test_celldiag_server_routes import KismetServer

ERR = "kismet.datasource.error"
REASON = "kismet.datasource.error_reason"


def _reopen_and_settle(ks, base):
    before = ks.source().get(F + "obs_total", 0)
    ks.get(base + "open_source.cmd")
    _await(ks, lambda r: r["kismet.datasource.running"]
           and r.get(F + "obs_total", 0) > before)
    # Flowing, and one poll later, so the answer is not a race with the open
    # report itself.
    time.sleep(1.0)
    return ks.source()


def test_a_disable_then_open_leaves_no_stale_error_reason(tmp_path):
    _fresh_server_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    "debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "obs_total", 0) > 0)
            base = f"datasource/by-uuid/{row['kismet.datasource.uuid']}/"

            ks.get(base + "disable_source.cmd")
            row = _await(ks, lambda r: not r["kismet.datasource.running"])
            # Positive control: the instrument must read the stale value when
            # it is there, or an empty reason below would prove nothing.
            assert row[REASON] == "Source disabled", row[REASON]

            row = _reopen_and_settle(ks, base)
            assert row[ERR] is False or row[ERR] == 0, row[ERR]
            assert row[REASON] == "", (
                f"a re-opened, flowing source still reports {row[REASON]!r}")


def test_a_close_then_open_never_reports_source_disabled(tmp_path):
    """The panel's own route: close_source is stop_source(), not a disable."""
    _fresh_server_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    "debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "obs_total", 0) > 0)
            base = f"datasource/by-uuid/{row['kismet.datasource.uuid']}/"

            ks.get(base + "close_source.cmd")
            row = _await(ks, lambda r: not r["kismet.datasource.running"])
            assert row[REASON] != "Source disabled", row[REASON]

            row = _reopen_and_settle(ks, base)
            assert row[ERR] is False or row[ERR] == 0, row[ERR]
            assert row[REASON] == "", (
                f"a re-opened, flowing source still reports {row[REASON]!r}")
