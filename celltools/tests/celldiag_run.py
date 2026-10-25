# SPDX-License-Identifier: Apache-2.0
"""The shared run harness for ``kismet_cap_cell_diag``.

Every celldiag test drives the COMPILED helper over the kismet_external
protocol (``kismet_capture_ipc.CaptureRun``). What is celldiag-specific about
that lives here, once, so the tests that need it import one module rather
than each other:

* ``_binary_or_skip`` -- the built helper, discovered rather than demanded
  (``cell_binaries.discover``); an absent one skips with the reason, a STALE one
  fails with the rebuild command.
* ``CellDiagRun`` -- one run, with the control lines (``diag_stats``,
  ``diag_census``) kept out of the observation list, and a replay that never
  ended or dropped records failed rather than compared.
* ``replay_must_end`` / ``_definition`` / ``_diag_stats_lines`` -- the small
  pieces the tests above share.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import cell_binaries
from kismet_capture_ipc import (  # noqa: F401 -- re-exported for the tests
    CaptureRun, SUB_GPS_FIELD_FIX, SUB_GPS_FIELD_LAT, SUB_GPS_FIELD_LON,
)

# 15-digit synthetic IMEI, stamped into prov.imei.
IMEI = "000000000000000"


def replay_must_end(definition: str) -> bool:
    """True when ``definition`` replays a file with the source enabled: the one
    run shape that finishes by itself. A live or stub port runs until stopped,
    and ``enabled=false`` never reads its replay, so both end by timeout on
    purpose."""
    _, _, opts = definition.partition(":")
    flags = dict(kv.split("=", 1) for kv in opts.split(",") if "=" in kv)
    return "replay" in flags and flags.get("enabled", "true").lower() != "false"


class CellDiagRun(CaptureRun):
    """One run of ``kismet_cap_cell_diag``.

    The single celldiag-shaped thing in the driver: two streams share the
    observation relay, and conflating them is a bug.
    """

    #: Relayed JSON types that are datasource-field updates the server
    #: INTERCEPTS before phy_cell can devicify them -- not cell observations.
    #: They also carry wall-clock fields (diag_stats' last_obs_epoch), so
    #: leaving one in `observations` makes every equality comparison between
    #: two runs fail for a reason that has nothing to do with decode.
    _CONTROL_TYPES = ("diag_stats", "diag_census")

    def run(self) -> "CellDiagRun":
        super().run()
        if self.timed_out and replay_must_end(self.definition):
            pytest.fail(
                f"REPLAY TIMEOUT: {self.binary} was still running after "
                f"{self.timeout:g} s with {len(self.observations)} observations "
                f"relayed. A replay of a file ends on its own, so this is a "
                f"wedge or a timeout too short for the file, and the "
                f"observation list is a prefix of unknown length. Comparing "
                f"it would report a divergence that is not there.")
        dropped = [e for e in self.errors if "REPLAY DROPPED" in e]
        if dropped:
            pytest.fail(f"the replay dropped records (a replay must be "
                        f"lossless; nothing measured here is trustworthy): "
                        f"{dropped[0]}")
        return self

    def _on_json(self, js: str) -> None:
        # Control lines are recognized by their declared type, not by asking
        # "is this diag_stats?" and treating everything else as an
        # observation. Otherwise any new control line (diag_census, for one)
        # would be counted as a cell observation.
        flat = js.replace(" ", "")
        if any(f'"type":"{t}"' in flat for t in self._CONTROL_TYPES):
            self.control.append(js)
        else:
            # _record_observation, not observations.append: it keeps
            # `observation_gps` in step (kismet_capture_ipc).
            self._record_observation(js)


def _binary_or_skip() -> str:
    """The compiled capture binary, discovered rather than demanded.

    A *stale* binary fails (see ``_fail_if_binary_is_stale``). An *absent* one
    skips, and the skip reason says which silence it is (no tree, never built,
    unconfigured host)."""
    found = cell_binaries.discover("celldiag")
    if not found.ok:
        pytest.skip(found.skip_reason())
    _fail_if_binary_is_stale(Path(found.path))
    return str(found.path)


def _fail_if_binary_is_stale(binary: Path) -> None:
    """FAIL (not skip) when the binary predates its own sources.

    These harnesses exercise the COMPILED ``kismet_cap_cell_diag``, not a
    model of it. A stale binary that disagrees with current source shows up as
    decode failures that accuse the decode path for what is purely a build
    artifact. The inverse is the dangerous direction: a stale binary that
    happens to still agree reports GREEN while testing code nobody shipped.

    **What counts as "its sources".** Not a directory glob, which is wrong in
    both directions: it would flag ``celldiag_probe.c`` and the
    ``test_diag_*.c`` drivers, which are linked into nothing here, and miss the
    C++ decode legs under ``../diagspec/``, which are. The set comes from the
    binary's real link rule + ``.d`` files; see
    ``cell_binaries.link_dependencies``.

    **The message leads with the rebuild command.** pytest's short summary
    shows the first line, so the fix must come first or the summary reads as a
    decode failure with no hint that the cause is a build artifact.
    """
    st = cell_binaries.staleness("celldiag", binary)
    if st.stale:
        pytest.fail(
            f"REBUILD NEEDED: {st.rebuild_cmd()} — "
            f"{binary.name} is older than its sources ({st.summary()}). "
            f"Usually means something restamped the sources without rebuilding. "
            f"This harness only means anything against a current binary — a "
            f"stale one silently tests code nobody shipped. "
            f"[dependency set: {st.deps.mode} — {st.deps.note}] "
            f"Full path: {binary}"
        )


def _definition(replay_file: Path, imei: str = IMEI, **flags) -> str:
    """A ``celldiag-<imei>:replay=<file>[,k=v...]`` source definition."""
    parts = [f"replay={replay_file}"]
    parts += [f"{k}={v}" for k, v in flags.items()]
    return f"celldiag-{imei}:" + ",".join(parts)


def _diag_stats_lines(run: CellDiagRun) -> list[dict]:
    """Every ``diag_stats`` control object the run emitted, parsed.

    FILTERED on type: the control channel also carries ``diag_census`` lines,
    which must not be read as stats.
    """
    out = []
    for js in run.control:
        obj = json.loads(js)
        if isinstance(obj, dict) and obj.get("type") == "diag_stats":
            out.append(obj)
    return out
