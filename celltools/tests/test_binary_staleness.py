# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the shared staleness predicate + the sync-time probe.

The celldiag harnesses FAIL when the compiled helper predates its own
sources (``celldiag_run._fail_if_binary_is_stale``). Whatever advances this tree -- a fetch and fast-forward, a branch
switch -- restamps exactly those source mtimes, so without a sync-time probe the
first sign is a red test that reads like a decode regression when the cause is
a stale build artifact.

The probe reports the condition where it is created. These tests pin the two
things that make it worth having:

1. **One predicate, not two.** The sync warning and the test guard both call
   ``cell_binaries.staleness()``. If the warning re-derived "its sources"
   its own way it would eventually disagree with the guard -- and the disagreement
   that matters is *sync says current, pytest says stale*, the very confusion
   the probe exists to prevent.
2. **It stays advisory.** A sync that builds, or that fails on a stale artifact,
   would be a worse trade than the problem: a sync's nonzero exit conventionally
   means *"this checkout needs attention"* (dirty / divergent / fetch-failed),
   and a stale binary is not that.

Synthetic tree, no real build, no compiler -- so they run on every host, following
``test_celldiag_link_deps.py``'s precedent.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

import cell_binaries
import check_binary_staleness

from test_celldiag_link_deps import tree  # noqa: F401  (shared fixture)


def _age(path: Path, seconds: float) -> None:
    """Move `path`'s mtime `seconds` into the past."""
    st = path.stat()
    os.utime(path, (st.st_atime, st.st_mtime - seconds))


def _touch_newer(path: Path, binary: Path, seconds: float = 60.0) -> None:
    """Stamp `path` `seconds` AFTER `binary` — what a git fast-forward does."""
    st = binary.stat()
    os.utime(path, (st.st_mtime + seconds, st.st_mtime + seconds))


# ── the predicate ─────────────────────────────────────────────────────────────
def test_a_binary_newer_than_every_source_is_not_stale(tree: Path):
    binary = tree / "kismet_cap_cell_diag"
    for p in tree.rglob("*"):
        if p.is_file() and p != binary:
            _age(p, 3600)
    assert cell_binaries.staleness("celldiag", binary).stale is False


def test_a_newer_linked_c_source_makes_it_stale_and_is_named(tree: Path):
    binary = tree / "kismet_cap_cell_diag"
    _touch_newer(tree / "diag_stats.c", binary)
    st = cell_binaries.staleness("celldiag", binary)
    assert st.stale
    assert "diag_stats.c" in st.summary()


def test_a_newer_UNLINKED_source_in_the_same_directory_does_NOT_make_it_stale(tree: Path):
    """The over-broad direction: an unlinked source is not a dependency.

    ``celldiag_probe.c`` lives in ``capture_cell_diag/`` but is in ``PROBE_OBJS``,
    not ``MONITOR_OBJS``. A sync-time warning that fired on it would be a false
    alarm on every advance that touched the probe — and a warning an operator
    learns to ignore is worse than no warning, because it also gets ignored on
    the run that mattered.
    """
    binary = tree / "kismet_cap_cell_diag"
    for name in ("celldiag_probe.c", "test_diag_stats.c", "test_diag_rawlog.c"):
        _touch_newer(tree / name, binary)
    assert cell_binaries.staleness("celldiag", binary).stale is False


def test_a_newer_carved_cpp_decode_leg_OUTSIDE_the_directory_makes_it_stale(tree: Path):
    """The under-broad direction, and the one a fast-forward actually hits.

    The 17 ``DIAGSPEC_SRCS`` legs live in ``../diagspec/`` and link in via
    ``NATIVE_OBJS``. A directory glob never saw them. Since a fast-forward
    restamps whatever the merge touched — decode legs very much included — a
    probe blind to these would report "current" on the commonest real case.
    """
    binary = tree / "kismet_cap_cell_diag"
    leg = tree.parent / "diagspec" / "generated" / "cpp" / "diag_0xb192.cpp"
    _touch_newer(leg, binary)
    st = cell_binaries.staleness("celldiag", binary)
    assert st.stale
    assert "diag_0xb192.cpp" in st.summary()


def test_newer_sources_are_reported_newest_first(tree: Path):
    binary = tree / "kismet_cap_cell_diag"
    _touch_newer(tree / "diag_stats.c", binary, 30)
    _touch_newer(tree / "capture_cell_diag.c", binary, 90)
    st = cell_binaries.staleness("celldiag", binary)
    assert [p.name for p in st.newer][0] == "capture_cell_diag.c"


def test_an_absent_binary_reports_NOT_stale_rather_than_inventing_a_verdict(tmp_path: Path):
    """`discover()` already owns "the binary is missing"; this must not guess.

    Reporting a nonexistent file as stale would advise a rebuild for the wrong
    reason.
    """
    missing = tmp_path / "capture_cell_diag" / "kismet_cap_cell_diag"
    assert cell_binaries.staleness("celldiag", missing).stale is False


def test_the_summary_truncates_and_says_how_many_it_dropped(tree: Path):
    binary = tree / "kismet_cap_cell_diag"
    for p in sorted(tree.rglob("*")) + sorted((tree.parent / "diagspec").rglob("*")):
        if p.is_file() and p != binary:
            _touch_newer(p, binary)
    st = cell_binaries.staleness("celldiag", binary)
    assert len(st.newer) > 2
    assert "more" in st.summary(limit=2)


def test_rebuild_cmd_names_the_roles_real_make_target(tree: Path):
    """The remedy must be runnable verbatim, not approximately right.

    ``ROLES`` records each driver's make target. Pinning a string against the
    constant it was copied from tests only that the copy happened; both sides
    move together and can stay wrong together. The real referent is the
    makefile, so ``test_the_logstream_target_has_a_rule_in_the_real_standalone_mk``
    below checks it there.
    """
    binary = tree / "kismet_cap_cell_diag"
    cmd = cell_binaries.staleness("celldiag", binary).rebuild_cmd()
    assert cmd == f"make -C {tree} kismet_cap_cell_diag"

    logstream = tree / "diag_logstream_dump"
    assert cell_binaries.staleness("logstream", logstream).rebuild_cmd() \
        == f"make -C {tree} diag_logstream_dump"


def _rule_exists(mk: Path, target: str) -> bool:
    """Does ``mk`` carry a rule for ``target``?

    Asked through the makefile's LOGICAL lines and its variables, not a raw
    grep for ``"<target>:"`` — ``diag_logstream_dump`` is spelled
    ``$(LOGSTREAM_DUMP_BIN):`` at its rule, so a grep for the literal name would
    report the CORRECT name as missing. Same parser the guard itself uses, for
    the same reason the sync warning and the test guard share one predicate.
    """
    lines = cell_binaries._logical_lines(mk.read_text())
    return cell_binaries._rule_prereqs(
        lines, target, cell_binaries._parse_vars(lines)) is not None


def test_the_logstream_target_has_a_rule_in_the_real_standalone_mk():
    """The logstream make target exists in the file an operator's ``make`` reads.

    The expected name is deliberately NOT this repo's own constant: a
    literal-vs-constant comparison cannot catch a name that was wrong the day it
    was written (such as the nonexistent ``logstream-dump``).
    """
    srcdir = Path(cell_binaries._TREE_ROOT) / "capture_cell_diag"
    mk = srcdir / "standalone.mk"
    if not mk.is_file():
        pytest.skip("no capture_cell_diag/standalone.mk on this host")

    _env, _rel, target = cell_binaries.ROLES["logstream"]
    assert _rule_exists(mk, target), (
        f"role 'logstream' names make target {target!r}, which {mk} has no rule "
        f"for — the printed remedy fails with 'No rule to make target'")
    # The negative control that makes the line above mean something: the name
    # that WAS shipped must be rejected by this same check.
    assert not _rule_exists(mk, "logstream-dump")


def test_no_role_or_escape_still_names_the_target_that_never_existed():
    """No role or escape table names the nonexistent ``logstream-dump`` target.

    This reads the tables rather than grepping the file, so a comment that
    merely mentions the old name does not trip it.
    """
    targets = {t for _e, _r, t in cell_binaries.ROLES.values()}
    targets |= {t for _sub, t, _out in cell_binaries._STANDALONE_ESCAPE.values()}
    assert "logstream-dump" not in targets


def test_the_dash_f_appears_only_where_a_makefile_actually_answered():
    """A role whose makefile cannot answer must not sprout a bogus ``-f``.

    ``standalone.mk`` has NO rule for the autoconf output path
    ``kismet_cap_cell_diag``: its ``native`` target writes
    ``build-native/kismet_cap_cell_diag`` instead, and that binary gets its
    own remedy. Rendering ``-f standalone.mk kismet_cap_cell_diag`` for the
    autoconf path would be an unrunnable remedy.
    """
    root = Path(cell_binaries._TREE_ROOT)
    checked = 0
    for role, (_env, rel, target) in cell_binaries.ROLES.items():
        binary = root / rel
        if not binary.parent.is_dir():
            continue
        cmd = cell_binaries.staleness(role, binary).rebuild_cmd()
        mk = cell_binaries.link_dependencies(binary).makefile
        if mk is None or mk.name == "Makefile":
            assert " -f " not in cmd, (
                f"role {role!r} renders {cmd!r}, naming a makefile that did not "
                f"produce its verdict")
        else:
            assert f" -f {mk.name} " in cmd
            assert _rule_exists(mk, target), (
                f"role {role!r} renders {cmd!r}, which cannot run")
        checked += 1
    assert checked, "no role directory was reachable — this test proved nothing"


# ── stale_roles(): what the sync actually calls ───────────────────────────────
def test_stale_roles_omits_roles_that_are_not_built(monkeypatch, tree: Path):
    """An unbuilt optional driver is not a staleness finding.

    Scolding a host for not having built ``cellat`` at sync time would be noise;
    ``discover()``'s ``not-built`` vocabulary already covers that question, and
    answering it a second way here is how the two answers diverge.
    """
    def fake(role, *, allow_build=None):
        if role == "celldiag":
            return cell_binaries.Discovery(
                role, "discovered", tree / "kismet_cap_cell_diag", "test")
        return cell_binaries.Discovery(role, "not-built", None, "test")

    monkeypatch.setattr(cell_binaries, "discover", fake)
    _touch_newer(tree / "diag_stats.c", tree / "kismet_cap_cell_diag")
    assert [s.role for s in cell_binaries.stale_roles()] == ["celldiag"]


def test_stale_roles_NEVER_opts_into_a_build(monkeypatch):
    """A sync must not invoke a compiler as a side effect.

    ``KP_CELL_BUILD=1`` may legitimately be exported in a shell that then
    runs a sync. ``allow_build`` is passed explicitly False so the env var
    cannot turn a read-only sweep into a multi-minute build.
    """
    seen = []

    def fake(role, *, allow_build=None):
        seen.append(allow_build)
        return cell_binaries.Discovery(role, "no-tree", None, "test")

    monkeypatch.setenv("KP_CELL_BUILD", "1")
    monkeypatch.setattr(cell_binaries, "discover", fake)
    cell_binaries.stale_roles()
    assert seen and all(v is False for v in seen)


# ── the CLI, as a driver invokes it ──────────────────────────────────────────
def _report(stale=(), examined=None, skipped=()):
    if examined is None:
        examined = stale
    return cell_binaries.StalenessReport(
        stale=tuple(stale), examined=tuple(examined), skipped=tuple(skipped))


def test_cli_is_advisory_by_default_and_gates_only_under_check(monkeypatch, capsys, tree: Path):
    binary = tree / "kismet_cap_cell_diag"
    _touch_newer(tree / "diag_stats.c", binary)
    st = cell_binaries.staleness("celldiag", binary)
    monkeypatch.setattr(cell_binaries, "staleness_report",
                        lambda: _report(stale=[st]))

    assert check_binary_staleness.main([]) == 0     # never fails the sync
    out = capsys.readouterr().out
    assert "STALE" in out and str(st.rebuild_cmd()) in out

    assert check_binary_staleness.main(["--check"]) == 1


def test_cli_quiet_says_nothing_when_everything_is_current(monkeypatch, capsys, tree: Path):
    binary = tree / "kismet_cap_cell_diag"
    for p in tree.rglob("*"):
        if p.is_file() and p != binary:
            _age(p, 3600)
    st = cell_binaries.staleness("celldiag", binary)
    monkeypatch.setattr(cell_binaries, "staleness_report",
                        lambda: _report(examined=[st]))
    assert check_binary_staleness.main(["--quiet"]) == 0
    assert capsys.readouterr().out == ""
    assert check_binary_staleness.main([]) == 0
    assert "current" in capsys.readouterr().out


def test_a_glob_mode_dependency_set_is_announced_even_when_NOT_stale(
        monkeypatch, capsys, tree: Path):
    """The degraded instrument must speak on the QUIET path.

    A ``[dependency set: glob — …]`` note printed only inside the STALE loop
    would appear only when the operator is already being told to rebuild,
    where being wrong is cheap. The expensive direction is a glob-mode set that
    reads CURRENT: a glob sees ``srcdir/*.[ch]`` and nothing else, so a linked
    source in another directory (``diag_wwanport.c``, shared by design) is
    invisible and editing it changes no verdict.

    Asserted under ``--quiet`` deliberately. "Everything is current" and "I
    could not parse the rule that decides what current means" are different
    sentences, and only the first one is what ``--quiet`` asks to suppress.
    """
    binary = tree / "kismet_cap_cell_diag"
    (tree / "Makefile").unlink()               # forces the glob fallback
    for p in tree.rglob("*"):
        if p.is_file() and p != binary:
            _age(p, 3600)
    st = cell_binaries.staleness("celldiag", binary)
    assert st.deps.mode == "glob" and not st.stale     # the premise, stated
    monkeypatch.setattr(cell_binaries, "staleness_report",
                        lambda: _report(examined=[st]))

    assert check_binary_staleness.main(["--quiet"]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""                          # still no status noise
    assert "DIRECTORY GLOB" in captured.err
    assert "false CURRENT" in captured.err


def test_a_derived_dependency_set_produces_NO_glob_warning(
        monkeypatch, capsys, tree: Path):
    """Positive control: the warning above must not fire on every run.

    Without this, deleting the ``mode != "glob"`` test would leave the suite
    green while the sync printed a scary warning on every healthy host — and a
    warning that always fires is one an operator learns to skip past.
    """
    binary = tree / "kismet_cap_cell_diag"
    for p in tree.rglob("*"):
        if p.is_file() and p != binary:
            _age(p, 3600)
    st = cell_binaries.staleness("celldiag", binary)
    assert st.deps.mode == "derived"
    monkeypatch.setattr(cell_binaries, "staleness_report",
                        lambda: _report(examined=[st]))

    assert check_binary_staleness.main([]) == 0
    captured = capsys.readouterr()
    assert "DIRECTORY GLOB" not in captured.err
    assert "current" in captured.out


def test_a_host_with_NOTHING_BUILT_is_not_reported_as_current(monkeypatch, capsys):
    """Zero binaries examined must not render as a pass.

    On a host where the tree is present but unconfigured, printing ``built
    drivers are current`` would mean having looked at nothing. A sync-time warning whose silence can mean *either* "checked, fine" or
    "never checked" is worth strictly less than no warning, because the operator
    cannot tell which they were told — and that is the same not-measured /
    measured-zero conflation ``discover()``'s vocabulary was written to end.
    """
    skipped = [cell_binaries.Discovery(r, "not-configurable", None, "test")
               for r in cell_binaries.ROLES]
    monkeypatch.setattr(cell_binaries, "staleness_report",
                        lambda: _report(skipped=skipped))
    assert check_binary_staleness.main([]) == 0
    out = capsys.readouterr().out
    assert "none built" in out
    assert "not-configurable" in out          # says WHICH silence this is
    assert "current" not in out


def test_report_separates_examined_from_skipped(monkeypatch, tree: Path):
    def fake(role, *, allow_build=None):
        if role == "celldiag":
            return cell_binaries.Discovery(
                role, "discovered", tree / "kismet_cap_cell_diag", "test")
        return cell_binaries.Discovery(role, "not-built", None, "test")

    monkeypatch.setattr(cell_binaries, "discover", fake)
    rep = cell_binaries.staleness_report()
    assert [s.role for s in rep.examined] == ["celldiag"]
    assert {d.role for d in rep.skipped} == set(cell_binaries.ROLES) - {"celldiag"}


def test_a_crashing_probe_does_not_take_the_sync_down(monkeypatch, capsys):
    """Verdict UNKNOWN is reported as unknown, never as a clean bill of health.

    The probe says so out loud, but still exits 0 — an unknown verdict is not
    grounds to block a sync.
    """
    def boom():
        raise RuntimeError("makefile ate itself")

    monkeypatch.setattr(cell_binaries, "staleness_report", boom)
    assert check_binary_staleness.main([]) == 0
    assert "UNKNOWN" in capsys.readouterr().err


# ── the guard message itself ─────────────────────────────────────────────────
def test_the_test_guard_failure_LEADS_with_the_rebuild_command(tree: Path):
    """pytest's short summary shows the first line — so the fix must be first.

    A message that opened with ``KP_CELLDIAG_BIN is STALE`` and closed with the
    rebuild command would give a reader skimming the summary line no reason to
    suspect a build artifact at all.

    The second assertion checks the *shape* of the cause -- "something
    restamped the sources without rebuilding" -- rather than naming any one
    sync script, so the harness does not depend on a particular caller.
    """
    import celldiag_run as replay

    binary = tree / "kismet_cap_cell_diag"
    _touch_newer(tree / "diag_stats.c", binary)
    # pytest.fail raises Failed, an OutcomeException — a BaseException subclass,
    # deliberately outside `except Exception` so a test cannot swallow it.
    with pytest.raises(BaseException) as exc:
        replay._fail_if_binary_is_stale(binary)
    msg = str(exc.value)
    assert msg.lstrip().startswith("REBUILD NEEDED: make -C ")
    assert "restamped the sources without rebuilding" in msg, (
        "the message must say what CAUSED the staleness, or the reader has no "
        "reason to suspect a build artifact rather than a decode regression")


# ── ONE convergent remedy for drivers that share libkismetdatasource.a ───────
#
# The cell drivers (celldiag, logstream, cellat) link the SAME
# ``libkismetdatasource.a``. Rebuilding one restamps the archive, whose new
# mtime then makes a sibling stale — so an operator who follows the per-driver
# remedy meets ``STALE-DRIVER`` a SECOND time, for a DIFFERENT driver, and the
# second occurrence reads as though the first remedy failed. The fix is a single
# ``&&``-chained command over EVERY examined driver: the first ``make`` rebuilds
# the shared archive, each subsequent ``make`` finds it current and only relinks.
def _synth(role, dirpath: Path, newer=(), makefile="Makefile"):
    binary = dirpath / cell_binaries.ROLES[role][2]
    deps = cell_binaries.LinkDeps(frozenset(), "derived", "test", Path(makefile))
    return cell_binaries.Staleness(role, binary, tuple(newer), deps)


def test_combined_remedy_chains_EVERY_examined_driver_not_only_the_stale_one(tmp_path):
    """The currently-CURRENT sibling must be in the command too.

    This is the whole point: rebuilding only the stale driver restamps the
    archive and makes the current sibling stale. Chaining every examined driver
    leaves them all current against the freshly-built archive, so one pass
    converges.
    """
    cdd = tmp_path / "capture_cell_diag"
    cat = tmp_path / "capture_cell_at"
    stale = _synth("celldiag", cdd, newer=[cdd / "diag_stats.c"])   # the stale one
    current = _synth("cellat", cat)                                 # NOT stale
    report = _report(stale=[stale], examined=[stale, current])

    cmd = cell_binaries.combined_rebuild_cmd(report)
    assert cmd is not None
    # both drivers named, chained with && so it is a single shell command
    assert " && " in cmd
    assert cmd.count("make -C ") == 2
    assert str(cdd) in cmd and "kismet_cap_cell_diag" in cmd
    assert str(cat) in cmd and "kismet_cap_cell_at" in cmd   # the CURRENT sibling


def test_combined_remedy_is_None_for_a_single_examined_driver(tmp_path):
    """No shared-archive cascade with one driver — rebuild_cmd already converges."""
    cdd = tmp_path / "capture_cell_diag"
    only = _synth("celldiag", cdd, newer=[cdd / "diag_stats.c"])
    report = _report(stale=[only], examined=[only])
    assert cell_binaries.combined_rebuild_cmd(report) is None


def test_cli_prints_the_ONE_convergent_command_when_drivers_share_the_archive(
        monkeypatch, capsys, tmp_path):
    cdd = tmp_path / "capture_cell_diag"
    cat = tmp_path / "capture_cell_at"
    stale = _synth("celldiag", cdd, newer=[cdd / "diag_stats.c"])
    current = _synth("cellat", cat)
    monkeypatch.setattr(cell_binaries, "staleness_report",
                        lambda: _report(stale=[stale], examined=[stale, current]))

    assert check_binary_staleness.main([]) == 0
    out = capsys.readouterr().out
    assert "STALE" in out
    # the single convergent command, naming BOTH dirs on one line
    assert " && " in out
    assert "libkismetdatasource.a" in out          # says WHY one command
    assert "makes the others stale" in out


def test_cli_falls_back_to_the_plain_per_driver_remedy_for_a_lone_driver(
        monkeypatch, capsys, tmp_path):
    cdd = tmp_path / "capture_cell_diag"
    stale = _synth("celldiag", cdd, newer=[cdd / "diag_stats.c"])
    monkeypatch.setattr(cell_binaries, "staleness_report",
                        lambda: _report(stale=[stale], examined=[stale]))

    assert check_binary_staleness.main([]) == 0
    out = capsys.readouterr().out
    assert "STALE" in out
    assert str(stale.rebuild_cmd()) in out
    assert " && " not in out       # no chain for a single driver


def test_combined_remedy_dedups_identical_rebuild_commands(tmp_path):
    """Two roles that resolve to the SAME make command collapse to one.

    The chain exists to rebuild each DISTINCT driver once. If a future role
    shared another's make target, ``make X && make X`` would be noise — and if
    dedup leaves only one distinct command there is no cascade to converge, so
    the result is ``None`` just like the lone-driver case. Pins the ``cmd not in
    cmds`` guard, which no real ROLES pair currently exercises.
    """
    cdd = tmp_path / "capture_cell_diag"
    a = _synth("celldiag", cdd, newer=[cdd / "diag_stats.c"])
    b = _synth("celldiag", cdd)                       # identical role+dir → identical cmd
    assert a.rebuild_cmd() == b.rebuild_cmd()         # the premise, stated
    report = _report(stale=[a], examined=[a, b])
    assert cell_binaries.combined_rebuild_cmd(report) is None
