#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Warn when a built driver predates its own sources.

## Why this exists separately from the test guard

Anything that advances this tree without rebuilding -- a fetch and
fast-forward, a branch switch, a ``stash pop`` -- restamps the mtimes of the
sources ``kismet_cap_cell_diag`` links, so the already-built binary is now
stale, and every celldiag harness under ``tests/`` correctly FAILS on it.

Nothing connects the two events: a clean sync is followed by a red test whose
one-line summary looks like a decode regression rather than a build artifact.
The cost is one ``make``; the cost of not saying so is either debugging the
wrong thing or learning to ignore a red suite, and the second is strictly worse.

So this is meant to be run by whatever advances the tree, reporting the
condition at the moment it is *created*, where the remedy is one line away,
instead of leaving it to surface as an unrelated-looking failure minutes later.

## What it deliberately does not do

**It does not build.** Running ``make`` from a sync step would add a
compiler dependency to a read-only operation, and turn a two-second sweep into a
multi-minute one on a cold tree. It prints the exact command and stops -- the
same line ``cell_binaries`` refuses to cross for ``./configure``.

**It does not fail its caller by default.** Exit status stays 0 for a stale
binary: a sync's nonzero status conventionally means *"this checkout needs
attention before you proceed"* (dirty / divergent / fetch-failed) and a stale
build artifact is not that. ``--check`` opts into a nonzero exit for a caller
that wants a gate.

Both of those are why the predicate lives in ``cell_binaries.staleness()``
rather than here: the test guard and this warning must agree, and the way they
stop agreeing is by each computing "its sources" its own way.

Usage:
    python3 celltools/check_binary_staleness.py           # advisory
    python3 celltools/check_binary_staleness.py --check   # exit 1 if stale
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cell_binaries  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 when any built driver is stale "
                         "(default: advisory, always exit 0)")
    ap.add_argument("--quiet", action="store_true",
                    help="print nothing when everything is current")
    args = ap.parse_args(argv)

    try:
        report = cell_binaries.staleness_report()
    except Exception as exc:                                  # pragma: no cover
        # A probe that crashes must not take the sync down with it. Say so and
        # return the benign status -- an unknown verdict is not a stale one.
        print(f"  cell binaries — staleness probe failed ({exc}); verdict UNKNOWN",
              file=sys.stderr)
        return 0

    if not report.examined:
        # NOT "current". Nothing was built, so nothing was measured, and
        # saying "current" here would be a clean bill of health for a sweep that
        # looked at zero binaries -- the not-measured-vs-measured-zero
        # conflation this whole module exists to eliminate.
        if not args.quiet:
            statuses = ", ".join(sorted({d.status for d in report.skipped}))
            print(f"  cell binaries  — none built on this host, nothing to check "
                  f"[{statuses}]")
        return 0

    # A glob-mode dependency set is a degraded instrument, and the warning
    # belongs on the silent path, not only beside STALE: a glob sees only
    # `srcdir/*.[ch]`, so a linked source in ANOTHER directory
    # (`diag_wwanport.c`, shared with capture_cell_diag by design) is outside its
    # view entirely, and editing it leaves the binary reading CURRENT. Say so
    # whenever it happens, including under --quiet: "nothing to report" and "I could not parse the
    # rule that says what to report on" are different sentences.
    for st in report.examined:
        if st.deps.mode != "glob":
            continue
        print(f"  ⚠️  {st.role} staleness was measured by DIRECTORY GLOB, not by "
              f"the link rule — {st.deps.note}", file=sys.stderr)
        print(f"      A glob cannot see a linked source outside {st.binary.parent.name}/, "
              f"so this verdict may be a false CURRENT.", file=sys.stderr)

    if not report.stale:
        if not args.quiet:
            names = ", ".join(s.role for s in report.examined)
            print(f"  cell binaries  — current ({names})")
        return 0

    # The drivers share libkismetdatasource.a, so rebuilding one stale driver
    # restamps the archive and makes a sibling stale: an operator who follows a per-driver remedy meets STALE-DRIVER a second time, for a
    # different driver, and reads it as the first remedy having failed. Print ONE
    # convergent command that rebuilds every examined driver (see
    # combined_rebuild_cmd) instead of a per-driver line each. When only one
    # driver was examined there is no cascade and the plain per-driver remedy is
    # correct.
    combined = cell_binaries.combined_rebuild_cmd(report)
    for st in report.stale:
        print(f"  ⚠️  {st.role} driver is STALE — {st.binary.name} is older "
              f"than {len(st.newer)} of its sources ({st.summary()})")
        if combined is None:
            print(f"      Rebuild before running the celldiag tests: {st.rebuild_cmd()}")
        print(f"      [dependency set: {st.deps.mode} — {st.deps.note}]")

    if combined is not None:
        print("      These drivers share libkismetdatasource.a — rebuilding one "
              "restamps the archive and makes the others stale.")
        print("      Rebuild EVERY examined driver in one pass so the check converges:")
        print(f"        {combined}")

    return 1 if args.check else 0


if __name__ == "__main__":
    raise SystemExit(main())
