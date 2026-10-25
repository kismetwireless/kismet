# SPDX-License-Identifier: Apache-2.0
"""The capture profiles' ``diag.target_codes`` must not drift from the code.

Every ``capture_cell_at/profiles/*.json`` carries a ``diag.target_codes`` list,
and every one of their ``diag.notes`` says the list mirrors ``DIAG_TARGET_CODES``
in ``capture_cell_diag/diag_config.c``, naming that file "the single source of
truth". This module enforces that claim; without it, a code added to the C array
(the GNSS codes ``0x1476`` / ``0x14D8``, for example) leaves every profile stale.

**Why the drift is worse than it looks.** ``target_codes`` is not read at runtime —
the helper subscribes ``DIAG_TARGET_CODES`` and narrows it with
``diag_config_filter_supported`` against the modem's own advertised ranges.
So a stale list changes no behaviour, which is exactly why it can rot unnoticed
while remaining the first thing a human reads to answer "what does this modem
capture?". It is documentation whose whole value is being accurate, with no failure
mode to announce when it is not.

The invariants asserted here are deliberately not "every profile lists every code":

* **subset** — a profile may legitimately list FEWER codes than the C array. The
  EG25-G (MDM9207) and LM960 (SDX20) have no NR radio, so ``0xB821`` / ``0xB97F``
  never fire on them and listing those would be its own inaccuracy.
* **union** — but across the fleet every code in ``DIAG_TARGET_CODES`` must be
  claimed by at least one profile, or a code was added to the C array and no
  profile ever documented which hardware it is for.
* **no invention** — a profile may not list a code that is NOT in the C array. That
  is the drift direction that actively misleads: it reads as capture coverage the
  helper never subscribes to.

Skips only when ``KP_ROOT`` was pointed at something that is not a source
tree. It does not skip on a missing/unparseable source: a guard that skips when
it cannot find the thing it guards silently stops guarding.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

from cell_binaries import tree_root

# The C array literal, e.g.
#     const uint16_t DIAG_TARGET_CODES[] = {
#         0xB193, 0xB0C0, ... };
_ARRAY_RE = re.compile(
    r"DIAG_TARGET_CODES\s*\[\s*\]\s*=\s*\{(?P<body>[^}]*)\}", re.S)
_HEX_RE = re.compile(r"0[xX]([0-9a-fA-F]{1,4})")


def _clone_or_skip() -> Path:
    clone = tree_root()
    if clone is None:
        pytest.skip("KP_ROOT does not point at a source tree")
    return clone


def _c_target_codes(clone: Path) -> set[int]:
    src = clone / "capture_cell_diag" / "diag_config.c"
    assert src.is_file(), f"{src} is missing — cannot check profile drift against it"
    m = _ARRAY_RE.search(src.read_text())
    assert m, f"could not find the DIAG_TARGET_CODES array literal in {src}"
    codes = {int(h, 16) for h in _HEX_RE.findall(m.group("body"))}
    assert codes, f"parsed an EMPTY DIAG_TARGET_CODES from {src}"
    return codes


def _profiles(clone: Path) -> list[tuple[str, dict]]:
    d = clone / "capture_cell_at" / "profiles"
    assert d.is_dir(), f"{d} is missing"
    out = []
    for p in sorted(d.glob("*.json")):
        out.append((p.name, json.loads(p.read_text())))
    assert out, f"no profiles found in {d}"
    return out


def _profile_codes(prof: dict) -> set[int] | None:
    diag = prof.get("diag")
    if not isinstance(diag, dict) or "target_codes" not in diag:
        return None
    return {int(c, 16) for c in diag["target_codes"]}


def test_no_profile_invents_a_code_the_helper_never_subscribes():
    """A profile listing a code absent from the C array reads as capture coverage
    that does not exist. This is the actively-misleading drift direction."""
    clone = _clone_or_skip()
    c_codes = _c_target_codes(clone)
    for name, prof in _profiles(clone):
        codes = _profile_codes(prof)
        if codes is None:
            continue
        extra = codes - c_codes
        assert not extra, (
            f"{name}: diag.target_codes lists {[f'0x{c:04X}' for c in sorted(extra)]}, "
            f"which DIAG_TARGET_CODES does not contain — the helper never subscribes "
            f"to them, so the profile promises coverage that cannot happen")


def test_every_target_code_is_claimed_by_some_profile():
    """Across the fleet, every code in the C array is documented on some modem.

    A code added to DIAG_TARGET_CODES and never mentioned in a profile is live in
    every capture yet named nowhere, while every profile asserts it mirrors the
    array.
    """
    clone = _clone_or_skip()
    c_codes = _c_target_codes(clone)
    claimed: set[int] = set()
    for _name, prof in _profiles(clone):
        codes = _profile_codes(prof)
        if codes is not None:
            claimed |= codes
    unclaimed = c_codes - claimed
    assert not unclaimed, (
        f"DIAG_TARGET_CODES contains {[f'0x{c:04X}' for c in sorted(unclaimed)]} "
        f"that NO profile documents. Add them to the profiles of the modems that "
        f"emit them (and to their diag.notes), or explain the omission there.")


def test_every_declared_target_code_is_named_in_the_diag_notes():
    """Every code in a profile's ``target_codes`` must be named in its ``diag.notes``.

    The array and the prose are two halves of one claim. If only the array is
    machine-checked, the prose drifts on its own: a note can enumerate fewer codes
    *while asserting it mirrors DIAG_TARGET_CODES*, directly beside an array that
    lists more, and the other checks in this module still pass because none of them
    read the notes. (Note that ``scans.serving.notes`` is an **AT** scan
    descriptor, which subscribes no DIAG code; it is not where this belongs.)

    Direction matters: this asserts declared-code ⊆ notes, NOT the converse. Notes
    legitimately mention codes the profile does not declare — the EG25-G and LM960
    both explain that 0xB821 / 0xB97F never fire on a part with no NR radio, and
    that explanation is the reason their lists are short.
    """
    clone = _clone_or_skip()
    for name, prof in _profiles(clone):
        codes = _profile_codes(prof)
        if codes is None:
            continue
        notes = prof["diag"].get("notes", "")
        unnamed = [f"0x{c:04X}" for c in sorted(codes)
                   if f"{c:04x}" not in notes.lower()]
        assert not unnamed, (
            f"{name}: diag.target_codes declares {unnamed}, which diag.notes never "
            f"names — the note claims to mirror DIAG_TARGET_CODES while describing "
            f"a smaller set than the array beside it")


def test_every_profile_with_a_diag_section_declares_target_codes():
    """A `diag` section without `target_codes` silently opts out of both checks
    above — so the opt-out has to be visible rather than incidental."""
    clone = _clone_or_skip()
    missing = [name for name, prof in _profiles(clone)
               if isinstance(prof.get("diag"), dict) and "target_codes" not in prof["diag"]]
    assert not missing, (
        f"profiles with a diag section but no diag.target_codes: {missing} — they "
        f"are invisible to the drift checks in this module")
