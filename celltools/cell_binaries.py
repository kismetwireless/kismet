# SPDX-License-Identifier: Apache-2.0
"""Shared binary discovery and staleness for the cell capture harnesses.

## The gap this closes

The harnesses in ``celltools/tests`` exercise the COMPILED capture binaries
(``kismet_cap_cell_diag``, ``kismet_cap_cell_at``, ``diag_logstream_dump``).
Without discovery they would skip silently unless ``KP_CELLDIAG_BIN`` and
friends were exported by hand. That is the *"the build succeeded, so nothing
complained"* shape one level up: **the test suite passes while the thing under
test never ran.**

## What this module does, and what it deliberately does not

**Does:** find an already-built binary **in the tree this file ships in**, so
the common case ("you built it, then ran the tests") needs no environment at
all.

The root is derived from ``__file__``, not from a sibling-directory
convention, and that is deliberate: a conventional default can resolve to a tree
the operator is not building, which makes a green run mean *"some* tree is
built" rather than *"this one* is". ``KP_ROOT`` overrides -- the same override
``celltools/kismet-host-preflight.sh`` takes, so the two agree on what "this
tree" means.

**Does not:** build inside a test run by default. A ``make`` invoked from pytest
turns a 2-second suite into a multi-minute one and makes a compiler error look
like a test failure. Set ``KP_CELL_BUILD=1`` to opt in.

**Does not:** fail when a binary is absent. The skip is *correct* on a checkout
nobody has built. What matters is that "there is no source tree here" and
"nobody built the binary" are not the same silence: they are different
strings.

**Answers staleness in ONE place.** "Is this binary older than the sources it
links?" is asked by the test-time guards and by ``check_binary_staleness.py``
alike, so the two cannot disagree (see ``staleness``).

## Resolution vocabulary

``discover()`` returns a ``Discovery`` whose ``status`` is one of:

===============  =============================================================
``env``          an explicit ``KP_*_BIN`` won; the operator's choice always wins
``discovered``   found built in this tree
``built``        not present, and ``KP_CELL_BUILD=1`` built it
``no-tree``      ``KP_ROOT`` points somewhere that is not a source tree -- only
                 reachable via an override, since the default is derived from
                 this file's own location. A legitimate, uninteresting skip
``not-built``    the tree is here and the binary was never built -- THE
                 interesting case, and the one most easily left invisible
``not-configured`` the tree was never ``./configure``d, so there
                 is no makefile to build with -- a fact about the HOST, in the
                 same family as ``no-tree`` / ``not-built``
``build-failed`` opted into the build and it failed -- never silent
``env-bad``      ``KP_*_BIN`` is set but is not an executable file
===============  =============================================================

## Why ``not-configured`` is its own status

This is an **autotools** project: a fresh clone carries ``Makefile.in`` but no
generated ``Makefile``. ``make`` in that state fails with *"No rule to make
target"*. Reported as ``build-failed`` -- which in this module's vocabulary
means **"a real breakage -- investigate"** -- it would send the reader hunting
for a compiler error that does not exist, i.e. tell the operator the *wrong
kind* of thing is wrong. An unconfigured clone is a property of the machine,
exactly like ``no-tree``, and its remedy is one command.

**This module deliberately does NOT run ``./configure`` itself**, even under
``KP_CELL_BUILD=1``. Configuring someone's clone writes makefiles across the
whole tree and bakes in host paths -- a categorically heavier side effect than
compiling one target that the operator already opted into. It reports the
remedy and stops.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

#: The tree this file ships in -- ``celltools/`` is top-level, so one level up
#: is the source root. ``KP_ROOT`` overrides, matching
#: ``celltools/kismet-host-preflight.sh``; the tests point it at a synthetic
#: tree that way.
_TREE_ROOT = Path(os.environ.get("KP_ROOT", str(Path(__file__).resolve().parents[1])))

#: role -> (env var, path within the tree, make target). The make targets are
#: recorded HERE rather than only in a harness docstring, so a reader of the
#: harness can find the command that builds each binary.
ROLES = {
    "celldiag": (
        "KP_CELLDIAG_BIN",
        "capture_cell_diag/kismet_cap_cell_diag",
        "kismet_cap_cell_diag",
    ),
    "logstream": (
        "KP_CELLDIAG_LOGSTREAM_BIN",
        "capture_cell_diag/diag_logstream_dump",
        # `diag_logstream_dump`, NOT `logstream-dump`. No target of the latter
        # name exists in `standalone.mk` -- `make logstream-dump` exits "No
        # rule to make target", so a remedy built from it cannot run.
        "diag_logstream_dump",
    ),
    #: The AT-side capture binary. Discovery is the same question as for the
    #: DIAG side ("is the built binary there, and if not, WHICH silence is
    #: this?"), and answering it twice in two places is how the two answers
    #: drift apart.
    "cellat": (
        "KP_CELLAT_BIN",
        "capture_cell_at/kismet_cap_cell_at",
        "kismet_cap_cell_at",
    ),
}


#: role -> the ``standalone.mk`` invocation that builds THIS role's binary
#: without ``./configure``, for the roles that have one. Absent means the role's
#: binary cannot be built standalone at all.
#:
#: WHY THIS IS A TABLE AND NOT A SENTENCE. Interpolating a role's subdirectory
#: into prose written about one particular binary produces advice like "build
#: diag_logstream_dump inside capture_cell_at, overridden by KP_CELLAT_BIN" --
#: three mismatched referents in one sentence. Templating a PATH into a sentence
#: about a DIFFERENT BINARY silently re-attributes the escape hatch to whichever
#: subdir is in play. Role-generic code cannot carry role-specific prose; the
#: fact has to be per-role data.
#:
#: Each entry is ``(subdir, make target, output path within subdir)``. The output
#: path is carried because it is NOT always the autoconf output path: the
#: capture binaries' standalone targets write into a build directory of their
#: own (``build-native/`` for the DIAG helper, ``build-baseline/`` for the AT
#: one) so they can never clobber a configured tree's binary, and discovery has
#: to look where the build actually wrote.
#:
#: ALL THREE roles have a standalone build. The capture binaries do not need
#: libwebsockets: every lws include and member in the capture framework is
#: under ``#ifdef HAVE_LIBWEBSOCKETS`` (an ``ldd`` showing lws only reflects a
#: build CONFIGURED with it). With the no-autoconf config naming the real OS and
#: lws optional, both link on Linux and on Darwin (libSystem alone).
_STANDALONE_ESCAPE = {
    "logstream": ("capture_cell_diag", "diag_logstream_dump", "diag_logstream_dump"),
    "celldiag": ("capture_cell_diag", "native", "build-native/kismet_cap_cell_diag"),
    "cellat": ("capture_cell_at", "baseline", "build-baseline/kismet_cap_cell_at"),
}

#: role -> the binary a role could NOT build without ./configure. Empty (see
#: above); kept, because the two tables must partition ``ROLES`` and a future
#: role has to be recorded in one of them.
_NO_STANDALONE_ESCAPE: dict[str, str] = {}


def _standalone_output(role: str, clone: Path) -> Path | None:
    """Where ``role``'s no-configure build writes its binary, if it has one."""
    esc = _STANDALONE_ESCAPE.get(role)
    return None if esc is None else clone / esc[0] / esc[2]


def _standalone_note(role: str, clone: Path) -> str:
    """The `-f standalone.mk` escape, stated for THIS role or denied for it.

    Every branch names the role's OWN binary. A reader must be able to act on
    this sentence without first checking whether it was written about a
    different driver.
    """
    if role in _STANDALONE_ESCAPE:
        subdir, target, out = _STANDALONE_ESCAPE[role]
        what = ("its binary links no capture framework" if role == "logstream"
                else "the standalone build links on Linux or Darwin, "
                     "libwebsockets optional")
        return (f"THIS role escapes that: {what}, so build it with no "
                f"configure at all via `make -C {clone / subdir} -f "
                f"standalone.mk {target}` -> {subdir}/{out}.")
    binary = _NO_STANDALONE_ESCAPE.get(role)
    if binary is None:
        return ("⚠️ whether this role has a no-configure build is unrecorded -- "
                "add it to _STANDALONE_ESCAPE or _NO_STANDALONE_ESCAPE.")
    esc_subdir, esc_target, _ = _STANDALONE_ESCAPE["logstream"]
    return (
        f"THIS role has NO standalone build and cannot be given one here: "
        f"{binary} links ../libkismetdatasource.a and needs libwebsockets "
        f"through the capture framework. Only the `logstream` role escapes: "
        f"`make -C {clone / esc_subdir} -f standalone.mk {esc_target}`. "
        f"That does NOT cover this role's tests; they need the capture binary. "
        f"What IS runnable here without configure is this directory's "
        f"framework-free selftests: `make -C {clone / _subdir_for(ROLES[role][1])} "
        f"-f standalone.mk check`.")


def _subdir_for(rel: str) -> str:
    """The subdirectory `make` must run in, derived from the role's path.

    Not hardcoded to ``capture_cell_diag``: the ``cellat`` role lives in
    ``capture_cell_at``, and a hardcoded subdir would report `not-configured` /
    build the WRONG target for it -- naming the wrong kind of problem.
    """
    return rel.split("/", 1)[0]


@dataclass(frozen=True)
class Discovery:
    role: str
    status: str
    path: Path | None
    detail: str

    @property
    def ok(self) -> bool:
        return self.path is not None

    def skip_reason(self) -> str:
        """A skip message that names WHICH silence this is."""
        env_var = ROLES[self.role][0]
        return f"[{self.status}] {self.detail} (override with {env_var}=<path>)"


def tree_root() -> Path | None:
    """The source tree these harnesses run against, or None if it is not one.

    The default is derived from this file's own location, so it can only be
    wrong when ``KP_ROOT`` says so -- which is exactly when the caller wants to
    hear about it. Membership is decided by the capture directories the roles
    name rather than by ``.git``: an exported tree has no ``.git`` and
    is still perfectly buildable, and a synthetic tree in ``tmp_path`` is not a
    repository either.
    """
    d = _TREE_ROOT
    return d if any((d / _subdir_for(rel)).is_dir() for _, rel, _ in ROLES.values()) \
        else None


#: pkg-config modules ``./configure`` HARD-FAILS on, with the OS package that
#: provides each. Derived by hand from this tree's ``configure.ac`` -- every
#: ``PKG_CHECK_MODULES`` whose failure branch is an ``AC_MSG_ERROR`` with no
#: ``--disable-*`` escape that the capture binaries would still build under.
#:
#: NONE OF THESE ARE USED BY THE CAPTURE BINARIES UNDER TEST:
#: ``grep -rl 'libwebsockets\|lws_' capture_cell_diag/`` is empty. Building the
#: capture binaries through autoconf is nonetheless gated on dependencies of the
#: Kismet SERVER, because that build path is the top-level ``./configure``.
#:
#: Verify this table by RUNNING ``./configure``, not only by reading
#: ``configure.ac``: ``./configure`` stops at the FIRST unmet dependency, so
#: one run reveals exactly one gap (on Debian/Kali, ``librtlsdr``, then
#: ``libmosquitto``, then ``libsensors``). An under-reported list means the
#: operator follows the remedy, hits a second error, and the diagnosis looks
#: wrong rather than incomplete. If you find another, add it here rather than
#: working around it locally.
_CONFIGURE_PKG_DEPS = {
    "libwebsockets": "libwebsockets-dev (brew: libwebsockets)",
    "libpcap": "libpcap-dev (brew: libpcap)",
    "sqlite3": "libsqlite3-dev (brew: sqlite)",
    "protobuf": "libprotobuf-dev + protobuf-compiler (brew: protobuf)",
    "librtlsdr": "librtlsdr-dev (brew: librtlsdr)",
    "libmosquitto": "libmosquitto-dev (brew: mosquitto)",
}

#: Dependencies ``./configure`` probes as a HEADER, not via pkg-config, and
#: still ``AC_MSG_ERROR``s on. Kept separate because lm-sensors ships **no**
#: ``.pc`` file even when fully installed -- putting it in the pkg-config table
#: would report it missing on every host forever, inventing exactly the wrong
#: cause this diagnosis exists to avoid.
_CONFIGURE_HEADER_DEPS = {
    "sensors/sensors.h": "libsensors-dev "
                         "(or ./configure --disable-lmsensors)",
}

#: Where a header probe looks. configure uses the compiler's own search path;
#: these are the two roots that cover Debian and Homebrew without shelling out
#: to a compiler from inside a test-support module.
_HEADER_ROOTS = ("/usr/include", "/usr/local/include", "/opt/homebrew/include")


def _dep_remedy(name: str) -> str:
    """The install hint for a dep from either table."""
    return _CONFIGURE_PKG_DEPS.get(name) or _CONFIGURE_HEADER_DEPS[name]


def missing_configure_deps(clone: Path) -> list[str]:
    """Dependencies ``./configure`` needs that this host does not have.

    WHY THIS IS ASKED BEFORE ADVISING ``./configure``. Without it,
    ``not-configured`` is classed with the AVOIDABLE omissions and the skip
    prints an imperative remedy -- and on a host missing one of these, that
    remedy HARD-FAILS: a silence whose stated cause is wrong. An operator then
    either installs an unrelated system library or learns to ignore the skip
    reason, which is how a diagnosis dies.

    Returns the missing dependency names, from BOTH probes.

    NOT "empty when pkg-config is absent". The two probes have different
    answerability:

    * **pkg-config deps** -- unanswerable without ``pkg-config``, so on a host
      lacking it we name NONE of them. Guessing "everything is missing" would
      invent a different wrong cause, which is the failure this whole status
      family exists to avoid.
    * **header deps** -- answerable regardless, so a missing header IS still
      reported on such a host. It is a measured fact, not a guess.

    So the return value is empty only when nothing is actually missing; on a
    pkg-config-less host it can be non-empty and every name in it is a header.
    """
    missing = []
    # Header probes stand alone -- they do not need pkg-config, so they are
    # still answerable on a host that lacks it.
    for header, _ in sorted(_CONFIGURE_HEADER_DEPS.items()):
        if not any((Path(root) / header).exists() for root in _HEADER_ROOTS):
            missing.append(header)
    if shutil.which("pkg-config") is None:
        return missing
    for mod in sorted(_CONFIGURE_PKG_DEPS):
        run = subprocess.run(["pkg-config", "--exists", mod],
                             capture_output=True, check=False)
        if run.returncode != 0:
            missing.append(mod)
    return missing


def is_configured(clone: Path, subdir: str = "capture_cell_diag") -> bool:
    """True when `clone` has been ``./configure``d, i.e. `make` can run at all.

    This is autotools: a fresh checkout has ``Makefile.in`` and no ``Makefile``.
    Both the root and the role's own subdir makefile are checked -- the subdir
    one is what the build actually invokes, and the root one is what
    ``./configure`` regenerates it from (``Makefile: Makefile.in
    ../config.status``), so a half-configured tree is not reported as ready.

    ``subdir`` defaults to ``capture_cell_diag`` so the older single-role call
    signature still works; ``discover()`` passes the role's own.
    """
    return (clone / "Makefile").is_file() and \
           (clone / subdir / "Makefile").is_file()


def _build(clone: Path, target: str, subdir: str = "capture_cell_diag",
           makefile: str | None = None) -> tuple[bool, str]:
    run = subprocess.run(
        ["make", "-C", str(clone / subdir)]
        + (["-f", makefile] if makefile else []) + [target],
        capture_output=True, text=True, check=False,
    )
    if run.returncode == 0:
        return True, ""
    # Keep the tail: make's useful line is the last error, not the first.
    return False, (run.stderr or run.stdout)[-800:]


def discover(role: str, *, allow_build: bool | None = None) -> Discovery:
    """Locate the binary for `role`. See the module docstring for the statuses.

    `allow_build` defaults to the ``KP_CELL_BUILD`` env var."""
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}; known: {sorted(ROLES)}")
    env_var, rel, target = ROLES[role]
    subdir = _subdir_for(rel)

    # 1. An explicit env var always wins -- the operator may be pointing at a
    #    binary outside this tree entirely.
    env = os.environ.get(env_var)
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return Discovery(role, "env", p, f"using {env_var}={env}")
        return Discovery(role, "env-bad", None,
                         f"{env_var}={env!r} is not an executable file")

    # 2. This tree. Not being one is a legitimate, uninteresting skip -- and,
    #    since the default root comes from __file__, only reachable when KP_ROOT
    #    was pointed somewhere it should not have been.
    clone = tree_root()
    if clone is None:
        return Discovery(role, "no-tree", None,
                         f"{_TREE_ROOT} is not a source tree (no capture "
                         "directory in it), so its binaries cannot be "
                         "exercised here -- unset or fix KP_ROOT")

    p = clone / rel
    if p.is_file() and os.access(p, os.X_OK):
        return Discovery(role, "discovered", p, f"found built at {p}")

    # 2b. The no-configure build, where it writes somewhere else. The
    #     autoconf path is checked FIRST: on a configured tree that is the
    #     binary Linux users get, and preferring a side build would measure a
    #     configuration the operator did not choose.
    sp = _standalone_output(role, clone)
    if sp is not None and sp != p and sp.is_file() and os.access(sp, os.X_OK):
        return Discovery(role, "discovered", sp,
                         f"found the no-configure build at {sp} "
                         f"(standalone.mk `{_STANDALONE_ESCAPE[role][1]}`)")

    if allow_build is None:
        allow_build = os.environ.get("KP_CELL_BUILD") == "1"

    # 3. Present, unbuilt, and never ./configure'd. Checked BEFORE the build
    #    branch: `make` cannot run without a makefile, so reporting this as
    #    `build-failed` names the wrong kind of problem. It also
    #    precedes `not-built`, whose remedy (`make -C ...`) would fail here
    #    for this same reason -- the remedy must be `./configure` first.
    if not is_configured(clone, subdir):
        # 3a. Opted into a build, and this role has a no-configure one:
        #     build THAT rather than reporting a remedy. Gated on standalone.mk
        #     actually being on disk, so a tree without one (a synthetic test
        #     tree, an older checkout) still gets the configure diagnosis below
        #     instead of a `make` that cannot work.
        if allow_build and sp is not None and \
                (clone / _STANDALONE_ESCAPE[role][0] / "standalone.mk").is_file():
            esc_subdir, esc_target, _ = _STANDALONE_ESCAPE[role]
            ok, err = _build(clone, esc_target, esc_subdir,
                             makefile="standalone.mk")
            if not ok:
                return Discovery(role, "build-failed", None,
                                 f"`make -f standalone.mk {esc_target}` "
                                 f"failed: {err}")
            if sp.is_file() and os.access(sp, os.X_OK):
                return Discovery(role, "built", sp,
                                 f"built {sp} with no ./configure "
                                 f"(standalone.mk `{esc_target}`)")
            return Discovery(role, "build-failed", None,
                             f"`make -f standalone.mk {esc_target}` succeeded "
                             f"but {sp} is still absent")
        # Probe the configure-time deps BEFORE advising ./configure. On a host
        # missing one, that advice hard-fails, and a remedy that cannot work is
        # worse than no remedy: it is a silence whose stated cause is wrong.
        missing = missing_configure_deps(clone)
        if missing:
            pkgs = "; ".join(f"{m} -> {_dep_remedy(m)}" for m in missing)
            return Discovery(
                role, "not-configurable", None,
                f"the tree at {clone} cannot be ./configure'd on this host: "
                f"missing {', '.join(missing)}. Install: {pkgs}. "
                + _standalone_note(role, clone))
        return Discovery(
            role, "not-configured", None,
            f"the tree at {clone} was never ./configure'd (Makefile.in "
            f"present, Makefile absent), so there is nothing for make to "
            f"read -- run `cd {clone} && ./configure && "
            f"make -C {clone} libkismetdatasource.a && "
            f"make -C {clone / subdir} {target}`. "
            "The middle step is NOT optional: capture_cell_diag's link line names "
            "`../libkismetdatasource.a`, which only the TOP-LEVEL makefile "
            "builds, so going straight to the subdir dies with `No rule to "
            "make target '../libkismetdatasource.a'` after compiling every "
            "object file -- a failure that arrives late and names a file "
            "rather than a step. Nothing here will configure your clone "
            "for you")

    # 4. Present but never built -- THE case that is otherwise invisible.
    if not allow_build:
        return Discovery(
            role, "not-built", None,
            f"{rel} was never built in {clone} -- run "
            f"`make -C {clone / subdir} {target}` "
            "(or set KP_CELL_BUILD=1)")

    ok, err = _build(clone, target, subdir)
    if not ok:
        return Discovery(role, "build-failed", None,
                         f"`make {target}` failed: {err}")
    if p.is_file() and os.access(p, os.X_OK):
        return Discovery(role, "built", p, f"built {p}")
    return Discovery(role, "build-failed", None,
                     f"`make {target}` succeeded but {p} is still absent")


# ─────────────────────────────────────────────────────────────────────────────
# Derived link dependencies
# ─────────────────────────────────────────────────────────────────────────────
#
# The staleness guard in ``test_celldiag_replay_ab.py`` asks "is this binary
# older than its sources?". A directory glob answers that wrongly in BOTH
# directions:
#
#   over-broad  -- ``capture_cell_diag/`` also holds ``celldiag_probe.c`` and the
#                  ``test_diag_*.c`` unit drivers, in no ``MONITOR_OBJS``.
#                  Editing one fails every replay test against a binary that
#                  is current.
#   under-broad -- ``diag_native_decode.cpp`` is in that directory but is
#                  ``.cpp``, which ``*.c`` never matches, and the C++ decode
#                  legs (``DIAGSPEC_SRCS``) live in ``../diagspec/`` outside it
#                  entirely. Both link into the binary via ``NATIVE_OBJS``.
#                  Editing a decode leg would leave the binary reading
#                  "current" -- the silence this guard exists to break, inside
#                  the guard itself.
#
# The ``.d`` files are necessary but not
# sufficient: the Makefile's rule is ``$(patsubst %c.o,%c.d,$(MONITOR_OBJS))``,
# so **no ``.d`` is generated for any C++ object**. The set below is therefore a
# union -- the link rule names the objects, ``.d`` files supply each C object's
# transitive headers, and objects without a ``.d`` fall back to resolving their
# source through the Makefile's own ``vpath``.
#
# Everything is derived from the real build inputs, which is the discipline the
# guard is itself enforcing: adding an object to ``MONITOR_OBJS`` or a leg to
# ``DIAGSPEC_SRCS`` is covered with no edit here.

_MAX_EXPANSION_DEPTH = 12

#: Prerequisite suffixes taken as sources when a rule links without objects.
_SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".hpp", ".cxx")


@dataclass(frozen=True)
class LinkDeps:
    """Sources a binary is built from.

    ``mode`` is ``"derived"`` when a makefile answered, ``"glob"`` when none
    could and this fell back to the old directory scan. The mode is carried
    rather than hidden so a caller's failure message can say which question it
    actually asked.

    ``makefile`` is WHICH makefile answered (``None`` in glob mode). It is
    carried for the same reason ``mode`` is, one step further on: the remedy a
    caller prints has to be runnable on the host that got the verdict. On an
    unconfigured host the deps come from ``standalone.mk``, and a ``make -C
    <dir> <target>`` with no ``-f`` reaches a Makefile that is not there.
    Deriving the remedy from the file that produced the verdict is
    what keeps the guard and the build system from disagreeing about the same
    binary.
    """
    sources: frozenset[Path]
    mode: str
    note: str
    makefile: Path | None = None


def _strip_comment(line: str) -> str:
    i = line.find("#")
    return line if i < 0 else line[:i]


def _logical_lines(text: str) -> list[str]:
    """Join make's backslash continuations into single logical lines."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        # A comment cannot be stripped before joining: make treats a trailing
        # backslash inside a comment as continuing the comment. This tree never
        # does that, and stripping after the join keeps `#` inside a recipe
        # (where it is not a comment to us either) from truncating the line.
        if raw.endswith("\\"):
            buf += raw[:-1] + " "
            continue
        out.append(buf + raw)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _parse_vars(lines: list[str]) -> dict[str, str]:
    """Simple-assignment variables (``=``, ``:=``, ``+=``) from a makefile.

    Deliberately not a make implementation -- just enough for this tree's
    ``MONITOR_OBJS`` / ``NATIVE_OBJS`` / ``DIAGSPEC_SRCS`` / ``PROBE_OBJS``.
    Anything unrecognized leaves the caller in ``glob`` mode rather than
    producing a quietly-narrow set.

    **Conditional arms are UNIONED, not last-wins.** A makefile that assigns
    one variable differently in two arms of an ``ifeq`` builds the binary from
    ONE of them, and which one is a configure-time fact this parser cannot see.
    Taking the LAST assignment drops the other arm's sources, so editing one of
    them would leave the binary "current" while nothing rebuilt it. That
    narrow-to-empty direction is the exact silence this derivation exists to
    end; the over-report from unioning costs at worst a spurious staleness
    failure a human reads in one line, the direction this module's fallback
    deliberately prefers.

    Unioning gives the wide answer for every arm without this file needing to
    know how the tree was configured -- a question it cannot answer from a
    makefile alone, and one it should not grow a second source of truth for.
    """
    variables: dict[str, str] = {}
    # Depth of open ifeq/ifneq/ifdef/ifndef blocks; assignments inside any of
    # them accumulate rather than replace.
    cond_depth = 0
    for line in lines:
        if line[:1] in ("\t",):          # recipe body
            continue
        stripped = _strip_comment(line).strip()
        if not stripped or stripped.startswith("."):
            continue
        head_word = stripped.split(None, 1)[0]
        if head_word in ("ifeq", "ifneq", "ifdef", "ifndef"):
            cond_depth += 1
            continue
        if head_word == "endif":
            cond_depth = max(0, cond_depth - 1)
            continue
        if head_word in ("else", "else:"):
            continue
        for op in (":=", "+=", "="):
            head, sep, tail = stripped.partition(op)
            if not sep:
                continue
            name = head.strip()
            if not name or not name.replace("_", "").isalnum():
                break
            # a rule (`target: prereqs`) also contains "=" only after a ":" --
            # partition on ":=" first, so a bare ":" in `head` means a rule.
            if ":" in head:
                break
            value = tail.strip()
            if (op == "+=" or cond_depth) and name in variables:
                variables[name] = f"{variables[name]} {value}"
            else:
                variables[name] = value
            break
    return variables


def _apply_patsubst(pattern: str, repl: str, words: str) -> str:
    out = []
    pre, _, post = pattern.partition("%")
    for w in words.split():
        if "%" in pattern and w.startswith(pre) and w.endswith(post) and \
                len(w) >= len(pre) + len(post):
            stem = w[len(pre):len(w) - len(post)] if post else w[len(pre):]
            out.append(repl.replace("%", stem))
        elif w == pattern:
            out.append(repl)
        else:
            out.append(w)
    return " ".join(out)


def _split_args(body: str) -> list[str]:
    """Split a make function's comma-separated args, respecting ``$(...)``."""
    args, depth, cur = [], 0, ""
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append(cur)
            cur = ""
            continue
        cur += ch
    args.append(cur)
    return args


def _expand(expr: str, variables: dict[str, str], depth: int = 0) -> str:
    """Expand ``$(VAR)``, ``$(notdir …)`` and ``$(patsubst a,b,…)``.

    An unknown function expands to the empty string -- the same thing make does
    for an undefined variable, and the reason the caller treats an empty object
    list as "could not derive" rather than "no dependencies".
    """
    if depth > _MAX_EXPANSION_DEPTH or "$" not in expr:
        return expr

    out, i = "", 0
    while i < len(expr):
        if expr[i] != "$" or i + 1 >= len(expr):
            out += expr[i]
            i += 1
            continue
        opener = expr[i + 1]
        if opener not in "({":
            out += expr[i + 1]
            i += 2
            continue
        closer = ")" if opener == "(" else "}"
        d, j = 1, i + 2
        while j < len(expr) and d:
            if expr[j] == opener:
                d += 1
            elif expr[j] == closer:
                d -= 1
            j += 1
        body = expr[i + 2:j - 1]
        i = j

        if body.startswith("notdir "):
            inner = _expand(body[len("notdir "):], variables, depth + 1)
            out += " ".join(w.rsplit("/", 1)[-1] for w in inner.split())
        elif body.startswith("patsubst "):
            args = _split_args(body[len("patsubst "):])
            if len(args) == 3:
                out += _apply_patsubst(
                    _expand(args[0], variables, depth + 1).strip(),
                    _expand(args[1], variables, depth + 1).strip(),
                    _expand(args[2], variables, depth + 1))
        elif " " in body:                       # some other make function
            pass
        else:
            out += _expand(variables.get(body, ""), variables, depth + 1)
    return out


def _vpaths(lines: list[str], srcdir: Path) -> list[tuple[str, list[Path]]]:
    """``vpath %.cpp dir…`` directives, as (suffix-pattern, search dirs)."""
    found = []
    for line in lines:
        s = _strip_comment(line).strip()
        if not s.startswith("vpath "):
            continue
        parts = s.split()
        if len(parts) >= 3:
            found.append((parts[1], [(srcdir / d).resolve() for d in parts[2:]]))
    return found


def _is_target_word(word: str) -> bool:
    """Could ``word`` be a make target name?

    A target list is a plain sequence of filenames. Prose is not: it carries
    parentheses, quotes and punctuation. Rejecting a head that holds any of
    those is what keeps an English sentence from being read as a rule even if
    it survives comment-stripping -- see ``_rule_prereqs``.

    Applied AFTER expansion, so ``$(MONITOR_BIN)`` is already
    ``kismet_cap_cell_at`` by the time it gets here and a legitimate rule is
    never rejected for the parentheses it was written with.
    """
    return not any(c in word for c in "()\"',")


def _rule_prereqs(lines: list[str], target: str, variables: dict[str, str]) -> str | None:
    """The prerequisite text of the rule building ``target``, or None.

    **Comments are stripped BEFORE the line is considered, because a sentence
    about a rule can otherwise be read as one.** A makefile comment such as::

        # a run reported kismet_cap_cell_at (14:48) as STALE against a

    matches ``<target>`` followed by ``:`` -- the colon in the *timestamp*
    ``14:48`` supplies it -- and parses as a rule whose prerequisites are
    ``48) as STALE against a``. Those contain no ``.o`` and no source suffix, so
    ``link_dependencies`` would report *"expanded to no objects or sources"*
    and fall back to the glob, which is wrong in BOTH directions at once:
    ``test_*.c`` files the binary never links come IN, and ``diag_wwanport.c``,
    which IS linked but lives in ``../capture_cell_diag/`` by design, stays
    OUT. The false-negative half is the one that matters: edit the shared
    classifier, rebuild celldiag only, and cellat links a stale copy with the
    guard green.

    The fix is structural (strip comments, and require a target list to LOOK
    like one via ``_is_target_word``) rather than a reword of one Makefile,
    because any explanatory comment can trip it.

    Ordering matters as much as matching: this returns the FIRST match, so a
    false rule ABOVE the real one hides it. Widening what counts as a rule would
    not help.
    """
    for line in lines:
        if line[:1] == "\t":                    # recipe body
            continue
        line = _strip_comment(line)
        if ":" not in line:
            continue
        head, _, tail = line.partition(":")
        if tail.startswith("="):                # a := assignment, not a rule
            continue
        names = _expand(head, variables).split()
        if not names or not all(_is_target_word(w) for w in names):
            continue
        if target in names:
            return _expand(tail, variables)
    return None


def _read_depfile(dep: Path) -> list[str]:
    """Prerequisites listed in a gcc ``-MD`` output file."""
    try:
        text = dep.read_text()
    except OSError:
        return []
    _, _, rhs = text.replace("\\\n", " ").partition(":")
    return rhs.split()


def _glob_deps(srcdir: Path, note: str) -> LinkDeps:
    found = {p.resolve() for p in list(srcdir.glob("*.c")) + list(srcdir.glob("*.h"))}
    return LinkDeps(frozenset(found), "glob", note)


#: Makefiles to consult, in order, when deriving a binary's link closure.
#:
#: ``standalone.mk`` is NOT a second-class fallback that happens to work.
#: ``Makefile`` exists only after ``./configure``, which many hosts cannot run
#: -- so on those hosts the ONLY prerequisite list on disk is ``standalone.mk``,
#: and consulting ``Makefile`` alone means globbing. The glob's over-breadth
#: then turns any commit to an unrelated ``.c`` in the directory into a STALE
#: report for a binary whose real prerequisites have not moved.
#:
#: The glob fallback itself stays, and stays WIDE (see ``link_dependencies``).
#: The fallback being broad is fine; a directory with a perfectly good
#: prerequisite list falling into it is not. Narrowing the fallback instead
#: would make the guard under-broad.
_MAKEFILE_NAMES = ("Makefile", "standalone.mk")


#: build directory -> the ``standalone.mk`` target that writes into it. The
#: capture binaries' standalone builds land here, away from the autoconf output
#: path: ``build-native/`` for the DIAG helper (``native``; the default goal
#: ``check-native`` builds it too), ``build-baseline/`` for the AT one. A
#: binary in one was built by ``<its parent>/standalone.mk`` -- never by the
#: generated ``Makefile``, whose rule for the same basename is a DIFFERENT build
#: (autoconf config, ``libkismetdatasource.a``).
_STANDALONE_BUILD_DIRS = {"build-native": "native", "build-baseline": "baseline"}


def _standalone_build_of(binary: Path) -> tuple[Path, str] | None:
    """``(srcdir, rule target)`` when ``binary`` is a standalone build output.

    Without this the link closure of a ``build-native/`` binary would be asked
    of ``build-native/`` itself: no makefile there, so the glob fallback --
    which in that directory finds nothing the binary is built from. That is the
    NARROW-to-empty direction this module exists to prevent: edit
    ``capture_cell_diag.c`` and the guard stays green.
    """
    if binary.parent.name not in _STANDALONE_BUILD_DIRS:
        return None
    srcdir = binary.parent.parent
    if not (srcdir / "standalone.mk").is_file():
        return None
    return srcdir, f"{binary.parent.name}/{binary.name}"


def _rebuild_cmd(role: str, binary: Path, makefile: Path | None) -> str:
    """The ``make`` line that rebuilds ``binary``, spelled for ``makefile``.

    Shared by :meth:`Staleness.rebuild_cmd` and :func:`combined_rebuild_cmd`
    so the per-binary remedy and the one-pass chain cannot disagree about how a
    binary is built.
    """
    target = ROLES[role][2]
    standalone = _standalone_build_of(binary)
    if standalone is not None:
        # A build-native/ or build-baseline/ binary is rebuilt by its PARENT's
        # standalone.mk; `make -C build-native` names no makefile.
        return (f"make -C {standalone[0]} -f standalone.mk "
                f"{_STANDALONE_BUILD_DIRS[binary.parent.name]}")
    flag = ("" if makefile is None or makefile.name == "Makefile"
            else f" -f {makefile.name}")
    return f"make -C {binary.parent}{flag} {target}"


def _find_makefile(srcdir: Path) -> Path | None:
    """The first makefile in ``srcdir`` that could state a prerequisite list."""
    for name in _MAKEFILE_NAMES:
        candidate = srcdir / name
        if candidate.is_file():
            return candidate
    return None


def _resolve_into(sources: set[Path], srcdir: Path, direct: list[str],
                  objects: list[str],
                  vpaths: list[tuple[str, list[Path]]]) -> None:
    """Add the sources behind ``direct`` + ``objects`` to ``sources``.

    Extracted from ``link_dependencies`` so a linked archive's objects
    are resolved by the SAME code as the binary's own -- .d files first, vpath
    second. A second, parallel resolver would be a second place for the .d
    handling to drift, and the drift would be silent in the direction that
    matters (fewer sources seen = the guard cannot fire).
    """
    for w in direct:
        p = (srcdir / w).resolve()
        if p.is_file():
            sources.add(p)
    for obj in objects:
        obj_path = (srcdir / obj)
        stem = obj[:-2]                          # foo.c.o -> foo.c

        dep = Path(str(obj_path)[:-2] + ".d")
        listed = _read_depfile(dep)
        if listed:
            for w in listed:
                p = (srcdir / w).resolve()
                if p.is_file():
                    sources.add(p)
            continue

        # No .d -- true for every C++ object here, since the Makefile only
        # generates them for %c.o. Resolve the source through vpath instead.
        candidates = [srcdir / stem]
        for pattern, dirs in vpaths:
            suffix = pattern.lstrip("%")
            if stem.endswith(suffix):
                candidates += [d / stem for d in dirs]
        for cand in candidates:
            if cand.is_file():
                sources.add(cand.resolve())
                break


def link_dependencies(binary: Path) -> LinkDeps:
    """Every source and header ``binary`` is actually built from.

    Falls back to a directory glob whenever no makefile can
    answer. The fallback is deliberately the WIDE behaviour: an over-broad guard
    produces a spurious failure a human immediately understands, while a
    narrow-to-empty one produces a guard that can never fire -- the exact
    silence being fixed.

    "No makefile" means neither ``Makefile`` nor ``standalone.mk`` is present.
    Asking only for ``Makefile`` would make the glob the *default* verdict on
    every unconfigured host -- see ``_MAKEFILE_NAMES``.
    """
    srcdir = binary.parent
    rule_target = binary.name
    makefile = _find_makefile(srcdir)
    standalone = _standalone_build_of(binary)
    if standalone is not None:
        srcdir, rule_target = standalone
        makefile = srcdir / "standalone.mk"
    if makefile is None:
        return _glob_deps(
            srcdir,
            f"no {' or '.join(_MAKEFILE_NAMES)} in {srcdir} -- fell back to "
            f"the directory glob")

    try:
        lines = _logical_lines(makefile.read_text())
    except OSError as exc:                                   # pragma: no cover
        return _glob_deps(srcdir, f"unreadable Makefile ({exc}) -- glob fallback")

    variables = _parse_vars(lines)
    prereqs = _rule_prereqs(lines, rule_target, variables)
    if prereqs is None:
        return _glob_deps(
            srcdir,
            f"no rule builds {binary.name} in {makefile} -- glob fallback")

    words = prereqs.split()
    objects = [w for w in words if w.endswith(".o")]

    # Some rules link straight from sources with no intermediate objects --
    # ``$(LOGSTREAM_DUMP_BIN): diag_logstream.c diag_logstream.h diag_hdlc.c …``
    # is exactly that shape, and it is the binary behind the logstream
    # harness. Those prerequisites ARE the dependency set, stated by the build
    # itself.
    direct = [w for w in words if w.endswith(_SOURCE_SUFFIXES)]

    if not objects and not direct:
        return _glob_deps(
            srcdir,
            f"the rule for {binary.name} expanded to no objects or sources "
            f"-- glob fallback")

    vpaths = _vpaths(lines, srcdir)
    sources: set[Path] = set()
    _resolve_into(sources, srcdir, direct, objects, vpaths)

    # ── linked archives ──────────────────────────────────────────────────────
    # An `.a` prerequisite is neither an object nor a recognised source suffix,
    # so it needs its own handling -- and `../libkismetdatasource.a` is where
    # `capture_framework.c` lives. A guard blind to it reports CURRENT for a
    # binary that links a day-old framework: a framework fix in source, an
    # archive on disk that predates it, and `make kismet_cap_cell_diag` relinks
    # the stale archive and exits 0, so tests fail with the symptom of a bug
    # that is already fixed. The subdirectory Makefile recurses to rebuild the
    # archive, and this reports it.
    #
    # Followed to the archive's OWN prerequisites, never by sweeping its
    # directory. The archive lives at the tree root beside thousands of files
    # linked into other binaries; a directory glob there would be over-broad
    # one level up, and far worse.
    archives = [w for w in words if w.endswith(".a")]
    followed = 0
    for w in archives:
        apath = (srcdir / w).resolve()
        # The archive itself: catches the other direction -- rebuilt but never
        # relinked -- which is a different event with the same silence.
        if apath.is_file():
            sources.add(apath)
        adir = apath.parent
        amake = _find_makefile(adir)
        if amake is None:
            continue
        try:
            alines = _logical_lines(amake.read_text())
        except OSError:                                      # pragma: no cover
            continue
        avars = _parse_vars(alines)
        aprereqs = _rule_prereqs(alines, apath.name, avars)
        if aprereqs is None:
            continue
        awords = aprereqs.split()
        _resolve_into(
            sources, adir,
            [x for x in awords if x.endswith(_SOURCE_SUFFIXES)],
            [x for x in awords if x.endswith(".o")],
            _vpaths(alines, adir))
        followed += 1

    if not sources:
        return _glob_deps(
            srcdir,
            f"resolved no sources for {binary.name}'s objects -- glob fallback")

    # A standalone build's rule cannot name the headers each .c pulls in, and
    # the AT one compiles its sources in ONE cc invocation, so it has no .d
    # files either.
    # The directory's own *.h / *.inc are added WIDE instead: an
    # over-broad header set costs a spurious STALE a human reads in one line,
    # while omitting them -- capture_cell_at.c compiles six .inc files -- lets a
    # decode edit leave the binary reading "current". Out-of-directory headers
    # are named in the rule itself (BASELINE_KISMET_HDRS / BASELINE_SHARED_HDRS).
    if standalone is not None:
        sources |= {h.resolve() for pat in ("*.h", "*.inc")
                    for h in srcdir.glob(pat)}

    via = []
    if objects:
        via.append(f"{len(objects)} objects")
    if direct:
        via.append(f"{len(direct)} source prerequisites")
    if followed:
        via.append(f"{followed} linked archive(s)")
    return LinkDeps(
        frozenset(sources), "derived",
        f"{len(sources)} sources from {' + '.join(via)} in "
        f"{makefile.name}'s rule for {binary.name}",
        makefile=makefile)


# ─────────────────────────────────────────────────────────────────────────────
# Staleness, asked in ONE place
# ─────────────────────────────────────────────────────────────────────────────
#
# The replay harnesses fail when the compiled helper predates its own sources,
# and that guard is correct. The problem is one of ORDERING:
# anything that restamps source mtimes without rebuilding -- a fast-forward, a
# ``git checkout``, a ``stash pop`` -- leaves a built driver older than the code
# it was built from, and nothing between that event and the eventual pytest run
# connects the two. The suite then opens red with a one-line summary naming a
# ``mask=wardrive`` decode test, which reads like a decode regression. That
# invites debugging the wrong thing, or learning to ignore red.
#
# The predicate is answered here rather than in the test so a sync-time warning
# and the test-time failure ask the *same question*. Warning on "the tree moved"
# would have been a different, sloppier question in both directions: the tree can
# advance without touching this binary's link closure (a false alarm the operator
# learns to ignore), and the binary can go stale with the tree untouched -- a
# local edit -- which that phrasing misses entirely.


@dataclass(frozen=True)
class Staleness:
    """Whether a built driver predates the sources it links."""
    role: str
    binary: Path
    newer: tuple[Path, ...]
    deps: LinkDeps

    @property
    def stale(self) -> bool:
        return bool(self.newer)

    def rebuild_cmd(self) -> str:
        """The remedy, spelled for the makefile that produced THIS verdict.

        The ``-f`` is not cosmetic. ``make -C <dir> <target>`` finds no
        makefile at all on an unconfigured host, so without it the printed
        remedy is unrunnable on precisely the hosts the message is addressed to. The
        makefile is taken from ``deps`` rather than from a per-role constant so
        the remedy cannot name a build the verdict did not come from.
        """
        return _rebuild_cmd(self.role, self.binary, self.deps.makefile)

    def summary(self, limit: int = 6) -> str:
        names = [p.name for p in self.newer]
        shown = ", ".join(names[:limit])
        if len(names) > limit:
            shown += f" +{len(names) - limit} more"
        return shown


def staleness(role: str, binary: Path) -> Staleness:
    """Sources of `binary` that are newer than it, newest first."""
    deps = link_dependencies(binary)
    try:
        bin_mtime = binary.stat().st_mtime
    except OSError:
        # Cannot stat the binary -- report NOT stale rather than inventing a
        # verdict. `discover()` already distinguishes an absent binary, and a
        # made-up staleness claim here would be the wrong-cause failure this
        # module keeps closing instances of.
        return Staleness(role, binary, (), deps)
    newer = sorted(
        (p for p in deps.sources if p.exists() and p.stat().st_mtime > bin_mtime),
        key=lambda p: p.stat().st_mtime, reverse=True,
    )
    return Staleness(role, binary, tuple(newer), deps)


@dataclass(frozen=True)
class StalenessReport:
    """What the sweep found, and — separately — what it never looked at.

    ``examined`` is carried rather than implied. A probe that returned only the
    stale list would tell a host with **no built driver at all** that ``built
    drivers are current`` — a clean bill of health for something never
    examined. That is not-measured reported as measured-zero, the same
    conflation ``discover()``'s status vocabulary exists to eliminate.
    """
    stale: tuple[Staleness, ...]
    examined: tuple[Staleness, ...]
    skipped: tuple[Discovery, ...]


def staleness_report() -> StalenessReport:
    """Staleness across every role with an ALREADY-BUILT driver in this tree.

    Roles that are absent, unbuilt, or on a host with no source tree land in
    ``skipped`` rather than being silently dropped: those are ``discover()``'s
    vocabulary, and a sync-time warning that scolded a host for not having built
    an optional driver would be noise — but a sweep that examined nothing must
    not be able to render as a pass.

    ``allow_build=False`` is explicit: this must never compile anything as a side
    effect of a sync, even in a shell that exported ``KP_CELL_BUILD=1``.
    """
    examined: list[Staleness] = []
    skipped: list[Discovery] = []
    for role in ROLES:
        found = discover(role, allow_build=False)
        if not found.ok or found.path is None:
            skipped.append(found)
            continue
        examined.append(staleness(role, found.path))
    return StalenessReport(
        stale=tuple(s for s in examined if s.stale),
        examined=tuple(examined),
        skipped=tuple(skipped),
    )


def stale_roles() -> list[Staleness]:
    """Every role whose already-built driver is stale. See ``staleness_report``."""
    return list(staleness_report().stale)


def combined_rebuild_cmd(report: StalenessReport) -> str | None:
    """ONE command that rebuilds every examined driver, convergent in one pass.

    The cell drivers (``celldiag`` / ``logstream`` / ``cellat``) link the SAME
    ``libkismetdatasource.a``. Rebuilding one restamps that archive, whose new
    mtime then makes a sibling stale — so an operator who follows the per-driver
    ``rebuild_cmd()`` meets a stale binary a SECOND time, for a DIFFERENT
    driver, and the second occurrence reads as though the first remedy failed.
    Chaining
    every examined driver's rebuild with ``&&`` converges in one run: the first
    ``make`` rebuilds the shared archive, each subsequent ``make`` finds it
    current and only relinks.

    Every **examined** driver is chained, not only the **stale** ones —
    including a currently-current sibling. That is the point: rebuilding just the
    stale driver would restamp the archive and make the current sibling stale, so
    the convergent set is "all of them", leaving every driver current against the
    freshly-built archive.

    Returns ``None`` when fewer than two DISTINCT rebuild commands were examined
    — with a single driver (or two roles that share one make target) there is no
    shared-archive cascade and ``rebuild_cmd()`` already converges, so a chain
    would be noise.
    """
    cmds: list[str] = []
    for st in sorted(report.examined, key=lambda s: s.role):
        cmd = st.rebuild_cmd()
        if cmd not in cmds:
            cmds.append(cmd)
    if len(cmds) < 2:
        return None
    return " && ".join(cmds)

