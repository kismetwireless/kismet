# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the derived link-dependency set behind the staleness guard.

The guard answers *"is the binary older than its sources?"*. A directory glob
(``srcdir.glob("*.c")`` + ``"*.h"``) gets that wrong in both directions:

* Over-broad: ``capture_cell_diag/`` also holds ``celldiag_probe.c`` and the
  ``test_diag_*.c`` unit drivers, none of which are in ``MONITOR_OBJS``, so
  editing one would fail every replay test with a stale-binary error about a
  binary that is current.
* Under-broad, the more dangerous direction: ``diag_native_decode.cpp`` sits
  in that directory but is ``.cpp``, and the generated C++ decode legs
  (``DIAGSPEC_SRCS``) live in ``../diagspec/``, outside the globbed directory.
  Both are linked into ``kismet_cap_cell_diag`` via ``NATIVE_OBJS``, so editing
  a decode leg would leave the binary reading "current".

The guard therefore derives the set from the Makefile's link rule.

These tests run against the parser alone (a synthetic tree, no real build, no
compiler), so they pin the logic on every host.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

import cell_binaries


MAKEFILE = """\
include ../Makefile.inc

MONITOR_OBJS = \\
\tcapture_cell_diag.c.o \\
\tdiag_stats.c.o

DIAGSPEC_SRCS = \\
\t../diagspec/generated/cpp/diag_0xb192.cpp \\
\t../kaitaistream.cc

vpath %.cpp ../diagspec/generated/cpp
vpath %.cc ..

NATIVE_OBJS = \\
\tdiag_native_decode.cpp.o \\
\t$(notdir $(patsubst %.cpp,%.cpp.o,$(patsubst %.cc,%.cc.o,$(DIAGSPEC_SRCS))))

MONITOR_BIN = kismet_cap_cell_diag

PROBE_OBJS = \\
\tcelldiag_probe.c.o \\
\tdiag_stats.c.o
PROBE_BIN = celldiag_probe

all: $(MONITOR_BIN)

# A hazard planted deliberately ABOVE the real rule, where such a comment sits
# in capture_cell_at/Makefile. The next two lines name the binary beside a
# timestamp colon. A parser that does not strip comments reads them as the link
# rule, with "prerequisites" `48) as STALE against a` that hold no object and no
# source, and falls back to the glob. Every test in this file runs against it.
# a run reported kismet_cap_cell_diag (14:48) as STALE against a
# libkismetdatasource.a rebuilt at 18:15, and 18 IPC tests failed.

$(MONITOR_BIN):\t$(MONITOR_OBJS) $(NATIVE_OBJS) ../libkismetdatasource.a
\t\t$(CCLD) -o $(MONITOR_BIN) $(MONITOR_OBJS) $(NATIVE_OBJS)

$(PROBE_BIN):\t$(PROBE_OBJS)
\t\t$(CCLD) -o $(PROBE_BIN) $(PROBE_OBJS)

LOGSTREAM_DUMP_BIN = diag_logstream_dump

$(LOGSTREAM_DUMP_BIN):\tdiag_logstream.c diag_logstream.h diag_stats.c
\t\t$(CC) -o $(LOGSTREAM_DUMP_BIN) diag_logstream.c diag_stats.c
"""


# The PARENT Makefile, which is where ../libkismetdatasource.a is actually built.
# capture_cell_diag/Makefile.in names the archive as a prerequisite and
# ships no rule for it, so this is the only place its contents are described.
PARENT_MAKEFILE = """\
DATASOURCE_COMMON_A = libkismetdatasource.a

DATASOURCE_COMMON_C_O = \\
\tsimple_ringbuf_c.c.o \\
\tcapture_framework.c.o

$(DATASOURCE_COMMON_A):\tmpack/mpack.c.o $(DATASOURCE_COMMON_C_O)
\t$(AR) rcs $(DATASOURCE_COMMON_A) $(DATASOURCE_COMMON_C_O)
"""


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A miniature of the capture_cell_diag/ + ../diagspec/ layout."""
    src = tmp_path / "capture_cell_diag"
    src.mkdir()
    gen = tmp_path / "diagspec" / "generated" / "cpp"
    gen.mkdir(parents=True)

    (src / "Makefile").write_text(MAKEFILE)

    # ── the archive and the tree that builds it ─────────────────────────────
    (tmp_path / "Makefile").write_text(PARENT_MAKEFILE)
    (tmp_path / "mpack").mkdir()
    (tmp_path / "mpack" / "mpack.c").write_text("void mp(void){}\n")
    (tmp_path / "capture_framework.c").write_text("void cf(void){}\n")
    (tmp_path / "capture_framework.h").write_text("void cf(void);\n")
    (tmp_path / "capture_framework.c.d").write_text(
        "capture_framework.c.o: capture_framework.c capture_framework.h\n")
    (tmp_path / "simple_ringbuf_c.c").write_text("void rb(void){}\n")
    (tmp_path / "libkismetdatasource.a").write_text("!<arch>")
    # In the parent directory, in NEITHER the archive nor the binary. The
    # negative control for following the archive: a whole-directory sweep of ..
    # would be as over-broad as a directory glob.
    (tmp_path / "kismet_server.cc").write_text("int main(void){return 0;}\n")

    # linked C sources, each with the .d the Makefile really generates
    (src / "capture_cell_diag.c").write_text("int main(void){return 0;}\n")
    (src / "diag_stats.c").write_text("void s(void){}\n")
    (src / "diag_stats.h").write_text("void s(void);\n")
    (src / "capture_cell_diag.c.d").write_text(
        "capture_cell_diag.c.o: capture_cell_diag.c ../config.h \\\n diag_stats.h\n")
    (src / "diag_stats.c.d").write_text("diag_stats.c.o: diag_stats.c diag_stats.h\n")
    (tmp_path / "config.h").write_text("#define X 1\n")

    # linked C++ sources -- NO .d is generated for these (the Makefile's rule is
    # $(patsubst %c.o,%c.d,$(MONITOR_OBJS)), which covers only the C objects)
    (src / "diag_native_decode.cpp").write_text("extern \"C\" void n(){}\n")
    (gen / "diag_0xb192.cpp").write_text("void b(){}\n")
    (tmp_path / "kaitaistream.cc").write_text("void k(){}\n")

    # present in the directory, linked into NOTHING the guard is asked about
    (src / "celldiag_probe.c").write_text("int main(void){return 0;}\n")
    (src / "test_diag_stats.c").write_text("int main(void){return 0;}\n")
    (src / "test_diag_rawlog.c").write_text("int main(void){return 0;}\n")

    # a rule that links straight from sources, with no intermediate objects
    (src / "diag_logstream.c").write_text("void l(void){}\n")
    (src / "diag_logstream.h").write_text("void l(void);\n")

    (src / "kismet_cap_cell_diag").write_text("ELF")
    (src / "diag_logstream_dump").write_text("ELF")
    return src


def _names(binary: Path) -> set[str]:
    deps = cell_binaries.link_dependencies(binary)
    return {p.name for p in deps.sources}


# ── the over-broad half ───────────────────────────────────────────────────────
def test_unlinked_sources_in_the_same_directory_are_excluded(tree: Path):
    """celldiag_probe.c and the test_*.c drivers are not in MONITOR_OBJS.

    Editing one of them must not mark kismet_cap_cell_diag stale: relinking
    would change nothing about the binary.
    """
    names = _names(tree / "kismet_cap_cell_diag")
    assert "celldiag_probe.c" not in names
    assert "test_diag_stats.c" not in names
    assert "test_diag_rawlog.c" not in names


# ── the under-broad half ──────────────────────────────────────────────────────
def test_linked_cpp_in_the_same_directory_is_included(tree: Path):
    """diag_native_decode.cpp is IN srcdir but `*.c` never matched it."""
    assert "diag_native_decode.cpp" in _names(tree / "kismet_cap_cell_diag")


def test_linked_cpp_outside_the_directory_is_included(tree: Path):
    """The generated decode legs live in ../diagspec/, outside any srcdir glob.

    Editing diag_0xb192.cpp changes what the helper decodes, so it must make
    the binary stale.
    """
    names = _names(tree / "kismet_cap_cell_diag")
    assert "diag_0xb192.cpp" in names, "a linked decode leg must count as a source"
    assert "kaitaistream.cc" in names, "vpath %.cc .. must resolve"


# ── the .d files carry headers the object list alone cannot ───────────────────
def test_headers_come_from_the_dependency_files(tree: Path):
    names = _names(tree / "kismet_cap_cell_diag")
    assert "diag_stats.h" in names
    assert "config.h" in names, "cross-directory header from the .d must count"


def test_the_c_sources_themselves_are_present(tree: Path):
    names = _names(tree / "kismet_cap_cell_diag")
    assert {"capture_cell_diag.c", "diag_stats.c"} <= names


# ── per-binary precision ──────────────────────────────────────────────────────
def test_a_different_target_gets_its_own_set(tree: Path):
    """The probe's set is PROBE_OBJS -- the inverse membership of the above."""
    names = _names(tree / "celldiag_probe")
    assert "celldiag_probe.c" in names
    assert "capture_cell_diag.c" not in names
    assert "diag_0xb192.cpp" not in names


def test_every_reported_source_exists(tree: Path):
    deps = cell_binaries.link_dependencies(tree / "kismet_cap_cell_diag")
    assert deps.sources, "a parsed Makefile must yield a non-empty set"
    assert all(p.is_file() for p in deps.sources)
    assert deps.mode == "derived"


def test_a_rule_that_links_straight_from_sources_is_derived_too(tree: Path):
    """``diag_logstream_dump`` has no objects — its prerequisites ARE the set.

    Without this, the logstream driver would fall back to the glob and be
    over-broad in the same way.
    """
    deps = cell_binaries.link_dependencies(tree / "diag_logstream_dump")
    assert deps.mode == "derived"
    names = {p.name for p in deps.sources}
    assert {"diag_logstream.c", "diag_logstream.h", "diag_stats.c"} <= names
    assert "celldiag_probe.c" not in names
    assert "capture_cell_diag.c" not in names


# ── degradation, never silence ────────────────────────────────────────────────
def test_no_makefile_falls_back_to_the_glob_and_says_so(tmp_path: Path):
    """A missing Makefile must WIDEN to the old behaviour, not narrow to nothing.

    An empty dependency set would make the guard silently unable to ever fire --
    trading an over-broad guard for an absent one.
    """
    src = tmp_path / "capture_cell_diag"
    src.mkdir()
    (src / "diag_stats.c").write_text("void s(void){}\n")
    (src / "diag_stats.h").write_text("void s(void);\n")
    (src / "kismet_cap_cell_diag").write_text("ELF")

    deps = cell_binaries.link_dependencies(src / "kismet_cap_cell_diag")
    assert deps.mode == "glob"
    assert {p.name for p in deps.sources} == {"diag_stats.c", "diag_stats.h"}
    assert "Makefile" in deps.note


def test_an_unknown_target_falls_back_to_the_glob(tree: Path):
    deps = cell_binaries.link_dependencies(tree / "some_other_binary")
    assert deps.mode == "glob"


# ── linked archives ───────────────────────────────────────────────────────────
# The link rule's prerequisites include `../libkismetdatasource.a`. If only `.o`
# words and recognised source suffixes are followed, the framework the helper
# links (`capture_framework.c`, where the CONFIGRESP path lives) is invisible to
# the guard.
#
# The subdirectory Makefile names the archive as a prerequisite and ships no
# rule for it, so `make kismet_cap_cell_diag` relinks a stale archive without
# complaint. A framework fix in source then never reaches the binary, while the
# guard calls the binary current. The archive's sources are therefore followed
# through the parent Makefile.

def test_a_linked_archives_sources_are_included(tree: Path):
    """Editing capture_framework.c must make the binary stale."""
    names = _names(tree / "kismet_cap_cell_diag")
    assert "capture_framework.c" in names, (
        "the linked archive's sources are invisible to the staleness guard -- "
        "a framework fix can land in source and never reach the binary")
    assert "simple_ringbuf_c.c" in names
    assert "mpack.c" in names, "an object named with a path prefix must resolve too"


def test_the_archives_headers_come_from_its_depfile(tree: Path):
    """The archive's .d files are read the same way the binary's own are."""
    assert "capture_framework.h" in _names(tree / "kismet_cap_cell_diag")


def test_the_archive_itself_counts_as_a_dependency(tree: Path):
    """A rebuilt archive that was never relinked is the OTHER direction of stale.

    Following the archive to its sources catches "source edited, archive never
    rebuilt". The archive's own mtime catches "archive rebuilt, binary never
    relinked" -- a different event with the same silence, and cheap to cover.
    """
    assert "libkismetdatasource.a" in _names(tree / "kismet_cap_cell_diag")


def test_following_the_archive_does_not_sweep_its_directory(tree: Path):
    """The negative control, and the reason this is derived rather than globbed.

    ``kismet_server.cc`` sits beside the archive and is linked into neither it
    nor the helper. Pulling in the parent directory wholesale would re-create
    the glob's over-broadness, one directory up and with a far bigger tree.
    """
    assert "kismet_server.cc" not in _names(tree / "kismet_cap_cell_diag")


def test_a_target_with_no_archive_gets_none_of_it(tree: Path):
    """PROBE_BIN does not link the archive; its dependency set must not grow one."""
    names = _names(tree / "celldiag_probe")
    assert "capture_framework.c" not in names
    assert "libkismetdatasource.a" not in names


def test_an_unbuildable_archive_degrades_without_losing_the_binarys_own_sources(
        tree: Path):
    """No parent Makefile: report what IS known rather than raising or emptying.

    The binary's own sources are still derivable, and a guard that threw here
    would take out every binary-using test over a tree layout it merely could
    not fully read.
    """
    (tree.parent / "Makefile").unlink()
    deps = cell_binaries.link_dependencies(tree / "kismet_cap_cell_diag")
    names = {p.name for p in deps.sources}
    assert deps.mode == "derived"
    assert "capture_cell_diag.c" in names
    assert "diag_0xb192.cpp" in names
    # The archive file itself is still a real prerequisite with a real mtime.
    assert "libkismetdatasource.a" in names


# ── prose is not a rule ───────────────────────────────────────────────────────
#
# The MAKEFILE fixture above carries a comment that names the binary next to a
# timestamp's colon, placed ABOVE the real rule. Every test in this file
# therefore runs against the hazard. A parser that falls for it answers a
# different question and says so only in a note nobody reads on the passing
# path.
#
# A test that only checks the happy path would pass on a parser without the
# fix. These do not: each asserts on something such a parser gets wrong (the
# returned prerequisite string, the mode, and the membership of a
# cross-directory source).

def test_a_comment_naming_the_binary_beside_a_colon_does_not_shadow_the_rule(
        tree: Path):
    """The real rule must win over a comment that merely mentions the target.

    Asserts on ``_rule_prereqs`` directly, because this is where the wrong
    answer is produced: without comment handling it returns ``'48) as STALE against a'``, the
    tail of an English sentence. Everything downstream is a consequence.
    """
    lines = cell_binaries._logical_lines((tree / "Makefile").read_text())
    variables = cell_binaries._parse_vars(lines)
    prereqs = cell_binaries._rule_prereqs(
        lines, "kismet_cap_cell_diag", variables)

    assert prereqs is not None
    assert "STALE" not in prereqs, (
        f"a comment was parsed as the link rule: {prereqs!r}")
    # the real rule's own words, from $(MONITOR_OBJS) + $(NATIVE_OBJS)
    assert "capture_cell_diag.c.o" in prereqs.split()
    assert "../libkismetdatasource.a" in prereqs.split()


def test_the_hazard_does_not_push_the_binary_into_glob_mode(tree: Path):
    """Mode is the operator-visible symptom, and it is silent when not stale.

    A glob-mode set is a different measurement wearing the same name. It reads
    the directory instead of the build, so it is over-broad and under-broad at
    once, and the mode must be checked even when the verdict is not stale.
    """
    deps = cell_binaries.link_dependencies(tree / "kismet_cap_cell_diag")
    assert deps.mode == "derived", deps.note
    # the two halves of the glob's error, asserted as absence and presence
    assert "test_diag_stats.c" not in {p.name for p in deps.sources}
    assert "diag_0xb192.cpp" in {p.name for p in deps.sources}


def test_prose_that_survives_comment_stripping_is_still_not_a_rule():
    """Defence in depth: comment-stripping alone is one Makefile edit from broken.

    A recipe-adjacent or ``define``-block sentence carries no ``#`` and would
    parse exactly as the comment did. ``_is_target_word`` refuses a head that
    holds the punctuation prose has and target lists do not.
    """
    lines = cell_binaries._logical_lines(
        "the guard reported kismet_cap_cell_diag (14:48) as STALE\n"
        "kismet_cap_cell_diag:\treal_prereq.c.o\n")
    prereqs = cell_binaries._rule_prereqs(lines, "kismet_cap_cell_diag", {})
    assert prereqs is not None
    assert prereqs.split() == ["real_prereq.c.o"]


def test_a_PUNCTUATION_FREE_comment_is_still_not_a_rule():
    """The test that keeps comment-stripping from being dead code.

    The fixture's comment contains ``(14``, which ``_is_target_word`` rejects
    on the parenthesis alone, so without this test the comment-strip could be
    reverted with the suite still green.

    A comment can carry a colon with no prose punctuation whatsoever::

        # see kismet_cap_cell_diag: rebuilt nightly by the cron sweep

    Every token in that head is a legal make target word, so the plausibility
    check passes it and only stripping the comment refuses it.
    """
    lines = cell_binaries._logical_lines(
        "# see kismet_cap_cell_diag: rebuilt nightly by the cron sweep\n"
        "kismet_cap_cell_diag:\treal_prereq.c.o\n")
    prereqs = cell_binaries._rule_prereqs(lines, "kismet_cap_cell_diag", {})
    assert prereqs is not None
    assert prereqs.split() == ["real_prereq.c.o"], (
        f"a punctuation-free comment shadowed the rule: {prereqs!r}")


def test_a_legitimate_rule_written_with_variables_is_not_rejected():
    """The negative control for ``_is_target_word``: it must not reject real rules.

    ``$(MONITOR_BIN):`` is parentheses in the raw text. The check runs AFTER
    expansion for exactly this reason, and a version that ran before it would
    make every rule in this tree unparseable while all the prose tests above
    still passed.
    """
    lines = cell_binaries._logical_lines(
        "MONITOR_BIN = kismet_cap_cell_diag\n"
        "$(MONITOR_BIN):\tonly_prereq.c.o\n")
    variables = cell_binaries._parse_vars(lines)
    prereqs = cell_binaries._rule_prereqs(
        lines, "kismet_cap_cell_diag", variables)
    assert prereqs is not None and prereqs.split() == ["only_prereq.c.o"]


# ── the real capture_cell_at / capture_cell_diag trees ────────────────────────
#
# The tests above run on a synthetic tree so they pin the logic on every host.
# This one runs on the checked-out tree, because the false-negative direction is
# a fact about this layout: diag_wwanport.c is deliberately shared across the
# two capture directories, so it is the one linked source a glob of
# capture_cell_at/ can never see.

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("subdir,binary", [
    ("capture_cell_at", "kismet_cap_cell_at"),
    ("capture_cell_diag", "kismet_cap_cell_diag"),
])
def test_the_real_makefiles_resolve_and_include_the_shared_classifier(
        subdir: str, binary: str):
    srcdir = REPO_ROOT / subdir
    if not (srcdir / "Makefile").is_file():
        pytest.skip(f"{subdir}/Makefile not generated on this host (./configure)")

    # link_dependencies reads the Makefile, not the binary -- so this runs on a
    # host that has never built anything.
    deps = cell_binaries.link_dependencies(srcdir / binary)
    names = {p.name for p in deps.sources}

    assert deps.mode == "derived", deps.note
    assert "diag_wwanport.c" in names, (
        f"the shared port classifier is outside {subdir}/, so a glob cannot "
        f"see it: {deps.note}")
    assert not [n for n in names if n.startswith("test_")], (
        f"unlinked selftest drivers leaked into the dependency set: "
        f"{sorted(n for n in names if n.startswith('test_'))}")


def test_without_a_makefile_the_wide_glob_fallback_survives(tree: Path):
    """An unconfigured directory still globs, and says so.

    An over-broad fallback produces a spurious failure a human understands; a
    narrow-to-empty one produces a guard that can never fire.
    """
    (tree / "Makefile").unlink()
    deps = cell_binaries.link_dependencies(tree / "diag_logstream_dump")
    assert deps.mode == "glob"
    assert deps.makefile is None
    assert "Makefile" in deps.note, (
        f"the glob note must name the makefile that was looked for: {deps.note}")
    assert "capture_cell_diag.c" in {p.name for p in deps.sources}
