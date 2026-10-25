"""Tests for celltools/kismet-host-preflight.sh.

The script asserts HOST state that lives nowhere in git — the nine
``/usr/local/etc/kismet*.conf`` symlinks, ``kismet_site.conf``'s four
``helper_binary_path`` entries, the data files, and whether the ``kismet`` on PATH is older than the build tree.

Everything is driven through ``KISMET_ETC`` / ``KISMET_SHARE`` / ``KISMET_ROOT`` /
``KISMET_BIN`` into a ``tmp_path`` so the suite never reads or writes the real
``/usr/local`` and never depends on the developer's own environment.

Each test below is a **mutation of one healthy fixture**, and each asserts a
*different* line of output. A decline test is not a gate test: the assertions
name the **reason** the check failed, not the count of failures, so a mutation
that trips the wrong check does not pass silently.
"""

from __future__ import annotations

import os
import shutil
import re
import subprocess
from pathlib import Path

import pytest

import cell_binaries


def _kismet_source_or_skip(relpath: str) -> str:
    """Read a source file from this tree, or skip.

    Source-reading guards are the only way to pin an invariant that lives in a
    code path no test host executes -- see ``test_the_two_httpd_auth_file_
    defaults_agree``, which guards a fallback nothing executes on a configured
    host.
    """
    clone = cell_binaries.tree_root()
    if clone is None:
        pytest.skip("KP_ROOT does not point at a source tree")
    path = clone / relpath
    if not path.is_file():
        pytest.skip(f"{relpath} not present in the tree at {clone}")
    return path.read_text()

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "celltools" / "kismet-host-preflight.sh"

CONF_FILES = [
    "kismet.conf",
    "kismet_httpd.conf",
    "kismet_memory.conf",
    "kismet_alerts.conf",
    "kismet_80211.conf",
    "kismet_logging.conf",
    "kismet_filter.conf",
    "kismet_uav.conf",
    "kismet_wardrive.conf",
]
# (name in conf/, name the SERVER opens under share/) — see the script's
# DATA_FILES comment. The two spellings differ for the bluetooth pair because
# bluetooth_ids.cc's built-in defaults omit .gz; kismet_uav.conf.yaml is absent
# from this list entirely because it is a build input, not a host data file.
DATA_FILES = [
    ("kismet_manuf.txt.gz", "kismet_manuf.txt.gz"),
    ("kismet_adsb_icao.txt.gz", "kismet_adsb_icao.txt.gz"),
    ("kismet_bluetooth_ids.txt.gz", "kismet_bluetooth_ids.txt"),
    ("kismet_bluetooth_manuf.txt.gz", "kismet_bluetooth_manuf.txt"),
]
# Compiled from conf/kismet_uav.conf.yaml at build time and shipped as a config
# symlink in [1/5]; the .yaml itself is never opened at runtime.
BUILD_INPUTS = ["kismet_uav.conf.yaml"]
HELPER_SUBDIRS = [
    "capture_cell_at",
    "capture_cell_diag",
    "capture_sdr_rtl433_v2",
    "capture_linux_wifi",
]


@pytest.fixture
def host(tmp_path: Path):
    """A synthetic host on which every check passes.

    Every mutation test starts here and breaks exactly one thing, so a FAIL is
    attributable to that mutation rather than to fixture noise.
    """
    root = tmp_path / "tree"
    conf = root / "conf"
    etc = tmp_path / "etc"
    share = tmp_path / "share"
    for d in (conf, etc, share):
        d.mkdir(parents=True)

    for name in CONF_FILES:
        (conf / name).write_text(f"# {name}\n")
        (etc / name).symlink_to(conf / name)

    # Data files live in the tree AND under share/ under the served name — the
    # healthy host is the one a `make install` produces, not one where --fix
    # scattered links into etc/.
    for src_name, served_name in DATA_FILES:
        (conf / src_name).write_text(f"# {src_name}\n")
        (share / served_name).symlink_to(conf / src_name)
    for name in BUILD_INPUTS:
        (conf / name).write_text(f"# {name}\n")

    site = conf / "kismet_site.conf"
    site.write_text(
        "".join(f"helper_binary_path={root / sub}\n" for sub in HELPER_SUBDIRS)
    )
    (etc / "kismet_site.conf").symlink_to(site)

    # REST credential. The healthy host is the one where a gate can
    # authenticate: kismet_httpd.conf declares the auth_file and the auth_file
    # holds a complete login. `httpd_auth_order=never` is deliberately ABSENT —
    # it is inert, and carrying it would make a bypass that never worked look
    # believable.
    (conf / "kismet_httpd.conf").write_text(
        "# kismet_httpd.conf\nhttpd_auth_file=%h/.kismet/kismet_httpd.conf\n"
    )
    home = tmp_path / "home"
    (home / ".kismet").mkdir(parents=True)
    (home / ".kismet" / "kismet_httpd.conf").write_text(
        "httpd_username=kismet\nhttpd_password=kismet\n"
    )

    # Build-tree binaries, plus a PATH copy that is NEWER — the healthy case.
    (root / "kismet").write_text("#!/bin/true\n")
    (root / "kismet").chmod(0o755)
    for sub in ("capture_cell_at", "capture_cell_diag"):
        (root / sub).mkdir()
        exe = root / sub / f"kismet_cap_{sub.removeprefix('capture_')}"
        exe.write_text("#!/bin/true\n")
        exe.chmod(0o755)

    installed = tmp_path / "bin"
    installed.mkdir()
    for src in (root / "kismet", *(root.glob("capture_cell_*/kismet_cap_*"))):
        dst = installed / src.name
        dst.write_text("#!/bin/true\n")
        dst.chmod(0o755)
        os.utime(dst, (2_000_000_000, 2_000_000_000))  # far future == fresh

    return {
        "tmp": tmp_path,
        "root": root,
        "conf": conf,
        "etc": etc,
        "share": share,
        "installed": installed,
        "home": home,
        "authfile": home / ".kismet" / "kismet_httpd.conf",
    }


def run(host, *args, path_first=None) -> subprocess.CompletedProcess:
    """Run the script against the synthetic host."""
    env = dict(os.environ)
    env.update(
        KISMET_ETC=str(host["etc"]),
        KISMET_SHARE=str(host["share"]),
        KISMET_ROOT=str(host["root"]),
        KISMET_BIN=str(host["installed"] / "kismet"),
        PATH=f"{host['installed']}:{env['PATH']}",
        # HOME is a real runtime variable -- the server resolves %h in
        # httpd_auth_file against it. Pointed at the synthetic host so [5/5]
        # never reads the developer's own ~/.kismet.
        HOME=str(host["home"]),
    )
    if path_first is not None:
        env["PATH"] = f"{path_first}:{env['PATH']}"
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_the_healthy_host_passes(host):
    """The control. If this fails, no mutation below means anything."""
    r = run(host)
    assert r.returncode == 0, r.stdout
    assert "PASS: 0 problems, 0 warning(s)" in r.stdout
    assert "FAIL" not in r.stdout
    assert "WARN" not in r.stdout


def test_the_removed_config_symlinks_are_named(host):
    """All nine config symlinks deleted: each is named as absent."""
    for name in CONF_FILES:
        (host["etc"] / name).unlink()
    r = run(host)
    assert r.returncode == 1
    for name in CONF_FILES:
        assert f"FAIL  {name} absent from" in r.stdout


def test_a_copy_is_a_warning_not_a_failure_and_names_the_conversion(host):
    """A copy STARTS the server — it is drift, not breakage. Different remedy.

    A host where every conf is a copy from a `make install` must be reported,
    not called healthy, and not failed as if the files were absent.
    """
    target = host["etc"] / "kismet.conf"
    target.unlink()
    target.write_text((host["conf"] / "kismet.conf").read_text())

    r = run(host)
    assert r.returncode == 0, "an identical copy must not fail the gate"
    assert "WARN  kismet.conf is a COPY, not a symlink" in r.stdout
    assert "to convert: rm" in r.stdout


def test_a_copy_that_already_differs_is_a_failure(host):
    """The moment the copy diverges, the server is reading something else."""
    target = host["etc"] / "kismet.conf"
    target.unlink()
    target.write_text("# stale, edited by hand\n")

    r = run(host)
    assert r.returncode == 1
    assert "FAIL  kismet.conf is a COPY and ALREADY DIFFERS" in r.stdout


def test_a_symlink_to_the_wrong_tree_is_a_failure(host):
    """Present, resolvable, and pointing at the wrong build. Starts fine."""
    other = host["tmp"] / "elsewhere.conf"
    other.write_text("# some other tree\n")
    (host["etc"] / "kismet.conf").unlink()
    (host["etc"] / "kismet.conf").symlink_to(other)

    r = run(host)
    assert r.returncode == 1
    assert "FAIL  kismet.conf is a symlink to" in r.stdout


def test_the_missing_celldiag_helper_path_is_named(host):
    """A site conf missing one helper path names exactly that path.

    With ``capture_cell_diag`` absent from ``kismet_site.conf``, celldiag
    sources cannot find their helper — with the config file present and
    readable throughout.
    """
    site = host["conf"] / "kismet_site.conf"
    site.write_text(
        "\n".join(
            line
            for line in site.read_text().splitlines()
            if "capture_cell_diag" not in line
        )
        + "\n"
    )
    r = run(host)
    assert r.returncode == 1
    assert "FAIL  helper_binary_path missing for" in r.stdout
    assert "capture_cell_diag" in r.stdout
    assert "helper_binary_path missing for" not in r.stdout.replace(
        f"FAIL  helper_binary_path missing for {host['root'] / 'capture_cell_diag'}", "", 1
    ), "exactly the one removed entry should be reported"


def test_an_absent_site_conf_fails_rather_than_passing_vacuously(host):
    """No site conf means the helper paths are UNVERIFIABLE, not satisfied.

    The tempting bug is to skip the loop when the file is missing, which reports
    a clean run on the host where the check matters most (one where
    kismet_site.conf is absent entirely).
    """
    (host["etc"] / "kismet_site.conf").unlink()
    r = run(host)
    assert r.returncode == 1
    assert "kismet_site.conf absent from" in r.stdout
    assert "helper_binary_path unverifiable" in r.stdout
    assert "OK    helper_binary_path" not in r.stdout


# ---------------------------------------------------------------------------
def test_a_stale_binary_on_path_is_a_failure(host):
    """The quiet one — a stale PATH copy starts, runs, and reports healthy.

    Nothing else notices a PATH copy that is days behind the build tree.
    """
    os.utime(host["installed"] / "kismet", (1_000_000, 1_000_000))
    r = run(host)
    assert r.returncode == 1
    assert "FAIL  kismet: PATH copy is STALE" in r.stdout
    assert "would use the OLD binary and say nothing" in r.stdout


def test_a_stale_capture_helper_is_caught_independently_of_the_server(host):
    """The server and its helpers install separately and go stale separately."""
    os.utime(
        host["installed"] / "kismet_cap_cell_diag", (1_000_000, 1_000_000)
    )
    r = run(host)
    assert r.returncode == 1
    assert "FAIL  kismet_cap_cell_diag: PATH copy is STALE" in r.stdout
    assert "FAIL  kismet: PATH copy is STALE" not in r.stdout


def test_path_resolving_into_the_build_tree_is_ok_regardless_of_mtime(host):
    """A symlink from PATH into the build tree can never be stale."""
    installed = host["installed"] / "kismet"
    installed.unlink()
    installed.symlink_to(host["root"] / "kismet")
    os.utime(host["root"] / "kismet", (1_000_000, 1_000_000))

    r = run(host)
    assert r.returncode == 0, r.stdout
    assert "kismet: PATH resolves to the build tree" in r.stdout


def test_fix_creates_absent_symlinks(host):
    for name in CONF_FILES:
        (host["etc"] / name).unlink()

    r = run(host, "--fix")
    assert r.returncode == 0, r.stdout
    for name in CONF_FILES:
        link = host["etc"] / name
        assert link.is_symlink()
        assert link.resolve() == (host["conf"] / name).resolve()


def test_fix_refuses_to_replace_a_regular_file(host):
    """Deliberate. Clobbering host state is the operator's call, not a side
    effect of a preflight run — the file may carry local edits nobody recorded.
    """
    target = host["etc"] / "kismet.conf"
    target.unlink()
    target.write_text("# hand-edited, unrecorded\n")

    r = run(host, "--fix")
    assert r.returncode == 1
    assert target.read_text() == "# hand-edited, unrecorded\n"
    assert not target.is_symlink()
    assert "ALREADY DIFFERS" in r.stdout


def test_fix_does_not_install_binaries(host):
    """--fix must never run `make install`; it names the command instead."""
    os.utime(host["installed"] / "kismet", (1_000_000, 1_000_000))
    before = (host["installed"] / "kismet").stat().st_mtime

    r = run(host, "--fix")
    assert r.returncode == 1
    assert (host["installed"] / "kismet").stat().st_mtime == before
    assert "make -C" in r.stdout


def test_data_files_are_satisfied_by_the_share_dir(host):
    """The `make install` shape: real files under share/ under the served name."""
    for _src, served in DATA_FILES:
        (host["share"] / served).unlink()
        (host["share"] / served).write_text("data\n")

    r = run(host)
    assert r.returncode == 0, r.stdout
    for _src, served in DATA_FILES:
        assert f"OK    {served} present" in r.stdout


def test_a_data_file_only_in_etc_is_not_ok(host):
    """A data file present only in etc/ must not report OK.

    The file is on the host, so every "is it installed?" test passes — but the
    consumer resolves %S/kismet/ and never looks in etc/, so the server cannot
    open it.
    """
    for src, served in DATA_FILES:
        (host["share"] / served).unlink()
        (host["etc"] / src).symlink_to(host["conf"] / src)

    r = run(host)
    assert r.returncode == 1, r.stdout
    for src, served in DATA_FILES:
        assert f"WARN  {src} is in {host['etc']}, which " in r.stdout
        assert f"FAIL  {served} absent from {host['share']}" in r.stdout


def test_fix_creates_data_links_where_the_consumer_reads_them(host):
    """--fix must repair the location the server uses, not the fallback.

    A --fix that created links in etc/ would let a second run report PASS over
    a host the server still could not read.
    """
    for _src, served in DATA_FILES:
        (host["share"] / served).unlink()

    r = run(host, "--fix")
    assert r.returncode == 0, r.stdout
    for src, served in DATA_FILES:
        link = host["share"] / served
        assert link.is_symlink(), f"{served} not created under share/"
        assert link.resolve() == (host["conf"] / src).resolve()
        assert not (host["etc"] / src).exists(), f"{src} wrongly created in etc/"

    # Idempotent, and green for the right reason the second time.
    again = run(host)
    assert again.returncode == 0, again.stdout
    assert "PASS: 0 problems" in again.stdout


def test_the_uav_yaml_is_not_checked_as_a_host_data_file(host):
    """It is a build input compiled into kismet_uav.conf; no runtime path opens it.

    Checking it could only ever produce a meaningless OK, so its absence from
    the host must not be reported at all — in either direction.
    """
    r = run(host)
    assert r.returncode == 0, r.stdout
    for name in BUILD_INPUTS:
        assert name not in r.stdout


def test_kismet_root_defaults_to_the_tree_this_script_ships_in():
    """The default root is the tree the script is in, not a guessed checkout.

    A conventional default (a fixed name under some clones directory) can
    resolve to a checkout
    the operator is not building, and then a PASS means "some tree is wired up",
    not "this one is" -- a wrong-cause pass, the failure class every check in
    this file exists to prevent.

    Asserted on the header line alone: the header prints before any check runs,
    so this test says nothing about the real host's state and is green whatever
    ``/usr/local/etc`` happens to hold.
    """
    env = {k: v for k, v in os.environ.items() if k != "KISMET_ROOT"}
    r = subprocess.run(
        ["bash", str(SCRIPT)],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert f"root={REPO}" in r.stdout, r.stdout


def test_an_absent_conf_dir_fails_early_and_says_so(host):
    """Without ``conf/`` there is nothing to compare against — say that, rather
    than reporting nine independent missing-symlink failures with a remedy that
    points at a directory that does not exist."""
    import shutil

    shutil.rmtree(host["conf"])
    r = run(host)
    assert r.returncode == 1
    assert "conf dir absent" in r.stdout
    assert "kismet.conf absent from" not in r.stdout


# ---------------------------------------------------------------------------
# [5/5] REST credential.
#
# Scripted gates read the REST API, REST is authenticated unconditionally, and
# the config line that looks like it disables it (`httpd_auth_order=never`) is
# not a directive in this base at all. So the
# thing to assert is not "auth is off" — it is that a credential EXISTS, in one
# of the two places the server looks. Each test below breaks one of those.


def test_an_absent_auth_file_fails_rather_than_passing_on_host_luck(host):
    """A missing auth file is a finding, not something host luck covers.

    Gates can pass only because an old ``~/.kismet/kismet_httpd.conf`` happens
    to exist. Remove it and the preflight must say so BEFORE a gate runs — on a fresh host the same run gets the interactive
    first-run login, and its 401 reads as "server down".
    """
    host["authfile"].unlink()
    r = run(host)
    assert r.returncode == 1
    assert "no REST credential" in r.stdout
    assert "401" in r.stdout or "first-run login" in r.stdout


def test_a_global_login_satisfies_the_check_without_an_auth_file(host):
    """``httpd_username``/``httpd_password`` in a global conf wins outright — the
    server raises GLOBALHTTPDUSER and ignores the auth file. A check that only
    looked for the file would fail a host that is correctly configured."""
    host["authfile"].unlink()
    site = host["conf"] / "kismet_site.conf"
    site.write_text(site.read_text() + "httpd_username=gate\nhttpd_password=s3cret\n")
    r = run(host)
    assert r.returncode == 0, r.stdout
    assert "global httpd_username/httpd_password" in r.stdout
    assert "no REST credential" not in r.stdout


def test_a_half_global_login_is_named_as_a_server_that_will_not_start(host):
    """Not a degraded credential — ``_MSG_FATAL`` + ``fatal_condition`` at
    startup. The operator needs the distinct diagnosis, because the symptom
    (no server) is nothing like the symptom of a missing credential (401)."""
    site = host["conf"] / "kismet_site.conf"
    site.write_text(site.read_text() + "httpd_username=gate\n")
    r = run(host)
    assert r.returncode == 1
    assert "has httpd_username but not httpd_password" in r.stdout
    assert "FATAL" in r.stdout


def test_a_partial_auth_file_is_not_treated_as_a_credential(host):
    """The file existing is not the same as being able to authenticate.

    ``kis_net_beast_httpd.cc`` logs "Found a partial configuration ... resetting
    login information" and empties BOTH fields, so the server falls through to
    the first-run prompt. A mere ``-r`` existence check would call this healthy.
    """
    host["authfile"].write_text("httpd_username=kismet\n")
    r = run(host)
    assert r.returncode == 1
    assert "PARTIAL credential" in r.stdout
    assert "missing httpd_password" in r.stdout


def test_an_absent_auth_file_directive_is_still_a_finding_after_the_typo_fix(host):
    """An absent ``httpd_auth_file=`` directive is a FAIL even though the
    built-in read and write defaults agree.

    The directive can be present and pointed somewhere unreadable, and an
    explicit directive is what makes the resolved credential path visible to an
    operator rather than implied by a default two call sites deep.
    """
    (host["conf"] / "kismet_httpd.conf").write_text("# no auth_file line\n")
    r = run(host)
    assert r.returncode == 1
    assert "no httpd_auth_file=" in r.stdout
    assert "built-in defaults agree" in r.stdout


def test_the_two_httpd_auth_file_defaults_agree():
    """The read and write defaults for ``httpd_auth_file`` must agree.

    The hazard is not that either default is wrong in isolation — each is a
    plausible path — but that the READ and WRITE sites, far apart in the file,
    can disagree in a fallback neither reaches on a configured host. One line in
    ``conf/kismet_httpd.conf`` masks it entirely, so nothing executes it.

    So the assertion is *equality of the two literals*, not the value of either.
    A future edit that "fixes" one site to a new path reintroduces the same
    class of bug and fails here.
    """
    src = _kismet_source_or_skip("kis_net_beast_httpd.cc")
    defaults = re.findall(
        r'fetch_opt_path\(\s*"httpd_auth_file"\s*,'      # the option name
        r'(?:\s*//[^\n]*\n)*'                            # any comment lines
        r'\s*"([^"]+)"',                                 # the default literal
        src)
    assert len(defaults) == 2, (
        f"expected exactly 2 httpd_auth_file default sites (the constructor's "
        f"read and set_admin_login()'s write); found {len(defaults)}: "
        f"{defaults!r}. If a third appears, all of them must agree -- update "
        "this guard deliberately rather than deleting it.")
    assert defaults[0] == defaults[1], (
        f"the read and write defaults for httpd_auth_file disagree: "
        f"{defaults[0]!r} vs {defaults[1]!r}. A credential set through the web "
        f"UI's first-run login is written to one and read back from the other, "
        f"so the login silently never sticks and no error names a path.")


def test_a_reappearing_httpd_auth_order_is_named_as_inert(host):
    """``httpd_auth_order`` is not breakage — the credential check
    still passes — but it is why an authenticated server looked like an open
    one, so it is reported wherever it comes back."""
    site = host["conf"] / "kismet_site.conf"
    site.write_text("httpd_auth_order=never\n" + site.read_text())
    r = run(host)
    assert r.returncode == 0, r.stdout
    assert "INERT key" in r.stdout
    assert "does not disable REST auth" in r.stdout


def test_the_auth_file_is_resolved_against_home_not_the_developers_own(host):
    """``%h`` is expanded against ``$HOME``. If the script read the real home
    directory instead, this suite would pass or fail depending on whose machine
    ran it."""
    r = run(host)
    assert r.returncode == 0, r.stdout
    assert str(host["authfile"]) in r.stdout


def test_make_install_ships_every_data_file_the_preflight_checks():
    """`make install` and `--fix` must produce the SAME host state.

    If ``make install`` skipped a data file the server opens, a host that was
    only installed -- never preflighted -- would silently lose (for example)
    Bluetooth service-name resolution, while a preflighted host, where
    ``--fix`` linked the file, would work and hide the gap.

    That is the failure this pins: two mechanisms that are supposed to converge
    on one host state, disagreeing, with only one of them exercised. This reads
    both sources and asserts every served name in the preflight's DATA_FILES
    table is also installed by the Makefile's install target.

    The served names are deliberately NOT the conf/ names for the two
    bluetooth files: ``bluetooth_ids.cc`` defaults to ``...\\_ids.txt`` without
    ``.gz`` and opens it with ``gzopen()``, which reads gzip content regardless
    of extension. Installing them under a faithful ``.txt.gz`` name is the
    obvious-looking change that breaks the lookup -- so this test asserts the
    SERVED name specifically, which is the one the server actually opens.
    """
    sh = _kismet_source_or_skip("celltools/kismet-host-preflight.sh")
    mk = _kismet_source_or_skip("Makefile.in")

    table = re.search(r"^DATA_FILES=\((.*?)^\)", sh, re.S | re.M)
    assert table, "the preflight's DATA_FILES table moved or was renamed"

    served = [line.split("|")[1]
              for line in re.findall(r'"([^"]+)"', table.group(1))]
    assert len(served) >= 4, (
        f"expected at least the 4 known data files; parsed {served!r}")

    install = mk[mk.index("conf/kismet_manuf.txt.gz $(SHARE)"):]
    install = install[:install.index("CONFINSTTARGETS")]

    missing = [n for n in served if f"$(SHARE)/{n}" not in install]
    assert not missing, (
        f"the preflight checks these served data files but `make install` "
        f"never copies them to $(SHARE): {missing}. A host that was only "
        f"installed -- never preflighted -- loses whatever reads them, with "
        f"nothing but a server log line to say so.")


def test_make_install_data_lines_survive_a_share_dir_that_fix_linked(tmp_path):
    """`--fix` then `make install` must compose, in that order.

    The test above pins that both paths ship the same served NAMES. It runs
    neither, so it cannot see that they ship different KINDS of file: ``--fix``
    links an absent data file into conf/, and a recipe using ``cp`` follows that
    link to its own source and aborts with "are the same file", so
    ``commoninstall`` dies there and ``configsinstall`` never runs.

    So this RUNS the Makefile.in recipe lines that write a data file into
    $(SHARE) -- whatever verb they use -- against a share dir in the exact state
    ``--fix`` leaves, and asserts each link is replaced by a real copy while
    conf/ is not written through it.
    """
    mk = _kismet_source_or_skip("Makefile.in")
    tree = cell_binaries.tree_root()
    lines = re.findall(r"^\t(.*\sconf/(kismet_\S+)\s+\$\(SHARE\)/?(\S+))$", mk, re.M)
    assert len(lines) >= len(DATA_FILES), (
        f"expected a $(SHARE) install line per data file; found {lines!r}")

    share = tmp_path / "share"
    share.mkdir()
    before = {}
    for _cmd, src, served in lines:
        (share / served).symlink_to(tree / "conf" / src)
        before[src] = (tree / "conf" / src).read_bytes()

    recipe = "\n".join(f"\t{cmd}" for cmd, _src, _served in lines)
    mkfile = tmp_path / "datafiles.mk"
    mkfile.write_text(f"datafiles:\n{recipe}\n")
    r = subprocess.run(
        ["make", "-f", str(mkfile), "datafiles",
         "INSTALL=/usr/bin/install -c", f"SHARE={share}",
         f"INSTUSR={os.getuid()}", f"INSTGRP={os.getgid()}"],
        cwd=tree, capture_output=True, text=True)
    assert r.returncode == 0, (
        f"the data-file install lines fail on a --fix-linked share dir"
        f":\n{r.stdout}{r.stderr}")

    for _cmd, src, served in lines:
        dest = share / served
        assert not dest.is_symlink(), f"{served} is still a link after install"
        assert dest.read_bytes() == before[src], f"{served} content differs from conf/{src}"
        assert (tree / "conf" / src).read_bytes() == before[src], (
            f"conf/{src} was written through the link")


# ---------------------------------------------------------------------------
# The OTHER half of the data-file convergence
# ---------------------------------------------------------------------------
#
# `test_make_install_ships_every_data_file_the_preflight_checks` pins the
# producer side: everything the preflight checks, `make install` also installs.
# Nothing pins the CONSUMER side -- that `$KISMET_SHARE` is the directory the
# server actually opens.
#
# That claim is load-bearing for the entire [3/5] group and it exists only as
# PROSE: in the script's comments, in the `consumer` column of its DATA_FILES
# table, and in a docstring above. If a default ever moved to `%E/` (etc), the
# preflight would go on checking share/, report 4x OK, and the server would read
# the copies in etc/ -- completely silent, because a group reporting OK is the
# group nobody re-reads.
#
# A source-text assertion can easily match PROSE rather than code. These read
# the DEFINING SITES -- a `key=value` line in
# conf/kismet.conf and a `fetch_opt_dfl(...)` call in bluetooth_ids.cc -- not a
# mention of the key anywhere in the file.

# consumer -> (source file, how its default is spelled there)
_CONSUMER_SITES = {
    "ouifile": ("conf/kismet.conf", "conf"),
    "icaofile": ("conf/kismet.conf", "conf"),
    "btoidfile": ("bluetooth_ids.cc", "fetch_opt_dfl"),
    "btmanuffile": ("bluetooth_ids.cc", "fetch_opt_dfl"),
}


def _consumer_default(key: str) -> str:
    relpath, kind = _CONSUMER_SITES[key]
    src = _kismet_source_or_skip(relpath)
    if kind == "conf":
        m = re.search(rf"^{re.escape(key)}=(\S+)\s*$", src, re.M)
    else:
        m = re.search(rf'fetch_opt_dfl\(\s*"{re.escape(key)}"\s*,\s*"([^"]+)"', src)
    assert m, f"no defining site for {key!r} in {relpath} -- the option was renamed or moved"
    return m.group(1)


@pytest.mark.parametrize("key", sorted(_CONSUMER_SITES))
def test_every_data_file_consumer_resolves_share_and_not_etc(key):
    """The preflight checks $KISMET_SHARE because that is where the code looks.

    Measured, not asserted. `%S` is the share dir and `%E` is the etc dir; data
    files sitting in `%E` while every consumer resolves `%S` are invisible to
    the server. If one of these defaults ever moves to `%E`, the
    preflight's whole [3/5] group silently starts measuring a directory nothing
    opens -- and it would report OK while doing it.
    """
    default = _consumer_default(key)
    assert default.startswith("%S/kismet/"), (
        f"{key} defaults to {default!r}, which does not resolve under the share "
        f"dir the preflight checks. Either the default moved or DATA_FILES did; "
        f"they have to move together.")
    assert "%E" not in default, (
        f"{key} defaults into the ETC dir ({default!r}) -- the data files "
        f"would then have to live in etc/, which the preflight does not check.")


def test_the_served_names_are_the_ones_the_consumers_actually_OPEN():
    """The `.gz`-vs-no-`.gz` asymmetry, DERIVED from source instead of asserted.

    The preflight's DATA_FILES table installs the two bluetooth databases under
    `...\\_ids.txt` while conf/ ships `...\\_ids.txt.gz`, and every comment in the
    tree explains why (`bluetooth_ids.cc` opens with `gzopen()`, which reads gzip
    content regardless of extension, but only at the name it was given).

    An explanation is not a check. This asserts each served name equals the
    basename the consumer's own default names -- so "rename these to match conf/",
    which the Makefile comment calls the obvious-looking change that reintroduces
    the bug, fails here rather than in a Bluetooth lookup nobody is watching.
    """
    served_by_key = {
        "ouifile": "kismet_manuf.txt.gz",
        "icaofile": "kismet_adsb_icao.txt.gz",
        "btoidfile": "kismet_bluetooth_ids.txt",
        "btmanuffile": "kismet_bluetooth_manuf.txt",
    }
    known_served = {served for _src, served in DATA_FILES}
    assert set(served_by_key.values()) == known_served, (
        f"this test's consumer->served map has drifted from DATA_FILES: "
        f"{sorted(served_by_key.values())} vs {sorted(known_served)}")

    for key, served in sorted(served_by_key.items()):
        default = _consumer_default(key)
        assert default.rsplit("/", 1)[-1] == served, (
            f"{key} opens {default.rsplit('/', 1)[-1]!r} but the preflight and "
            f"`make install` place {served!r}. The file would be on the host and "
            f"unreadable to the code.")
