"""An isolated, REAL Kismet server for the celldiag/cellat server tests.

The panel's mask and F3 selectors and its Restart button all sit on
``POST /datasource/by-uuid/:uuid/update_definition`` and the close/open
sequence around it. Tests that read source text cannot show that a running
server accepts that sequence, so those tests drive it over HTTP through the
``KismetServer`` harness defined here (the route round trips themselves need a
replayed capture with data flowing, and are run where such captures are
available).

``CaptureRun`` is not enough here: it speaks the capture-framework IPC
protocol straight to the helper binary, while these routes live in the server
(``datasourcetracker.cc``) and are only reachable over HTTP. This harness
starts an isolated ``kismet`` instead (private ``--homedir`` / ``--confdir``,
an ephemeral port, logging off) and drives the endpoints as the panel does.

The route refuses a running source, so the only working order is
``close_source -> update_definition -> open_source``. With
``update_definition`` first, the first call returns 500, ``.then()`` does not
chain on a rejection, and the close and open never happen. The panel installs
no ``.fail()`` handler, so that failure would be silent.

Only ``f3_preset`` can be checked end to end offline. A ``replay=``
source hard-codes ``mask_preset`` to the literal ``"replay"``
(``capture_cell_diag.c``), so the mask selector's round-trip still needs a
modem. ``f3_preset`` is resolved *before* the live/replay split and reports
honestly — and it exercises the identical route, so the shared mechanism is
covered even though one of its two labels is not.
"""

from __future__ import annotations

import base64
import json
import re
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

KP_ROOT = Path(__file__).resolve().parents[2]
SERVER = KP_ROOT / "kismet"
CONF = KP_ROOT / "conf"

#: 15-digit synthetic IMEI. `probe_callback` requires `celldiag-<15 digits>`;
#: a bare `celldiag:` interface is silently declined and the source never
#: registers at all, with no message.
IMEI = "000000000000000"

#: Sources whose staleness makes a run meaningless: these routes and the
#: sequence they enforce are compiled INTO the server binary.
_SERVER_DEPS = ("datasourcetracker.cc", "kis_datasource.cc", "kis_datasource.h")

def _server_or_skip() -> Path:
    """The built server, and it must be NEWER than the routes under test.

    A stale ``kismet`` would drive the old route, report green, and certify a
    sequence nobody compiled. Skips (naming ``make kismet``) rather than
    failing, because an unbuilt server is a host property: the build takes
    about ten minutes and not every checkout wants to pay it.
    """
    if not SERVER.is_file():
        pytest.skip(f"no server binary at {SERVER} -- run `make kismet` in {KP_ROOT}")
    mtime = SERVER.stat().st_mtime
    stale = [d for d in _SERVER_DEPS
             if (KP_ROOT / d).is_file() and (KP_ROOT / d).stat().st_mtime > mtime]
    if stale:
        pytest.skip(f"{SERVER.name} is older than {', '.join(stale)} -- "
                    f"run `make kismet` in {KP_ROOT}")
    return SERVER


#: capture dir -> the role whose DISCOVERED binary the server must launch.
_HELPER_ROLES = {"capture_cell_at": "cellat", "capture_cell_diag": "celldiag"}


def _helper_dir(capture_dir: str) -> Path:
    """Where the server should look for ``capture_dir``'s helper binary.

    The directory of the binary ``cell_binaries.discover`` found (the same
    binary every staleness guard here inspects), not a fixed
    ``KP_ROOT/<capture_dir>``. On a configured tree the two agree. On a tree
    built only through ``standalone.mk`` (e.g. macOS) the binary is in its
    standalone build directory (``build-native/`` for celldiag), and the fixed
    path would make every real-server test fail "Unable to find driver". Roles
    without an entry keep the fixed path.
    """
    role = _HELPER_ROLES.get(capture_dir)
    if role is not None:
        import cell_binaries
        found = cell_binaries.discover(role)
        if found.ok:
            return Path(found.path).parent
    return KP_ROOT / capture_dir


def _base(row: dict) -> str:
    return f"datasource/by-uuid/{row['kismet.datasource.uuid']}/"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class KismetServer:
    """An isolated Kismet, with an HTTP client that speaks the panel's dialect.

    Isolated in three ways: a private ``--homedir`` (so the generated admin
    credentials and server UUID never touch the operator's ``~/.kismet``), a
    copied ``--confdir`` (so the port and logging overrides do not edit the
    repo's ``kismet_site.conf``), and an ephemeral port (so a developer's own
    running Kismet is neither disturbed nor accidentally driven by this test).
    """

    USER, PASSWD = "celldiagtest", "celldiagtest"

    def __init__(self, tmp_path: Path, srcdef: str, silent: bool = True) -> None:
        #: `--silent` suppresses every message after startup, including
        #: `Found type`, `Data source … launched successfully`, `Unable to find
        #: driver`, `Data source … failed to launch` and every `celldiag stats:`
        #: line. No test that runs with `silent=True` may assert on log
        #: content: an assertion that a message is absent passes whether or
        #: not it was emitted.
        #:
        #: Every test in THIS file asserts on HTTP/reported fields, so the
        #: default is safe and kept. Pass `silent=False` when the log IS the
        #: measurement (see `test_celldiag_live_native_ab.py`).
        self.silent = silent
        self.port = _free_port()
        self.home = tmp_path / "home"
        (self.home / ".kismet").mkdir(parents=True)
        # Pre-seeding the credentials skips Kismet's first-run setup prompt,
        # which otherwise leaves every LOGON_ROLE route unreachable.
        (self.home / ".kismet" / "kismet_httpd.conf").write_text(
            f"httpd_username={self.USER}\nhttpd_password={self.PASSWD}\n")
        self.conf = tmp_path / "conf"
        shutil.copytree(CONF, self.conf)
        # The site conf names its helpers by absolute path to one checkout
        # (`helper_binary_path=<that checkout>/capture_cell_at`).
        # helper_binary_path is a search list and the first hit wins, so from
        # any other tree (a worktree, a scratch copy) the server would launch
        # that checkout's helpers while every staleness guard here inspects
        # this tree's binaries. Point each capture dir at this tree's.
        site = self.conf / "kismet_site.conf"
        text = re.sub(
            r"(?m)^helper_binary_path=\S*/(capture_[A-Za-z0-9_]+)\s*$",
            lambda m: f"helper_binary_path={_helper_dir(m.group(1))}",
            site.read_text())
        # Drop the site conf's own bind line (``0.0.0.0``: the operator's
        # LAN-reachable server). The first value of a key wins, so with it in
        # place the loopback line appended below is dead text and the harness
        # server listens on every interface with this class's fixed
        # USER/PASSWD.
        site.write_text(re.sub(r"(?m)^[ \t]*httpd_bind_address[ \t]*=.*\n?", "", text))
        with (self.conf / "kismet_site.conf").open("a") as fp:
            # `remote_capture_enabled=false` is required. The repo's site
            # conf listens on the fixed port 3501, and a server that cannot
            # bind it dies with "KISMET HAS ENCOUNTERED A FATAL ERROR", so
            # back-to-back tests would race each other's lingering socket and
            # a developer's own running Kismet would fail the suite.
            fp.write(f"\nhttpd_port={self.port}\nhttpd_bind_address=127.0.0.1\n"
                     "enable_logging=false\n"
                     "remote_capture_enabled=false\n")
        self.srcdef = srcdef
        self.logpath = tmp_path / "kismet.log"
        self._log = self.logpath.open("wb")
        self.proc: subprocess.Popen | None = None

    # ── lifecycle ────────────────────────────────────────────────────────
    def __enter__(self) -> "KismetServer":
        argv = [str(SERVER), "--no-ncurses", "--no-line-wrap",
                "--homedir", str(self.home), "--confdir", str(self.conf),
                "--datadir", str(KP_ROOT)]
        # srcdef=None: a server started with no sources, where everything is
        # enabled later from the Data Sources panel.
        if self.srcdef:
            # A list starts several sources (one modem's cellat + celldiag).
            for d in ([self.srcdef] if isinstance(self.srcdef, str) else self.srcdef):
                argv += ["-c", d]
        if self.silent:
            argv.insert(2, "--silent")
        # KISMET_CONF, not just --confdir. --confdir sets only the directory
        # the kismet_*.conf overrides are read from; the base kismet.conf path
        # is `$KISMET_CONF/kismet.conf`, falling back to the compiled-in
        # SYSCONF_LOC. Without it, a build-only host exits at once ("Error
        # reading config file '/usr/local/etc/kismet.conf'"), and a host with
        # an installed Kismet silently reads the installed base config. The
        # private copy keeps the base config as isolated as the overrides.
        self.proc = subprocess.Popen(
            argv,
            stdout=self._log, stderr=subprocess.STDOUT, cwd=str(KP_ROOT),
            env={**os.environ, "HOME": str(self.home),
                 "KISMET_CONF": str(self.conf)})
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"kismet exited early:\n{self.tail()}")
            try:
                self.get("system/status.json")
                return self
            except Exception:
                time.sleep(0.5)
        raise AssertionError(f"kismet never served HTTP:\n{self.tail()}")

    def __exit__(self, *exc) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(30)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.proc.kill()
        self._log.close()

    def tail(self, n: int = 3000) -> str:
        return self.logpath.read_text(errors="replace")[-n:]

    # ── HTTP ─────────────────────────────────────────────────────────────
    def _request(self, path: str, data: bytes | None = None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/{path}", data=data)
        token = base64.b64encode(
            f"{self.USER}:{self.PASSWD}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
        if data is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        return req

    def get(self, path: str):
        with urllib.request.urlopen(self._request(path), timeout=30) as r:
            return json.loads(r.read().decode())

    def post(self, path: str, payload: dict):
        """POST the way the panel does -- a urlencoded ``json=`` field."""
        body = ("json=" + urllib.parse.quote(json.dumps(payload))).encode()
        with urllib.request.urlopen(self._request(path, body), timeout=30) as r:
            return r.status, json.loads(r.read().decode())

    # ── datasource helpers ───────────────────────────────────────────────
    def source(self) -> dict | None:
        rows = self.get("datasource/all_sources.json")
        return rows[0] if rows else None

    def await_running(self, want: bool = True, timeout: float = 90) -> dict:
        deadline = time.monotonic() + timeout
        row = None
        while time.monotonic() < deadline:
            row = self.source()
            if row is not None and bool(row["kismet.datasource.running"]) is want:
                return row
            time.sleep(0.5)
        raise AssertionError(
            f"source never reached running={want}; last row="
            f"{json.dumps(row, indent=1) if row else None}\n{self.tail()}")

    def ensure_running(self) -> dict:
        """Re-open the source if the replay has drained.

        A `replay=` source is finite. There is no loop and no pacing, so the
        capture thread reaches EOF and the source spins down, which is normal
        and not an error. With `retry=false` (see the source definition)
        nothing re-opens it behind the test's back, which is the property every
        attribution here depends on; the cost is that the test must open it
        itself when a previous step ran long.
        """
        row = self.source()
        assert row is not None, f"no datasource registered\n{self.tail()}"
        if row["kismet.datasource.running"]:
            return row
        self.get(f"datasource/by-uuid/{row['kismet.datasource.uuid']}/"
                 "open_source.cmd")
        return self.await_running(True)

    def await_field(self, name: str, want, timeout: float = 60) -> None:
        """Wait for a celldiag stats field to REPORT ``want``.

        The outcome of every one of these controls is a field the capture
        binary re-reports on its own stats interval -- never the HTTP status,
        which a refused celldiag setting returns as success anyway.
        """
        key = f"kismet.datasource.celldiag.{name}"
        deadline = time.monotonic() + timeout
        got = None
        while time.monotonic() < deadline:
            row = self.source()
            got = (row or {}).get(key)
            if got == want:
                return
            time.sleep(0.5)
        raise AssertionError(
            f"{name} never reported {want!r} (last {got!r})\n{self.tail()}")


# ─────────────────────────────────────────────────────────────────────────
def test_the_harness_turns_logging_off_with_a_key_kismet_reads():
    """Every conf key this harness writes must be one the server reads.

    Kismet reads only ``enable_logging`` (default true), not
    ``logging_enabled``. A misspelled key is accepted without a word, logging
    stays on, and every run leaves a ``.kismet`` log in the tree root. Source
    text only, so it runs on a host with no server build.
    """
    block = Path(__file__).read_text().split("fp.write(", 1)[1].split(")", 1)[0]
    written = set(re.findall(r'(?:\\n|")([a-z_]+)=', block))
    assert "httpd_port" in written, written   # the parse itself found the block
    assert "enable_logging" in written, written
    assert "logging_enabled" not in written, written
    logtracker = (KP_ROOT / "logtracker.cc").read_text()
    assert 'fetch_opt_bool("enable_logging"' in logtracker


def _first_value(conf_text: str, key: str) -> "str | None":
    """Kismet's rule for a key set twice in one file: the FIRST value wins
    (``config_file::fetch_opt`` returns ``second[0]``, configfile.cc)."""
    for line in conf_text.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip().lower() == key:
            return v.strip()
    return None


def test_the_harness_conf_binds_the_server_to_loopback(tmp_path):
    """The harness's REST server must listen on 127.0.0.1 only.

    The repo's ``kismet_site.conf`` sets ``httpd_bind_address=0.0.0.0``, and
    the harness appends ``httpd_bind_address=127.0.0.1`` to the same file.
    The first value of a key wins, so unless the original line is removed the
    append is dead text and the server listens on every interface with this
    file's fixed USER/PASSWD. Conf only, so it runs with no server build.
    """
    srv = KismetServer(tmp_path, None)
    srv._log.close()
    site = (srv.conf / "kismet_site.conf").read_text()
    assert _first_value(site, "httpd_port") == str(srv.port), "the parse found the block"
    assert _first_value(site, "httpd_bind_address") == "127.0.0.1", \
        [ln for ln in site.splitlines() if "httpd_bind_address" in ln]


def test_the_harness_server_listens_on_loopback_only(tmp_path):
    """Loopback-only binding, read off the running server's bound address.

    ``kis_net_beast_httpd.cc`` logs ``HTTP server listening on <addr>:<port>``
    from the bound endpoint, so this is the server's own report, not the
    conf's claim. ``silent=False``: the log IS the measurement here.
    """
    _server_or_skip()
    with KismetServer(tmp_path, None, silent=False) as srv:
        port = srv.port
    log = srv.logpath.read_text(errors="replace")
    m = re.search(r"HTTP server listening on (\S+):(\d+)", log)
    assert m, f"no listen line in the server log:\n{log[-1500:]}"
    assert (m.group(1), int(m.group(2))) == ("127.0.0.1", port), m.group(0)
