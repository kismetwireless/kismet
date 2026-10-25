"""A bare tree whose ``qmifeed=auto`` runs a test's shell feed.

``qmifeed=`` only runs the feed that ships beside the binary, so a test that
needs its own feed copies the binary into a tree whose
``qmifeed/kismet_qmi_feed.py`` execs the test's shell script.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from installed_datadir import forget_installed_datadir


def feed_tree(tmp_path: Path, binary: "str | Path", feed_sh: Path) -> Path:
    """Copy ``binary`` into a bare tree running ``feed_sh``; return the copy."""
    capdir = tmp_path / "feedtree" / "capture_cell_at"
    (capdir / "qmifeed").mkdir(parents=True, exist_ok=True)
    dest = capdir / Path(binary).name
    shutil.copy2(binary, dest)
    forget_installed_datadir(dest)
    (capdir / "qmifeed" / "kismet_qmi_feed.py").write_text(
        "import os\n"
        f"os.execv('/bin/sh', ['sh', {str(feed_sh)!r}])\n")
    return dest


#: The helper the server tests launch, before it is copied into a feed tree.
CELLAT_BIN = Path(__file__).resolve().parents[2] / "capture_cell_at" / "kismet_cap_cell_at"


def server_feed(server, tmp_path: Path, feed_sh: Path):
    """Point a not-yet-started test server at a feed tree running ``feed_sh``.

    helper_binary_path is a search list and the first hit wins, so the feed
    tree goes first in the copied site conf. Returns ``server``.
    """
    tree = feed_tree(tmp_path, CELLAT_BIN, feed_sh).parent
    site = server.conf / "kismet_site.conf"
    site.write_text(f"helper_binary_path={tree}\n" + site.read_text())
    return server
