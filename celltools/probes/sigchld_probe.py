# SPDX-License-Identifier: Apache-2.0
"""sigchld_probe -- runtime sampling of a capture helper's threads.

## What it measures

The capture framework delivers SIGCHLD to a dedicated signal thread, which
reaps every exited child of the process. Two properties of a running helper
are worth measuring from outside, with no source reading and no debugger:

1. **No thread spins.** On an idle source, no thread may sit runnable at
   ~100% CPU. A reaper that loops after a child exit looks exactly like that:
   one thread going from 0% to 90-110% CPU and staying there until the
   process exits.
2. **No fork after start.** The helper decodes in process, so once it is up
   it has no children to start, and none to reap.

The sampling functions (:func:`threads`, :func:`cpu_pct`, :func:`hot_threads`,
:func:`children`, :func:`own_child`) read ``/proc/<pid>/task/*`` for each
thread's name and CPU ticks, and are imported by the harnesses that assert
those two properties against a running helper.

Linux only (``/proc``).
"""
from __future__ import annotations

import os
import time
from pathlib import Path

HZ = os.sysconf("SC_CLK_TCK")
#: Above this, a thread on an idle source is spinning, not working.
HOT_PCT = 50.0


# ── /proc sampling (importable) ──────────────────────────────────────────────
def _stat_fields(stat: str) -> list[str]:
    """The fields after ``comm``; comm may itself contain spaces or parens."""
    return stat[stat.rindex(")") + 2:].split()


def threads(pid: int) -> dict[int, tuple[str, int, str]]:
    """``{tid: (comm, utime+stime ticks, state)}`` for every thread of `pid`."""
    res = {}
    for t in Path(f"/proc/{pid}/task").iterdir():
        try:
            f = _stat_fields((t / "stat").read_text())
            res[int(t.name)] = ((t / "comm").read_text().strip(),
                                int(f[11]) + int(f[12]), f[0])
        except (OSError, ValueError):
            pass
    return res


def cpu_pct(a: dict, b: dict, dt: float) -> dict[int, tuple[str, float, str]]:
    """Per-thread CPU% between two :func:`threads` snapshots taken `dt` apart."""
    return {tid: (b[tid][0], round(100.0 * (b[tid][1] - a[tid][1]) / HZ / dt, 1),
                  b[tid][2])
            for tid in b if tid in a}


def hot_threads(pid: int, dt: float = 1.0, limit: float = HOT_PCT) -> dict:
    """Threads of `pid` above `limit`% CPU over a `dt`-second window."""
    a = threads(pid)
    time.sleep(dt)
    return {tid: v for tid, v in cpu_pct(a, threads(pid), dt).items()
            if v[1] > limit}


def children(pid: int) -> list[int]:
    out = []
    for t in Path(f"/proc/{pid}/task").iterdir():
        try:
            out += [int(c) for c in (t / "children").read_text().split()]
        except OSError:
            pass
    return out


def own_child(binary: str, deadline: float) -> int | None:
    """The pid of THIS process's child running `binary`.

    Matching on the executable alone also matches a previous trial's
    process that is still exiting, which then vanishes under the sampler.
    """
    want = os.path.realpath(binary)
    while time.monotonic() < deadline:
        for p in Path("/proc").iterdir():
            if not p.name.isdigit():
                continue
            try:
                ppid = int(_stat_fields((p / "stat").read_text())[1])
                if ppid == os.getpid() and os.readlink(p / "exe") == want:
                    return int(p.name)
            except (OSError, ValueError):
                pass
        time.sleep(0.05)
    return None
