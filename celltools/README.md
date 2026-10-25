# `celltools/` — host checks and Python harnesses for the cell capture sources

Test and diagnostic tooling for `capture_cell_at/`, `capture_cell_diag/`, and
`diagspec/` that is **too high-level to be a C unit test**: it drives built
binaries, inspects the build tree, or asserts state that lives on the host
rather than in the tree.

The C unit tests stay where they are — `make check` in each capture directory
builds and runs `test_diag_*.c` / `test_*at*.c`. Nothing here replaces those.

## Why this is a directory of its own

The cell work lives in top-level directories that upstream Kismet does not
have (`capture_cell_at/`, `capture_cell_diag/`, `diagspec/`, and this one).
That is deliberate:

- **Merges from upstream never touch these paths**, so catching up costs nothing
  here.
- **The cell tooling stays self-contained.** Putting these files in upstream's
  `tools/` would mix upstream code and cell-specific code in one directory, and
  make it harder to see which is which.

## Running

```sh
make -C celltools check          # everything
python3 -m pytest celltools/tests -q
python3 -m pytest celltools/tests/test_kismet_host_preflight.py -q
```

**These tests depend on nothing outside this tree.** Standard library plus
`pytest`; no project virtualenv, no sibling checkout, no network. That is a
requirement, not a happy accident — a harness that needs an external checkout to
run is a harness that silently does not run for anyone who lacks one, and a
green suite then means "nobody measured this."

Correctness is pinned against inputs that ship in this tree: synthetic
captures built by `capture_cell_diag/fixtures/make_functional_fixture.py` and
the expectations committed beside them, or bytes pinned in the test itself.
There is no external reference decoder to fetch. A harness that cannot run on
this host (no built binary, no `make`, no modem attached) **skips with the
reason named in the skip message** — never fails, and never passes vacuously.

## What is here

| path | what it checks |
|---|---|
| `kismet-host-preflight.sh` | that this **host** is wired to *this* build tree: the `/usr/local/etc/kismet*.conf` symlinks, `kismet_site.conf`'s `helper_binary_path` entries, the data files, whether the `kismet` on `PATH` predates the tree, and a REST credential (there is no way to disable REST auth) |
| `tests/test_kismet_host_preflight.py` | the above, against a synthetic host built under `tmp_path` — it never reads or writes the real `/usr/local` |
| `cell_binaries.py` | **the foundation.** Finds the built capture binaries in this tree, names *which* silence a miss is (`no-tree` / `not-built` / `not-configured` / `not-configurable` / `build-failed` / `env-bad`), derives each binary's real link closure from the makefile, and answers "is this binary older than its own sources?" — once, so the probe and the test guard cannot drift into disagreeing |
| `check_binary_staleness.py` | the advisory staleness probe, for whatever advances this tree. Never builds, never fails its caller unless asked (`--check`) |
| `tests/celldiag_run.py` | the shared celldiag run harness: the discovered, staleness-checked binary, and one run of it over the datasource IPC |
| `tests/test_celldiag_replay_ab.py` | drives the compiled `kismet_cap_cell_diag` over the datasource IPC with replay files built in the tree, and checks what it relays |
| `tests/test_celldiag_native_only.py` | the decoder options that no longer exist are refused by name, and the census and GSMTAP tap give pinned answers on synthetic records |
| `tests/test_celldiag_standalone_native.py` | `standalone.mk check-native`: the helper built with no autoconf, decoding the tree's own capture into exactly the committed expectation |
| `tests/test_cellat_ipc.py` | drives `kismet_cap_cell_at` against a scripted AT responder on a pty — no modem, no server |
| `tests/test_cell_binaries.py` | the discovery + skip-reason contract: the statuses must stay mutually distinguishable, each actionable one must carry **its own** remedy, and the no-configure builds stay where discovery looks |
| `tests/test_celldiag_link_deps.py` | the makefile parser, against a synthetic tree: no build, no compiler |
| `tests/test_binary_staleness.py` | the staleness predicate and the probe CLI, same synthetic tree |
| `tests/test_celldiag_profile_target_codes.py` | `capture_cell_at/profiles/*.json` `diag.target_codes` vs `DIAG_TARGET_CODES` in `capture_cell_diag/diag_config.c` |
| `tests/kismet_capture_ipc.py`, `tests/fake_at_modem.py`, `tests/fake_diag_modem.py` | helpers: the v3 `kismet_external` framing + capture driver, and the pty AT and DIAG responders |

Discovery, link-dep derivation, staleness and the profile check are pure
introspection of this tree and run everywhere. The binary-driving harnesses
need the binaries built (`make -C capture_cell_diag -f standalone.mk` builds
the helper with no `./configure`), and name the command in their skip message
when one is missing.

### `kismet-host-preflight.sh`

Run it before any live Kismet gate:

```sh
celltools/kismet-host-preflight.sh          # report only; exit 1 on any FAIL
celltools/kismet-host-preflight.sh --fix    # create MISSING symlinks only
```

`--fix` is deliberately timid: it creates absent symlinks and nothing else. It
will not replace an existing regular file and will not run `make install`.
Clobbering host state and installing system-wide binaries are the operator's
call, so both cases print the exact command instead of running it.

`[2/5]` checks `helper_binary_path`, the directory holding the capture
**binaries**, which the *server* needs in order to exec the capture process.
The capture processes need nothing beyond themselves: a celldiag source decodes
in process.

Run it with the `PATH` you will run the gate with: `[4/5]` compares the
`kismet` and capture binaries found there against the build tree.

The `[3/5]` data-file group asserts the path the **consumer** opens, not merely
that a file of that name is somewhere on the host. Those are different
questions: a file in `KISMET_ETC` looks installed, but the server opens
`KISMET_SHARE` and logs
`Could not open ICAO database /usr/local/share/kismet/...`. Each entry carries
the name its consumer resolves under `KISMET_SHARE` — which differs from the
`conf/` name for the two bluetooth databases, whose built-in defaults omit
`.gz`. `kismet_uav.conf.yaml` is not checked: it is a build input compiled into
`kismet_uav.conf`, not a file the server reads.

`KISMET_ROOT` defaults to **the tree this script ships in**, not to a checkout
found by convention. A conventional default can resolve to a tree the operator
is not building, and a `PASS` would then mean "some tree is wired up" rather
than "this one is". `KISMET_ETC` / `KISMET_SHARE` / `KISMET_ROOT` / `KISMET_BIN`
all override,
which is how the tests point it at a synthetic host.
