# `celltools/` — host checks for the cell capture sources

Diagnostic tooling for `capture_cell_at/`, `capture_cell_diag/`, and
`diagspec/` that inspects the build tree or the host rather than the code.

The C unit tests are the `test_diag_*.c` / `test_*at*.c` files in each capture
directory, built when Kismet is configured with `--enable-cell-selftest`.

## What is here

| path | what it checks |
|---|---|
| `kismet-host-preflight.sh` | that this **host** is wired to *this* build tree: the `/usr/local/etc/kismet*.conf` symlinks, `kismet_site.conf`'s `helper_binary_path` entries, the data files, whether the `kismet` on `PATH` predates the tree, and a REST credential (there is no way to disable REST auth) |
| `cell_binaries.py` | finds the built capture binaries in this tree, says why one is missing (`no-tree` / `not-built` / `not-configured` / `not-configurable` / `build-failed` / `env-bad`), derives each binary's link closure from the makefile, and answers "is this binary older than its own sources?" |
| `check_binary_staleness.py` | the advisory staleness probe, for whatever advances this tree. Never builds, never fails its caller unless asked (`--check`) |

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
the name its consumer resolves under `KISMET_SHARE` (the installed `.gz` name
for the compressed databases). `kismet_uav.conf.yaml` is not checked: it is a build input compiled into
`kismet_uav.conf`, not a file the server reads.

`KISMET_ROOT` defaults to **the tree this script ships in**, not to a checkout
found by convention. A conventional default can resolve to a tree the operator
is not building, and a `PASS` would then mean "some tree is wired up" rather
than "this one is". `KISMET_ETC` / `KISMET_SHARE` / `KISMET_ROOT` / `KISMET_BIN`
all override.
