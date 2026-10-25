#!/usr/bin/env bash
# kismet-host-preflight.sh -- assert the HOST state a live Kismet gate needs,
# before the gate fails with a one-line error that names none of it.
#
# Why this exists
# ---------------
# Live gates for the cell sources start with `kismet -c cellat-… -c celldiag-…`.
# That command depends on state that lives on the MACHINE and nowhere in git:
#
#   * nine `/usr/local/etc/kismet*.conf` files resolving to the build tree
#   * `kismet_site.conf`, carrying the four `helper_binary_path` entries that
#     tell the server where the freshly-built capture helpers are
#   * four data files (`kismet_manuf.txt.gz`, …) under `/usr/local/share/kismet`
#   * a `kismet` on PATH that is not older than the build tree
#   * a REST credential, because there is no way to turn REST auth OFF
#
# `helper_binary_path` is the dir holding the capture BINARIES: the SERVER
# needs it, to exec the capture process ([2/5]). The capture processes need
# nothing beyond themselves: celldiag decodes in process.
#
# With the config symlinks missing, every gate dies on:
#
#   ERROR: Error reading config file '/usr/local/etc/kismet.conf': No such file
#
# `--confdir <path>` does NOT work around that: the initial system config read
# resolves `/usr/local/etc/kismet.conf` and errors before the flag applies.
#
# That loud failure is the friendly one. This script exists mostly for the
# quiet ones:
#
#   * a config file that is a **copy** rather than a symlink still starts the
#     server, and then silently diverges from `conf/` forever;
#   * a `kismet` on PATH from an old `make install` starts fine and runs a
#     binary predating every decode leg landed since, with no test to notice;
#   * a data file present on the host but in a directory no consumer reads.
#     The check therefore asserts the path the CONSUMER opens (see DATA_FILES),
#     not merely that a file of that name exists somewhere;
#   * a host with no REST credential. `httpd_auth_order=never` looks like a
#     bypass but is not a directive in this code base, so REST gates pass only
#     where a `~/.kismet/kismet_httpd.conf` happens to exist, and a fresh host
#     gets the interactive first-run login instead. Checked in [5/5];
#   * an ABSENT `kismet_site.conf`, so the `helper_binary_path` lines are not
#     in effect and the server finds the stale installed helpers.
#
# Usage
# -----
#   celltools/kismet-host-preflight.sh          # report only; exit 1 on any FAIL
#   celltools/kismet-host-preflight.sh --fix    # create MISSING symlinks only
#
# `--fix` is deliberately timid. It creates symlinks that are absent and
# nothing else. It will NOT replace an existing regular file with a symlink and
# it will NOT run `make install`: clobbering host state or installing
# system-wide binaries is the operator's call, not a side effect of a
# preflight check. Both cases report the exact command to run instead.
#
# Environment overrides (used by the tests; defaults are the real host layout):
#   KISMET_ETC   config dir                     (default /usr/local/etc)
#   KISMET_SHARE data dir                       (default /usr/local/share/kismet)
#   KISMET_ROOT  tree to check against          (default: this script's own tree)
#   KISMET_BIN   server binary to check on PATH (default `command -v kismet`)
#
# KISMET_ROOT defaults to this script's own tree, not to a checkout found by
# convention. The check is about whether the host is wired to the build tree
# this script ships in; a default that searched elsewhere could report PASS for a
# tree the operator is not building. The override stays for the tests, which
# point it at a synthetic host under tmp_path.
set -uo pipefail

KISMET_ETC="${KISMET_ETC:-/usr/local/etc}"
KISMET_SHARE="${KISMET_SHARE:-/usr/local/share/kismet}"
KISMET_ROOT="${KISMET_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
KISMET_CONF="$KISMET_ROOT/conf"

FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

fails=0
warns=0

ok()   { printf '  OK    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }
warn() { printf '  WARN  %s\n' "$*"; warns=$((warns + 1)); }

# The config files a `make install` links or copies into $KISMET_ETC.
CONF_FILES=(
  kismet.conf kismet_httpd.conf kismet_memory.conf kismet_alerts.conf
  kismet_80211.conf kismet_logging.conf kismet_filter.conf kismet_uav.conf
  kismet_wardrive.conf
)
# kismet_site.conf is listed separately: it is the one file with HOST-LOCAL
# content (helper_binary_path, bind addresses), so its absence is a different
# finding from a missing generic conf, and its content is checked below.
# Data files, each paired with the path the SERVER actually opens. Checking
# only "is a file with this name somewhere on the host" would accept a file in
# $KISMET_ETC and report OK while the server logs "Could not open ICAO database
# /usr/local/share/kismet/...". Every
# consumer below resolves %S/kismet/ (== $KISMET_SHARE) and none of them ever
# looks in $KISMET_ETC, so the served name is what the check has to assert.
#
# Format: <name in conf/>|<name under $KISMET_SHARE>|<consumer that reads it>
#
# ⚠️ Two of these differ from the conf/ name: the bluetooth defaults in
# bluetooth_ids.cc are spelled WITHOUT .gz. That is not a typo to correct here
# -- the consumer opens them with gzopen(), which reads gzip content regardless
# of extension, so a link named .txt pointing at conf/'s .txt.gz resolves and
# decompresses correctly. Naming them .txt.gz under share/ does not.
#
# ⚠️ kismet_uav.conf.yaml is deliberately NOT in this group. It is a BUILD
# input -- a build step compiles it into conf/kismet_uav.conf,
# which is what ships as a config symlink in [1/5]. No runtime code path opens
# the .yaml, so a host check on it can only ever produce a meaningless OK.
DATA_FILES=(
  "kismet_manuf.txt.gz|kismet_manuf.txt.gz|kismet.conf ouifile"
  "kismet_adsb_icao.txt.gz|kismet_adsb_icao.txt.gz|kismet.conf icaofile"
  "kismet_bluetooth_ids.txt.gz|kismet_bluetooth_ids.txt|bluetooth_ids.cc btoidfile default"
  "kismet_bluetooth_manuf.txt.gz|kismet_bluetooth_manuf.txt|bluetooth_ids.cc btmanuffile default"
)
# The helper dirs kismet_site.conf must put on the search path. Without these
# the server falls back to the installed helpers in /usr/local/bin, which is the
# quiet-staleness failure this script exists to catch.
HELPER_DIRS=(
  "$KISMET_ROOT/capture_cell_at"
  "$KISMET_ROOT/capture_cell_diag"
  "$KISMET_ROOT/capture_sdr_rtl433_v2"
  "$KISMET_ROOT/capture_linux_wifi"
)

echo "kismet host preflight"
echo "  etc=$KISMET_ETC  share=$KISMET_SHARE  root=$KISMET_ROOT"
echo

if [ ! -d "$KISMET_CONF" ]; then
  fail "conf dir absent: $KISMET_CONF (wrong KISMET_ROOT, or an incomplete tree)"
  echo
  echo "FAIL: $fails problem(s)."
  exit 1
fi

# ---------------------------------------------------------------- link checks
# One routine for all three groups. Distinguishes four states, because they need
# four different remedies:
#   absent          -> --fix can create it
#   symlink -> tree -> OK
#   symlink -> else -> points at the wrong tree; operator decides
#   regular file    -> a copy; starts fine, drifts silently. NOT auto-replaced.
check_link() {
  local dir="$1" name="$2" src="$3"
  local dst="$dir/$name"

  if [ ! -e "$src" ]; then
    warn "$name: source missing from this tree ($src) — not a host problem"
    return
  fi

  if [ -L "$dst" ]; then
    local target
    target="$(readlink -f "$dst" 2>/dev/null || true)"
    if [ "$target" = "$(readlink -f "$src")" ]; then
      ok "$name -> tree"
    else
      fail "$name is a symlink to '$target', not '$src'"
    fi
    return
  fi

  if [ -f "$dst" ]; then
    if cmp -s "$dst" "$src"; then
      warn "$name is a COPY, not a symlink (identical today — will drift silently)"
    else
      fail "$name is a COPY and ALREADY DIFFERS from $src"
    fi
    printf '        to convert: rm %s && ln -s %s %s\n' "$dst" "$src" "$dst"
    return
  fi

  if [ "$FIX" = 1 ]; then
    if mkdir -p "$dir" && ln -s "$src" "$dst"; then
      ok "$name -> tree (created)"
    else
      fail "$name absent and could not be created at $dst"
    fi
  else
    fail "$name absent from $dir"
  fi
}

echo "[1/5] config symlinks ($KISMET_ETC)"
for f in "${CONF_FILES[@]}"; do check_link "$KISMET_ETC" "$f" "$KISMET_CONF/$f"; done
echo

echo "[2/5] kismet_site.conf + helper_binary_path (the SERVER's helper: capture binaries)"
check_link "$KISMET_ETC" kismet_site.conf "$KISMET_CONF/kismet_site.conf"
# Read the file the SERVER will read, following the link — checking this tree's own
# copy would pass while the host resolved something else entirely.
site="$KISMET_ETC/kismet_site.conf"
if [ -r "$site" ]; then
  for d in "${HELPER_DIRS[@]}"; do
    if grep -qxF "helper_binary_path=$d" "$site"; then
      ok "helper_binary_path=$(basename "$d")"
    else
      # A restored older kismet_site.conf can lack an entry (typically
      # capture_cell_diag), leaving those sources unable to find their helper.
      fail "helper_binary_path missing for $d"
    fi
  done
else
  fail "kismet_site.conf unreadable at $site — helper_binary_path unverifiable"
fi
echo

echo "[3/5] data files ($KISMET_SHARE)"
for entry in "${DATA_FILES[@]}"; do
  IFS='|' read -r src_name served_name consumer <<<"$entry"
  if [ -e "$KISMET_SHARE/$served_name" ]; then
    ok "$served_name present"
    continue
  fi

  # Diagnosis first, remedy second -- they are separate findings. A file in
  # $KISMET_ETC is on the host, so it looks installed, but $consumer never
  # looks there. Say so, then let check_link report/repair the real location.
  if [ -e "$KISMET_ETC/$src_name" ]; then
    warn "$src_name is in $KISMET_ETC, which $consumer does not read"
  fi

  if [ -e "$KISMET_CONF/$src_name" ]; then
    check_link "$KISMET_SHARE" "$served_name" "$KISMET_CONF/$src_name"
  else
    warn "$src_name: not under $KISMET_SHARE and not in conf/ — nothing to link"
  fi
done
echo

# ------------------------------------------------------------ staleness check
# The quiet one. A stale binary on PATH starts, runs, reports running=1 err=0,
# and decodes with legs that no longer match the tree. Never auto-fixed: a
# `make install` is a system-wide mutation and the operator's call.
echo "[4/5] binary freshness (PATH vs build tree)"
check_fresh() {
  local label="$1" built="$2" installed="$3"
  if [ ! -x "$built" ]; then
    warn "$label: no build-tree binary at $built — nothing to compare"
    return
  fi
  if [ -z "$installed" ] || [ ! -x "$installed" ]; then
    ok "$label: nothing on PATH — the build tree is the only copy"
    return
  fi
  if [ "$(readlink -f "$installed")" = "$(readlink -f "$built")" ]; then
    ok "$label: PATH resolves to the build tree"
  elif [ "$installed" -nt "$built" ] || [ ! "$built" -nt "$installed" ]; then
    ok "$label: installed copy is not older than the build tree"
  else
    fail "$label: PATH copy is STALE
        on PATH: $installed ($(date -r "$installed" '+%Y-%m-%d %H:%M' 2>/dev/null))
        built:   $built ($(date -r "$built" '+%Y-%m-%d %H:%M' 2>/dev/null))
        A gate run as '$label' would use the OLD binary and say nothing.
        Fix with an explicit path, or re-install: make -C $KISMET_ROOT install"
  fi
}
check_fresh kismet "$KISMET_ROOT/kismet" "${KISMET_BIN:-$(command -v kismet || true)}"
for h in kismet_cap_cell_at kismet_cap_cell_diag; do
  sub=capture_cell_at
  [ "$h" = kismet_cap_cell_diag ] && sub=capture_cell_diag
  check_fresh "$h" "$KISMET_ROOT/$sub/$h" "$(command -v "$h" || true)"
done

echo

# ----------------------------------------------------------- REST credential
# The undeclared prerequisite. Automated gates read the REST API to assert
# source health and cell counts, and REST is authenticated unconditionally:
# there is NO directive in this code base that turns it off.
# `httpd_auth_order=never` looks like one, but kis_net_beast_httpd.cc never
# fetches that key, so it is inert and every request still returns 401. A gate
# that passes does so only because an auth file happens to exist on that host.
# On a fresh host the same gate gets the interactive first-run login instead,
# and a 401 reads as "server down".
#
# So the check is for a CREDENTIAL, in the two places the server looks:
#
#   1. httpd_username + httpd_password in a GLOBAL conf. Wins outright — the
#      server raises GLOBALHTTPDUSER and ignores the auth file entirely.
#   2. the httpd_auth_file, default %h/.kismet/kismet_httpd.conf, which is what
#      the web UI's first-run login writes.
#
# A HALF credential is worse than none and is checked separately: a global
# username without a password (or vice versa) is _MSG_FATAL + fatal_condition
# at startup, so the server does not come up at all. In the auth FILE the same
# half-configuration is not fatal — it logs "Found a partial configuration" and
# resets BOTH to empty, i.e. it degrades to the first-run prompt.
#
# The constructor and set_admin_login() both default httpd_auth_file to
# "%h/.kismet/kismet_httpd.conf". The two must stay identical, or a credential
# set through the first-run login is written to one path and read from another.
#
# The ABSENT-directive check below is still a FAIL: the directive can be
# present and pointed somewhere UNREADABLE, and an explicit directive makes the
# resolved path visible to an operator instead of implied by a default two call
# sites deep.
echo "[5/5] REST credential (scripted gates authenticate; there is no bypass)"

# An inert bypass is not breakage, but it makes gates look unauthenticated, so
# it gets named wherever it appears.
if [ -r "$site" ] && grep -qE '^[[:space:]]*httpd_auth_order=' "$site"; then
  warn "kismet_site.conf sets httpd_auth_order — an INERT key
        No code path fetches it. It does not disable REST auth and never did;
        it only makes an authenticated server look like an open one."
fi

cred_ok=0
site_user=''
site_pass=''
if [ -r "$site" ]; then
  site_user=$(sed -n 's/^[[:space:]]*httpd_username=//p' "$site" | tail -1)
  site_pass=$(sed -n 's/^[[:space:]]*httpd_password=//p' "$site" | tail -1)
fi

if [ -n "$site_user" ] && [ -n "$site_pass" ]; then
  ok "global httpd_username/httpd_password in kismet_site.conf (auth file ignored)"
  cred_ok=1
elif [ -n "$site_user" ] || [ -n "$site_pass" ]; then
  # Not a degraded credential -- a server that refuses to start.
  fail "kismet_site.conf has httpd_$([ -n "$site_user" ] && echo username || echo password) but not httpd_$([ -n "$site_user" ] && echo password || echo username)
        The server treats a half global login as FATAL and exits at startup.
        Set both, or remove both and use the httpd_auth_file instead."
fi

if [ "$cred_ok" -eq 0 ]; then
  # Resolve the auth file the way the server does: the directive from the conf
  # the server reads (kismet.conf includes kismet_httpd.conf), %h -> $HOME.
  auth_decl=$(sed -n 's/^[[:space:]]*httpd_auth_file=//p' "$KISMET_ETC/kismet_httpd.conf" 2>/dev/null | tail -1)
  if [ -z "$auth_decl" ]; then
    fail "no httpd_auth_file= in $KISMET_ETC/kismet_httpd.conf
        The built-in defaults agree (%h/.kismet/kismet_httpd.conf on both the
        read and write paths), so this is not a broken-default finding. It is
        still a FAIL: the explicit
        directive is what makes the resolved credential path visible to an
        operator rather than implied by a default two call sites deep. Restore
        the explicit directive."
  else
    auth_file="${auth_decl//%h/$HOME}"
    if [ ! -r "$auth_file" ]; then
      fail "no REST credential: $auth_file absent and no global login
        Every scripted REST gate will get 401, or the interactive first-run
        login on a fresh host. Neither is a state a gate may depend on.
        Fix: start kismet once and set the login at http://localhost:2501/,
        or copy the credential file from a host that has one."
    else
      f_user=$(sed -n 's/^[[:space:]]*httpd_username=//p' "$auth_file" | tail -1)
      f_pass=$(sed -n 's/^[[:space:]]*httpd_password=//p' "$auth_file" | tail -1)
      if [ -n "$f_user" ] && [ -n "$f_pass" ]; then
        ok "auth file credential present ($auth_file, user=$f_user)"
        cred_ok=1
      else
        # The server logs "Found a partial configuration ... resetting" and
        # falls through to the first-run prompt -- present but unusable.
        fail "$auth_file is a PARTIAL credential (missing httpd_$([ -n "$f_user" ] && echo password || echo username))
        The server resets both to empty and asks for a first-run login, so the
        file existing is not the same as a gate being able to authenticate."
      fi
    fi
  fi
fi
echo

if [ "$fails" -gt 0 ]; then
  echo "FAIL: $fails problem(s), $warns warning(s). Live Kismet gates are not safe to run."
  exit 1
fi
echo "PASS: 0 problems, $warns warning(s)."
exit 0
