#!/bin/sh
# test_check_binary_symbols.sh -- self-test for the symbol-presence guard.
#
# A guard is only worth its runtime if it FAILS on the thing it exists to catch.
# The failures check_binary_symbols.sh exists to catch all produce green
# builds, so "the guard passed on the current tree" proves nothing on its own --
# a guard that expects nothing also passes. Every case below is therefore a
# NEGATIVE control except the first.
#
# Deliberately builds its own fixtures rather than leaning on the linked
# kismet/kismet_cap_cell_diag: those need the full Kismet object tree, and a test
# that silently skips when they are absent would be the same skip-by-default
# shape one level up.
#
# Usage: diagspec/test_check_binary_symbols.sh [repo-root]

set -e

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
GUARD="$ROOT/diagspec/check_binary_symbols.sh"
CC="${CC:-cc}"
CXX="${CXX:-c++}"

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

pass=0
fail=0

ok() { pass=$((pass + 1)); echo "  ok   -- $1"; }
no() { fail=$((fail + 1)); echo "  FAIL -- $1" >&2; }

# expect_pass <label> <args...>
expect_pass() {
    label="$1"; shift
    if sh "$GUARD" "$@" >"$TMPD/out" 2>&1; then ok "$label"
    else no "$label (guard exited nonzero)"; sed 's/^/         /' "$TMPD/out" >&2; fi
}

# expect_fail <label> <must-mention> <args...>
expect_fail() {
    label="$1"; want="$2"; shift 2
    if sh "$GUARD" "$@" >"$TMPD/out" 2>&1; then
        no "$label (guard PASSED; it must not)"
        sed 's/^/         /' "$TMPD/out" >&2
    elif grep -qF "$want" "$TMPD/out"; then
        ok "$label"
    else
        no "$label (failed, but not for the expected reason: wanted '$want')"
        sed 's/^/         /' "$TMPD/out" >&2
    fi
}

echo "test_check_binary_symbols: root=$ROOT"

# build_noleg <out> -- a binary with no decode surface and no legs at all.
build_noleg() {
    printf 'int main(void) { return 0; }\n' > "$TMPD/nolegmain.c"
    $CC $CFLAGS $CPPFLAGS -o "$1" "$TMPD/nolegmain.c" 2>"$TMPD/build-noleg.log"
}

# nodefs_cases <root> <no-leg binary> -- a tree with no diagspec/enrichment:
# the server role passes and says why, the helper role fails.
nodefs_cases() {
    expect_pass "no definitions: server passes" server "$2" "$1"
    if sh "$GUARD" server "$2" "$1" 2>&1 | grep -qF "no decode definitions in this tree"; then
        ok "no definitions: server says why it has no legs to check"
    else
        no "no definitions: server passed without naming the reason"
    fi
    expect_fail "no definitions: helper fails" "needs the decode definitions" helper "$2" "$1"
}

# A tree without the decode definitions can run only those cases: every other
# fixture is built from them.
if [ ! -d "$ROOT/diagspec/enrichment/cpp" ]; then
    echo "  (no decode definitions in this tree: running the no-definitions cases only)"
    if build_noleg "$TMPD/noleg"; then
        nodefs_cases "$ROOT" "$TMPD/noleg"
    else
        no "could not build the no-leg fixture"
        sed 's/^/         /' "$TMPD/build-noleg.log" >&2
    fi
    echo ""
    echo "test_check_binary_symbols: $pass passed, $fail failed"
    [ "$fail" -eq 0 ] || exit 1
    exit 0
fi

# --- fixture 1: the COMPLETE closure --------------------------------------
# Exactly the object set kismet_cap_cell_diag links: the extern "C" shim plus
# every leg it #includes. This is the positive control.
DIAGSPEC_INC="-I$ROOT/diagspec/generated/cpp -I$ROOT/diagspec/enrichment/cpp -I$ROOT"
# Every shim #include that resolves into enrichment/cpp is a leg -- the same
# rule check_binary_symbols.sh derives its expected set from (so a leg not
# named diag_0x*, such as lte_meas_join, is still covered by both).
SRCS=""
for s in $(sed -n 's/^#include[ \t]*"\([A-Za-z0-9_]*\)\.h".*/\1/p' \
        "$ROOT/capture_cell_diag/diag_native_decode.cpp"); do
    [ -f "$ROOT/diagspec/enrichment/cpp/$s.h" ] && SRCS="$SRCS $s"
done

FULL_SRCS="$ROOT/capture_cell_diag/diag_native_decode.cpp $ROOT/kaitaistream.cc"
for s in $SRCS; do
    # diag_0xb192_observation -> diag_0xb192, the generated Kaitai parser it calls.
    # (A non-diag_0x leg maps to itself and has no generated parser; its own
    # dependencies arrive through the transitive walk below.)
    code=$(printf '%s\n' "$s" | sed 's/^\(diag_0x[0-9a-fA-F]*\).*/\1/')
    FULL_SRCS="$FULL_SRCS $ROOT/diagspec/enrichment/cpp/$s.cpp"
    # Two legs of one code (0xB0C0's observation + gsmtap, 0xB821's identity +
    # observation) share one generated parser: list it once, or the link fails
    # on duplicate definitions before the guard can check anything.
    gen="$ROOT/diagspec/generated/cpp/$code.cpp"
    case " $FULL_SRCS " in *" $gen "*) continue ;; esac
    if [ -f "$gen" ]; then
        FULL_SRCS="$FULL_SRCS $gen"
    fi
done
# A leg's own dependencies (0xB0C0 -> the SIB1/ASN.1 closure; 0xB821 -> the NR
# SIB1 closure) are pulled in by walking each source's #includes TRANSITIVELY.
#
# Do not replace this with a hand-typed dependency list. A new LEG is picked up
# automatically by the sed above, but a hand-typed list would miss a new leg's
# new DEPENDENCY (e.g. diag_0xb821_identity needs diag_0xb821_enrich and
# nr_rrc_sib): the positive-control fixture would stop linking and the script
# would exit BEFORE the absence check it exists to run. A guard whose own
# fixture cannot build is not a guard. Derived, so a new leg needs no edit here.
closure_pending="$SRCS"
closure_seen=""
while [ -n "$closure_pending" ]; do
    next=""
    for stem in $closure_pending; do
        case " $closure_seen " in *" $stem "*) continue ;; esac
        closure_seen="$closure_seen $stem"
        for dir in enrichment generated; do
            hdr="$ROOT/diagspec/$dir/cpp/$stem.h"
            [ -f "$hdr" ] || continue
            next="$next $(sed -n 's/^#include[ \t]*"\([A-Za-z0-9_]*\)\.h".*/\1/p' "$hdr")"
            src="$ROOT/diagspec/$dir/cpp/$stem.cpp"
            [ -f "$src" ] || continue
            next="$next $(sed -n 's/^#include[ \t]*"\([A-Za-z0-9_]*\)\.h".*/\1/p' "$src")"
        done
    done
    closure_pending="$next"
done
for stem in $closure_seen; do
    for dir in enrichment generated; do
        src="$ROOT/diagspec/$dir/cpp/$stem.cpp"
        [ -f "$src" ] || continue
        case " $FULL_SRCS " in *" $src "*) continue ;; esac
        FULL_SRCS="$FULL_SRCS $src"
    done
done

cat > "$TMPD/main.cpp" <<'EOF'
int main() { return 0; }
EOF

# -DKS_STR_ENCODING_NONE is what the real build passes (Makefile.inc); the
# vendored kaitaistream.cc #errors without one of the KS_STR_ENCODING_* choices.
# Set here rather than inherited so this test runs standalone, not only under make.
echo "  ... building the complete-closure fixture"
$CXX $CXXFLAGS $CPPFLAGS -DKS_STR_ENCODING_NONE $DIAGSPEC_INC -o "$TMPD/full" \
    $FULL_SRCS "$TMPD/main.cpp" 2>"$TMPD/build.log" || {
        echo "  FAIL -- could not build the complete-closure fixture" >&2
        sed 's/^/         /' "$TMPD/build.log" >&2
        exit 1
    }

expect_pass "complete closure passes the helper check" helper "$TMPD/full" "$ROOT"

# --- fixture 2: the shim WITHOUT the legs ---------------------------------
# The MONITOR_OBJS-omission shape: the extern "C" entry points are present and the
# process still cannot decode anything. Presence of the shim must not satisfy the
# guard on its own.
cat > "$TMPD/stub.c" <<'EOF'
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
int diag_native_decode(uint16_t c, const uint8_t *p, size_t l, void *o, size_t m) {
    (void)c; (void)p; (void)l; (void)o; (void)m; return -1;
}
bool diag_native_has_leg(uint16_t c) { (void)c; return false; }
size_t diag_native_codes(uint16_t *o, size_t m) { (void)o; (void)m; return 0; }
int main(void) { return 0; }
EOF
$CC $CFLAGS $CPPFLAGS -o "$TMPD/stub" "$TMPD/stub.c"
expect_fail "shim present but legs absent is caught" "MISSING decode legs" \
    helper "$TMPD/stub" "$ROOT"

# --- fixture 3: absent binary FAILS, does not skip -------------------------
expect_fail "absent binary fails (does not skip)" "does not exist" \
    helper "$TMPD/nonexistent" "$ROOT"

# --- fixture 4: stale binary FAILS ----------------------------------------
cp "$TMPD/full" "$TMPD/stale"
touch -t 199001010000 "$TMPD/stale"
expect_fail "stale binary fails" "STALE" helper "$TMPD/stale" "$ROOT"

# --- fixture 5: an EMPTY derived set is itself a failure -------------------
# A source-derived guard pointed at a tree with no legs asserts NOTHING, in
# either direction: under presence it passes against a binary containing none,
# under absence against a binary containing all of them. Both are the guard's own
# version of "nothing complained."
mkdir -p "$TMPD/emptyroot/diagspec/enrichment/cpp"
expect_fail "empty derived set fails" "EMPTY decode-leg symbol set" \
    server "$TMPD/full" "$TMPD/emptyroot"

# --- fixture 6: the server role PASSES on a binary with no legs ------------
# This role asserts absence: the server never receives a raw DIAG payload, so a
# leg linked into `kismet` is unreachable by construction and must NOT be there.
# The stub -- extern "C" surface, zero legs -- is the shape the server is
# supposed to have, so what fixture 2 rejects for the helper is exactly what the
# server requires. Same binary, opposite verdicts: that is the polarity split.
expect_pass "server role passes a binary with no legs" server "$TMPD/stub" "$ROOT"

# --- fixture 7: the server role CATCHES a re-linked leg, under both names --
# The regression this exists to stop: someone puts an object back into
# DIAGSPEC_O. Build the full server-side leg set -- every .cpp behind the
# three server-side header suffixes -- and require the guard to fire and to name
# BOTH conventions. The server set spans diag_0xbNNN_observation::observations()
# and diagspec::celldiag::diag_0xbNNN_to_gsmtap(); a header parser that handled
# only one would silently let the other class back in.
SERVER_SRCS="$ROOT/kaitaistream.cc"
for h in "$ROOT"/diagspec/enrichment/cpp/diag_0x*_observation.h \
         "$ROOT"/diagspec/enrichment/cpp/diag_0x*_gsmtap.h \
         "$ROOT"/diagspec/enrichment/cpp/diag_0x*_exported_pdu.h; do
    [ -f "$h" ] || continue
    stem=$(basename "$h" .h)
    code=$(printf '%s\n' "$stem" | sed 's/^\(diag_0x[0-9a-fA-F]*\).*/\1/')
    SERVER_SRCS="$SERVER_SRCS $ROOT/diagspec/enrichment/cpp/$stem.cpp"
    [ -f "$ROOT/diagspec/generated/cpp/$code.cpp" ] &&
        SERVER_SRCS="$SERVER_SRCS $ROOT/diagspec/generated/cpp/$code.cpp"
done
# The shared sinks + ASN.1 closure the legs above call into. A new leg whose
# decoder is not yet here makes this fixture fail to LINK, which names the
# missing unit (nr5g_rrc_meas_report: the 0xB821 observation leg;
# lte_nas_structure: the LTE NAS GSMTAP bridges' TS 24.301 check).
for extra in gsmtap exported_pdu diag_0xb0c0_enrich diag_0xb821_enrich \
             lte_rrc_sib asn1_helpers uper nr5g_rrc_meas_report \
             lte_nas_structure; do
    [ -f "$ROOT/diagspec/enrichment/cpp/$extra.cpp" ] &&
        SERVER_SRCS="$SERVER_SRCS $ROOT/diagspec/enrichment/cpp/$extra.cpp"
done
# Deduplicate -- 0xB0C0 owns both an _observation and a _gsmtap header, so its
# generated parser is named twice and would otherwise be a duplicate-symbol link
# error rather than the fixture we want.
SERVER_SRCS=$(printf '%s\n' $SERVER_SRCS | sort -u | tr '\n' ' ')

if $CXX $CXXFLAGS $CPPFLAGS -DKS_STR_ENCODING_NONE $DIAGSPEC_INC \
        -o "$TMPD/serverfull" $SERVER_SRCS "$TMPD/main.cpp" 2>"$TMPD/build3.log"; then
    if sh "$GUARD" server "$TMPD/serverfull" "$ROOT" >"$TMPD/out" 2>&1; then
        no "re-linked server legs are caught (guard PASSED; it must not)"
    elif grep -q "_observation::observations" "$TMPD/out" && \
         grep -q "diagspec::celldiag::" "$TMPD/out"; then
        ok "server role catches re-linked legs under BOTH naming conventions"
    else
        no "server role missed one of the two naming conventions"
        sed 's/^/         /' "$TMPD/out" >&2
    fi
else
    no "could not build the server-legs fixture"
    sed 's/^/         /' "$TMPD/build3.log" >&2
fi

# --- fixture 8: the GNSS leg does NOT trip the server absence check --------
# The 0x1476 GNSS leg is helper-only, and it stays out of the
# server set BY NAMING: diag_0x1476_gpsfix.h matches none of the three
# server-side suffixes. So a binary carrying ONLY that leg must pass the server
# role. If the glob ever widened to "every leg header", this fixture fails and
# the exclusion has to become deliberate rather than incidental.
GNSS_SRCS="$ROOT/kaitaistream.cc $ROOT/diagspec/enrichment/cpp/diag_0x1476_gpsfix.cpp"
[ -f "$ROOT/diagspec/generated/cpp/diag_0x1476.cpp" ] &&
    GNSS_SRCS="$GNSS_SRCS $ROOT/diagspec/generated/cpp/diag_0x1476.cpp"
if $CXX $CXXFLAGS $CPPFLAGS -DKS_STR_ENCODING_NONE $DIAGSPEC_INC \
        -o "$TMPD/gnssonly" $GNSS_SRCS "$TMPD/main.cpp" 2>"$TMPD/build4.log"; then
    if nm -C -g --defined-only "$TMPD/gnssonly" 2>/dev/null | grep -q 'diag_0x1476_gpsfix'; then
        expect_pass "helper-only GNSS leg does not trip the server check" \
            server "$TMPD/gnssonly" "$ROOT"
    else
        no "fixture precondition: gnssonly does not define the 0x1476 GNSS leg"
    fi
else
    no "could not build the GNSS-only fixture"
    sed 's/^/         /' "$TMPD/build4.log" >&2
fi

# --- fixture 9: ONE leg removed from the link, the rest intact -------------
# The key negative control, and the closest reproduction of a leg that is
# compiled and correct but whose object is simply not in the link list: the
# build stays green because NOTHING CALLS IT. So this fixture links the whole
# closure with a single leg's objects dropped and the shim replaced by the
# stub -- no caller, hence no linker error.
# The guard must fire, and must name that leg and ONLY that leg: an "everything
# is missing" result would pass this assertion for the wrong reason.
DROP="diag_0xb97f_observation"
ONE_OUT=""
for f in $FULL_SRCS; do
    case "$f" in
        */$DROP.cpp|*/diag_native_decode.cpp) ;;
        *) ONE_OUT="$ONE_OUT $f" ;;
    esac
done
if $CXX $CXXFLAGS $CPPFLAGS -DKS_STR_ENCODING_NONE $DIAGSPEC_INC -o "$TMPD/oneout" \
        $ONE_OUT "$TMPD/stub.c" 2>"$TMPD/build2.log"; then
    if sh "$GUARD" helper "$TMPD/oneout" "$ROOT" >"$TMPD/out" 2>&1; then
        no "one dropped leg is caught (guard PASSED; it must not)"
    else
        got=$(sed -n 's/^    \([A-Za-z_].*\)$/\1/p' "$TMPD/out" | grep '::' || true)
        # A leg exports more than observations() (is_refusal() too),
        # so "only that leg" means: every reported symbol is in ${DROP}::, and
        # its observations() is among them.
        others=$(printf '%s\n' $got | grep -v "^${DROP}::" || true)
        if printf '%s\n' $got | grep -qx "${DROP}::observations" && [ -z "$others" ]; then
            ok "one dropped leg is caught, and only that leg is reported"
        else
            no "one dropped leg: expected only ${DROP}:: symbols incl. observations, got: $(echo $got)"
        fi
    fi
else
    no "could not build the one-leg-short fixture"
    sed 's/^/         /' "$TMPD/build2.log" >&2
fi

# --- fixture 9: a tree with NO decode definitions -------------------------
# The shim ships; diagspec/enrichment does not.  Distinct from fixture
# 5, where the directory exists and is empty -- that is a broken tree.
mkdir -p "$TMPD/nodefs/capture_cell_diag" "$TMPD/nodefs/diagspec"
cp -p "$ROOT/capture_cell_diag/diag_native_decode.cpp" \
   "$ROOT/capture_cell_diag/diag_native_decode.h" "$TMPD/nodefs/capture_cell_diag/"
if build_noleg "$TMPD/nodefs-noleg"; then
    nodefs_cases "$TMPD/nodefs" "$TMPD/nodefs-noleg"
else
    no "could not build the no-definitions no-leg fixture"
    sed 's/^/         /' "$TMPD/build-noleg.log" >&2
fi

echo ""
echo "test_check_binary_symbols: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
exit 0
