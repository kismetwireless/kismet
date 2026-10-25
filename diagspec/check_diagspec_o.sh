#!/bin/sh
# check_diagspec_o.sh -- guard against a stale generated Makefile silently
# omitting DIAGSPEC_O objects from the kismet link.
#
# Background: `make kismet` reads the *generated* Makefile.  If that Makefile is
# stale, the link uses whatever DIAGSPEC_O it happens to carry: decode legs can
# be compiled and self-tested yet absent from the kismet binary, and the build
# still SUCCEEDS, so nothing flags it.
#
# The `Makefile: Makefile.in configure` rule regenerates Makefile via
# config.status.  This script is the cheap backstop: it also catches a hand-edited generated Makefile, a partially
# applied config.status run, or any other drift between the two files.
#
# Usage: diagspec/check_diagspec_o.sh [Makefile.in] [Makefile]
# Exit 0 if the DIAGSPEC_O object lists match (or the check is not applicable),
# exit 1 with a diff if they drift.

set -e

IN="${1:-Makefile.in}"
GEN="${2:-Makefile}"

# Not applicable outside a configured build tree -- stay silent, succeed.
if [ ! -f "$IN" ] || [ ! -f "$GEN" ]; then
    exit 0
fi

# Extract the object list from a `DIAGSPEC_O = \` ... continuation block.
# Emits one object path per line, sorted, so the comparison is order-insensitive.
extract() {
    awk '
        /^DIAGSPEC_O[ \t]*=/ { inblock = 1; sub(/^[^=]*=[ \t]*/, ""); }
        inblock {
            line = $0
            cont = (line ~ /\\[ \t]*$/)
            sub(/\\[ \t]*$/, "", line)
            gsub(/[ \t]+/, "\n", line)
            printf "%s\n", line
            if (!cont) exit
        }
    ' "$1" | grep -v '^[[:space:]]*$' | sort
}

IN_OBJS=$(extract "$IN")
GEN_OBJS=$(extract "$GEN")

if [ "$IN_OBJS" = "$GEN_OBJS" ]; then
    exit 0
fi

echo "*** ERROR: DIAGSPEC_O drift between $IN and $GEN ***" >&2
echo "" >&2
echo "The generated Makefile -- the one that actually links kismet -- does not" >&2
echo "list the same diagspec objects as $IN.  Linking now would silently omit" >&2
echo "(or wrongly include) decode legs.  Re-run ./configure, then make." >&2
echo "" >&2
# dash has no process substitution -- use temp files so this stays POSIX sh.
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
printf '%s\n' "$IN_OBJS" > "$TMPD/in"
printf '%s\n' "$GEN_OBJS" > "$TMPD/gen"

echo "  only in $IN (would be MISSING from the binary):" >&2
comm -23 "$TMPD/in" "$TMPD/gen" | sed 's/^/    /' >&2
echo "  only in $GEN (stale entries):" >&2
comm -13 "$TMPD/in" "$TMPD/gen" | sed 's/^/    /' >&2
exit 1
