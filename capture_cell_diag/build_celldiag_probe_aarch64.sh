#!/bin/sh
# build_celldiag_probe_aarch64.sh — cross-compile celldiag_probe for aarch64.
#
# WHY THIS EXISTS: celldiag_probe drives the modem's /dev/…_DIAG port. When the
# modem is a PCIe/MHI M.2 module inside another host — e.g. an RM520N-GL in an
# aarch64 OpenWrt router — an x86 celldiag_probe built by the normal Makefile
# cannot run ON the router, and a one-way `ssh cat /dev/mhi_DIAG` sets no LOG
# mask so the modem emits nothing.
#
# This produces a STATIC aarch64 binary (glibc, -static) that runs on the
# router's musl userland with no dynamic loader, does the bidirectional DIAG
# LOG_CONFIG handshake ON the router, and streams the modem's raw HDLC bytes
# to stdout. Capture a bounded window to a file over SSH, then decode it by
# replaying it through the capture helper:
#
#   ssh root@<router> '/root/celldiag_probe-aarch64 /dev/mhi_DIAG 4000000' \
#     > cap.hdlc                                    # bound with `timeout` too
#   ./celldiag_replay_ndjson ./kismet_cap_cell_diag \
#       celldiag-000000000000000:replay=<absolute path of cap.hdlc>
#
# Unlike a mask=max capture proxy, celldiag_probe applies only the targeted
# celldiag mask -- ~50x less capture volume on the router.
#
# The probe is self-contained (5 libc-only C files, no capture-framework /
# libwebsockets / Kismet link), so this needs no Linux sysroot beyond the
# cross toolchain's own.
#
# Requirements (Debian/Ubuntu build host):
#   apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
#
# Usage:
#   ./build_celldiag_probe_aarch64.sh              # -> ./celldiag_probe-aarch64
#   AARCH64_CC=aarch64-linux-musl-gcc ./build_…    # musl toolchain, if preferred
set -eu

CC="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
OUT="${OUT:-celldiag_probe-aarch64}"
# The exact object set the Makefile's PROBE_BIN links, as sources (a cross
# build cannot reuse the host .o files).
SRCS="celldiag_probe.c diag_hdlc.c diag_config.c diag_profile.c diag_capture.c"

cd "$(dirname "$0")"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "*** ERROR: cross compiler '$CC' not found." >&2
    echo "    apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu" >&2
    exit 1
fi

# -static: bundle glibc so the binary runs on the router's musl userland with
# no ld-linux-aarch64 loader.
# -I.. matches the Makefile's `CPPFLAGS += -I..`; -I. picks up the sibling headers.
"$CC" -static -O2 -Wall -I.. -I. -o "$OUT" $SRCS

# Hard-fail if the ABI is wrong — a host-arch binary here would silently fail to
# run on the router, which is exactly the failure mode this script prevents.
if ! file "$OUT" | grep -q 'ARM aarch64'; then
    echo "*** ERROR: $OUT is not an aarch64 ELF — wrong toolchain?" >&2
    file "$OUT" >&2
    exit 1
fi
if ! file "$OUT" | grep -q 'statically linked'; then
    echo "*** ERROR: $OUT is not statically linked — it will need a loader the" >&2
    echo "    musl router does not have." >&2
    file "$OUT" >&2
    exit 1
fi

echo "built: $OUT"
file "$OUT"
ls -lh "$OUT" | awk '{print "size: "$5}'
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$OUT"
fi
echo "verify: OK (aarch64 + static)"
