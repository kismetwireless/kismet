#!/bin/sh
# Builds mac80211_hwsim.ko for a kernel built without it but with cfg80211 and
# mac80211 as modules, such as Ubuntu's Azure kernels from 6.17 (CONFIG_WLAN is
# off), from the kernel.org source of the same version.
#
# From https://github.com/rfhs/rfctf-container
# (infrastructure_containers/tools/build_mac80211_hwsim.sh), BSD-2-Clause,
# Copyright (c) 2021, rfhs.
#
# Usage: build_mac80211_hwsim.sh [OUTDIR]    (default .)
# KVER picks the kernel (default: the running one), whose headers have to be in
# /lib/modules/KVER/build. UPSTREAM sets the kernel.org version; by default it
# comes from /proc/version_signature on Ubuntu, else from KVER's major.minor.
set -eu

missing_tools=""
for tool in cp curl make mktemp rm uname; do
  command -v "${tool}" > /dev/null 2>&1 || missing_tools="${missing_tools} ${tool}"
done
if [ -n "${missing_tools}" ]; then
  printf '%s: required commands not found:%s\n' "${0##*/}" "${missing_tools}" >&2
  exit 1
fi
kver="${KVER:-$(uname -r)}"
out="${1:-.}"
upstream="${UPSTREAM:-}"
if [ -z "${upstream}" ] && [ -z "${KVER:-}" ] && [ -r /proc/version_signature ]; then
  upstream="$(awk '{print $NF}' /proc/version_signature)"
fi
if [ -z "${upstream}" ]; then
  upstream="$(printf '%s' "${kver}" | cut -d. -f1-2)"
fi
# kernel.org tags the first release of a series v6.17, not v6.17.0
case "${upstream}" in
  *.*.0) upstream="${upstream%.0}";;
esac

src="$(mktemp -d)"
trap 'rm -rf "${src}"' EXIT
for f in mac80211_hwsim.c mac80211_hwsim.h; do
  curl -fsSL --retry 3 -o "${src}/${f}" \
    "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/drivers/net/wireless/virtual/${f}?h=v${upstream}"
done
echo 'obj-m := mac80211_hwsim.o' > "${src}/Kbuild"
make -C "/lib/modules/${kver}/build" M="${src}" modules
cp "${src}/mac80211_hwsim.ko" "${out}/"
printf 'Built %s/mac80211_hwsim.ko for %s from v%s\n' "${out}" "${kver}" "${upstream}"
