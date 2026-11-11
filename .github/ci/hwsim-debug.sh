#!/bin/bash
# Usage: sudo .github/ci/hwsim-debug.sh IMAGE [LOGDIR]
#
# Narrows down why kismet captures little or nothing on many mac80211_hwsim
# radios, for runtime-test.sh:
#
#  1. the bands and frequencies a mac80211_hwsim radio offers;
#  2. without kismet, the beacons a monitor interface fixed on channel 1 sees
#     from a hostapd access point in 5 s, with 4, 10, 25 and 52 radios loaded:
#     first with the other radios idle, then with monitor interfaces on all of
#     them hopping five times a second, as kismet's sources do;
#  3. runtime-test.sh on IMAGE in each of VARIANTS (default: r4 r10 r25 r50
#     r50-ch1-6-11 r50-ch1), about 3.5 minutes each:
#       r4, r10, r25, r50  that many radios, the full hop list
#       r50-ch1-6-11       50 radios hopping only channels 1, 6 and 11
#       r50-ch1            50 radios with channel=1
#       r10-verbose        10 radios, logging every channel the helpers
#                          can't tune and their channel set times
#       r10-24ghz          10 radios hopping only 2.4GHz channels 1-11
#       r10-24-5ghz        10 radios hopping 2.4GHz and some 5GHz channels
#       r10-hopsync        10 radios with synchronized hopping
#       r10-ht40           10 radios hopping 1, 6, 1HT40+ and 6HT40-
#       r10-vht            10 radios hopping 1, 6, 36VHT80 and 36VHT160
#       r10-5ghz           10 radios hopping 1, 6, 36 and 149
#       r10-6ghz           10 radios hopping 1, 6, 1W6e and 5W6e
#     The soaks run 90 s (60 and 30 s for the last four), past the point where
#     a helper drops the channels it couldn't tune (one pass of a 161 channel
#     list at 5 a second);
#  4. without kismet, the beacons a monitor interface on channel 1 sees before
#     and after it spends 0.2 s on each other kind of channel kismet hops to
#     (HT40, 5GHz, VHT80, VHT160, 6GHz), with its parent interface down as
#     kismet leaves it;
#  5. without kismet, the beacons from access points on channels 1 and 6 that
#     a monitor interface hopping kismet's lists at 0.2 s a channel receives.
#
# STEPS (default "1 2 3") picks the steps; they run in the order 1 2 3 4 5. Results go to LOGDIR/summary.txt
# (default LOGDIR: a new directory under /tmp), with each step's logs beside
# it.
#
# Needs root, iw, rfkill, hostapd, tcpdump and what runtime-test.sh needs, and
# mac80211_hwsim not loaded. It loads it with as many channels as radios, or
# HWSIM_CHANNELS. A udev rule in /run keeps NetworkManager off the radios
# while it runs.

set -uo pipefail
export LC_ALL=C

image="${1:?usage: hwsim-debug.sh IMAGE [LOGDIR]}"
here="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
	echo "Run it as root" >&2
	exit 2
fi
missing=""
for tool in iw rfkill hostapd tcpdump modprobe lsmod ip timeout pkill; do
	command -v "${tool}" > /dev/null 2>&1 || missing="${missing} ${tool}"
done
if [ -n "${missing}" ]; then
	echo "required commands not found:${missing}" >&2
	exit 2
fi
hwsim_loaded() {
	[ -e /sys/module/mac80211_hwsim/initstate ]
}

if hwsim_loaded; then
	echo "mac80211_hwsim is already loaded; unload it first (modprobe -r mac80211_hwsim)" >&2
	exit 2
fi
logdir="${2:-$(mktemp -d /tmp/kismet-hwsim-debug.XXXXXX)}"
mkdir -p "${logdir}"
logdir="$(cd "${logdir}" && pwd)"
summary="${logdir}/summary.txt"
: > "${summary}"
hop_pids=()

say() {
	echo "$*" | tee -a "${summary}"
}

hwsim_phys() {
	local phy
	for phy in /sys/class/ieee80211/*; do
		[ -e "${phy}/device/driver" ] || continue
		[ "$(basename "$(readlink -f "${phy}/device/driver")")" = mac80211_hwsim ] || continue
		echo "$(cat "${phy}/index") ${phy##*/}"
	done | sort -n | cut -d' ' -f2
}

# mac80211_hwsim registers its radios one by one after modprobe returns
wait_radios() {
	local i
	for i in $(seq 1 30); do
		[ "$(hwsim_phys | grep -c .)" -ge "$1" ] && return 0
		sleep 1
	done
	return 1
}

phy_iface() {
	local net
	for net in "/sys/class/ieee80211/$1/device/net"/*; do
		echo "${net##*/}"
		return
	done
}

stop_radios() {
	local pid pidfile i
	for pid in "${hop_pids[@]}"; do
		pkill -P "${pid}" 2> /dev/null
		kill "${pid}" 2> /dev/null
	done
	hop_pids=()
	for pidfile in "${logdir}"/hostapd-*.pid; do
		[ -e "${pidfile}" ] || continue
		pid="$(cat "${pidfile}")"
		kill "${pid}" 2> /dev/null
		for i in $(seq 1 10); do
			kill -0 "${pid}" 2> /dev/null || break
			sleep 1
		done
		rm -f "${pidfile}"
	done
	if hwsim_loaded; then
		for i in $(seq 1 20); do
			modprobe -r mac80211_hwsim 2> "${logdir}/modprobe-r.err" && break
			sleep 1
		done
		if hwsim_loaded; then
			radio_state "mac80211_hwsim would not unload: $(cat "${logdir}/modprobe-r.err")"
			exit 2
		fi
	fi
}

# What holds the radios, for when they won't load or unload
radio_state() {
	{
		echo "== $(date) $1"
		lsmod | grep -E '^(mac80211_hwsim|mac80211|cfg80211) '
		echo "refcnt $(cat /sys/module/mac80211_hwsim/refcnt 2> /dev/null)"
		ls /sys/class/ieee80211
		iw dev
		pgrep -a 'hostapd|wpa_supplicant|iw|tcpdump'
		dmesg | tail -60
	} >> "${logdir}/radio-state.txt" 2>&1
	say "$1 (see radio-state.txt)"
}
# NetworkManager takes new Wi-Fi devices as they appear and hands them to the
# wpa_supplicant the host's own Wi-Fi uses; this keeps it off the hwsim radios
# from the start. /run is cleared at boot, should the rule be left behind.
nm_rule=/run/udev/rules.d/90-kismet-ci-hwsim.rules
nm_ignore_hwsim() {
	command -v udevadm > /dev/null || return 0
	mkdir -p "${nm_rule%/*}"
	echo 'SUBSYSTEM=="net", DRIVERS=="mac80211_hwsim", ENV{NM_UNMANAGED}="1"' > "${nm_rule}"
	udevadm control --reload
}
nm_unignore_hwsim() {
	[ -e "${nm_rule}" ] || return 0
	rm -f "${nm_rule}"
	udevadm control --reload
}

finish() {
	stop_radios
	nm_unignore_hwsim
	chmod -R a+rX "${logdir}"
}
trap finish EXIT
nm_ignore_hwsim

load_radios() {
	local phy rf iface
	modprobe mac80211_hwsim radios="$1" channels="${HWSIM_CHANNELS:-$1}" || exit 2
	command -v udevadm > /dev/null && udevadm settle
	if ! wait_radios "$1"; then
		radio_state "only $(hwsim_phys | grep -c .) of $1 mac80211_hwsim radios appeared"
		exit 2
	fi
	mapfile -t phys < <(hwsim_phys)
	for phy in "${phys[@]}"; do
		for rf in "/sys/class/ieee80211/${phy}"/rfkill*; do
			[ -e "${rf}" ] && rfkill unblock "${rf##*/rfkill}"
		done
		iface="$(phy_iface "${phy}")"
		if command -v nmcli > /dev/null 2>&1 && [ -n "${iface}" ]; then
			nmcli device set "${iface}" managed no > /dev/null 2>&1
		fi
	done
}

# beacons from $2 that monitor interface $1 sees in $3 (default 5) s
count_beacons() {
	timeout "${3:-5}" tcpdump -i "$1" -nn -e -l "type mgt subtype beacon and wlan addr2 $2" 2> /dev/null | grep -c .
}

# start_ap NAME [RADIO [CHANNEL]]: an open access point on radio RADIO
# (default 0) and channel CHANNEL (default 1); sets ap and bssid
start_ap() {
	local _
	ap="$(phy_iface "${phys[${2:-0}]}")"
	printf 'interface=%s\ndriver=nl80211\nssid=hwsim-debug-%s\nhw_mode=g\nchannel=%s\n' \
		"${ap}" "$1" "${3:-1}" > "${logdir}/hostapd-$1.conf"
	for _ in 1 2 3 4 5; do
		if hostapd -B -P "${logdir}/hostapd-$1.pid" -f "${logdir}/hostapd-$1.log" "${logdir}/hostapd-$1.conf" > /dev/null; then
			bssid="$(cat "/sys/class/net/${ap}/address")"
			return 0
		fi
		sleep 2
	done
	say "$1: hostapd failed to start on ${ap}, see hostapd-$1.log"
	return 1
}

steps="${STEPS:-1 2 3}"
variants="${VARIANTS:-r4 r10 r25 r50 r50-ch1-6-11 r50-ch1}"

# --- 1: bands ------------------------------------------------------------------

if [[ " ${steps} " == *" 1 "* ]]; then

load_radios 2
iw phy "${phys[0]}" info > "${logdir}/phy-info.txt"
say "== 1. mac80211_hwsim bands (full list in phy-info.txt)"
awk '/^\tBand /{band=$2} /^\t\t\t\* [0-9.]+ MHz/{n[band]++; if (!(band in lo)) lo[band]=$2; hi[band]=$2} END {for (b in n) printf "Band %s %d frequencies, %s-%s MHz\n", b, n[b], lo[b], hi[b]}' \
	"${logdir}/phy-info.txt" | sort | tee -a "${summary}"
stop_radios
fi

# --- 2: raw capture without kismet ---------------------------------------------

if [[ " ${steps} " == *" 2 "* ]]; then

say ""
say "== 2. beacons on a channel 1 monitor in 5 s, no kismet (about 48 expected)"
for n in 4 10 25 52; do
	load_radios "${n}"
	if ! start_ap "${n}"; then
		stop_radios
		continue
	fi
	last="${phys[$((${#phys[@]} - 1))]}"
	iw phy "${last}" interface add dbgmon0 type monitor
	ip link set dbgmon0 up
	iw dev dbgmon0 set channel 1
	sleep 2
	idle="$(count_beacons dbgmon0 "${bssid}")"

	i=1
	for phy in "${phys[@]:1:$((${#phys[@]} - 2))}"; do
		iw phy "${phy}" interface add "dbgmon${i}" type monitor
		ip link set "dbgmon${i}" up
		(
			while :; do
				for ch in 1 6 11 36 40 44 48 149 153 157 161; do
					iw dev "dbgmon${i}" set channel "${ch}" 2> /dev/null
					sleep 0.2
				done
			done
		) &
		hop_pids+=("$!")
		i=$((i + 1))
	done
	sleep 2
	hopping="$(count_beacons dbgmon0 "${bssid}")"
	say "${n} radios: ${idle} beacons with the others idle, ${hopping} with $((i - 1)) others hopping"
	stop_radios
done
fi

# --- 3: kismet ---------------------------------------------------------------------

if [[ " ${steps} " == *" 3 "* ]]; then
say ""
say "== 3. runtime-test.sh (packets and sources with packets per phase)"
variant() {
	local name="$1" f phase
	shift
	env SETTLE=10 SOAK1=90 SOAK2=90 "$@" LOGDIR="${logdir}/${name}" \
		"${here}/runtime-test.sh" "${image}" > "${logdir}/${name}.txt" 2>&1
	for phase in phase1 phase2; do
		f="${logdir}/${name}/${phase}/all_sources.json"
		if [ -s "${f}" ]; then
			say "${name} ${phase}: $(jq -r '[.[] | select(.["kismet.datasource.name"] | startswith("hwsim"))]
				| "\(map(select(.["kismet.datasource.running"] == 1)) | length) running, \(map(.["kismet.datasource.num_packets"]) | add // 0) packets, \(map(select(.["kismet.datasource.num_packets"] > 0)) | length) sources with packets"' "${f}")"
		else
			say "${name} ${phase}: no source list (the phase failed earlier)"
		fi
	done
	grep '^::error' "${logdir}/${name}.txt" | cut -c1-200 | sed 's/^/    /' | tee -a "${summary}"
}
for v in ${variants}; do
	case "${v}" in
		r4) variant r4 RADIOS=4 ;;
		r10) variant r10 RADIOS=10 ;;
		r25) variant r25 RADIOS=25 ;;
		r50) variant r50 RADIOS=50 ;;
		r50-ch1-6-11) variant r50-ch1-6-11 RADIOS=50 'SOURCE_OPTS=channels="1,6,11"' ;;
		r50-ch1) variant r50-ch1 RADIOS=50 SOURCE_OPTS=channel=1 ;;
		r10-verbose) variant r10-verbose RADIOS=10 SOURCE_OPTS=verbose=true,statistics=true ;;
		r10-24ghz) variant r10-24ghz RADIOS=10 'SOURCE_OPTS=channels="1,2,3,4,5,6,7,8,9,10,11"' ;;
		r10-24-5ghz) variant r10-24-5ghz RADIOS=10 'SOURCE_OPTS=channels="1,6,11,36,40,44,48,149,153,157,161"' ;;
		r10-hopsync) variant r10-hopsync RADIOS=10 SOURCE_OPTS=hopsync=true ;;
		r10-ht40) variant r10-ht40 RADIOS=10 SOAK1=60 SOAK2=30 'SOURCE_OPTS=channels="1,6,1HT40+,6HT40-"' ;;
		r10-vht) variant r10-vht RADIOS=10 SOAK1=60 SOAK2=30 'SOURCE_OPTS=channels="1,6,36VHT80,36VHT160"' ;;
		r10-5ghz) variant r10-5ghz RADIOS=10 SOAK1=60 SOAK2=30 'SOURCE_OPTS=channels="1,6,36,149"' ;;
		r10-6ghz) variant r10-6ghz RADIOS=10 SOAK1=60 SOAK2=30 'SOURCE_OPTS=channels="1,6,1W6e,5W6e"' ;;
		*) say "unknown variant ${v}" ;;
	esac
done
fi

# --- 4: channel 1 after other channel types ------------------------------------

if [[ " ${steps} " == *" 4 "* ]]; then
say ""
say "== 4. beacons on channel 1 in 3 s (about 30 expected), before and after the monitor"
say "   spends 0.2 s on another kind of channel, as kismet's hopping does (no kismet)"
load_radios 2
if start_ap step4; then
	parent="$(phy_iface "${phys[1]}")"
	iw phy "${phys[1]}" interface add dbgmon0 type monitor
	ip link set "${parent}" down
	ip link set dbgmon0 up
	for other in "channel 6" "channel 1 HT40+" "channel 6 HT40-" "freq 5180" \
		"freq 5180 HT20" "freq 5180 80 5210" "freq 5180 160 5250" "freq 5955 20" \
		"freq 5955 80 5985" "channel 1"; do
		iw dev dbgmon0 set channel 1
		sleep 0.2
		before="$(count_beacons dbgmon0 "${bssid}" 3)"
		# shellcheck disable=SC2086 # split into iw's arguments
		if err="$(iw dev dbgmon0 set ${other} 2>&1)"; then
			err=""
		else
			err=" (setting it failed: ${err})"
		fi
		sleep 0.2
		iw dev dbgmon0 set channel 1
		sleep 0.2
		after="$(count_beacons dbgmon0 "${bssid}" 3)"
		say "set ${other}: ${before} before, ${after} after${err}; now $(iw dev dbgmon0 info | grep -o 'channel .*')"
	done
fi
stop_radios
fi

# --- 5: a hopping monitor ------------------------------------------------------

if [[ " ${steps} " == *" 5 "* ]]; then
say ""
say "== 5. beacons a monitor hopping kismet's way (0.2 s a channel) receives in 20 s"
say "   from access points on channels 1 and 6 (no kismet); about 200 x the share of"
say "   channel 1 (or 6) entries in the list expected"
load_radios 3
if start_ap ch1 0 1 && bssid1="${bssid}" && start_ap ch6 1 6; then
	bssid6="${bssid}"
	parent="$(phy_iface "${phys[2]}")"
	iw phy "${phys[2]}" interface add dbgmon0 type monitor
	ip link set "${parent}" down
	ip link set dbgmon0 up
	# Entries are iw channel or (with f) freq arguments, : for spaces
	for list in "1 6 11" "1 6 36 149" "1 2 3 4 5 6 7 8 9 10 11" "1 6 1:HT40+ 6:HT40-" \
		"1 6 f5180:80:5210 f5180:160:5250" "1 6 f5955:20 f5975:20"; do
		(
			while :; do
				for ch in ${list}; do
					case "${ch}" in
						f*) args="freq ${ch#f}" ;;
						*) args="channel ${ch}" ;;
					esac
					# shellcheck disable=SC2086 # split into iw's arguments
					iw dev dbgmon0 set ${args//:/ } 2> /dev/null
					sleep 0.2
				done
			done
		) &
		hop_pids+=("$!")
		timeout 20 tcpdump -i dbgmon0 -nn -e -l "type mgt subtype beacon" > "${logdir}/step5.tmp" 2> /dev/null
		pkill -P "${hop_pids[-1]}" 2> /dev/null
		kill "${hop_pids[-1]}" 2> /dev/null
		unset 'hop_pids[-1]'
		say "hopping ${list}: $(grep -ci "${bssid1}" "${logdir}/step5.tmp") from channel 1, $(grep -ci "${bssid6}" "${logdir}/step5.tmp") from channel 6"
	done
	rm -f "${logdir}/step5.tmp"
fi
stop_radios
fi

say ""
say "Logs: ${logdir}"
