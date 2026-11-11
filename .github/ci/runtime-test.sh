#!/bin/bash
# Usage: sudo .github/ci/runtime-test.sh IMAGE
#
# Runs the kismet installed in IMAGE (by `make suidinstall`, as the build
# images' *-build.sh do) on mac80211_hwsim radios, unprivileged:
#
#  0. kismet alone, with no sources, for SETTLE seconds (60);
#  1. RADIOS (50) kismet_cap_linux_wifi helpers, run on their own in a second
#     container and connected over the websocket remote capture (sources
#     hwsimNN-ws), for SOAK1 seconds (120);
#  2. the same over the legacy TCP remote capture (hwsimNN-tcp), with a fresh
#     kismet;
#  3. the same with every other helper on websockets and the rest on TCP;
#  4. kismet launching the helpers itself from source= lines (hwsimNN), for
#     SOAK2 seconds (60).
#
# Two more radios stay on the host as hostapd access points on channels 1 and
# 6, which each phase has to see, and a third as a monitor that checks they're
# beaconing before kismet starts and after each soak, so that a silent access
# point isn't blamed on kismet. Each phase ends with kismet shutting down,
# which has to be clean. Failures are printed as GitHub annotations naming
# whether kismet or a capture helper failed; logs, kismetdb files and docker
# state go to LOGDIR (default: a new directory under /tmp).
#
# Needs root, docker, iw, rfkill, hostapd, tcpdump, curl, jq and python3, and a
# mac80211_hwsim module. It only touches mac80211_hwsim radios, loads the
# module with RADIOS + 3 radios and HWSIM_CHANNELS (RADIOS + 3) channels
# (reloading it if it has too few and none is in use elsewhere) and unloads it
# afterwards if it loaded it. No container is
# privileged or sees the host's devices.
#
# The independent helpers start HELPER_STAGGER seconds (0.5) apart: started
# together, they wait on linuxwifi's system-wide interface lock and give up
# after 5 s. SOURCE_OPTS (e.g. channel=1, or channels="1,6,11") is added to
# every source's options.
#
# CI_FAULT=kismet-early|kismet-late|helper sends SIGSEGV to kismet in phase 0,
# or to kismet or one helper (a TCP one in phase 3) 10 s into the soak of the
# phase CI_FAULT_PHASE=ws|tcp|mixed (ws: 1, tcp: 2, mixed: 3), to check the
# annotations.
#
# DEBUG_TAP=1 runs the host's tcpdump (with nsenter) on the first three
# sources' monitor interfaces for 30 s of each helper phase's soak, and samples
# their channel, into LOGDIR/phaseN/tap-*.

set -uo pipefail
export LC_ALL=C

image="${1:?usage: runtime-test.sh IMAGE}"
radios="${RADIOS:-50}"
settle="${SETTLE:-60}"
soak1="${SOAK1:-120}"
soak2="${SOAK2:-60}"
attach_wait="${ATTACH_WAIT:-120}"
port="${KISMET_CI_PORT:-12501}"
fault="${CI_FAULT:-}"
fault_phase="${CI_FAULT_PHASE:-ws}"
stagger="${HELPER_STAGGER:-0.5}"
source_opts="${SOURCE_OPTS:+,${SOURCE_OPTS}}"
here="$(cd "$(dirname "$0")" && pwd)"
run_image="kismet-ci-run:$$"
netns="kismet-ci-netns"
kismet="kismet-ci-kismet"
helpers="kismet-ci-helpers"
user=ci
password="$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
failed=0
loaded_hwsim=0
ap_ifaces=()
ap_bssids=()
ifaces=()
sources=()
phase_args=()

case "${fault}" in
	''|kismet-early|kismet-late|helper) ;;
	*) echo "CI_FAULT=${fault}: expected kismet-early, kismet-late or helper" >&2; exit 2 ;;
esac
case "${fault_phase}" in
	ws|tcp|mixed) ;;
	*) echo "CI_FAULT_PHASE=${fault_phase}: expected ws, tcp or mixed" >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
	echo "Run it as root" >&2
	exit 2
fi
missing=""
for tool in docker iw rfkill hostapd tcpdump curl jq python3 modprobe lsmod; do
	command -v "${tool}" > /dev/null 2>&1 || missing="${missing} ${tool}"
done
if [ -n "${missing}" ]; then
	echo "required commands not found:${missing}" >&2
	exit 2
fi
logdir="${LOGDIR:-$(mktemp -d /tmp/kismet-runtime.XXXXXX)}"
mkdir -p "${logdir}"
logdir="$(cd "${logdir}" && pwd)"

# GitHub reads only the first line of an annotation, so newlines are escaped
annotate() {
	local level="$1" title="$2" msg="$3"
	msg="${msg//'%'/'%25'}"
	msg="${msg//$'\r'/'%0D'}"
	msg="${msg//$'\n'/'%0A'}"
	printf '::%s title=%s::%s\n' "${level}" "${title}" "${msg}"
	[ "${level}" = error ] && failed=1
	return 0
}

summary() {
	echo "$1"
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		echo "$1" >> "${GITHUB_STEP_SUMMARY}"
	fi
}

describe_exit() {
	local code="$1"
	if [ "${code}" -gt 128 ] && [ "${code}" -lt 160 ]; then
		printf 'signal %d (SIG%s)' "$((code - 128))" "$(kill -l "$((code - 128))" 2> /dev/null || echo '?')"
	else
		printf 'status %d' "${code}"
	fi
}

container_state() {
	docker inspect -f '{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}' "$1" 2> /dev/null || echo "missing 0 false"
}

# Exits from the container's init (tini) carry 128 + the signal that killed kismet
kismet_died() {
	local running code oom
	read -r running code oom <<< "$(container_state "${kismet}")"
	[ "${running}" = true ] && return 1
	died="kismet exited with $(describe_exit "${code}")"
	[ "${oom}" = true ] && died="${died}, killed for running out of memory"
	return 0
}

save_logs() {
	docker logs "${kismet}" > "${logdir}/$1/kismet.log" 2>&1
}

# Kismet's output isn't read as workflow commands
log_tail() {
	local token
	token="$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
	echo "::group::Last 60 lines of kismet's output ($1)"
	echo "::stop-commands::${token}"
	tail -n 60 "${logdir}/$1/kismet.log"
	echo "::${token}::"
	echo "::endgroup::"
}

api() {
	curl -fsS --max-time 10 -u "${user}:${password}" "$@"
}

hwsim_loaded() {
	[ -e /sys/module/mac80211_hwsim/initstate ]
}

hwsim_phys() {
	local phy
	for phy in /sys/class/ieee80211/*; do
		[ -e "${phy}/device/driver" ] || continue
		[ "$(basename "$(readlink -f "${phy}/device/driver")")" = mac80211_hwsim ] || continue
		echo "$(cat "${phy}/index") ${phy##*/}"
	done | sort -n | cut -d' ' -f2
}

phy_iface() {
	local net
	for net in "/sys/class/ieee80211/$1/device/net"/*; do
		echo "${net##*/}"
		return
	done
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

hwsim_radios() {
	cat /sys/module/mac80211_hwsim/parameters/radios 2> /dev/null || echo 0
}

# Matches the command itself, as docker-init's arguments hold kismet's too
kill_in() {
	local container="$1" command="$2" pattern="$3" pid
	pid="$(docker top "${container}" -eo pid,args |
		awk -v c="${command}" -v p="${pattern}" 'NR > 1 && $2 == c && $0 ~ p { print $1; exit }')"
	if [ -n "${pid}" ]; then
		echo "CI_FAULT: sending SIGSEGV to ${pid} in ${container}"
		kill -SEGV "${pid}"
	fi
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
# shellcheck disable=SC2317,SC2329 # run by cleanup
nm_unignore_hwsim() {
	[ -e "${nm_rule}" ] || return 0
	rm -f "${nm_rule}"
	udevadm control --reload
}

# shellcheck disable=SC2317,SC2329 # run by the EXIT trap
cleanup() {
	local pidfile i
	docker rm -f "${helpers}" "${kismet}" "${netns}" > /dev/null 2>&1
	for pidfile in "${logdir}"/hostapd-*.pid; do
		[ -e "${pidfile}" ] && kill "$(cat "${pidfile}")" 2> /dev/null
	done
	docker image rm "${run_image}" > /dev/null 2>&1
	if [ "${loaded_hwsim}" = 1 ]; then
		# The radios come back from the container's namespace asynchronously
		for i in $(seq 1 20); do
			modprobe -r mac80211_hwsim 2> /dev/null && break
			sleep 1
		done
	fi
	nm_unignore_hwsim
	# kismet writes its logs as kismetci; the artifact upload runs as the runner
	chmod -R a+rX "${logdir}"
}
trap cleanup EXIT

wait_running() {
	local i
	for i in $(seq 1 30); do
		[ "$(docker inspect -f '{{.State.Running}}' "$1" 2> /dev/null)" = true ] && return 0
		sleep 1
	done
	return 1
}

start_kismet() {
	local phase="$1"
	shift
	mkdir -p "${logdir}/${phase}"
	chown "${uid}" "${logdir}/${phase}"
	{
		echo "httpd_username=${user}"
		echo "httpd_password=${password}"
		echo "log_prefix=/logs/"
		echo "log_title=${phase}"
		echo "remote_capture_enabled=true"
		echo "remote_capture_listen=127.0.0.1"
		echo "remote_capture_port=3501"
	} > "${logdir}/${phase}/kismet_site.conf"
	if [ "$#" -gt 0 ]; then
		printf 'source=%s\n' "$@" >> "${logdir}/${phase}/kismet_site.conf"
	fi
	docker run -d --name "${kismet}" --init --network "container:${netns}" \
		--user kismetci "${kismet_caps[@]}" \
		-v "${logdir}/${phase}/kismet_site.conf:/usr/local/etc/kismet_site.conf:ro" \
		-v "${logdir}/${phase}:/logs" \
		--entrypoint kismet "${run_image}" --no-ncurses > /dev/null
}

wait_api() {
	local i
	for i in $(seq 1 "$1"); do
		api "http://127.0.0.1:${port}/system/status.json" -o /dev/null 2> /dev/null && return 0
		kismet_died && return 1
		sleep 1
	done
	return 1
}

# Prints "<running> <total>" for this phase's sources
count_sources() {
	api "http://127.0.0.1:${port}/datasource/all_sources.json" 2> /dev/null |
		jq -r '[.[] | select(.["kismet.datasource.name"] | startswith("hwsim"))] |
			"\([.[] | select(.["kismet.datasource.running"] == 1)] | length) \(length)"' 2> /dev/null ||
		echo "0 0"
}

wait_sources() {
	local i running total
	for i in $(seq 1 "${attach_wait}"); do
		read -r running total <<< "$(count_sources)"
		[ "${running}" -ge "${radios}" ] && return 0
		kismet_died && return 1
		[ -n "${1:-}" ] && [ -s "$1" ] && return 1
		sleep 1
	done
	return 1
}

# by_transport TEXT: how many websocket and TCP sources TEXT names, for phase 3
by_transport() {
	local ws tcp
	ws="$(grep -oE 'hwsim[0-9]+-ws' <<< "$1" | sort -u | grep -c .)"
	tcp="$(grep -oE 'hwsim[0-9]+-tcp' <<< "$1" | sort -u | grep -c .)"
	printf ' (%d of %d websocket, %d of %d TCP)' "${ws}" "$(((radios + 1) / 2))" "${tcp}" "$((radios / 2))"
}

# Packets captured by the sources whose names end in $2
packets_of() {
	jq --arg s "$2" '[.[] | select(.["kismet.datasource.name"] | startswith("hwsim") and endswith($s))
		| .["kismet.datasource.num_packets"]] | add // 0' <<< "$1"
}

# check_capture PHASE WHAT [mixed]: checks what kismet saw during a phase;
# prints annotations, returns 1 on error
check_capture() {
	local phase="$1" what="$2" mixed="${3:-}" json devices bssid not_running quiet packets split="" t n
	json="$(api "http://127.0.0.1:${port}/datasource/all_sources.json")" || {
		annotate error "Kismet stopped answering (${what})" "kismet is running but its REST API didn't answer at the end of the ${phase} soak"
		return 1
	}
	echo "${json}" > "${logdir}/${phase}/all_sources.json"
	not_running="$(jq -r '.[] | select(.["kismet.datasource.name"] | startswith("hwsim"))
		| select(.["kismet.datasource.running"] != 1)
		| "\(.["kismet.datasource.name"]) (\(.["kismet.datasource.interface"])): \(.["kismet.datasource.error_reason"] // "not running")"' <<< "${json}")"
	if [ -n "${not_running}" ]; then
		[ -n "${mixed}" ] && split="$(by_transport "${not_running}")"
		annotate error "Capture sources stopped (${what})" "$(grep -c . <<< "${not_running}") of ${radios} sources were not running at the end of the ${phase} soak${split}:
${not_running}"
	fi
	packets="$(packets_of "${json}" "")"
	quiet="$(jq -r '[.[] | select(.["kismet.datasource.name"] | startswith("hwsim"))
		| select(.["kismet.datasource.num_packets"] == 0) | .["kismet.datasource.name"]] | join(" ")' <<< "${json}")"
	if [ "${packets}" -eq 0 ]; then
		annotate error "No packets captured (${what})" "none of the ${radios} sources captured a packet during the ${phase} soak"
	else
		if [ -n "${mixed}" ]; then
			for t in websocket TCP; do
				n="$(packets_of "${json}" "$([ "${t}" = TCP ] && echo -tcp || echo -ws)")"
				if [ "${n}" -eq 0 ]; then
					annotate error "No packets captured over ${t} (${what})" "the ${t} sources captured nothing during the ${phase} soak, while the others captured ${packets} packets"
				fi
			done
			packets="${packets} (websocket $(packets_of "${json}" -ws), TCP $(packets_of "${json}" -tcp))"
		fi
		if [ -n "${quiet}" ]; then
			[ -n "${mixed}" ] && split="$(by_transport "${quiet}")"
			annotate warning "Sources without packets (${what})" "these sources captured nothing during the ${phase} soak${split}: ${quiet}"
		fi
	fi
	devices="$(api -d 'json={"fields":["kismet.device.base.macaddr"]}' \
		"http://127.0.0.1:${port}/devices/last-time/0/devices.json" |
		jq -r '.[]["kismet.device.base.macaddr"]')" || devices=""
	for bssid in "${ap_bssids[@]}"; do
		if ! grep -qix "${bssid}" <<< "${devices}"; then
			annotate error "Access point not seen (${what})" "kismet has no device for the hostapd access point ${bssid} after the ${phase} soak"
		fi
	done
	summary "| ${phase} | ${what} | $(jq '[.[] | select(.["kismet.datasource.name"] | startswith("hwsim")) | select(.["kismet.datasource.running"] == 1)] | length' <<< "${json}")/${radios} | ${packets} | $(grep -c . <<< "${devices}") |"
}

# Stops kismet as `docker stop` would and checks it exits 0 and wrote its log
# With "nopackets", after an earlier failure, the log only has to be readable
stop_kismet() {
	local phase="$1" what="$2" expect="${3:-}" code db rows f
	docker stop -t 30 "${kismet}" > /dev/null
	save_logs "${phase}"
	read -r _ code _ <<< "$(container_state "${kismet}")"
	if [ "${code}" -ne 0 ]; then
		annotate error "Kismet did not shut down cleanly (${what})" "kismet exited with $(describe_exit "${code}") when stopped after the ${phase} soak"
		log_tail "${phase}"
	fi
	db=""
	for f in "${logdir}/${phase}"/*.kismet; do
		[ -e "${f}" ] && db="${f}"
	done
	if [ -z "${db}" ]; then
		annotate error "No kismetdb log (${what})" "kismet wrote no .kismet log in the ${phase} phase"
	elif ! rows="$(python3 -I -c 'import sqlite3, sys
print(sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True).execute("select count(*) from packets").fetchone()[0])' "${db}" 2>&1)"; then
		annotate error "Unreadable kismetdb log (${what})" "${db##*/}: ${rows}"
	elif [ "${rows}" -eq 0 ] && [ "${expect}" != nopackets ]; then
		annotate error "Empty kismetdb log (${what})" "${db##*/} has no packets"
	fi
	docker rm "${kismet}" > /dev/null
}

echo "Logs go to ${logdir}"

# --- image with an unprivileged user in the kismet group -------------------

if ! docker build -q -t "${run_image}" - > /dev/null <<-EOF
	FROM ${image}
	RUN grep -q '^kismet:' /etc/group && useradd -m -G kismet kismetci
	EOF
then
	annotate error "Kismet is not installed" "${image} has no kismet group (from make suidinstall) or no useradd"
	exit 1
fi
uid="$(docker run --rm --entrypoint id "${run_image}" -u kismetci)"

# --- radios ------------------------------------------------------------------

want=$((radios + 3))
channels="${HWSIM_CHANNELS:-${want}}"
nm_ignore_hwsim
if ! hwsim_loaded; then
	modprobe mac80211_hwsim radios="${want}" channels="${channels}" || exit 2
	loaded_hwsim=1
elif [ "$(hwsim_phys | grep -c .)" -lt "${want}" ] ||
	[ "$(cat /sys/module/mac80211_hwsim/parameters/channels)" -lt "${channels}" ]; then
	if [ "$(hwsim_phys | grep -c .)" -ne "$(hwsim_radios)" ]; then
		echo "mac80211_hwsim is loaded and some of its radios are in other namespaces; not reloading it" >&2
		exit 2
	fi
	modprobe -r mac80211_hwsim && modprobe mac80211_hwsim radios="${want}" channels="${channels}" || exit 2
	loaded_hwsim=1
fi
command -v udevadm > /dev/null && udevadm settle
wait_radios "${want}"
for phy in $(hwsim_phys); do
	index="$(cat "/sys/class/ieee80211/${phy}/index")"
	[ "${phy}" = "phy${index}" ] || iw phy "${phy}" set name "phy${index}"
done
mapfile -t phys < <(hwsim_phys)
if [ "${#phys[@]}" -lt "${want}" ]; then
	echo "only ${#phys[@]} free mac80211_hwsim radios, ${want} needed; kernel log in dmesg.txt" >&2
	dmesg | tail -100 > "${logdir}/dmesg.txt" 2>&1
	exit 2
fi
for phy in "${phys[@]:0:${want}}"; do
	for rf in "/sys/class/ieee80211/${phy}"/rfkill*; do
		[ -e "${rf}" ] && rfkill unblock "${rf##*/rfkill}"
	done
done

# --- access points -------------------------------------------------------------

n=0
for phy in "${phys[@]:0:2}"; do
	iface="$(phy_iface "${phy}")"
	if command -v nmcli > /dev/null 2>&1; then
		nmcli device set "${iface}" managed no > /dev/null 2>&1
	fi
	channel=$((n == 0 ? 1 : 6))
	{
		echo "interface=${iface}"
		echo "driver=nl80211"
		echo "ssid=kismet-ci-${channel}"
		echo "hw_mode=g"
		echo "channel=${channel}"
		if [ "${n}" = 1 ]; then
			echo "wpa=2"
			echo "wpa_key_mgmt=WPA-PSK"
			echo "rsn_pairwise=CCMP"
			echo "wpa_passphrase=kismet-ci-passphrase"
		fi
	} > "${logdir}/hostapd-${channel}.conf"
	# NetworkManager can still hold the interface for a moment after letting it go
	started=0
	for _ in 1 2 3 4 5; do
		if hostapd -B -P "${logdir}/hostapd-${channel}.pid" -f "${logdir}/hostapd-${channel}.log" \
			"${logdir}/hostapd-${channel}.conf" > /dev/null; then
			started=1
			break
		fi
		sleep 2
	done
	if [ "${started}" = 0 ]; then
		cat "${logdir}/hostapd-${channel}.log" >&2
		echo "hostapd failed to start on ${iface}" >&2
		exit 2
	fi
	ap_ifaces+=("${iface}")
	ap_bssids+=("$(cat "/sys/class/net/${iface}/address")")
	n=$((n + 1))
done
echo "Access points: ${ap_ifaces[*]} (${ap_bssids[*]})"

witness=kcwitness
iw phy "${phys[2]}" interface add "${witness}" type monitor
ip link set "$(phy_iface "${phys[2]}")" down
ip link set "${witness}" up

# check_beacons WHEN: annotates and fails if either access point sent no
# beacon the witness monitor saw in 3 s on its channel
check_beacons() {
	local i ch count missing=""
	for i in 0 1; do
		ch=$((i == 0 ? 1 : 6))
		iw dev "${witness}" set channel "${ch}"
		count="$(timeout 3 tcpdump -i "${witness}" -nn -e -l \
			"type mgt subtype beacon and wlan addr2 ${ap_bssids[${i}]}" 2> /dev/null | grep -c .)"
		echo "$1: ${count} beacons from ${ap_ifaces[${i}]} on channel ${ch} in 3 s" >> "${logdir}/beacons.txt"
		[ "${count}" -gt 0 ] || missing="${missing} ${ap_ifaces[${i}]} (channel ${ch})"
	done
	if [ -n "${missing}" ]; then
		annotate error "Access point not beaconing" "$1, a monitor on the host saw no beacons in 3 s from${missing}; the test's radios failed, not kismet"
		return 1
	fi
}

check_beacons "before kismet started" || exit 1

# --- phase 0: kismet alone -----------------------------------------------------

docker rm -f "${helpers}" "${kismet}" "${netns}" > /dev/null 2>&1
docker run -d --name "${netns}" --init --cap-drop all -p "127.0.0.1:${port}:2501" \
	--entrypoint tail "${run_image}" -f /dev/null > /dev/null
wait_running "${netns}" || { echo "the namespace container didn't start" >&2; exit 2; }

summary "| Phase | Sources | Running | Packets | Devices |"
summary "|---|---|---|---|---|"

kismet_caps=(--cap-drop all)
start_kismet phase1
if [ "${fault}" = kismet-early ]; then
	sleep 15
	kill_in "${kismet}" kismet ''
fi
for i in $(seq 1 "${settle}"); do
	kismet_died && break
	sleep 1
done
if kismet_died || ! wait_api 15; then
	save_logs phase1
	if kismet_died; then
		annotate error "Kismet failed before capture sources were added" "${died} within ${settle} s of starting, with no capture sources"
	else
		annotate error "Kismet failed before capture sources were added" "kismet is running but its REST API didn't answer on port 2501 after ${settle} s"
	fi
	log_tail phase1
	summary "| settle | none | - | - | - |"
	exit 1
fi
summary "| settle | none | - | - | - |"
echo "Phase 0: kismet ran ${settle} s with no sources"

# --- phases 1-3: helpers run on their own ------------------------------------

pid="$(docker inspect -f '{{.State.Pid}}' "${netns}")"
n=0
for phy in "${phys[@]:3:${radios}}"; do
	iface="$(phy_iface "${phy}")"
	iw phy "${phy}" set netns "${pid}"
	ifaces+=("${iface}")
	sources+=("${iface}:name=$(printf 'hwsim%02d' "${n}")${source_opts}")
	n=$((n + 1))
done

# A helper killed by a signal crashed; one that exited with a status failed,
# and its last error says why
helper_title() {
	if awk '$2 > 128 { found = 1 } END { exit !found }' "${logdir}/$1/helpers.status"; then
		echo "Capture helper crashed"
	else
		echo "Capture helper failed"
	fi
}

helper_crashes() {
	local phase="$1" iface code name a out=""
	while read -r iface code; do
		[ -n "${iface}" ] || continue
		name=""
		for a in "${phase_args[@]}"; do
			a="${a#*/}"
			if [ "${a%%:*}" = "${iface}" ]; then
				name="${a#*:name=}"
				name="${name%%,*}"
			fi
		done
		out="${out}${name:-?} (${iface}): $(describe_exit "${code}")"
		if [ "${code}" -le 128 ] && [ -n "${name}" ]; then
			out="${out}: $(grep -E '^(ERROR|FATAL)' "${logdir}/${phase}/helpers/${name}.log" | head -n 1)"
		fi
		out="${out}"$'\n'
	done < "${logdir}/${phase}/helpers.status"
	printf '%s' "${out}"
}

running_names() {
	api "http://127.0.0.1:${port}/datasource/all_sources.json" 2> /dev/null |
		jq -r '.[] | select(.["kismet.datasource.running"] == 1) | .["kismet.datasource.name"]' 2> /dev/null
}

# What the first three sources' monitor interfaces receive beside kismet, and
# the channel they're on every 0.1 s, for 30 s
tap_capture() {
	local phase="$1" iface mon
	for iface in "${ifaces[@]:0:3}"; do
		mon="${iface}mon"
		nsenter -t "${pid}" -n timeout 30 tcpdump -i "${mon}" -nn -e -l "type mgt subtype beacon" \
			> "${logdir}/${phase}/tap-${mon}.txt" 2> /dev/null &
		(
			for _ in $(seq 1 300); do
				echo "$(date +%s.%N | cut -c1-14) $(nsenter -t "${pid}" -n iw dev "${mon}" info | grep -o 'channel .*')"
				sleep 0.1
			done
		) > "${logdir}/${phase}/tap-${mon}-channels.txt" &
	done
	wait
}

# Starts a fresh kismet for a helper phase; annotates and returns 1 if it fails
start_helper_kismet() {
	local phase="$1" what="$2"
	start_kismet "${phase}"
	wait_api "${settle}" && return 0
	save_logs "${phase}"
	if kismet_died; then
		annotate error "Kismet failed to start (${what})" "${died} before any capture helper connected"
	else
		annotate error "Kismet failed to start (${what})" "kismet's REST API didn't answer within ${settle} s"
	fi
	log_tail "${phase}"
	summary "| ${phase} | ${what} | - | - | - |"
	docker rm -f "${kismet}" > /dev/null
	return 1
}

# helper_phase PHASE WHAT ws|tcp|mixed: connects a helper per radio to the
# running kismet from a container of their own, soaks, checks and stops kismet
helper_phase() {
	local phase="$1" what="$2" transport="$3" ok=1 i n=0 t iface victim="" split="" running total
	phase_args=()
	for iface in "${ifaces[@]}"; do
		t="${transport}"
		if [ "${t}" = mixed ]; then
			t=ws
			[ $((n % 2)) = 1 ] && t=tcp
		fi
		phase_args+=("${t}/${iface}:name=$(printf 'hwsim%02d' "${n}")-${t}${source_opts}")
		if [ -z "${victim}" ] && { [ "${transport}" != mixed ] || [ "${t}" = tcp ]; }; then
			victim="${iface}"
		fi
		n=$((n + 1))
	done

	mkdir -p "${logdir}/${phase}/helpers"
	: > "${logdir}/${phase}/helpers.status"
	chown -R "${uid}" "${logdir}/${phase}"
	# The setuid-root helper gets net_admin and net_raw from the bounding set,
	# as it does when a user in the kismet group runs it
	docker run -d --name "${helpers}" --init --network "container:${netns}" \
		--cap-drop all --cap-add net_admin --cap-add net_raw --user kismetci \
		-e KISMET_USER="${user}" -e KISMET_PASSWORD="${password}" -e HELPER_STAGGER="${stagger}" \
		-v "${here}/run-helpers.sh:/ci/run-helpers.sh:ro" -v "${logdir}/${phase}:/logs" \
		--entrypoint sh "${run_image}" /ci/run-helpers.sh /logs/helpers.status /logs/helpers \
		"${phase_args[@]}" > /dev/null

	if ! wait_sources "${logdir}/${phase}/helpers.status"; then
		ok=0
		read -r running total <<< "$(count_sources)"
		save_logs "${phase}"
		if kismet_died; then
			annotate error "Kismet crashed after capture sources were added (${what})" "${died} while ${running} of ${radios} helpers had connected"
			log_tail "${phase}"
		elif [ -s "${logdir}/${phase}/helpers.status" ]; then
			[ "${transport}" = mixed ] && split="$(by_transport "$(helper_crashes "${phase}")")"
			annotate error "$(helper_title "${phase}") (${what})" "helpers exited while connecting${split}, with ${running} of ${radios} sources running:
$(helper_crashes "${phase}")"
		else
			[ "${transport}" = mixed ] && split="$(by_transport "$(running_names)")"
			annotate error "Capture sources did not start (${what})" "only ${running} of ${radios} sources (${total} known to kismet) were running after ${attach_wait} s${split}"
		fi
	fi

	if [ "${ok}" = 1 ]; then
		echo "${phase}: ${radios} ${what} connected, soaking ${soak1} s"
		for i in $(seq 1 "${soak1}"); do
			if [ "${fault_phase}" = "${transport}" ] && [ "${i}" = 10 ]; then
				[ "${fault}" = kismet-late ] && kill_in "${kismet}" kismet ''
				[ "${fault}" = helper ] && kill_in "${helpers}" kismet_cap_linux_wifi " ${victim}:"
			fi
			if [ "${DEBUG_TAP:-0}" = 1 ] && [ "${i}" = 10 ]; then
				tap_capture "${phase}" &
			fi
			if kismet_died; then
				save_logs "${phase}"
				annotate error "Kismet crashed after capture sources were added (${what})" "${died} ${i} s into the ${soak1} s soak with ${radios} independent capture helpers"
				log_tail "${phase}"
				ok=0
				break
			fi
			if [ -s "${logdir}/${phase}/helpers.status" ]; then
				[ "${transport}" = mixed ] && split="$(by_transport "$(helper_crashes "${phase}")")"
				annotate error "$(helper_title "${phase}") (${what})" "helpers exited ${i} s into the soak${split} while kismet kept running:
$(helper_crashes "${phase}")"
				ok=0
				break
			fi
			sleep 1
		done
	fi

	if ! kismet_died; then
		if [ "${ok}" = 1 ]; then
			check_beacons "after the ${phase} soak"
			check_capture "${phase}" "${what}" "$([ "${transport}" = mixed ] && echo mixed)"
		else
			summary "| ${phase} | ${what} | - | - | - |"
		fi
		stop_kismet "${phase}" "${what}" "$([ "${ok}" = 1 ] || echo nopackets)"
	else
		summary "| ${phase} | ${what} | - | - | - |"
		docker rm "${kismet}" > /dev/null
	fi
	docker rm -f "${helpers}" > /dev/null 2>&1
}

helper_phase phase1 "websocket helpers" ws
start_helper_kismet phase2 "TCP helpers" && helper_phase phase2 "TCP helpers" tcp
start_helper_kismet phase3 "websocket + TCP helpers" && helper_phase phase3 "websocket + TCP helpers" mixed

# --- phase 4: kismet launches the helpers --------------------------------------

# kismet needs the helpers' capabilities in its bounding set to run them
kismet_caps=(--cap-drop all --cap-add net_admin --cap-add net_raw)
start_kismet phase4 "${sources[@]}"
if ! wait_api "${settle}"; then
	save_logs phase4
	if kismet_died; then
		annotate error "Kismet failed to start (kismet-launched sources)" "${died} while starting with ${radios} source= lines"
	else
		annotate error "Kismet failed to start (kismet-launched sources)" "kismet's REST API didn't answer within ${settle} s"
	fi
	log_tail phase4
	exit 1
fi
if ! wait_sources; then
	read -r running total <<< "$(count_sources)"
	save_logs phase4
	if kismet_died; then
		annotate error "Kismet crashed while opening its capture sources (kismet-launched sources)" "${died} with ${running} of ${radios} sources running"
		log_tail phase4
		exit 1
	fi
	annotate error "Capture sources did not start (kismet-launched sources)" "only ${running} of ${radios} sources (${total} defined) were running after ${attach_wait} s; kismet said:
$(grep -E '^ERROR: ' "${logdir}/phase4/kismet.log" | sort | uniq -c | sort -rn | head -n 5)"
	summary "| phase4 | kismet-launched sources | ${running}/${radios} | - | - |"
	stop_kismet phase4 "kismet-launched sources" nopackets
	exit 1
fi
echo "phase4: soaking ${soak2} s"
for i in $(seq 1 "${soak2}"); do
	if kismet_died; then
		save_logs phase4
		annotate error "Kismet crashed after capture sources were added (kismet-launched sources)" "${died} ${i} s into the ${soak2} s soak"
		log_tail phase4
		exit 1
	fi
	sleep 1
done
check_beacons "after the phase4 soak"
check_capture phase4 "kismet-launched sources"
stop_kismet phase4 "kismet-launched sources"

if [ "${failed}" = 0 ]; then
	echo "kismet ran with no sources, with ${radios} independent helpers over websockets, over TCP and over both, and with ${radios} sources of its own"
fi
exit "${failed}"
