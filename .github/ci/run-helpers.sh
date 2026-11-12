#!/bin/sh
# Usage (inside the helpers container, by runtime-test.sh):
#   run-helpers.sh STATUSFILE LOGDIR {ws|tcp}/INTERFACE:name=NAME[,OPTION...]...
#
# Starts one kismet_cap_linux_wifi per source, each connecting to the kismet
# server either over the websocket remote capture on 127.0.0.1:2501 as
# KISMET_USER/KISMET_PASSWORD (ws/) or over the legacy TCP remote capture on
# 127.0.0.1:3501 (tcp/), and appends "<interface> <exit status>" to STATUSFILE
# as each one exits. HELPER_STAGGER seconds (default 0) pass between starts.

status="${1:?usage: run-helpers.sh STATUSFILE LOGDIR SOURCE...}"
logdir="${2:?usage: run-helpers.sh STATUSFILE LOGDIR SOURCE...}"
shift 2

for arg in "$@"; do
	transport="${arg%%/*}"
	source="${arg#*/}"
	iface="${source%%:*}"
	name="${source#*:name=}"
	name="${name%%,*}"
	# The loop's list is already expanded, so "$@" is free to hold the arguments
	case "${transport}" in
		ws) set -- --connect 127.0.0.1:2501 --user "${KISMET_USER}" --password "${KISMET_PASSWORD}" ;;
		tcp) set -- --connect 127.0.0.1:3501 --tcp ;;
		*)
			echo "${arg}: unknown transport ${transport}" >&2
			exit 2
			;;
	esac
	(
		kismet_cap_linux_wifi "$@" --source "${source}" --disable-retry \
			> "${logdir}/${name}.log" 2>&1
		echo "${iface} $?" >> "${status}"
	) &
	sleep "${HELPER_STAGGER:-0}"
done
wait
