#!/bin/sh
# Usage (inside the helpers container, by runtime-test.sh):
#   run-helpers.sh STATUSFILE LOGDIR INTERFACE:name=NAME[,OPTION...]...
#
# Starts one kismet_cap_linux_wifi per source, each connecting to the
# kismet server on 127.0.0.1:2501 as KISMET_USER/KISMET_PASSWORD, and appends
# "<interface> <exit status>" to STATUSFILE as each one exits. HELPER_STAGGER
# seconds (default 0) pass between starts.

status="${1:?usage: run-helpers.sh STATUSFILE LOGDIR SOURCE...}"
logdir="${2:?usage: run-helpers.sh STATUSFILE LOGDIR SOURCE...}"
shift 2

for source in "$@"; do
	iface="${source%%:*}"
	name="${source#*:name=}"
	name="${name%%,*}"
	(
		kismet_cap_linux_wifi --connect 127.0.0.1:2501 \
			--user "${KISMET_USER}" --password "${KISMET_PASSWORD}" \
			--source "${source}" --disable-retry \
			> "${logdir}/${name}.log" 2>&1
		echo "${iface} $?" >> "${status}"
	) &
	sleep "${HELPER_STAGGER:-0}"
done
wait
