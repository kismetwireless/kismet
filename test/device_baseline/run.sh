#!/bin/bash
# Replay the baseline test capture through a Kismet build with the baseline filters on,
# and check what the shipped filters do, how hand changes hold, and that baseline filters
# do nothing while device_rules_baseline is off.  Takes about two minutes: the shortest
# expiry a filter may set is a minute.
#
# Usage: test/device_baseline/run.sh [kismet build dir]
# Needs python3 and curl; uses port $BASELINE_TEST_PORT (2596 by default) on 127.0.0.1,
# and no remote capture port or log files, so it can run next to a Kismet server.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd)
PORT=${BASELINE_TEST_PORT:-2596}
URL=http://127.0.0.1:$PORT
AUTH=baselinetest:baselinetest
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

AP1=02:00:00:00:b1:01 AP2=02:00:00:00:b1:02 AP3=02:00:00:00:b1:03 AP4=02:00:00:00:b1:04
CL=00:00:5e:00:53:99 R1=06:00:00:00:c1:20 R2=06:00:00:00:c1:21

python3 -I "$HERE/baseline_pcaps.py" "$WORK/baseline.pcap" || exit 1

pid=
fail=0

# start NAME [override lines...]
start() {
    local name=$1; shift
    mkdir -p "$WORK/$name/home"
    {
        printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\n" "$PORT"
        printf "enable_logging=false\nhttpd_username=baselinetest\nhttpd_password=baselinetest\n"
        printf "helper_binary_path=%s\n" "$K"
        printf "alert=DEAUTHCODEINVALID,10/min,1/sec\nalert=BCASTDISCON,10/min,1/sec\nalert=LONGSSID,10/min,1/sec\n"
        for l in "$@"; do printf "%s\n" "$l"; done
    } > "$WORK/$name/override.conf"

    (cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/$name/home" --confdir "$K/conf" \
        --datadir "$K" --no-ncurses --override "$WORK/$name/override.conf" \
        -c "$WORK/baseline.pcap:type=pcapfile,realtime=false" > "$WORK/$name/kismet.log" 2>&1) &
    pid=$!

    for i in $(seq 1 30); do
        curl -s -o /dev/null -u $AUTH $URL/system/status.json && return 0
        kill -0 $pid 2>/dev/null || break
        sleep 1
    done
    echo "FAIL $name: Kismet did not start:"; tail -5 "$WORK/$name/kismet.log"
    stop
    return 1
}

stop() {
    [ -n "$pid" ] && { kill $pid 2>/dev/null; wait $pid 2>/dev/null; }
    pid=
}

key() {
    python3 -I "$HERE/check.py" $URL $AUTH keys | sed -n "s/^$1=//p"
}

tag() {
    python3 -I "$HERE/check.py" $URL $AUTH tag "$(key $1)" "${@:2}"
}

# check NAME: expectations on stdin
check() {
    cat > "$WORK/expect.$1"
    if DB="$WORK/on/home/.kismet/devicetracker.db3" python3 -I "$HERE/check.py" $URL $AUTH state "$WORK/expect.$1"; then
        echo "ok   $1"
    else
        echo "FAIL $1"; fail=1
    fi
}

# Baseline filters on, with one-off-random's times cut down to test them
if start on device_rules_baseline=true \
    'device_baseline=one-off-random { when random_address and not linked and age(last_time) > 5s and last_time - first_time < 2m and packets < 50  every 10s  add  ephemeral  expire 1m }'; then
    t0=$(date +%s)
    # Before the filters' first runs, 10s after the rules load
    sleep 2
    for m in $AP1 $AP2 $AP3 $AP4 $CL; do tag $m baseline 1790000000; done
    sleep 14

    check "alerts filter, one-off-random adds" <<EOF
# EXPLOIT alerts take a device out even when it also sent a DENIAL one; DENIAL alone doesn't
$AP1 out hold=alerts
$AP2 out hold=alerts
$AP3 in by=user
$AP4 in by=user
$CL in by=user
$R1 in by=one-off-random ephemeral
$R2 in by=one-off-random ephemeral
filter alerts removed=2 baseline_active=1
filter one-off-random added=2
saved $AP3 baseline yes
saved $R1 baseline no
EOF
    n=$(grep -c "which was added to the baseline by hand" "$WORK/on/kismet.log")
    [ "$n" = 2 ] && echo "ok   console names both hand-added devices" ||
        { echo "FAIL console: $n hand-added removals reported"; fail=1; }

    # Taking a device out by hand holds it out; adding one by hand lifts a hold, until the
    # filter that took it out matches again
    tag $R1 baseline
    tag $AP2 baseline 1790000000
    sleep 1
    check "hand changes" <<EOF
$R1 out hold=user
$AP2 in by=user hold=-
EOF
    sleep 11
    check "filters respect holds" <<EOF
$R1 out hold=user
$AP2 out hold=alerts
filter alerts removed=3
EOF

    # one-off-random's tag expires a minute after it added R2
    left=$(( t0 + 16 + 60 + 12 - $(date +%s) ))
    [ $left -gt 0 ] && sleep $left
    check "expiry" <<EOF
$R2 out expired=one-off-random
$R1 out hold=user
filter one-off-random expired=1
EOF
    stop
else
    fail=1
fi

# Baseline filters off: nothing runs, and hand changes still work
if start off; then
    tag $AP3 baseline 1790000000
    sleep 13
    check "filters off" <<EOF
$AP1 out hold=-
$AP3 in by=user
$R1 out
filter alerts runs=0 baseline_active=0
filter one-off-random runs=0 baseline_active=0
EOF
    stop
else
    fail=1
fi

[ $fail = 0 ] && echo "PASS" || echo "FAIL"
exit $fail
