#!/bin/bash
# Replay the karma / mana test pcaps through a Kismet build and check the DOT11KARMA alerts and
# the phydot11_karma view against the expected ones.  Each scenario runs in its own Kismet
# instance; every JSON reply is parsed as strict UTF-8.
#
# Usage: test/dot11_karma/run.sh [kismet build dir] [scenario...]
# Needs python3, curl and ss; uses port $KARMA_TEST_PORT (2615 by default) on 127.0.0.1, and
# no remote capture port or log files, so it can run next to a Kismet server.  Work files go
# under $TMPDIR; set KEEP=1 to keep them.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd) || exit 1
shift
PORT=${KARMA_TEST_PORT:-2615}

port_busy() {
    ss -ltn 2>/dev/null | grep -q "[:.]$PORT " || curl -s -o /dev/null "http://127.0.0.1:$PORT/"
}

if port_busy; then
    echo "port $PORT is already in use; set KARMA_TEST_PORT to a free port"
    exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/karma-test.XXXXXX") || exit 1
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

# Suspected karma APs expected per scenario (DOT11KARMA alerts and view entries)
expect() {
    case "$1" in
        karma)          echo 1 ;;   # directed probes for 5 networks, each answered
        loudmana)       echo 1 ;;   # broadcast probes answered with the networks others probed for
        beaconresp)     echo 1 ;;   # unicast beacons for the probed names
        pool)           echo 1 ;;   # 12 preloaded names nobody probed for
        multisource)    echo 1 ;;   # two sensors, skewed clocks, read in any order
        hostile)        echo 1 ;;   # karma answering hostile SSIDs
        cisco)          echo 1 ;;   # hidden multi-SSID AP without MBSSID: expected to alert
        evade)          echo 1 ;;   # 33 NUL padded hidden SSIDs don't hide 8 matched answers
        burst)          echo 3 ;;   # three suspects at once, rate limited alerts raised later
        fill_bcn)       echo 1 ;;   # full SSID lists: karma and new SSID alerts still run
        fill_resp)      echo 1 ;;
        cisco_ignored)  echo 0 ;;   # the same, listed in dot11_karma_ignore_bssids
        hidden)         echo 0 ;;   # zero length hidden SSID
        hidden_nul)     echo 0 ;;   # NUL padded hidden SSID
        mbssid)         echo 0 ;;   # transmitter and hosted BSSs answering for their own
        p2p)            echo 0 ;;   # DIRECT- names
        mesh)           echo 0 ;;   # mesh, no SSID
        responsesonly)  echo 0 ;;   # one network answered, beacons never heard
        latebeacons)    echo 0 ;;   # answers heard before the beacons
        legit)          echo 0 ;;   # an AP answering for its own network
        rename)         echo 0 ;;   # a renamed AP answering for both names
    esac
}
ORDER="karma loudmana beaconresp pool multisource hostile cisco evade burst fill_bcn fill_resp
       cisco_ignored hidden hidden_nul mbssid p2p mesh responsesonly latebeacons legit rename"

extra() {
    case "$1" in
        cisco_ignored)  echo "dot11_karma_ignore_bssids=02:00:00:00:4b:01" ;;
    esac
}

# Source options: burst is read slowly enough for the alert rate limit to let alerts through
# (pps only applies without realtime)
srcopt() {
    case "$1" in
        burst)          echo "pps=20" ;;
        *)              echo "realtime=false" ;;
    esac
}

# Other alerts a scenario must raise
needalert() {
    case "$1" in
        fill_bcn|fill_resp) echo "FORMATSTRING" ;;
    esac
}

fail=0
for sc in ${@:-$ORDER}; do
    mkdir -p "$WORK/$sc/home"
    python3 -I "$HERE/karma_pcaps.py" "$sc" "$WORK/$sc" > /dev/null || { echo "$sc: no pcap"; fail=1; continue; }

    # Scenario lines first: the first copy of a key in an override file wins
    { extra "$sc"
      printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\nenable_logging=false\nhttpd_username=karmatest\nhttpd_password=karmatest\nhelper_binary_path=%s\n" \
        "$PORT" "$K"; } > "$WORK/$sc/override.conf"

    src=()
    npcap=0
    for f in "$WORK/$sc"/*.pcap; do
        src+=(-c "$f:type=pcapfile,$(srcopt "$sc")")
        npcap=$((npcap + 1))
    done

    (cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/$sc/home" --confdir "$K/conf" \
        --datadir "$K" --no-ncurses --override "$WORK/$sc/override.conf" "${src[@]}" \
        > "$WORK/$sc/kismet.log" 2>&1 < /dev/null) &
    pid=$!

    # Wait until every pcap has been read
    done_reading=0
    for i in $(seq 1 240); do
        kill -0 $pid 2>/dev/null || break
        if [ "$(grep -c "end of pcapfile reached" "$WORK/$sc/kismet.log")" -ge $npcap ]; then
            done_reading=1
            break
        fi
        sleep 0.5
    done
    if [ $done_reading = 0 ] || ! curl -s -o /dev/null "http://127.0.0.1:$PORT/"; then
        echo "FAIL $sc: Kismet did not start or read its sources:"; tail -5 "$WORK/$sc/kismet.log"
        kill $pid 2>/dev/null; wait $pid 2>/dev/null; fail=1; continue
    fi
    sleep 2

    curl -s -u karmatest:karmatest -o "$WORK/$sc/alerts.json" http://127.0.0.1:$PORT/alerts/all_alerts.json
    curl -s -u karmatest:karmatest -o "$WORK/$sc/view.json" \
        http://127.0.0.1:$PORT/devices/views/phydot11_karma/last-time/0/devices.json
    curl -s -u karmatest:karmatest -o "$WORK/$sc/devices.json" \
        http://127.0.0.1:$PORT/devices/views/all/last-time/0/devices.json

    kill $pid; wait $pid 2>/dev/null

    got=$(python3 -I - "$WORK/$sc" "$(needalert "$sc")" <<'EOF'
import json, sys
def load(p):
    with open(p, "rb") as f:
        return json.loads(f.read().decode("utf-8", "strict"),
                parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
d = sys.argv[1]
all_alerts = load(d + "/alerts.json")
alerts = [a for a in all_alerts if a["kismet.alert.header"] == "DOT11KARMA"]
view = load(d + "/view.json")
devs = load(d + "/devices.json")
suspect = [v for v in view if v.get("dot11.device", {}).get("dot11.device.karma", {}).get("dot11.karma.suspect") == 1]
flagged = [v for v in devs if v.get("dot11.device", {}).get("dot11.device.karma", {}).get("dot11.karma.suspect") == 1]
wifi = [v for v in devs if "dot11.device" in v]
missing = [h for h in sys.argv[2].split() if not any(a["kismet.alert.header"] == h for a in all_alerts)]
print("%d %d %d %d %d %s" % (len(alerts), len(view), len(suspect), len(flagged), len(wifi),
        ",".join(missing) or "-"))
EOF
)
    [ -n "$got" ] || got="invalid-json"

    want=$(expect "$sc")
    read -r na nv ns nf nwifi missing <<< "$got"
    if [ "$na $nv $ns $nf" = "$want $want $want $want" ] && [ "${nwifi:-0}" -gt 0 ] 2>/dev/null &&
            [ "$missing" = "-" ]; then
        echo "ok   $sc: alerts/view/suspect/flagged $na $nv $ns $nf, $nwifi Wi-Fi devices"
    else
        echo "FAIL $sc: alerts/view/suspect/flagged/devices/missing alerts '$got', expected $want each, devices > 0, no missing alerts"
        fail=1
    fi
done

exit $fail
