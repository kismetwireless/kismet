#!/bin/bash
# Replay the channel switch test pcaps through a Kismet build and compare the alerts with the
# expected ones.  Each scenario runs in its own Kismet instance, since alerts are throttled by
# wall clock and a replay with realtime=false takes a fraction of a second.
#
# Usage: test/dot11_csa/run.sh [kismet build dir] [scenario...]
# Needs python3 and curl; uses port $CSA_TEST_PORT (2599 by default) on 127.0.0.1, and no
# remote capture port or log files, so it can run next to a Kismet server.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd); shift
PORT=${CSA_TEST_PORT:-2599}
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

# Expected alerts among DOT11CSA*, CHANCHANGE and PROBECHAN; a case statement rather than an
# associative array, so it runs on the bash 3.2 macOS ships
expect() {
    case "$1" in
        realswitch)    echo "CHANCHANGE" ;;   # countdown 10 to 1, then channel 11
        realswitch5)   echo "CHANCHANGE" ;;   # 36 to 149 with CSA and ECSA
        realecsa)      echo "CHANCHANGE" ;;   # CSA and ECSA (operating class 81)
        lossy)         echo "CHANCHANGE" ;;   # half of the beacons missed
        multisource)   echo "CHANCHANGE" ;;   # two lossy sources, one clock 300 ms ahead
        probes)        echo "CHANCHANGE" ;;   # probe responses between the countdown beacons
        cancel)        echo "CHANCHANGE" ;;   # announced, cancelled, announced again with a higher count
        reboot)        echo "CHANCHANGE" ;;   # the AP restarts mid-countdown, TSF starts over
        badtsf)        echo "CHANCHANGE" ;;   # an AP whose TSF never advances
        multicopy)     echo "CHANCHANGE" ;;   # the same frames from two sources
        air14)         echo "DOT11CSACH14 DOT11CSAFLOOD DOT11CSASPOOF" ;;   # aireplay-ng --csa
        air11)         echo "DOT11CSAFLOOD DOT11CSASPOOF" ;;   # aireplay-ng --csa --csa-channel 11
        owntsf)        echo "DOT11CSASPOOF" ;;   # 3 spoofed beacons with the attacker's TSF
        hold)          echo "DOT11CSASPOOF" ;;   # paced spoofed beacons, count stays at 3
        rise)          echo "DOT11CSASPOOF" ;;   # count goes up
        badchan)       echo "DOT11CSASPOOF" ;;   # CSA to 36 from a 2.4 GHz AP
        crossband)     echo "DOT11CSASPOOF" ;;   # ECSA to the 5 GHz band from a 2.4 GHz AP
        actbadchan)    echo "DOT11CSASPOOF" ;;   # spectrum management CSA action frame to 15
        actcrossband)  echo "DOT11CSASPOOF" ;;   # public ECSA action frame to the 5 GHz band
        actvalid)      echo "" ;;   # CSA action frames to a valid channel: nothing to judge
        actflood)      echo "DOT11CSAFLOOD" ;;   # 50 public ECSA action frames in 1 s
        poison_owntsf) echo "DOT11CSASPOOF" ;;   # owntsf after one copied beacon
        poison_air11)  echo "DOT11CSAFLOOD DOT11CSASPOOF" ;;   # air11 after one copied beacon
        poison_hold)   echo "DOT11CSASPOOF" ;;   # hold after two beacons sharing a TSF
    esac
}
ORDER="realswitch realswitch5 realecsa lossy multisource probes cancel reboot badtsf multicopy
       air14 air11 owntsf hold rise badchan crossband actbadchan actcrossband actvalid actflood
       poison_owntsf poison_air11 poison_hold"

printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\nenable_logging=false\nhttpd_username=csatest\nhttpd_password=csatest\nhelper_binary_path=%s\n" \
    "$PORT" "$K" > "$WORK/override.conf"

fail=0
for sc in ${@:-$ORDER}; do
    mkdir -p "$WORK/$sc/home"
    python3 -I "$HERE/csa_pcaps.py" "$sc" "$WORK/$sc" > /dev/null || { echo "$sc: no pcap"; fail=1; continue; }

    src=()
    for f in "$WORK/$sc"/*.pcap; do src+=(-c "$f:type=pcapfile,realtime=false"); done

    (cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/$sc/home" --confdir "$K/conf" \
        --datadir "$K" --no-ncurses --override "$WORK/override.conf" "${src[@]}" > "$WORK/$sc/kismet.log" 2>&1) &
    pid=$!

    up=0
    for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:$PORT/ && { up=1; break; }; sleep 1; done
    if [ $up = 0 ]; then
        echo "FAIL $sc: Kismet did not start:"; tail -5 "$WORK/$sc/kismet.log"
        kill $pid 2>/dev/null; wait $pid 2>/dev/null; fail=1; continue
    fi
    sleep 5

    got=$(curl -s -u csatest:csatest http://127.0.0.1:$PORT/alerts/all_alerts.json | python3 -c '
import sys, json
names = {a["kismet.alert.header"] for a in json.load(sys.stdin)}
print(" ".join(sorted(n for n in names if n.startswith("DOT11CSA") or n in ("CHANCHANGE", "PROBECHAN"))))')

    kill $pid; wait $pid 2>/dev/null

    want=$(echo $(expect "$sc") | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
    if [ "$got" = "$want" ]; then
        echo "ok   $sc: ${got:--}"
    else
        echo "FAIL $sc: got '${got}', expected '${want}'"
        fail=1
    fi
done

exit $fail
