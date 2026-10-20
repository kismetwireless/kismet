#!/bin/bash
# Replay the channel switch test pcaps through a Kismet build and compare the alerts with the
# expected ones.  Each scenario runs in its own Kismet instance, since alerts are throttled by
# wall clock and a replay with realtime=false takes a fraction of a second.
#
# Usage: test/dot11_csa/run.sh [kismet build dir] [scenario...]
# Needs python3 and curl; uses port 2501 on 127.0.0.1.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd); shift
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

# Expected alerts among DOT11CSA*, CHANCHANGE and PROBECHAN
declare -A EXPECT=(
    [realswitch]="CHANCHANGE"           # countdown 10 to 1, then channel 11
    [realswitch5]="CHANCHANGE"          # 36 to 149 with CSA and ECSA
    [realecsa]="CHANCHANGE"             # CSA and ECSA (operating class 81)
    [lossy]="CHANCHANGE"                # half of the beacons missed
    [multisource]="CHANCHANGE"          # two lossy sources, one clock 300 ms ahead
    [probes]="CHANCHANGE"               # probe responses between the countdown beacons
    [cancel]="CHANCHANGE"               # announced, cancelled, announced again with a higher count
    [reboot]="CHANCHANGE"               # the AP restarts mid-countdown, TSF starts over
    [badtsf]="CHANCHANGE"               # an AP whose TSF never advances
    [multicopy]="CHANCHANGE"            # the same frames from two sources
    [air14]="DOT11CSACH14 DOT11CSAFLOOD DOT11CSASPOOF"   # aireplay-ng --csa
    [air11]="DOT11CSAFLOOD DOT11CSASPOOF"                # aireplay-ng --csa --csa-channel 11
    [owntsf]="DOT11CSASPOOF"            # 3 spoofed beacons with the attacker's TSF
    [hold]="DOT11CSASPOOF"              # paced spoofed beacons, count stays at 3
    [rise]="DOT11CSASPOOF"              # count goes up
    [badchan]="DOT11CSASPOOF"           # CSA to 36 from a 2.4 GHz AP
    [crossband]="DOT11CSASPOOF"         # ECSA to the 5 GHz band from a 2.4 GHz AP
    [actbadchan]="DOT11CSASPOOF"        # spectrum management CSA action frame to 15
    [actcrossband]="DOT11CSASPOOF"      # public ECSA action frame to the 5 GHz band
    [actvalid]=""                       # CSA action frames to a valid channel: nothing to judge
    [actflood]="DOT11CSAFLOOD"          # 50 public ECSA action frames in 1 s
)
ORDER="realswitch realswitch5 realecsa lossy multisource probes cancel reboot badtsf multicopy
       air14 air11 owntsf hold rise badchan crossband actbadchan actcrossband actvalid actflood"

printf "httpd_bind_address=127.0.0.1\nhttpd_username=csatest\nhttpd_password=csatest\nhelper_binary_path=%s\n" \
    "$K" > "$WORK/override.conf"

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
    for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:2501/ && { up=1; break; }; sleep 1; done
    if [ $up = 0 ]; then
        echo "FAIL $sc: Kismet did not start:"; tail -5 "$WORK/$sc/kismet.log"
        kill $pid 2>/dev/null; wait $pid 2>/dev/null; fail=1; continue
    fi
    sleep 5

    got=$(curl -s -u csatest:csatest http://127.0.0.1:2501/alerts/all_alerts.json | python3 -c '
import sys, json
names = {a["kismet.alert.header"] for a in json.load(sys.stdin)}
print(" ".join(sorted(n for n in names if n.startswith("DOT11CSA") or n in ("CHANCHANGE", "PROBECHAN"))))')

    kill $pid; wait $pid 2>/dev/null

    want=$(echo ${EXPECT[$sc]} | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
    if [ "$got" = "$want" ]; then
        echo "ok   $sc: ${got:--}"
    else
        echo "FAIL $sc: got '${got}', expected '${want}'"
        fail=1
    fi
done

exit $fail
