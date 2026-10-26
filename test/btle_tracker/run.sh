#!/bin/bash
# Replay the BTLE tracker test pcap through a Kismet build and check the decoded tracker fields,
# once with the default settings and once with btle_ignore_random=true.
#
# Usage: test/btle_tracker/run.sh [kismet build dir]
# Needs python3 and curl; uses port $BTLE_TRACKER_TEST_PORT (2598 by default) on 127.0.0.1, and
# no remote capture port, log files or plugins, so it can run next to a Kismet server.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd)
PORT=${BTLE_TRACKER_TEST_PORT:-2598}
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

python3 -I "$HERE/tracker_pcaps.py" "$WORK/trackers.pcap" || { echo "FAIL: no pcap"; exit 1; }

check() {
    python3 -c '
import sys, json
ignore_random = sys.argv[1] == "true"
devs = {d["kismet.device.base.macaddr"].lower(): d for d in json.load(sys.stdin)}
want = {
    "c2:00:00:5a:fd:01": {"btle.device.tracker.type": "samsung_smarttag",
        "btle.device.tracker.state": 3, "btle.device.tracker.state_name": "overmature_offline",
        "btle.device.tracker.separated": 1, "btle.device.tracker.battery": "full",
        "btle.device.tracker.uwb": 0, "btle.device.tracker.flags": 3,
        "btle.device.tracker.aging_counter": 0x0102,
        "btle.device.tracker.privacy_id": "1122334455667788"},
    "c2:00:00:5a:fd:02": {"btle.device.tracker.type": "samsung_smarttag",
        "btle.device.tracker.state": 5, "btle.device.tracker.state_name": "connected",
        "btle.device.tracker.separated": 0, "btle.device.tracker.battery": "low",
        "btle.device.tracker.uwb": 1, "btle.device.tracker.flags": 5,
        "btle.device.tracker.aging_counter": 0x0a0b0c,
        "btle.device.tracker.privacy_id": "8877665544332211"},
    "c2:00:00:4c:00:01": {"btle.device.tracker.type": "apple_findmy",
        "btle.device.tracker.state": 0x50, "btle.device.tracker.state_name": "separated",
        "btle.device.tracker.separated": 1, "btle.device.tracker.battery": "medium",
        "btle.device.tracker.flags": 0x50, "btle.device.tracker.subtype": "airtag"},
    "c2:00:00:4c:00:02": {"btle.device.tracker.type": "apple_findmy",
        "btle.device.tracker.state": 0x30, "btle.device.tracker.state_name": "near_owner",
        "btle.device.tracker.separated": 0, "btle.device.tracker.battery": "full",
        "btle.device.tracker.flags": 0x30, "btle.device.tracker.subtype": "airpods"},
    "c2:00:00:aa:fe:01": {"btle.device.tracker.type": "google_fmdn",
        "btle.device.tracker.state": 0x41,
        "btle.device.tracker.state_name": "unwanted_tracking_protection",
        "btle.device.tracker.separated": 0, "btle.device.tracker.battery": "unknown",
        "btle.device.tracker.flags": 0,
        "btle.device.tracker.ephemeral_id": bytes(range(0x10, 0x24)).hex()},
    "c2:00:00:b2:fc:01": {"btle.device.tracker.type": "dult",
        "btle.device.tracker.state": 0, "btle.device.tracker.state_name": "separated",
        "btle.device.tracker.separated": 1, "btle.device.tracker.battery": "unknown",
        "btle.device.tracker.flags": 0, "btle.device.tracker.network_id": 7},
    "c2:00:00:b2:fc:02": {"btle.device.tracker.type": "google_fmdn",
        "btle.device.tracker.state": 0x40, "btle.device.tracker.state_name": "normal",
        "btle.device.tracker.separated": 1, "btle.device.tracker.battery": "unknown",
        "btle.device.tracker.network_id": 2,
        "btle.device.tracker.ephemeral_id": bytes(range(0x10, 0x24)).hex()},
}
# Fields of other tracker types must not show up
absent = {
    "c2:00:00:5a:fd:01": ("subtype", "ephemeral_id", "network_id"),
    "c2:00:00:4c:00:01": ("uwb", "aging_counter", "privacy_id", "ephemeral_id", "network_id"),
    "c2:00:00:aa:fe:01": ("uwb", "aging_counter", "privacy_id", "subtype", "network_id"),
    "c2:00:00:b2:fc:01": ("uwb", "aging_counter", "privacy_id", "subtype", "ephemeral_id"),
}
bad = []
for mac, fields in want.items():
    d = devs.get(mac)
    if d is None:
        bad.append(mac + " missing"); continue
    t = d.get("btle.device", {}).get("btle.device.tracker")
    if not isinstance(t, dict):
        bad.append(mac + " has no tracker record"); continue
    for k, v in fields.items():
        if t.get(k) != v:
            bad.append("%s %s=%r, expected %r" % (mac, k, t.get(k), v))
    for k in absent.get(mac, ()):
        if "btle.device.tracker." + k in t:
            bad.append("%s has %s" % (mac, k))
    if t.get("btle.device.tracker.last_time", 0) <= 0:
        bad.append(mac + " no last_time")
    if d.get("kismet.device.base.type") != "BTLE Tracker":
        bad.append("%s type %r" % (mac, d.get("kismet.device.base.type")))
for mac in ("c2:00:00:5a:fd:03", "c2:00:00:4c:00:03", "c2:00:00:aa:fe:02", "c2:00:00:00:00:99"):
    d = devs.get(mac)
    if ignore_random:
        if d is not None:
            bad.append(mac + " kept with btle_ignore_random")
    elif d is None:
        bad.append(mac + " missing")
    elif "btle.device.tracker" in d.get("btle.device", {}):
        bad.append(mac + " has a tracker record")
print("\n".join(bad))
' "$1"
}

fail=0
for ignore in false true; do
    mkdir -p "$WORK/$ignore/home"
    printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\nenable_logging=false\nhttpd_username=trackertest\nhttpd_password=trackertest\nhelper_binary_path=%s\nbtle_ignore_random=%s\n" \
        "$PORT" "$K" "$ignore" > "$WORK/$ignore/override.conf"

    (cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/$ignore/home" --confdir "$K/conf" \
        --datadir "$K" --no-ncurses --no-plugins --override "$WORK/$ignore/override.conf" \
        -c "$WORK/trackers.pcap:type=pcapfile,realtime=false" > "$WORK/$ignore/kismet.log" 2>&1) &
    pid=$!

    up=0
    for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:$PORT/ && { up=1; break; }; sleep 1; done
    if [ $up = 0 ]; then
        echo "FAIL btle_ignore_random=$ignore: Kismet did not start:"; tail -5 "$WORK/$ignore/kismet.log"
        kill $pid 2>/dev/null; wait $pid 2>/dev/null; fail=1; continue
    fi
    sleep 5

    curl -s -u trackertest:trackertest http://127.0.0.1:$PORT/devices/views/phy-BTLE/devices.json \
        > "$WORK/$ignore/devices.json"
    kill $pid; wait $pid 2>/dev/null

    bad=$(check $ignore < "$WORK/$ignore/devices.json")
    if [ -z "$bad" ]; then
        echo "ok   btle_ignore_random=$ignore"
    else
        echo "FAIL btle_ignore_random=$ignore:"; echo "$bad" | sed 's/^/     /'
        fail=1
    fi
done

exit $fail
