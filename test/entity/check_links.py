# Checks a Kismet server that read the wifi_link_pcaps.py captures: the links, their evidence,
# both records' entity ids and related devices, the wired record reachable from the Wi-Fi one,
# a device rule on the entity id, and refused API input.  python3 -I.
#
# Usage: check_links.py <url> <creds file> <manifest.json>
import base64, json, sys, urllib.error, urllib.parse, urllib.request

fails = 0

def report(ok, what):
    global fails
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        fails += 1

def strict(body):
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate key " + k)
            d[k] = v
        return d
    def no_const(c):
        raise ValueError("non-finite " + c)
    return json.loads(body.decode("utf-8", errors="strict"), object_pairs_hook=no_dupes, parse_constant=no_const)

class api:
    def __init__(self, url, creds):
        self.url = url
        with open(creds) as f:
            self.auth = "Basic " + base64.b64encode(f.read().strip().encode()).decode()

    def req(self, path, form=None):
        data = None
        if form is not None:
            data = urllib.parse.urlencode({"json": json.dumps(form)}).encode()
        r = urllib.request.Request(self.url + path, data=data, headers={"Authorization": self.auth})
        try:
            with urllib.request.urlopen(r, timeout=20) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def get(self, path, form=None):
        st, body = self.req(path, form)
        if st != 200:
            raise RuntimeError("%s: HTTP %d %r" % (path, st, body[:200]))
        return strict(body)

def main():
    if len(sys.argv) != 4:
        sys.exit("usage: check_links.py url creds manifest.json")
    url, creds, manifest = sys.argv[1:4]
    a = api(url, creds)
    with open(manifest) as f:
        man = json.load(f)

    st = a.get("/entities/status.json")
    report(st.get("kismet.entity.status.enabled") == 1, "status: linking enabled")

    edges = a.get("/entities/edges.json?length=1000")
    by_mac = {}
    for e in edges["kismet.entity.edges"]:
        by_mac.setdefault(e["kismet.entity.edge.macaddr"].upper(), []).append(e)
    report(edges["kismet.entity.total"] == len(edges["kismet.entity.edges"]), "edges: total %d = returned" % edges["kismet.entity.total"])

    def devs_of(m):
        ds = a.get("/devices/by-mac/%s/devices.json" % m)
        out = {}
        for d in ds:
            out[d["kismet.device.base.phyname"]] = d
        return out

    for g, rows in man["groups"].items():
        for r in rows:
            m = r["mac"].upper()
            es = by_mac.get(m, [])
            if "rel" not in r:
                report(not es, "%s %s: no link" % (g, m))
                continue
            if len(es) != 1:
                report(False, "%s %s: %d links, expected 1" % (g, m, len(es)))
                continue
            e = es[0]
            got = (e["kismet.entity.edge.relationship"], e["kismet.entity.edge.wifi_kind"],
                    e["kismet.entity.edge.confidence"], bool(e["kismet.entity.edge.linked"]))
            want = (r["rel"], r["kind"], r["confidence"], r["linked"])
            report(got == want, "%s %s: %s (want %s) evidence %s" % (g, m, got, want,
                ",".join(e["kismet.entity.edge.evidence_names"])))
            if "via" in r:
                via = [v.upper() for v in e["kismet.entity.edge.via"]]
                report(r["via"].upper() in via, "%s %s: via %s in %s" % (g, m, r["via"], via))

            ds = devs_of(m)
            w, l = ds.get("IEEE802.11"), ds.get("IEEE802.3")
            if w is None or l is None:
                report(False, "%s %s: both records present" % (g, m))
                continue
            wid = w.get("kismet.device.base.entity_id", 0)
            lid = l.get("kismet.device.base.entity_id", 0)
            rel = r["rel"]
            wrel = w.get("kismet.device.base.related_devices", {}).get(rel, {})
            lrel = l.get("kismet.device.base.related_devices", {}).get(rel, {})
            if r["linked"]:
                report(wid != 0 and wid == lid, "%s %s: shared entity id %d/%d" % (g, m, wid, lid))
                report(l["kismet.device.base.key"] in wrel and w["kismet.device.base.key"] in lrel,
                        "%s %s: related devices %s both ways" % (g, m, rel))
            else:
                report(wid == 0 and lid == 0 and not wrel and not lrel, "%s %s: possible link only, not grouped" % (g, m))

    vr = man["vrrp"].upper()
    report(vr not in by_mac, "vrrp %s: no link" % vr)

    # The wire as seen from the Wi-Fi record: the hostile client's wired record, DHCP name and all
    hm = man["hostile_mac"].upper()
    ds = devs_of(hm)
    wk = ds["IEEE802.11"]["kismet.device.base.key"]
    lk = a.get("/entities/by-device/%s/linked.json" % wk)
    es = lk["kismet.entity.edges"]
    ok = len(es) == 1 and len(es[0]["kismet.entity.edge.peer"]) == 1
    report(ok, "linked.json: one link with the peer record")
    if ok:
        peer = es[0]["kismet.entity.edge.peer"][0]
        report(peer["kismet.device.base.phyname"] == "IEEE802.3", "linked.json: peer is the Ethernet record")
        eth = peer.get("ethernet.device", {})
        report(bool(eth.get("ethernet.device.ipv4")), "linked.json: peer carries the wired IPv4 list")
        report("ethernet.device.dhcp" in json.dumps(eth) or "dhcp" in json.dumps(eth).lower(),
                "linked.json: peer carries the DHCP data")
        report(lk["kismet.entity.entity_id"] == ds["IEEE802.11"].get("kismet.device.base.entity_id"),
                "linked.json: entity id matches the record")

    lk = a.get("/entities/by-device/%s/linked.json" % ds["IEEE802.3"]["kismet.device.base.key"],
            {"fields": ["kismet.entity.entity_id"]})
    report(list(lk.keys()) == ["kismet.entity.entity_id"], "linked.json: field simplification")

    sub = a.get("/entities/edges.json?min_confidence=85&length=1000")
    n85 = sum(1 for e in edges["kismet.entity.edges"] if e["kismet.entity.edge.confidence"] >= 85)
    report(sub["kismet.entity.total"] == n85, "edges: min_confidence=85 total %d = %d" % (sub["kismet.entity.total"], n85))
    sub = a.get("/entities/edges.json?mac=%s" % hm)
    report(sub["kismet.entity.total"] == 1, "edges: mac filter")
    sub = a.get("/entities/edges.json?start=5&length=3")
    report(len(sub["kismet.entity.edges"]) == 3 and sub["kismet.entity.start"] == 5, "edges: paging")
    sub = a.get("/entities/edges.json", {"length": 2, "min_confidence": 50})
    report(len(sub["kismet.entity.edges"]) == 2, "edges: json body parameters")

    rules = 'rule linked { when exists(kismet.device.base.entity_id) tag "linked" }'
    for phy, want in (("IEEE802.11", True), ("IEEE802.3", True)):
        res = a.get("/devices/rules/test.cmd", {"rules": rules, "device": ds[phy]["kismet.device.base.key"]})
        report(res.get("matches", {}).get("linked") is want, "device rule exists(entity_id) on %s" % phy)
    only = devs_of(man["groups"]["wireonly"][0]["mac"].upper())["IEEE802.3"]
    res = a.get("/devices/rules/test.cmd", {"rules": rules, "device": only["kismet.device.base.key"]})
    report(res.get("matches", {}).get("linked") is False, "device rule exists(entity_id) false when unlinked")

    bad = [
        "/entities/by-device/garbage/linked.json",
        "/entities/by-device/%s/linked.json" % ("A" * 200),
        "/entities/by-device/%25%00%0a/linked.json",
        "/entities/edges.json?mac=zz:zz",
        "/entities/edges.json?mac=" + "0" * 40,
        "/entities/edges.json?mac=01:02:03:04:05:06:07:08",
        "/entities/edges.json?length=0",
        "/entities/edges.json?length=5000",
        "/entities/edges.json?min_confidence=101",
        "/entities/edges.json?start=99999999",
        "/entities/edges.json?length=-1",
        "/entities/edges.json?length=1e9",
    ]
    for p in bad:
        st, body = a.req(p)
        report(400 <= st < 600 and st != 200 and len(body) < 4096, "refused %s: HTTP %d" % (p, st))
    st, body = a.req("/entities/edges.json", {"length": [1]})
    report(st != 200, "refused json length array: HTTP %d" % st)
    st, body = a.req("/entities/edges.json", {"length": -3})
    report(st != 200, "refused json length -3: HTTP %d" % st)

    # Unknown but well-formed key: an empty answer, not an error
    st, body = a.req("/entities/by-device/00000000_0000000000000000/linked.json")
    report(st == 200 and strict(body)["kismet.entity.edges"] == [], "unknown key: HTTP %d, no links" % st)

    st = a.get("/entities/status.json")
    print("status", json.dumps(st, sort_keys=True))
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
