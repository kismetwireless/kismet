# Test pcaps (DLT 105) for the 802.11 karma / mana detection (DOT11KARMA): karma, loud mana,
# beacon response mode, preloaded SSID pools and multi-source captures, and the benign cases
# that must stay quiet.  Usage: karma_pcaps.py <scenario> <outdir>
# Locally administered MACs and generic SSIDs only.
import struct, sys

def mac(s): return bytes.fromhex(s.replace(":", ""))
BC = mac("ff:ff:ff:ff:ff:ff")
RATES = b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
T0 = 1_790_000_000     # capture epoch
MS = 1000

def dev(n, kind=0x02): return bytes([kind, 0, 0, 0, (n >> 8) & 0xff, n & 0xff])
AP = dev(0x4b01)
AP2 = dev(0x4b02)
AP3 = dev(0x4b03)

class Seq:
    n = 0
    @classmethod
    def next(cls):
        cls.n = (cls.n + 1) & 0xfff
        return cls.n

def hdr(fc, a1, a2, a3):
    return struct.pack("<BBH", fc, 0, 0) + a1 + a2 + a3 + struct.pack("<H", Seq.next() << 4)

def ssid_ie(ssid): return b"\x00" + bytes([len(ssid)]) + ssid

def adv_ies(ssid, chan, extra=b""):
    return ssid_ie(ssid) + RATES + b"\x03\x01" + bytes([chan]) + extra

def fixed(t): return struct.pack("<QHH", 50_000_000 + t, 100, 0x0411)

def beacon(t, bssid, ssid, chan=6, dest=BC, extra=b""):
    return (t, hdr(0x80, dest, bssid, bssid) + fixed(t) + adv_ies(ssid, chan, extra))

def probe_resp(t, bssid, dest, ssid, chan=6, extra=b""):
    return (t, hdr(0x50, dest, bssid, bssid) + fixed(t) + adv_ies(ssid, chan, extra))

def probe_req(t, client, ssid, bssid=BC):
    return (t, hdr(0x40, bssid, client, bssid) + ssid_ie(ssid) + RATES)

def names(prefix, n): return [b"%s-%02d" % (prefix, i) for i in range(n)]

def clients(n): return [dev(0x1000 + i, 0x06) for i in range(n)]

def beacons(bssid, ssid, start, count, step=102_400, **kw):
    return [beacon(start + i * step, bssid, ssid, **kw) for i in range(count)]

def karma(nets, ap=AP, start=0, own=b"karma-own"):
    # each client probes for its home network; the AP answers 5 ms later for every one
    out = beacons(ap, own, start, 30) if own else []
    for i, (c, n) in enumerate(zip(clients(len(nets)), nets)):
        t = start + 200 * MS + i * 300 * MS
        out += [probe_req(t, c, n), probe_resp(t + 5 * MS, ap, c, n)]
    return out

# MBSSID element with nontransmitted profiles (ssid, index); probe responses carry no DTIM
def mbssid(profiles, beacon_frame, n=2):
    body = b""
    for ssid, idx in profiles:
        prof = b"\x53\x02\x11\x04" + ssid_ie(ssid) + (b"\x55\x03" + bytes([idx, 1, 0]) if beacon_frame else b"\x55\x01" + bytes([idx]))
        body += b"\x00" + bytes([len(prof)]) + prof
    return b"\x47" + bytes([1 + len(body), n]) + body

def hosted(bssid, idx, n=2):
    # max BSSID indicator n: the low n bits of the transmitter address plus the index
    m = (1 << n) - 1
    b = bytearray(bssid)
    b[5] = (b[5] & ~m) | ((b[5] + idx) & m)
    return bytes(b)

def pool_beacons(bssid, pool, start, count, step=100 * MS):
    # one SSID per beacon, rotating through the pool (PineAP broadcast pool)
    return [beacon(start + i * step, bssid, pool[i % len(pool)]) for i in range(count)]

def build(name):
    cl = clients(20)
    if name == "karma":
        return [karma(names(b"home", 5))]
    if name == "loudmana":
        # clients probe for their networks; a new client's broadcast probe gets an answer for
        # every one of them, and later clients' broadcast probes the same
        nets = names(b"mana", 6)
        out = beacons(AP, b"mana-own", 0, 30)
        for i, n in enumerate(nets):
            out.append(probe_req(100 * MS + i * 50 * MS, cl[i], n))
        for j in range(3):
            t = 1_000 * MS + j * 500 * MS
            out.append(probe_req(t, cl[10 + j], b""))
            out += [probe_resp(t + (k + 1) * MS, AP, cl[10 + j], n) for k, n in enumerate(nets)]
        return [out]
    if name == "beaconresp":
        # beacon response mode: unicast beacons for the probed name, no probe responses
        nets = names(b"bresp", 4)
        out = beacons(AP, b"bresp-own", 0, 30)
        for i, n in enumerate(nets):
            t = 200 * MS + i * 300 * MS
            out += [probe_req(t, cl[i], n), beacon(t + 3 * MS, AP, n, dest=cl[i])]
        return [out]
    if name == "pool":
        # a preloaded pool answered to broadcast probes; nobody nearby probed for these
        out = []
        for j in range(12):
            t = 100 * MS + j * 100 * MS
            out += [probe_req(t, cl[j], b""), probe_resp(t + 2 * MS, AP, cl[j], b"pool-%02d" % j)]
        return [out]
    if name == "multisource":
        # two sensors, each hearing part of it, the second one's clock 2 s behind; the
        # sources are read in no particular order, and it alerts once
        nets = names(b"multi", 5)
        a, b = beacons(AP, b"multi-own", 0, 10), beacons(AP, b"multi-own", 3_000 * MS, 10)
        for i, n in enumerate(nets):
            t = 3_000 * MS + i * 300 * MS
            a.append(probe_req(t, cl[i], n))
            if i <= 2:
                a.append(probe_resp(t + 5 * MS, AP, cl[i], n))
            if i >= 2:
                b.append(probe_req(t, cl[i], n))
            if i >= 1:
                b.append(probe_resp(t + 5 * MS, AP, cl[i], n))
        b = [(t - 2_000 * MS, f) for t, f in b]
        return [a, b]
    if name == "hostile":
        nets = [b'q"uote', b"<script>", b"x]]>y", b"ctl\x01\x1f\x7f", b"bad\xff\xfeutf8",
                b"A" * 32, b"back\\slash", b"amp&amp;"]
        return [karma(nets)]
    if name == "hidden":
        out = beacons(AP, b"", 0, 30)
        for i in range(10):
            t = 100 * MS + i * 200 * MS
            out += [probe_req(t, cl[i], b"hidden-net"), probe_resp(t + 3 * MS, AP, cl[i], b"hidden-net")]
        return [out]
    if name == "hidden_nul":
        out = beacons(AP, b"\x00" * 10, 0, 30)
        for i in range(10):
            t = 100 * MS + i * 200 * MS
            out += [probe_req(t, cl[i], b"hidden-net2"), probe_resp(t + 3 * MS, AP, cl[i], b"hidden-net2")]
        return [out]
    if name == "mbssid":
        # a transmitter hosting two BSSs; it answers for all three, and the hosted BSSs also
        # answer from their own addresses
        prof = [(b"mb-guest", 1), (b"mb-iot", 2)]
        tx = mac("02:00:00:00:4b:10")
        out = beacons(tx, b"mb-main", 0, 30, extra=mbssid(prof, True))
        for i, n in enumerate([b"mb-main", b"mb-guest", b"mb-iot"] * 2):
            t = 500 * MS + i * 200 * MS
            out.append(probe_req(t, cl[i], n))
            out.append(probe_resp(t + 2 * MS, tx, cl[i], b"mb-main", extra=mbssid(prof, False)))
            if n != b"mb-main":
                idx = 1 if n == b"mb-guest" else 2
                out.append(probe_resp(t + 3 * MS, hosted(tx, idx), cl[i], n))
        return [out]
    if name == "p2p":
        out = []
        for i in range(12):
            t = 100 * MS + i * 100 * MS
            n = b"DIRECT-%02d-Phone" % i
            out += [probe_req(t, cl[i], n), probe_resp(t + 2 * MS, AP, cl[i], n)]
        return [out]
    if name == "mesh":
        meshid = b"\x72\x08mesh-net"
        out = beacons(AP, b"", 0, 30, extra=meshid)
        for i in range(12):
            t = 100 * MS + i * 100 * MS
            out += [probe_req(t, cl[i], b""), probe_resp(t + 2 * MS, AP, cl[i], b"", extra=meshid)]
        return [out]
    if name == "responsesonly":
        # beacons never heard; one network answered
        out = []
        for i in range(10):
            t = 100 * MS + i * 200 * MS
            out += [probe_req(t, cl[i], b"far-net"), probe_resp(t + 2 * MS, AP, cl[i], b"far-net")]
        return [out]
    if name == "latebeacons":
        # three APs heard answering before their beacons; then a fourth network each,
        # beaconed later too
        out = []
        for k, (ap, nets) in enumerate([(AP, [b"late-a", b"late-b"]), (AP2, [b"late-c", b"late-d"]),
                                        (AP3, [b"late-e", b"late-f"])]):
            for i, n in enumerate(nets):
                t = 100 * MS + k * 50 * MS + i * 300 * MS
                out += [probe_req(t, cl[k * 2 + i], n), probe_resp(t + 2 * MS, ap, cl[k * 2 + i], n)]
            for n in nets:
                out += beacons(ap, n, 2_000 * MS + k * 10 * MS, 10)
        # and answering again after the beacons
        for k, (ap, n) in enumerate([(AP, b"late-a"), (AP2, b"late-c"), (AP3, b"late-e")]):
            t = 4_000 * MS + k * 100 * MS
            out += [probe_req(t, cl[k], n), probe_resp(t + 2 * MS, ap, cl[k], n)]
        return [out]
    if name == "legit":
        out = beacons(AP, b"corp-net", 0, 50)
        for i in range(15):
            t = 100 * MS + i * 200 * MS
            out += [probe_req(t, cl[i], b"corp-net"), probe_resp(t + 2 * MS, AP, cl[i], b"corp-net"),
                    probe_req(t + 50 * MS, cl[i], b""), probe_resp(t + 52 * MS, AP, cl[i], b"corp-net")]
        return [out]
    if name == "rename":
        out = beacons(AP, b"old-name", 0, 20)
        out += beacons(AP, b"new-name", 3_000 * MS, 20)
        for i, n in enumerate([b"old-name", b"new-name", b"old-name", b"new-name"]):
            t = 200 * MS + i * 1_000 * MS
            out += [probe_req(t, cl[i], n), probe_resp(t + 2 * MS, AP, cl[i], n)]
        return [out]
    if name in ("cisco", "cisco_ignored"):
        # a multi-SSID AP without MBSSID: hidden beacons, directed probes answered for four
        # networks from one BSSID
        out = beacons(AP, b"", 0, 30)
        for i, n in enumerate(names(b"site", 4) * 2):
            t = 100 * MS + i * 200 * MS
            out += [probe_req(t, cl[i], n), probe_resp(t + 2 * MS, AP, cl[i], n)]
        return [out]
    if name == "evade":
        # karma AP also beaconing NUL padded hidden SSIDs of every length (33 cloaked SSIDs),
        # then answering 8 clients' directed probes: only one hidden SSID is allowed for
        out = []
        for k in range(33):
            out += [beacon(k * 10 * MS + r * MS, AP, b"\x00" * k) for r in range(3)]
        for i, n in enumerate(names(b"evade", 8)):
            t = 1_000 * MS + i * 300 * MS
            out += [probe_req(t, cl[i], n), probe_resp(t + 5 * MS, AP, cl[i], n)]
        return [out]
    if name == "burst":
        # three karma APs turning suspect on consecutive frames, then answering again; the
        # 1/sec alert burst limit holds back all but the first, which alert on later answers
        out = []
        for ap, pfx in ((AP, b"burst-a"), (AP2, b"burst-b"), (AP3, b"burst-c")):
            nets = names(pfx, 5)
            out += karma(nets, ap=ap, own=pfx + b"-own")
            # a different SSID each time, so no answer repeats the last one's tags
            out += [probe_resp(5_000 * MS + i * 100 * MS, ap, cl[0], nets[i % 5]) for i in range(20)]
        return [out]
    if name in ("fill_bcn", "fill_resp"):
        # one BSSID fills its advertised and responded lists with 200 recent SSIDs each, then
        # sends a format string SSID as a beacon or as a probe response: the alerts on a new
        # SSID still run although the SSID isn't kept
        out = []
        for i in range(200):
            out += [beacon(i * 5 * MS, AP, b"fill-b-%03d" % i),
                    probe_resp(i * 5 * MS + 1, AP, cl[0], b"fill-r-%03d" % i)]
        for r in range(3):
            t = 1_500 * MS + r * 100 * MS
            if name == "fill_bcn":
                out.append(beacon(t, AP, b"bcn%n%n"))
            else:
                out.append(probe_resp(t + 1, AP, cl[0], b"rsp%s%s"))
        return [out]
    if name == "bpool":
        # 40 pool SSIDs broadcast-beaconed from one BSSID, nobody answered
        return [pool_beacons(AP, names(b"bpool", 40), 0, 600)]
    if name == "bpool_hostile":
        nets = [b'q"uote', b"<script>", b"x]]>y", b"ctl\x01\x1f\x7f", b"bad\xff\xfeutf8",
                b"A" * 32, b"back\\slash", b"amp&amp;", b"\xc0\x80over", b"\xf4\x90\x80\x80hi",
                b"\xf5lead", b"pct%s%n"]
        return [pool_beacons(AP, nets, 0, 240)]
    if name == "bpool_karma":
        # pool and karma from the start: each probed name is answered and joins the pool
        # beacons right away, so every answered SSID is also beaconed
        pool = names(b"bpk", 40)
        homes = names(b"bpk-home", 5)
        out = []
        for i, (c, n) in enumerate(zip(clients(5), homes)):
            t = 200 * MS + i * 300 * MS
            out += [probe_req(t, c, n), probe_resp(t + 5 * MS, AP, c, n)]
        out += pool_beacons(AP, homes + pool, 0, 600)
        return [out]
    if name == "karma_bpool":
        # karma first, then the answered names and a pool beaconed: the answers still count
        homes = names(b"kbp-home", 5)
        out = karma(homes, own=None)
        out += pool_beacons(AP, homes + names(b"kbp", 20), 5_000 * MS, 600)
        return [out]
    if name == "pool9":
        # one BSSID beaconing 9 SSIDs: under dot11_karma_min_pool
        return [pool_beacons(AP, names(b"nine", 9), 0, 600)]
    if name == "threebss":
        # three BSSIDs, one SSID each
        out = []
        for k, ap in enumerate((AP, AP2, AP3)):
            out += beacons(ap, b"three-%d" % k, k * 7 * MS, 300)
        return [out]
    if name == "rename2":
        # renamed twice, beacons changing their other tags too
        out = beacons(AP, b"name-one", 0, 100)
        out += beacons(AP, b"name-two", 20_000 * MS, 100, chan=11)
        out += beacons(AP, b"name-three", 40_000 * MS, 100, chan=1)
        return [out]
    if name == "hiddenmix":
        # zero length and NUL padded hidden SSIDs of 32 lengths from one BSSID
        out = []
        for i in range(330):
            out.append(beacon(i * 100 * MS, AP, b"\x00" * (i % 33)))
        return [out]
    if name == "ciscomulti":
        # one radio, 8 BSSIDs each beaconing its own SSID, with the same BSS timestamps
        out = []
        for k in range(8):
            ap = dev(0x4b20 + k)
            out += beacons(ap, b"site-ssid-%d" % k, k * MS, 200)
        return [out]
    if name == "mbssid8":
        # a transmitter hosting 8 nontransmitted BSSs (max BSSID indicator 4), answering for
        # its own network; the hosted BSSs answer for theirs
        prof = [(b"mb8-prof-%d" % i, i) for i in range(1, 9)]
        tx = mac("02:00:00:00:4b:30")
        out = beacons(tx, b"mb8-main", 0, 300, extra=mbssid(prof, True, 4))
        for i, (n, idx) in enumerate(prof):
            t = 500 * MS + i * 200 * MS
            out.append(probe_req(t, cl[i], n))
            out.append(probe_resp(t + 2 * MS, tx, cl[i], b"mb8-main", extra=mbssid(prof, False, 4)))
            out.append(probe_resp(t + 3 * MS, hosted(tx, idx, 4), cl[i], n))
        return [out]
    if name == "earlyresp":
        # an AP answering for its own network before its first beacon is heard, then
        # beaconing it and answering 2000 more probes for it
        out = [probe_req(0, cl[0], b"early-own"), probe_resp(5 * MS, AP, cl[0], b"early-own")]
        out += beacons(AP, b"early-own", 1_000 * MS, 300)
        for i in range(2000):
            t = 2_000 * MS + i * 10 * MS
            out += [probe_req(t, cl[i % 20], b"early-own"), probe_resp(t + 2 * MS, AP, cl[i % 20], b"early-own")]
        return [out]
    if name == "mbssidresp":
        # a hosted BSS with karma state (two names answered from its own address), then its
        # transmitter answering 200 probes with the same tags: the repeats use the cached
        # hosted record, which is refreshed and never parsed again
        prof = [(b"mbr-guest", 1)]
        tx = mac("02:00:00:00:4b:40")
        out = beacons(tx, b"mbr-main", 0, 30, extra=mbssid(prof, True))
        for i, n in enumerate(names(b"mbr-x", 2)):
            out.append(probe_resp(500 * MS + i * 100 * MS, hosted(tx, 1), cl[i], n))
        for i in range(200):
            out.append(probe_resp(1_000 * MS + i * 100 * MS, tx, cl[i % 20], b"mbr-main",
                extra=mbssid(prof, False)))
        return [out]
    if name in ("bafter", "bafter8", "bfirst", "bfirst8"):
        # each probed name answered and broadcast-beaconed once, after the answer or before
        # it: the beaconed names make a pool, which 40 reach and 8 don't
        n = 8 if name.endswith("8") else 40
        out = beacons(AP, b"karma-own", 0, 30)
        for i, (c, s) in enumerate(zip(clients(n), names(b"home", n))):
            t = 200 * MS + i * 300 * MS
            out.append(probe_req(t, c, s))
            if name.startswith("bfirst"):
                out += [beacon(t + 2 * MS, AP, s), probe_resp(t + 5 * MS, AP, c, s)]
            else:
                out += [probe_resp(t + 5 * MS, AP, c, s), beacon(t + 6 * MS, AP, s)]
        return [out]
    if name == "corrupt":
        # an AP's own SSID with a bit flipped in 20 of its beacons, each flip a different one
        out = beacons(AP, b"corrupt-own", 0, 600)
        for i in range(20):
            s = bytearray(b"corrupt-own")
            s[i % len(s)] ^= 1 << (i // len(s) + 1)
            out.append(beacon(1_000 * MS + i * 1_500 * MS + 50 * MS, AP, bytes(s)))
        return [out]
    if name == "repeatresp":
        # karma answering each name twice with the same tags, the client's probe only near the
        # second answer: the repeated response, from the cached tags, still matches it
        out = beacons(AP, b"karma-own", 0, 30)
        for i, n in enumerate(names(b"home", 3)):
            t = 1_000 * MS + i * 200_000 * MS
            out += [probe_resp(t, AP, cl[10], n), probe_req(t + 100_000 * MS, cl[i], n),
                    probe_resp(t + 100_005 * MS, AP, cl[i], n)]
        return [out]
    if name == "corrupt10":
        # a renamed AP, its new SSID with a bit flipped in 10 beacons, each flip a different one
        out = beacons(AP, b"first-name", 0, 100) + beacons(AP, b"corrupt-ten", 20_000 * MS, 600)
        for i in range(10):
            s = bytearray(b"corrupt-ten")
            s[i] ^= 0x02
            out.append(beacon(21_000 * MS + i * 1_500 * MS + 50 * MS, AP, bytes(s)))
        return [out]
    if name in ("rr100", "rr1000", "rr1000long"):
        # a PineAP pool bigger than the SSID lists: one SSID per beacon at 10 beacons/s, each
        # repeated only once the round robin comes back to it; the long one for 20 minutes
        n = 100 if name == "rr100" else 1000
        secs = {"rr100": 200, "rr1000": 500, "rr1000long": 1200}[name]
        return [pool_beacons(AP, [b"rr-%04d" % i for i in range(n)], 0, secs * 10)]
    if name == "norecord":
        # normal APs: a renamed one, a hidden one beaconing its name too, and one SSID with a
        # bit flipped once, each answering for its own name
        out = beacons(AP, b"old-name", 0, 30) + beacons(AP, b"new-name", 4_000 * MS, 30)
        for i in range(30):
            out += [beacon(i * 102_400, AP2, b""), beacon(i * 102_400 + 50 * MS, AP2, b"named-net")]
        out += beacons(AP3, b"plain-net", 0, 60)
        out.append(beacon(2_000 * MS + 50 * MS, AP3, b"plain-nev"))
        for i, (ap, n) in enumerate([(AP, b"new-name"), (AP2, b"named-net"), (AP3, b"plain-net")] * 2):
            t = 5_000 * MS + i * 200 * MS
            out += [probe_req(t, cl[i], n), probe_resp(t + 2 * MS, ap, cl[i], n)]
        return [out]
    if name == "perf_pool":
        # a pool of 128 SSIDs at 10 beacons/s, 100k beacons
        return [pool_beacons(AP, [b"perfpool-%03d" % i for i in range(128)], 0, 100_000)]
    if name == "perf":
        # loud mana worst case: 200 clients probing for 1000 networks, 100k directed probes
        # each answered, and 20 broadcast probes each answered with all 1000 networks
        many = clients(200)
        nets = [b"perf-%04d" % i for i in range(1000)]
        out = beacons(AP, b"perf-own", 0, 100)
        t = 0
        for i in range(100_000):
            c = i % 200
            n = nets[(c * 5 + (i // 200) % 5) % 1000]
            t += 200
            out += [probe_req(t, many[c], n), probe_resp(t + 50, AP, many[c], n)]
            if i % 5000 == 0:
                out.append(probe_req(t + 60, many[c], b""))
                out += [probe_resp(t + 61 + k, AP, many[c], m) for k, m in enumerate(nets)]
        return [out]
    if name == "perf_flood":
        # forged probe responses from one BSSID, every one for a new SSID
        many = clients(200)
        out = beacons(AP, b"perf-own", 0, 100)
        for i in range(100_000):
            out.append(probe_resp(i * 200, AP, many[i % 200], b"flood-%06d" % i))
        return [out]
    if name == "perf_quiet":
        # the same volume of probes answered by a legitimate AP for its own network
        many = clients(200)
        out = beacons(AP, b"perf-own", 0, 100)
        t = 0
        for i in range(100_000):
            t += 200
            out += [probe_req(t, many[i % 200], b"perf-own"), probe_resp(t + 50, AP, many[i % 200], b"perf-own")]
        return [out]
    raise SystemExit("unknown scenario " + name)

name, outdir = sys.argv[1], sys.argv[2]
for n, frames in enumerate(build(name)):
    frames = sorted(frames, key=lambda x: x[0])
    with open("%s/%s-%d.pcap" % (outdir, name, n), "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
        for t, p in frames:
            f.write(struct.pack("<IIII", T0 + t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)
    print("%s-%d: %d frames" % (name, n, len(frames)))
