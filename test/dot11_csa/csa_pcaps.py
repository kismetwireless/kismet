# Test pcaps (DLT 105) for the 802.11 channel switch alerts: real AP switches, lossy and
# multi-source captures, and spoofed announcements.  Usage: csa_pcaps.py <scenario> <outdir>
# A real AP beacons every 102.4 ms with HT; its TSF and sequence number advance per beacon.
import random, struct, sys

def mac(s): return bytes.fromhex(s.replace(":", ""))
BC = mac("ff:ff:ff:ff:ff:ff")
AP = mac("02:00:00:00:25:a1")
CL = mac("42:00:00:00:25:99")
SSID = b"csa-test"
RATES = b"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"
TU = 1024
BI = 100 * TU          # beacon interval in us
T0 = 1_790_000_000     # capture epoch

def hdr(fc, a1, seq):
    return struct.pack("<BBH", fc, 0, 0) + a1 + AP + AP + struct.pack("<H", (seq & 0xfff) << 4)

def ies(chan, extra=b""):
    ht = b"\x2d\x1a" + bytes(26) + b"\x3d\x16" + bytes([chan]) + bytes(21)
    return b"\x00" + bytes([len(SSID)]) + SSID + RATES + b"\x03\x01" + bytes([chan]) + ht + extra

def csa(ch, count, mode=1): return b"\x25\x03" + bytes([mode, ch, count])
def ecsa(op, ch, count, mode=1): return b"\x3c\x04" + bytes([mode, op, ch, count])

def beacon(tsf, seq, chan, extra=b""):
    return hdr(0x80, BC, seq) + struct.pack("<QHH", tsf, 100, 0x0411) + ies(chan, extra)

def probe_resp(tsf, seq, chan, extra=b""):
    return hdr(0x50, CL, seq) + struct.pack("<QHH", tsf, 100, 0x0411) + ies(chan, extra)

def action_csa(seq, ch, count): return hdr(0xd0, BC, seq) + b"\x00\x04" + csa(ch, count)
def action_ecsa(seq, op, ch, count): return hdr(0xd0, BC, seq) + b"\x04\x04" + bytes([1, op, ch, count])

class AP_:
    """A real AP; time and TSF in us, TSF starts at tsf0 when the capture starts"""
    def __init__(self, tsf0=50_000_000, chan=6):
        self.t = 0; self.tsf = tsf0; self.seq = 0; self.chan = chan
    def beacon(self, extra=b"", chan=None):
        f = (self.t, beacon(self.tsf, self.seq, chan or self.chan, extra))
        self.t += BI; self.tsf += BI; self.seq += 1
        return f

def real_switch(ap, count, to, ecsa_op=None):
    out = [ap.beacon() for _ in range(10)]
    for c in range(count, 0, -1):
        e = csa(to, c) + (ecsa(ecsa_op, to, c) if ecsa_op else b"")
        out.append(ap.beacon(e))
    ap.chan = to
    # right after the switch some APs keep the announcement, now for their own channel
    out += [ap.beacon(csa(to, 0)) for _ in range(2)]
    out += [ap.beacon() for _ in range(10)]
    return out

def lossy(frames, keep, seed):
    r = random.Random(seed)
    return [f for f in frames if r.random() < keep]

def shift(frames, dt):
    return [(t + dt, f) for t, f in frames]

def build(name):
    ap = AP_()
    if name == "realswitch":
        return [real_switch(ap, 10, 11)]
    if name == "realswitch5":
        ap.chan = 36
        return [real_switch(ap, 10, 149, ecsa_op=125)]
    if name == "realecsa":
        return [real_switch(ap, 10, 11, ecsa_op=81)]
    if name == "lossy":
        return [lossy(real_switch(ap, 20, 11), 0.5, 1)]
    if name == "multisource":
        fr = real_switch(ap, 20, 11)
        # two sensors, each missing beacons, the second one's clock 300 ms ahead
        return [lossy(fr, 0.7, 2), shift(lossy(fr, 0.7, 3), 300_000)]
    if name == "probes":
        out = []
        for i in range(10): out.append(ap.beacon())
        for c in range(10, 0, -1):
            out.append(ap.beacon(csa(11, c)))
            # probe responses between beacons carry the current count
            for k in (20_000, 60_000):
                out.append((ap.t - BI + k, probe_resp(ap.tsf - BI + k, ap.seq + 1000 + k, 6, csa(11, c))))
        ap.chan = 11
        out += [ap.beacon() for _ in range(10)]
        return [out]
    if name == "cancel":
        out = [ap.beacon() for _ in range(10)]
        out += [ap.beacon(csa(11, c)) for c in range(20, 15, -1)]
        out += [ap.beacon() for _ in range(5)]                          # cancelled
        out += [ap.beacon(csa(11, c)) for c in range(25, 0, -1)]        # announced again
        ap.chan = 11
        out += [ap.beacon() for _ in range(10)]
        return [lossy(out, 0.8, 4)]
    if name == "reboot":
        out = [ap.beacon() for _ in range(10)]
        out += [ap.beacon(csa(11, c)) for c in range(10, 5, -1)]
        # the AP restarts: 30 s gap, TSF and sequence numbers start over
        ap.t += 30_000_000; ap.tsf = 100_000; ap.seq = 0
        out += [ap.beacon() for _ in range(20)]
        out += [ap.beacon(csa(11, c)) for c in range(10, 0, -1)]
        ap.chan = 11
        out += [ap.beacon() for _ in range(10)]
        return [out]
    if name == "badtsf":
        # an AP whose TSF never advances
        out = []
        for f in real_switch(ap, 10, 11):
            t, b = f
            out.append((t, b[:24] + struct.pack("<Q", 12345) + b[32:]))
        return [out]
    if name == "multicopy":
        # the same frames from two sources with clocks 50 ms apart, including the announcement
        fr = real_switch(ap, 10, 11)
        return [fr, shift(fr, 50_000)]

    # attacks: the real AP beacons for 3 s, the attacker starts after 1 s
    real = [ap.beacon() for _ in range(30)]
    at = 1_000_000
    if name in ("air14", "air11"):
        ch = 14 if name == "air14" else 11
        # aireplay-ng --csa: a captured beacon (frozen TSF) with CSA appended, bursts of 64
        tsf, seq = 50_000_000 + 9 * BI, 9
        out, t = [], at
        for burst in range(5):
            t += 180_000
            for i in range(64):
                out.append((t, beacon(tsf, 3000 + burst * 64 + i, 6, csa(ch, 0)))); t += 2000
        return [real + out]
    if name == "owntsf":
        # a few spoofed beacons with the attacker's own TSF
        return [real + [(at + i * 1000, beacon(99_000_000 + i, 3000 + i, 6, csa(11, 1))) for i in range(3)]]
    if name == "hold":
        # paced at the beacon interval with a plausible TSF, the count stays at 3; the sensor
        # only hears the attacker
        return [[(at + i * BI, beacon(60_000_000 + i * BI, 3000 + i, 6, csa(11, 3))) for i in range(10)]]
    if name == "rise":
        return [[(at + i * BI, beacon(60_000_000 + i * BI, 3000 + i, 6, csa(11, 1 + i))) for i in range(6)]]
    if name == "badchan":
        return [real + [(at + i * 1000, beacon(50_000_000 + at + i * 1000, 3000 + i, 6, csa(36, 1))) for i in range(3)]]
    if name == "crossband":
        return [real + [(at + i * 1000, beacon(50_000_000 + at + i * 1000, 3000 + i, 6, ecsa(115, 36, 1))) for i in range(3)]]
    if name == "actbadchan":
        return [real + [(at + i * 1000, action_csa(3000 + i, 15, 1)) for i in range(3)]]
    if name == "actcrossband":
        return [real + [(at + i * 1000, action_ecsa(3000 + i, 128, 36, 1)) for i in range(3)]]
    if name == "actvalid":
        return [real + [(at + i * 1000, action_csa(3000 + i, 11, 1)) for i in range(3)]]
    if name == "actflood":
        return [real + [(at + i * 20000, action_ecsa(3000 + i, 81, 11, 1)) for i in range(50)]]
    raise SystemExit("unknown scenario " + name)

name, outdir = sys.argv[1], sys.argv[2]
for n, frames in enumerate(build(name)):
    frames = sorted(frames, key=lambda x: x[0])
    with open("%s/%s-%d.pcap" % (outdir, name, n), "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
        for t, p in frames:
            f.write(struct.pack("<IIII", T0 + t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)
    print("%s-%d: %d frames" % (name, n, len(frames)))
