# Synthetic Wi-Fi (DLT 105, raw 802.11) and Ethernet (DLT 1) pcaps for linking wired and
# wireless records with the same MAC.  Every address is synthetic: MACs 02:xx (locally
# administered) or 00:00:5e:00:53:xx (documentation, globally administered), IPv4 192.0.2/24
# and 198.51.100/24, the SSID "entity-test".
#
# Usage: wifi_link_pcaps.py <wifi.pcap> <wire.pcap> <manifest.json> [--t0-wifi S] [--t0-wire S]
#
# The air side has an open AP, and:
#   clients    50 radio clients (25 global MACs, 25 local) that associate and send to-DS UDP;
#              all are on the wire, sending ARP with the same IPv4
#   wifionly   20 radio clients that never appear on the wire
#   bridged    10 wired hosts seen as the source of from-DS frames behind the AP; 5 send from
#              the IPv4 they use on the wire, 5 from another one
#   wds        5 wired hosts behind a WDS bridge: the source of 4-address frames from one WDS
#              radio to another
#   probe      3 clients heard only in probe requests, also on the wire
#   mgmtip     3 clients heard only in an association request, leased the IPv4 they use on
#              the wire by a broadcast from-DS DHCP ACK: management-only plus the IPv4 bonus
#              is still a possible link, not linked.  (A probe-only client has no client
#              record to hold an IPv4, and any data frame to or from it makes it associated.)
#   ap         the AP's own MAC also sends ARP on the wire
#   vrrp       a VRRP virtual router MAC on both sides (never linked)
#   hostile    one client's wired DHCP request carries a hostile hostname
# The wire side adds 30 hosts never seen on the air.
#
# The manifest lists each MAC by group with the IPv4 it uses and the expected relationship,
# kind and confidence, for the scenario checks.
import json, os, struct, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ethernet"))
from eth_pcaps import mac, macs, ip4, eth, udp4, arp, dhcp4, client_id, PRL, BC  # noqa: E402

SSID = b"entity-test"
AP = mac("02:00:00:00:a0:01")
WDS_TX = mac("02:00:00:00:a1:01")
WDS_RX = mac("02:00:00:00:a1:02")
VRRP = mac("00:00:5e:00:01:01")
HOSTILE_NAME = b'evil"\\name\x01\x02\x03\x1b[31m\xff\xfe\xc0\x80<x>&]]>'

class pcap:
    def __init__(self, path, dlt, t0):
        self.f = open(path, "wb")
        self.t0 = t0
        self.t = 0
        self.f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, dlt))

    def add(self, frame, dt=2000):
        self.f.write(struct.pack("<IIII", self.t0 + self.t // 1000000, self.t % 1000000, len(frame), len(frame)))
        self.f.write(frame)
        self.t += dt

    def close(self):
        self.f.close()

def ie(eid, data): return bytes([eid, len(data)]) + data

RATES = ie(1, bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]))

def hdr(fc0, fc1, a1, a2, a3, seq, a4=None):
    h = struct.pack("<BBH6s6s6sH", fc0, fc1, 0, a1, a2, a3, (seq & 0xfff) << 4)
    return h + (a4 if a4 is not None else b"")

def beacon(seq):
    body = struct.pack("<QHH", seq * 102400, 100, 0x0001) + ie(0, SSID) + RATES + ie(3, b"\x06")
    return hdr(0x80, 0, BC, AP, AP, seq) + body

def probe_req(src, seq):
    return hdr(0x40, 0, BC, src, BC, seq) + ie(0, b"") + RATES

def assoc_req(src, seq):
    return hdr(0x00, 0, AP, src, AP, seq) + struct.pack("<HH", 0x0001, 10) + ie(0, SSID) + RATES

def assoc_resp(dst, seq, aid):
    return hdr(0x10, 0, dst, AP, AP, seq) + struct.pack("<HHH", 0x0001, 0, 0xc000 | aid) + RATES

SNAP_IP = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"

def to_ds(src, dst, ip_src, ip_dst, seq):
    return hdr(0x08, 0x01, AP, src, dst, seq) + SNAP_IP + udp4(ip_src, ip_dst, 40000, 9, b"entity")

def from_ds(src, dst, ip_src, ip_dst, seq):
    return hdr(0x08, 0x02, dst, AP, src, seq) + SNAP_IP + udp4(ip_src, ip_dst, 9, 40000, b"bridged")

def dhcp_ack_bcast(chaddr, yiaddr, seq):
    ack = dhcp4(2, 5, 0x5000 + seq, chaddr, [(54, ip4("192.0.2.1")), (1, ip4("255.255.255.0"))], yiaddr=yiaddr)
    return hdr(0x08, 0x02, BC, AP, AP, seq) + SNAP_IP + udp4("192.0.2.1", "255.255.255.255", 67, 68, ack)

def four_addr(src, dst, ip_src, ip_dst, seq):
    return hdr(0x08, 0x03, WDS_RX, WDS_TX, dst, seq, a4=src) + SNAP_IP + udp4(ip_src, ip_dst, 9, 40001, b"wds")

def wire_arp(m, ip):
    # Gratuitous reply: sha and spa are the sender's own
    return eth(BC, m, 0x0806, arp(2, m, ip, BC, ip))

def main():
    a = sys.argv[1:]
    if len(a) < 3:
        sys.exit("usage: wifi_link_pcaps.py wifi.pcap wire.pcap manifest.json [--t0-wifi S] [--t0-wire S]")
    t0 = {"--t0-wifi": 1_790_000_000, "--t0-wire": 1_790_000_000}
    i = 3
    while i < len(a):
        if a[i] not in t0 or i + 1 >= len(a):
            sys.exit("unknown or incomplete option %s" % a[i])
        t0[a[i]] = int(a[i + 1])
        i += 2

    air = pcap(a[0], 105, t0["--t0-wifi"])
    wire = pcap(a[1], 1, t0["--t0-wire"])
    man = {"ap": macs(AP), "wds_tx": macs(WDS_TX), "vrrp": macs(VRRP), "groups": {}}
    g = man["groups"]
    seq = 0

    def nseq():
        nonlocal seq
        seq += 1
        return seq

    for k in range(4):
        air.add(beacon(nseq()))

    g["clients"] = []
    for k in range(50):
        m = mac("00:00:5e:00:53:%02x" % (0x10 + k)) if k < 25 else mac("02:00:00:00:c0:%02x" % k)
        ip = "192.0.2.%d" % (10 + k)
        local = k >= 25
        air.add(assoc_req(m, nseq()))
        air.add(assoc_resp(m, nseq(), k + 1))
        for r in range(3):
            air.add(to_ds(m, BC, ip, "192.0.2.255", nseq()))
        wire.add(wire_arp(m, ip))
        g["clients"].append({"mac": macs(m), "ip": ip, "rel": "wired_same_mac", "kind": "client",
            "confidence": (75 if local else 80) + 10, "linked": True})

    # The first client's wired DHCP request carries the hostile hostname
    hm = mac(g["clients"][0]["mac"])
    wire.add(eth(BC, hm, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67,
        dhcp4(1, 3, 0x4242, hm, [(61, client_id(hm)), (12, HOSTILE_NAME), (55, PRL)]))))
    man["hostile_mac"] = macs(hm)

    g["wifionly"] = []
    for k in range(20):
        m = mac("02:00:00:00:d0:%02x" % k)
        air.add(assoc_req(m, nseq()))
        air.add(to_ds(m, BC, "198.51.100.%d" % (10 + k), "198.51.100.255", nseq()))
        g["wifionly"].append({"mac": macs(m)})

    g["bridged"] = []
    for k in range(10):
        m = mac("02:00:00:00:b0:%02x" % k)
        ip = "192.0.2.%d" % (100 + k)
        air_ip = ip if k < 5 else "198.51.100.%d" % (100 + k)
        dst = mac(g["clients"][k]["mac"])
        for r in range(2):
            air.add(from_ds(m, dst, air_ip, g["clients"][k]["ip"], nseq()))
        wire.add(wire_arp(m, ip))
        g["bridged"].append({"mac": macs(m), "ip": ip, "rel": "wired_bridged", "kind": "bridged",
            "confidence": 80 if k < 5 else 70, "linked": True, "via": macs(AP)})

    g["wds"] = []
    for k in range(5):
        m = mac("02:00:00:00:e1:%02x" % k)
        ip = "192.0.2.%d" % (150 + k)
        dst = mac("02:00:00:00:e2:%02x" % k)
        for r in range(2):
            air.add(four_addr(m, dst, "198.51.100.%d" % (150 + k), "198.51.100.%d" % (200 + k), nseq()))
        wire.add(wire_arp(m, ip))
        g["wds"].append({"mac": macs(m), "ip": ip, "rel": "wired_bridged", "kind": "bridged",
            "confidence": 70, "linked": True, "via": macs(WDS_TX)})

    g["probe"] = []
    for k in range(3):
        m = mac("02:00:00:00:f2:%02x" % k)
        air.add(probe_req(m, nseq()))
        wire.add(wire_arp(m, "192.0.2.%d" % (200 + k)))
        g["probe"].append({"mac": macs(m), "rel": "wired_same_mac", "kind": "client_mgmt",
            "confidence": 45, "linked": False})

    # The same IPv4 on both sides adds its bonus, and must still stay under the threshold
    g["mgmtip"] = []
    for k in range(3):
        m = mac("02:00:00:00:f3:%02x" % k)
        ip = "192.0.2.%d" % (210 + k)
        air.add(assoc_req(m, nseq()))
        air.add(dhcp_ack_bcast(m, ip, nseq()))
        wire.add(wire_arp(m, ip))
        g["mgmtip"].append({"mac": macs(m), "ip": ip, "rel": "wired_same_mac", "kind": "client_mgmt",
            "confidence": 55, "linked": False})

    wire.add(wire_arp(AP, "192.0.2.1"))
    g["ap"] = [{"mac": macs(AP), "rel": "wired_same_mac", "kind": "ap", "confidence": 70, "linked": True}]

    air.add(from_ds(VRRP, mac(g["clients"][0]["mac"]), "192.0.2.254", g["clients"][0]["ip"], nseq()))
    wire.add(wire_arp(VRRP, "192.0.2.254"))

    g["wireonly"] = []
    for k in range(30):
        m = mac("02:00:00:00:90:%02x" % k)
        wire.add(wire_arp(m, "198.51.100.%d" % (k + 1)))
        g["wireonly"].append({"mac": macs(m)})

    for k in range(4):
        air.add(beacon(nseq()))

    air.close()
    wire.close()
    with open(a[2], "w") as f:
        json.dump(man, f, indent=1)

if __name__ == "__main__":
    main()
