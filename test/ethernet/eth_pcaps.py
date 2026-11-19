# Synthetic Ethernet test pcaps for the IEEE802.3 phy.  Every address is from a documentation
# range or locally administered: MACs 02:xx or 00:00:5e:00:53:xx, IPv4 192.0.2/24,
# 198.51.100/24 and 203.0.113/24, IPv6 2001:db8::/32, names under example.com.
#
# Usage: eth_pcaps.py <scenario> <out.pcap> [--dlt 1|113|276] [--count N] [--rate N]
#                     [--manifest out.json]
#
# Scenarios:
#   mixed    one of each: untagged, 802.1Q, QinQ (0x88a8 and 0x9100 outer), priority VID 0,
#            3 and 5 tags, ARP, DHCPv4 DORA (options 12 55 60 61 81, overload 52), DHCPv6,
#            IPv4 with options, IPv6 with extension headers, TCP and UDP
#   hostile  DHCP and DHCPv6 names with quotes, control characters, invalid UTF-8 and
#            censor marker bytes, and malformed lengths
#   flood    --count random source MACs (default 40000) at --rate new MACs per second of
#            capture time (default 1000), each to a random destination MAC
#   scale    --count hosts (default 20000), each with a DHCP request (hostname, options)
#            and an ARP reply
#   perf     --count frames (default 1000000) of TCP/UDP/ARP traffic among 256 hosts,
#            one frame per microsecond
#
# --manifest writes the fields of each frame as the generator built them, for
# check_tshark.py to compare with tshark's decode.
import json, random, struct, sys

T0 = 1_790_000_000

def mac(s): return bytes.fromhex(s.replace(":", ""))
def macs(b): return ":".join("%02x" % x for x in b)
def ip4(s): return bytes(int(x) for x in s.split("."))
def ip6(s):
    import ipaddress
    return ipaddress.IPv6Address(s).packed

BC = mac("ff:ff:ff:ff:ff:ff")
CLIENT = mac("02:00:00:00:e0:01")
SERVER = mac("00:00:5e:00:53:01")
ROUTER = mac("00:00:5e:00:53:fe")
HOST2 = mac("02:00:00:00:e0:02")
HOST3 = mac("02:00:00:00:e0:03")

def csum(b):
    if len(b) & 1:
        b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

# Ethernet with a tag stack of (tpid, pcp, vid), outermost first
def eth(dst, src, etype, payload, tags=()):
    h = dst + src
    for tpid, pcp, vid in tags:
        h += struct.pack("!HH", tpid, (pcp << 13) | (vid & 0xfff))
    return h + struct.pack("!H", etype) + payload

def ipv4(src, dst, proto, payload, options=b"", ttl=64, ident=1, frag=0x4000):
    if len(options) % 4:
        raise ValueError("IPv4 options must be padded to 4 bytes")
    ihl = 5 + len(options) // 4
    h = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, ihl * 4 + len(payload), ident, frag, ttl, proto,
            0, ip4(src), ip4(dst)) + options
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return h + payload

def l4sum4(src, dst, proto, seg):
    return csum(ip4(src) + ip4(dst) + struct.pack("!BBH", 0, proto, len(seg)) + seg)

def l4sum6(src, dst, proto, seg):
    return csum(ip6(src) + ip6(dst) + struct.pack("!IxxxB", len(seg), proto) + seg)

def udp(sport, dport, payload, sumf):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    c = sumf(17, seg) or 0xffff
    return seg[:6] + struct.pack("!H", c) + seg[8:]

def tcp(sport, dport, seq, ack, flags, sumf, payload=b"", opts=b""):
    off = 5 + len(opts) // 4
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off << 4, flags, 65535, 0, 0) + opts + payload
    c = sumf(6, seg)
    return seg[:16] + struct.pack("!H", c) + seg[18:]

def udp4(src, dst, sport, dport, payload, **kw):
    return ipv4(src, dst, 17, udp(sport, dport, payload, lambda p, s: l4sum4(src, dst, p, s)), **kw)

def tcp4(src, dst, sport, dport, seq, ack, flags, payload=b"", **kw):
    return ipv4(src, dst, 6, tcp(sport, dport, seq, ack, flags, lambda p, s: l4sum4(src, dst, p, s),
        payload), **kw)

# IPv6 with extension headers [(type, body)], each body padded to 8-byte units by the caller
# except the fragment header (type 44, 6 bytes of body)
def ipv6(src, dst, nh, payload, ext=(), hlim=64):
    chain = b""
    types = [e[0] for e in ext] + [nh]
    for i, (t, body) in enumerate(ext):
        nxt = types[i + 1]
        if t == 44:
            chain += struct.pack("!BB", nxt, 0) + body
        else:
            hl = (len(body) + 2) // 8 - 1
            chain += struct.pack("!BB", nxt, hl) + body
    first = types[0]
    return struct.pack("!IHBB16s16s", 0x60000000, len(chain) + len(payload), first, hlim,
            ip6(src), ip6(dst)) + chain + payload

PADN4 = b"\x01\x04\x00\x00\x00\x00"   # PadN filling a 6-byte option area

def arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, sha, ip4(spa), tha, ip4(tpa))

def opt(code, data): return bytes([code, len(data)]) + data

def dns_name(name):
    out = b""
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"

def dhcp4(op, msgtype, xid, chaddr, options, ciaddr="0.0.0.0", yiaddr="0.0.0.0",
        siaddr="0.0.0.0", sname=b"", file=b""):
    body = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000,
            ip4(ciaddr), ip4(yiaddr), ip4(siaddr), ip4("0.0.0.0"), chaddr + bytes(10),
            sname.ljust(64, b"\x00"), file.ljust(128, b"\x00"))
    o = b"\x63\x82\x53\x63" + opt(53, bytes([msgtype]))
    for code, data in options:
        o += opt(code, data)
    return body + o + b"\xff"

def client_id(m): return b"\x01" + m
def fqdn81(name): return b"\x05\x00\x00" + dns_name(name)
PRL = bytes([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252])

def duid_llt(m): return struct.pack("!HHI", 1, 1, 700000000) + m

def dhcp6(msgtype, xid, options):
    o = b""
    for code, data in options:
        o += struct.pack("!HH", code, len(data)) + data
    return bytes([msgtype]) + xid.to_bytes(3, "big") + o

class pcap:
    def __init__(self, path, dlt):
        self.f = open(path, "wb")
        self.dlt = dlt
        self.f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, dlt))
        self.n = 0

    def write(self, t_us, frame):
        self.f.write(struct.pack("<IIII", T0 + t_us // 1000000, t_us % 1000000, len(frame), len(frame)))
        self.f.write(frame)
        self.n += 1

    def close(self):
        self.f.close()

# Wrap an Ethernet frame for the output DLT.  SLL and SLL2 keep only the source address and a
# packet type; tags after the first stay inline in the payload, as libpcap delivers them.
def link(dlt, frame, outgoing=False):
    # runts go out as they are, too short for any link header
    if dlt == 1 or len(frame) < 14:
        return frame
    dst, src, rest = frame[:6], frame[6:12], frame[12:]
    if dst == BC:
        ptype = 1
    elif dst[0] & 1:
        ptype = 2
    else:
        ptype = 4 if outgoing else 0
    proto = struct.unpack("!H", rest[:2])[0]
    payload = rest[2:]
    if dlt == 113:
        return struct.pack("!HHH8sH", ptype, 1, 6, src + b"\x00\x00", proto) + payload
    if dlt == 276:
        return struct.pack("!HHIHBB8s", proto, 0, 2, 1, ptype, 6, src + b"\x00\x00") + payload
    raise ValueError("unsupported dlt")

class out:
    def __init__(self, path, dlt, manifest):
        self.p = pcap(path, dlt)
        self.dlt = dlt
        self.manifest = [] if manifest else None
        self.t = 0

    def add(self, frame, info=None, dt=1000, outgoing=False):
        self.p.write(self.t, link(self.dlt, frame, outgoing))
        if self.manifest is not None:
            self.manifest.append(info or {})
        self.t += dt

# Expected decode of one frame, for check_tshark.py; only the keys present are compared
def info(src, dst=None, vlans=(), **kw):
    d = {"src": macs(src)}
    if dst is not None:
        d["dst"] = macs(dst)
    if vlans:
        d["vlans"] = list(vlans)
    d.update(kw)
    return d

def scen_mixed(o):
    c4 = lambda f, i: o.add(f, i)
    # plain untagged UDP and TCP
    c4(eth(HOST2, HOST3, 0x0800, udp4("192.0.2.3", "192.0.2.2", 40000, 53, b"\x12\x34" + bytes(10))),
            info(HOST3, HOST2, ip_src="192.0.2.3", ip_dst="192.0.2.2", udp_sport=40000, udp_dport=53))
    for flags, a, b, s, d, sp, dp in ((0x02, HOST2, HOST3, "192.0.2.2", "192.0.2.3", 50000, 80),
            (0x12, HOST3, HOST2, "192.0.2.3", "192.0.2.2", 80, 50000),
            (0x10, HOST2, HOST3, "192.0.2.2", "192.0.2.3", 50000, 80),
            (0x18, HOST2, HOST3, "192.0.2.2", "192.0.2.3", 50000, 80),
            (0x11, HOST3, HOST2, "192.0.2.3", "192.0.2.2", 80, 50000)):
        c4(eth(b, a, 0x0800, tcp4(s, d, sp, dp, 1000, 2000, flags, b"GET" if flags == 0x18 else b"")),
                info(a, b, ip_src=s, ip_dst=d, tcp_sport=sp, tcp_dport=dp, tcp_flags=flags))

    # 802.1Q, priority tagged VID 0, QinQ with both outer TPIDs, 3 tags, 5 tags (too deep)
    c4(eth(BC, HOST2, 0x0806, arp(1, HOST2, "198.51.100.2", bytes(6), "198.51.100.1"), [(0x8100, 0, 10)]),
            info(HOST2, BC, [10], arp_op=1, arp_spa="198.51.100.2", arp_tpa="198.51.100.1"))
    c4(eth(HOST2, ROUTER, 0x0806, arp(2, ROUTER, "198.51.100.1", HOST2, "198.51.100.2"), [(0x8100, 0, 10)]),
            info(ROUTER, HOST2, [10], arp_op=2, arp_spa="198.51.100.1", arp_tpa="198.51.100.2"))
    c4(eth(HOST3, HOST2, 0x0800, udp4("198.51.100.2", "198.51.100.3", 1234, 5678, b"pcp"), [(0x8100, 5, 0)]),
            info(HOST2, HOST3, [0], ip_src="198.51.100.2", udp_dport=5678))
    c4(eth(HOST3, HOST2, 0x0800, udp4("203.0.113.2", "203.0.113.3", 41111, 42221, b"qinq"),
        [(0x88a8, 0, 100), (0x8100, 0, 20)]),
            info(HOST2, HOST3, [100, 20], ip_src="203.0.113.2", udp_dport=42221))
    c4(eth(HOST3, HOST2, 0x0800, udp4("203.0.113.2", "203.0.113.3", 41111, 42223, b"qinq9100"),
        [(0x9100, 0, 200), (0x8100, 0, 30)]),
            info(HOST2, HOST3, [200, 30], ip_src="203.0.113.2", udp_dport=42223))
    c4(eth(HOST3, HOST2, 0x0800, udp4("203.0.113.2", "203.0.113.3", 41111, 42224, b"three"),
        [(0x88a8, 0, 300), (0x8100, 0, 40), (0x8100, 0, 41)]),
            info(HOST2, HOST3, [300, 40, 41], ip_src="203.0.113.2", udp_dport=42224))
    c4(eth(HOST3, HOST2, 0x0800, udp4("203.0.113.2", "203.0.113.3", 41111, 42225, b"five"),
        [(0x88a8, 0, 400), (0x8100, 0, 50), (0x8100, 0, 51), (0x8100, 0, 52), (0x8100, 0, 53)]),
            info(HOST2, HOST3, [400, 50, 51, 52, 53], deep_tags=True))

    # ARP on the untagged LAN
    c4(eth(BC, CLIENT, 0x0806, arp(1, CLIENT, "0.0.0.0", bytes(6), "192.0.2.10")),
            info(CLIENT, BC, arp_op=1, arp_spa="0.0.0.0", arp_tpa="192.0.2.10"))
    c4(eth(BC, ROUTER, 0x0806, arp(1, ROUTER, "192.0.2.1", bytes(6), "192.0.2.1")),
            info(ROUTER, BC, arp_op=1, arp_spa="192.0.2.1", arp_tpa="192.0.2.1"))

    # DHCPv4: discover, offer (unicast), request with FQDN, ack
    xid = 0x11223344
    copts = [(61, client_id(CLIENT)), (12, b"client-one"), (60, b"example-vendor 1.0"), (55, PRL)]
    c4(eth(BC, CLIENT, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, dhcp4(1, 1, xid, CLIENT, copts))),
            info(CLIENT, BC, dhcp_type=1, dhcp_hostname="client-one", dhcp_vendor="example-vendor 1.0",
                dhcp_prl=list(PRL)))
    sopts = [(54, ip4("192.0.2.254")), (51, struct.pack("!I", 3600)), (1, ip4("255.255.255.0")),
            (3, ip4("192.0.2.1")), (6, ip4("192.0.2.53"))]
    c4(eth(CLIENT, SERVER, 0x0800, udp4("192.0.2.254", "192.0.2.10", 67, 68,
        dhcp4(2, 2, xid, CLIENT, sopts, yiaddr="192.0.2.10", siaddr="192.0.2.254"))),
            info(SERVER, CLIENT, dhcp_type=2, dhcp_yiaddr="192.0.2.10"))
    ropts = copts + [(50, ip4("192.0.2.10")), (54, ip4("192.0.2.254")), (81, fqdn81("client-one.example.com"))]
    c4(eth(BC, CLIENT, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, dhcp4(1, 3, xid, CLIENT, ropts))),
            info(CLIENT, BC, dhcp_type=3, dhcp_hostname="client-one", dhcp_fqdn="client-one.example.com"))
    c4(eth(CLIENT, SERVER, 0x0800, udp4("192.0.2.254", "192.0.2.10", 67, 68,
        dhcp4(2, 5, xid, CLIENT, sopts, yiaddr="192.0.2.10", siaddr="192.0.2.254"))),
            info(SERVER, CLIENT, dhcp_type=5, dhcp_yiaddr="192.0.2.10"))

    # DHCPv4 option overload: the hostname lives in the file field, the vendor class in sname
    c4(eth(BC, HOST3, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67,
        dhcp4(1, 3, 0x55667788, HOST3, [(61, client_id(HOST3)), (52, b"\x03")],
            file=opt(12, b"overload-host") + b"\xff", sname=opt(60, b"overload-vendor") + b"\xff"))),
            info(HOST3, BC, dhcp_type=3, dhcp_hostname="overload-host", dhcp_vendor="overload-vendor"))

    # IPv4 with options: router alert (IHL 6) and a full record route (IHL 15)
    c4(eth(HOST3, HOST2, 0x0800, udp4("192.0.2.2", "192.0.2.3", 7000, 7001, b"ra",
        options=b"\x94\x04\x00\x00")),
            info(HOST2, HOST3, ip_src="192.0.2.2", ip_hl=24, udp_sport=7000, udp_dport=7001))
    rr = b"\x07\x27\x04" + bytes(36) + b"\x00"
    c4(eth(HOST3, HOST2, 0x0800, tcp4("192.0.2.2", "192.0.2.3", 7002, 7003, 1, 0, 0x02, options=rr)),
            info(HOST2, HOST3, ip_src="192.0.2.2", ip_hl=60, tcp_sport=7002, tcp_dport=7003))

    # DHCPv6 solicit, advertise, request, reply
    v6c, v6s = "fe80::ff:fe00:e001", "fe80::5eff:fe00:5301"
    s6 = lambda p, s: l4sum6(v6c, "ff02::1:2", p, s)
    xid6 = 0xabcdef
    o6 = [(1, duid_llt(CLIENT)), (8, b"\x00\x00"), (6, b"\x00\x17\x00\x18\x00\x27"),
            (39, b"\x01" + dns_name("client-six.example.com")), (16, struct.pack("!IH", 311, 9) + b"vendor-v6")]
    m6 = mac("33:33:00:01:00:02")
    c4(eth(m6, CLIENT, 0x86dd, ipv6(v6c, "ff02::1:2", 17, udp(546, 547, dhcp6(1, xid6, o6), s6))),
            info(CLIENT, m6, ipv6_src=v6c, udp_dport=547, dhcpv6_type=1, dhcpv6_fqdn="client-six.example.com"))
    sid = (2, duid_llt(SERVER))
    ia = (3, struct.pack("!III", 1, 1800, 2880) + struct.pack("!HH16sII", 5, 24, ip6("2001:db8::100"), 3600, 7200))
    s6s = lambda p, s: l4sum6(v6s, v6c, p, s)
    c4(eth(CLIENT, SERVER, 0x86dd, ipv6(v6s, v6c, 17, udp(547, 546, dhcp6(2, xid6, [sid, (1, duid_llt(CLIENT)), ia]), s6s))),
            info(SERVER, CLIENT, ipv6_src=v6s, dhcpv6_type=2))
    c4(eth(m6, CLIENT, 0x86dd, ipv6(v6c, "ff02::1:2", 17, udp(546, 547, dhcp6(3, xid6 + 1, o6 + [sid, ia]), s6))),
            info(CLIENT, m6, dhcpv6_type=3))
    c4(eth(CLIENT, SERVER, 0x86dd, ipv6(v6s, v6c, 17, udp(547, 546, dhcp6(7, xid6 + 1, [sid, (1, duid_llt(CLIENT)), ia]), s6s))),
            info(SERVER, CLIENT, dhcpv6_type=7))

    # IPv6 with extension headers: hop-by-hop + routing + destination options, then TCP;
    # a first fragment carrying UDP; a later fragment; a chain of 10 destination options
    a6, b6 = "2001:db8::2", "2001:db8::3"
    t6 = lambda p, s: l4sum6(a6, b6, p, s)
    rh = struct.pack("!BBxxxx", 0, 0) + bytes(16)   # type 0, segments left 0, one address
    hbh = PADN4
    seg = tcp(6000, 443, 5, 0, 0x02, t6)
    c4(eth(HOST3, HOST2, 0x86dd, ipv6(a6, b6, 6, seg, ext=[(0, hbh), (43, rh), (60, PADN4)])),
            info(HOST2, HOST3, ipv6_src=a6, ipv6_dst=b6, tcp_sport=6000, tcp_dport=443))
    useg = udp(6001, 9999, b"frag-first-part", t6)
    c4(eth(HOST3, HOST2, 0x86dd, ipv6(a6, b6, 17, useg, ext=[(44, struct.pack("!HI", 0x0001, 0x1234))])),
            info(HOST2, HOST3, ipv6_src=a6, udp_sport=6001, udp_dport=9999, frag=True))
    c4(eth(HOST3, HOST2, 0x86dd, ipv6(a6, b6, 17, b"later-fragment-bytes", ext=[(44, struct.pack("!HI", 0x0100, 0x1234))])),
            info(HOST2, HOST3, ipv6_src=a6, frag=True))
    deep = [(60, PADN4)] * 10
    c4(eth(HOST3, HOST2, 0x86dd, ipv6(a6, b6, 17, udp(6002, 9998, b"deep", t6), ext=deep)),
            info(HOST2, HOST3, ipv6_src=a6, deep_ext=True))

    # Something with an ethertype nobody parses, and a jumbo-ish UDP frame
    c4(eth(BC, HOST2, 0x88b5, b"local experimental ethertype"), info(HOST2, BC))
    c4(eth(HOST3, HOST2, 0x0800, udp4("192.0.2.2", "192.0.2.3", 8000, 8001, bytes(1400))),
            info(HOST2, HOST3, udp_sport=8000, udp_dport=8001))

# Censor marker bytes (censor.h span_open, span_value, span_close) around a fake span
CENSOR_MARKS = b"\x01name\x02hidden\x03 and \x03\x02\x01"

def scen_hostile(o):
    names = [b'quote"name\\slash', b"ctl\x01\x07\x1f\x7fname", b"bad\xff\xfe\xc3(utf8", b"<tag>&amp;]]>",
            CENSOR_MARKS, b"=cmd|' /C calc'!A0", b"a" * 255, b"\x00nul-first", b"multi\x00nul"]
    for i, n in enumerate(names):
        m = mac("02:00:00:00:f0:%02x" % i)
        xid = 0x1000 + i
        opts = [(61, client_id(m)), (12, n), (60, n[:200]), (55, PRL), (81, b"\x05\x00\x00" + n[:60])]
        o.add(eth(BC, m, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, dhcp4(1, 3, xid, m, opts))),
                info(m, BC, dhcp_type=3, hostile=True))
        v6 = "fe80::ff:fe00:f0%02x" % i
        s6 = lambda p, s, v6=v6: l4sum6(v6, "ff02::1:2", p, s)
        o6 = [(1, duid_llt(m)), (39, b"\x01" + bytes([min(len(n), 63)]) + n[:63] + b"\x00")]
        o.add(eth(mac("33:33:00:01:00:02"), m, 0x86dd, ipv6(v6, "ff02::1:2", 17, udp(546, 547, dhcp6(1, xid, o6), s6))),
                info(m, hostile=True))

    m = mac("02:00:00:00:f1:01")
    # DHCP option lengths running past the end, a zero-length option, an overload loop,
    # a DNS name with a forward pointer and with a pointer loop in option 81
    bad = dhcp4(1, 1, 0x2000, m, [(12, b"ok-before-bad"), (0x99, b"")])[:-1] + b"\x0c\x40short"
    o.add(eth(BC, m, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, bad)), info(m, hostile=True))
    loop = dhcp4(1, 1, 0x2001, m, [(52, b"\x03")], file=opt(52, b"\x03") + b"\xff", sname=opt(52, b"\x01") + b"\xff")
    o.add(eth(BC, m, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, loop)), info(m, hostile=True))
    ptr = dhcp4(1, 1, 0x2002, m, [(81, b"\x05\x00\x00\xc0\x03"), (81, b"\x05\x00\x00\x03abc\xc0\x03")])
    o.add(eth(BC, m, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, ptr)), info(m, hostile=True))
    # IHL past the frame, IPv4 total length larger than the frame, an ARP with odd lengths
    v4 = bytearray(udp4("192.0.2.9", "192.0.2.10", 1, 2, b"x"))
    v4[0] = 0x4f
    o.add(eth(HOST3, m, 0x0800, bytes(v4)[:30]), info(m, hostile=True))
    v4 = bytearray(udp4("192.0.2.9", "192.0.2.10", 1, 2, b"x"))
    v4[2:4] = b"\xff\xff"
    o.add(eth(HOST3, m, 0x0800, bytes(v4)), info(m, hostile=True))
    o.add(eth(BC, m, 0x0806, struct.pack("!HHBBH", 1, 0x0800, 255, 255, 1) + bytes(20)), info(m, hostile=True))
    # Runt frames
    o.add(eth(BC, m, 0x0800, b""), info(m, hostile=True))
    o.add(m[:5], {})

def scen_flood(o, count, rate):
    r = random.Random(7)
    dt = max(1, 1000000 // max(1, rate))
    seen = set()
    for i in range(count):
        while True:
            s = bytes([0x02] + [r.randrange(256) for _ in range(5)])
            if s not in seen:
                seen.add(s)
                break
        d = bytes([0x02] + [r.randrange(256) for _ in range(5)])
        o.add(eth(d, s, 0x0800, udp4("198.51.100.%d" % (i % 250 + 1), "203.0.113.%d" % (i % 250 + 1),
            9, 9, b"flood")), info(s, d), dt=dt)

DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")

def scen_scale(o, count):
    for i in range(count):
        m = bytes([0x02, 0x00]) + struct.pack("!I", 0x100000 + i)
        hn = b"host-%06d" % i
        opts = [(61, client_id(m)), (12, hn), (60, b"example-os 1"), (55, PRL)]
        o.add(eth(BC, m, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, dhcp4(1, 3, i, m, opts))),
                info(m, BC, dhcp_type=3), dt=100)
        # only 762 documentation addresses, so they repeat past that
        a = DOC_NETS[(i // 254) % 3] + ".%d" % (i % 254 + 1)
        o.add(eth(BC, m, 0x0806, arp(1, m, a, bytes(6), a)), info(m, BC), dt=100)

def scen_perf(o, count):
    hosts = [bytes([0x02, 0x00, 0x00, 0x00, 0x01, i]) for i in range(256)]
    r = random.Random(11)
    frames = []
    for k in range(4096):
        a, b = r.randrange(256), r.randrange(256)
        if a == b:
            b = (b + 1) & 0xff
        sa, sb = "192.0.2.%d" % a, "198.51.100.%d" % b
        kind = k % 8
        if kind < 5:
            f = eth(hosts[b], hosts[a], 0x0800, tcp4(sa, sb, 30000 + k, 443, k, k, 0x18, bytes(r.randrange(0, 400))))
        elif kind < 7:
            f = eth(hosts[b], hosts[a], 0x0800, udp4(sa, sb, 40000 + k, 53, bytes(r.randrange(20, 400))))
        else:
            f = eth(BC, hosts[a], 0x0806, arp(1, hosts[a], sa, bytes(6), sb), [(0x8100, 0, 10 + (k % 4))])
        frames.append(f)
    for i in range(count):
        o.add(frames[i % len(frames)], None, dt=1)

def main():
    a = sys.argv[1:]
    if len(a) < 2:
        sys.stderr.write(__doc__ if __doc__ else "usage: eth_pcaps.py scenario out.pcap\n")
        sys.exit(2)
    scen, path = a[0], a[1]
    kw = {"--dlt": "1", "--count": None, "--rate": "1000", "--manifest": None}
    i = 2
    while i < len(a):
        if a[i] not in kw or i + 1 >= len(a):
            sys.exit("unknown or incomplete option %s" % a[i])
        kw[a[i]] = a[i + 1]
        i += 2
    dlt = int(kw["--dlt"])
    if dlt not in (1, 113, 276):
        sys.exit("dlt must be 1, 113 or 276")
    o = out(path, dlt, kw["--manifest"] is not None)
    if scen == "mixed":
        scen_mixed(o)
    elif scen == "hostile":
        scen_hostile(o)
    elif scen == "flood":
        scen_flood(o, int(kw["--count"] or 40000), int(kw["--rate"]))
    elif scen == "scale":
        scen_scale(o, int(kw["--count"] or 20000))
    elif scen == "perf":
        scen_perf(o, int(kw["--count"] or 1000000))
    else:
        sys.exit("unknown scenario " + scen)
    o.p.close()
    if kw["--manifest"]:
        with open(kw["--manifest"], "w") as f:
            json.dump({"dlt": dlt, "frames": o.manifest}, f)
    print(o.p.n)

if __name__ == "__main__":
    main()
