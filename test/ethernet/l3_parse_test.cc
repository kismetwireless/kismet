/* Tests for kis_l3_parse (the wired frame decoder) and wired_flow_tracker.
 *
 *   make test/ethernet/l3_parse_test && test/ethernet/l3_parse_test
 *
 * Every frame is also decoded at every captured length below its full length, which under
 * ASan/UBSan shows any read past the captured bytes.
 */

#include "config.h"

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "kis_l3_parse.h"
#include "unordered_dense.h"
#include "wired_flow_tracker.h"

using namespace kis_l3;
using bytes = std::vector<uint8_t>;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static void put16(bytes& b, size_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xff));
}
static void put32(bytes& b, uint32_t v) { put16(b, v >> 16); put16(b, v & 0xffff); }
static void put(bytes& b, const bytes& v) { b.insert(b.end(), v.begin(), v.end()); }
static void puts_(bytes& b, const char *s) { b.insert(b.end(), s, s + strlen(s)); }

static const bytes mac_a{0x02, 0, 0, 0, 0xe0, 0x01};
static const bytes mac_b{0x02, 0, 0, 0, 0xe0, 0x02};
static const bytes bcast(6, 0xff);

static bytes eth(const bytes& dst, const bytes& src, std::vector<std::pair<unsigned, unsigned>> tags,
        unsigned type, const bytes& payload) {
    bytes b;
    put(b, dst);
    put(b, src);
    for (auto [tpid, tci] : tags) {
        put16(b, tpid);
        put16(b, tci);
    }
    put16(b, type);
    put(b, payload);
    return b;
}

static bytes ipv4(const bytes& src, const bytes& dst, uint8_t proto, const bytes& payload,
        const bytes& opts = {}, int total_override = -1, unsigned frag = 0x4000) {
    bytes b;
    const size_t ihl = 5 + opts.size() / 4;
    b.push_back(static_cast<uint8_t>(0x40 | ihl));
    b.push_back(0);
    put16(b, total_override >= 0 ? total_override : ihl * 4 + payload.size());
    put16(b, 1);
    put16(b, frag);
    b.push_back(64);
    b.push_back(proto);
    put16(b, 0);
    put(b, src);
    put(b, dst);
    put(b, opts);
    put(b, payload);
    return b;
}

static bytes udp(unsigned sport, unsigned dport, const bytes& payload) {
    bytes b;
    put16(b, sport);
    put16(b, dport);
    put16(b, 8 + payload.size());
    put16(b, 0);
    put(b, payload);
    return b;
}

static bytes tcp(unsigned sport, unsigned dport, uint8_t flags) {
    bytes b;
    put16(b, sport);
    put16(b, dport);
    put32(b, 1);
    put32(b, 0);
    b.push_back(0x50);
    b.push_back(flags);
    put16(b, 65535);
    put16(b, 0);
    put16(b, 0);
    return b;
}

static bytes opt(uint8_t code, const bytes& d) {
    bytes b{code, static_cast<uint8_t>(d.size())};
    put(b, d);
    return b;
}

static bytes str(const char *s) { return bytes(s, s + strlen(s)); }

static bytes dhcp4(uint8_t op, uint8_t type, const bytes& chaddr, const bytes& opts,
        const bytes& yiaddr = {0, 0, 0, 0}, const bytes& sname = {}, const bytes& file = {}) {
    bytes b{op, 1, 6, 0};
    put32(b, 0x11223344);
    put16(b, 0);
    put16(b, 0x8000);
    put(b, bytes(4));
    put(b, yiaddr);
    put(b, bytes(8));
    put(b, chaddr);
    put(b, bytes(10));
    bytes sn = sname; sn.resize(64);
    bytes fl = file; fl.resize(128);
    put(b, sn);
    put(b, fl);
    put32(b, 0x63825363);
    put(b, opt(53, {type}));
    put(b, opts);
    b.push_back(255);
    return b;
}

static bytes dns(const char *name) {
    bytes b;
    std::string n(name);
    size_t p = 0;
    while (p < n.size()) {
        auto d = n.find('.', p);
        if (d == std::string::npos)
            d = n.size();
        b.push_back(static_cast<uint8_t>(d - p));
        b.insert(b.end(), n.begin() + p, n.begin() + d);
        p = d + 1;
    }
    b.push_back(0);
    return b;
}

static frame parse(int dlt, const bytes& b) {
    frame f;
    parse_frame(dlt, b.data(), b.size(), f);
    // and every shorter capture of it
    for (size_t l = 0; l < b.size(); l++) {
        frame t;
        std::vector<uint8_t> cut(b.begin(), b.begin() + l);
        parse_frame(dlt, cut.empty() ? nullptr : cut.data(), cut.size(), t);
        if (t.dhcp4.hostname.len > max_opt_string || t.dhcp4.fqdn.len > max_dns_name)
            failures++;
    }
    return f;
}

static ip_addr v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    ip_addr r;
    r.family = 4;
    r.a[0] = a; r.a[1] = b; r.a[2] = c; r.a[3] = d;
    return r;
}

static void test_l2() {
    const bytes s{192, 0, 2, 1}, d{192, 0, 2, 2};
    auto f = parse(1, eth(mac_b, mac_a, {}, 0x0800, ipv4(s, d, 17, udp(1000, 2000, str("x")))));
    CHECK(f.l2_ok && f.has_dst && f.dclass == dst_class::unicast);
    CHECK(f.n_tags == 0 && f.ethertype == 0x0800 && f.l3 == l3_type::ipv4);
    CHECK(f.l4_ok && f.sport == 1000 && f.dport == 2000 && f.ip_proto == 17);
    CHECK(f.src[5] == 0x01 && f.dst[5] == 0x02 && f.errors == 0);

    f = parse(1, eth(bcast, mac_a, {{0x8100, 0xa000 | 10}}, 0x0806, bytes(28)));
    CHECK(f.dclass == dst_class::broadcast && f.n_tags == 1 && f.tags[0].vid() == 10 && f.tags[0].pcp() == 5);

    // priority tagged: one tag, VLAN 0
    f = parse(1, eth(mac_b, mac_a, {{0x8100, 0x6000}}, 0x0800, ipv4(s, d, 17, udp(1, 2, {}))));
    CHECK(f.n_tags == 1 && f.tags[0].vid() == 0 && f.l4_ok);

    f = parse(1, eth(mac_b, mac_a, {{0x88a8, 100}, {0x8100, 20}}, 0x0800, ipv4(s, d, 6, tcp(1, 2, 0x12))));
    CHECK(f.n_tags == 2 && f.tags[0].tpid == 0x88a8 && f.tags[0].vid() == 100 && f.tags[1].vid() == 20);
    CHECK(f.tcp_flags == 0x12 && f.l4_ok);

    f = parse(1, eth(mac_b, mac_a, {{0x9100, 200}, {0x8100, 30}}, 0x0800, ipv4(s, d, 6, tcp(1, 2, 0x02))));
    CHECK(f.n_tags == 2 && f.tags[0].tpid == 0x9100 && f.l4_ok);

    f = parse(1, eth(mac_b, mac_a, {{0x88a8, 1}, {0x8100, 2}, {0x8100, 3}, {0x9200, 4}}, 0x0800,
                ipv4(s, d, 6, tcp(1, 2, 0x02))));
    CHECK(f.n_tags == 4 && f.l4_ok && f.errors == 0);

    // five tags: malformed, nothing past the tags
    f = parse(1, eth(mac_b, mac_a, {{0x88a8, 1}, {0x8100, 2}, {0x8100, 3}, {0x8100, 4}, {0x8100, 5}},
                0x0800, ipv4(s, d, 6, tcp(1, 2, 0x02))));
    CHECK((f.errors & err_tags_deep) && f.l3 == l3_type::none && f.n_tags == 4);

    // multicast destination, LLC length field, LLC/SNAP with IPv4
    f = parse(1, eth({0x01, 0x00, 0x5e, 0, 0, 1}, mac_a, {}, 46, bytes(46)));
    CHECK(f.dclass == dst_class::multicast && f.llc && f.l3 == l3_type::none);
    bytes snap{0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00};
    put(snap, ipv4(s, d, 17, udp(5, 6, {})));
    f = parse(1, eth(mac_b, mac_a, {}, static_cast<unsigned>(snap.size()), snap));
    CHECK(f.llc && f.ethertype == 0x0800 && f.l4_ok && f.dport == 6);

    // runts
    CHECK(!parse_frame(1, mac_a.data(), 6, f));
    CHECK(!parse_frame(1, nullptr, 0, f));

    // SLL: source only, broadcast packet type, a tag inline
    bytes sll;
    put16(sll, 1);
    put16(sll, 1);
    put16(sll, 6);
    put(sll, mac_a);
    put16(sll, 0);
    put16(sll, 0x8100);
    put16(sll, 42);
    put16(sll, 0x0800);
    put(sll, ipv4(s, d, 17, udp(7, 8, {})));
    f = parse(113, sll);
    CHECK(f.l2_ok && !f.has_dst && f.dclass == dst_class::broadcast && f.src[5] == 0x01);
    CHECK(f.n_tags == 1 && f.tags[0].vid() == 42 && f.l4_ok && f.dport == 8);

    // SLL2, outgoing
    bytes sll2;
    put16(sll2, 0x0800);
    put16(sll2, 0);
    put32(sll2, 3);
    put16(sll2, 1);
    sll2.push_back(4);
    sll2.push_back(6);
    put(sll2, mac_a);
    put16(sll2, 0);
    put(sll2, ipv4(s, d, 6, tcp(9, 10, 0x10)));
    f = parse(276, sll2);
    CHECK(f.l2_ok && f.outgoing && f.dclass == dst_class::unknown && f.l4_ok && f.dport == 10);

    // SLL from a non-Ethernet interface (loopback, ARPHRD 772)
    sll2[8] = 0x03;
    sll2[9] = 0x04;
    CHECK(!parse_frame(276, sll2.data(), sll2.size(), f));

    // unknown DLT
    CHECK(!parse_frame(105, sll2.data(), sll2.size(), f));
}

static void test_ipv4() {
    const bytes s{192, 0, 2, 1}, d{192, 0, 2, 2};

    // IHL 6 (router alert) and IHL 15 (record route)
    auto f = parse(1, eth(mac_b, mac_a, {}, 0x0800, ipv4(s, d, 17, udp(7000, 7001, {}), {0x94, 4, 0, 0})));
    CHECK(f.ipv4_ihl == 24 && f.l4_ok && f.sport == 7000 && f.dport == 7001);
    bytes rr{7, 39, 4};
    rr.resize(40);
    f = parse(1, eth(mac_b, mac_a, {}, 0x0800, ipv4(s, d, 6, tcp(7002, 7003, 2), rr)));
    CHECK(f.ipv4_ihl == 60 && f.l4_ok && f.sport == 7002);

    // IHL past the captured bytes
    auto b = eth(mac_b, mac_a, {}, 0x0800, ipv4(s, d, 17, udp(1, 2, {})));
    b[14] = 0x4f;
    f = parse(1, b);
    CHECK((f.errors & err_ip_short) && !f.l4_ok && f.ip_src == v4(192, 0, 2, 1));

    // total length shorter than the header; and IHL < 5
    f = parse(1, eth(mac_b, mac_a, {}, 0x0800, ipv4(s, d, 17, udp(1, 2, {}), {}, 10)));
    CHECK((f.errors & err_ip_len) && !f.l4_ok);
    b = eth(mac_b, mac_a, {}, 0x0800, ipv4(s, d, 17, udp(1, 2, {})));
    b[14] = 0x44;
    f = parse(1, b);
    CHECK((f.errors & err_ip_hdr) && f.l3 == l3_type::none);

    // total length larger than the frame: read what was captured
    f = parse(1, eth(mac_b, mac_a, {}, 0x0800, ipv4(s, d, 17, udp(1, 2, {}), {}, 0xffff)));
    CHECK(f.l4_ok && f.dport == 2);

    // Ethernet padding past the datagram doesn't become UDP payload: a DHCP header in the
    // padding isn't parsed
    auto dh = dhcp4(1, 1, mac_a, opt(12, str("pad")));
    auto u = udp(68, 67, {});
    auto ip = ipv4(s, d, 17, u);
    put(ip, dh);
    f = parse(1, eth(bcast, mac_a, {}, 0x0800, ip));
    CHECK(f.l4_ok && !f.dhcp4.valid);

    // later fragment: no transport
    f = parse(1, eth(mac_b, mac_a, {}, 0x0800, ipv4(s, d, 17, udp(1, 2, {}), {}, -1, 0x0010)));
    CHECK(f.fragment && !f.l4_ok);
}

static bytes ipv6(uint8_t nh, const bytes& payload, std::vector<std::pair<uint8_t, bytes>> ext = {}) {
    bytes chain;
    std::vector<uint8_t> types;
    for (auto& e : ext)
        types.push_back(e.first);
    types.push_back(nh);
    for (size_t i = 0; i < ext.size(); i++) {
        chain.push_back(types[i + 1]);
        if (ext[i].first == 44)
            chain.push_back(0);
        else
            chain.push_back(static_cast<uint8_t>((ext[i].second.size() + 2) / 8 - 1));
        put(chain, ext[i].second);
    }
    bytes b;
    put32(b, 0x60000000);
    put16(b, chain.size() + payload.size());
    b.push_back(types[0]);
    b.push_back(64);
    bytes a(16), z(16);
    a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8; a[15] = 2;
    z = a; z[15] = 3;
    put(b, a);
    put(b, z);
    put(b, chain);
    put(b, payload);
    return b;
}

static void test_ipv6() {
    const bytes padn{1, 4, 0, 0, 0, 0};
    bytes rh{0, 0, 0, 0, 0, 0};
    rh.resize(22);

    auto f = parse(1, eth(mac_b, mac_a, {}, 0x86dd, ipv6(6, tcp(6000, 443, 2), {{0, padn}, {43, rh}, {60, padn}})));
    CHECK(f.l3 == l3_type::ipv6 && f.n_ext == 3 && f.l4_ok && f.sport == 6000 && f.dport == 443);
    CHECK(f.ip_src.family == 6 && f.ip_src.a[15] == 2);

    // first fragment carries UDP; a later one doesn't
    f = parse(1, eth(mac_b, mac_a, {}, 0x86dd, ipv6(17, udp(6001, 9999, str("frag")), {{44, {0x00, 0x01, 0, 0, 0x12, 0x34}}})));
    CHECK(!f.fragment && f.more_fragments && f.l4_ok && f.dport == 9999);
    f = parse(1, eth(mac_b, mac_a, {}, 0x86dd, ipv6(17, str("later-bytes"), {{44, {0x01, 0x00, 0, 0, 0x12, 0x34}}})));
    CHECK(f.fragment && !f.l4_ok && f.ip_proto == 17);

    // 8 extension headers are read, a 9th is too deep
    std::vector<std::pair<uint8_t, bytes>> ext(8, {60, padn});
    f = parse(1, eth(mac_b, mac_a, {}, 0x86dd, ipv6(17, udp(1, 2, {}), ext)));
    CHECK(f.l4_ok && f.n_ext == 8 && f.errors == 0);
    ext.push_back({60, padn});
    f = parse(1, eth(mac_b, mac_a, {}, 0x86dd, ipv6(17, udp(1, 2, {}), ext)));
    CHECK((f.errors & err_ext_deep) && !f.l4_ok);

    // an extension header claiming more than was captured
    auto b = eth(mac_b, mac_a, {}, 0x86dd, ipv6(17, udp(1, 2, {}), {{60, padn}}));
    b[14 + 40 + 1] = 200;
    f = parse(1, b);
    CHECK((f.errors & err_ip_short) && !f.l4_ok);

    // ESP ends the chain
    f = parse(1, eth(mac_b, mac_a, {}, 0x86dd, ipv6(50, bytes(16))));
    CHECK(f.ip_proto == 50 && !f.l4_ok);

    // ICMPv6
    f = parse(1, eth(mac_b, mac_a, {}, 0x86dd, ipv6(58, {135, 0, 0, 0, 0, 0, 0, 0})));
    CHECK(f.l4_ok && f.icmp_type == 135);
}

static void test_arp() {
    bytes a;
    put16(a, 1);
    put16(a, 0x0800);
    a.push_back(6);
    a.push_back(4);
    put16(a, 2);
    put(a, mac_a);
    put(a, {192, 0, 2, 1});
    put(a, mac_b);
    put(a, {192, 0, 2, 2});
    auto f = parse(1, eth(mac_b, mac_a, {}, 0x0806, a));
    CHECK(f.l3 == l3_type::arp && f.arp_op == 2 && f.arp_spa == v4(192, 0, 2, 1) && f.arp_tpa == v4(192, 0, 2, 2));
    CHECK(f.arp_sha[5] == 1 && f.arp_tha[5] == 2 && f.errors == 0);

    // hardware length 255: not decoded
    a[4] = 255;
    f = parse(1, eth(mac_b, mac_a, {}, 0x0806, a));
    CHECK((f.errors & err_arp) && !f.arp_spa.set());
}

static frame dhcp_frame(const bytes& d, unsigned sport = 68, unsigned dport = 67) {
    return parse(1, eth(bcast, mac_a, {}, 0x0800, ipv4({0, 0, 0, 0}, {255, 255, 255, 255}, 17, udp(sport, dport, d))));
}

static void test_dhcp4() {
    bytes fq{0x05, 0, 0};
    put(fq, dns("client-one.example.com"));
    bytes opts;
    put(opts, opt(61, {1, 2, 0, 0, 0, 0xe0, 1}));
    put(opts, opt(12, str("client-one")));
    put(opts, opt(60, str("vendor 1.0")));
    put(opts, opt(55, {1, 3, 6, 15}));
    put(opts, opt(81, fq));
    put(opts, opt(50, {192, 0, 2, 10}));
    auto f = dhcp_frame(dhcp4(1, 3, mac_a, opts));
    const auto& d = f.dhcp4;
    CHECK(d.valid && d.op == 1 && d.msgtype == 3 && d.xid == 0x11223344 && d.chaddr_eth);
    CHECK(d.hostname.view() == "client-one" && d.vendor.view() == "vendor 1.0");
    CHECK(d.prl.len == 4 && d.prl.buf[3] == 15 && d.client_id.len == 7);
    CHECK(d.has_fqdn && d.fqdn.view() == "client-one.example.com");
    CHECK(d.requested == v4(192, 0, 2, 10));

    // server: router, DNS, yiaddr
    bytes so;
    put(so, opt(54, {192, 0, 2, 254}));
    put(so, opt(3, {192, 0, 2, 1, 192, 0, 2, 2}));
    put(so, opt(6, {192, 0, 2, 53, 192, 0, 2, 54, 192, 0, 2, 55, 192, 0, 2, 56, 192, 0, 2, 57}));
    put(so, opt(1, {255, 255, 255, 0}));
    f = dhcp_frame(dhcp4(2, 5, mac_a, so, {192, 0, 2, 10}), 67, 68);
    CHECK(f.dhcp4.op == 2 && f.dhcp4.msgtype == 5 && f.dhcp4.yiaddr == v4(192, 0, 2, 10));
    CHECK(f.dhcp4.router == v4(192, 0, 2, 1) && f.dhcp4.n_dns == max_dns_servers);
    CHECK(f.dhcp4.server_id == v4(192, 0, 2, 254));

    // overload: file then sname
    bytes fl = opt(12, str("overload-host"));
    fl.push_back(255);
    bytes sn = opt(60, str("overload-vendor"));
    sn.push_back(255);
    f = dhcp_frame(dhcp4(1, 3, mac_a, opt(52, {3}), {0, 0, 0, 0}, sn, fl));
    CHECK(f.dhcp4.overload == 3 && f.dhcp4.hostname.view() == "overload-host" &&
            f.dhcp4.vendor.view() == "overload-vendor");

    // option 52 inside the file or sname field is ignored, so no loop and no re-read
    bytes fl52 = opt(52, {3});
    fl52.push_back(255);
    f = dhcp_frame(dhcp4(1, 1, mac_a, opt(52, {1}), {0, 0, 0, 0}, {}, fl52));
    CHECK(f.dhcp4.overload == 1);

    // option running past the end: stops, keeps what came before
    auto bad = dhcp4(1, 1, mac_a, opt(12, str("before")));
    bad.pop_back();
    put(bad, {60, 0x40, 'x'});
    f = dhcp_frame(bad);
    CHECK((f.errors & err_dhcp_opt) && f.dhcp4.hostname.view() == "before" && f.dhcp4.vendor.empty());

    // RFC 3396 concatenation, capped
    bytes cat;
    for (int i = 0; i < 3; i++)
        put(cat, opt(12, bytes(200, 'a')));
    f = dhcp_frame(dhcp4(1, 1, mac_a, cat));
    CHECK(f.dhcp4.hostname.len == max_opt_string && (f.errors & err_truncated_string));

    // FQDN with the E flag clear is ASCII
    bytes fa{0x01, 0, 0};
    put(fa, str("ascii.example.com"));
    fa.push_back(0);
    f = dhcp_frame(dhcp4(1, 1, mac_a, opt(81, fa)));
    CHECK(f.dhcp4.has_fqdn && f.dhcp4.fqdn.view() == "ascii.example.com");

    // FQDN partial name (no root label)
    bytes fp{0x05, 0, 0, 4, 'h', 'o', 's', 't'};
    f = dhcp_frame(dhcp4(1, 1, mac_a, opt(81, fp)));
    CHECK(f.dhcp4.has_fqdn && f.dhcp4.fqdn.view() == "host");

    // FQDN that is only the root names nothing
    f = dhcp_frame(dhcp4(1, 1, mac_a, opt(81, {0x05, 0, 0, 0})));
    CHECK(!f.dhcp4.has_fqdn && f.errors == 0);

    // FQDN with a pointer loop, and a forward pointer
    f = dhcp_frame(dhcp4(1, 1, mac_a, opt(81, {0x05, 0, 0, 0xc0, 0x00})));
    CHECK(!f.dhcp4.has_fqdn && (f.errors & err_dns_name));
    f = dhcp_frame(dhcp4(1, 1, mac_a, opt(81, {0x05, 0, 0, 0xc0, 0x02, 0})));
    CHECK(!f.dhcp4.has_fqdn);

    // bad magic, short message
    auto nm = dhcp4(1, 1, mac_a, {});
    nm[236] = 0;
    f = dhcp_frame(nm);
    CHECK(!f.dhcp4.valid && (f.errors & err_dhcp));
    f = dhcp_frame(bytes(100));
    CHECK(!f.dhcp4.valid && (f.errors & err_dhcp));

    // relay to server, 67 to 67
    f = dhcp_frame(dhcp4(1, 3, mac_a, {}), 67, 67);
    CHECK(f.dhcp4.valid);
}

static void test_dns_names() {
    bstr<max_dns_name> out;

    auto n = dns("a.example.com");
    CHECK(decode_dns_name(n.data(), n.size(), 0, out) && out.view() == "a.example.com");

    // backward pointer: "www" then a pointer to the name at 0
    bytes m = dns("example.com");
    const size_t at = m.size();
    put(m, {3, 'w', 'w', 'w', 0xc0, 0x00});
    CHECK(decode_dns_name(m.data(), m.size(), at, out) && out.view() == "www.example.com");

    // a pointer to itself, and a forward pointer
    bytes self{3, 'a', 'b', 'c', 0xc0, 0x00};
    CHECK(!decode_dns_name(self.data(), self.size(), 0, out));
    bytes fwd{0xc0, 0x02, 1, 'x', 0};
    CHECK(!decode_dns_name(fwd.data(), fwd.size(), 0, out));

    // pointer chain that goes backwards each time is fine
    bytes chain{1, 'a', 0, 1, 'b', 0xc0, 0x00, 1, 'c', 0xc0, 0x03};
    CHECK(decode_dns_name(chain.data(), chain.size(), 7, out) && out.view() == "c.b.a");

    // 128 one-character labels are fine (255 bytes), 129 are not
    bytes many;
    for (int i = 0; i < 128; i++)
        put(many, {1, 'x'});
    many.push_back(0);
    CHECK(decode_dns_name(many.data(), many.size(), 0, out) && out.len == 255);
    bytes too_many;
    for (int i = 0; i < 129; i++)
        put(too_many, {1, 'x'});
    too_many.push_back(0);
    CHECK(!decode_dns_name(too_many.data(), too_many.size(), 0, out));

    // over 255 bytes
    bytes longn;
    for (int i = 0; i < 5; i++) {
        longn.push_back(63);
        put(longn, bytes(63, 'y'));
    }
    longn.push_back(0);
    CHECK(!decode_dns_name(longn.data(), longn.size(), 0, out));

    // label running off the end, reserved label types, no terminator
    bytes off{10, 'a', 'b'};
    CHECK(!decode_dns_name(off.data(), off.size(), 0, out));
    bytes rsv{0x40, 'a', 0};
    CHECK(!decode_dns_name(rsv.data(), rsv.size(), 0, out));
    bytes noterm{1, 'a'};
    CHECK(!decode_dns_name(noterm.data(), noterm.size(), 0, out));
    CHECK(!decode_dns_name(noterm.data(), noterm.size(), 5, out));
}

static void test_dhcp6() {
    bytes d{1, 0xab, 0xcd, 0xef};
    auto o6 = [&d](unsigned code, const bytes& v) { put16(d, code); put16(d, v.size()); put(d, v); };
    bytes duid{0, 1, 0, 1, 0x29, 0xb9, 0x27, 0};
    put(duid, mac_a);
    o6(1, duid);
    o6(6, {0, 23, 0, 24, 0, 39});
    bytes fq{1};
    put(fq, dns("six.example.com"));
    o6(39, fq);
    bytes vc;
    put32(vc, 311);
    put16(vc, 3);
    puts_(vc, "abc");
    o6(16, vc);

    auto v6 = [](const bytes& payload) {
        return parse(1, eth(mac_b, mac_a, {}, 0x86dd, ipv6(17, udp(546, 547, payload))));
    };

    auto f = v6(d);
    CHECK(f.dhcp6.valid && f.dhcp6.msgtype == 1 && f.dhcp6.xid == 0xabcdef);
    CHECK(f.dhcp6.client_duid.len == 14 && f.dhcp6.n_oro == 3 && f.dhcp6.oro[2] == 39);
    CHECK(f.dhcp6.has_fqdn && f.dhcp6.fqdn.view() == "six.example.com");
    CHECK(f.dhcp6.vendor.view() == "abc" && f.dhcp6.vendor_enterprise == 311);

    // reply with an IA_NA holding two addresses
    bytes r{7, 0, 0, 1};
    bytes ia;
    put32(ia, 1);
    put32(ia, 100);
    put32(ia, 200);
    for (int i = 0; i < 2; i++) {
        put16(ia, 5);
        put16(ia, 24);
        bytes a(16);
        a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8; a[15] = static_cast<uint8_t>(0x10 + i);
        put(ia, a);
        put32(ia, 1);
        put32(ia, 2);
    }
    put16(r, 3);
    put16(r, ia.size());
    put(r, ia);
    f = parse(1, eth(mac_a, mac_b, {}, 0x86dd, ipv6(17, udp(547, 546, r))));
    CHECK(f.dhcp6.msgtype == 7 && f.dhcp6.n_ia_addrs == 2 && f.dhcp6.ia_addrs[1].a[15] == 0x11);

    // option length past the end
    bytes bad{1, 0, 0, 1, 0, 1, 0xff, 0xff, 1, 2};
    f = v6(bad);
    CHECK((f.errors & err_dhcp6) && f.dhcp6.client_duid.empty());

    // relay-forward isn't unwrapped; type 0 is invalid
    f = v6({12, 0, 0, 0});
    CHECK(!f.dhcp6.valid && f.errors == 0);
    f = v6({0, 0, 0, 0});
    CHECK(!f.dhcp6.valid && (f.errors & err_dhcp6));

    // oversized DUID is capped
    bytes big{1, 0, 0, 1};
    put16(big, 1);
    put16(big, 300);
    put(big, bytes(300, 0x41));
    f = v6(big);
    CHECK(f.dhcp6.client_duid.len == max_duid && (f.errors & err_truncated_string));
}

static wired_flow_tracker::observation obs(uint8_t a, uint8_t b, uint16_t sp, uint16_t dp, time_t ts,
        uint8_t proto = 17, uint8_t flags = 0) {
    wired_flow_tracker::observation o;
    o.src = v4(192, 0, 2, a);
    o.dst = v4(198, 51, 100, b);
    o.proto = proto;
    o.sport = sp;
    o.dport = dp;
    o.tcp_flags = flags;
    o.bytes = 100;
    o.ts = ts;
    o.seen = ts;
    o.src_mac = 0x020000000000ULL | a;
    o.dst_mac = 0x020000000100ULL | b;
    return o;
}

// Trackers in tests hash with fixed seeds so every run places flows alike
constexpr uint64_t test_seed = 0x5eed;

static void test_flows() {
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 100;
    p.on_full = wired_flow_tracker::full_policy::drop;
    wired_flow_tracker t(p, test_seed);

    CHECK(t.add(obs(1, 1, 1000, 53, 10)) == r::created);
    CHECK(t.add(obs(1, 1, 1000, 53, 11)) == r::updated);

    // the reply is the same flow, other direction
    auto rep = obs(1, 1, 1000, 53, 12);
    std::swap(rep.src, rep.dst);
    std::swap(rep.sport, rep.dport);
    std::swap(rep.src_mac, rep.dst_mac);
    CHECK(t.add(rep) == r::updated);

    std::vector<wired_flow_tracker::flow> out;
    size_t total;
    t.snapshot({}, 0, 0, out, total);
    CHECK(total == 1 && out.size() == 1);
    CHECK(out[0].packets_ab + out[0].packets_ba == 3 && out[0].first_time == 10 && out[0].last_time == 12);
    CHECK(out[0].initiator_a);

    // different VLAN is a different flow
    auto vo = obs(1, 1, 1000, 53, 13);
    vo.vlan = wired_flow_tracker::vlan_key(1, 10, 0);
    CHECK(t.add(vo) == r::created);

    // fill to 90: still admitted on the first packet
    for (uint16_t i = 0; i < 88; i++)
        CHECK(t.add(obs(2, 2, static_cast<uint16_t>(2000 + i), 80, 20, 6)) == r::created);
    CHECK(t.get_stats().flows == 90);

    // past 90%: a new flow waits for its second packet
    CHECK(t.add(obs(3, 3, 1, 1, 21)) == r::deferred);
    CHECK(t.add(obs(3, 3, 1, 1, 21)) == r::created);

    for (uint16_t i = 0; i < 9; i++) {
        t.add(obs(4, 4, static_cast<uint16_t>(10 + i), 1, 22));
        t.add(obs(4, 4, static_cast<uint16_t>(10 + i), 1, 22));
    }
    CHECK(t.get_stats().flows == 100);
    CHECK(t.add(obs(5, 5, 1, 1, 23)) == r::dropped);
    CHECK(t.add(obs(5, 5, 1, 1, 23)) == r::dropped);
    CHECK(t.get_stats().dropped_full == 2 && t.get_stats().evicted == 0);

    // filters and paging
    wired_flow_tracker::filter f;
    f.vlan = 10;
    t.snapshot(f, 0, 0, out, total);
    CHECK(total == 1 && out.size() == 1);
    f = {};
    f.mac = 0x020000000002ULL;
    t.snapshot(f, 0, 10, out, total);
    CHECK(total == 88 && out.size() == 10);
    t.snapshot(f, 85, 10, out, total);
    CHECK(out.size() == 3);
    t.snapshot(f, 500, 10, out, total);
    CHECK(out.empty());
    f = {};
    f.ip = v4(198, 51, 100, 4);
    t.snapshot(f, 0, 0, out, total);
    CHECK(total == 9);

    // TCP after FIN expires after 10 s, open TCP after 300, UDP after 60
    CHECK(t.add(obs(2, 2, 2000, 80, 25, 6, 0x11)) == r::updated);
    size_t before = t.get_stats().flows;
    t.expire(36);
    CHECK(t.get_stats().flows == before - 1);
    t.expire(100);
    CHECK(t.get_stats().flows == 87);
    t.expire(400);
    CHECK(t.get_stats().flows == 0);

    // mismatched families and a zero cap are ignored
    wired_flow_tracker::observation m = obs(1, 1, 1, 1, 1);
    m.dst.family = 6;
    CHECK(t.add(m) == r::ignored);
    p.max_flows = 0;
    wired_flow_tracker z(p, test_seed);
    CHECK(z.add(obs(1, 1, 1, 1, 1)) == r::ignored);
}

// UDP 192.0.2.10:2588 hashed, without a seed, to the same shard and pending slot as the
// victim's :40000, so one attacker packet between the victim's two kept it deferred
static void test_flow_seed_collision() {
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 100;

    // any seed puts them in one slot one time in 16384; none of these do
    for (uint64_t seed = 1; seed <= 8; seed++) {
        wired_flow_tracker t(p, seed);
        for (uint16_t i = 0; i < 90; i++)
            t.add(obs(2, 2, static_cast<uint16_t>(2000 + i), 80, 20, 6));

        CHECK(t.add(obs(10, 10, 40000, 443, 21)) == r::deferred);
        CHECK(t.add(obs(10, 10, 2588, 443, 21)) == r::deferred);
        CHECK(t.add(obs(10, 10, 40000, 443, 22)) == r::created);
    }
}

// The unseeded hash could be solved for addr_b: a UDP flow 2001:db8::1:1 -> [forged]:i whose
// pre-avalanche value is target, so every forged key with one target had one hash, and
// target 0 gave hash 0 (splitmix64 maps 0 to 0)
static wired_flow_tracker::observation forged_obs(uint16_t i, uint64_t target) {
    constexpr uint64_t c = 0x9e3779b97f4a7c15ULL;
    const auto mixf = [](uint64_t h, uint64_t v) { return h ^ (v + c + (h << 6) + (h >> 2)); };
    const auto unmix = [](uint64_t h, uint64_t t) { return (t ^ h) - c - (h << 6) - (h >> 2); };

    wired_flow_tracker::observation o;
    o.src.family = o.dst.family = 6;
    o.src.a = {0x20, 0x01, 0x0d, 0xb8};
    o.src.a[15] = 1;
    o.proto = 17;
    o.sport = 1;
    o.dport = i;
    o.bytes = 60;

    uint64_t h = (6ULL << 56) | (17ULL << 48) | (1ULL << 16) | i;
    h = mixf(h, 0);
    uint64_t ahi = 0, alo = 0;
    for (int k = 0; k < 8; k++) {
        ahi = (ahi << 8) | o.src.a[k];
        alo = (alo << 8) | o.src.a[k + 8];
    }
    h = mixf(h, mixf(ahi, alo));
    const uint64_t bhi = 0x20010db800000000ULL | i;
    const uint64_t blo = unmix(bhi, unmix(h, target));
    for (int k = 0; k < 8; k++) {
        o.dst.a[k] = static_cast<uint8_t>(bhi >> (56 - 8 * k));
        o.dst.a[k + 8] = static_cast<uint8_t>(blo >> (56 - 8 * k));
    }
    return o;
}

struct flow_peek : public wired_flow_tracker {
    using wired_flow_tracker::wired_flow_tracker;

    size_t shard_size(size_t i) const {
        std::lock_guard<std::mutex> lk(shards[i].mutex);
        return shards[i].flows.size();
    }

    // Pending slots hold 0 (empty) or a tag with bit 0 set
    bool pending_tags_odd() const {
        for (size_t i = 0; i < n_shards; i++) {
            std::lock_guard<std::mutex> lk(shards[i].mutex);
            for (auto v : shards[i].pending)
                if (v != 0 && (v & 1) == 0)
                    return false;
        }
        return true;
    }

    uint64_t hash_of(const key& k) const { return hasher(k); }

    // Every shard's map hashes with the tracker's seeded hasher, not a default one
    bool maps_use_hasher(const key& k) const {
        for (size_t i = 0; i < n_shards; i++) {
            if (shards[i].flows.hash_function()(k) != hasher(k))
                return false;
        }
        return true;
    }
};

static void test_flow_forged_keys() {
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 100;

    // a hash-0 key matched an empty pending slot and was admitted on its first packet
    flow_peek t(p, test_seed);
    for (uint16_t i = 0; i < 90; i++)
        t.add(obs(2, 2, static_cast<uint16_t>(2000 + i), 80, 20, 6));
    for (uint16_t i = 1; i <= 4; i++)
        CHECK(t.add(forged_obs(i, 0)) == r::deferred);
    for (uint16_t i = 0; i < 200; i++)
        t.add(obs(3, 3, static_cast<uint16_t>(3000 + i), 53, 21));
    CHECK(t.pending_tags_odd());

    // keys forged to one hash all went to one shard and one probe chain
    p.max_flows = 16384;
    flow_peek u(p, test_seed);
    constexpr uint16_t n_forged = 512;
    for (uint16_t i = 1; i <= n_forged; i++)
        CHECK(u.add(forged_obs(i, 0x1234567ULL)) == r::created);
    CHECK(u.get_stats().flows == n_forged);
    size_t biggest = 0;
    for (size_t s = 0; s < wired_flow_tracker::n_shards; s++)
        biggest = std::max(biggest, u.shard_size(s));
    // 32 per shard expected
    CHECK(biggest < 64);
}

static void flip_key_bit(wired_flow_tracker::key& k, unsigned bit) {
    if (bit < 8)
        k.family ^= 1U << bit;
    else if (bit < 16)
        k.proto ^= 1U << (bit - 8);
    else if (bit < 32)
        k.port_a ^= 1U << (bit - 16);
    else if (bit < 48)
        k.port_b ^= 1U << (bit - 32);
    else if (bit < 112)
        k.vlan ^= 1ULL << (bit - 48);
    else if (bit < 240)
        k.addr_a[(bit - 112) / 8] ^= 1U << ((bit - 112) % 8);
    else
        k.addr_b[(bit - 240) / 8] ^= 1U << ((bit - 240) % 8);
}

static void test_flow_hash_seed() {
    using kh = wired_flow_tracker::key_hash;
    constexpr unsigned key_bits = 368;
    constexpr unsigned n_keys = 256;
    constexpr uint64_t slot_mask = wired_flow_tracker::n_shards * wired_flow_tracker::pending_slots - 1;

    const kh a(1), a2(1), b(2);
    unsigned same_shard = 0, same_slot = 0, mismatched = 0;

    for (unsigned i = 0; i < n_keys; i++) {
        wired_flow_tracker::key k;
        k.family = 4;
        k.proto = 17;
        k.port_a = static_cast<uint16_t>(1024 + i);
        k.port_b = 53;
        k.addr_a[0] = 192; k.addr_a[2] = 2; k.addr_a[3] = 1;
        k.addr_b[0] = 198; k.addr_b[1] = 51; k.addr_b[2] = 100; k.addr_b[3] = 1;

        if (a(k) != a2(k))
            mismatched++;
        if (a(k) % wired_flow_tracker::n_shards == b(k) % wired_flow_tracker::n_shards)
            same_shard++;
        if ((a(k) & slot_mask) == (b(k) & slot_mask))
            same_slot++;
    }

    // the same seed is repeatable; another seed reshuffles shards (1 in 16 alike) and slots
    CHECK(mismatched == 0);
    CHECK(same_shard < n_keys / 8);
    CHECK(same_slot < 4);

    // every key bit flips about half of the hash
    uint64_t total = 0;
    unsigned weak = 0;
    for (unsigned bit = 0; bit < key_bits; bit++) {
        unsigned flipped = 0;
        for (unsigned i = 0; i < 64; i++) {
            wired_flow_tracker::key k;
            k.family = 6;
            k.proto = 6;
            k.port_a = static_cast<uint16_t>(i * 977);
            k.port_b = 443;
            k.vlan = static_cast<uint64_t>(i) * 0x10001;
            k.addr_a[0] = 0x20; k.addr_a[1] = 0x01; k.addr_a[2] = 0x0d; k.addr_a[3] = 0xb8;
            k.addr_a[15] = static_cast<uint8_t>(i);
            k.addr_b = k.addr_a;
            k.addr_b[14] = 1;
            const auto h = a(k);
            flip_key_bit(k, bit);
            flipped += std::popcount(h ^ a(k));
        }
        total += flipped;
        if (flipped < 64 * 28 || flipped > 64 * 36)
            weak++;
    }
    const double mean = static_cast<double>(total) / (key_bits * 64);
    CHECK(mean > 31.5 && mean < 32.5);
    CHECK(weak == 0);

    // trackers with one seed defer and admit alike
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 100;
    wired_flow_tracker t1(p, 7), t2(p, 7);
    for (uint16_t i = 0; i < 90; i++) {
        t1.add(obs(2, 2, static_cast<uint16_t>(2000 + i), 80, 20, 6));
        t2.add(obs(2, 2, static_cast<uint16_t>(2000 + i), 80, 20, 6));
    }
    for (uint16_t i = 0; i < 64; i++) {
        const auto o = obs(10, 10, static_cast<uint16_t>(3000 + i * 13), 443, 21);
        CHECK(t1.add(o) == t2.add(o));
    }
    CHECK(t1.get_stats().deferred == t2.get_stats().deferred && t1.get_stats().flows == t2.get_stats().flows);
    CHECK(t1.add(obs(10, 10, 40000, 443, 22)) == r::deferred);

    // without a seed each tracker draws its own, and the maps hash with it
    wired_flow_tracker::key k;
    k.family = 4;
    k.proto = 17;
    const flow_peek d1(p), d2(p), s1(p, 7);
    CHECK(d1.hash_of(k) != d2.hash_of(k));
    CHECK(s1.hash_of(k) == kh(7)(k) && s1.hash_of(k) != kh()(k));
    CHECK(d1.maps_use_hasher(k) && d2.maps_use_hasher(k) && s1.maps_use_hasher(k));
}

// phy_ethernet's IP table hash before it was seeded: FNV-1a and a fixed mix
static uint64_t unseeded_ip_hash(const ip_addr& a) {
    uint64_t h = 0xcbf29ce484222325ULL ^ a.family;
    for (auto b : a.a) {
        h ^= b;
        h *= 0x100000001b3ULL;
    }
    h ^= h >> 32;
    h *= 0x9e3779b97f4a7c15ULL;
    h ^= h >> 29;
    return h;
}

// fe80::/64 with chosen low bits
static ip_addr link_local(uint64_t lo) {
    ip_addr a;
    a.family = 6;
    a.a[0] = 0xfe;
    a.a[1] = 0x80;
    for (size_t k = 0; k < 8; k++)
        a.a[8 + k] = static_cast<uint8_t>(lo >> (56 - 8 * k));
    return a;
}

// Keys in the fullest of 2^bits buckets, chosen by the top bits of the hash as unordered_dense
// chooses them
template<typename K, typename H>
static size_t fullest_bucket(const std::vector<K>& keys, const H& h, unsigned bits) {
    std::vector<size_t> n(size_t{1} << bits);
    size_t most = 0;
    for (const auto& k : keys)
        most = std::max(most, ++n[h(k) >> (64 - bits)]);
    return most;
}

// Keys whose hash under h has top bits target, ground offline from make(1), make(2), ...
template<typename K, typename M, typename H>
static std::vector<K> grind(const M& make, const H& h, unsigned bits, uint64_t target, size_t count) {
    std::vector<K> r;
    for (uint64_t i = 1; r.size() < count; i++) {
        const K k = make(i);
        if ((h(k) >> (64 - bits)) == target)
            r.push_back(k);
    }
    return r;
}

// The IP table and VLAN inventory used to hash with fixed functions, so addresses chosen
// offline piled into one probe chain under ip_mutex; seeded, the same keys spread out.
// 256 keys in 4096 buckets put 4 or more in the fullest bucket about one seed in 300.
static void test_ip_hash_seed() {
    constexpr unsigned bits = 12;
    constexpr size_t n_keys = 256;
    constexpr size_t max_spread = 6;

    const auto forged = grind<ip_addr>(link_local, unseeded_ip_hash, bits, 0x123, n_keys);
    CHECK(fullest_bucket(forged, unseeded_ip_hash, bits) == n_keys);

    std::vector<ip_addr> v4;
    for (uint32_t i = 0; i < 4096; i++) {
        ip_addr a;
        a.family = 4;
        a.a[0] = 10;
        a.a[2] = static_cast<uint8_t>(i >> 8);
        a.a[3] = static_cast<uint8_t>(i);
        v4.push_back(a);
    }

    for (uint64_t seed = 1; seed <= 8; seed++) {
        const ip_addr_hash h(seed);
        CHECK(fullest_bucket(forged, h, bits) <= max_spread);
        // 4096 in 4096: the fullest bucket of a random hash holds about 7
        CHECK(fullest_bucket(v4, h, bits) <= 12);
    }

    const ip_addr_hash a(1), a2(1), b(2), placeholder;
    const auto k = link_local(0x1234);
    CHECK(a(k) == a2(k) && a(k) != b(k) && a(k) != placeholder(k));

    // v4 10.0.0.1 and a v6 address with the same bytes
    ip_addr k4 = v4[1], k6 = v4[1];
    k6.family = 6;
    CHECK(a(k4) != a(k6));

    // the family and every address bit flip about half of the hash
    uint64_t total = 0;
    unsigned weak = 0;
    for (unsigned bit = 0; bit < 136; bit++) {
        unsigned flipped = 0;
        for (uint64_t i = 0; i < 64; i++) {
            ip_addr x = link_local(i * 0x9e3779b97f4a7c15ULL);
            const auto h = a(x);
            if (bit < 128)
                x.a[bit / 8] ^= static_cast<uint8_t>(1U << (bit % 8));
            else
                x.family ^= static_cast<uint8_t>(1U << (bit - 128));
            flipped += std::popcount(h ^ a(x));
        }
        total += flipped;
        if (flipped < 64 * 28 || flipped > 64 * 36)
            weak++;
    }
    const double mean = static_cast<double>(total) / (136 * 64);
    CHECK(mean > 31.5 && mean < 32.5);
    CHECK(weak == 0);

    // VLAN inventory keys, laid out as phy_ethernet's vlan_inv_key: tags, outer and inner VID
    const auto vlan_key = [](uint64_t i) {
        return (uint64_t{2} << 32) | (((i >> 12) & 0xfff) << 16) | (i & 0xfff);
    };
    const ankerl::unordered_dense::hash<uint64_t> unseeded_u64;
    const auto forged_vlans = grind<uint64_t>(vlan_key, unseeded_u64, bits, 0x123, n_keys);
    CHECK(fullest_bucket(forged_vlans, unseeded_u64, bits) == n_keys);

    for (uint64_t seed = 1; seed <= 8; seed++)
        CHECK(fullest_bucket(forged_vlans, seeded_u64_hash(seed), bits) <= max_spread);

    const seeded_u64_hash u(1), u2(1), w(2), u_placeholder;
    CHECK(u(5) == u2(5) && u(5) != w(5) && u(5) != u_placeholder(5));

    // a map built with a seeded hasher hashes with it
    ankerl::unordered_dense::map<ip_addr, int, ip_addr_hash> m(0, ip_addr_hash(7));
    CHECK(m.hash_function()(k) == ip_addr_hash(7)(k) && m.hash_function()(k) != placeholder(k));
}

static void test_flow_times() {
    wired_flow_tracker::params p;
    p.max_flows = 1000;
    wired_flow_tracker t(p, test_seed);

    // Packet times from 2036 and a day back: expiry follows server time only
    auto fut = obs(1, 1, 1, 1, 0);
    fut.ts = 2100000000;
    fut.seen = 1000;
    t.add(fut);
    for (uint16_t i = 0; i < 100; i++) {
        auto o = obs(2, 2, static_cast<uint16_t>(100 + i), 53, 0);
        o.ts = 1700000000 - 86400;
        o.seen = 1000;
        t.add(o);
    }
    t.expire(1050);
    CHECK(t.get_stats().flows == 101);
    t.expire(1061);
    CHECK(t.get_stats().flows == 0);

    // Newest packet first, ties in key order, and every page of a large table agrees with a
    // full listing
    wired_flow_tracker u(p, test_seed);
    for (int i = 0; i < 500; i++)
        u.add(obs(static_cast<uint8_t>(i % 7), static_cast<uint8_t>(i % 11), static_cast<uint16_t>(i), 9,
                    static_cast<time_t>(i % 13)));

    std::vector<wired_flow_tracker::flow> all, page;
    size_t total;
    u.snapshot({}, 0, 0, all, total);
    CHECK(total == 500 && all.size() == 500);
    for (size_t i = 1; i < all.size(); i++)
        CHECK(all[i - 1].last_time >= all[i].last_time);

    for (size_t start = 0; start < 520; start += 37) {
        u.snapshot({}, start, 37, page, total);
        CHECK(total == 500);
        CHECK(page.size() == (start >= 500 ? 0 : std::min<size_t>(37, 500 - start)));
        for (size_t i = 0; i < page.size(); i++)
            CHECK(page[i].k == all[start + i].k);
    }
}

// The shard t puts a flow in, by t's own seeded hash.  obs() puts the lower address on the
// source side, so its key is in packet order.
static size_t shard_of(const flow_peek& t, const wired_flow_tracker::observation& o) {
    wired_flow_tracker::key k;
    k.family = 4;
    k.proto = o.proto;
    k.vlan = o.vlan;
    k.addr_a = o.src.a;
    k.addr_b = o.dst.a;
    k.port_a = o.sport;
    k.port_b = o.dport;
    return t.hash_of(k) % wired_flow_tracker::n_shards;
}

static size_t shard_of(const flow_peek& t, const wired_flow_tracker::flow& f) {
    return t.hash_of(f.k) % wired_flow_tracker::n_shards;
}

// Both packets a new flow needs past the admission threshold
static wired_flow_tracker::result add2(wired_flow_tracker& t, const wired_flow_tracker::observation& o) {
    auto res = t.add(o);
    if (res == wired_flow_tracker::result::deferred)
        res = t.add(o);
    return res;
}

// The next flow from port *port up which t puts in shard s
static wired_flow_tracker::observation in_shard(const flow_peek& t, size_t s, uint8_t b, uint16_t& port, time_t seen,
        uint8_t proto = 17) {
    while (true) {
        auto o = obs(9, b, port++, 7, seen, proto);
        if (shard_of(t, o) == s)
            return o;
    }
}

static std::vector<wired_flow_tracker::flow> all_flows(const wired_flow_tracker& t) {
    std::vector<wired_flow_tracker::flow> out;
    size_t total;
    t.snapshot({}, 0, 0, out, total);
    return out;
}

static bool has_flow(const std::vector<wired_flow_tracker::flow>& v, const wired_flow_tracker::flow& f) {
    return std::any_of(v.begin(), v.end(), [&](const auto& x) { return x.k == f.k; });
}

static void test_flow_evict() {
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 32;

    // A full table of idle flows, each seen a second after the last: a new flow takes the
    // place of the oldest in its shard
    flow_peek t(p, test_seed);
    for (uint16_t i = 0; i < 32; i++)
        CHECK(add2(t, obs(1, 1, static_cast<uint16_t>(1000 + i), 53, 100 + i)) == r::created);
    auto before = all_flows(t);
    CHECK(before.size() == 32);

    uint16_t port = 1;
    const auto shard = shard_of(t, before[0]);
    size_t in_s = 0;
    const wired_flow_tracker::flow *oldest = nullptr;
    for (const auto& f : before) {
        if (shard_of(t, f) != shard)
            continue;
        in_s++;
        if (oldest == nullptr || f.seen < oldest->seen)
            oldest = &f;
    }
    CHECK(in_s <= wired_flow_tracker::evict_samples);

    auto nf = in_shard(t, shard, 1, port, 1000);
    CHECK(t.add(nf) == r::deferred);
    CHECK(t.add(nf) == r::created);
    auto after = all_flows(t);
    auto st = t.get_stats();
    CHECK(after.size() == 32 && st.flows == 32);
    CHECK(st.created == 33 && st.evicted == 1 && st.dropped_full == 0 && st.expired == 0);
    CHECK(oldest != nullptr && !has_flow(after, *oldest));
    for (const auto& f : before)
        CHECK(&f == oldest || has_flow(after, f));

    // A flood of new flows replaces idle ones only, never another new one, and never past
    // the cap; once a shard has only new flows, its new flows are dropped
    size_t made = 0, dropped = 0;
    for (uint16_t i = 0; i < 400; i++) {
        auto res = add2(t, obs(2, 2, static_cast<uint16_t>(3000 + i), 80, 1000));
        CHECK(res == r::created || res == r::dropped);
        if (res == r::created)
            made++;
        else
            dropped++;
        CHECK(t.get_stats().flows == 32);
    }
    after = all_flows(t);
    st = t.get_stats();
    size_t fresh = 0;
    for (const auto& f : after)
        if (f.seen == 1000)
            fresh++;
    CHECK(fresh == made + 1);
    CHECK(st.evicted == made + 1 && st.dropped_full == dropped && st.created == 33 + made);
    CHECK(st.created - st.evicted - st.expired == st.flows);
    CHECK(made == 31 && dropped == 400 - 31 && fresh == 32);

    // 9 s later the flood's flows are still too recent; at 10 s they can go
    st = t.get_stats();
    CHECK(add2(t, in_shard(t, shard, 3, port, 1009)) == r::dropped);
    CHECK(t.get_stats().evicted == st.evicted && t.get_stats().dropped_full == st.dropped_full + 1);
    CHECK(add2(t, in_shard(t, shard, 3, port, 1010)) == r::created);
    CHECK(t.get_stats().evicted == st.evicted + 1);

    // A flow stamped later than the packet (another thread's clock) is recent, not idle
    flow_peek c(p, test_seed);
    for (uint16_t i = 0; i < 32; i++)
        add2(c, obs(1, 1, static_cast<uint16_t>(1000 + i), 53, 2000));
    CHECK(add2(c, in_shard(c, shard_of(c, all_flows(c)[0]), 3, port, 1990)) == r::dropped);
    CHECK(c.get_stats().evicted == 0 && c.get_stats().dropped_full == 1);
}

static void test_flow_evict_closed() {
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 32;
    flow_peek t(p, test_seed);
    uint16_t port = 1;

    // A closed TCP flow goes before older open ones
    auto fin = in_shard(t, 0, 4, port, 500, 6);
    fin.tcp_flags = 0x11;
    CHECK(add2(t, fin) == r::created);
    for (uint16_t i = 0; t.get_stats().flows < 32; i++)
        add2(t, obs(1, 1, static_cast<uint16_t>(1000 + i), 53, 100));
    auto before = all_flows(t);
    size_t in_s = 0;
    for (const auto& f : before)
        if (shard_of(t, f) == 0)
            in_s++;
    CHECK(in_s >= 2 && in_s <= wired_flow_tracker::evict_samples);

    CHECK(add2(t, in_shard(t, 0, 5, port, 1000)) == r::created);
    auto after = all_flows(t);
    CHECK(t.get_stats().evicted == 1);
    for (const auto& f : before)
        CHECK(has_flow(after, f) == !f.closed);

    // Closed TCP waits a second; open flows wait evict_idle
    flow_peek u(p, test_seed);
    fin = in_shard(u, 0, 4, port, 1000, 6);
    fin.tcp_flags = 0x04;
    add2(u, fin);
    for (uint16_t i = 0; u.get_stats().flows < 32; i++)
        add2(u, obs(1, 1, static_cast<uint16_t>(1000 + i), 53, 1000));
    CHECK(add2(u, in_shard(u, 0, 5, port, 1000)) == r::dropped);
    CHECK(add2(u, in_shard(u, 0, 5, port, 1001)) == r::created);
    auto st = u.get_stats();
    CHECK(st.evicted == 1 && st.dropped_full == 1);
    for (const auto& f : all_flows(u))
        CHECK(!f.closed);
    CHECK(add2(u, in_shard(u, 0, 5, port, 1002)) == r::dropped);
}

static void test_flow_full_drop() {
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 32;
    p.on_full = wired_flow_tracker::full_policy::drop;
    wired_flow_tracker t(p, test_seed);

    for (uint16_t i = 0; t.get_stats().flows < 32; i++)
        add2(t, obs(1, 1, static_cast<uint16_t>(1000 + i), 53, 100));
    auto before = all_flows(t);
    auto st = t.get_stats();

    // Idle for 900 s, but drop keeps the table and never defers at the cap
    CHECK(t.add(obs(2, 2, 1, 1, 1000)) == r::dropped);
    CHECK(t.add(obs(2, 2, 1, 1, 1000)) == r::dropped);
    auto st2 = t.get_stats();
    CHECK(st2.evicted == 0 && st2.dropped_full == st.dropped_full + 2 && st2.deferred == st.deferred);
    auto after = all_flows(t);
    CHECK(after.size() == before.size());
    for (const auto& f : before)
        CHECK(has_flow(after, f));
}

static void test_flow_evict_cursor() {
    using r = wired_flow_tracker::result;
    wired_flow_tracker::params p;
    p.max_flows = 64;
    flow_peek t(p, test_seed);
    uint16_t port = 1;

    // One shard holds the whole table, the idle flows last: the cursor still reaches every
    // one of them within a sweep of the shard per idle flow
    for (int i = 0; i < 56; i++)
        CHECK(add2(t, in_shard(t, 0, 1, port, 1000)) == r::created);
    for (int i = 0; i < 8; i++)
        CHECK(add2(t, in_shard(t, 0, 2, port, 100)) == r::created);

    size_t made = 0;
    for (int i = 0; i < 64; i++)
        if (add2(t, in_shard(t, 0, 3, port, 1000)) == r::created)
            made++;
    auto st = t.get_stats();
    CHECK(made == 8 && st.evicted == 8 && st.dropped_full == 56 && st.flows == 64);
    for (const auto& f : all_flows(t))
        CHECK(f.seen == 1000);
}

static void test_flow_threads() {
    wired_flow_tracker::params p;
    p.max_flows = 256;
    p.tcp_idle = p.udp_idle = p.other_idle = 5;
    p.evict_idle = 2;
    wired_flow_tracker t(p, test_seed);

    // Adds in every shard while the clock moves, against expiry and listings
    std::atomic<time_t> clock{1000};
    std::atomic<bool> done{false};
    std::vector<std::thread> adders;
    for (int a = 0; a < 4; a++)
        adders.emplace_back([&, a] {
            for (int i = 0; i < 20000; i++) {
                auto o = obs(static_cast<uint8_t>(10 + a), static_cast<uint8_t>(i >> 8),
                        static_cast<uint16_t>(i), 1, clock.load(), (i & 1) ? 6 : 17, (i & 2) ? 0x01 : 0);
                add2(t, o);
                if (a == 0 && (i % 500) == 0)
                    clock.fetch_add(1);
            }
        });
    std::thread expirer([&] {
        std::vector<wired_flow_tracker::flow> out;
        size_t total;
        while (!done.load()) {
            t.expire(clock.load());
            t.snapshot({}, 0, 50, out, total);
            if (t.get_stats().flows > p.max_flows)
                failures++;
        }
    });
    for (auto& th : adders)
        th.join();
    done = true;
    expirer.join();

    auto st = t.get_stats();
    CHECK(st.flows <= p.max_flows && st.flows == all_flows(t).size());
    CHECK(st.created - st.evicted - st.expired == st.flows);
    CHECK(st.evicted > 0);
}

static void test_escape_hidden() {
    CHECK(escape_hidden("plain") == "plain");
    CHECK(escape_hidden("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80") == "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80");
    CHECK(escape_hidden("a\x7f" "b") == "a\\u007fb");
    CHECK(escape_hidden("\xc2\x85") == "\\u0085");
    CHECK(escape_hidden("soft\xc2\xadhy") == "soft\\u00adhy");
    CHECK(escape_hidden("alm\xd8\x9c") == "alm\\u061c");
    CHECK(escape_hidden("\xe2\x80\x8b\xe2\x80\x8f") == "\\u200b\\u200f");
    CHECK(escape_hidden("\xe2\x80\xa8\xe2\x80\xae") == "\\u2028\\u202e");
    CHECK(escape_hidden("\xe2\x81\xa0\xe2\x81\xa4") == "\\u2060\\u2064");
    CHECK(escape_hidden("\xe2\x81\xa6\xe2\x81\xa9") == "\\u2066\\u2069");
    CHECK(escape_hidden("\xef\xbb\xbf" "bom") == "\\ufeffbom");
    CHECK(escape_hidden("\xef\xbf\xb9\xef\xbf\xbb") == "\\ufff9\\ufffb");
    CHECK(escape_hidden("tag\xf3\xa0\x80\x81\xf3\xa0\x81\xbf") == "tag\\U000e0001\\U000e007f");

    // Neighbours of each range pass
    CHECK(escape_hidden("\xc2\xa0\xc2\xac\xc2\xae") == "\xc2\xa0\xc2\xac\xc2\xae");
    CHECK(escape_hidden("\xd8\x9b\xe2\x80\x8a\xe2\x80\x90\xe2\x81\xa5\xe2\x81\xaa") ==
            "\xd8\x9b\xe2\x80\x8a\xe2\x80\x90\xe2\x81\xa5\xe2\x81\xaa");
    CHECK(escape_hidden("\xef\xbf\xb8\xef\xbf\xbc\xf3\xa0\x82\x80") == "\xef\xbf\xb8\xef\xbf\xbc\xf3\xa0\x82\x80");

    // Truncated or stray bytes are copied, never read past the end
    CHECK(escape_hidden("\xe2\x80") == "\xe2\x80");
    CHECK(escape_hidden("x\xf3\xa0\x80") == "x\xf3\xa0\x80");
    CHECK(escape_hidden("\xc2") == "\xc2");
    CHECK(escape_hidden("\x80\xc2\x85") == "\x80\\u0085");
}

static void test_frame_reuse() {
    // A frame struct reused for a short frame after a DHCP one keeps nothing of the first
    auto pkt = eth(bcast, mac_a, {}, 0x0800, ipv4({0, 0, 0, 0}, {255, 255, 255, 255}, 17,
                udp(68, 67, dhcp4(1, 3, mac_a, opt(12, str("host"))))));
    frame f;
    CHECK(parse_frame(dlt_en10mb, pkt.data(), pkt.size(), f));
    CHECK(f.dhcp4.valid && f.dhcp4.hostname.view() == "host" && f.l4_ok);

    auto arp_short = eth(bcast, mac_a, {}, 0x0806, {0x00, 0x01});
    CHECK(parse_frame(dlt_en10mb, arp_short.data(), arp_short.size(), f));
    CHECK(!f.dhcp4.valid && f.dhcp4.hostname.empty() && f.l3 == l3_type::arp && !f.l4_ok);
    CHECK(!f.ip_src.set() && f.sport == 0);
}

int main() {
    test_l2();
    test_ipv4();
    test_ipv6();
    test_arp();
    test_dhcp4();
    test_dns_names();
    test_dhcp6();
    test_flows();
    test_flow_seed_collision();
    test_flow_forged_keys();
    test_flow_hash_seed();
    test_ip_hash_seed();
    test_flow_times();
    test_flow_evict();
    test_flow_evict_closed();
    test_flow_full_drop();
    test_flow_evict_cursor();
    test_flow_threads();
    test_frame_reuse();
    test_escape_hidden();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("all wired parser and flow tests passed\n");
    return 0;
}
