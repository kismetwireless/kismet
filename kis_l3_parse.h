/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __KIS_L3_PARSE_H__
#define __KIS_L3_PARSE_H__

// Bounded decode of a wired frame: the link header (Ethernet, Linux cooked SLL and SLL2),
// up to 4 VLAN tags, then IPv4, IPv6, ARP, UDP, TCP, ICMPv6, DHCPv4 and DHCPv6.
//
// Every read is guarded by the captured length; lengths from the frame (IPv4 total length,
// IPv6 payload length, UDP length) only ever shorten what is read, never extend it.  Strings
// are copied raw (bounded, not printable) for the caller to clean up.  Parsing doesn't
// allocate or throw; one call fills one frame struct from scratch.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace kis_l3 {

constexpr int dlt_en10mb = 1;
constexpr int dlt_linux_sll = 113;
constexpr int dlt_linux_sll2 = 276;

constexpr size_t max_vlan_tags = 4;
constexpr size_t max_ipv6_ext = 8;
constexpr size_t max_dns_name = 255;
constexpr size_t max_dns_labels = 128;
constexpr size_t max_opt_string = 255;
constexpr size_t max_duid = 130;
constexpr size_t max_oro = 32;
constexpr size_t max_ia_addrs = 4;
constexpr size_t max_dns_servers = 4;

constexpr bool is_vlan_tpid(uint16_t t) {
    return t == 0x8100 || t == 0x88a8 || t == 0x9100 || t == 0x9200;
}

// A bounded byte string; len never exceeds N
template<size_t N>
struct bstr {
    uint16_t len = 0;
    std::array<char, N> buf{};

    // Appends up to the capacity, returns false if anything was cut
    bool append(const uint8_t *d, size_t n) {
        size_t room = N - len;
        size_t take = n < room ? n : room;
        for (size_t i = 0; i < take; i++)
            buf[len + i] = static_cast<char>(d[i]);
        len = static_cast<uint16_t>(len + take);
        return take == n;
    }

    bool push(char c) {
        if (len >= N)
            return false;
        buf[len++] = c;
        return true;
    }

    std::string_view view() const { return std::string_view(buf.data(), len); }
    bool empty() const { return len == 0; }
    void clear() { len = 0; }
};

enum class dst_class : uint8_t { unknown, unicast, multicast, broadcast };

enum class l3_type : uint8_t { none, ipv4, ipv6, arp, other };

// Things that were wrong with the frame; parsing stops at the first one that makes the rest
// unreadable
constexpr uint32_t err_l2_short = 1 << 0;
constexpr uint32_t err_tags_deep = 1 << 1;
constexpr uint32_t err_ip_short = 1 << 2;
constexpr uint32_t err_ip_hdr = 1 << 3;
constexpr uint32_t err_ip_len = 1 << 4;
constexpr uint32_t err_ext_deep = 1 << 5;
constexpr uint32_t err_l4_short = 1 << 6;
constexpr uint32_t err_arp = 1 << 7;
constexpr uint32_t err_dhcp = 1 << 8;
constexpr uint32_t err_dhcp_opt = 1 << 9;
constexpr uint32_t err_dhcp6 = 1 << 10;
constexpr uint32_t err_dns_name = 1 << 11;
constexpr uint32_t err_truncated_string = 1 << 12;

struct ip_addr {
    uint8_t family = 0;            // 4, 6, or 0 when unset
    std::array<uint8_t, 16> a{};

    bool set() const { return family != 0; }
    bool operator==(const ip_addr& o) const { return family == o.family && a == o.a; }
    bool operator!=(const ip_addr& o) const { return !(*this == o); }
};

struct vlan_tag {
    uint16_t tpid;
    uint16_t tci;

    uint16_t vid() const { return tci & 0x0fff; }
    uint8_t pcp() const { return tci >> 13; }
};

// Each record splits into fixed fields, cleared by assigning a fresh one, and bounded strings,
// cleared by length; reset() leaves the string buffers alone, so a frame isn't 2.5 kB of
// zeroing per packet
struct dhcp4_fixed {
    bool valid = false;
    uint8_t op = 0;
    uint8_t msgtype = 0;           // option 53; 0 if missing (BOOTP)
    uint32_t xid = 0;
    std::array<uint8_t, 6> chaddr{};
    bool chaddr_eth = false;       // htype 1, hlen 6
    ip_addr ciaddr, yiaddr, siaddr;
    ip_addr requested;             // option 50
    ip_addr server_id;             // option 54
    ip_addr router;                // option 3, first address
    ip_addr subnet_mask;           // option 1
    std::array<ip_addr, max_dns_servers> dns{};
    uint8_t n_dns = 0;
    uint8_t overload = 0;          // option 52
    bool has_fqdn = false;
};

struct dhcp4_info : dhcp4_fixed {
    bstr<max_opt_string> hostname; // option 12
    bstr<max_opt_string> vendor;   // option 60
    bstr<max_opt_string> client_id;    // option 61, raw
    bstr<max_opt_string> prl;      // option 55, raw option codes
    bstr<max_dns_name> fqdn;       // option 81, decoded

    void reset() {
        static_cast<dhcp4_fixed&>(*this) = dhcp4_fixed{};
        hostname.clear();
        vendor.clear();
        client_id.clear();
        prl.clear();
        fqdn.clear();
    }
};

struct dhcp6_fixed {
    bool valid = false;
    uint8_t msgtype = 0;
    uint32_t xid = 0;
    bool has_fqdn = false;
    uint32_t vendor_enterprise = 0;
    std::array<uint16_t, max_oro> oro{};   // option 6
    uint8_t n_oro = 0;
    std::array<ip_addr, max_ia_addrs> ia_addrs{};  // IA_NA / IA_TA addresses
    uint8_t n_ia_addrs = 0;
};

struct dhcp6_info : dhcp6_fixed {
    bstr<max_duid> client_duid;    // option 1
    bstr<max_duid> server_duid;    // option 2
    bstr<max_dns_name> fqdn;       // option 39, decoded
    bstr<max_opt_string> vendor;   // option 16, first vendor-class-data item

    void reset() {
        static_cast<dhcp6_fixed&>(*this) = dhcp6_fixed{};
        client_duid.clear();
        server_duid.clear();
        fqdn.clear();
        vendor.clear();
    }
};

struct frame_fixed {
    uint32_t errors = 0;

    // Link layer
    bool l2_ok = false;
    bool has_dst = false;          // SLL/SLL2 carry only the source
    std::array<uint8_t, 6> src{};
    std::array<uint8_t, 6> dst{};
    dst_class dclass = dst_class::unknown;
    bool outgoing = false;         // SLL packet type 4: sent by the capturing host
    uint8_t n_tags = 0;
    std::array<vlan_tag, max_vlan_tags> tags{};
    uint16_t ethertype = 0;        // after the tags; 0 for an 802.3 length frame
    bool llc = false;

    // Network layer
    l3_type l3 = l3_type::none;
    ip_addr ip_src, ip_dst;
    uint8_t ttl = 0;
    uint8_t ip_proto = 0;          // the transport protocol, after IPv6 extension headers
    uint8_t ipv4_ihl = 0;
    uint8_t n_ext = 0;
    bool fragment = false;         // a non-first fragment: no transport header
    bool more_fragments = false;

    // ARP (htype 1, ptype IPv4 only)
    uint16_t arp_op = 0;
    std::array<uint8_t, 6> arp_sha{}, arp_tha{};
    ip_addr arp_spa, arp_tpa;

    // Transport layer
    bool l4_ok = false;
    uint16_t sport = 0, dport = 0;
    uint8_t tcp_flags = 0;
    uint8_t icmp_type = 0;
};

struct frame : frame_fixed {
    dhcp4_info dhcp4;
    dhcp6_info dhcp6;

    void reset() {
        static_cast<frame_fixed&>(*this) = frame_fixed{};
        dhcp4.reset();
        dhcp6.reset();
    }
};

// Decode one frame of the given DLT; false only when the link header itself can't be read
bool parse_frame(int dlt, const uint8_t *data, size_t caplen, frame& out);

// The DLT handlers above, from the network layer on: an ethertype and the bytes after it
void parse_l3(uint16_t ethertype, const uint8_t *data, size_t len, frame& out);

// DHCPv4 and DHCPv6 messages (the UDP payload)
void parse_dhcp4(const uint8_t *data, size_t len, frame& out);
void parse_dhcp6(const uint8_t *data, size_t len, frame& out);

// A DNS wire-format name at offset off of msg; pointers may only point backwards.  Labels
// are joined with '.'; false on any loop, overrun, or more than max_dns_labels labels.
bool decode_dns_name(const uint8_t *msg, size_t msg_len, size_t off, bstr<max_dns_name>& out);

// Code points that are valid UTF-8 but hide or reorder text on screen: DEL, C1 controls, soft
// hyphen, the Arabic letter mark, zero-width and direction marks, line and paragraph separators,
// direction embeddings and isolates, invisible operators, the BOM, interlinear annotation
// controls, and tag characters
constexpr bool hidden_codepoint(uint32_t cp) {
    return cp == 0x7f || (cp >= 0x80 && cp <= 0x9f) || cp == 0xad || cp == 0x61c ||
        (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) ||
        (cp >= 0x2060 && cp <= 0x2064) || (cp >= 0x2066 && cp <= 0x2069) || cp == 0xfeff ||
        (cp >= 0xfff9 && cp <= 0xfffb) || (cp >= 0xe0000 && cp <= 0xe007f);
}

// s with each hidden code point written as \uXXXX (\UXXXXXXXX above U+FFFF).  Meant for
// valid UTF-8; any other byte is copied as it is.
std::string escape_hidden(std::string s);

}

#endif
