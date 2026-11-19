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

#include "kis_l3_parse.h"

// In this file, a variable named *_len or avail is always a count of captured bytes which
// bounds reads; header length fields from the wire are named *_wire and only shorten them.

namespace kis_l3 {

namespace {

constexpr uint16_t be16(const uint8_t *p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

constexpr uint32_t be32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
        (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

void set_v4(ip_addr& a, const uint8_t *p) {
    a.family = 4;
    a.a = {};
    for (size_t i = 0; i < 4; i++)
        a.a[i] = p[i];
}

void set_v6(ip_addr& a, const uint8_t *p) {
    a.family = 6;
    for (size_t i = 0; i < 16; i++)
        a.a[i] = p[i];
}

template<size_t N>
void append_checked(bstr<N>& s, const uint8_t *d, size_t n, frame& out) {
    if (!s.append(d, n))
        out.errors |= err_truncated_string;
}

// A name with no terminating root label is allowed when partial is set (DHCP FQDN options
// may carry a partial name); otherwise as decode_dns_name
bool dns_name(const uint8_t *msg, size_t msg_len, size_t off, bstr<max_dns_name>& out, bool partial) {
    out.len = 0;

    size_t pos = off;
    // Pointers must point before the start of the run of labels being read, so each jump
    // goes strictly backwards and a loop is impossible
    size_t limit = off;
    size_t labels = 0;

    while (true) {
        if (pos >= msg_len)
            return partial && pos == msg_len && limit == off;

        const uint8_t l = msg[pos];

        if (l == 0)
            return true;

        if ((l & 0xc0) == 0xc0) {
            if (pos + 1 >= msg_len)
                return false;

            const size_t ptr = (static_cast<size_t>(l & 0x3f) << 8) | msg[pos + 1];
            if (ptr >= limit)
                return false;

            limit = ptr;
            pos = ptr;
            continue;
        }

        // 0x40 and 0x80 label types are obsolete or reserved
        if (l & 0xc0)
            return false;

        if (l > msg_len - pos - 1)
            return false;

        if (++labels > max_dns_labels)
            return false;

        if (!out.empty() && !out.push('.'))
            return false;

        if (!out.append(msg + pos + 1, l))
            return false;

        pos += 1 + static_cast<size_t>(l);
    }
}

// DHCP client FQDN (option 81 or DHCPv6 39): wire-format name, or ASCII for an option 81
// without the E flag
void fqdn_name(const uint8_t *d, size_t len, bool ascii, bstr<max_dns_name>& out, bool& has, frame& out_f) {
    if (len == 0)
        return;

    if (ascii) {
        out.len = 0;
        // ASCII names may carry their terminating NUL
        size_t n = len;
        if (d[n - 1] == 0)
            n--;
        append_checked(out, d, n, out_f);
        has = !out.empty();
        return;
    }

    // A root-only name is valid but names nothing
    if (dns_name(d, len, 0, out, true)) {
        has = !out.empty();
    } else {
        out.len = 0;
        out_f.errors |= err_dns_name;
    }
}

struct dhcp4_accum {
    bstr<max_opt_string + 3> fqdn_raw;
};

void dhcp4_option(uint8_t code, const uint8_t *d, size_t olen, bool main_area, dhcp4_accum& acc,
        frame& out) {
    auto& h = out.dhcp4;

    switch (code) {
        case 1:
            if (olen >= 4)
                set_v4(h.subnet_mask, d);
            break;
        case 3:
            if (olen >= 4 && !h.router.set())
                set_v4(h.router, d);
            break;
        case 6:
            for (size_t i = 0; i + 4 <= olen && h.n_dns < max_dns_servers; i += 4)
                set_v4(h.dns[h.n_dns++], d + i);
            break;
        case 12:
            append_checked(h.hostname, d, olen, out);
            break;
        case 50:
            if (olen >= 4)
                set_v4(h.requested, d);
            break;
        case 52:
            // Overload is only read from the options field; one in sname or file is ignored
            if (main_area && olen >= 1 && d[0] >= 1 && d[0] <= 3)
                h.overload = d[0];
            break;
        case 53:
            if (olen >= 1)
                h.msgtype = d[0];
            break;
        case 54:
            if (olen >= 4)
                set_v4(h.server_id, d);
            break;
        case 55:
            append_checked(h.prl, d, olen, out);
            break;
        case 60:
            append_checked(h.vendor, d, olen, out);
            break;
        case 61:
            append_checked(h.client_id, d, olen, out);
            break;
        case 81:
            // RFC 3396 splits long options over several instances; join them, then decode
            append_checked(acc.fqdn_raw, d, olen, out);
            break;
        default:
            break;
    }
}

void dhcp4_options(const uint8_t *p, size_t len, bool main_area, dhcp4_accum& acc, frame& out) {
    size_t i = 0;

    while (i < len) {
        const uint8_t code = p[i];

        if (code == 0) {
            i++;
            continue;
        }

        if (code == 255)
            return;

        if (len - i < 2) {
            out.errors |= err_dhcp_opt;
            return;
        }

        const size_t olen = p[i + 1];

        if (olen > len - i - 2) {
            out.errors |= err_dhcp_opt;
            return;
        }

        dhcp4_option(code, p + i + 2, olen, main_area, acc, out);
        i += 2 + olen;
    }
}

void parse_udp(const uint8_t *p, size_t len, frame& out) {
    if (len < 8) {
        out.errors |= err_l4_short;
        return;
    }

    out.sport = be16(p);
    out.dport = be16(p + 2);
    out.l4_ok = true;

    const size_t udp_wire = be16(p + 4);
    if (udp_wire < 8) {
        out.errors |= err_ip_len;
        return;
    }

    size_t payload_len = len - 8;
    if (udp_wire - 8 < payload_len)
        payload_len = udp_wire - 8;

    const auto s = out.sport, d = out.dport;

    if ((s == 68 && d == 67) || (s == 67 && d == 68) || (s == 67 && d == 67))
        parse_dhcp4(p + 8, payload_len, out);
    else if ((s == 546 && d == 547) || (s == 547 && d == 546) || (s == 547 && d == 547))
        parse_dhcp6(p + 8, payload_len, out);
}

void parse_l4(uint8_t proto, const uint8_t *p, size_t len, frame& out) {
    out.ip_proto = proto;

    switch (proto) {
        case 6:
            if (len < 20) {
                out.errors |= err_l4_short;
                return;
            }
            out.sport = be16(p);
            out.dport = be16(p + 2);
            out.tcp_flags = p[13];
            out.l4_ok = true;
            break;
        case 17:
            parse_udp(p, len, out);
            break;
        case 1:
        case 58:
            if (len < 4) {
                out.errors |= err_l4_short;
                return;
            }
            out.icmp_type = p[0];
            out.l4_ok = true;
            break;
        default:
            break;
    }
}

void parse_ipv4(const uint8_t *p, size_t len, frame& out) {
    if (len < 20) {
        out.errors |= err_ip_short;
        return;
    }

    const size_t hdr_len = static_cast<size_t>(p[0] & 0x0f) * 4;
    if ((p[0] >> 4) != 4 || hdr_len < 20) {
        out.errors |= err_ip_hdr;
        return;
    }

    out.l3 = l3_type::ipv4;
    out.ipv4_ihl = static_cast<uint8_t>(hdr_len);
    out.ttl = p[8];
    out.ip_proto = p[9];
    set_v4(out.ip_src, p + 12);
    set_v4(out.ip_dst, p + 16);

    const uint16_t frag = be16(p + 6);
    out.more_fragments = (frag & 0x2000) != 0;

    if (hdr_len > len) {
        out.errors |= err_ip_short;
        return;
    }

    const size_t total_wire = be16(p + 2);
    if (total_wire < hdr_len) {
        out.errors |= err_ip_len;
        return;
    }

    // Trailing Ethernet padding is not part of the datagram
    size_t l4_len = len - hdr_len;
    if (total_wire - hdr_len < l4_len)
        l4_len = total_wire - hdr_len;

    if ((frag & 0x1fff) != 0) {
        out.fragment = true;
        return;
    }

    parse_l4(out.ip_proto, p + hdr_len, l4_len, out);
}

void parse_ipv6(const uint8_t *p, size_t len, frame& out) {
    if (len < 40) {
        out.errors |= err_ip_short;
        return;
    }

    if ((p[0] >> 4) != 6) {
        out.errors |= err_ip_hdr;
        return;
    }

    out.l3 = l3_type::ipv6;
    out.ttl = p[7];
    set_v6(out.ip_src, p + 8);
    set_v6(out.ip_dst, p + 24);

    size_t avail = len - 40;
    const size_t payload_wire = be16(p + 4);
    // 0 is a jumbogram, whose length is in a hop-by-hop option; read what was captured
    if (payload_wire != 0 && payload_wire < avail)
        avail = payload_wire;

    uint8_t nh = p[6];
    const uint8_t *q = p + 40;

    while (true) {
        size_t hl;

        switch (nh) {
            case 0:     // hop-by-hop
            case 43:    // routing
            case 60:    // destination options
            case 135:   // mobility
            case 139:   // HIP
            case 140:   // shim6
                if (out.n_ext >= max_ipv6_ext) {
                    out.errors |= err_ext_deep;
                    out.ip_proto = nh;
                    return;
                }
                if (avail < 8) {
                    out.errors |= err_ip_short;
                    out.ip_proto = nh;
                    return;
                }
                hl = (static_cast<size_t>(q[1]) + 1) * 8;
                break;
            case 51:    // authentication header
                if (out.n_ext >= max_ipv6_ext) {
                    out.errors |= err_ext_deep;
                    out.ip_proto = nh;
                    return;
                }
                if (avail < 8) {
                    out.errors |= err_ip_short;
                    out.ip_proto = nh;
                    return;
                }
                hl = (static_cast<size_t>(q[1]) + 2) * 4;
                break;
            case 44:    // fragment
                if (out.n_ext >= max_ipv6_ext) {
                    out.errors |= err_ext_deep;
                    out.ip_proto = nh;
                    return;
                }
                if (avail < 8) {
                    out.errors |= err_ip_short;
                    out.ip_proto = nh;
                    return;
                }
                out.n_ext++;
                out.more_fragments = (q[3] & 0x01) != 0;
                if ((be16(q + 2) >> 3) != 0) {
                    out.fragment = true;
                    out.ip_proto = q[0];
                    return;
                }
                nh = q[0];
                q += 8;
                avail -= 8;
                continue;
            default:
                // ESP (50) and no next header (59) end here too, with nothing to read
                if (nh == 50 || nh == 59) {
                    out.ip_proto = nh;
                    return;
                }
                parse_l4(nh, q, avail, out);
                return;
        }

        if (hl > avail) {
            out.errors |= err_ip_short;
            out.ip_proto = nh;
            return;
        }

        out.n_ext++;
        nh = q[0];
        q += hl;
        avail -= hl;
    }
}

void parse_arp(const uint8_t *p, size_t len, frame& out) {
    out.l3 = l3_type::arp;

    if (len < 8) {
        out.errors |= err_arp;
        return;
    }

    out.arp_op = be16(p + 6);

    // Only Ethernet / IPv4 ARP has addresses we use
    if (be16(p) != 1 || be16(p + 2) != 0x0800)
        return;

    if (p[4] != 6 || p[5] != 4 || len < 28) {
        out.errors |= err_arp;
        return;
    }

    for (size_t i = 0; i < 6; i++) {
        out.arp_sha[i] = p[8 + i];
        out.arp_tha[i] = p[18 + i];
    }
    set_v4(out.arp_spa, p + 14);
    set_v4(out.arp_tpa, p + 24);
}

// The VLAN tags and the network layer, from the first ethertype on
void parse_tags_l3(uint16_t type, const uint8_t *data, size_t caplen, size_t off, frame& out) {
    while (is_vlan_tpid(type)) {
        if (out.n_tags >= max_vlan_tags) {
            out.errors |= err_tags_deep;
            return;
        }

        if (caplen - off < 4) {
            out.errors |= err_l2_short;
            return;
        }

        out.tags[out.n_tags++] = vlan_tag{type, be16(data + off)};
        type = be16(data + off + 2);
        off += 4;
    }

    if (type < 0x0600) {
        out.llc = true;

        // LLC/SNAP with an ethertype
        if (caplen - off >= 8 && data[off] == 0xaa && data[off + 1] == 0xaa && data[off + 2] == 0x03 &&
                data[off + 3] == 0 && data[off + 4] == 0 && data[off + 5] == 0) {
            type = be16(data + off + 6);
            off += 8;
        } else {
            return;
        }
    }

    out.ethertype = type;
    parse_l3(type, data + off, caplen - off, out);
}

dst_class sll_class(uint16_t pkttype, frame& out) {
    switch (pkttype) {
        case 0:     // to us
        case 3:     // to someone else
            return dst_class::unicast;
        case 1:
            return dst_class::broadcast;
        case 2:
            return dst_class::multicast;
        case 4:
            out.outgoing = true;
            return dst_class::unknown;
        default:
            return dst_class::unknown;
    }
}

}

bool decode_dns_name(const uint8_t *msg, size_t msg_len, size_t off, bstr<max_dns_name>& out) {
    if (dns_name(msg, msg_len, off, out, false))
        return true;
    out.len = 0;
    return false;
}

void parse_dhcp4(const uint8_t *p, size_t len, frame& out) {
    auto& h = out.dhcp4;

    // Fixed header (236) and the magic cookie
    if (len < 240) {
        out.errors |= err_dhcp;
        return;
    }

    if ((p[0] != 1 && p[0] != 2) || be32(p + 236) != 0x63825363) {
        out.errors |= err_dhcp;
        return;
    }

    h.valid = true;
    h.op = p[0];
    h.chaddr_eth = (p[1] == 1 && p[2] == 6);
    h.xid = be32(p + 4);
    set_v4(h.ciaddr, p + 12);
    set_v4(h.yiaddr, p + 16);
    set_v4(h.siaddr, p + 20);
    for (size_t i = 0; i < 6; i++)
        h.chaddr[i] = p[28 + i];

    dhcp4_accum acc;

    dhcp4_options(p + 240, len - 240, true, acc, out);

    // RFC 2132 9.3: the file field is read before sname
    if (h.overload & 1)
        dhcp4_options(p + 108, 128, false, acc, out);
    if (h.overload & 2)
        dhcp4_options(p + 44, 64, false, acc, out);

    if (!acc.fqdn_raw.empty()) {
        const auto *r = reinterpret_cast<const uint8_t *>(acc.fqdn_raw.buf.data());
        // flags, rcode1, rcode2, name; the E flag (0x04) means wire format
        if (acc.fqdn_raw.len >= 3)
            fqdn_name(r + 3, acc.fqdn_raw.len - 3, !(r[0] & 0x04), h.fqdn, h.has_fqdn, out);
        else
            out.errors |= err_dhcp_opt;
    }
}

void parse_dhcp6(const uint8_t *p, size_t len, frame& out) {
    auto& h = out.dhcp6;

    if (len < 4) {
        out.errors |= err_dhcp6;
        return;
    }

    if (p[0] == 0 || p[0] > 36) {
        out.errors |= err_dhcp6;
        return;
    }

    // Relay messages wrap the client's message; not unwrapped here
    if (p[0] == 12 || p[0] == 13)
        return;

    h.valid = true;
    h.msgtype = p[0];
    h.xid = (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3];

    size_t i = 4;

    while (i < len) {
        if (len - i < 4) {
            out.errors |= err_dhcp6;
            return;
        }

        const uint16_t code = be16(p + i);
        const size_t olen = be16(p + i + 2);

        if (olen > len - i - 4) {
            out.errors |= err_dhcp6;
            return;
        }

        const uint8_t *d = p + i + 4;

        switch (code) {
            case 1:
                if (h.client_duid.empty())
                    append_checked(h.client_duid, d, olen, out);
                break;
            case 2:
                if (h.server_duid.empty())
                    append_checked(h.server_duid, d, olen, out);
                break;
            case 3:     // IA_NA: IAID, T1, T2, options
            case 4: {   // IA_TA: IAID, options
                const size_t hdr = code == 3 ? 12 : 4;
                if (olen < hdr)
                    break;
                size_t j = hdr;
                while (olen - j >= 4) {
                    const uint16_t sc = be16(d + j);
                    const size_t sl = be16(d + j + 2);
                    if (sl > olen - j - 4) {
                        out.errors |= err_dhcp6;
                        break;
                    }
                    if (sc == 5 && sl >= 24 && h.n_ia_addrs < max_ia_addrs)
                        set_v6(h.ia_addrs[h.n_ia_addrs++], d + j + 4);
                    j += 4 + sl;
                }
                break;
            }
            case 6:
                for (size_t j = 0; j + 2 <= olen && h.n_oro < max_oro; j += 2)
                    h.oro[h.n_oro++] = be16(d + j);
                break;
            case 16:    // vendor class: enterprise, then length-prefixed items
                if (olen >= 6 && h.vendor.empty()) {
                    h.vendor_enterprise = be32(d);
                    const size_t il = be16(d + 4);
                    if (il <= olen - 6)
                        append_checked(h.vendor, d + 6, il, out);
                    else
                        out.errors |= err_dhcp6;
                }
                break;
            case 39:    // client FQDN: flags, then a wire-format name
                if (olen >= 1 && !h.has_fqdn)
                    fqdn_name(d + 1, olen - 1, false, h.fqdn, h.has_fqdn, out);
                break;
            default:
                break;
        }

        i += 4 + olen;
    }
}

void parse_l3(uint16_t ethertype, const uint8_t *data, size_t len, frame& out) {
    switch (ethertype) {
        case 0x0800:
            parse_ipv4(data, len, out);
            break;
        case 0x86dd:
            parse_ipv6(data, len, out);
            break;
        case 0x0806:
            parse_arp(data, len, out);
            break;
        default:
            out.l3 = l3_type::other;
            break;
    }
}

bool parse_frame(int dlt, const uint8_t *data, size_t caplen, frame& out) {
    out.reset();

    if (data == nullptr)
        return false;

    if (dlt == dlt_en10mb) {
        if (caplen < 14) {
            out.errors |= err_l2_short;
            return false;
        }

        for (size_t i = 0; i < 6; i++) {
            out.dst[i] = data[i];
            out.src[i] = data[6 + i];
        }

        out.has_dst = true;
        out.l2_ok = true;

        bool bcast = true;
        for (size_t i = 0; i < 6; i++)
            if (out.dst[i] != 0xff)
                bcast = false;

        if (bcast)
            out.dclass = dst_class::broadcast;
        else if (out.dst[0] & 0x01)
            out.dclass = dst_class::multicast;
        else
            out.dclass = dst_class::unicast;

        parse_tags_l3(be16(data + 12), data, caplen, 14, out);
        return true;
    }

    size_t hdr_len;
    uint16_t pkttype, hatype, halen, proto;
    const uint8_t *addr;

    if (dlt == dlt_linux_sll) {
        hdr_len = 16;
        if (caplen < hdr_len) {
            out.errors |= err_l2_short;
            return false;
        }
        pkttype = be16(data);
        hatype = be16(data + 2);
        halen = be16(data + 4);
        addr = data + 6;
        proto = be16(data + 14);
    } else if (dlt == dlt_linux_sll2) {
        hdr_len = 20;
        if (caplen < hdr_len) {
            out.errors |= err_l2_short;
            return false;
        }
        proto = be16(data);
        hatype = be16(data + 8);
        pkttype = data[10];
        halen = data[11];
        addr = data + 12;
    } else {
        return false;
    }

    // Only Ethernet interfaces of an "any" capture have a MAC to track
    if (hatype != 1 || halen != 6)
        return false;

    for (size_t i = 0; i < 6; i++)
        out.src[i] = addr[i];

    out.l2_ok = true;
    out.dclass = sll_class(pkttype, out);

    // Cooked headers give the protocol in host terms: 1 and 4 are 802.3 and 802.2 frames
    if (proto < 0x0600) {
        out.llc = true;
        return true;
    }

    parse_tags_l3(proto, data, caplen, hdr_len, out);
    return true;
}

std::string escape_hidden(std::string s) {
    // Every hidden code point has one of these lead bytes
    bool any = false;
    for (auto c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u == 0x7f || u == 0xc2 || u == 0xd8 || u == 0xe2 || u == 0xef || u == 0xf3) {
            any = true;
            break;
        }
    }

    if (!any)
        return s;

    static constexpr char hx[] = "0123456789abcdef";
    std::string r;
    r.reserve(s.length() + 16);

    const auto cont = [&s](size_t i) {
        return i < s.length() && (static_cast<unsigned char>(s[i]) & 0xc0) == 0x80;
    };
    const auto bits = [&s](size_t i) { return static_cast<uint32_t>(static_cast<unsigned char>(s[i]) & 0x3f); };

    for (size_t i = 0; i < s.length(); ) {
        const auto u = static_cast<unsigned char>(s[i]);
        size_t n = 1;
        uint32_t cp = u;

        // Decoded only when the continuation bytes are there; otherwise the byte is copied
        if (u >= 0xf0 && u < 0xf8 && cont(i + 1) && cont(i + 2) && cont(i + 3)) {
            n = 4;
            cp = ((u & 0x07u) << 18) | (bits(i + 1) << 12) | (bits(i + 2) << 6) | bits(i + 3);
        } else if (u >= 0xe0 && u < 0xf0 && cont(i + 1) && cont(i + 2)) {
            n = 3;
            cp = ((u & 0x0fu) << 12) | (bits(i + 1) << 6) | bits(i + 2);
        } else if (u >= 0xc0 && u < 0xe0 && cont(i + 1)) {
            n = 2;
            cp = ((u & 0x1fu) << 6) | bits(i + 1);
        } else if (u >= 0x80) {
            cp = 0xfffd;
        }

        if (hidden_codepoint(cp)) {
            const int digits = cp > 0xffff ? 8 : 4;
            r += cp > 0xffff ? "\\U" : "\\u";
            for (int sh = (digits - 1) * 4; sh >= 0; sh -= 4)
                r.push_back(hx[(cp >> sh) & 0xf]);
        } else {
            r.append(s, i, n);
        }

        i += n;
    }

    return r;
}

}
