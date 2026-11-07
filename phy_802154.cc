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

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <memory>

#include "devicetracker_component.h"
#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"
#include "messagebus.h"
#include "crc32.h"
#include "configfile.h"
#include "wire_order.h"

#include "phy_802154.h"
#include "zigbee_crypto.h"

#include <cmath>

#define BEACON_802154   0x00
#define DATA_802154     0x01
#define ACK_802154      0x02
#define CMD_802154      0x03

// 802.15.4 frame control, decoded from its little-endian wire value
struct _802_15_4_fcf {
    unsigned int type = 0;
    unsigned int security = 0;
    unsigned int pending = 0;
    unsigned int ack_req = 0;
    unsigned int pan_id_comp = 0;
    unsigned int reserved = 0;
    unsigned int sns = 0;
    unsigned int iep = 0;
    unsigned int dest_addr_mode = 0;
    unsigned int frame_ver = 0;
    unsigned int src_addr_mode = 0;

    static constexpr _802_15_4_fcf decode(uint16_t v) {
        _802_15_4_fcf f;
        f.type = v & 0x07;
        f.security = (v >> 3) & 0x01;
        f.pending = (v >> 4) & 0x01;
        f.ack_req = (v >> 5) & 0x01;
        f.pan_id_comp = (v >> 6) & 0x01;
        f.reserved = (v >> 7) & 0x01;
        f.sns = (v >> 8) & 0x01;
        f.iep = (v >> 9) & 0x01;
        f.dest_addr_mode = (v >> 10) & 0x03;
        f.frame_ver = (v >> 12) & 0x03;
        f.src_addr_mode = (v >> 14) & 0x03;
        return f;
    }
};

// Data frame, ack request, PAN id compression, short dest, 2006 version, long source
static_assert(_802_15_4_fcf::decode(0xd861).type == DATA_802154);
static_assert(_802_15_4_fcf::decode(0xd861).ack_req == 1);
static_assert(_802_15_4_fcf::decode(0xd861).pan_id_comp == 1);
static_assert(_802_15_4_fcf::decode(0xd861).dest_addr_mode == 0x02);
static_assert(_802_15_4_fcf::decode(0xd861).frame_ver == 0x01);
static_assert(_802_15_4_fcf::decode(0xd861).src_addr_mode == 0x03);


// The 802.15.4 FCS: the ITU-T CRC-16 (x^16 + x^12 + x^5 + 1), initial value 0, LSB first
// (CRC-16/KERMIT), sent low byte first
static uint16_t crc16_802154(const uint8_t *p, size_t n) {
    uint16_t crc = 0;

    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1) ? (uint16_t) ((crc >> 1) ^ 0x8408) : (uint16_t) (crc >> 1);
    }

    return crc;
}

// The IPHC header (RFC 6282) at p: its length up to the next header, and through *nh whether that
// is compressed (1), inline (0, the next header value in *nh_value); 0 when it does not fit.
static unsigned int iphc_length(const uint8_t *p, size_t n, int *nh, uint8_t *nh_value) {
    static const unsigned int tf_len[4] = {4, 3, 1, 0};
    unsigned int l = 2;

    if (n < 2)
        return 0;

    const unsigned int tf = (p[0] >> 3) & 0x03, nhc = (p[0] >> 2) & 0x01, hlim = p[0] & 0x03;
    const unsigned int cid = (p[1] >> 7) & 0x01, sac = (p[1] >> 6) & 0x01, sam = (p[1] >> 4) & 0x03;
    const unsigned int m = (p[1] >> 3) & 0x01, dac = (p[1] >> 2) & 0x01, dam = p[1] & 0x03;

    l += cid;
    l += tf_len[tf];

    if (!nhc) {
        if (l + 1 > n)
            return 0;
        *nh_value = p[l];
        l += 1;
    }

    l += hlim == 0 ? 1 : 0;

    static const unsigned int sam_len[2][4] = {{16, 8, 2, 0}, {0, 8, 2, 0}};
    l += sam_len[sac][sam];

    if (!m) {
        static const unsigned int dam_len[2][4] = {{16, 8, 2, 0}, {0, 8, 2, 0}};
        l += dam_len[dac][dam];
    } else {
        static const unsigned int mdam_len[2][4] = {{16, 6, 4, 1}, {6, 0, 0, 0}};
        l += mdam_len[dac][dam];
    }

    if (l > n)
        return 0;

    *nh = nhc;
    return l;
}

// A UDP datagram carried whole in one 6LoWPAN frame
struct lowpan_udp_datagram {
    unsigned int sport = 0, dport = 0;
    const uint8_t *data = nullptr;
    size_t len = 0;
};

// The UDP datagram of an unfragmented 6LoWPAN frame (IPHC, then NHC or inline UDP): its ports and
// payload.  An inline UDP header's length must fit the frame; with NHC the length is the frame's.
static bool lowpan_udp(const uint8_t *p, size_t n, lowpan_udp_datagram& u) {
    int nh = 0;
    uint8_t nh_value = 0;

    if (n < 2 || (p[0] & 0xe0) != 0x60)
        return false;

    const unsigned int l = iphc_length(p, n, &nh, &nh_value);
    if (l == 0)
        return false;

    if (!nh) {
        // an uncompressed UDP header: source port, destination port, length, checksum
        if (nh_value != 17 || l + 8 > n)
            return false;

        const size_t ulen = (p[l + 4] << 8) | p[l + 5];
        if (ulen < 8 || ulen > n - l)
            return false;

        u.sport = (p[l] << 8) | p[l + 1];
        u.dport = (p[l + 2] << 8) | p[l + 3];
        u.data = p + l + 8;
        u.len = ulen - 8;
        return true;
    }

    // NHC UDP: 11110CPP, the ports (both inline; one 0xf0xx; both 0xf0bx), the checksum unless C
    static constexpr unsigned int port_len[4] = {4, 3, 3, 1};

    if (l + 1 > n || (p[l] & 0xf8) != 0xf0)
        return false;

    const unsigned int ports = p[l] & 0x03;
    const size_t o = l + 1 + port_len[ports] + ((p[l] & 0x04) ? 0 : 2);
    const uint8_t *q = p + l + 1;

    if (o > n)
        return false;

    switch (ports) {
        case 0:
            u.sport = (q[0] << 8) | q[1];
            u.dport = (q[2] << 8) | q[3];
            break;
        case 1:
            u.sport = (q[0] << 8) | q[1];
            u.dport = 0xf000 | q[2];
            break;
        case 2:
            u.sport = 0xf000 | q[0];
            u.dport = (q[1] << 8) | q[2];
            break;
        default:
            u.sport = 0xf0b0 | (q[0] >> 4);
            u.dport = 0xf0b0 | (q[0] & 0x0f);
            break;
    }

    u.data = p + o;
    u.len = n - o;
    return true;
}

// Whether p is a 6LoWPAN frame, its header checked through (RFC 4944, RFC 6282): uncompressed IPv6
// with version 6; IPHC that fits and leads to UDP, ICMPv6, TCP or an IPv6 extension header (or to
// compressed UDP or extension headers); a fragment with a plausible datagram size whose first
// fragment carries IPHC; a mesh header followed by one of these.  One octet is not enough: any
// payload starting 0x40-0xff would otherwise pass.
static bool lowpan_frame(const uint8_t *p, size_t n, int depth = 0) {
    if (n < 2 || depth > 2)
        return false;

    const uint8_t d0 = p[0];

    if (d0 == 0x41)
        return n >= 41 && (p[1] >> 4) == 6;

    if ((d0 & 0xe0) == 0x60) {
        int nh = 0;
        uint8_t nh_value = 0;
        const unsigned int l = iphc_length(p, n, &nh, &nh_value);

        if (l == 0)
            return false;

        if (nh)
            return l < n && ((p[l] & 0xf8) == 0xf0 || (p[l] & 0xf0) == 0xe0);

        return nh_value == 17 || nh_value == 58 || nh_value == 6 || nh_value == 0 ||
            nh_value == 43 || nh_value == 44 || nh_value == 60;
    }

    if ((d0 & 0xf8) == 0xc0 || (d0 & 0xf8) == 0xe0) {
        const unsigned int size = ((d0 & 0x07) << 8) | p[1];
        const size_t hdr = (d0 & 0xf8) == 0xc0 ? 4 : 5;

        if (size < 64 || size > 1280 || n <= hdr)
            return false;

        // a first fragment carries the compressed IPv6 header; later ones carry data
        return (d0 & 0xf8) == 0xe0 || ((p[hdr] & 0xe0) == 0x60 && lowpan_frame(p + hdr, n - hdr, depth + 1));
    }

    if ((d0 & 0xc0) == 0x80) {
        // mesh: originator and final addresses of 8 (V, F clear) or 2 octets, hops left (0xf: one more octet)
        size_t l = 1 + ((d0 & 0x20) ? 2 : 8) + ((d0 & 0x10) ? 2 : 8) + ((d0 & 0x0f) == 0x0f ? 1 : 0);

        return l < n && lowpan_frame(p + l, n - l, depth + 1);
    }

    return false;
}

// A Green Power device known only by its source ID is tracked under a synthetic 8-byte address:
// a locally administered prefix, then the source ID.  Source ID 0 is unspecified, and
// 0xFFFFFFF9 and up are reserved or broadcast, so those never make one.
constexpr uint8_t gpd_addr_prefix[4] = {0x02, 0x47, 0x50, 0x00};

static mac_addr gpd_mac(uint32_t srcid) {
    const uint8_t a[8] = {gpd_addr_prefix[0], gpd_addr_prefix[1], gpd_addr_prefix[2], gpd_addr_prefix[3],
        (uint8_t) (srcid >> 24), (uint8_t) (srcid >> 16), (uint8_t) (srcid >> 8), (uint8_t) srcid};
    return mac_addr(a, 8);
}

static bool is_gpd_mac(const mac_addr& m) {
    return m.length() == 8 && m[0] == gpd_addr_prefix[0] && m[1] == gpd_addr_prefix[1] &&
        m[2] == gpd_addr_prefix[2] && m[3] == gpd_addr_prefix[3];
}

using net_kind = kis_802154_packinfo::network_kind;

static std::string ext_pan_string(const uint8_t *le8) {
    return fmt::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            le8[7], le8[6], le8[5], le8[4], le8[3], le8[2], le8[1], le8[0]);
}

// A Thread extended PAN ID, sent most significant octet first
static std::string thread_ext_pan_string(const uint8_t *be8) {
    return fmt::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            be8[0], be8[1], be8[2], be8[3], be8[4], be8[5], be8[6], be8[7]);
}

// Thread MeshCoP TLVs: type, length (0xff: a 2-octet length follows), value.  Calls
// f(type, value, length) for each whole one, and stops at one that doesn't fit.
template <typename F>
static void meshcop_tlvs(const uint8_t *p, size_t n, F&& f) {
    size_t o = 0;

    while (o + 2 <= n) {
        const unsigned int type = p[o];
        size_t len = p[o + 1], hdr = 2;

        if (len == 0xff) {
            if (o + 4 > n)
                return;
            len = (p[o + 2] << 8) | p[o + 3];
            hdr = 4;
        }

        if (len > n - o - hdr)
            return;

        f(type, p + o + hdr, len);
        o += hdr + len;
    }
}

// What a commissioner's steering data says: all ones lets any device join, all zeros none, and
// anything else is a bloom filter of the devices it expects
static thread_join_state thread_steering(const uint8_t *v, size_t len) {
    if (len == 0)
        return thread_join_state::closed;

    bool ones = true, zeros = true;

    for (size_t i = 0; i < len; i++) {
        ones = ones && v[i] == 0xff;
        zeros = zeros && v[i] == 0x00;
    }

    return ones ? thread_join_state::any : zeros ? thread_join_state::closed : thread_join_state::specific;
}

constexpr unsigned int thread_mle_port = 19788;
constexpr unsigned int mle_discovery_request = 16, mle_discovery_response = 17;
constexpr unsigned int mle_tlv_discovery = 26;
constexpr unsigned int meshcop_ext_pan_id = 2, meshcop_network_name = 3, meshcop_steering = 8,
          meshcop_joiner_port = 18, meshcop_discovery_request = 128, meshcop_discovery_response = 129;

/*
 * MLE (Thread, UDP port 19788): the security suite, then with 255 (none) the command and its TLVs.
 * A Discovery Request (16) or Response (17) carries a Thread Discovery TLV (26) of MeshCoP TLVs: the
 * request its version and whether its sender wants to join; the response its network's version,
 * whether a native commissioner may join, its extended PAN ID, name, steering data (no steering
 * data: no commissioner, so no new devices) and the joiner port.  Other MLE commands are secured.
 */
static void read_mle(const uint8_t *p, size_t n, kis_802154_packinfo *pi) {
    // Secured (suite 0): the auxiliary header gives the key sequence as its key source (key ID
    // mode 2): security control, frame counter, key source, key index
    if (n >= 11 && p[0] == 0x00 && ((p[1] >> 3) & 0x03) == 0x02) {
        pi->has_mle_key_seq = true;
        pi->mle_key_seq = ((uint32_t) p[6] << 24) | ((uint32_t) p[7] << 16) | ((uint32_t) p[8] << 8) | p[9];
        return;
    }

    if (n < 2 || p[0] != 0xff)
        return;

    const unsigned int cmd = p[1];
    if (cmd != mle_discovery_request && cmd != mle_discovery_response)
        return;

    const bool response = cmd == mle_discovery_response;
    size_t o = 2;

    // MLE TLVs have a one-octet length
    while (o + 2 <= n) {
        const unsigned int type = p[o], len = p[o + 1];

        if (len > n - o - 2)
            return;

        if (type == mle_tlv_discovery) {
            bool steering = false;

            meshcop_tlvs(p + o + 2, len, [&](unsigned int t, const uint8_t *v, size_t l) {
                if (t == meshcop_discovery_request && !response && l >= 1) {
                    pi->thread_version = v[0] >> 4;
                    pi->thread_disc = (v[0] & 0x08) ? thread_disc_state::joining : thread_disc_state::scanning;
                } else if (t == meshcop_discovery_response && response && l >= 1) {
                    pi->thread_version = v[0] >> 4;
                    pi->thread_native = v[0] & 0x08;
                } else if (t == meshcop_ext_pan_id && response && l == 8) {
                    pi->ext_pan_id = thread_ext_pan_string(v);
                } else if (t == meshcop_network_name && response && l >= 1 && l <= 16) {
                    pi->network_name = std::string(reinterpret_cast<const char *>(v), strnlen(reinterpret_cast<const char *>(v), l));
                } else if (t == meshcop_steering && l >= 1 && l <= 16) {
                    steering = true;
                    pi->thread_join = thread_steering(v, l);
                } else if (t == meshcop_joiner_port && l == 2) {
                    pi->thread_joiner_port = (v[0] << 8) | v[1];
                }
            });

            if (response && !steering)
                pi->thread_join = thread_join_state::closed;
            if (!response && pi->thread_disc == thread_disc_state::none)
                pi->thread_disc = thread_disc_state::scanning;
        }

        o += 2 + len;
    }
}

// A channel number from the packet's channel, 0 when it isn't one
static unsigned int channel_number(const std::string& ch) {
    if (ch.empty() || ch.length() > 3)
        return 0;

    unsigned int c = 0;

    for (const char x : ch) {
        if (x < '0' || x > '9')
            return 0;
        c = c * 10 + (x - '0');
    }

    return c;
}

static std::string key_string(const uint8_t *k) {
    std::string s;

    for (unsigned int i = 0; i < 16; i++) {
        if (i)
            s += ':';
        s += fmt::format("{:02x}", k[i]);
    }

    return s;
}

// A Transport Key command (APS command 0x05) at c: the key it carries, and its type
static void read_transport_key(const uint8_t *c, size_t n, kis_802154_packinfo *pi) {
    static const char *key_types[] = {"Trust Center master", "network", "application master",
        "application link", "Trust Center link", "high-security network"};

    if (n < 18 || c[0] != 0x05)
        return;

    pi->exposed_key = key_string(c + 2);
    pi->exposed_key_type = c[1] < 6 ? key_types[c[1]] : fmt::format("type {}", c[1]);
}

/*
 * The APS frame of a Zigbee NWK data frame, for keys anyone can know (Zigbee 2.2.5, 4.4): a
 * Transport Key command sent without APS security, whose key is then in the clear, or APS security
 * under a publicly known link key (zigbee_crypto::known_keys, ZigBeeAlliance09 among them): the
 * data key is the link key itself (key identifier 0), the key-transport and key-load keys are hashed
 * from it (2 and 3).  A frame that decrypts and whose MIC verifies under one of these is secured
 * with it.  The CCM* nonce takes the
 * source's extended address from the auxiliary header, or, without the extended nonce, from the
 * NWK or MAC header (srcs, each as sent or null).
 */
static void read_aps(const uint8_t *q, size_t n, const uint8_t *const srcs[3],
        std::vector<zigbee_user_key>& user_keys, kis_802154_packinfo *pi) {
    if (n < 2)
        return;

    const unsigned int fc = q[0], ftype = fc & 0x03, delivery = (fc >> 2) & 0x03;
    const bool secured = (fc >> 5) & 0x01, ext_hdr = (fc >> 7) & 0x01;
    size_t o = 1;

    if (ftype == 0) {
        // the destination endpoint (unicast, broadcast) or group address, cluster, profile,
        // source endpoint
        o += (delivery == 0 || delivery == 2) ? 1 : delivery == 3 ? 2 : 0;
        o += 5;
    } else if (ftype != 1) {
        // acknowledgements carry no key
        return;
    }

    // the APS counter, then the extended header (fragmentation: a block number)
    o += 1;

    if (ext_hdr) {
        if (o + 1 > n)
            return;
        o += 1 + ((q[o] & 0x03) ? 1 : 0);
    }

    if (o >= n)
        return;

    if (!secured) {
        if (ftype == 1 && q[o] == 0x05 && o + 18 <= n) {
            pi->weak_keys |= kis_802154_packinfo::weak_key_clear_transport;
            read_transport_key(q + o, n - o, pi);
        }
        return;
    }

    // The auxiliary security header: security control, frame counter, the source address with
    // the extended nonce, the key sequence number with the network key (identifier 1)
    if (o + 5 > n)
        return;

    const uint8_t sc = q[o];
    const unsigned int key_id = (sc >> 3) & 0x03;
    const bool ext_nonce = (sc >> 5) & 0x01;
    const size_t aux_end = o + 5 + (ext_nonce ? 8 : 0) + (key_id == 1 ? 1 : 0);

    if (aux_end + 4 > n || aux_end > zigbee_crypto::max_ccm_len)
        return;

    const uint8_t *const aux_src[3] = {q + o + 5, nullptr, nullptr};
    const uint8_t *const *cand = ext_nonce ? aux_src : srcs;

    // Without a source address there is no nonce, so the frame can't be checked
    if (cand[0] == nullptr && cand[1] == nullptr && cand[2] == nullptr)
        return;

    // The security level is not sent; the nonce and the authenticated header have level 5
    uint8_t a[zigbee_crypto::max_ccm_len];
    memcpy(a, q, aux_end);
    a[o] = (uint8_t) ((sc & 0xf8) | 0x05);

    pi->key_checked = true;

    auto& known = zigbee_crypto::known_ciphers();
    uint8_t plain[zigbee_crypto::max_ccm_len];
    size_t plain_len;

    for (unsigned int i = 0; i < 3; i++) {
        if (cand[i] == nullptr)
            continue;

        uint8_t nonce[13];
        zigbee_crypto::make_nonce(cand[i], q + o + 1, a[o], nonce);

        for (size_t k = 0; k < zigbee_crypto::n_known_keys; k++) {
            if (!zigbee_crypto::ccm_star_decrypt(known[k].aps[key_id], nonce, a, aux_end,
                        q + aux_end, n - aux_end, plain, plain_len))
                continue;

            pi->weak_keys |= kis_802154_packinfo::weak_key_aps;
            pi->key_matched = true;
            pi->aps_key_name = zigbee_crypto::known_keys[k].name;
            if (ftype == 1)
                read_transport_key(plain, plain_len, pi);
            return;
        }

        // then the user's own keys, as link keys
        for (auto& u : user_keys) {
            if (!zigbee_crypto::ccm_star_decrypt(u.ciphers.aps[key_id], nonce, a, aux_end,
                        q + aux_end, n - aux_end, plain, plain_len))
                continue;

            pi->key_matched = true;
            pi->user_key_name = u.name;
            return;
        }
    }
}

/*
 * What a frame's payload says about its network.  Beacons: the superframe specification (the PAN
 * coordinator bit), the GTS and pending-address fields skipped, then the beacon payload's protocol
 * ID: 0 a Zigbee beacon (stack profile, extended PAN ID), 3 a Thread beacon (network name, extended
 * PAN ID).  Data: 6LoWPAN by its dispatch (MLE, UDP port 19788, is Thread), or a Zigbee NWK header
 * (protocol version 2; 3 with no MAC source is Green Power), whose source short and IEEE addresses
 * and security bit are kept, and whose security or APS frame may show a key anyone can know.
 * mac_src is the MAC source's extended address as sent, or null.  Returns false when it says
 * nothing.
 */
static bool read_payload(unsigned int frame_type, bool has_mac_src, const uint8_t *mac_src,
        const uint8_t *p, size_t n, std::vector<zigbee_user_key>& user_keys,
        kis_802154_packinfo *pi) {
    if (frame_type == BEACON_802154) {
        if (n < 4)
            return false;

        const unsigned int sf = p[0] | (p[1] << 8);
        size_t o = 2;

        pi->beacon = true;
        pi->pan_coordinator = (sf >> 14) & 0x01;

        // GTS: the specification, then for a nonzero count the directions and 3 octets each
        const unsigned int gts = p[o] & 0x07;
        o += 1;
        if (gts)
            o += 1 + 3 * gts;

        // pending addresses: the specification, then the short and extended addresses
        if (o + 1 > n)
            return true;
        const unsigned int pend = p[o];
        o += 1 + 2 * (pend & 0x07) + 8 * ((pend >> 4) & 0x07);

        if (o + 1 > n)
            return true;

        if (p[o] == 0x00 && o + 3 + 8 <= n) {
            // Zigbee: protocol ID, stack profile and protocol version, capabilities, extended PAN ID
            pi->network = net_kind::zigbee;
            pi->stack_profile = p[o + 1] & 0x0f;
            pi->ext_pan_id = ext_pan_string(p + o + 3);
        } else if (p[o] == 0x03 && o + 2 + 16 + 8 <= n) {
            // Thread 1.1: protocol ID, version and flags (joining permitted, native commissioner),
            // network name (16), extended PAN ID (8, most significant octet first), then MeshCoP
            // TLVs: the steering data says which devices may join
            const unsigned int flags = p[o + 1];

            pi->network = net_kind::thread;
            pi->thread_version = flags >> 4;
            pi->thread_native = flags & 0x08;
            const char *name = reinterpret_cast<const char *>(p + o + 2);
            pi->network_name = std::string(name, strnlen(name, 16));
            pi->ext_pan_id = thread_ext_pan_string(p + o + 18);

            if (!(flags & 0x01)) {
                pi->thread_join = thread_join_state::closed;
            } else {
                pi->thread_join = thread_join_state::specific;
                meshcop_tlvs(p + o + 26, n - o - 26, [&](unsigned int t, const uint8_t *v, size_t l) {
                    if (t == meshcop_steering && l >= 1 && l <= 16)
                        pi->thread_join = thread_steering(v, l);
                });
            }
        }

        return true;
    }

    if (frame_type != DATA_802154 || n < 2)
        return false;

    // 6LoWPAN, by its whole header; MLE (UDP port 19788) is Thread
    if (lowpan_frame(p, n)) {
        lowpan_udp_datagram u;

        if (lowpan_udp(p, n, u) && (u.dport == thread_mle_port || u.sport == thread_mle_port)) {
            pi->network = net_kind::thread;
            read_mle(u.data, u.len, pi);
        } else {
            pi->network = net_kind::lowpan;
        }

        return true;
    }

    // A Zigbee NWK header: frame type (data, command, inter-PAN), protocol version 2, the discover
    // route field 0 or 1
    const unsigned int fc = p[0] | (p[1] << 8);
    const unsigned int ftype = fc & 0x03, version = (fc >> 2) & 0x0f, discover = (fc >> 6) & 0x03;

    // Green Power: a one-octet NWK frame control (data or maintenance, protocol version 3), the
    // extended frame control when bit 7 is set (application ID, direction), then for
    // application ID 0 the GPD source ID.  Application ID 0 has no MAC source; ID 2 has the
    // GPD's IEEE address as the MAC source.
    if (version == 3) {
        if (ftype > 1)
            return false;

        unsigned int app_id = 0, from_gpp = 0;
        size_t o = 1;

        if (p[0] & 0x80) {
            app_id = p[1] & 0x07;
            from_gpp = (p[1] >> 7) & 0x01;
            o = 2;
        }

        if (app_id != (has_mac_src ? 2u : 0u))
            return false;

        pi->network = net_kind::zigbee_gp;

        // the source ID names the GPD; in a frame to it (from a proxy) it is the destination
        if (app_id == 0 && (ftype == 0 || (p[0] & 0x80)) && o + 4 <= n && !from_gpp) {
            const uint32_t srcid = (uint32_t) p[o] | ((uint32_t) p[o + 1] << 8) |
                ((uint32_t) p[o + 2] << 16) | ((uint32_t) p[o + 3] << 24);

            if (srcid != 0 && srcid < 0xFFFFFFF9) {
                pi->gpd_srcid = srcid;
                pi->has_gpd_srcid = true;
            }
        }

        return true;
    }

    if (version != 2 || ftype == 2 || discover > 1 || n < 8)
        return false;

    pi->network = net_kind::zigbee;
    pi->nwk_secured = (fc >> 9) & 0x01;
    pi->nwk_src = p[4] | (p[5] << 8);

    // after destination, source, radius and sequence: the destination IEEE address, then the source's
    size_t o = 8;
    const uint8_t *nwk_src_ieee = nullptr;

    if ((fc >> 11) & 0x01)
        o += 8;

    if ((fc >> 12) & 0x01) {
        if (o + 8 > n)
            return true;

        for (unsigned int i = 0; i < 8; i++)
            pi->nwk_ieee[7 - i] = p[o + i];
        pi->has_nwk_ieee = true;
        nwk_src_ieee = p + o;
        o += 8;
    }

    // the multicast control field, then the source route subframe (relay count, relay index,
    // the relays)
    if ((fc >> 8) & 0x01)
        o += 1;

    if ((fc >> 10) & 0x01) {
        if (o + 2 > n)
            return true;
        o += 2 + 2 * p[o];
    }

    if (o >= n)
        return true;

    if (!pi->nwk_secured) {
        const uint8_t *const srcs[3] = {nwk_src_ieee, mac_src, nullptr};

        if (ftype == 0)
            read_aps(p + o, n - o, srcs, user_keys, pi);
        return true;
    }

    // NWK security (4.3.1): the auxiliary header (security control, frame counter, source
    // address, key sequence number; always the extended nonce and the network key), the encrypted
    // NWK payload, a 4-octet MIC.  A frame whose MIC verifies under a publicly known key (the TI
    // Z-Stack default key among them) is secured with it, and its APS frame can be read in turn.
    if (o + 14 + 4 > n)
        return true;

    const uint8_t sc = p[o];

    if (!((sc >> 5) & 0x01) || ((sc >> 3) & 0x03) != 1)
        return true;

    const size_t aux_end = o + 14;

    if (aux_end > zigbee_crypto::max_ccm_len)
        return true;

    uint8_t a[zigbee_crypto::max_ccm_len];
    memcpy(a, p, aux_end);
    a[o] = (uint8_t) ((sc & 0xf8) | 0x05);

    uint8_t nonce[13];
    zigbee_crypto::make_nonce(p + o + 5, p + o + 1, a[o], nonce);

    pi->key_checked = true;

    auto& known = zigbee_crypto::known_ciphers();
    uint8_t plain[zigbee_crypto::max_ccm_len];
    size_t plain_len;
    const uint8_t *const srcs[3] = {nwk_src_ieee, p + o + 5, mac_src};

    for (size_t k = 0; k < zigbee_crypto::n_known_keys; k++) {
        if (!zigbee_crypto::ccm_star_decrypt(known[k].nwk, nonce, a, aux_end, p + aux_end,
                    n - aux_end, plain, plain_len))
            continue;

        pi->weak_keys |= kis_802154_packinfo::weak_key_nwk;
        pi->key_matched = true;
        pi->nwk_key_name = zigbee_crypto::known_keys[k].name;
        pi->nwk_key = key_string(zigbee_crypto::known_keys[k].key);

        if (ftype == 0)
            read_aps(plain, plain_len, srcs, user_keys, pi);
        return true;
    }

    // then the user's own keys, as the network key
    for (auto& u : user_keys) {
        if (!zigbee_crypto::ccm_star_decrypt(u.ciphers.nwk, nonce, a, aux_end, p + aux_end,
                    n - aux_end, plain, plain_len))
            continue;

        pi->key_matched = true;
        pi->user_key_name = u.name;

        if (ftype == 0)
            read_aps(plain, plain_len, srcs, user_keys, pi);
        break;
    }

    return true;
}

kis_802154_phy::kis_802154_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("802.15.4");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();

    alert_weakkey_ref =
        alertracker->activate_configured_alert("ZIGBEEWEAKKEY",
                "EXPLOIT", kis_alert_severity::high,
                "A Zigbee network uses a key anyone can know: its Trust Center sent a key in a "
                "Transport Key command without APS security, secured APS frames with a publicly "
                "known link key such as ZigBeeAlliance09 (with which it also sends the network key "
                "to joining devices), or secured NWK frames with a publicly known network key such "
                "as the TI Z-Stack default.  Anyone who receives these frames can decrypt the "
                "network's traffic.", phyid);

    alert_threadjoin_ref =
        alertracker->activate_configured_alert("THREADJOINABLE",
                "OTHER", kis_alert_severity::low,
                "A Thread network is accepting new devices: a router's Discovery Response or Thread "
                "1.1 beacon shows that its commissioner lets any device, or devices it lists, join "
                "with the network's joining credential.  Networks open for joining while a device "
                "is added; one left open, or opened unexpectedly, lets other devices join.", phyid);

    // The user's own keys, zigbee_key=name,key (16 octets in hex, colons and spaces allowed)
    auto sv_trim = [](std::string_view s) {
        while (!s.empty() && isspace((unsigned char) s.front()))
            s.remove_prefix(1);
        while (!s.empty() && isspace((unsigned char) s.back()))
            s.remove_suffix(1);
        return s;
    };

    for (const auto& k : Globalreg::globalreg->kismet_config->fetch_opt_vec("zigbee_key")) {
        auto toks = base_sv_tokenize(k, ",", "");
        if (toks.size() != 2) {
            _MSG_ERROR("Invalid zigbee_key '{}', expected name,key", k);
            continue;
        }

        auto name = sv_trim(toks[0]);
        if (name.length() == 0) {
            _MSG_ERROR("Invalid zigbee_key '{}', the name is empty", k);
            continue;
        }

        std::string hex;
        for (const char c : sv_trim(toks[1]))
            if (c != ':' && c != ' ' && c != '-')
                hex += c;

        uint8_t key[16];
        bool ok = hex.length() == 32;
        for (unsigned int i = 0; ok && i < 16; i++) {
            if (!isxdigit((unsigned char) hex[2 * i]) || !isxdigit((unsigned char) hex[2 * i + 1]))
                ok = false;
            else
                key[i] = (uint8_t) std::stoul(hex.substr(2 * i, 2), nullptr, 16);
        }

        kis_aes::secure_zero(hex.data(), hex.size());

        if (!ok) {
            _MSG_ERROR("Invalid zigbee_key for '{}', the key must be 16 octets in hex", name);
            continue;
        }

        user_keys.push_back(zigbee_user_key{std::string{name}, zigbee_crypto::key_ciphers{key}});
        kis_aes::secure_zero(key, sizeof(key));
    }

    if (!user_keys.empty())
        _MSG_INFO("Loaded {} Zigbee key(s) from zigbee_key", user_keys.size());

    show_keys = Globalreg::globalreg->kismet_config->fetch_opt_bool("zigbee_show_keys", false);

    // Held-back alerts also go out without new frames, as the rate limit allows
    weak_key_timer =
        Globalreg::fetch_mandatory_global_as<time_tracker>()->register_timer(SERVER_TIMESLICES_SEC,
                nullptr, 1, [this](int) -> int {
                    if (alert_weakkey_ref < 0 || !weak_key_backlogged.load())
                        return 1;

                    kis_lock_guard<kis_mutex> wlk(weak_key_mutex, "802154_weak_key timer");
                    drain_weak_key_backlog();
                    weak_key_backlogged.store(!weak_key_backlog.empty());
                    return 1;
                });
    weak_key_backlog_max =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("zigbee_alert_backlog", 64);

    kis_802154_device_entry_id =
        entrytracker->register_field("802154.device",
                tracker_element_factory<kis_802154_tracked_device>(),
                "802.15.4 device");

	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_802154 = packetchain->register_packet_component("802154");

    // Extract the dynamic DLT
    auto dltt =
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");
    dlt = KDLT_IEEE802_15_4_NOFCS;

    packetchain->register_handler(&dissector802154, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&commonclassifier802154, this, CHAINPOS_CLASSIFIER, -100);

    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_802_15_4", "js/kismet.ui.802_15_4.js");
}

kis_802154_phy::~kis_802154_phy() {
    Globalreg::fetch_mandatory_global_as<time_tracker>()->remove_timer(weak_key_timer);
    packetchain->remove_handler(&dissector802154, CHAINPOS_LLCDISSECT);
    packetchain->remove_handler(&commonclassifier802154, CHAINPOS_CLASSIFIER);
}

void kis_802154_phy::drain_weak_key_backlog() {
    while (!weak_key_backlog.empty()) {
        const auto& a = weak_key_backlog.front();

        if (alertracker->raise_alert(alert_weakkey_ref, nullptr, mac_addr{}, a.source, a.dest,
                    mac_addr{}, a.channel, a.text) != 1)
            break;

        weak_key_backlog.pop_front();
    }
}

int kis_802154_phy::dissector802154(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_802154_phy *>(auxdata);

    if (in_pack->duplicate || in_pack->filtered)
        return 1;

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    // Per-packet parse state; the dissector runs in all packet threads at once, so this must
    // not be shared between calls.
    uint8_t dest[2] = {0x00, 0x00};
    uint8_t dest_pan[2] = {0x00, 0x00};
    uint8_t src[2] = {0x00, 0x00};
    uint8_t src_pan[2] = {0x00, 0x00};
    uint8_t ext_dest[8] = {0};
    uint8_t ext_source[8] = {0};
    bool dest_pan_present = false, src_pan_present = false;
    unsigned int payload_off = 0;   // where a readable payload starts (0: none)

    // From the MAC header: a data poll, a CSL period, the security key index (-1: none)
    bool data_poll = false;
    uint16_t csl_period = 0;
    int key_index = -1;

    _802_15_4_fcf fcf_fields;
    const auto hdr_802_15_4_fcf = &fcf_fields;

    if (packdata == nullptr) {
        return 0;
    }

    // Is it a packet we care about?
    if (packdata->dlt != KDLT_IEEE802_15_4_NOFCS && packdata->dlt != KDLT_IEEE802_15_4_TAP) {
        return 0;
    }

    // Where the MPDU starts, and where it ends with its FCS left out
    unsigned int pkt_ctr = 0;
    size_t frame_end = packdata->length();

    if (packdata->dlt == KDLT_IEEE802_15_4_TAP) {
        // The header and its TLVs by their types and lengths, so any TAP writer is read
        struct tap_802_15_4_meta tap;
        const auto *raw = reinterpret_cast<const uint8_t *>(packdata->data());

        if (!tap_802_15_4_parse(raw, packdata->length(), &tap)) {
            in_pack->error = 1;
            return 0;
        }

        const unsigned int fcs_len = tap.fcs_type == 1 ? 2 : tap.fcs_type == 2 ? 4 : 0;

        pkt_ctr = tap.header_len;

        // An MPDU is 3 to 127 octets with its FCS, or up to 2047 on the SUN PHYs, which use
        // the 32-bit FCS
        const size_t max_mpdu = fcs_len == 4 ? 2047 : 127;

        if (packdata->length() < pkt_ctr + 3 + fcs_len || packdata->length() - pkt_ctr > max_mpdu) {
            in_pack->error = 1;
            return 0;
        }

        frame_end = packdata->length() - fcs_len;

        // A frame whose FCS does not check is not attributed to anyone
        if (fcs_len == 2) {
            const uint16_t fcs = (uint16_t) (raw[frame_end] | (raw[frame_end + 1] << 8));

            if (crc16_802154(raw + pkt_ctr, frame_end - pkt_ctr) != fcs) {
                in_pack->error = 1;
                return 0;
            }
        } else if (fcs_len == 4) {
            // the 32-bit FCS is the 802.3 CRC-32, sent low byte first
            const uint32_t fcs = (uint32_t) raw[frame_end] | ((uint32_t) raw[frame_end + 1] << 8) |
                ((uint32_t) raw[frame_end + 2] << 16) | ((uint32_t) raw[frame_end + 3] << 24);

            if (crc32_fast(raw + pkt_ctr, frame_end - pkt_ctr, 0) != fcs) {
                in_pack->error = 1;
                return 0;
            }
        }

        // The signal, channel and frequency the header gives, unless the datasource already
        // set them (Kismet's own 802.15.4 sources do)
        if (!in_pack->signal_info.data_ok &&
                (tap.have_rss || tap.have_legacy_rssi || tap.have_channel || tap.have_frequency)) {
            auto& si = in_pack->signal_info;

            if (tap.have_rss || tap.have_legacy_rssi) {
                si.signal_type = kis_l1_signal_type_dbm;
                si.signal_dbm = tap.have_rss ? (int) std::lround(tap.rss_dbm) : tap.legacy_rssi;
            }

            if (tap.have_channel)
                si.channel = fmt::format("{}", tap.channel);

            if (tap.have_frequency)
                si.freq_khz = tap.frequency_khz;
            else if (tap.have_channel)
                si.freq_khz = tap_802_15_4_channel_khz(tap.channel, tap.page);

            si.data_ok = true;
        }
    } else {
        // Do we have enough data for an OUI? and are within the Zigbee spec
        if (packdata->length() < 6 || packdata->length() > 128) {
            in_pack->error = 1;
            return 0;
        }
    }

    if (in_pack->common_info.common_info_ok) {
        return 0;
    }

    // Are we more than just a header?
    if (pkt_ctr >= frame_end)
        return 0;

    if (packdata->dlt == KDLT_IEEE802_15_4_NOFCS ||
        packdata->dlt == KDLT_IEEE802_15_4_TAP) {

        // Do we have enough for the frame control field?
        if (pkt_ctr + 2 > frame_end)
            return 0;

        fcf_fields = _802_15_4_fcf::decode(
            kismet::load_le<uint16_t>(reinterpret_cast<const uint8_t *>(&packdata->data()[pkt_ctr])));

        pkt_ctr += 2;

        // only parsing specific types of packets
        if (hdr_802_15_4_fcf->type > 0x03) {
            return 0;
        }

        // Check if the specific packet types are actually valid

        // Look for an invalid Beacon
        if (hdr_802_15_4_fcf->type == BEACON_802154) {
            // Beacon should not have security enabled
            if (hdr_802_15_4_fcf->security == 0x01)
                return 0;

            // A beacon has no destination, except an enhanced beacon (2015)
            if (hdr_802_15_4_fcf->dest_addr_mode != 0x00 && hdr_802_15_4_fcf->frame_ver < 0x02)
                return 0;

            // Sequence number suppression is only defined from the 2015 frame version
            if (hdr_802_15_4_fcf->sns && hdr_802_15_4_fcf->frame_ver < 0x02)
                return 0;

            // Frame version not valid for this header type
            if (hdr_802_15_4_fcf->frame_ver == 0x03)
                return 0;
        }

        // Look for invalid Data packet
        if (hdr_802_15_4_fcf->type == DATA_802154) {
            // Data should not have a dest 0x01
            if (hdr_802_15_4_fcf->dest_addr_mode == 0x01)
                return 0;

            // Frame version not valid for this header type
            if (hdr_802_15_4_fcf->frame_ver == 0x03)
                return 0;
        }

        // Look for invalid Ack packet
        if (hdr_802_15_4_fcf->type == ACK_802154) {
            // Ack needs a source
            if (hdr_802_15_4_fcf->src_addr_mode <= 0x01)
                return 0;

            // Ack should not have a dest 0x01
            if (hdr_802_15_4_fcf->dest_addr_mode == 0x01)
                return 0;

            // Ack should not have security enabled
            if (hdr_802_15_4_fcf->security == 0x01)
                return 0;

            // sns not valid for this header type
            if (hdr_802_15_4_fcf->sns && hdr_802_15_4_fcf->frame_ver == 0x00)
                return 0;
        }

        // Look for invalid Cmd packet
        if (hdr_802_15_4_fcf->type == CMD_802154) {
            // Command needs a source
            if (hdr_802_15_4_fcf->src_addr_mode <= 0x01)
                return 0;

            // Sequence number suppression is only defined from the 2015 frame version
            if (hdr_802_15_4_fcf->sns && hdr_802_15_4_fcf->frame_ver < 0x02)
                return 0;

            // Frame version not valid for this header type
            if (hdr_802_15_4_fcf->frame_ver == 0x03)
                return 0;
        }

        // the sequence number, unless suppressed (2015 frames only)
        if (hdr_802_15_4_fcf->sns && hdr_802_15_4_fcf->frame_ver < 0x02)
            return 0;

        if (!hdr_802_15_4_fcf->sns)
            pkt_ctr++;

        const unsigned int dmode = hdr_802_15_4_fcf->dest_addr_mode;
        const unsigned int smode = hdr_802_15_4_fcf->src_addr_mode;
        const bool panc = hdr_802_15_4_fcf->pan_id_comp;

        // Mode 1 is reserved before 2015 and not used for these frames after
        if (dmode == 0x01 || smode == 0x01)
            return 0;

        if (hdr_802_15_4_fcf->frame_ver < 0x02) {
            // 2003 / 2006: a destination PAN with a destination address; a source PAN with a
            // source address unless the PAN ID is compressed (it is then the destination's)
            dest_pan_present = dmode != 0;
            src_pan_present = smode != 0 && !panc;
        } else {
            // 2015, Table 7-2: which PAN IDs the addressing modes and PAN ID compression imply
            if (dmode == 0 && smode == 0) {
                dest_pan_present = panc;
                src_pan_present = false;
            } else if (smode == 0) {
                dest_pan_present = !panc;
                src_pan_present = false;
            } else if (dmode == 0) {
                dest_pan_present = false;
                src_pan_present = !panc;
            } else if (dmode == 0x03 && smode == 0x03) {
                dest_pan_present = !panc;
                src_pan_present = false;
            } else {
                dest_pan_present = true;
                src_pan_present = !panc;
            }
        }

        // n octets of a little-endian field, stored most significant first
        const auto *mpdu = reinterpret_cast<const uint8_t *>(packdata->data());
        auto take = [&](uint8_t *out, unsigned int n) -> bool {
            if (pkt_ctr + n > frame_end)
                return false;
            for (unsigned int i = 0; i < n; i++)
                out[n - 1 - i] = mpdu[pkt_ctr + i];
            pkt_ctr += n;
            return true;
        };

        if (dest_pan_present && !take(dest_pan, 2))
            return 0;
        if (dmode == 0x02 && !take(dest, 2))
            return 0;
        if (dmode == 0x03 && !take(ext_dest, 8))
            return 0;
        if (src_pan_present && !take(src_pan, 2))
            return 0;
        if (smode == 0x02 && !take(src, 2))
            return 0;
        if (smode == 0x03 && !take(ext_source, 8))
            return 0;

        // The auxiliary security header, then the information elements (2015), then the payload,
        // which is readable when it is not encrypted (security levels 4-7 encrypt it)
        bool clear = true;
        bool well_formed = true;
        unsigned int mic_len = 0;

        if (hdr_802_15_4_fcf->security) {
            static const unsigned int key_id_len[4] = {0, 1, 5, 9};

            if (pkt_ctr + 1 > frame_end) {
                well_formed = false;
            } else {
                static const unsigned int mic_lens[4] = {0, 4, 8, 16};
                const uint8_t sc = mpdu[pkt_ctr];
                const unsigned int key_mode = (sc >> 3) & 0x03;
                unsigned int n = 1 + key_id_len[key_mode];

                // the frame counter, unless suppressed (2015)
                if (!(hdr_802_15_4_fcf->frame_ver >= 0x02 && (sc & 0x20)))
                    n += 4;

                clear = (sc & 0x07) < 4;
                mic_len = mic_lens[sc & 0x03];

                if (pkt_ctr + n > frame_end) {
                    well_formed = false;
                } else {
                    // key ID mode 1: the key index alone, the last octet of the header
                    if (key_mode == 1)
                        key_index = mpdu[pkt_ctr + n - 1];
                    pkt_ctr += n;
                }
            }
        }

        if (well_formed && hdr_802_15_4_fcf->iep && hdr_802_15_4_fcf->frame_ver >= 0x02) {
            // header IEs (sent in the clear) up to a termination: HT1, payload IEs follow;
            // HT2, the payload follows; or the end of the frame
            bool payload_ies = false;

            while (pkt_ctr + 2 <= frame_end) {
                const unsigned int ie = mpdu[pkt_ctr] | (mpdu[pkt_ctr + 1] << 8);
                const unsigned int len = ie & 0x7f, id = (ie >> 7) & 0xff;

                if (pkt_ctr + 2 + len > frame_end) {
                    well_formed = false;
                    break;
                }

                // CSL: phase, then period
                if (id == 0x1a && len >= 4)
                    csl_period = mpdu[pkt_ctr + 4] | (mpdu[pkt_ctr + 5] << 8);

                pkt_ctr += 2 + len;

                if (id == 0x7e) {
                    payload_ies = true;
                    break;
                }

                if (id == 0x7f)
                    break;
            }

            // payload IEs are encrypted with the payload
            while (well_formed && clear && payload_ies && pkt_ctr + 2 <= frame_end) {
                const unsigned int ie = mpdu[pkt_ctr] | (mpdu[pkt_ctr + 1] << 8);
                const unsigned int len = ie & 0x7ff, group = (ie >> 11) & 0x0f;

                if (pkt_ctr + 2 + len > frame_end) {
                    well_formed = false;
                    break;
                }

                pkt_ctr += 2 + len;

                if (group == 0x0f)
                    break;
            }
        }

        if (well_formed && clear && pkt_ctr < frame_end)
            payload_off = pkt_ctr;

        // A Data Request between short addresses: its command ID, which 2006 frames send in the
        // clear; a secured 2015 command frame with only a command ID and its MIC is taken for one
        if (well_formed && hdr_802_15_4_fcf->type == CMD_802154 && dmode == 0x02 && smode == 0x02 &&
                pkt_ctr < frame_end) {
            if (hdr_802_15_4_fcf->security && hdr_802_15_4_fcf->frame_ver >= 0x02)
                data_poll = frame_end - pkt_ctr == 1 + mic_len;
            else
                data_poll = mpdu[pkt_ctr] == 0x04;
        }
    }

    if (hdr_802_15_4_fcf->src_addr_mode >= 0x02 ||
        hdr_802_15_4_fcf->dest_addr_mode >= 0x02) {

        in_pack->common_info.common_info_ok = true;
        in_pack->common_info.phyid = mphy->fetch_phy_id();
        in_pack->common_info.type = packet_basic_data;

        if (hdr_802_15_4_fcf->security) {
            in_pack->common_info.basic_crypt_set = KIS_DEVICE_BASICCRYPT_ENCRYPTED | KIS_DEVICE_BASICCRYPT_L2;
        }

        // The sender's PAN: its own, or with PAN ID compression the destination PAN
        static const uint8_t no_pan[2] = {0xFF, 0xFF};
        const uint8_t *src_pan_p = nullptr;

        if (hdr_802_15_4_fcf->src_addr_mode >= 0x02) {
            if (src_pan_present)
                src_pan_p = src_pan;
            else if (dest_pan_present)
                src_pan_p = dest_pan;
        }

        // Short addresses are only unique within a PAN, so a short address is tracked as
        // PAN + short address (4 bytes, PAN first); without a PAN in the frame, under the
        // broadcast PAN 0xFFFF.  Extended addresses are globally unique.
        auto short_addr = [](const uint8_t *pan, const uint8_t *addr) {
            const uint8_t pan_addr[4] = {pan[0], pan[1], addr[0], addr[1]};
            return mac_addr(pan_addr, 4);
        };

        if (hdr_802_15_4_fcf->src_addr_mode == 0x03) {
            in_pack->common_info.source = mac_addr(ext_source, 8);
        } else if (hdr_802_15_4_fcf->src_addr_mode == 0x02) {
            in_pack->common_info.source = short_addr(src_pan_p != nullptr ? src_pan_p : no_pan, src);
        }

        if (hdr_802_15_4_fcf->dest_addr_mode == 0x03) {
            in_pack->common_info.dest = mac_addr(ext_dest, 8);
        } else if (hdr_802_15_4_fcf->dest_addr_mode == 0x02) {
            in_pack->common_info.dest = short_addr(dest_pan, dest);
        }

        auto pi = mphy->packetchain->new_packet_component<kis_802154_packinfo>();
        bool keep = false;

        if (data_poll || csl_period || key_index >= 0) {
            pi->data_poll = data_poll;
            pi->csl_period = csl_period;
            pi->has_key_index = key_index >= 0;
            pi->key_index = (uint8_t) (key_index >= 0 ? key_index : 0);
            keep = true;
        }

        // A sender on the broadcast PAN (associating, rejoining, orphaned) keeps the PAN it was
        // last seen in
        if (src_pan_p != nullptr && !(src_pan_p[0] == 0xFF && src_pan_p[1] == 0xFF)) {
            pi->src_pan = (src_pan_p[0] << 8) | src_pan_p[1];
            pi->has_src_pan = true;
            keep = true;
        }

        // the MAC source's extended address as sent (ext_source holds it most significant first)
        uint8_t mac_src_as_sent[8];
        for (unsigned int i = 0; i < 8; i++)
            mac_src_as_sent[i] = ext_source[7 - i];

        if (payload_off != 0 && payload_off < frame_end &&
                read_payload(hdr_802_15_4_fcf->type, hdr_802_15_4_fcf->src_addr_mode >= 0x02,
                    hdr_802_15_4_fcf->src_addr_mode == 0x03 ? mac_src_as_sent : nullptr,
                    reinterpret_cast<const uint8_t *>(packdata->data()) + payload_off,
                    frame_end - payload_off, mphy->user_keys, pi.get())) {
            keep = true;

            // Zigbee secures at the NWK layer with the MAC unsecured
            if (pi->nwk_secured)
                in_pack->common_info.basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED | KIS_DEVICE_BASICCRYPT_L3;
        }

        // A Green Power frame with no MAC source is from the GPD its source ID names
        if (pi->has_gpd_srcid && hdr_802_15_4_fcf->src_addr_mode == 0x00)
            in_pack->common_info.source = gpd_mac(pi->gpd_srcid);

        if (keep)
            in_pack->insert(mphy->pack_comp_802154, pi);
    }

    return 1;
}

int kis_802154_phy::commonclassifier802154(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_802154_phy *>(auxdata);

    if (in_pack->filtered)
        return 1;

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt &&
        (packdata->dlt != KDLT_IEEE802_15_4_NOFCS && packdata->dlt != KDLT_IEEE802_15_4_TAP))
        return 0;

    if (!in_pack->common_info.common_info_ok) {
        return 0;
    }

    // The dissector only fills in addresses the frame carries, as 4-byte PAN + short or 8-byte
    // extended addresses; a missing one is left at the 6-byte default
    auto addr_present = [](const mac_addr& m) {
        return m.length() == 4 || m.length() == 8;
    };

    const auto& source = in_pack->common_info.source;
    const auto& dest = in_pack->common_info.dest;

    // ZIGBEEWEAKKEY alerts to raise once the device list is unlocked
    std::vector<censor::marked_string> weak_key_alerts;

    // A THREADJOINABLE alert to raise once the device list is unlocked, with its PAN and state
    censor::marked_string thread_join_alert;
    uint16_t thread_join_pan = 0;
    auto thread_join = thread_join_state::unknown;

    if (in_pack->duplicate && addr_present(source)) {
        auto source_dev =
            mphy->devicetracker->update_common_device(source,
                    mphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY),
                    "802.15.4");
    }

    // as source
    // Update with all the options in case we can add signal and frequency
    // in the future
    if (addr_present(source)) {
        auto source_dev =
            mphy->devicetracker->update_common_device(source,
                    mphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                     UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                    "802.15.4");

        // This phy doesn't lock devices individually; its devices change under the list lock
        kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(),
                "802154_common_classifier");

        auto source_kis_802154 = source_dev->get_sub_as<kis_802154_tracked_device>(
            mphy->kis_802154_device_entry_id);

        if (source_kis_802154 == NULL) {
            _MSG_INFO(
                "Detected new 802.15.4 device {}", source);
            source_kis_802154 = Globalreg::globalreg->entrytracker->get_shared_instance_as<kis_802154_tracked_device>(mphy->kis_802154_device_entry_id);
            source_dev->insert(source_kis_802154);

            if (source.length() == 8 && (source[0] & 0x02) && !is_gpd_mac(source))
                source_dev->set_manuf(Globalreg::globalreg->manufdb->get_random_manuf());
        }

        auto pi = in_pack->fetch<kis_802154_packinfo>(mphy->pack_comp_802154);
        uint16_t src_pan = source_kis_802154->get_pan_id();

        if (pi != nullptr && pi->has_src_pan) {
            source_kis_802154->set_pan_id(pi->src_pan);
            src_pan = pi->src_pan;
        }

        // A short address is tracked with its PAN (4 bytes, PAN first)
        if (source.length() == 4)
            source_kis_802154->set_short_addr((source[2] << 8) | source[3]);

        if (pi != nullptr && pi->has_gpd_srcid && is_gpd_mac(source))
            source_kis_802154->set_gpd_srcid(pi->gpd_srcid);

        if (pi != nullptr) {
            static const char *names[] = {"", "6LoWPAN", "Zigbee Green Power", "Zigbee", "Thread"};

            // network_type only becomes more certain: 6LoWPAN gives way to Thread, never back
            if (pi->network != net_kind::unknown &&
                    static_cast<uint8_t>(pi->network) >= source_kis_802154->get_network_rank()) {
                source_kis_802154->set_network_rank(static_cast<uint8_t>(pi->network));
                source_kis_802154->set_network_type(names[static_cast<size_t>(pi->network)]);
            }

            if (!pi->ext_pan_id.empty())
                source_kis_802154->set_ext_pan_id(pi->ext_pan_id);
            if (!pi->network_name.empty()) {
                source_kis_802154->set_network_name(pi->network_name);
                source_dev->set_devicename(pi->network_name);
            }
            if (pi->stack_profile)
                source_kis_802154->set_stack_profile(pi->stack_profile);

            // Thread: what a router says of its network, and what a device looking for one is doing
            if (pi->thread_version)
                source_kis_802154->set_thread_version(pi->thread_version);
            if (pi->thread_join != thread_join_state::unknown) {
                source_kis_802154->set_thread_joining(pi->thread_join);
                source_kis_802154->set_thread_native(pi->thread_native);
            }
            if (pi->thread_joiner_port)
                source_kis_802154->set_thread_joiner_port(pi->thread_joiner_port);
            if (pi->thread_disc != thread_disc_state::none)
                source_kis_802154->set_thread_discovery(pi->thread_disc);
            if (pi->has_mle_key_seq)
                source_kis_802154->set_thread_key_seq(pi->mle_key_seq);

            // The role a beacon shows: the PAN coordinator, or a beaconing router; in Zigbee every
            // router beacons, in Thread none does after 1.1
            if (pi->beacon) {
                if (pi->pan_coordinator)
                    source_kis_802154->set_role("PAN coordinator");
                else if (source_kis_802154->get_role().empty())
                    source_kis_802154->set_role("Router");
            }

            // A Zigbee NWK header that gives its source's IEEE address: map PAN + NWK short ->
            // IEEE, and when the MAC sender is that device (one hop), it is this record
            if (pi->has_nwk_ieee) {
                const mac_addr ieee(pi->nwk_ieee, 8);
                const uint32_t key = ((uint32_t) src_pan << 16) | pi->nwk_src;

                mphy->learn_ieee(key, ieee);

                if (source.length() == 8 && source == ieee)
                    source_kis_802154->set_short_addr(pi->nwk_src);
            }

            // Secured frames checked against the publicly known keys, and how many of them matched
            if (pi->key_checked)
                source_kis_802154->set_key_frames(source_kis_802154->has_key_frames() ?
                        source_kis_802154->get_key_frames() + 1 : 1);
            if (pi->key_matched)
                source_kis_802154->set_key_frames_matched(source_kis_802154->has_key_frames_matched() ?
                        source_kis_802154->get_key_frames_matched() + 1 : 1);
            if (!pi->user_key_name.empty())
                source_kis_802154->set_user_key(pi->user_key_name);

            // Keys anyone can know, seen in use: kept with the sender, and an alert the first time
            // a PAN shows each kind
            if (pi->weak_keys) {
                using pk = kis_802154_packinfo;
                const uint8_t all = pi->weak_keys |
                    (source_kis_802154->has_weak_keys() ? source_kis_802154->get_weak_keys() : 0);

                if (!pi->aps_key_name.empty())
                    source_kis_802154->set_known_link_key(pi->aps_key_name);
                if (!pi->nwk_key_name.empty())
                    source_kis_802154->set_known_network_key(pi->nwk_key_name);

                std::string desc;

                if (all & pk::weak_key_clear_transport)
                    desc += "Key sent in the clear";
                if (all & pk::weak_key_aps)
                    desc += std::string(desc.empty() ? "" : "; ") + "link key: " +
                        source_kis_802154->get_known_link_key();
                if (all & pk::weak_key_nwk)
                    desc += std::string(desc.empty() ? "" : "; ") + "network key: " +
                        source_kis_802154->get_known_network_key();

                source_kis_802154->set_weak_keys(all);
                source_kis_802154->set_weak_key(desc);

                // Key values only with zigbee_show_keys; otherwise the key's type or name
                const std::string exposed_value = mphy->show_keys ? " " + pi->exposed_key : "";

                if (!pi->exposed_key.empty())
                    source_kis_802154->set_exposed_key(mphy->show_keys ?
                            pi->exposed_key_type + " key " + pi->exposed_key :
                            pi->exposed_key_type + " key (value hidden; set zigbee_show_keys=true to record it)");

                const std::string exposed = pi->exposed_key.empty() ? "" :
                    fmt::format("; its Transport Key command gives the {} key{}",
                            pi->exposed_key_type, exposed_value);

                for (const uint8_t bit : {pk::weak_key_clear_transport, pk::weak_key_aps, pk::weak_key_nwk}) {
                    if (!(pi->weak_keys & bit))
                        continue;

                    const uint32_t once = ((uint32_t) src_pan << 8) | bit;

                    {
                        kis_lock_guard<kis_mutex> wlk(mphy->weak_key_mutex, "802154_weak_key");
                        if (!mphy->weak_key_alerted.insert(once).second)
                            continue;
                    }

                    if (bit == pk::weak_key_clear_transport)
                        weak_key_alerts.push_back(censor::format("Zigbee device {} on PAN 0x{:04x} sent "
                                    "a Transport Key command without APS security: the {} key{} "
                                    "is in the clear to anyone who received it",
                                    source, src_pan, pi->exposed_key_type,
                                    exposed_value));
                    else if (bit == pk::weak_key_aps)
                        weak_key_alerts.push_back(censor::format("Zigbee device {} on PAN 0x{:04x} "
                                    "secures APS frames with the publicly known link key {}{}",
                                    source, src_pan, pi->aps_key_name, exposed));
                    else
                        weak_key_alerts.push_back(censor::format("Zigbee device {} on PAN 0x{:04x} "
                                    "secures NWK frames with the publicly known network key {}{}; "
                                    "anyone can decrypt the network's traffic",
                                    source, src_pan, pi->nwk_key_name,
                                    mphy->show_keys ? " (" + pi->nwk_key + ")" : ""));
                }
            }
        }

        // Thread PANs: a frame that shows its PAN is Thread teaches it, and a device on a known
        // Thread PAN is Thread, with the network's name, unless its own frames say Zigbee.  Most
        // Thread frames are encrypted, so this is how most Thread devices are known.
        if (src_pan != 0xFFFF) {
            const unsigned int channel = channel_number(in_pack->common_info.channel);

            if (pi != nullptr && pi->network == net_kind::thread)
                mphy->learn_thread_pan(src_pan, channel, pi->network_name, pi->ext_pan_id);

            const auto rank = source_kis_802154->get_network_rank();
            std::string name, ext_pan_id;

            if ((rank == static_cast<uint8_t>(net_kind::unknown) ||
                        rank == static_cast<uint8_t>(net_kind::lowpan) ||
                        rank == static_cast<uint8_t>(net_kind::thread)) &&
                    mphy->find_thread_pan(src_pan, channel, name, ext_pan_id)) {
                if (rank != static_cast<uint8_t>(net_kind::thread)) {
                    source_kis_802154->set_network_rank(static_cast<uint8_t>(net_kind::thread));
                    source_kis_802154->set_network_type("Thread");
                }
                if (!name.empty() && source_kis_802154->get_network_name() != name)
                    source_kis_802154->set_network_name(name);
                if (!ext_pan_id.empty() && source_kis_802154->get_ext_pan_id() != ext_pan_id)
                    source_kis_802154->set_ext_pan_id(ext_pan_id);
            }

            // Thread devices by their RLOC16 (the short address): the router ID (6 bits), a reserved
            // bit, the child ID (9 bits; 0 for the router itself).  Children poll their parent,
            // and synchronized sleepy children carry a CSL IE.
            if (source.length() == 4 && source_kis_802154->get_network_rank() ==
                    static_cast<uint8_t>(net_kind::thread)) {
                const uint16_t rloc = (source[2] << 8) | source[3];
                const unsigned int router = rloc >> 10, child = rloc & 0x1ff;

                if (!(rloc & 0x0200) && router < 63) {
                    uint8_t routers = 0;
                    uint16_t children = 0;

                    const bool counted =
                        mphy->thread_topology(src_pan, rloc, in_pack->ts.tv_sec, routers, children);

                    source_kis_802154->set_thread_router_id(router);
                    source_kis_802154->set_thread_child_id(child);
                    if (counted)
                        source_kis_802154->set_thread_routers(routers);

                    if (pi != nullptr && pi->data_poll) {
                        const uint64_t now_ms = (uint64_t) in_pack->ts.tv_sec * 1000 + in_pack->ts.tv_usec / 1000;
                        const uint64_t last = source_kis_802154->has_thread_last_poll() ?
                            source_kis_802154->get_thread_last_poll() : 0;

                        // Polls repeated within a moment (no answer yet) and long gaps don't
                        // count toward the usual interval
                        if (last != 0 && now_ms > last && now_ms - last >= 200 && now_ms - last <= 3600 * 1000) {
                            const uint32_t gap = (uint32_t) (now_ms - last);
                            const uint32_t avg = source_kis_802154->has_thread_poll_interval() ?
                                source_kis_802154->get_thread_poll_interval() : 0;
                            source_kis_802154->set_thread_poll_interval(avg == 0 ? gap :
                                    (uint32_t) (((uint64_t) avg * 3 + gap) / 4));
                        }

                        if (now_ms > last)
                            source_kis_802154->set_thread_last_poll(now_ms);
                        source_kis_802154->set_thread_polls(source_kis_802154->has_thread_polls() ?
                                source_kis_802154->get_thread_polls() + 1 : 1);
                    }

                    if (pi != nullptr && pi->csl_period)
                        source_kis_802154->set_thread_csl_period(pi->csl_period);

                    if (child == 0) {
                        source_kis_802154->set_role("Router");
                        if (counted)
                            source_kis_802154->set_thread_children(children);
                    } else {
                        const uint8_t parent[4] = {(uint8_t) (src_pan >> 8), (uint8_t) src_pan,
                            (uint8_t) (router << 2), 0x00};

                        source_kis_802154->set_thread_parent(device_key(mphy->fetch_phyname_hash(),
                                    mac_addr(parent, 4)));
                        source_kis_802154->set_role(source_kis_802154->has_thread_csl_period() ?
                                "Synchronized sleepy end device" : source_kis_802154->has_thread_polls() ?
                                "Sleepy end device" : "End device");
                    }
                }
            }

            if (pi != nullptr && pi->has_key_index &&
                    source_kis_802154->get_network_rank() == static_cast<uint8_t>(net_kind::thread))
                source_kis_802154->set_thread_key_index(pi->key_index);

            // A network open to new devices, once per PAN each time it opens
            if (pi != nullptr && pi->thread_join != thread_join_state::unknown &&
                    mphy->alert_threadjoin_ref >= 0 && mphy->thread_alert_due(src_pan, pi->thread_join)) {
                thread_join_pan = src_pan;
                thread_join = pi->thread_join;
                const auto net_name = pi->network_name.empty() ? censor::marked_string{"(unnamed)"} :
                    censor::format("'{}'", censor::ssid(pi->network_name));
                const auto ext_pan = pi->ext_pan_id.empty() ? censor::marked_string{} :
                    censor::format(" (extended PAN ID {})", censor::ident(pi->ext_pan_id));
                thread_join_alert = censor::format("Thread network {}{} on PAN 0x{:04x} is accepting {}: "
                        "router {} says so in its {}", net_name, ext_pan, src_pan,
                        pi->thread_join == thread_join_state::any ? "any new device" :
                        "the new devices its commissioner lists", source,
                        pi->beacon ? "beacon" : "Discovery Response");
            }
        }

        // A short-address device whose IEEE address a NWK header gave: its EUI-64, and the
        // manufacturer from it when it is a factory (universally administered) address
        if (source.length() == 4) {
            const uint32_t key = ((uint32_t) ((source[0] << 8) | source[1]) << 16) | ((source[2] << 8) | source[3]);
            mac_addr ieee;
            bool found = false;

            {
                kis_lock_guard<kis_mutex> mlk(mphy->ieee_map_mutex, "802154_ieee_map");
                auto mi = mphy->ieee_by_short.find(key);
                if (mi != mphy->ieee_by_short.end()) {
                    ieee = mi->second;
                    found = true;
                }
            }

            if (found && !(source_kis_802154->get_ieee_addr() == ieee)) {
                source_kis_802154->set_ieee_addr(ieee);

                if (!(ieee[0] & 0x02))
                    source_dev->set_manuf(Globalreg::globalreg->manufdb->lookup_oui(ieee));
            }
        }

        // The device type the network and role make
        const auto net = source_kis_802154->get_network_type();
        const auto role = source_kis_802154->get_role();

        if (!net.empty()) {
            std::string type;

            if (net == "Zigbee")
                type = role == "PAN coordinator" ? "Zigbee coordinator" : role == "Router" ? "Zigbee router" : "Zigbee device";
            else if (net == "Thread")
                type = !source_kis_802154->has_thread_child_id() ? "Thread device" :
                    source_kis_802154->get_thread_child_id() == 0 ? "Thread router" : "Thread end device";
            else
                type = net + " device";

            source_dev->set_tracker_type_string(mphy->devicetracker->get_cached_devicetype(type));
        } else if (!role.empty()) {
            source_dev->set_tracker_type_string(mphy->devicetracker->get_cached_devicetype(
                        role == "PAN coordinator" ? "802.15.4 coordinator" : "802.15.4 router"));
        }

        // The key check's outcome: a publicly known or exposed key seen in use, or secured frames
        // checked that no known key matched, or nothing checked yet
        const uint8_t weak =
            source_kis_802154->has_weak_keys() ? source_kis_802154->get_weak_keys() : 0;
        const uint64_t checked =
            source_kis_802154->has_key_frames() ? source_kis_802154->get_key_frames() : 0;
        const uint64_t matched =
            source_kis_802154->has_key_frames_matched() ? source_kis_802154->get_key_frames_matched() : 0;
        const bool user_key = source_kis_802154->has_user_key();

        if (weak) {
            if (!source_kis_802154->has_key_state() ||
                    source_kis_802154->get_key_state() != zigbee_key_state::known) {
                source_kis_802154->set_key_state(zigbee_key_state::known);
                source_kis_802154->set_key_first_time(in_pack->ts.tv_sec);
            }

            source_kis_802154->set_key_status(checked == 0 ?
                    "Known key in use: " + source_kis_802154->get_weak_key() :
                    fmt::format("Known key in use: {} ({} of {} secured frames matched a publicly "
                        "known key)", source_kis_802154->get_weak_key(), matched, checked));
        } else if (user_key) {
            source_kis_802154->set_key_state(zigbee_key_state::user);
            source_kis_802154->set_key_status(fmt::format("Your key in use: {} ({} of {} secured "
                        "frames matched; no publicly known key)", source_kis_802154->get_user_key(),
                        matched, checked));
        } else if (checked > 0) {
            source_kis_802154->set_key_state(zigbee_key_state::not_known);
            const auto n_user = mphy->user_keys.size();

            source_kis_802154->set_key_status(fmt::format("No known key: {} secured frames checked "
                        "against the {} publicly known keys{}, none matched; the network uses a key "
                        "of its own", checked, zigbee_crypto::n_known_keys,
                        n_user == 0 ? "" : fmt::format(" and your {} key{}", n_user, n_user == 1 ? "" : "s")));
        } else if (source_dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L3) {
            source_kis_802154->set_key_status("Not checked yet: its encrypted frames so far could "
                    "not be checked against the publicly known keys (no complete NWK auxiliary "
                    "security header); it will be when one can");
        } else if (source_dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L2) {
            source_kis_802154->set_key_status("Not checked: 802.15.4 MAC-layer security is not "
                    "checked against the publicly known keys");
        }

        // The encryption, with the weakest known key it was seen to use
        if (weak & kis_802154_packinfo::weak_key_nwk)
            source_dev->set_crypt_string("Zigbee NWK: publicly known key (" + source_kis_802154->get_known_network_key() + ")");
        else if (weak & kis_802154_packinfo::weak_key_clear_transport)
            source_dev->set_crypt_string("Zigbee: key sent in the clear");
        else if (weak & kis_802154_packinfo::weak_key_aps)
            source_dev->set_crypt_string("Zigbee APS: publicly known link key (" + source_kis_802154->get_known_link_key() + ")");
        else if (user_key)
            source_dev->set_crypt_string("Zigbee: your key (" + source_kis_802154->get_user_key() + ")");
        else if ((source_dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L3) && checked > 0)
            source_dev->set_crypt_string("Zigbee NWK");
        else if (source_dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L3)
            source_dev->set_crypt_string("Zigbee NWK: not checked yet");
        else if (checked > 0)
            source_dev->set_crypt_string("Zigbee APS");
        else if (source_dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L2)
            source_dev->set_crypt_string("802.15.4 MAC: not checked");
    }

    // Not raised (the rate limit): due again with the next frame that shows it
    if (!thread_join_alert.plain().empty() &&
            mphy->alertracker->raise_alert(mphy->alert_threadjoin_ref, in_pack.get(), mac_addr{},
                source, dest, mac_addr{}, in_pack->common_info.channel, thread_join_alert) != 1)
        mphy->unmark_thread_alert(thread_join_pan, thread_join);

    // Alerts held back by the rate limit first, in order, as far as it lets them through (they
    // are no longer this frame's, so no packet goes with them); then this frame's, which wait in
    // turn when they cannot go now
    if (mphy->alert_weakkey_ref >= 0 &&
            (!weak_key_alerts.empty() || mphy->weak_key_backlogged.load())) {
        kis_lock_guard<kis_mutex> wlk(mphy->weak_key_mutex, "802154_weak_key");
        auto& backlog = mphy->weak_key_backlog;

        mphy->drain_weak_key_backlog();

        for (const auto& text : weak_key_alerts) {
            if (backlog.empty() &&
                    mphy->alertracker->raise_alert(mphy->alert_weakkey_ref, in_pack.get(), mac_addr{},
                        source, dest, mac_addr{}, in_pack->common_info.channel, text) == 1)
                continue;

            // Held back; the backlog is capped (zigbee_alert_backlog), dropping the oldest
            if (mphy->weak_key_backlog_max == 0)
                continue;
            while (backlog.size() >= mphy->weak_key_backlog_max)
                backlog.pop_front();
            backlog.push_back({source, dest, in_pack->common_info.channel, text});
        }

        mphy->weak_key_backlogged.store(!backlog.empty());
    }

    // as destination
    // The destination didn't transmit this frame, so it must not get the signal and location
    // of the sender, and a destination alone is not enough to create a device (like the 802.11
    // destination handling).  Skip the 0xFFFF broadcast short address entirely, in any PAN.
    auto broadcast_short = [](const mac_addr& m) {
        return m.length() == 4 && m[2] == 0xFF && m[3] == 0xFF;
    };

    if (addr_present(dest) && !broadcast_short(dest)) {
        mphy->devicetracker->update_common_device(dest,
                mphy, in_pack,
                (UCD_UPDATE_SEENBY | UCD_UPDATE_EXISTING_ONLY),
                "802.15.4");
    }

    return 1;
}

void kis_802154_phy::learn_ieee(uint32_t pan_short, const mac_addr& ieee) {
    kis_lock_guard<kis_mutex> lk(ieee_map_mutex, "802154_learn_ieee");

    auto mi = ieee_by_short.find(pan_short);
    if (mi != ieee_by_short.end()) {
        mi->second = ieee;
        return;
    }

    if (ieee_by_short.size() >= ieee_map_max) {
        ieee_by_short.erase(ieee_by_short_order.front());
        ieee_by_short_order.pop_front();
    }

    ieee_by_short.emplace(pan_short, ieee);
    ieee_by_short_order.push_back(pan_short);
}

void kis_802154_phy::learn_thread_pan(uint16_t pan, unsigned int channel,
        const std::string& name, const std::string& ext_pan_id) {
    kis_lock_guard<kis_mutex> lk(thread_pan_mutex, "802154_learn_thread_pan");

    auto ti = thread_pans.find(pan);

    if (ti == thread_pans.end()) {
        if (thread_pans.size() >= thread_pan_max) {
            thread_pans.erase(thread_pan_order.front());
            thread_pan_order.pop_front();
        }

        ti = thread_pans.emplace(pan, thread_pan{}).first;
        thread_pan_order.push_back(pan);
    }

    if (channel != 0)
        ti->second.channel = channel;
    if (!name.empty())
        ti->second.name = name;
    if (!ext_pan_id.empty())
        ti->second.ext_pan_id = ext_pan_id;
}

bool kis_802154_phy::find_thread_pan(uint16_t pan, unsigned int channel, std::string& name,
        std::string& ext_pan_id) {
    kis_lock_guard<kis_mutex> lk(thread_pan_mutex, "802154_find_thread_pan");

    auto ti = thread_pans.find(pan);

    if (ti == thread_pans.end())
        return false;

    if (channel != 0 && ti->second.channel != 0 && channel != ti->second.channel)
        return false;

    name = ti->second.name;
    ext_pan_id = ti->second.ext_pan_id;
    return true;
}

bool kis_802154_phy::thread_alert_due(uint16_t pan, thread_join_state state) {
    kis_lock_guard<kis_mutex> lk(thread_pan_mutex, "802154_thread_alert_due");

    auto ti = thread_pans.find(pan);

    if (ti == thread_pans.end())
        return false;

    if (state == thread_join_state::closed) {
        ti->second.alerted = 0;
        return false;
    }

    // Once while it's open, and again when it widens from listed devices to any
    const uint8_t bit = (uint8_t) (1u << static_cast<uint8_t>(state));
    const uint8_t any_bit = (uint8_t) (1u << static_cast<uint8_t>(thread_join_state::any));

    if ((ti->second.alerted & bit) || (state != thread_join_state::any && ti->second.alerted != 0) ||
            (ti->second.alerted & any_bit))
        return false;

    ti->second.alerted |= bit;
    return true;
}

bool kis_802154_phy::thread_topology(uint16_t pan, uint16_t rloc16, time_t now, uint8_t& routers,
        uint16_t& children) {
    kis_lock_guard<kis_mutex> lk(thread_pan_mutex, "802154_thread_topology");

    routers = 0;
    children = 0;

    auto ti = thread_pans.find(pan);
    if (ti == thread_pans.end())
        return false;

    auto& net = ti->second;
    const unsigned int router = rloc16 >> 10;

    net.router_seen[router] = now;

    if (rloc16 & 0x1ff) {
        auto ci = net.child_seen.find(rloc16);

        if (ci != net.child_seen.end()) {
            ci->second = now;
        } else {
            if (net.child_seen.size() >= thread_children_max) {
                for (auto i = net.child_seen.begin(); i != net.child_seen.end(); ) {
                    if (now - i->second > thread_topology_window)
                        i = net.child_seen.erase(i);
                    else
                        ++i;
                }
            }

            if (net.child_seen.size() < thread_children_max)
                net.child_seen.emplace(rloc16, now);
        }
    }

    for (const auto t : net.router_seen)
        if (t != 0 && now - t <= thread_topology_window)
            routers++;

    // A router's children: the RLOC16s under its router ID
    if (!(rloc16 & 0x1ff))
        for (const auto& c : net.child_seen)
            if ((c.first >> 10) == router && now - c.second <= thread_topology_window)
                children++;

    return true;
}

void kis_802154_phy::unmark_thread_alert(uint16_t pan, thread_join_state state) {
    kis_lock_guard<kis_mutex> lk(thread_pan_mutex, "802154_unmark_thread_alert");

    auto ti = thread_pans.find(pan);

    if (ti != thread_pans.end())
        ti->second.alerted &= (uint8_t) ~(1u << static_cast<uint8_t>(state));
}

void kis_802154_phy::load_phy_storage(
    shared_tracker_element in_storage, shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto kis_802154devi = storage->find(kis_802154_device_entry_id);

    if (kis_802154devi != storage->end()) {
        auto kis_802154dev = std::make_shared<kis_802154_tracked_device>(
            kis_802154_device_entry_id,
            std::static_pointer_cast<tracker_element_map>(
                kis_802154devi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(
            kis_802154dev);
    }
}

