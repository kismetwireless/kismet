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

#include "phy_802154.h"

#include <cmath>

#define BEACON_802154   0x00
#define DATA_802154     0x01
#define ACK_802154      0x02
#define CMD_802154      0x03

// 802.15.4 header
struct _802_15_4_fcf {
    unsigned char type : 3;
    unsigned char security : 1;
    unsigned char pending : 1;
    unsigned char ack_req : 1;
    unsigned char pan_id_comp : 1;
    unsigned char reserved : 1;
    unsigned char sns : 1;
    unsigned char iep : 1;
    unsigned char dest_addr_mode : 2;
    unsigned char frame_ver : 2;
    unsigned char src_addr_mode : 2;
};


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

// The UDP destination port of a 6LoWPAN frame (IPHC, then NHC or inline UDP); -1 when not UDP
static int lowpan_udp_dport(const uint8_t *p, size_t n) {
    int nh = 0;
    uint8_t nh_value = 0;
    unsigned int l;

    if (n < 2 || (p[0] & 0xe0) != 0x60)
        return -1;

    l = iphc_length(p, n, &nh, &nh_value);
    if (l == 0)
        return -1;

    if (!nh) {
        // an uncompressed UDP header: source port, destination port
        if (nh_value != 17 || l + 4 > n)
            return -1;
        return (p[l + 2] << 8) | p[l + 3];
    }

    // NHC UDP: 11110CPP
    if (l + 1 > n || (p[l] & 0xf8) != 0xf0)
        return -1;

    const unsigned int ports = p[l] & 0x03;
    const uint8_t *q = p + l + 1;
    const size_t left = n - l - 1;

    switch (ports) {
        case 0: return left >= 4 ? (q[2] << 8) | q[3] : -1;    // both inline
        case 1: return left >= 3 ? 0xf000 | q[2] : -1;         // source inline, destination 0xf0xx
        case 2: return left >= 3 ? (q[1] << 8) | q[2] : -1;    // source 0xf0xx, destination inline
        default: return left >= 1 ? 0xf0b0 | (q[0] & 0x0f) : -1;
    }
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

static std::string ext_pan_string(const uint8_t *le8) {
    return fmt::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            le8[7], le8[6], le8[5], le8[4], le8[3], le8[2], le8[1], le8[0]);
}

/*
 * What a frame's payload says about its network.  Beacons: the superframe specification (the PAN
 * coordinator bit), the GTS and pending-address fields skipped, then the beacon payload's protocol
 * ID: 0 a Zigbee beacon (stack profile, extended PAN ID), 3 a Thread beacon (network name, extended
 * PAN ID).  Data: 6LoWPAN by its dispatch (MLE, UDP port 19788, is Thread), or a Zigbee NWK header
 * (protocol version 2; 3 with no MAC source is Green Power), whose source short and IEEE addresses
 * and security bit are kept.  Returns false when it says nothing.
 */
static bool read_payload(unsigned int frame_type, bool has_mac_src, const uint8_t *p, size_t n,
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
            pi->network = kis_802154_packinfo::network_zigbee;
            pi->stack_profile = p[o + 1] & 0x0f;
            pi->ext_pan_id = ext_pan_string(p + o + 3);
        } else if (p[o] == 0x03 && o + 2 + 16 + 8 <= n) {
            // Thread 1.1: protocol ID, version and flags, network name (16), extended PAN ID (8)
            pi->network = kis_802154_packinfo::network_thread;
            const char *name = reinterpret_cast<const char *>(p + o + 2);
            pi->network_name = std::string(name, strnlen(name, 16));
            pi->ext_pan_id = ext_pan_string(p + o + 18);
        }

        return true;
    }

    if (frame_type != DATA_802154 || n < 2)
        return false;

    // 6LoWPAN, by its whole header; MLE (UDP port 19788) is Thread
    if (lowpan_frame(p, n)) {
        pi->network = lowpan_udp_dport(p, n) == 19788 ?
            kis_802154_packinfo::network_thread : kis_802154_packinfo::network_6lowpan;
        return true;
    }

    // A Zigbee NWK header: frame type (data, command, inter-PAN), protocol version 2, the discover
    // route field 0 or 1
    const unsigned int fc = p[0] | (p[1] << 8);
    const unsigned int ftype = fc & 0x03, version = (fc >> 2) & 0x0f, discover = (fc >> 6) & 0x03;

    if (version == 3 && !has_mac_src && ftype != 2) {
        pi->network = kis_802154_packinfo::network_zigbee_gp;
        return true;
    }

    if (version != 2 || ftype == 2 || discover > 1 || n < 8)
        return false;

    pi->network = kis_802154_packinfo::network_zigbee;
    pi->nwk_secured = (fc >> 9) & 0x01;
    pi->nwk_src = p[4] | (p[5] << 8);

    // after destination, source, radius and sequence: the destination IEEE address, then the source's
    size_t o = 8;
    if ((fc >> 11) & 0x01)
        o += 8;

    if (((fc >> 12) & 0x01) && o + 8 <= n) {
        for (unsigned int i = 0; i < 8; i++)
            pi->nwk_ieee[7 - i] = p[o + i];
        pi->has_nwk_ieee = true;
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
    packetchain->remove_handler(&dissector802154, CHAINPOS_LLCDISSECT);
    packetchain->remove_handler(&commonclassifier802154, CHAINPOS_CLASSIFIER);
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

    unsigned short fcf = 0;
    auto hdr_802_15_4_fcf = reinterpret_cast<_802_15_4_fcf *>(&fcf);

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

        // An MPDU is 3 to 127 octets with its FCS
        if (packdata->length() < pkt_ctr + 3 + fcs_len || packdata->length() - pkt_ctr > 127) {
            in_pack->error = 1;
            return 0;
        }

        frame_end = packdata->length() - fcs_len;

        // A frame whose 16-bit FCS does not check is not attributed to anyone.  (A 32-bit FCS,
        // of the SUN PHYs, is left unchecked.)
        if (fcs_len == 2) {
            const uint16_t fcs = (uint16_t) (raw[frame_end] | (raw[frame_end + 1] << 8));

            if (crc16_802154(raw + pkt_ctr, frame_end - pkt_ctr) != fcs) {
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

        fcf = (((short) packdata->data()[pkt_ctr + 1]) << 8) |
            (0x00ff & packdata->data()[pkt_ctr]);

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

        if (hdr_802_15_4_fcf->security) {
            static const unsigned int key_id_len[4] = {0, 1, 5, 9};

            if (pkt_ctr + 1 > frame_end) {
                well_formed = false;
            } else {
                const uint8_t sc = mpdu[pkt_ctr];
                unsigned int n = 1 + key_id_len[(sc >> 3) & 0x03];

                // the frame counter, unless suppressed (2015)
                if (!(hdr_802_15_4_fcf->frame_ver >= 0x02 && (sc & 0x20)))
                    n += 4;

                clear = (sc & 0x07) < 4;

                if (pkt_ctr + n > frame_end)
                    well_formed = false;
                else
                    pkt_ctr += n;
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

        // A sender on the broadcast PAN (associating, rejoining, orphaned) keeps the PAN it was
        // last seen in
        if (src_pan_p != nullptr && !(src_pan_p[0] == 0xFF && src_pan_p[1] == 0xFF)) {
            pi->src_pan = (src_pan_p[0] << 8) | src_pan_p[1];
            pi->has_src_pan = true;
            keep = true;
        }

        if (payload_off != 0 && payload_off < frame_end &&
                read_payload(hdr_802_15_4_fcf->type, hdr_802_15_4_fcf->src_addr_mode >= 0x02,
                    reinterpret_cast<const uint8_t *>(packdata->data()) + payload_off,
                    frame_end - payload_off, pi.get())) {
            keep = true;

            // Zigbee secures at the NWK layer with the MAC unsecured
            if (pi->nwk_secured)
                in_pack->common_info.basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED | KIS_DEVICE_BASICCRYPT_L3;
        }

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
                "Detected new 802.15.4 device {}", source.mac_to_string());
            source_kis_802154 = Globalreg::globalreg->entrytracker->get_shared_instance_as<kis_802154_tracked_device>(mphy->kis_802154_device_entry_id);
            source_dev->insert(source_kis_802154);

            if (source.length() == 8 && (source[0] & 0x02))
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

        if (pi != nullptr) {
            static const char *names[] = {"", "6LoWPAN", "Zigbee Green Power", "Zigbee", "Thread"};

            // network_type only becomes more certain: 6LoWPAN gives way to Thread, never back
            if (pi->network != kis_802154_packinfo::network_unknown &&
                    (uint8_t) pi->network >= source_kis_802154->get_network_rank()) {
                source_kis_802154->set_network_rank((uint8_t) pi->network);
                source_kis_802154->set_network_type(names[pi->network]);
            }

            if (!pi->ext_pan_id.empty())
                source_kis_802154->set_ext_pan_id(pi->ext_pan_id);
            if (!pi->network_name.empty()) {
                source_kis_802154->set_network_name(pi->network_name);
                source_dev->set_devicename(pi->network_name);
            }
            if (pi->stack_profile)
                source_kis_802154->set_stack_profile(pi->stack_profile);

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

                {
                    kis_lock_guard<kis_mutex> mlk(mphy->ieee_map_mutex, "802154_ieee_map");
                    mphy->ieee_by_short[key] = ieee;
                }

                if (source.length() == 8 && source == ieee)
                    source_kis_802154->set_short_addr(pi->nwk_src);
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
                type = "Thread device";
            else
                type = net + " device";

            source_dev->set_tracker_type_string(mphy->devicetracker->get_cached_devicetype(type));
        } else if (!role.empty()) {
            source_dev->set_tracker_type_string(mphy->devicetracker->get_cached_devicetype(
                        role == "PAN coordinator" ? "802.15.4 coordinator" : "802.15.4 router"));
        }

        if (source_dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L3)
            source_dev->set_crypt_string("Zigbee NWK");
        else if (source_dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L2)
            source_dev->set_crypt_string("802.15.4 MAC");
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

