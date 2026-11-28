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

/* DLT handler framework */

#include "config.h"

#include "globalregistry.h"
#include "util.h"
#include "endian_magic.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif // Open/Net

#ifdef SYS_FREEBSD
#include <net80211/ieee80211_radiotap.h>
#endif // FreeBSD

// Include the linux system radiotap headers
#ifdef HAVE_LINUX_SYS_RADIOTAP
#include <net/ieee80211_radiotap.h>
#endif

// If we couldn't make any sense of system rt headers (OSX perhaps, or
// win32, or an older linux) then pull in the local radiotap copy
#ifdef HAVE_LOCAL_RADIOTAP
#include "local_ieee80211_radiotap.h"
#endif

#include "kis_dlt_radiotap.h"

#include "dot11_phy_rate.h"
#include "kis_datasource.h"
#include "radiotap_walk.h"

#include "tcpdump-extract.h"

// Extension to radiotap header not yet included in all BSD's
#ifndef IEEE80211_RADIOTAP_F_FCS
#define IEEE80211_RADIOTAP_F_FCS        0x10    /* frame includes FCS */
#endif

// Extension to radiotap header not yet found everywhere, indicates a packet
// has a bad FCS but may not include the FCS itself
#ifndef IEEE80211_RADIOTAP_F_BADFCS
#define IEEE80211_RADIOTAP_F_BADFCS     0x40    /* frame has bad FCS */
#endif

kis_dlt_radiotap::kis_dlt_radiotap() :
    kis_dlt_handler() {

    dlt_name = "Radiotap";
    dlt = DLT_IEEE802_11_RADIO;

    _MSG("Registering support for DLT_RADIOTAP packet header decoding", MSGFLAG_INFO);

    crc32_init_table_80211(crc32_table);
}

#define IEEE80211_CHAN_700 0x0001
#define IEEE80211_CHAN_800 0x0002
#define IEEE80211_CHAN_900 0x0004
#define IEEE80211_CHAN_TURBO 0x0010
#define IEEE80211_CHAN_CCK 0x0020
#define IEEE80211_CHAN_OFDM 0x0040
#define IEEE80211_CHAN_2GHZ 0x0080
#define IEEE80211_CHAN_5GHZ 0x0100
#define IEEE80211_CHAN_PASSIVE 0x0200
#define IEEE80211_CHAN_DYN 0x0400
#define IEEE80211_CHAN_GFSK 0x0800

/*
 * Useful combinations of channel characteristics.
 */
#define    IEEE80211_CHAN_FHSS \
    (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define    IEEE80211_CHAN_A \
    (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define    IEEE80211_CHAN_BPLUS \
    (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK | IEEE80211_CHAN_TURBO)
#define    IEEE80211_CHAN_B \
    (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define    IEEE80211_CHAN_PUREG \
    (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define    IEEE80211_CHAN_G \
    (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define    IEEE80211_CHAN_T \
    (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)

#define    IEEE80211_IS_CHAN_700MHZ(_flags) \
    ((_flags & IEEE80211_CHAN_700) == IEEE80211_CHAN_700)
#define    IEEE80211_IS_CHAN_800MHZ(_flags) \
    ((_flags & IEEE80211_CHAN_800) == IEEE80211_CHAN_800)
#define    IEEE80211_IS_CHAN_900MHZ(_flags) \
    ((_flags & IEEE80211_CHAN_900) == IEEE80211_CHAN_900)
#define    IEEE80211_IS_CHAN_S1G(_flags) \
    ((_flags & (IEEE80211_CHAN_700 | IEEE80211_CHAN_800 | IEEE80211_CHAN_900)) != 0)
#define    IEEE80211_IS_CHAN_FHSS(_flags) \
    ((_flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define    IEEE80211_IS_CHAN_A(_flags) \
    ((_flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define    IEEE80211_IS_CHAN_BPLUS(_flags) \
    ((_flags & IEEE80211_CHAN_BPLUS) == IEEE80211_CHAN_BPLUS)
#define    IEEE80211_IS_CHAN_B(_flags) \
    ((_flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define    IEEE80211_IS_CHAN_PUREG(_flags) \
    ((_flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define    IEEE80211_IS_CHAN_G(_flags) \
    ((_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define    IEEE80211_IS_CHAN_T(_flags) \
    ((_flags & IEEE80211_CHAN_T) == IEEE80211_CHAN_T)

// Radiotap TLVs (radiotap.org/fields/TLV), not in every system header.  The TLV bit means a
// TLV list follows all the other fields and fills the rest of the header
// (kis_radiotap::walk finds where it starts).
constexpr uint16_t radiotap_tlv_vendor_namespace = 30;
constexpr uint16_t radiotap_tlv_s1g = 32;

// Morse Micro vendor namespace (morse_driver s1g_radiotap.h); type 35 is the frequency in
// kHz, since the channel field can't hold the half MHz S1G channel centers
constexpr uint8_t morse_oui[3] = { 0x0c, 0xbf, 0x74 };
constexpr uint16_t morse_vendor_freq_khz = 35;

static void radiotap_parse_tlvs(const u_char *p, const u_char *end,
        const std::shared_ptr<kis_packet>& in_pack, dot11_radiotap_rate& rate) {
    while (end - p >= 4) {
        const uint16_t type = EXTRACT_LE_16BITS(p);
        const uint16_t len = EXTRACT_LE_16BITS(p + 2);
        p += 4;

        if (len > end - p)
            return;

        rate.tlv(type, std::span<const uint8_t>(p, len));

        switch (type) {
            case radiotap_tlv_s1g:
                in_pack->signal_info.data_ok = true;
                in_pack->signal_info.carrier = carrier_80211ah;
                in_pack->signal_info.encoding = encoding_ofdm;
                break;

            case radiotap_tlv_vendor_namespace:
                // OUI, sub namespace, vendor type, reserved, data
                if (len >= 12 && memcmp(p, morse_oui, sizeof(morse_oui)) == 0 && p[3] == 0 &&
                        EXTRACT_LE_16BITS(p + 4) == morse_vendor_freq_khz) {
                    const uint32_t khz = EXTRACT_LE_32BITS(p + 8);

                    if (khz != 0) {
                        in_pack->signal_info.data_ok = true;
                        in_pack->signal_info.freq_khz = khz;
                    }
                }
                break;

            default:
                break;
        }

        // TLVs are padded to 4 bytes
        const size_t padded = (static_cast<size_t>(len) + 3) & ~static_cast<size_t>(3);
        if (padded > static_cast<size_t>(end - p))
            return;

        p += padded;
    }
}

int kis_dlt_radiotap::handle_packet(const std::shared_ptr<kis_packet>& in_pack) {
    if (in_pack->has(pack_comp_decap))
        return 1;

    auto linkchunk = in_pack->fetch<kis_datachunk>(pack_comp_linkframe);

    if (linkchunk == nullptr) {
        return 1;
    }

    if (linkchunk->dlt != dlt) {
        return 1;
    }

    if (linkchunk->length() == 0) {
        return 1;
    }

    auto datasrc = in_pack->fetch<packetchain_comp_datasource>(pack_comp_datasrc);

    // Everything needs a data source so we know how to checksum
    if (datasrc == nullptr) {
        return 1;
    }

    int fcs_cut = 0; // fcs at end of frame
    bool fcs_flag_invalid = false; // fcs known invalid

    if (linkchunk->length() < kis_radiotap::header_min_len) {
        return 0;
    }

    const auto rt = reinterpret_cast<const uint8_t *>(linkchunk->data());
    const auto radiotap_len = EXTRACT_LE_16BITS(rt + 2);
    if (radiotap_len < kis_radiotap::header_min_len || linkchunk->length() < radiotap_len) {
        return 0;
    }

    bool assigned_signal = false;

    dot11_radiotap_rate phy_rate(kis_radiotap::openbsd_bits);

    // Signal and antenna of one radiotap namespace (one per antenna on mac80211), applied
    // once all its fields are seen
    size_t record = 0;
    int record_antenna = -1;
    int record_signal = 0;
    bool signal_present = false;

    auto finish_record = [&]() {
        if (signal_present) {
            // If we haven't assigned a signal, assign the first one we see as the
            // overall signal level
            if (!assigned_signal) {
                assigned_signal = true;
                in_pack->signal_info.data_ok = true;
                in_pack->signal_info.signal_type = kis_l1_signal_type_dbm;
                in_pack->signal_info.signal_dbm = record_signal;
            }

            if (record_antenna >= 0) {
                in_pack->signal_info.data_ok = true;
                in_pack->signal_info.signal_type = kis_l1_signal_type_dbm;
                in_pack->signal_info.antenna_signal_map[record_antenna] = record_signal;
            }
        }

        record_antenna = -1;
        record_signal = 0;
        signal_present = false;
    };

    auto apply_field = [&](unsigned int bit, size_t field_record, std::span<const uint8_t> field) {
        if (field_record != record) {
            finish_record();
            record = field_record;
        }

        phy_rate.field(bit, field);

        switch (bit) {
            case kis_radiotap::bit_channel: {
                const uint16_t freq_mhz = EXTRACT_LE_16BITS(field.data());
                const uint16_t chan_flags = EXTRACT_LE_16BITS(field.data() + 2);

                in_pack->signal_info.data_ok = true;
                in_pack->signal_info.freq_khz = (double) freq_mhz * 1000;

                // handle broken drivers reporting s1g wrong
                if (IEEE80211_IS_CHAN_S1G(chan_flags) && in_pack->signal_info.freq_khz > 1e6) {
                    in_pack->signal_info.freq_khz /= 10;
                }

                if (IEEE80211_IS_CHAN_S1G(chan_flags))
                    in_pack->signal_info.carrier = carrier_80211ah;
                else if (IEEE80211_IS_CHAN_FHSS(chan_flags))
                    in_pack->signal_info.carrier = carrier_80211fhss;
                else if (IEEE80211_IS_CHAN_A(chan_flags))
                    in_pack->signal_info.carrier = carrier_80211a;
                else if (IEEE80211_IS_CHAN_BPLUS(chan_flags))
                    in_pack->signal_info.carrier = carrier_80211bplus;
                else if (IEEE80211_IS_CHAN_B(chan_flags))
                    in_pack->signal_info.carrier = carrier_80211b;
                else if (IEEE80211_IS_CHAN_PUREG(chan_flags))
                    in_pack->signal_info.carrier = carrier_80211g;
                else if (IEEE80211_IS_CHAN_G(chan_flags))
                    in_pack->signal_info.carrier = carrier_80211g;
                else if (IEEE80211_IS_CHAN_T(chan_flags))
                    in_pack->signal_info.carrier = carrier_80211a;/*XXX*/
                else
                    in_pack->signal_info.carrier = carrier_unknown;
                if ((chan_flags & IEEE80211_CHAN_CCK) == IEEE80211_CHAN_CCK)
                    in_pack->signal_info.encoding = encoding_cck;
                else if ((chan_flags & IEEE80211_CHAN_OFDM) == IEEE80211_CHAN_OFDM)
                    in_pack->signal_info.encoding = encoding_ofdm;
                else if ((chan_flags & IEEE80211_CHAN_DYN) == IEEE80211_CHAN_DYN)
                    in_pack->signal_info.encoding = encoding_dynamiccck;
                else if ((chan_flags & IEEE80211_CHAN_GFSK) == IEEE80211_CHAN_GFSK)
                    in_pack->signal_info.encoding = encoding_gfsk;
                else
                    in_pack->signal_info.encoding = encoding_unknown;
                break;
            }
            case kis_radiotap::bit_rate:
                /* strip basic rate bit & convert to kismet units */
                in_pack->signal_info.data_ok = true;
                in_pack->signal_info.datarate = ((float) (field[0] &~ 0x80) / 2) * 10;
                break;
            case kis_radiotap::bit_antenna:
                record_antenna = field[0];
                break;
            case kis_radiotap::bit_dbm_antsignal:
                record_signal = static_cast<int8_t>(field[0]);
                signal_present = true;
                break;
            case kis_radiotap::bit_dbm_antnoise:
                in_pack->signal_info.data_ok = true;
                in_pack->signal_info.signal_type = kis_l1_signal_type_dbm;
                in_pack->signal_info.noise_dbm = static_cast<int8_t>(field[0]);
                break;
            case kis_radiotap::bit_flags:
                if (field[0] & IEEE80211_RADIOTAP_F_FCS) {
                    fcs_cut = 4;
                }

                if (field[0] & IEEE80211_RADIOTAP_F_BADFCS) {
                    fcs_flag_invalid = true;
                }

                break;
#if defined(SYS_OPENBSD)
            case kis_radiotap::bit_openbsd_rssi: {
                // OpenBSD relative RSSI (rssi, max_rssi), unitless; scaled to 0-255 and
                // reported as RSSI, not dBm.  A dBm antenna signal in the same header wins:
                // it's applied after this record's fields, or already was.  A scaled 0 is
                // dropped since the trackers read 0 as no signal.
                const auto rssi = field[0];
                const auto max_rssi = field[1];

                if (assigned_signal || max_rssi == 0)
                    break;

                const int scaled_rssi = int(std::min(rssi, max_rssi)) * 255 / max_rssi;

                if (scaled_rssi == 0)
                    break;

                in_pack->signal_info.data_ok = true;
                in_pack->signal_info.signal_type = kis_l1_signal_type_rssi;
                in_pack->signal_info.signal_rssi = scaled_rssi;
                break;
            }
#endif
            default:
                break;
        }
    };

    const auto walked = kis_radiotap::walk(std::span<const uint8_t>(rt, radiotap_len), apply_field);

    // Presence words running past the header
    if (walked.status == kis_radiotap::walk_status::malformed) {
        return 0;
    }

    finish_record();

    if (walked.tlv_offset) {
        radiotap_parse_tlvs(rt + *walked.tlv_offset, rt + radiotap_len, in_pack, phy_rate);
    }

    in_pack->signal_info.phy_rate = phy_rate.finish();

    // HT and later frames have no legacy rate field; their rate is bounded by max_phy_rate_kbps
    if (!phy_rate.legacy_rate_seen() && in_pack->signal_info.phy_rate.rate_kbps > 0) {
        in_pack->signal_info.data_ok = true;
        in_pack->signal_info.datarate = dot11_datarate_of(in_pack->signal_info.phy_rate.rate_kbps);
    }

    auto decapchunk = packetchain->new_packet_component<kis_datachunk>();

    decapchunk->dlt = KDLT_IEEE802_11;

    const auto offset = radiotap_len;

    // A frame captured shorter than it was (snap length, truncate_data) doesn't have its FCS,
    // whatever the flags say
    if (fcs_cut && in_pack->original_len > linkchunk->length())
        fcs_cut = 0;

    if (fcs_cut && offset + fcs_cut > (int) linkchunk->length()) {
        return 0;
    }

    // Slice the rtap headers off and put them in the l1chunk record
    auto l1chunk = packetchain->new_packet_component<kis_datachunk>();
    l1chunk->set_data(linkchunk->substr(0, offset));
    in_pack->insert(pack_comp_l1data, l1chunk);

    decapchunk->set_data(linkchunk->substr(offset, linkchunk->length() - offset - fcs_cut));

    in_pack->insert(pack_comp_decap, decapchunk);

    uint32_t fcs_data = 0;

    if (fcs_cut) {
        if (linkchunk->length() < 4) {
            in_pack->error = true;
            return 1;
        }

        if (fcs_flag_invalid) {
            in_pack->crc_ok = true;
            in_pack->checksum_valid = false;
        }

        memcpy(&fcs_data, linkchunk->substr(linkchunk->length() - 4, 4).data(), 4);
    } else if (fcs_flag_invalid) {
        if (fcs_flag_invalid) {
            in_pack->crc_ok = true;
            in_pack->checksum_valid = false;
        }
    }

    // Radiotap only encapsulates wireless so we can do our own fcs algo locally;
    // if we have an unknown FCS, and FCS bytes available, we should do a full
    // checksum
    if (datasrc != nullptr &&
            datasrc->ref_source != nullptr &&
            !in_pack->crc_ok &&
            fcs_data != 0) {
        // Compare it and flag the packet
        uint32_t calc_crc =
            crc32_le_80211(crc32_table, decapchunk->data(), decapchunk->length());
        uint32_t flipped_crc = kis_swap32(calc_crc);

        in_pack->crc_ok = true;
        if (fcs_data == calc_crc || fcs_data == flipped_crc) {
            in_pack->checksum_valid = true;
        } else {
            in_pack->checksum_valid = false;
        }
    }

    return 1;
}

// Taken from the BBN USRP 802.11 encoding code
unsigned int kis_dlt_radiotap::update_crc32_80211(unsigned int crc, const char *data,
        int len, unsigned int poly) {
    int i, j;
    unsigned short ch;

    for ( i = 0; i < len; ++i) {
        ch = data[i];
        for (j = 0; j < 8; ++j) {
            if ((crc ^ ch) & 0x0001) {
                crc = (crc >> 1) ^ poly;
            } else {
                crc = (crc >> 1);
            }
            ch >>= 1;
        }
    }
    return crc;
}

void kis_dlt_radiotap::crc32_init_table_80211(unsigned int *crc32_table) {
    int i;
    char c;

    for (i = 0; i < 256; ++i) {
        c = i;
        crc32_table[i] = update_crc32_80211(0, &c, 1, IEEE_802_3_CRC32_POLY);
    }
}

unsigned int kis_dlt_radiotap::crc32_le_80211(unsigned int *crc32_table,
        const char *buf, int len) {
    int i;
    unsigned int crc = 0xFFFFFFFF;

    for (i = 0; i < len; ++i) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ buf[i]) & 0xFF];
    }

    crc ^= 0xFFFFFFFF;

    return crc;
}

