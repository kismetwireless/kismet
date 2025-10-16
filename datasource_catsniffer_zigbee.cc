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

#include "datasource_catsniffer_zigbee.h"
#include "packetchain.h"
#include "packet.h"
#include "packinfo_signal.h"
#include <fmt/format.h>
#include <vector>
#include <cstring>
#include <endian.h>         //le16toh / le32toh for TAP TLVs
#include <inttypes.h>
#include "messagebus.h"
#include "globalregistry.h"

int kis_datasource_catsniffer_zigbee::handle_rx_data_content(
        kis_packet *packet, kis_datachunk *datachunk,
        const uint8_t *content, size_t content_sz) {

     /*_MSG(fmt::format("Catsniffer DS: handle_rx_data_content() dlt={} content_sz={}",
                     (datachunk ? (int)datachunk->dlt : -1), (int)content_sz),
         MSGFLAG_INFO); */ //Debug

    // Basic guards
    if (!packet) {
        //_MSG("Catsniffer DS: packet==nullptr; bail", MSGFLAG_INFO); //Debug
        return 0;
    }
    if (!datachunk) {
        //_MSG("Catsniffer DS: datachunk==nullptr; bail", MSGFLAG_INFO); //Debug
        return 0;
    }
    if (!content || content_sz < sizeof(_802_15_4_tap)) {
        /* _MSG(fmt::format("Catsniffer DS: content null/too small ({} bytes < {})",
                         (int)content_sz, (int)sizeof(_802_15_4_tap)), MSGFLAG_INFO); */ //Debug
        return 0;
    }

    if (datachunk->dlt != KDLT_IEEE802_15_4_TAP) {
        /* _MSG(fmt::format("Catsniffer DS: non-TAP DLT {}; letting pipeline continue",
                         (int)datachunk->dlt), MSGFLAG_INFO); */ //Debug
        return 0;
    }

    // --- Treat incoming bytes as 802.15.4 TAP frame ---
    const _802_15_4_tap *tap = reinterpret_cast<const _802_15_4_tap *>(content);
    const uint16_t tap_len = le16toh(tap->length);

    //_MSG(fmt::format("Catsniffer DS: TAP length={} bytes (declared)", (int)tap_len), MSGFLAG_INFO); //Debug

    if (tap_len < 28 || tap_len > content_sz) {
        /* _MSG(fmt::format("Catsniffer DS: bad TAP length {} for content_sz {}; bail",
                         (int)tap_len, (int)content_sz), MSGFLAG_INFO); */ //Debug
        return 0;
    }

    //const uint8_t *mac = content + tap_len;
    const size_t mac_len = content_sz - tap_len;
    packet->original_len = mac_len;

    //_MSG(fmt::format("Catsniffer DS: MAC payload len={} (original_len set)", (int)mac_len), MSGFLAG_INFO); //Debug

    // Log TLV headers (we expect at least tlv[0..2] in your struct)
    //const uint16_t t0_type = le16toh(tap->tlv[0].type);
    //const uint16_t t0_len  = le16toh(tap->tlv[0].length);
    //const uint32_t t0_val  = le32toh(tap->tlv[0].value);

    const uint16_t t1_type = le16toh(tap->tlv[1].type);
    const uint16_t t1_len  = le16toh(tap->tlv[1].length);
    const uint32_t t1_val  = le32toh(tap->tlv[1].value);

    const uint16_t t2_type = le16toh(tap->tlv[2].type);
    const uint16_t t2_len  = le16toh(tap->tlv[2].length);
    const uint32_t t2_val  = le32toh(tap->tlv[2].value);

    //Debug
    //_MSG(fmt::format("Catsniffer DS: TLV0 type={} len={} val=0x{:08X}", (int)t0_type, (int)t0_len, t0_val), MSGFLAG_INFO);
    //_MSG(fmt::format("Catsniffer DS: TLV1 type={} len={} val=0x{:08X}", (int)t1_type, (int)t1_len, t1_val), MSGFLAG_INFO);
    //_MSG(fmt::format("Catsniffer DS: TLV2 type={} len={} val=0x{:08X}", (int)t2_type, (int)t2_len, t2_val), MSGFLAG_INFO);

    // Hexdump (truncated) of TAP header portion and MAC payload
    /* _MSG(fmt::format("Catsniffer DS: TAP bytes[0:{}]: {}",
                     (int)tap_len, hexstr(content, tap_len)), MSGFLAG_INFO); */
    /* _MSG(fmt::format("Catsniffer DS: MAC bytes[{}]: {}",
                     (int)mac_len, hexstr(mac, mac_len)), MSGFLAG_INFO); */

    // --- Attach LINKFRAME so 802.15.4 decoders can run ---
    // Copy capture buffer into packet->data and create a LINKFRAME component
    packet->set_data(reinterpret_cast<const char*>(content), content_sz);
    auto linkframe = packetchain->new_packet_component<kis_datachunk>();
    linkframe->dlt = datachunk->dlt;              // KDLT_IEEE802_15_4_TAP
    linkframe->set_data(packet->data);
    packet->insert(pack_comp_linkframe, linkframe);

    /* _MSG(fmt::format("Catsniffer DS: inserted LINKFRAME dlt={} bytes={}",
                     (int)linkframe->dlt, (int)content_sz), MSGFLAG_INFO); */ //Debug

    // --- Build radiodata (RSSI / Channel) for UI ---
    auto radioheader = packetchain->new_packet_component<kis_layer1_packinfo>();
    radioheader->signal_type = kis_l1_signal_type_none;

    // RSSI (TLV 10)
    if (t1_type == 10 && t1_len >= 1) {
        const int8_t rssi = static_cast<int8_t>(t1_val & 0xFF);
        radioheader->signal_type = kis_l1_signal_type_dbm;
        radioheader->signal_dbm  = rssi;
        //_MSG(fmt::format("Catsniffer DS: RSSI (dbm) parsed={}", (int)rssi), MSGFLAG_INFO); //Debug
    } else {
        //_MSG("Catsniffer DS: RSSI TLV missing or len<1; leaving signal_type=none", MSGFLAG_INFO); //Debug
    }

    // Channel (TLV 3)
    if (t2_type == 3) {
        uint8_t page = 0, chan = 0;
        if (t2_len == 1) {
            chan = static_cast<uint8_t>(t2_val & 0xFF);
        } else if (t2_len == 3) {
            page = static_cast<uint8_t>(t2_val & 0xFF);
            chan = static_cast<uint8_t>((t2_val >> 8) & 0xFF);
        } else {
            chan = static_cast<uint8_t>(t2_val & 0xFF);
        }

        radioheader->channel = fmt::format("{}", chan);
        if (page == 0 && chan >= 11 && chan <= 26)
            radioheader->freq_khz = (2405 + ((chan - 11) * 5)) * 1000;

        /*_MSG(fmt::format("Catsniffer DS: channel parsed={} page={} freq_khz={}",
                         (int)chan, (int)page, (uint64_t)radioheader->freq_khz), MSGFLAG_INFO); */ //Debug
    } else {
        //_MSG(fmt::format("Catsniffer DS: Channel TLV not present (type={})", (int)t2_type), MSGFLAG_INFO); //Debug
    }

    packet->insert(pack_comp_radiodata, radioheader);
    /*
    _MSG(fmt::format("Catsniffer DS: radiodata set -> signal_type={} signal_dbm={} channel='{}' freq_khz={}",
                     (int)radioheader->signal_type,
                     (int)radioheader->signal_dbm,
                     radioheader->channel,
                     (uint64_t)radioheader->freq_khz),
         MSGFLAG_INFO);
    */ //Debug
    return 0;
}

