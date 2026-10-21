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
#include <inttypes.h>

#include "messagebus.h"
#include "globalregistry.h"
#include "kis_endian.h"         //le16toh / le32toh for TAP TLVs

kis_datasource_catsniffer_zigbee::rx_content kis_datasource_catsniffer_zigbee::handle_rx_data_content(
        kis_packet *packet, kis_datachunk *datachunk,
        const uint8_t *content, size_t content_sz) {

     /*_MSG(fmt::format("Catsniffer DS: handle_rx_data_content() dlt={} content_sz={}",
                     (datachunk ? (int)datachunk->dlt : -1), (int)content_sz),
         MSGFLAG_INFO); */ //Debug

    // Basic guards
    if (packet == nullptr) {
        return rx_content::error;
    }

    if (datachunk == nullptr) {
        return rx_content::error;
    }

    if (content == nullptr || content_sz < sizeof(_802_15_4_tap)) {
        return rx_content::error;
    }

    if (datachunk->dlt != KDLT_IEEE802_15_4_TAP) {
        return rx_content::error;
    }

    // --- Treat incoming bytes as 802.15.4 TAP frame: its TLVs by type and length ---
    struct tap_802_15_4_meta tap;

    if (!tap_802_15_4_parse(reinterpret_cast<const uint8_t *>(content), content_sz, &tap) ||
            tap.header_len < sizeof(_802_15_4_tap)) {
        return rx_content::error;
    }

    const size_t mac_len = content_sz - tap.header_len;
    packet->original_len = mac_len;

    // --- The datachunk becomes the LINKFRAME so 802.15.4 decoders can run ---
    packet->set_data(reinterpret_cast<const char*>(content), content_sz);
    datachunk->set_data(packet->data);

    // --- Build radiodata (RSSI / Channel) for UI ---
    packet->signal_info.data_ok = true;
    packet->signal_info.signal_type = kis_l1_signal_type_none;

    if (tap.have_rss) {
        packet->signal_info.signal_type = kis_l1_signal_type_dbm;
        packet->signal_info.signal_dbm = (int) tap.rss_dbm;
    } else if (tap.have_lqi) {
        // An older catsniffer capture tool: its RSSI as a signed octet in the LQI TLV
        packet->signal_info.signal_type = kis_l1_signal_type_dbm;
        packet->signal_info.signal_dbm = (int8_t) tap.lqi;
    }

    if (tap.have_channel) {
        packet->signal_info.channel = fmt::format("{}", tap.channel);
        packet->signal_info.freq_khz = tap_802_15_4_channel_khz(tap.channel, tap.page);
    }

    return rx_content::frame;
}

