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

#include "kis_dlt_loratap.h"

#include "dlttracker.h"
#include "globalregistry.h"
#include "endian_magic.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"

kis_dlt_loratap::kis_dlt_loratap() : kis_dlt_handler() {
    dlt_name = "Loratap";
    dlt = KDLT_LORATAP;

    _MSG_INFO("Registering support for DLT_LORATAP packet header decoding");

    auto dltt =
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");

    dlt_meshtastic = dltt->register_linktype("MESHTASTIC");
    dlt_meshcore = dltt->register_linktype("MESHCORE");
    dlt_lora_generic = dltt->register_linktype("LORA_GENERIC");
}

int kis_dlt_loratap::handle_packet(const std::shared_ptr<kis_packet>& in_pack) {
    if (in_pack->has(pack_comp_decap)) {
        return 1;
    }

    auto linkchunk = in_pack->fetch<kis_datachunk>(pack_comp_linkframe);

    if (linkchunk == nullptr) {
        return 1;
    }

    if (linkchunk->dlt != dlt) {
        return 1;
    }

    if (linkchunk->length() <= sizeof(loratap_header_prefix_t)) {
        return 1;
    }

    auto prefix_hdr = reinterpret_cast<const loratap_header_prefix_t *>(linkchunk->data());
    auto len = kis_ntoh16(prefix_hdr->length);
    uint8_t syncword = 0;

    if (prefix_hdr->version == 0) {
        if (len < sizeof(loratap_header_v0_t) || len > linkchunk->length()) {
            return 1;
        }

        auto v0_hdr = reinterpret_cast<const loratap_header_v0_t *>(linkchunk->data());

        syncword = v0_hdr->sync_word;

        in_pack->signal_info.data_ok = true;
        in_pack->signal_info.signal_type = kis_l1_signal_type_dbm;
        in_pack->signal_info.signal_dbm = -139 + v0_hdr->rssi;
        in_pack->signal_info.freq_khz = (double) kis_ntoh32(v0_hdr->frequency) / 1024;
        in_pack->signal_info.channel = fmt::format("{}-{}-{}-0-{:2x}",
                in_pack->signal_info.freq_khz * 1024,
                v0_hdr->bandwidth, v0_hdr->spread_factor,
                v0_hdr->sync_word);


    } else if (prefix_hdr->version == 1) {
        if (len < sizeof(loratap_header_v1_t) || len > linkchunk->length()) {
            return 1;
        }

        auto v1_hdr = reinterpret_cast<const loratap_header_v1_t *>(linkchunk->data());

        syncword = v1_hdr->v0_common.sync_word;

        in_pack->signal_info.data_ok = true;
        in_pack->signal_info.signal_type = kis_l1_signal_type_dbm;
        in_pack->signal_info.signal_dbm = -139 + v1_hdr->v0_common.rssi;
        in_pack->signal_info.freq_khz = (double) kis_ntoh32(v1_hdr->v0_common.frequency) / 1024;
        in_pack->signal_info.channel = fmt::format("{}-{}-{}-0-{:2x}",
                in_pack->signal_info.freq_khz * 1024,
                v1_hdr->v0_common.bandwidth, v1_hdr->v0_common.spread_factor,
                v1_hdr->v0_common.sync_word);
    } else {
        return 1;
    }

    auto decapchunk = packetchain->new_packet_component<kis_datachunk>();

    decapchunk->set_data(linkchunk->substr(len, linkchunk->length() - len));

    switch (syncword) {
        case sync_meshtastic:
            decapchunk->dlt = dlt_meshtastic;
            break;
        case sync_meshcore:
            decapchunk->dlt = dlt_meshcore;
            break;
        default:
            decapchunk->dlt = dlt_lora_generic;
            break;
    }

    in_pack->insert(pack_comp_decap, decapchunk);


    return 1;
}
