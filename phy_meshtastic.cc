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

#include "phy_meshtastic.h"

#include "kis_dlt_loratap.h"

#include "base64.h"
#include "configfile.h"
#include "dlttracker.h"
#include "kis_net_beast_httpd.h"
#include "manuf.h"

kis_meshtastic_phy::kis_meshtastic_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    mutex_.set_name("kis_meshtastic_phy");

    set_phy_name("Meshtastic");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    datasourcetracker =
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_decap = packetchain->register_packet_component("DECAP");

    auto dltt =
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");

    dlt_meshtastic = dltt->register_linktype("MESHTASTIC");

    generic_manuf = Globalreg::globalreg->manufdb->make_manuf("Lora / Meshtastic");

    // cached names
    model_tlora_v2 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v2");
    model_tlora_v1 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v1");
    model_tlora_v2_1_1p6 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v2.1-1.6");
    model_tbeam = Globalreg::globalreg->manufdb->make_manuf("T-Beam");
    model_heltec_v2_0 = Globalreg::globalreg->manufdb->make_manuf("Heltec v2.0");
    model_tbeam_v0p7 = Globalreg::globalreg->manufdb->make_manuf("T-Beam v0.7");
    model_t_echo = Globalreg::globalreg->manufdb->make_manuf("T-Echo");
    model_tlora_v1_1p3 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v1-1.3");
    model_rak4631 = Globalreg::globalreg->manufdb->make_manuf("RAK4631");
    model_heltec_v2_1 = Globalreg::globalreg->manufdb->make_manuf("Heltec v2.1");
    model_heltec_v1 = Globalreg::globalreg->manufdb->make_manuf("Heltec v1");
    model_lilygo_tbeam_s3_core = Globalreg::globalreg->manufdb->make_manuf("LilyGo T-Beam S3 Core");
    model_rak11200 = Globalreg::globalreg->manufdb->make_manuf("RAK11200");
    model_nano_g1 = Globalreg::globalreg->manufdb->make_manuf("Nano G1");
    model_tlora_v2_1_1p8 = Globalreg::globalreg->manufdb->make_manuf("T-Lora v2 1-1.8");
    model_tlora_t3_s3 = Globalreg::globalreg->manufdb->make_manuf("T-Lora t3-s3");
    model_nano_g1_explorer = Globalreg::globalreg->manufdb->make_manuf("Nano G1 Explorer");
    model_nano_g2_ultra = Globalreg::globalreg->manufdb->make_manuf("Nano G2 Ultra");
    model_lora_type = Globalreg::globalreg->manufdb->make_manuf("Lora Type");
    model_station_g1 = Globalreg::globalreg->manufdb->make_manuf("Station G1");
    model_rak11310 = Globalreg::globalreg->manufdb->make_manuf("RAK11310");
    model_senselora_s3 = Globalreg::globalreg->manufdb->make_manuf("SenseLora S3");
    model_canaryone = Globalreg::globalreg->manufdb->make_manuf("CanaryOne");
    model_rp2040_lora = Globalreg::globalreg->manufdb->make_manuf("RP2040 Lora");
    model_station_g2 = Globalreg::globalreg->manufdb->make_manuf("Station G2");
    model_lora_relay_v1 = Globalreg::globalreg->manufdb->make_manuf("Lora Relay v1");
    model_nrf52840dk = Globalreg::globalreg->manufdb->make_manuf("NRF52840dk");
    model_ppr = Globalreg::globalreg->manufdb->make_manuf("PPR");
    model_genieblocks = Globalreg::globalreg->manufdb->make_manuf("GenieBlocks");
    model_nrf52_unknown = Globalreg::globalreg->manufdb->make_manuf("NRF52 Unknown");
    model_portuino = Globalreg::globalreg->manufdb->make_manuf("Portuino");
    model_android_sim = Globalreg::globalreg->manufdb->make_manuf("Android Sim");
    model_diy_v1 = Globalreg::globalreg->manufdb->make_manuf("DIY v1");
    model_nrf52840_pca10059 = Globalreg::globalreg->manufdb->make_manuf("NRF52840 PCA10059");
    model_dr_dev = Globalreg::globalreg->manufdb->make_manuf("Dr Dev");
    model_m5stack = Globalreg::globalreg->manufdb->make_manuf("m5stack");
    model_heltec_v3 = Globalreg::globalreg->manufdb->make_manuf("Heltec v3");
    model_heltec_wsl_v3 = Globalreg::globalreg->manufdb->make_manuf("Heltec WSL v3");
    model_betafpv_2400_tx = Globalreg::globalreg->manufdb->make_manuf("BetaFPV 2400 tx");
    model_betafpv_900_nano_tx = Globalreg::globalreg->manufdb->make_manuf("BetaFPV 900 Nano tx");
    model_rpi_pico = Globalreg::globalreg->manufdb->make_manuf("RPi Pico");
    model_heltec_wireless_tracker = Globalreg::globalreg->manufdb->make_manuf("Heltec Wireless Tracker");
    model_heltec_wireless_paper = Globalreg::globalreg->manufdb->make_manuf("Heltec Wireless Paper");
    model_t_deck = Globalreg::globalreg->manufdb->make_manuf("T-Deck");
    model_t_watch_s3 = Globalreg::globalreg->manufdb->make_manuf("T-Watch s3");
    model_picomputer_s3 = Globalreg::globalreg->manufdb->make_manuf("Picomputer s3");
    model_heltec_ht62 = Globalreg::globalreg->manufdb->make_manuf("Heltec ht62");
    model_ebyte_esp32_s3 = Globalreg::globalreg->manufdb->make_manuf("Ebyte ESP32 s3");
    model_esp32_s3_pico = Globalreg::globalreg->manufdb->make_manuf("ESP32 s3 pico");
    model_chatter2 = Globalreg::globalreg->manufdb->make_manuf("Chatter2");
    model_heltec_wireless_paper_v1_0 = Globalreg::globalreg->manufdb->make_manuf("Heltec Wireless Paper v1.0");
    model_heltec_wireless_tracker_v1_0 = Globalreg::globalreg->manufdb->make_manuf("Heltec Wireless Tracker v1.0");

    keys["default"] = std::string((const char *) default_key, 16);
    keys["default2"] = std::string((const char *) default_key2, 32);

    for (const auto& k : Globalreg::globalreg->kismet_config->fetch_opt_vec("meshtastic_key")) {
        auto toks = base_sv_tokenize(k, ",", "");
        if (toks.size() != 2) {
            _MSG_ERROR("Invalid meshtastic key '{}', expected name,base64key", k);
            continue;
        }

        auto dk = base64::decode(toks[1]);
        if (dk.length() != 16 && dk.length() != 32) {
            _MSG_ERROR("Invalid meshtastic key '{}', expected base64 key", k);
            continue;
        }
    }

    max_live_messages = Globalreg::globalreg->kismet_config->fetch_opt_ulong("meshtastic_max_messages", 128);

    channels.emplace("default", meshtastic_channel{"default", keys["default"], max_live_messages});
    channels.emplace("default2", meshtastic_channel{"default2", keys["default2"], max_live_messages});

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();


    httpd->register_route("/meshtastic/channels", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_jsonable_endpoint>(std::make_unique<json_adapter_v2::jsonable_map<channels_map_t, channels_map_t::iterator>>(channels, "meshtastic.channels"), mutex_));
}

kis_meshtastic_phy::~kis_meshtastic_phy() {
    // packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

int kis_meshtastic_phy::packet_handler(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_meshtastic_phy *>(auxdata);

    if (in_pack->duplicate || in_pack->filtered) {
        return 1;
    }

    if (in_pack->common_info.common_info_ok) {
        return 0;
    }

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_decap, mphy->pack_comp_linkframe);

    if (packdata == nullptr) {
        return 0;
    }

    if (packdata->dlt != mphy->dlt_meshtastic) {
        return 0;
    }

    if (packdata->length() < sizeof(meshtastic_frame_t)) {
        return 0;
    }

    auto mesh_frame = reinterpret_cast<const meshtastic_frame_t *>(packdata->data());

    auto src_mac = mesh_to_mac(mesh_frame->source_id);
    auto dst_mac = mesh_to_mac(mesh_frame->dest_id);
    if (in_pack->signal_info.data_ok) {
        in_pack->common_info.common_info_ok = true;
        in_pack->common_info.type = packet_basic_data;
        in_pack->common_info.phyid = mphy->fetch_phy_id();

        in_pack->common_info.freq_khz = in_pack->signal_info.freq_khz;
        in_pack->common_info.channel = in_pack->signal_info.channel;

        in_pack->common_info.source = src_mac;
        in_pack->common_info.transmitter = src_mac;
        in_pack->common_info.dest = dst_mac;
    }

    // Update the base dev without setting location, because we want to
    // override that location ourselves later once we've gotten our
    // adsb device and possibly merged packets

    bool new_device;

    std::shared_ptr<kis_tracked_device_base> basedev =
        mphy->devicetracker->update_common_device(src_mac, mphy, in_pack,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                 UCD_UPDATE_SEENBY), "Meshtastic", new_device);

    if (basedev == nullptr) {
        return 0;
    }

    kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(), __func__);

    if (new_device) {

    }

    uint8_t iv[16];
    kis_aes::aes128 aes128;
    kis_aes::aes256 aes256;

    std::string decoded;

    for (const auto& k : mphy->keys) {
        memset(iv, 0, 16);

        memcpy(iv, packdata->data() + 8, 4);
        memcpy(iv + 8, packdata->data() + 4, 4);

        try {
            if (k.second.length() == 16) {
                aes128.set((const uint8_t *) k.second.data(), iv);
                decoded = aes128.ctr_crypt(std::string((const char *) packdata->data() + 16,
                                packdata->length() - 16));
            } else if (k.second.length() == 32) {
                aes256.set((const uint8_t *) k.second.data(), iv);
                decoded = aes128.ctr_crypt(std::string((const char *) packdata->data() + 16,
                                packdata->length() - 16));
            }

            protobuf_decoder::decoder decoder(decoded);
            int64_t fn;
            meshtastic_portnum port;
            std::string_view subcontent;

            while (1) {
                fn = decoder.next_field();

                if (fn < 0) {
                    break;
                }

                switch (static_cast<meshtastic_data_pb>(fn)) {
                    case meshtastic_data_pb::fn_portnum:
                        port = static_cast<meshtastic_portnum>(decoder.get_int());
                        break;
                    case meshtastic_data_pb::fn_payload:
                        subcontent = decoder.get_bytearray();
                        break;
                    default:
                        decoder.ignore_field();
                        break;
                }
            }

            if (subcontent.length() == 0) {
                break;
            }

            switch (port) {
                case meshtastic_portnum::text_message:

                default:
                    break;
            }
        } catch (...) {
            // silently skip decrypt or protobuf errors
            continue;
        }
    }



    return 1;
}

void kis_meshtastic_phy::handle_meshtashtic_pb(const std::string_view& pbuf,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node) {

}

void kis_meshtastic_phy::handle_telemetry_pb(const std::string& pbuf,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node) {

}

void kis_meshtastic_phy::handle_powermetrics_pb(const std::string& pbuf,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node) {

}

void kis_meshtastic_phy::handle_devicemetrics_pb(const std::string& pbuf,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node) {

}

void kis_meshtastic_phy::handle_position_pb(const std::string& pbuf,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node) {

}

void kis_meshtastic_phy::handle_user_pb(const std::string& pbuf,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node) {

}

void kis_meshtastic_phy::handle_nodeinfo_pb(const std::string& pbuf,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node) {

}

