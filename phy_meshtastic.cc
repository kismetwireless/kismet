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

namespace {
    std::string_view sv_trim(std::string_view s) {
        const auto ws = " \t\r\n";
        const auto b = s.find_first_not_of(ws);

        if (b == std::string_view::npos)
            return {};

        return s.substr(b, s.find_last_not_of(ws) - b + 1);
    }

    // Accept standard or url-safe base64, with or without padding; the decoder stops
    // silently at unknown characters so reject them here
    std::optional<std::string> normalize_b64(std::string_view in) {
        std::string out;
        out.reserve(in.size());

        bool padding = false;

        for (const auto c : in) {
            if (c == '=') {
                padding = true;
                continue;
            }

            if (padding)
                return std::nullopt;

            if (c == '-')
                out += '+';
            else if (c == '_')
                out += '/';
            else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '/')
                out += c;
            else
                return std::nullopt;
        }

        return out;
    }
}

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

    mesh_node_id =
        Globalreg::globalreg->entrytracker->register_field("meshtastic.node",
                tracker_element_factory<tracked_meshtastic_node>(),
                "Meshtastic node");

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
    model_private_hw = Globalreg::globalreg->manufdb->make_manuf("Lora (Private Hardware)");

    max_live_messages = Globalreg::globalreg->kismet_config->fetch_opt_ulong("meshtastic_num_messages", 128);

    const meshtastic_crypto::psk default_psk{meshtastic_crypto::psk_type::aes128,
        std::string(reinterpret_cast<const char *>(meshtastic_crypto::default_psk.data()),
                meshtastic_crypto::default_psk.size())};

    for (const auto& name : meshtastic_crypto::preset_channel_names) {
        channels.emplace(std::string{name}, meshtastic_channel{name, default_psk, max_live_messages});
    }

    for (const auto& k : Globalreg::globalreg->kismet_config->fetch_opt_vec("meshtastic_key")) {
        auto toks = base_sv_tokenize(k, ",", "");
        if (toks.size() != 2) {
            _MSG_ERROR("Invalid meshtastic_key '{}', expected channelname,base64key", k);
            continue;
        }

        auto name = sv_trim(toks[0]);
        if (name.length() == 0 || name.length() > meshtastic_crypto::max_channel_name_len) {
            _MSG_ERROR("Invalid meshtastic_key channel name '{}', expected 1 to {} characters",
                    name, meshtastic_crypto::max_channel_name_len);
            continue;
        }

        auto b64 = normalize_b64(sv_trim(toks[1]));
        if (!b64) {
            _MSG_ERROR("Invalid meshtastic_key for channel '{}', key is not valid base64", name);
            continue;
        }

        auto psk = meshtastic_crypto::expand_psk(base64::decode(*b64));
        if (!psk) {
            _MSG_ERROR("Invalid meshtastic_key for channel '{}', keys may be at most 32 bytes", name);
            continue;
        }

        std::string name_s{name};

        if (channels.erase(name_s) > 0) {
            _MSG_INFO("Meshtastic channel '{}' redefined by meshtastic_key", name);
        }

        auto ci = channels.emplace(name_s, meshtastic_channel{name, *psk, max_live_messages}).first;

        _MSG_INFO("Meshtastic added channel '{}' ({}, hash {:02x})", name,
                psk->type == meshtastic_crypto::psk_type::none ? "unencrypted" :
                psk->type == meshtastic_crypto::psk_type::aes128 ? "AES128" : "AES256",
                ci->second.hash());
    }

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/meshtastic/channels", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_jsonable_endpoint>(std::make_unique<json_adapter_v2::jsonable_map<channels_map_t, channels_map_t::iterator>>(channels, "meshtastic.channels"), mutex_));

	packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);
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

    // _MSG_DEBUG("packdata length {}", packdata->length());

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

    bool new_device = false;
    bool new_mesh = false;

    std::shared_ptr<kis_tracked_device_base> basedev =
        mphy->devicetracker->update_common_device(src_mac, mphy, in_pack,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                 UCD_UPDATE_SEENBY), "Meshtastic", new_device);

    if (basedev == nullptr) {
        // _MSG_DEBUG("Failed to make new device");
        return 0;
    }

    kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(), __func__);

    if (new_device) {
        basedev->set_manuf(mphy->generic_manuf);
        basedev->set_tracker_type_string(mphy->devicetracker->get_cached_devicetype("Meshtastic"));
        basedev->set_devicename(fmt::format("Meshtastic !{:08X}", mesh_frame->source_id));
    }

    auto meshdev = basedev->get_sub_as<tracked_meshtastic_node>(mphy->mesh_node_id);
    if (meshdev == nullptr) {
        meshdev =
            Globalreg::globalreg->entrytracker->get_shared_instance_as<tracked_meshtastic_node>(mphy->mesh_node_id);
        basedev->insert(meshdev);
        new_mesh = true;
    }

    if (new_mesh) {
        meshdev->set_nodeid(fmt::format("!{:08X}", mesh_frame->source_id));
    }

    const auto payload =
        packdata->substr(sizeof(meshtastic_frame_t),
                packdata->length() - sizeof(meshtastic_frame_t));

    // nonce is the packet id as a 64 bit int followed by the sender id, both little endian
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    memcpy(iv, packdata->data() + 8, 4);
    memcpy(iv + 8, packdata->data() + 4, 4);

    kis_aes::aes128 aes128;
    kis_aes::aes256 aes256;

    bool matched_hash = false;

    // multiple channels can share an 8 bit hash, so try each until one decodes
    for (auto& [chan_name, chan] : mphy->channels) {
        if (chan.hash() != mesh_frame->channel) {
            continue;
        }

        matched_hash = true;

        std::string decoded;

        switch (chan.psk().type) {
            case meshtastic_crypto::psk_type::none:
                decoded = std::string{payload};
                break;
            case meshtastic_crypto::psk_type::aes128:
                aes128.set((const uint8_t *) chan.psk().key.data(), iv);
                decoded = aes128.ctr_crypt(std::string{payload});
                break;
            case meshtastic_crypto::psk_type::aes256:
                aes256.set((const uint8_t *) chan.psk().key.data(), iv);
                decoded = aes256.ctr_crypt(std::string{payload});
                break;
        }

        std::optional<meshtastic_portnum> port;
        std::string_view subcontent;

        // _MSG_DEBUG("decoded paylaod size {}", decoded.size());

        try {
            protobuf_decoder::decoder decoder(decoded);
            int64_t fn;

            while ((fn = decoder.next_field()) >= 0) {
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
        } catch (const std::exception& e) {
            // _MSG_DEBUG("meshtastic channel '{}' failed to decode: {}", chan_name, e.what());
            continue;
        }

        // a wrong key can still produce a parseable protobuf; require a port
        if (!port) {
            continue;
        }

        // _MSG_DEBUG("decoded a packet on channel {}", chan_name);

        try {
            switch (*port) {
                case meshtastic_portnum::text_message:
                    _MSG_INFO("Meshtastic \"{}\" ({}) on channel \"{}\":  len {} {}",
                            basedev->get_most_apt_name(), meshdev->get_nodeid(),
                            chan_name, subcontent.length(), std::string(subcontent.data(), subcontent.length()));
                    chan.add_message(meshdev->get_nodeid(), subcontent);
                    break;
                case meshtastic_portnum::nodeinfo:
                    mphy->handle_user_pb(subcontent, in_pack, basedev, meshdev);
                    break;
                case meshtastic_portnum::position:
                    mphy->handle_position_pb(subcontent, in_pack, basedev, meshdev);
                    break;
                case meshtastic_portnum::telemetry:
                    mphy->handle_telemetry_pb(subcontent, in_pack, basedev, meshdev);
                    break;
                default:
                    _MSG_DEBUG("Meshtastic \"{}\" ({}) not handling message on port {} ({})",
                            basedev->get_most_apt_name(), meshdev->get_nodeid(),
                            portnum_to_string(*port), static_cast<int>(*port));
                    break;
            }
        } catch (const std::exception& e) {
            _MSG_DEBUG("meshtastic failed to decode: {}", chan_name, e.what());
            continue;
        }

        break;
    }

    if (!matched_hash) {
        _MSG_DEBUG("meshtastic packet for unknown channel hash {:02x}", mesh_frame->channel);
    }

    if (new_device) {
        _MSG_INFO("Detected new Meshtastic Lora device {} ({})", basedev->get_most_apt_name(), meshdev->get_nodeid());
    }

    return 1;
}

void kis_meshtastic_phy::handle_telemetry_pb(const std::string_view& pbuf,
        const std::shared_ptr<kis_packet>& packet,
        std::shared_ptr<kis_tracked_device_base> base,
        std::shared_ptr<tracked_meshtastic_node> node) {

}

void kis_meshtastic_phy::handle_devicemetrics_pb(const std::string_view& pbuf,
        const std::shared_ptr<kis_packet>& packet,
        std::shared_ptr<kis_tracked_device_base> base,
        std::shared_ptr<tracked_meshtastic_node> node) {
    protobuf_decoder::decoder dec(pbuf);

    int64_t fn;
    while (1) {
        fn = dec.next_field();

        if (fn < 0) {
            break;
        }

        switch (static_cast<meshtastic_devicemetrics_pb>(fn)) {
            case meshtastic_devicemetrics_pb::fn_battery_level:
                node->set_telem_battery_perc(dec.get_int());
                break;
            case meshtastic_devicemetrics_pb::fn_voltage:
                node->set_telem_battery_voltage(dec.get_float<float>());
                break;
            case meshtastic_devicemetrics_pb::fn_channel_utilization:
                node->set_telem_channel_util(dec.get_float<float>());
                break;
            case meshtastic_devicemetrics_pb::fn_air_util_tx:
                node->set_telem_channel_tx_util(dec.get_float<float>());
                break;
            case meshtastic_devicemetrics_pb::fn_uptime_seconds:
                node->set_telem_uptime_sec(dec.get_int());
                break;
            default:
                dec.ignore_field();
        }
    }

}

void kis_meshtastic_phy::handle_user_pb(const std::string_view& pbuf,
        const std::shared_ptr<kis_packet>& packet,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node) {
    protobuf_decoder::decoder dec(pbuf);

    std::string_view data;
    std::shared_ptr<tracker_element_string> manuf;

    _MSG_DEBUG("meshtastic - handling user block");

    int64_t fn;
    while (1) {
        fn = dec.next_field();

        if (fn < 0) {
            break;
        }

        switch (static_cast<meshtastic_user_pb>(fn)) {
            case meshtastic_user_pb::fn_id:
                dec.next_field();
                /* do nodes send out details for OTHER nodes?  if so we have to
                 * convert & look up the proper device
                data = dec.get_bytearray();
                printf("  id: %s\n", std::string(data.data(), data.length()).c_str());
                */
                break;
            case meshtastic_user_pb::fn_long_name:
                data = dec.get_bytearray();
                node->set_longname(std::string(data.data(), data.length()));
                break;
            case meshtastic_user_pb::fn_short_name:
                data = dec.get_bytearray();
                node->set_shortname(std::string(data.data(), data.length()));
                break;
            case meshtastic_user_pb::fn_hw_model:
                node->set_manuf_id(dec.get_int());
                manuf = model_id_to_string(node->get_manuf_id());
                if (manuf != nullptr) {
                    base->set_manuf(manuf);
                }
                break;
            case meshtastic_user_pb::fn_is_licensed:
                node->set_licensed(dec.get_int());
                break;
            case meshtastic_user_pb::fn_role:
                node->set_role(dec.get_int());
                break;
            default:
                dec.ignore_field();
                break;
        }
    }

}

void kis_meshtastic_phy::handle_position_pb(const std::string_view& pbuf,
        const std::shared_ptr<kis_packet>& packet,
        std::shared_ptr<kis_tracked_device_base> base,
        std::shared_ptr<tracked_meshtastic_node> node) {
    protobuf_decoder::decoder dec(pbuf);

    int64_t fn;
    double lat = 0, lon = 0;
    double alt = 0;
    double speed = 0;

    while (1) {
        fn = dec.next_field();

        if (fn < 0) {
            break;
        }

        // todo - handle heading?

        switch (static_cast<meshtastic_position_pb>(fn)) {
            case meshtastic_position_pb::fn_latitude_i:
                lat = ((double) (int32_t) dec.get_int()) * 0.0000001;
                break;
            case meshtastic_position_pb::fn_longitude_i:
                lon = ((double) (int32_t) dec.get_int()) * 0.0000001;
                break;
            case meshtastic_position_pb::fn_altitude:
                alt = (uint32_t) dec.get_int();
                break;
            case meshtastic_position_pb::fn_ground_speed:
                speed = (uint32_t) dec.get_int();
                break;
            default:
                dec.ignore_field();
        }
    }

    if (lat != 0 && lon != 0) {
        packet->gps_info.gps_info_ok = true;
        packet->gps_info.lat = lat;
        packet->gps_info.lon = lon;
        packet->gps_info.alt = alt;
        packet->gps_info.speed = speed;
        packet->gps_info.fix = alt == 0 ? 2 : 3;
    }
}

void kis_meshtastic_phy::handle_nodeinfo_pb(const std::string_view& pbuf,
        const std::shared_ptr<kis_packet>& packet,
        std::shared_ptr<kis_tracked_device_base> base,
        std::shared_ptr<tracked_meshtastic_node> node) {
    protobuf_decoder:: decoder dec(pbuf);

    int64_t fn;
    while (1) {
        fn = dec.next_field();

        if (fn < 0) {
            break;
        }

        switch (static_cast<meshtastic_nodeinfo_pb>(fn)) {
            case meshtastic_nodeinfo_pb::fn_num:
                dec.ignore_field();
                break;
            case meshtastic_nodeinfo_pb::fn_user:
                dec.ignore_field();
                break;
            case meshtastic_nodeinfo_pb::fn_position:
                dec.ignore_field();
                break;
            case meshtastic_nodeinfo_pb::fn_snr:
                break;
            case meshtastic_nodeinfo_pb::fn_last_heard:
                break;
            case meshtastic_nodeinfo_pb::fn_device_metrics:
                dec.ignore_field();
                break;
            case meshtastic_nodeinfo_pb::fn_channels:
                break;
            case meshtastic_nodeinfo_pb::fn_via_mqtt:
                break;
            case meshtastic_nodeinfo_pb::fn_via_hops_away:
                break;
            default:
                dec.ignore_field();
                break;
        }
    }
}

std::shared_ptr<tracker_element_string> kis_meshtastic_phy::model_id_to_string(int hw) {
    switch (static_cast<meshtastic_hw_model>(hw)) {
        case meshtastic_hw_model::tlora_v2:
            return model_tlora_v2;
        case meshtastic_hw_model::tlora_v1:
            return model_tlora_v1;
        case meshtastic_hw_model::tlora_v2_1_1p6:
            return model_tlora_v2_1_1p6;
        case meshtastic_hw_model::tbeam:
            return model_tbeam;
        case meshtastic_hw_model::heltec_v2_0:
            return model_heltec_v2_0;
        case meshtastic_hw_model::tbeam_v0p7:
            return model_tbeam_v0p7;
        case meshtastic_hw_model::t_echo:
            return model_t_echo;
        case meshtastic_hw_model::tlora_v1_1p3:
            return model_tlora_v1_1p3;
        case meshtastic_hw_model::rak4631:
            return model_rak4631;
        case meshtastic_hw_model::heltec_v2_1:
            return model_heltec_v2_1;
        case meshtastic_hw_model::heltec_v1:
            return model_heltec_v1;
        case meshtastic_hw_model::lilygo_tbeam_s3_core:
            return model_lilygo_tbeam_s3_core;
        case meshtastic_hw_model::rak11200:
            return model_rak11200;
        case meshtastic_hw_model::nano_g1:
            return model_nano_g1;
        case meshtastic_hw_model::tlora_v2_1_1p8:
            return model_tlora_v2_1_1p8;
        case meshtastic_hw_model::tlora_t3_s3:
            return model_tlora_t3_s3;
        case meshtastic_hw_model::nano_g1_explorer:
            return model_nano_g1_explorer;
        case meshtastic_hw_model::nano_g2_ultra:
            return model_nano_g2_ultra;
        case meshtastic_hw_model::lora_type:
            return model_lora_type;
        case meshtastic_hw_model::station_g1:
            return model_station_g1;
        case meshtastic_hw_model::rak11310:
            return model_rak11310;
        case meshtastic_hw_model::senselora_s3:
            return model_senselora_s3;
        case meshtastic_hw_model::canaryone:
            return model_canaryone;
        case meshtastic_hw_model::rp2040_lora:
            return model_rp2040_lora;
        case meshtastic_hw_model::station_g2:
            return model_station_g2;
        case meshtastic_hw_model::lora_relay_v1:
            return model_lora_relay_v1;
        case meshtastic_hw_model::nrf52840dk:
            return model_nrf52840dk;
        case meshtastic_hw_model::ppr:
            return model_ppr;
        case meshtastic_hw_model::genieblocks:
            return model_genieblocks;
        case meshtastic_hw_model::nrf52_unknown:
            return model_nrf52_unknown;
        case meshtastic_hw_model::portuino:
            return model_portuino;
        case meshtastic_hw_model::android_sim:
            return model_android_sim;
        case meshtastic_hw_model::diy_v1:
            return model_diy_v1;
        case meshtastic_hw_model::nrf52840_pca10059:
            return model_nrf52840_pca10059;
        case meshtastic_hw_model::dr_dev:
            return model_dr_dev;
        case meshtastic_hw_model::m5stack:
            return model_m5stack;
        case meshtastic_hw_model::heltec_v3:
            return model_heltec_v3;
        case meshtastic_hw_model::heltec_wsl_v3:
            return model_heltec_wsl_v3;
        case meshtastic_hw_model::betafpv_2400_tx:
            return model_betafpv_2400_tx;
        case meshtastic_hw_model::betafpv_900_nano_tx:
            return model_betafpv_900_nano_tx;
        case meshtastic_hw_model::rpi_pico:
            return model_rpi_pico;
        case meshtastic_hw_model::heltec_wireless_tracker:
            return model_heltec_wireless_tracker;
        case meshtastic_hw_model::heltec_wireless_paper:
            return model_heltec_wireless_paper;
        case meshtastic_hw_model::t_deck:
            return model_t_deck;
        case meshtastic_hw_model::t_watch_s3:
            return model_t_watch_s3;
        case meshtastic_hw_model::picomputer_s3:
            return model_picomputer_s3;
        case meshtastic_hw_model::heltec_ht62:
            return model_heltec_ht62;
        case meshtastic_hw_model::ebyte_esp32_s3:
            return model_ebyte_esp32_s3;
        case meshtastic_hw_model::esp32_s3_pico:
            return model_esp32_s3_pico;
        case meshtastic_hw_model::chatter2:
            return model_chatter2;
        case meshtastic_hw_model::heltec_wireless_paper_v1_0:
            return model_heltec_wireless_paper_v1_0;
        case meshtastic_hw_model::heltec_wireless_tracker_v1_0:
            return model_heltec_wireless_tracker_v1_0;
        case meshtastic_hw_model::private_hw:
            return model_private_hw;
        default:
            return nullptr;
    }
}
