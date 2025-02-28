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

#include "phy_adsb.h"
#include "datasource_virtual.h"

#include "devicetracker.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "manuf.h"
#include "messagebus.h"

uint32_t kis_adsb_phy::modes_checksum_table[] = {
    0x3935ea, 0x1c9af5, 0xf1b77e, 0x78dbbf, 0xc397db, 0x9e31e9, 
    0xb0e2f0, 0x587178, 0x2c38bc, 0x161c5e, 0x0b0e2f, 0xfa7d13, 
    0x82c48d, 0xbe9842, 0x5f4c21, 0xd05c14, 0x682e0a, 0x341705, 
    0xe5f186, 0x72f8c3, 0xc68665, 0x9cb936, 0x4e5c9b, 0xd8d449,
    0x939020, 0x49c810, 0x24e408, 0x127204, 0x093902, 0x049c81, 
    0xfdb444, 0x7eda22, 0x3f6d11, 0xe04c8c, 0x702646, 0x381323, 
    0xe3f395, 0x8e03ce, 0x4701e7, 0xdc7af7, 0x91c77f, 0xb719bb, 
    0xa476d9, 0xadc168, 0x56e0b4, 0x2b705a, 0x15b82d, 0xf52612,
    0x7a9309, 0xc2b380, 0x6159c0, 0x30ace0, 0x185670, 0x0c2b38, 
    0x06159c, 0x030ace, 0x018567, 0xff38b7, 0x80665f, 0xbfc92b, 
    0xa01e91, 0xaff54c, 0x57faa6, 0x2bfd53, 0xea04ad, 0x8af852, 
    0x457c29, 0xdd4410, 0x6ea208, 0x375104, 0x1ba882, 0x0dd441,
    0xf91024, 0x7c8812, 0x3e4409, 0xe0d800, 0x706c00, 0x383600, 
    0x1c1b00, 0x0e0d80, 0x0706c0, 0x038360, 0x01c1b0, 0x00e0d8, 
    0x00706c, 0x003836, 0x001c1b, 0xfff409, 0x000000, 0x000000, 
    0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000,
    0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 
    0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 0x000000, 
    0x000000, 0x000000, 0x000000, 0x000000
};

kis_adsb_phy::kis_adsb_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("ADSB");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    datasourcetracker = 
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();

	pack_comp_common = 
        packetchain->register_packet_component("COMMON");
    pack_comp_json = 
        packetchain->register_packet_component("JSON");
    pack_comp_meta =
        packetchain->register_packet_component("METABLOB");
	pack_comp_gps =
        packetchain->register_packet_component("GPS");
    pack_comp_datasource =
        packetchain->register_packet_component("KISDATASRC");

    adsb_adsb_id =
        Globalreg::globalreg->entrytracker->register_field("adsb.device",
                tracker_element_factory<adsb_tracked_adsb>(),
                "ADSB adsb");


    map_min_lat_id = 
        Globalreg::globalreg->entrytracker->register_field("kismet.adsb.map.min_lat",
                tracker_element_factory<tracker_element_double>(),
                "ADSB map minimum latitude");
    map_max_lat_id = 
        Globalreg::globalreg->entrytracker->register_field("kismet.adsb.map.max_lat",
                tracker_element_factory<tracker_element_double>(),
                "ADSB map maximum latitude");
    map_min_lon_id = 
        Globalreg::globalreg->entrytracker->register_field("kismet.adsb.map.min_lon",
                tracker_element_factory<tracker_element_double>(),
                "ADSB map minimum longitude");
    map_max_lon_id = 
        Globalreg::globalreg->entrytracker->register_field("kismet.adsb.map.max_lon",
                tracker_element_factory<tracker_element_double>(),
                "ADSB map maximum longitude");
    map_recent_devs_id = 
        Globalreg::globalreg->entrytracker->register_field("kismet.adsb.map.devices",
                tracker_element_factory<tracker_element_vector>(),
                "ADSB map recent devices");

    // Make the manuf string
    rtl_manuf = Globalreg::globalreg->manufdb->make_manuf("ADSB");

    // Register js module for UI
    auto httpregistry =
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_adsb", "js/kismet.ui.adsb.js");

	packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    icaodb = std::make_shared<kis_adsb_icao>();

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/phy/ADSB/proxy/create", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this, httpd](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    uuid src_uuid;

                    if (!con->json()["uuid"].is_null()) {
                        src_uuid = string_to_n<uuid>(con->json()["uuid"].get<std::string>());

                        if (src_uuid.error)
                            throw std::runtime_error("invalid UUID");

                        auto ds = datasourcetracker->find_datasource(src_uuid);

                        if (ds != nullptr)
                            throw std::runtime_error("datasource with that UUID already exists");
                    } else {
                        src_uuid.generate_random_time_uuid();
                    }

                    std::string src_name = "ADSB proxy";

                    if (!con->json()["name"].is_null()) {
                        src_name = con->json()["name"].get<std::string>();
                    }

                    auto virtual_builder = Globalreg::fetch_mandatory_global_as<datasource_virtual_builder>();
                    auto virtual_source = virtual_builder->build_datasource(virtual_builder);

                    auto vs_cast = std::static_pointer_cast<kis_datasource_virtual>(virtual_source);

                    vs_cast->set_virtual_hardware("ADSB proxy");

                    virtual_source->set_source_uuid(src_uuid);
                    virtual_source->set_source_key(adler32_checksum(src_uuid.uuid_to_string()));
                    virtual_source->set_source_name(src_name);

                    datasourcetracker->merge_source(virtual_source);

                    auto uri = fmt::format("/phy/ADSB/by-uuid/{}/proxy", src_uuid);
                    httpd->register_websocket_route(uri, {httpd->LOGON_ROLE, "datasource"}, {"ws"},
                            std::make_shared<kis_net_web_function_endpoint>(
                                [this, virtual_source, vs_cast](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                                vs_cast->open_virtual_interface();

                                auto ws =
                                std::make_shared<kis_net_web_websocket_endpoint>(con,
                                        [this, virtual_source](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                                            std::shared_ptr<boost::asio::streambuf> buf, bool text) {

                                            // Inject as a packet so it makes it into logs

                                            if (!text)
                                                return;

                                            if (buf->size() < 4)
                                                return;

                                            auto bufstr = boost::beast::buffers_to_string(buf->data());

                                            if (bufstr[0] != '*') {
                                                _MSG_DEBUG("Invalid adsb proxy {}", bufstr);
                                                return;
                                            }

                                            if (bufstr[bufstr.length() - 2] != ';') {
                                                _MSG_DEBUG("Invalid adsb proxy {}", bufstr);
                                                return;
                                            }

                                            // Proxy input
                                            auto packet = packetchain->generate_packet();
                                            gettimeofday(&(packet->ts), NULL);

                                            auto jsoninfo = std::make_shared<kis_json_packinfo>();

                                            jsoninfo->type = "adsb";

                                            jsoninfo->json_string = 
                                                fmt::format("{{\"adsb_raw_msg\": \"{}\"}}",
                                                        bufstr.substr(1, bufstr.length() - 3));

                                            packet->insert(pack_comp_json, jsoninfo);

                                            virtual_source->handle_rx_packet(packet);

                                        });

                                try {
                                    ws->handle_request(con);
                                } catch (const std::exception& e) {
                                    ;
                                }

                                vs_cast->close_virtual_interface();
                        }));

                    return virtual_source;
                }));

    httpd->register_route("/phy/ADSB/map_data", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return adsb_map_endp_handler(con);
                }, devicetracker->get_devicelist_mutex()));

    httpd->register_websocket_route("/phy/ADSB/beast", {httpd->RO_ROLE, "ADSB"}, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                auto ws =
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf, bool text) {
                            // Do nothing on input
                        });

                struct uptr_t {
                    std::shared_ptr<kis_net_web_websocket_endpoint> ws;
                    kis_adsb_phy *adsb;
                };

                auto uptr = new uptr_t();

                uptr->ws = ws;
                uptr->adsb = this;

                auto beast_handler_id = 
                    packetchain->register_handler(
                            [](void *auxdata, const std::shared_ptr<kis_packet>& in_pack) -> int {
                                auto uptr = reinterpret_cast<struct uptr_t *>(auxdata);

                                if (in_pack->error || in_pack->filtered || in_pack->duplicate)
                                    return 0;

                                auto json = in_pack->fetch<kis_json_packinfo>(uptr->adsb->pack_comp_json);

                                if (json == NULL)
                                    return 0;

                                if (json->type != "adsb")
                                    return 0;

                                std::stringstream ss(json->json_string);
                                nlohmann::json device_json;

                                try {
                                    ss >> device_json;

                                    std::string adsb_content;

                                    auto hex_j = device_json["adsb"];

                                    if (hex_j.is_null() || !hex_j.is_string()) {
                                        hex_j = device_json["adsb_raw_msg"];
                                        adsb_content = hex_to_bytes(hex_j);
                                    } else {
                                        const auto stradsb = hex_j.get<std::string>();
                                        adsb_content = hex_to_bytes(stradsb.substr(1, stradsb.size() - 2));    
                                    }


                                    if (adsb_content.size() != 7 && adsb_content.size() != 14) {
                                        _MSG_DEBUG("unexpected content length {}", adsb_content.size());
                                        return 0;
                                    }

                                    auto buf = new char[sizeof(adsb_beast_frame) + adsb_content.size()];
                                    auto frame = reinterpret_cast<adsb_beast_frame_t *>(buf);

                                    frame->esc = 0x1a;

                                    if (adsb_content.size() == 7)
                                        frame->frametype = '2';
                                    else if (adsb_content.size() == 14)
                                        frame->frametype = '3';

                                    struct timeval tv;
                                    gettimeofday(&tv, 0);

                                    auto mlat_s = reinterpret_cast<uint32_t *>(&frame->mlat_ts);
                                    auto mlat_us = reinterpret_cast<uint32_t *>(&frame->mlat_ts + 2);

                                    *mlat_s = tv.tv_usec << 4;
                                    *mlat_us = tv.tv_usec;

                                    frame->signal = 0;

                                    memcpy(frame->modes, adsb_content.data(), adsb_content.size());

                                    uptr->ws->write(std::string(buf, sizeof(adsb_beast_frame) + adsb_content.size()));

                                    delete[] buf;

                                } catch (std::exception& e) {
                                    return 0;
                                }

                                return 1;
                    }, uptr, CHAINPOS_LOGGING, 1000);

                ws->binary();

                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ;
                }

                packetchain->remove_handler(beast_handler_id, CHAINPOS_LOGGING);
                delete uptr;
            }));

    httpd->register_websocket_route("/phy/ADSB/raw", {httpd->RO_ROLE, "ADSB"}, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                auto ws = 
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf,
                            bool text) mutable {
                            // Do nothing on input
                        });

                struct uptr_t {
                    std::shared_ptr<kis_net_web_websocket_endpoint> ws;
                    kis_adsb_phy *adsb;
                };

                auto uptr = new uptr_t();

                uptr->ws = ws;
                uptr->adsb = this;

                auto raw_handler_id = 
                    packetchain->register_handler(
                            [](void *auxdata, const std::shared_ptr<kis_packet>& in_pack) -> int {

                            auto uptr = reinterpret_cast<struct uptr_t *>(auxdata);

                            if (in_pack->error || in_pack->filtered || in_pack->duplicate)
                                return 0;

                            auto json = in_pack->fetch<kis_json_packinfo>(uptr->adsb->pack_comp_json);

                            if (json == NULL)
                                return 0;

                            if (json->type != "adsb")
                                return 0;

                            std::stringstream ss(json->json_string);
                            nlohmann::json device_json;

                            try {
                                ss >> device_json;

                                auto hex_j = device_json["adsb"];

                                if (hex_j.is_null() || !hex_j.is_string()) {
                                    hex_j = device_json["adsb_raw_msg"];
                                }

                                auto adsb_content = 
                                    fmt::format("{}\n", hex_j.get<std::string>());

                                uptr->ws->write(adsb_content);
                            } catch (std::exception& e) {
                                return 0;
                            }

                            return 1;
                    }, uptr, CHAINPOS_LOGGING, 1000);

                ws->text();

                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ;
                }
           
                packetchain->remove_handler(raw_handler_id, CHAINPOS_LOGGING);
                delete(uptr);
            }));

    httpd->register_websocket_route("/datasource/by-uuid/:uuid/adsb_raw", {httpd->RO_ROLE, "ADSB"}, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                auto srcuuid = 
                    uuid(con->uri_params()[":uuid"]);

                if (srcuuid.error)
                    throw std::runtime_error("invalid UUID");

                auto ws = 
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf, bool text) {
                            // Do nothing on input
                        });

                struct uptr_t {
                    std::shared_ptr<kis_net_web_websocket_endpoint> ws;
                    kis_adsb_phy *adsb;                
                    uuid srcuuid;
                };

                auto uptr = new uptr_t();

                uptr->ws = ws;
                uptr->adsb = this;
                uptr->srcuuid = srcuuid;

                auto raw_handler_id = 
                    packetchain->register_handler(
                            [](void *auxdata, const std::shared_ptr<kis_packet>& in_pack) -> int {

                            auto uptr = reinterpret_cast<struct uptr_t *>(auxdata);

                            if (in_pack->error || in_pack->filtered || in_pack->duplicate)
                                return 0;

                            auto json = in_pack->fetch<kis_json_packinfo>(uptr->adsb->pack_comp_json);
                            
                            if (json == nullptr)
                                return 0;

                            if (json->type != "adsb")
                                return 0;

                            auto src = in_pack->fetch<packetchain_comp_datasource>(uptr->adsb->pack_comp_datasource);

                            if (src == nullptr)
                                return 0;

                            if (src->ref_source->get_source_uuid() != uptr->srcuuid)
                                return 0;

                            std::stringstream ss(json->json_string);
                            nlohmann::json device_json;

                            try {
                                ss >> device_json;

                                auto adsb_content = 
                                    fmt::format("*{};\n", device_json["adsb"].get<std::string>());

                                uptr->ws->write(adsb_content);
                            } catch (std::exception& e) {
                                return 0;
                            }

                            return 1;
                    }, uptr, CHAINPOS_LOGGING, 1000);

                ws->text();

                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ;
                }
            
                packetchain->remove_handler(raw_handler_id, CHAINPOS_LOGGING);
                delete uptr;
            }));

}

kis_adsb_phy::~kis_adsb_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

mac_addr kis_adsb_phy::icao_to_mac(uint32_t icao) {
    // Derive a mac addr from the model and device id data
    //
    // We turn the model string into 4 bytes using the adler32 checksum,
    // then we use the model as a (potentially) 16bit int
    //
    // Finally we set the locally assigned bit on the first octet
    
    uint8_t bytes[6];
    uint16_t *model = (uint16_t *) bytes;
    uint32_t *checksum = (uint32_t *) (bytes + 2);

    memset(bytes, 0, 6);

    std::string smodel = "unk";

    *model = icao;
    *checksum = adler32_checksum((const uint8_t *) &icao, 4);
  
    // Set the local bit
    bytes[0] |= 0x2;

    return mac_addr(bytes, 6);
}

bool kis_adsb_phy::process_adsb_hex(nlohmann::json& json, const std::shared_ptr<kis_packet>& packet) {
	auto hex_j = json["adsb"];
	
	if (hex_j.is_null() || !hex_j.is_string()) {
		hex_j = json["adsb_raw_msg"];
	}

	if (hex_j.is_null() || !hex_j.is_string()) {
        return false;
    }

    const std::string adsb_hex = hex_j.get<std::string>();
    std::string adsb_bin;

    try {
		if (adsb_hex[0] == '*') {
			adsb_bin = hex_to_bytes(adsb_hex.substr(1, adsb_hex.length() - 2));
		} else {
			adsb_bin = hex_to_bytes(adsb_hex);
		}
    } catch (...) {
        return false;
    }

    if (adsb_bin.length() == 0) {
        return false;
    }

    auto crc1 = adsb_msg_get_crc(adsb_bin);
    auto crc2 = modes_checksum(adsb_bin);

    if (crc1 != crc2) {
        return false;
    }

    auto icao = adsb_msg_get_icao(adsb_bin);
    auto icao_s = fmt::format("{:x}", icao & 0x00FFFFFF);
    auto msgtype = adsb_msg_get_type(adsb_bin);
    auto msgsize = adsb_msg_len_by_type(msgtype);

    if (msgsize / 8 > adsb_bin.length()) {
        return false;
    }

    std::string callsign;
    bool use_callsign = false;

    unsigned long altitude = 0;
    bool use_altitude = false;

    adsb_location location;
    bool use_location = false;

    double speed = 0;
    bool use_speed = 0;

    double heading = 0;
    bool use_heading = 0;

    if (msgtype == 17) {
        auto msgme = adsb_msg_get_me_type(adsb_bin);
        auto msgsubme = adsb_msg_get_me_subtype(adsb_bin);

        if (msgme >= 1 && msgme <= 4) {
            callsign = adsb_msg_get_flight(adsb_bin);
            use_callsign = true;
        } else if (msgme >= 9 && msgme <= 18) {
            altitude = adsb_msg_get_ac12_altitude(adsb_bin);
            use_altitude = true;

            adsb_msg_get_airborne_position(adsb_bin, location);
            use_location = true;
        } else if (msgme == 19 && (msgsubme >= 1 && msgsubme <= 4)) {
            altitude = adsb_msg_get_ac12_altitude(adsb_bin);
            use_altitude = true;

            if (msgsubme == 1 || msgsubme == 2) {
                speed = adsb_msg_get_airborne_velocity(adsb_bin);
                use_speed = true;

                if (adsb_msg_get_airborne_heading_valid(adsb_bin)) {
                    heading = adsb_msg_get_airborne_heading(adsb_bin);
                    use_heading = true;
                }
            } else if (msgsubme == 3 || msgsubme == 4) {
                if (adsb_msg_get_airborne_heading_valid(adsb_bin)) {
                    heading = adsb_msg_get_airborne_heading(adsb_bin);
                    use_heading = true;
                }
            }
        }
    } else if (msgtype == 0 || msgtype == 4 || msgtype == 16 || msgtype == 20) {
        altitude = adsb_msg_get_ac13_altitude(adsb_bin);
        use_altitude = true;
    }

    auto mac = icao_to_mac(icao);

    auto common = packet->fetch_or_add<kis_common_info>(pack_comp_common);

    common->type = packet_basic_data;
    common->phyid = fetch_phy_id();
    common->datasize = 0;

    common->freq_khz = 1090000;
    common->source = mac;
    common->transmitter = mac;

    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "adsb_raw");

    // Update the base dev without setting location, because we want to
    // override that location ourselves later once we've gotten our
    // adsb device and possibly merged packets
    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                 UCD_UPDATE_SEENBY), "ADSB");

    if (basedev == nullptr) {
        return 0;
    }

    auto dn = fmt::format("{}", icao_s);

    basedev->set_manuf(rtl_manuf);

    basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Airplane"));
    basedev->set_devicename(fmt::format("ADSB {}", dn));

    // Generate the adsb device record
    bool new_adsb = false;
    std::stringstream new_ss;

    auto adsbdev = 
        basedev->get_sub_as<adsb_tracked_adsb>(adsb_adsb_id);

    if (adsbdev == NULL) {
        adsbdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<adsb_tracked_adsb>(adsb_adsb_id);
        basedev->insert(adsbdev);
        new_adsb = true;

        new_ss << "Detected new ADSB device ICAO " << icao_s;
    }

    adsbdev->set_icao(icao_s);

    auto icao_record = icaodb->lookup_icao(icao_s);
    adsbdev->set_icao_record(icao_record);

    if (use_callsign) {
        auto raw_cs = callsign;

        std::string mangle_cs;

        for (size_t i = 0; i < raw_cs.length(); i++) {
            if (raw_cs[i] != '_') {
                mangle_cs += raw_cs[i];
            }
        }

        adsbdev->set_callsign(mangle_cs);
        if (adsbdev->get_callsign() != "")
            new_ss << adsbdev->get_callsign();
    }

    if (icao_record != icaodb->get_unknown_icao()) {
        new_ss << " " << icao_record->get_model();
        new_ss << " " << icao_record->get_model_type();
        new_ss << " " << icao_record->get_owner();
        new_ss << " " << icao_record->get_atype()->get();
    }

    if (use_altitude) {
        adsbdev->alt = (double) altitude * 0.3048;
        adsbdev->update_location = true;
    }

    if (use_speed) {
        adsbdev->speed = (double) speed * 1.60934;
        adsbdev->update_location = true;
    }

    if (use_heading) {
        adsbdev->heading = heading;
        adsbdev->update_location = true;
    }

    if (use_location) {
        bool calc_coords = false;

        if (location.even) {
            adsbdev->set_even_raw_lat(location.lat);
            adsbdev->set_even_raw_lon(location.lon);
            adsbdev->set_even_ts(time(0));

            if (adsbdev->get_even_ts() - adsbdev->get_odd_ts() < 10)
                calc_coords = true;

        } else {
            adsbdev->set_odd_raw_lat(location.lat);
            adsbdev->set_odd_raw_lon(location.lon);
            adsbdev->set_odd_ts(time(0));

            if (adsbdev->get_odd_ts() - adsbdev->get_even_ts() < 10)
                calc_coords = true;
        }

        if (calc_coords)
            decode_cpr(adsbdev, packet);
    }


    if (new_adsb) {
        _MSG_INFO("{}", new_ss.str());
    }

    if (icao_record != icaodb->get_unknown_icao()) {
        switch (icao_record->get_atype_short()) {
            case '1':
            case '7':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Glider"));
                break;
            case '2':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Balloon"));
                break;
            case '3':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Blimp"));
                break;
            case '4':
            case '5':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Airplane"));
                break;
            case '6':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Helicopter"));
                break;
            case '8':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Parachute"));
                break;
            case '9':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Gyroplane"));
                break;
            default:
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Aircraft"));
                break;
        }

        auto cs = adsbdev->get_callsign();
        if (cs.length() != 0)
            cs += " ";

        basedev->set_devicename(fmt::format("{} {} {}",
                    cs, icao_record->get_model_type(), icao_record->get_owner()));
    }

    if (adsbdev->update_location) {
        adsbdev->update_location = false;

        // Update the common device with location if we've got a location record now
        // We have to make a new component here, not fetch the existing one; otherwise we 
        // clobber the global gps record!
        auto gpsinfo = packetchain->new_packet_component<kis_gps_packinfo>();

        gpsinfo->lat = adsbdev->lat;
        gpsinfo->lon = adsbdev->lon;
        gpsinfo->speed = adsbdev->speed;
        gpsinfo->alt = adsbdev->alt;
        gpsinfo->heading = adsbdev->heading;

        if (adsbdev->alt != 0)
            gpsinfo->fix = 3;

        gpsinfo->tv = packet->ts;

        packet->insert(pack_comp_gps, gpsinfo);
        devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_LOCATION), "ADSB Transmitter");
    }

    return true;
}

bool kis_adsb_phy::json_to_rtl(nlohmann::json& json, const std::shared_ptr<kis_packet>& packet) {
    std::string err;
    std::string v;

    auto crc_j = json["crc_valid"];
    if (crc_j.is_boolean() && crc_j == false)
        return false;

    // synth a mac out of it
    mac_addr rtlmac;
    auto icao_j = json["icao"];
    if (icao_j.is_number()) {
        rtlmac = icao_to_mac(icao_j.get<uint32_t>());
    } else {
        return false;
    }

    auto common = packet->fetch_or_add<kis_common_info>(pack_comp_common);

    common->type = packet_basic_data;
    common->phyid = fetch_phy_id();
    common->datasize = 0;

    auto channel_j = json["channel"];
    if (channel_j.is_string())
        common->channel = channel_j;
    else if (channel_j.is_number())
        common->channel = fmt::format("{}", channel_j.get<int>());

    common->freq_khz = 1090000;
    common->source = rtlmac;
    common->transmitter = rtlmac;

    // Update the base dev without setting location, because we want to
    // override that location ourselves later once we've gotten our
    // adsb device and possibly merged packets
    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                 UCD_UPDATE_SEENBY), "ADSB");

    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "adsb_json_to_rtl");

    std::string dn = "Airplane";

    try {
        dn = json["icao"];
    } catch (...) { }

    basedev->set_manuf(rtl_manuf);

    basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Airplane"));
    basedev->set_devicename(fmt::format("ADSB {}", dn));

    std::shared_ptr<adsb_tracked_adsb> adsbdev;

    if (is_adsb(json))
        adsbdev = add_adsb(packet, json, basedev);

    if (adsbdev == nullptr)
        return false;

    auto icao = adsbdev->get_icao_record();

    if (icao != icaodb->get_unknown_icao()) {
        switch (icao->get_atype_short()) {
            case '1':
            case '7':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Glider"));
                break;
            case '2':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Balloon"));
                break;
            case '3':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Blimp"));
                break;
            case '4':
            case '5':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Airplane"));
                break;
            case '6':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Helicopter"));
                break;
            case '8':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Parachute"));
                break;
            case '9':
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Gyroplane"));
                break;
            default:
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Aircraft"));
                break;
        }

        auto cs = adsbdev->get_callsign();
        if (cs.length() != 0)
            cs += " ";

        basedev->set_devicename(fmt::format("{} {} {}",
                    cs, icao->get_model_type(), icao->get_owner()));
    }

    /*
    // Have to update location outside of locks because it needs to promote to exclusive locking
    //
    // No longer true, we do all work under exclusive lock.
    //
    lk_list.unlock();
    lk_device.unlock();
    */

    if (adsbdev->update_location) {
        adsbdev->update_location = false;

        // Update the common device with location if we've got a location record now
        auto gpsinfo = packet->fetch_or_add<kis_gps_packinfo>(pack_comp_gps);

        gpsinfo->lat = adsbdev->lat;
        gpsinfo->lon = adsbdev->lon;
        gpsinfo->speed = adsbdev->speed;
        gpsinfo->alt = adsbdev->alt;
        gpsinfo->heading = adsbdev->heading;

        if (adsbdev->alt != 0)
            gpsinfo->fix = 3;

        gettimeofday(&gpsinfo->tv, NULL);

        packet->insert(pack_comp_gps, gpsinfo);

        devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_LOCATION), "ADSB Transmitter");
    }

    return true;
}

bool kis_adsb_phy::is_adsb(nlohmann::json json) {

    //fprintf(stderr, "ADSB: checking to see if it is a adsb\n");
    auto icao_j = json["icao"];

    if (!icao_j.is_null()) {
        return true;
    }

    return false;
}

std::shared_ptr<adsb_tracked_adsb> kis_adsb_phy::add_adsb(const std::shared_ptr<kis_packet>& packet,
        nlohmann::json json, const std::shared_ptr<kis_tracked_device_base>& rtlholder) {

    auto icao_j = json["icao"];
    bool new_adsb = false;
    std::stringstream new_ss;

    if (!icao_j.is_null()) {
        auto adsbdev = 
            rtlholder->get_sub_as<adsb_tracked_adsb>(adsb_adsb_id);

        if (adsbdev == NULL) {
            adsbdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<adsb_tracked_adsb>(adsb_adsb_id);
            rtlholder->insert(adsbdev);
            new_adsb = true;

            new_ss << "Detected new ADSB device ICAO " << icao_j;
        }

        adsbdev->set_icao(icao_j);

        auto icao_record = icaodb->lookup_icao(icao_j.get<std::string>());
        adsbdev->set_icao_record(icao_record);

        auto callsign_j = json["callsign"];
        if (callsign_j.is_string()) {
            auto raw_cs = callsign_j.get<std::string>();

            std::string mangle_cs;

            for (size_t i = 0; i < raw_cs.length(); i++) {
                if (raw_cs[i] != '_') {
                    mangle_cs += raw_cs[i];
                }
            }

            adsbdev->set_callsign(mangle_cs);
            if (adsbdev->get_callsign() != "")
                new_ss << adsbdev->get_callsign();
        }

        if (icao_record != icaodb->get_unknown_icao()) {
            new_ss << " " << icao_record->get_model();
            new_ss << " " << icao_record->get_model_type();
            new_ss << " " << icao_record->get_owner();
            new_ss << " " << icao_record->get_atype()->get();
        }

        auto altitude_j = json["altitude"];
        if (altitude_j.is_number()) {
            adsbdev->alt = altitude_j.get<double>() * 0.3048;
            adsbdev->update_location = true;
        }

        auto speed_j = json["speed"];
        if (speed_j.is_number()) {
            adsbdev->speed = speed_j.get<double>() * 1.60934;
            adsbdev->update_location = true;
        }

        auto heading_j = json["heading"];
        if (heading_j.is_number()) {
            adsbdev->heading = heading_j.get<double>();
            adsbdev->update_location = true;
        }

        auto gsas_j = json["gsas"];
        if (gsas_j.is_string()) {
            adsbdev->set_gsas(gsas_j);
        }

        try {
            auto raw_lat = json["raw_lat"].get<double>();
            auto raw_lon = json["raw_lon"].get<double>();
            auto raw_even = json["coordpair_even"].get<bool>();
            bool calc_coords = false;

            if (raw_even) {
                adsbdev->set_even_raw_lat(raw_lat);
                adsbdev->set_even_raw_lon(raw_lon);
                adsbdev->set_even_ts(time(0));

                if (adsbdev->get_even_ts() - adsbdev->get_odd_ts() < 10)
                    calc_coords = true;

            } else {
                adsbdev->set_odd_raw_lat(raw_lat);
                adsbdev->set_odd_raw_lon(raw_lon);
                adsbdev->set_odd_ts(time(0));

                if (adsbdev->get_odd_ts() - adsbdev->get_even_ts() < 10)
                    calc_coords = true;
            }

            if (calc_coords)
                decode_cpr(adsbdev, packet);

        } catch (...) { }

        if (new_adsb) {
            _MSG_INFO("{}", new_ss.str());
        }
        
        return adsbdev;
    }

    return nullptr;
}

int kis_adsb_phy::packet_handler(CHAINCALL_PARMS) {
    kis_adsb_phy *adsb = (kis_adsb_phy *) auxdata;

    //fprintf(stderr, "ADSB: packethandler kicked in\n");

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto json = in_pack->fetch<kis_json_packinfo>(adsb->pack_comp_json);
    if (json == NULL)
        return 0;

    //std::fprintf(stderr, "ADSB: json type: %s\n", json->type.c_str());
    

    if (json->type != "adsb" && json->type != "RTLadsb")
        return 0;

    std::stringstream ss(json->json_string);
    nlohmann::json device_json;

    try {
        ss >> device_json;

        // Process raw ADSB, and then process parsed ADSB JSON
        if (adsb->process_adsb_hex(device_json, in_pack)) {
             auto adata = in_pack->fetch_or_add<packet_metablob>(adsb->pack_comp_meta);
             adata->set_data("ADSB", json->json_string);
        } else if (adsb->json_to_rtl(device_json, in_pack)) {
             auto adata = in_pack->fetch_or_add<packet_metablob>(adsb->pack_comp_meta);
             adata->set_data("ADSB", json->json_string);
        }
    } catch (std::exception& e) {
        fprintf(stderr, "debug - error processing json %s\n", e.what());
        return 0;
    }

    return 1;
}

// cpr_mod, _nl, _n, _dlon, and decode_cpr from the dump1090 project,
// Copyright (C) 2012 by Salvatore Sanfilippo <antirez@gmail.com>
// Modified minimally for C++ and use with our data structures
int kis_adsb_phy::cpr_mod(int a, int b) {
    // Force positive on MOD
    int res = a % b;

    if (res < 0)
        res += b;

    return res;
}

int kis_adsb_phy::cpr_nl(double lat) {
    // Precomputed table from 1090-WP-9-14
    //
    if (lat < 0) 
        lat = -lat;

    if (lat < 10.47047130) return 59;
    if (lat < 14.82817437) return 58;
    if (lat < 18.18626357) return 57;
    if (lat < 21.02939493) return 56;
    if (lat < 23.54504487) return 55;
    if (lat < 25.82924707) return 54;
    if (lat < 27.93898710) return 53;
    if (lat < 29.91135686) return 52;
    if (lat < 31.77209708) return 51;
    if (lat < 33.53993436) return 50;
    if (lat < 35.22899598) return 49;
    if (lat < 36.85025108) return 48;
    if (lat < 38.41241892) return 47;
    if (lat < 39.92256684) return 46;
    if (lat < 41.38651832) return 45;
    if (lat < 42.80914012) return 44;
    if (lat < 44.19454951) return 43;
    if (lat < 45.54626723) return 42;
    if (lat < 46.86733252) return 41;
    if (lat < 48.16039128) return 40;
    if (lat < 49.42776439) return 39;
    if (lat < 50.67150166) return 38;
    if (lat < 51.89342469) return 37;
    if (lat < 53.09516153) return 36;
    if (lat < 54.27817472) return 35;
    if (lat < 55.44378444) return 34;
    if (lat < 56.59318756) return 33;
    if (lat < 57.72747354) return 32;
    if (lat < 58.84763776) return 31;
    if (lat < 59.95459277) return 30;
    if (lat < 61.04917774) return 29;
    if (lat < 62.13216659) return 28;
    if (lat < 63.20427479) return 27;
    if (lat < 64.26616523) return 26;
    if (lat < 65.31845310) return 25;
    if (lat < 66.36171008) return 24;
    if (lat < 67.39646774) return 23;
    if (lat < 68.42322022) return 22;
    if (lat < 69.44242631) return 21;
    if (lat < 70.45451075) return 20;
    if (lat < 71.45986473) return 19;
    if (lat < 72.45884545) return 18;
    if (lat < 73.45177442) return 17;
    if (lat < 74.43893416) return 16;
    if (lat < 75.42056257) return 15;
    if (lat < 76.39684391) return 14;
    if (lat < 77.36789461) return 13;
    if (lat < 78.33374083) return 12;
    if (lat < 79.29428225) return 11;
    if (lat < 80.24923213) return 10;
    if (lat < 81.19801349) return 9;
    if (lat < 82.13956981) return 8;
    if (lat < 83.07199445) return 7;
    if (lat < 83.99173563) return 6;
    if (lat < 84.89166191) return 5;
    if (lat < 85.75541621) return 4;
    if (lat < 86.53536998) return 3;
    if (lat < 87.00000000) return 2;
    else return 1;
}

int kis_adsb_phy::cpr_n(double lat, int odd) {
    int nl = cpr_nl(lat) - odd;

    if (nl < 1)
        nl = 1;

    return nl;
}

double kis_adsb_phy::cpr_dlon(double lat, int odd) {
    return 360.0 / cpr_n(lat, odd);
}

void kis_adsb_phy::decode_cpr(const std::shared_ptr<adsb_tracked_adsb>& adsb,
        const std::shared_ptr<kis_packet>& packet) {
    /* This algorithm comes from:
     * http://www.lll.lu/~edward/edward/adsb/DecodingADSBposition.html.
     *
     *
     * A few remarks:
     * 1) 131072 is 2^17 since CPR latitude and longitude are encoded in 17 bits.
     * 2) We assume that we always received the odd packet as last packet for
     *    simplicity. This may provide a position that is less fresh of a few
     *    seconds.
     */

    const double dlat0 = 360.0 / 60;
    const double dlat1 = 360.0 / 59;

    double lat0 = adsb->get_even_raw_lat();
    double lat1 = adsb->get_odd_raw_lat();
    double lon0 = adsb->get_even_raw_lon();
    double lon1 = adsb->get_odd_raw_lon();

    int j = floor(((59 * lat0 - 60 * lat1) / 131072) + 0.5);

    double rlat0 = dlat0 * (cpr_mod(j, 60) + lat0 / 131072);
    double rlat1 = dlat1 * (cpr_mod(j, 59) + lat1 / 131072);

    if (rlat0 >= 270)
        rlat0 -= 360;

    if (rlat1 >= 270)
        rlat1 -= 360;

    // If they're not both in the same zone, fail
    if (cpr_nl(rlat0) != cpr_nl(rlat1))
        return;

    if (adsb->get_even_ts() > adsb->get_odd_ts()) {
        int ni = cpr_n(rlat0, 0);
        int m = floor((((lon0 * (cpr_nl(rlat0) - 1)) -
                        (lon1 * cpr_nl(rlat0))) / 131072) + 0.5);

        adsb->lon = cpr_dlon(rlat0, 0) * (cpr_mod(m, ni) + lon0 / 131072);
        adsb->lat = rlat0;
    } else {
        int ni = cpr_n(rlat1, 1);
        int m = floor((((lon0 * (cpr_nl(rlat1) - 1)) -
                        (lon1 * cpr_nl(rlat1))) / 131072.0) + 0.5);
        adsb->lon = cpr_dlon(rlat1, 1) * (cpr_mod(m, ni) + lon1 / 131072);
        adsb->lat = rlat1;
    }

    if (adsb->lon > 180)
        adsb->lon -= 360;

    adsb->update_location = true;
}

std::shared_ptr<tracker_element> 
kis_adsb_phy::adsb_map_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    auto ret_map = std::make_shared<tracker_element_map>();
    auto adsb_view = devicetracker->get_phy_view(phyid);

    if (adsb_view == nullptr) {
        auto error = 
            Globalreg::globalreg->entrytracker->register_and_get_field_as<tracker_element_string>(
                    "kismet.common.error",
                    tracker_element_factory<tracker_element_string>(),
                    "Device error");
        error->set("PHY view tracking disabled or no ADSB devices seen");
        ret_map->insert(error);
        return ret_map;
    }

    auto min_lat = std::make_shared<tracker_element_double>(map_min_lat_id);
    auto min_lon = std::make_shared<tracker_element_double>(map_min_lon_id);
    auto max_lat = std::make_shared<tracker_element_double>(map_max_lat_id);
    auto max_lon = std::make_shared<tracker_element_double>(map_max_lon_id);

    ret_map->insert(min_lat);
    ret_map->insert(min_lon);
    ret_map->insert(max_lat);
    ret_map->insert(max_lon);

    auto recent_devs = std::make_shared<tracker_element_vector>(map_recent_devs_id);
    ret_map->insert(recent_devs);

    auto now = time(0);

    kis_mutex response_mutex;

    // Find all devices active w/in the last 10 minutes, and set their bounding box
    auto recent_worker = 
        device_tracker_view_function_worker([this, now, recent_devs, min_lat, 
                min_lon, max_lat, max_lon, &response_mutex](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
            auto adsbdev = 
                dev->get_sub_as<adsb_tracked_adsb>(adsb_adsb_id);
 
            if (adsbdev == nullptr) {
                return false;
            }

            if (dev->get_last_time() < now - (60 * 10)) {
                return false;
            }

            kis_lock_guard<kis_mutex> lk(response_mutex);

            recent_devs->push_back(dev);

            auto loc = dev->get_tracker_location();

            if (loc != nullptr) {
                auto last_loc = loc->get_last_loc();

                if (last_loc != nullptr && last_loc->get_lat() != 0 &&
                        last_loc->get_lon() != 0) {
                    if (last_loc->get_lat() < min_lat->get() || min_lat->get() == 0)
                        min_lat->set(last_loc->get_lat());
                    if (last_loc->get_lon() < min_lon->get() || min_lon->get() == 0)
                        min_lon->set(last_loc->get_lon());

                    if (last_loc->get_lat() > max_lat->get() || max_lat->get() == 0)
                        max_lat->set(last_loc->get_lat());
                    if (last_loc->get_lon() > max_lon->get() || max_lon->get() == 0)
                        max_lon->set(last_loc->get_lon());
                }
            }

            return false;
        });

    adsb_view->do_readonly_device_work(recent_worker);

    return ret_map;
}

size_t kis_adsb_phy::adsb_msg_len_by_type(uint8_t type) {
    switch (type) {
        case 16:
        case 7:
        case 19:
        case 20:
        case 21:
            return 112; 
            break; 
        default:
            return 56;
    }

    return 56;
}

uint32_t kis_adsb_phy::adsb_msg_get_crc(const std::string& u8_buf) {
    if (u8_buf.size() < 7)
        return 0; 

    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());

    uint32_t crc = 0;
    auto len = u8_buf.size(); 

    crc = buf[len - 3] << 16; 
    crc |= buf[len - 2] << 8;
    crc |= buf[len - 1];

    return crc & 0x00FFFFFF;
}

uint8_t kis_adsb_phy::adsb_msg_get_type(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    return buf[0] >> 3;
}

uint32_t kis_adsb_phy::adsb_msg_get_icao(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    uint32_t icao = 0; 

    icao |= buf[1] << 16;     
    icao |= buf[2] << 8;      
    icao |= buf[3];

    return icao;
}

uint8_t kis_adsb_phy::adsb_msg_get_fs(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    return buf[0] & 7;
}

uint8_t kis_adsb_phy::adsb_msg_get_me_type(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    return buf[4] >> 3;
}

uint8_t kis_adsb_phy::adsb_msg_get_me_subtype(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    return buf[4] & 7;
}

int kis_adsb_phy::adsb_msg_get_ac13_altitude(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    int m_bit = buf[3] & (1 << 6);
    int q_bit = buf[3] & (1 << 4);

    if (!m_bit) {
        if (q_bit) {
            int n = (buf[2] & 31) << 6;
            n |= (buf[3] & 0x80) >> 2;
            n |= (buf[3] & 0x20) >> 1;
            n |= (buf[3] & 0x15);

            return n * 25 - 1000;
        }
    }

    return 0;
}

int kis_adsb_phy::adsb_msg_get_ac12_altitude(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    int q_bit = buf[5] & 1;
    int n = 0;

    if (q_bit) {
        // Extract the 11bit integer after removing bit 0
        n = (buf[5] >> 1) << 4;
        n |= (buf[6] & 0xF0) >> 4;

        return n * 25 - 1000;
    }

    return 0;
}

std::string kis_adsb_phy::adsb_msg_get_flight(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    std::string ais_charset = "?ABCDEFGHIJKLMNOPQRSTUVWXYZ????? ???????????????0123456789??????";

    std::ostringstream flight;

    flight << ais_charset[buf[5] >> 2];
    flight << ais_charset[((buf[5] & 3) << 4) | (buf[6] >> 4)];
    flight << ais_charset[((buf[6] & 15) << 2) | (buf[7] >> 6)];
    flight << ais_charset[buf[7] & 63];
    flight << ais_charset[buf[8] >> 2];
    flight << ais_charset[((buf[8] & 3) << 4) | (buf[9] >> 4)];
    flight << ais_charset[((buf[9] & 15) << 2) | (buf[10] >> 6)];
    flight << ais_charset[buf[10] & 63];

    return flight.str();
}

void kis_adsb_phy::adsb_msg_get_airborne_position(const std::string& u8_buf, kis_adsb_phy::adsb_location_t &ret) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    // Decode the airborne position from message 17             
    
    int even = (buf[6] & (1 << 2)) == 0;                    

    int lat = 0;                                           
    lat = (buf[6] & 3) << 15;                                   
    lat |= buf[7] << 7;                                         
    lat |= buf[8] >> 1;                                         

    int lon = 0;                                           
    lon = (buf[8] & 1) << 16;                                   
    lon |= buf[9] << 8;                                         
    lon |= buf[10];                                             

    ret.even = even;
    ret.lat = lat;
    ret.lon = lon;

}

double kis_adsb_phy::adsb_msg_get_airborne_velocity(const std::string& u8_buf) const {
    // Get airborne velocity from message 17
    // Synthesized from the EW/NS velocities
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());

    // int ew_dir = (buf[5] & 4) >> 2;
    int ew_velocity = ((buf[5] & 3) << 8) | buf[6];
    // int ns_dir = (buf[7] & 0x80) >> 7;
    int ns_velocity = ((buf[7] & 0x7f) << 3) | ((buf[8] & 0xe0) >> 5);

    double velocity = sqrt(ns_velocity * ns_velocity + ew_velocity * ew_velocity);

    return velocity;
}

bool kis_adsb_phy::adsb_msg_get_airborne_heading_valid(const std::string& u8_buf) const {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    return buf[5] & (1 << 2);
}

double kis_adsb_phy::adsb_msg_get_airborne_heading(const std::string& u8_buf) const {
    // Airborne heading from message 17 
    // Synthesized from EW/NS headings
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());

    int ew_dir = (buf[5] & 4) >> 2;
    int ew_velocity = ((buf[5] & 3) << 8) | buf[6];
    int ns_dir = (buf[7] & 0x80) >> 7;
    int ns_velocity = ((buf[7] & 0x7f) << 3) | ((buf[8] & 0xe0) >> 5);

    if (ew_dir)
        ew_velocity *= -1;
    
    if (ns_dir)
        ns_velocity *= -1;
    
    double heading = atan2(ew_velocity, ns_velocity);

    heading = heading * 360 / (M_PI * 2);
    
    if (heading < 0)
        heading += 360;
    
    return heading;
}

double kis_adsb_phy::adsb_msg_get_sub3_heading(const std::string& u8_buf) const {
    // Direct heading from msg17 sub3 and sub4
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
       
    if (!(buf[5] & (1 << 2)))
        return -1;

    int iheading = (buf[5] & 3) << 5;
    iheading |= buf[6] >> 3;
    double heading = iheading * (double) (360.0 / 128);

    if (heading < 0)
        heading += 360;

    return heading;

}

uint32_t kis_adsb_phy::modes_checksum(const std::string& u8_buf) {
    auto buf = reinterpret_cast<const uint8_t *>(u8_buf.data());
    uint32_t crc = 0;
    size_t offset = 0; 

    if (u8_buf.size() < 7)
        return 0; 

    if (u8_buf.size() != 14) 
        offset = 112 - 56;

    for (unsigned int j = 0; j < u8_buf.size() * 8; j++) {
        uint8_t b = j / 8;
        uint8_t bit = j % 8;
        uint8_t mask = 1 << (7 - bit);

        if (buf[b] & mask) {
            crc ^= modes_checksum_table[j + offset];
        }
    }

    return (crc & 0x00FFFFFF);
}




