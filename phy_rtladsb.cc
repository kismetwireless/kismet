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

#include "phy_rtladsb.h"
#include "devicetracker.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "manuf.h"
#include "messagebus.h"

kis_rtladsb_phy::kis_rtladsb_phy(global_registry *in_globalreg, int in_phyid) :
    kis_phy_handler(in_globalreg, in_phyid) {

    set_phy_name("RTLADSB");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

	pack_comp_common = 
        packetchain->register_packet_component("COMMON");
    pack_comp_json = 
        packetchain->register_packet_component("JSON");
    pack_comp_meta =
        packetchain->register_packet_component("METABLOB");
	pack_comp_gps =
        packetchain->register_packet_component("GPS");

    rtladsb_adsb_id =
        Globalreg::globalreg->entrytracker->register_field("rtladsb.device",
                tracker_element_factory<rtladsb_tracked_adsb>(),
                "RTLADSB adsb");


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
    rtl_manuf = Globalreg::globalreg->manufdb->make_manuf("RTLADSB");

    // Register js module for UI
    auto httpregistry =
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_rtladsb", "js/kismet.ui.rtladsb.js");

	packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    icaodb = std::make_shared<kis_adsb_icao>();

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/phy/RTLADSB/map_data", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return adsb_map_endp_handler(con);
                }));

    httpd->register_websocket_route("/phy/RTLADSB/beast", httpd->RO_ROLE, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                auto ws = 
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            boost::beast::flat_buffer& buf, bool text) {
                            // Do nothing on input
                        });

                auto beast_handler_id = 
                    packetchain->register_handler(
                            [this, ws](kis_packet *in_pack) -> int {

                            if (in_pack->error || in_pack->filtered || in_pack->duplicate)
                                return 0;

                            kis_json_packinfo *json = in_pack->fetch<kis_json_packinfo>(pack_comp_json);
                            
                            if (json == NULL)
                                return 0;

                            if (json->type != "RTLadsb")
                                return 0;

                            std::stringstream ss(json->json_string);
                            Json::Value device_json;

                            try {
                                ss >> device_json;

                                auto adsb_content = hex_to_bytes(device_json["adsb_raw_msg"].asString());

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

                                ws->write(std::string(buf, sizeof(adsb_beast_frame) + adsb_content.size()), false);

                                delete[] buf;

                            } catch (std::exception& e) {
                                return 0;
                            }


                            return 1;
                    }, CHAINPOS_LOGGING, 1000);

                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ;
                }
            
                packetchain->remove_handler(beast_handler_id, CHAINPOS_LOGGING);
            }));

    httpd->register_websocket_route("/phy/RTLADSB/raw", httpd->RO_ROLE, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                auto ws = 
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            boost::beast::flat_buffer& buf, bool text) {
                            // Do nothing on input
                        });

                auto beast_handler_id = 
                    packetchain->register_handler(
                            [this, ws](kis_packet *in_pack) -> int {

                            if (in_pack->error || in_pack->filtered || in_pack->duplicate)
                                return 0;

                            kis_json_packinfo *json = in_pack->fetch<kis_json_packinfo>(pack_comp_json);
                            
                            if (json == NULL)
                                return 0;

                            if (json->type != "RTLadsb")
                                return 0;

                            std::stringstream ss(json->json_string);
                            Json::Value device_json;

                            try {
                                ss >> device_json;

                                auto adsb_content = 
                                    fmt::format("*{};\n", device_json["adsb_raw_msg"].asString());

                                ws->write(adsb_content, true);
                            } catch (std::exception& e) {
                                return 0;
                            }


                            return 1;
                    }, CHAINPOS_LOGGING, 1000);

                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ;
                }
            
                packetchain->remove_handler(beast_handler_id, CHAINPOS_LOGGING);
            }));

}

kis_rtladsb_phy::~kis_rtladsb_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

mac_addr kis_rtladsb_phy::json_to_mac(Json::Value json) {
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

    if (json.isMember("icao")) {
        Json::Value m = json["icao"];
        if (m.isString()) {
            smodel = m.asString();
        }
    }

    *checksum = adler32_checksum(smodel.c_str(), smodel.length());

    bool set_model = false;

    if (json.isMember("icao")) {
        Json::Value i = json["icao"];
        if (i.isString()) {
	    std::string icaotmp = i.asString();
	    int icaoint = std::stoi(icaotmp, 0, 16);
            *model = kis_hton16((uint16_t) icaoint);
            set_model = true;
        }
    }
  
    if (!set_model) {
        *model = 0x0000;
    }

    // Set the local bit
    bytes[0] |= 0x2;

    return mac_addr(bytes, 6);
}

bool kis_rtladsb_phy::json_to_rtl(Json::Value json, kis_packet *packet) {
    std::string err;
    std::string v;

    if (json.isMember("crc_valid")) {
        if (!json["crc_valid"].asBool()) {
            return false;
        }
    }


    // synth a mac out of it
    mac_addr rtlmac = json_to_mac(json);

    if (rtlmac.state.error) {
        return false;
    }

    kis_common_info *common = 
        (kis_common_info *) packet->fetch(pack_comp_common);

    if (common == NULL) {
        common = new kis_common_info;
        packet->insert(pack_comp_common, common);
    }

    common->type = packet_basic_data;
    common->phyid = fetch_phy_id();
    common->datasize = 0;

    // If this json record has a channel
    if (json.isMember("channel")) {
        Json::Value c = json["channel"];
        if (c.isNumeric()) {
            common->channel = int_to_string(c.asInt());
        } else if (c.isString()) {
            common->channel = munge_to_printable(c.asString());
        }
    }

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

    auto devlocker = devicelist_range_scope_locker(devicetracker, basedev);

    std::string dn = "Airplane";

    auto icao_j = json["icao"];
    if (icao_j.isString()) {
        dn = icao_j.asString();
    }

    basedev->set_manuf(rtl_manuf);

    basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Airplane"));
    basedev->set_devicename(fmt::format("ADSB {}", dn));

    std::shared_ptr<rtladsb_tracked_adsb> adsbdev;

    if (is_adsb(json))
        adsbdev = add_adsb(packet, json, basedev);

    if (adsbdev != nullptr) {
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
    }

    if (adsbdev->update_location) {
        adsbdev->update_location = false;

        // Update the common device with location if we've got a location record now
        auto gpsinfo = new kis_gps_packinfo();

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
                (UCD_UPDATE_LOCATION), "RTLADSB Transmitter");
    }

    return true;
}

bool kis_rtladsb_phy::is_adsb(Json::Value json) {

    //fprintf(stderr, "RTLADSB: checking to see if it is a adsb\n");
    auto icao_j = json["icao"];

    if (!icao_j.isNull()) {
        return true;
    }

    return false;
}

std::shared_ptr<rtladsb_tracked_adsb> kis_rtladsb_phy::add_adsb(kis_packet *packet,
        Json::Value json, std::shared_ptr<kis_tracked_device_base> rtlholder) {
    auto icao_j = json["icao"];
    bool new_adsb = false;
    std::stringstream new_ss;

    if (!icao_j.isNull()) {
        auto adsbdev = 
            rtlholder->get_sub_as<rtladsb_tracked_adsb>(rtladsb_adsb_id);

        if (adsbdev == NULL) {
            adsbdev = 
                std::make_shared<rtladsb_tracked_adsb>(rtladsb_adsb_id);
            rtlholder->insert(adsbdev);
            new_adsb = true;

            new_ss << "Detected new ADSB device ICAO " << icao_j.asString();
        }

        adsbdev->set_icao(icao_j.asString());

        auto icao_record = icaodb->lookup_icao(icao_j.asString());
        adsbdev->set_icao_record(icao_record);

        if (json.isMember("callsign")) {
            auto callsign_j = json["callsign"];
            if (callsign_j.isString()) {
                auto raw_cs = callsign_j.asString();

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
        }

        if (icao_record != icaodb->get_unknown_icao()) {
            new_ss << " " << icao_record->get_model();
            new_ss << " " << icao_record->get_model_type();
            new_ss << " " << icao_record->get_owner();
            new_ss << " " << icao_record->get_atype()->get();
        }

        if (json.isMember("altitude")) {
            auto altitude_j = json["altitude"];
            if (altitude_j.isDouble()) {
                adsbdev->alt = altitude_j.asDouble() * 0.3048;
                adsbdev->update_location = true;
            }
        }

        if (json.isMember("speed")) {
            auto speed_j = json["speed"];
            if (speed_j.isDouble()) {
                adsbdev->speed = speed_j.asDouble() * 1.60934;
                adsbdev->update_location = true;
            }
        }

        if (json.isMember("heading")) {
            auto heading_j = json["heading"];
            if (heading_j.isDouble()) {
                adsbdev->heading = heading_j.asDouble();
                adsbdev->update_location = true;
            }
        }

        if (json.isMember("gsas")) {
            auto gsas_j = json["gsas"];
            if (gsas_j.isString()) {
                adsbdev->set_gsas(gsas_j.asString());
            }
        }

        if (json.isMember("raw_lat") && json.isMember("raw_lon") &&
                json.isMember("coordpair_even")) {
            auto raw_lat = json["raw_lat"].asDouble();
            auto raw_lon = json["raw_lon"].asDouble();
            auto raw_even = json["coordpair_even"].asBool();
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
        }

        if (new_adsb) {
            _MSG_INFO("{}", new_ss.str());
        }
        
        return adsbdev;
    }

    return nullptr;
}

int kis_rtladsb_phy::packet_handler(CHAINCALL_PARMS) {
    kis_rtladsb_phy *rtladsb = (kis_rtladsb_phy *) auxdata;

    //fprintf(stderr, "RTLADSB: packethandler kicked in\n");

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    kis_json_packinfo *json = in_pack->fetch<kis_json_packinfo>(rtladsb->pack_comp_json);
    if (json == NULL)
        return 0;

    //std::fprintf(stderr, "RTLADSB: json type: %s\n", json->type.c_str());
    

    if (json->type != "RTLadsb")
        return 0;

    std::stringstream ss(json->json_string);
    Json::Value device_json;

    try {
        ss >> device_json;

        // Copy the JSON as the meta field for logging, if it's valid
        if (rtladsb->json_to_rtl(device_json, in_pack)) {
            packet_metablob *metablob = in_pack->fetch<packet_metablob>(rtladsb->pack_comp_meta);
            if (metablob == NULL) {
                metablob = new packet_metablob("RTLADSB", json->json_string);
                in_pack->insert(rtladsb->pack_comp_meta, metablob);
            }
        }
    } catch (std::exception& e) {
        fprintf(stderr, "debug - error processing rtl json %s\n", e.what());
        return 0;
    }

    return 1;
}

// cpr_mod, _nl, _n, _dlon, and decode_cpr from the dump1090 project,
// Copyright (C) 2012 by Salvatore Sanfilippo <antirez@gmail.com>
// Modified minimally for C++ and use with our data structures
int kis_rtladsb_phy::cpr_mod(int a, int b) {
    // Force positive on MOD
    int res = a % b;

    if (res < 0)
        res += b;

    return res;
}

int kis_rtladsb_phy::cpr_nl(double lat) {
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

int kis_rtladsb_phy::cpr_n(double lat, int odd) {
    int nl = cpr_nl(lat) - odd;

    if (nl < 1)
        nl = 1;

    return nl;
}

double kis_rtladsb_phy::cpr_dlon(double lat, int odd) {
    return 360.0 / cpr_n(lat, odd);
}

void kis_rtladsb_phy::decode_cpr(std::shared_ptr<rtladsb_tracked_adsb> adsb,
        kis_packet *packet) {
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
kis_rtladsb_phy::adsb_map_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
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

    kis_recursive_timed_mutex response_mutex;

    // Find all devices active w/in the last 10 minutes, and set their bounding box
    auto recent_worker = 
        device_tracker_view_function_worker([this, now, recent_devs, min_lat, 
                min_lon, max_lat, max_lon, &response_mutex](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
            auto adsbdev = 
                dev->get_sub_as<rtladsb_tracked_adsb>(rtladsb_adsb_id);
 
            if (adsbdev == nullptr) {
                return false;
            }

            if (dev->get_last_time() < now - (60 * 10)) {
                return false;
            }

            local_locker l(&response_mutex);

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


