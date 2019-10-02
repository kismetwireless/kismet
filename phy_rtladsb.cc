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
#include "kismet_json.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "manuf.h"

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

    rtladsb_holder_id =
        Globalreg::globalreg->entrytracker->register_field("rtladsb.device", 
                tracker_element_factory<tracker_element_map>(),
                "rtl_adsb device");

    rtladsb_common_id =
        Globalreg::globalreg->entrytracker->register_field("rtladsb.device.common",
                tracker_element_factory<rtladsb_tracked_common>(),
                "Common RTLADSB device info");

    rtladsb_adsb_id =
        Globalreg::globalreg->entrytracker->register_field("rtladsb.device.adsb",
                tracker_element_factory<rtladsb_tracked_adsb>(),
                "RTLADSB adsb");

    // Make the manuf string
    rtl_manuf = Globalreg::globalreg->manufdb->MakeManuf("RTLADSB");

    // Register js module for UI
    auto httpregistry =
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_rtladsb", "js/kismet.ui.rtladsb.js");

	packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    adsb_map_endp = 
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>(
                "/phy/RTLADSB/map_data", 
                [this]() -> std::shared_ptr<tracker_element> {
                    return adsb_map_endp_handler();
                });
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
	    //*model = i.asString();
	    std::string icaotmp = i.asString();
	    int icaoint = std::stoi(icaotmp, 0, 16);
            *model = kis_hton16((uint16_t) icaoint);
            set_model = true;
        }
    }
  
    /* if (!set_model && json.isMember("device")) {
        Json::Value d = json["device"];
        if (d.isNumeric()) {
            *model = kis_hton16((uint16_t) d.asUInt());
            set_model = true;
        }
    } */

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

    if (rtlmac.error) {
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

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "RTLADSB Sensor");

    local_locker bssidlock(&(basedev->device_mutex));

    std::string dn = "Airplane";

    auto icao_j = json["icao"];
    if (icao_j.isString()) {
        dn = icao_j.asString();
    }

    basedev->set_manuf(rtl_manuf);

    basedev->set_type_string("Airplane");
    basedev->set_devicename(fmt::format("ADSB {}", dn));

    auto rtlholder = basedev->get_sub_as<tracker_element_map>(rtladsb_holder_id);
    bool newrtl = false;

    if (rtlholder == NULL) {
        rtlholder =
            std::make_shared<tracker_element_map>(rtladsb_holder_id);
        basedev->insert(rtlholder);
        newrtl = true;
    }

    auto commondev =
        rtlholder->get_sub_as<rtladsb_tracked_common>(rtladsb_common_id);

    if (commondev == NULL) {
        commondev =
            std::make_shared<rtladsb_tracked_common>(rtladsb_common_id);
        rtlholder->insert(commondev);

        commondev->set_model(dn);

        bool set_id = false;
        //std::fprintf(stderr, "RTLADSB: ID? %d\n", json["Message"]["ID"]);
        //std::fprintf(stderr, "RTLADSB: Detected Message\n");
        if (json.isMember("icao")) {
            //std::fprintf(stderr, "RTLADSB: ID Detected\n");
            //Json::Value id_j = json["icao"];
	    auto icao_j = json["icao"];
            //std::fprintf(stderr, "RTLADSB: ID? %d\n", id_j);
            if (icao_j.isString()) {
                commondev->set_rtlid(icao_j.asString());
                set_id = true;
            }
        }

        if (!set_id) {
            commondev->set_rtlid("");
        }

        commondev->set_rtlchannel("0");
    }

    if (json.isMember("channel")) {
        auto channel_j = json["channel"];

        if (channel_j.isNumeric())
            commondev->set_rtlchannel(int_to_string(channel_j.asInt()));
        else if (channel_j.isString())
            commondev->set_rtlchannel(munge_to_printable(channel_j.asString()));
    }

    std::shared_ptr<rtladsb_tracked_adsb> adsbdev;
    if (is_adsb(json))
        adsbdev = add_adsb(json, rtlholder);

    if (adsbdev != nullptr) {
        std::stringstream ss;
        bool need_space = false;

        if (adsbdev->get_atype() != "") {
            ss << adsbdev->get_atype();
            need_space = true;

            if (adsbdev->get_callsign() != "") {
                if (need_space) ss << " ";
                ss << adsbdev->get_callsign();
                need_space = true;

                if (adsbdev->get_aoperator() != "") {
                    if (need_space) ss << " ";
                    ss << adsbdev->get_aoperator();
                    need_space = true;
                }

                basedev->set_devicename(ss.str());
            } else if (adsbdev->get_regid() != "") {
                if (need_space) ss << " ";
                ss << adsbdev->get_regid();
                need_space = true;

                if (adsbdev->get_aoperator() != "") {
                    if (need_space) ss << " ";
                    ss << adsbdev->get_aoperator();
                    need_space = true;
                }

            }

            basedev->set_devicename(ss.str());
        }
    }

    if (newrtl && commondev != NULL) {
        std::string info = "Detected new RTLADSB RF device '" + basedev->get_devicename() + "' model '" + commondev->get_model() + "'";

        if (commondev->get_rtlid() != "") 
            info += " ID " + commondev->get_rtlid();

        if (commondev->get_rtlchannel() != "0")
            info += " Channel " + commondev->get_rtlchannel();

        _MSG(info, MSGFLAG_INFO);
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

std::shared_ptr<rtladsb_tracked_adsb> kis_rtladsb_phy::add_adsb(Json::Value json, std::shared_ptr<tracker_element_map> rtlholder) {
    auto icao_j = json["icao"];

    if (!icao_j.isNull()) {
        //fprintf(stderr, "RTLADSB: Detected new adsb\n");
        auto adsbdev = 
            rtlholder->get_sub_as<rtladsb_tracked_adsb>(rtladsb_adsb_id);

        if (adsbdev == NULL) {
            adsbdev = 
                std::make_shared<rtladsb_tracked_adsb>(rtladsb_adsb_id);
            rtlholder->insert(adsbdev);
        }

        adsbdev->set_icao(icao_j.asString());
	
        if (json.isMember("regid")) {
            auto regid_j = json["regid"];
            if (regid_j.isString()) {
                adsbdev->set_regid(regid_j.asString());
            }
        }

        if (json.isMember("mdl")) {
            auto mdl_j = json["mdl"];
            if (mdl_j.isString()) {
                adsbdev->set_mdl(mdl_j.asString());
            }
        }

        if (json.isMember("type")) {
            auto type_j = json["type"];
            if (type_j.isString()) {
                adsbdev->set_atype(type_j.asString());
            }
        }

        if (json.isMember("operator")) {
            auto operator_j = json["operator"];
            if (operator_j.isString()) {
                adsbdev->set_aoperator(operator_j.asString());
            }
        }

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
            }
        }

        if (json.isMember("altitude")) {
            auto altitude_j = json["altitude"];
            if (altitude_j.isDouble()) {
                adsbdev->set_altitude(altitude_j.asDouble());
            }
        }

        if (json.isMember("speed")) {
            auto speed_j = json["speed"];
            if (speed_j.isDouble()) {
                adsbdev->set_speed(speed_j.asDouble());
            }
        }

        if (json.isMember("heading")) {
            auto heading_j = json["heading"];
            if (heading_j.isDouble()) {
                adsbdev->set_heading(heading_j.asDouble());
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
                decode_cpr(adsbdev);
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

        //std::fprintf(stderr, "RTLADSB: json? %s\n", json->json_string.c_str());
        //std::fprintf(stderr, "RTLADSB: json? %s\n", device_json);
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

void kis_rtladsb_phy::decode_cpr(std::shared_ptr<rtladsb_tracked_adsb> adsb) {
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
        adsb->set_longitude(cpr_dlon(rlat0, 0) * (cpr_mod(m, ni) + lon0 / 131072));
        adsb->set_latitude(rlat0);
    } else {
        int ni = cpr_n(rlat1, 1);
        int m = floor((((lon0 * (cpr_nl(rlat1) - 1)) -
                        (lon1 * cpr_nl(rlat1))) / 131072.0) + 0.5);
        adsb->set_longitude(cpr_dlon(rlat1, 1) * (cpr_mod(m, ni) + lon1 / 131072));
        adsb->set_latitude(rlat1);
    }

    if (adsb->get_longitude() > 180)
        adsb->set_longitude(adsb->get_longitude() - 360);

    // fmt::print(stderr, "adsb got lat {} lon {} raw {},{} {},{}\n", adsb->get_latitude(), adsb->get_longitude(), adsb->get_odd_raw_lat(), adsb->get_odd_raw_lon(), adsb->get_even_raw_lat(), adsb->get_even_raw_lon());
}

std::shared_ptr<tracker_element> kis_rtladsb_phy::adsb_map_endp_handler() {
    auto ret_map = std::make_shared<tracker_element_map>();
    auto adsb_view = devicetracker->get_phy_view(phyid);

    if (adsb_view == nullptr) {
        auto error = std::make_shared<tracker_element_string>("PHY view tracking disabled or no ADSB devices seen.");
        error->set_local_name("kismet.common.error");
        ret_map->insert(error);
        return ret_map;
    }

    auto min_lat = std::make_shared<tracker_element_double>();
    auto min_lon = std::make_shared<tracker_element_double>();
    auto max_lat = std::make_shared<tracker_element_double>();
    auto max_lon = std::make_shared<tracker_element_double>();

    min_lat->set_local_name("kismet.adsb.map.min_lat");
    min_lon->set_local_name("kismet.adsb.map.min_lon");
    max_lat->set_local_name("kismet.adsb.map.max_lat");
    max_lon->set_local_name("kismet.adsb.map.max_lon");

    ret_map->insert(min_lat);
    ret_map->insert(min_lon);
    ret_map->insert(max_lat);
    ret_map->insert(max_lon);

    

    return ret_map;
}


