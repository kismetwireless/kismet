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

#include <cmath>

#include "devicetracker.h"
#include "kis_httpd_registry.h"
#include "manuf.h"
#include "messagebus.h"
#include "phy_80211.h"
#include "phy_uav_drone.h"

void uav_manuf_match::set_uav_manuf_ssid_regex(const std::string& in_regexstr) {
#if defined(HAVE_LIBPCRE1)
    const char *compile_error, *study_error;
    int erroroffset;
    std::ostringstream errordesc;

    re = pcre_compile(in_regexstr.c_str(), 0, &compile_error, &erroroffset, NULL);

    if (re == NULL) {
        errordesc << "Could not parse PCRE expression: " << compile_error << 
            "at character " << erroroffset << " (" << in_regexstr.substr(erroroffset, 5) <<
            ")";
        throw std::runtime_error(errordesc.str());
    }

    study = pcre_study(re, 0, &study_error);
    
    if (study_error != NULL) {
        errordesc << "Could not parse PCRE expression, optimization failure: " << study_error;
        throw std::runtime_error(errordesc.str());
    }
#elif defined(HAVE_LIBPCRE2)
    PCRE2_SIZE erroroffset;
    int errornumber;

    re = NULL;
    match_data = NULL;

    re = pcre2_compile((PCRE2_SPTR8) in_regexstr.c_str(),
       PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);

    if (re == nullptr) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        const auto e = fmt::format("Could not parse PCRE regex: {} at {}",
                (int) erroroffset, (char *) buffer);
        throw std::runtime_error(e);
    }

	match_data = pcre2_match_data_create_from_pattern(re, NULL);
#else
    throw std::runtime_error("Cannot set PCRE match for SSID; Kismet was not compiled with PCRE "
            "support");
#endif

    uav_manuf_ssid_regex->set(in_regexstr);
}

bool uav_manuf_match::match_record(const mac_addr& in_mac, const std::string& in_ssid) {
    if (get_uav_manuf_mac().longmac != 0) {
        if (get_uav_manuf_mac() == in_mac) {
            if (get_uav_manuf_partial() || get_uav_manuf_ssid_regex() == "")
                return true;
        } else {
            return false;
        }
    }

#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
    int r;
#if defined(HAVE_LIBPCRE1)
    int ovector[128];

    r = pcre_exec(re, study, in_ssid.c_str(), in_ssid.length(), 0, 0, ovector, 128);
#elif defined(HAVE_LIBPCRE2)
    r = pcre2_match(re, (PCRE2_SPTR8) in_ssid.c_str(), in_ssid.length(), 
            0, 0, match_data, NULL);
#endif

    if (r >= 0)
        return true;
#endif

    return false;
}


kis_uav_phy::kis_uav_phy(int in_phyid) :
    kis_phy_handler(in_phyid) { 

    phyname = "UAV";

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

	pack_comp_common = 
		packetchain->register_packet_component("COMMON");
    pack_comp_80211 =
        packetchain->register_packet_component("PHY80211");
    pack_comp_device =
        packetchain->register_packet_component("DEVICE");
    pack_comp_json = 
        packetchain->register_packet_component("JSON");
    pack_comp_meta =
        packetchain->register_packet_component("METABLOB");
	pack_comp_gps =
        packetchain->register_packet_component("GPS");

    uav_device_id =
        Globalreg::globalreg->entrytracker->register_field("uav.device",
                tracker_element_factory<uav_tracked_device>(),
                "UAV device");

    manuf_match_vec =
        std::make_shared<tracker_element_vector>();

    dji_manuf =
        Globalreg::globalreg->manufdb->make_manuf("DJI");

    // Tag into the packet chain at the very end so we've gotten all the other tracker
    // elements already
    packetchain->register_handler(kis_uav_phy::common_classifier, this, CHAINPOS_TRACKER, 65535);

    // Register js module for UI
    auto httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_uav", "js/kismet.ui.uav.js");

    // Parse the ssid regex options
    auto uav_lines = Globalreg::globalreg->kismet_config->fetch_opt_vec("uav_match");
    for (auto l : uav_lines)
        parse_manuf_definition(l);

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/phy/phyuav/manuf_matchers", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(manuf_match_vec, uav_mutex));

}

kis_uav_phy::~kis_uav_phy() {

}


void kis_uav_phy::load_phy_storage(shared_tracker_element in_storage, shared_tracker_element in_device) {
    if (in_storage == NULL || in_device == NULL)
        return;

    auto storage_map =
        tracker_element::safe_cast_as<tracker_element_map>(in_storage);

    // Does the imported record have UAV?
    auto devi = storage_map->find(uav_device_id);

    if (devi != storage_map->end()) {
        auto uavdev =
            std::make_shared<uav_tracked_device>(uav_device_id, 
                    tracker_element::safe_cast_as<tracker_element_map>(devi->second));

        tracker_element::safe_cast_as<tracker_element_map>(in_device)->insert(uavdev);
    }
}

int kis_uav_phy::common_classifier(CHAINCALL_PARMS) {
    kis_uav_phy *uavphy = (kis_uav_phy *) auxdata;

	auto commoninfo = in_pack->fetch<kis_common_info>(uavphy->pack_comp_common);
    auto dot11info = in_pack->fetch<dot11_packinfo>(uavphy->pack_comp_80211);
	auto devinfo = in_pack->fetch<kis_tracked_device_info>(uavphy->pack_comp_device);
    auto json = in_pack->fetch<kis_json_packinfo>(uavphy->pack_comp_json);

    if (in_pack->error || in_pack->filtered || in_pack->duplicate) {
        return 0;
    }

    // Handle JSON packets from droneid rf
    if (json != nullptr) {
        if (json->type != "antsdr-droneid") {
            return 1;
        }

        std::stringstream ss(json->json_string);
        nlohmann::json device_json;

        try {
            ss >> device_json;

            auto serial_no = device_json["serial_number"].get<std::string>();
            auto dev_type = device_json["device_type"].get<std::string>();
            auto drone_lat = device_json["drone_lat"].get<double>();
            auto drone_lon = device_json["drone_lon"].get<double>();
            auto app_lat = device_json["app_lat"].get<double>();
            auto app_lon = device_json["app_lon"].get<double>();
            // auto drone_height = device_json["drone_height"].get<double>();
            auto drone_alt = device_json["drone_alt"].get<double>();
            auto home_lat = device_json["home_lat"].get<double>();
            auto home_lon = device_json["home_lon"].get<double>();
            auto freq = device_json["freq"].get<double>();
            auto speed_e = device_json["speed_e"].get<double>();
            auto speed_n = device_json["speed_n"].get<double>();
            // auto speed_u = device_json["speed_u"].get<double>();

            uint8_t bytes[6];
            uint16_t *pfx = (uint16_t *) bytes;
            uint32_t *srcs = (uint32_t *) (bytes + 2);

            memset(bytes, 0, 6);
            *srcs = adler32_checksum(serial_no);
            *pfx = adler32_checksum(dev_type);

            auto dronemac = mac_addr(bytes, 6);

            if (commoninfo == nullptr) {
                commoninfo = 
                    in_pack->fetch_or_add<kis_common_info>(uavphy->pack_comp_common);
            }

            commoninfo->type = packet_basic_data;
            commoninfo->phyid = uavphy->fetch_phy_id();
            commoninfo->datasize = 0;

            commoninfo->freq_khz = freq * 1000;

            commoninfo->source = dronemac;
            commoninfo->transmitter = dronemac;

            auto flags = 
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                 UCD_UPDATE_SEENBY);

            if (drone_lat != 0 && drone_lon != 0) {
                // We have to make a new component here, not fetch the existing one; otherwise we 
                // clobber the global gps record!
                auto gpsinfo = uavphy->packetchain->new_packet_component<kis_gps_packinfo>();
                gpsinfo->lat = drone_lat;
                gpsinfo->lon = drone_lon;

                // Absolute altitude of drone, not height from takeoff
                gpsinfo->alt = drone_alt;
              
                // velocity vector to radians to degrees
                auto heading_r = std::atan2(speed_e, speed_n);
                gpsinfo->heading = heading_r * (180.0f / M_PI);
                if (gpsinfo->heading < 0) {
                    gpsinfo->heading += 360;
                }

                // speed is the magnitude of the ENU velocity vector,
                // because we generally don't track the vertical speed
                // in other situations (adsb, wifi) we only take the EN
                // vector for 2d speed over ground here
                gpsinfo->speed =
                    std::sqrt((speed_e * speed_e) + (speed_n * speed_n));

                if (drone_alt != 0)
                    gpsinfo->fix = 3;

                gpsinfo->tv = in_pack->ts;

                in_pack->insert(uavphy->pack_comp_gps, gpsinfo);

                flags |= UCD_UPDATE_LOCATION;
            }

            auto basedev = 
                uavphy->devicetracker->update_common_device(commoninfo, 
                        commoninfo->source, uavphy, in_pack,
                        flags, "DRONEID");

            if (basedev == nullptr) {
                return 0;
            }

            auto lg = kis_lock_guard<kis_mutex>(uavphy->devicetracker->get_devicelist_mutex(), "uav rf droneid");

            basedev->set_manuf(uavphy->dji_manuf);
            basedev->set_tracker_type_string(uavphy->devicetracker->get_cached_devicetype("DJI UAV"));
            basedev->set_devicename(fmt::format("{}-{}", dev_type, serial_no));

            auto uavdev = basedev->get_sub_as<uav_tracked_device>(uavphy->uav_device_id);

            if (uavdev == nullptr) {
                uavdev = 
                    Globalreg::globalreg->entrytracker->get_shared_instance_as<uav_tracked_device>(uavphy->uav_device_id);

                basedev->insert(uavdev);

                uavdev->set_uav_manufacturer("DJI");
                uavdev->set_uav_model(dev_type);
                uavdev->set_uav_match_type("DroneID RF");
                uavdev->set_uav_serialnumber(serial_no);

                _MSG_INFO("Detected new DJI DroneID RF UAV {} serial {}", dev_type, serial_no);
            }

            if (home_lat != 0 && home_lon != 0) {
                auto homeloc = uavdev->get_home_location();
                homeloc->set_location(home_lat, home_lon);
                homeloc->set_fix(2);
            }

            if (app_lat != 0 && app_lon != 0) {
                auto apploc = uavdev->get_app_location();
                apploc->set_location(app_lat, app_lon);
                apploc->set_fix(2);
            }

            // For now, work towards combining locational tracking; ultimately we want ADSB-beaconed airplanes, drones, and any 
            // other known-location devices to be organized the same way.  There is probably no use in trying to shove the 
            // antsdr telemetry into a uav-telem record

        } catch (const std::exception& e) {
            _MSG_DEBUG("antsdr-droneid json error: {}", e.what());
            return 0;
        }

        return 1;
    }

    // Otherwise we're looking for droneid in dot11 beacons, or wifi drones 
    // that match the ssid/mac filters; drop a record along the dot11 device 
    // record

    if (devinfo == nullptr || commoninfo == nullptr || dot11info == nullptr) {
        return 1;
    }

    kis_lock_guard<kis_mutex> lk(uavphy->devicetracker->get_devicelist_mutex(), "uav_phy common_classifier");

    for (auto di : devinfo->devrefs) {
        auto basedev = di.second;

        if (basedev == NULL)
            return 1;

        // Only compare to the AP device for droneid and SSID matching
        if (basedev->get_macaddr() != dot11info->bssid_mac)
            continue;

        if (dot11info->droneid != NULL) {
            try {
                if (dot11info->droneid->subcommand() == 0x00) {
                    // DJI Mavic firmware has known bugs where it sends completely blank
                    // droneID frames.  Known affected firmware includes:
                    //
                    // Mavic V01.04.0100 
                    // Mavic V01.04.0200
                    //
                    // Look for subcommand of 0, with 0 content
                    if (dot11info->droneid->raw_record_data().substr(0, 32).find_first_not_of(std::string("\x00", 1)) == std::string::npos) {
                        auto uavdev =
                            basedev->get_sub_as<uav_tracked_device>(uavphy->uav_device_id);

                        if (uavdev == nullptr) {
                            uavdev = 
                                Globalreg::globalreg->entrytracker->get_shared_instance_as<uav_tracked_device>(uavphy->uav_device_id);
                            basedev->insert(uavdev);
                        }

                        uavdev->set_uav_manufacturer("DJI");
                        uavdev->set_uav_model("(Broken firmware)");
                        uavdev->set_uav_match_type("DroneID");
                    }

                } 

                auto flightinfo = dot11info->droneid->flight_reg_record();
                if (flightinfo != nullptr) {
                    auto uavdev =
                        basedev->get_sub_as<uav_tracked_device>(uavphy->uav_device_id);

                    if (uavdev == nullptr) {
                        uavdev = 
                            Globalreg::globalreg->entrytracker->get_shared_instance_as<uav_tracked_device>(uavphy->uav_device_id);
                        basedev->insert(uavdev);
                    }

                    if (flightinfo->state_serial_valid()) {
                        uavdev->set_uav_serialnumber(munge_to_printable(flightinfo->serialnumber()));
                    }

                    std::shared_ptr<uav_tracked_telemetry> telem = uavdev->new_telemetry();
                    telem->from_droneid_flight_reg(flightinfo);
                    telem->set_telem_timestamp(ts_to_double(in_pack->ts));

                    auto ltr = uavdev->get_last_telem_loc();
                    ltr->set(telem);

                    auto tvec = uavdev->get_uav_telem_history();

                    tvec->push_back(telem);

                    if (tvec->size() > 128)
                        tvec->erase(tvec->begin());

                    uavdev->set_uav_match_type("DroneID WiFi");

                    if (uavdev->get_uav_manufacturer() == "")
                        uavdev->set_uav_manufacturer("DJI");

                    if (uavdev->get_uav_model() == "")
                        uavdev->set_uav_model(flightinfo->product_type_str());

                    // Set the home location
                    if (flightinfo->home_lat() != 0 && flightinfo->home_lon() != 0) {
                        auto homeloc = uavdev->get_home_location();
                        homeloc->set_location(flightinfo->home_lat(), flightinfo->home_lon());
                        homeloc->set_fix(2);
                    }

                    if (flightinfo->app_lat() != 0 && flightinfo->app_lon() != 0) {
                        auto apploc = uavdev->get_app_location();
                        apploc->set_location(flightinfo->app_lat(), flightinfo->app_lon());
                        apploc->set_fix(2);
                    }

                } 
               
                auto flightpurpose = dot11info->droneid->flight_purpose_record();
                if (flightpurpose != NULL) {
                    auto uavdev =
                        basedev->get_sub_as<uav_tracked_device>(uavphy->uav_device_id);

                    if (uavdev == NULL) {
                        uavdev = 
                            Globalreg::globalreg->entrytracker->get_shared_instance_as<uav_tracked_device>(uavphy->uav_device_id);
                        basedev->insert(uavdev);
                    }

                    uavdev->set_uav_serialnumber(munge_to_printable(flightpurpose->serialnumber()));
                    uavdev->set_uav_match_type("DroneID WiFi");

                    if (uavdev->get_uav_manufacturer() == "")
                        uavdev->set_uav_manufacturer("DJI");
                } 
            } catch (const std::exception& e) {
                _MSG_DEBUG("Unable to parse droneid frame - {}", e.what());
            }
        }
        
        if (dot11info->new_adv_ssid && dot11info->type == packet_management && 
                (dot11info->subtype == packet_sub_beacon || dot11info->subtype == packet_sub_probe_resp)) {

            for (auto mi : *(uavphy->manuf_match_vec)) {
                auto m = std::static_pointer_cast<uav_manuf_match>(mi);

                if (m->match_record(dot11info->bssid_mac, dot11info->ssid)) {
                    auto uavdev =
                        basedev->get_sub_as<uav_tracked_device>(uavphy->uav_device_id);

                    if (uavdev == nullptr) {
                        uavdev = 
                            Globalreg::globalreg->entrytracker->get_shared_instance_as<uav_tracked_device>(uavphy->uav_device_id);
                        basedev->insert(uavdev);
                        uavdev->set_uav_manufacturer(m->get_uav_manuf_name());
                        uavdev->set_uav_model(m->get_uav_manuf_model());
                    }

                    auto mtr = uavdev->get_matched_rule();
                    mtr->set(m);

                    uavdev->set_uav_match_type("UAV Fingerprint");

                    break;
                }
            }
        }
    }

    return 1;
}

bool kis_uav_phy::parse_manuf_definition(std::string in_def) {
    kis_lock_guard<kis_mutex> lk(uav_mutex);

    size_t cpos = in_def.find(':');

    if (cpos == std::string::npos) {
        _MSG("Invalid 'uav_match' configuration line, expected 'name:option1=\"...\","  
                "option2=\"...\" but got '" + in_def + "'", MSGFLAG_ERROR);
        return false;
    }

    std::string name = in_def.substr(0, cpos);

    for (auto i : *manuf_match_vec) {
        auto mi = std::static_pointer_cast<uav_manuf_match>(i);

        if (mi->get_uav_match_name() == name) {
            _MSG_INFO("Invalid 'uav_match=' configuration line, match name '{}' already in use.",
                    name);
            return false;
        }
    }

    std::vector<opt_pair> optvec;
    string_to_opts(in_def.substr(cpos + 1, in_def.length()), ",", &optvec);

    std::string manuf_name = fetch_opt("name", &optvec);
    std::string manuf_model = fetch_opt("model", &optvec);
    std::string macstr = fetch_opt("mac", &optvec);
    std::string ssid = fetch_opt("ssid", &optvec);
    bool matchany = fetch_opt_bool("match_any", &optvec, false);

    if (manuf_name == "") {
        _MSG("Invalid 'uav_match' configuration line, expected 'name=\"...\"' in definition, "
                "but got '" + in_def + "'", MSGFLAG_ERROR);
        return false;
    }

    mac_addr mac;

    if (macstr != "") {
        mac = mac_addr(macstr);

        if (mac.state.error) {
            _MSG("Invalid 'uav_match' configuration line, expected 'mac=macaddr' in definition, "
                    "but got an invalid mac in '" + in_def + "'", MSGFLAG_ERROR);
            return false;
        }
    }

    auto manufmatch =
        std::make_shared<uav_manuf_match>();

    try {
        manufmatch->set_uav_match_name(name);
        manufmatch->set_uav_manuf_name(manuf_name);

        if (manuf_model != "")
            manufmatch->set_uav_manuf_model(manuf_model);

        if (macstr != "") 
            manufmatch->set_uav_manuf_mac(mac);

        if (ssid != "")
            manufmatch->set_uav_manuf_ssid_regex(ssid);

        manufmatch->set_uav_manuf_partial(matchany);
    } catch (const std::exception& e) {
        _MSG_ERROR("Invalid 'uav_match=' configuration line: {} in devinition '{}'",
                e.what(), in_def);
        return false;
    }

    manuf_match_vec->push_back(manufmatch);

    return true;
}

