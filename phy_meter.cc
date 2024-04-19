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

#include "fmt/core.h"
#include "nlohmann/json.hpp"
#include "phy_meter.h"
#include "devicetracker.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "manuf.h"
#include "messagebus.h"

kis_meter_phy::kis_meter_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("METER");

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
	pack_comp_device = 
		packetchain->register_packet_component("DEVICE");

    tracked_meter_id =
        Globalreg::globalreg->entrytracker->register_field("meter.device",
                tracker_element_factory<tracked_meter>(),
                "RF Meter");

    // Make the manuf string
    meter_manuf = Globalreg::globalreg->manufdb->make_manuf("RF METER");

    // Register js module for UI
    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_meter", "js/kismet.ui.meter.js");

	packetchain->register_handler(&PacketHandler, this, CHAINPOS_CLASSIFIER, -100);
}

kis_meter_phy::~kis_meter_phy() {
    packetchain->remove_handler(&PacketHandler, CHAINPOS_CLASSIFIER);
}

mac_addr kis_meter_phy::synth_mac(std::string model_s, uint64_t id) {
	// Derive a MAC from the ID; previously we used the model as well but 
	// rtl_433 decodes multiple meter models from a single signal so we 
	// use the decoded ID only

    uint8_t bytes[6];
    // uint16_t *model = (uint16_t *) bytes;
    uint32_t *deviceid = (uint32_t *) (bytes + 2);

    memset(bytes, 0, 6);

    try {
        // *model = (uint16_t) id;
        // *deviceid = adler32_checksum(model_s);
		*deviceid = (uint32_t) id;
    } catch (const std::exception& e) {
        mac_addr m;
        m.state.error = true;
        return m;
    }

    // Set the local bit
    bytes[0] |= 0x2;

    return mac_addr(bytes, 6);
}

mac_addr kis_meter_phy::json_to_mac(nlohmann::json json) {
    // Derive a mac addr from the model and device id data
    //
    // We turn the model string into 4 bytes using the adler32 checksum,
    // then we use the model as a (potentially) 16bit int
    //
    // Finally we set the locally assigned bit on the first octet

    uint8_t bytes[6];
    uint16_t *model = (uint16_t *) bytes;
    uint32_t *deviceid = (uint32_t *) (bytes + 2);

    memset(bytes, 0, 6);

    try {
        *model = json["model"];
        *deviceid = json["meterid"];
    } catch (const std::exception& e) {
        mac_addr m;
        m.state.error = true;
        return m;
    }

    // Set the local bit
    bytes[0] |= 0x2;

    return mac_addr(bytes, 6);
}

bool kis_meter_phy::rtlamr_json_to_phy(nlohmann::json json, std::shared_ptr<kis_packet> packet) {
    std::string err;
    std::string v;

    // If we're not valid from the capture engine, drop entirely
    try {
        if (!json["valid"].get<bool>())
            return false;
    } catch (const std::exception& e) {
        return false;
    }

    auto id_j = json["meterid"];
    auto type_j = json["metertype"];
    auto phy_j = json["phytamper"];
    auto end_j = json["endptamper"];
    auto consumption_j = json["consumption"];

    // We need at least an id, type, and consumption
    if (id_j.is_null() || type_j.is_null() || consumption_j.is_null())
        return false;

    // synth a mac out of of the type and id
    mac_addr mac = json_to_mac(json);

    if (mac.state.error) {
        return false;
    }

    auto common = packet->fetch_or_add<kis_common_info>(pack_comp_common);

    common->type = packet_basic_data;
    common->phyid = fetch_phy_id();
    common->datasize = 0;

    common->freq_khz = 912600;
    common->source = mac;
    common->transmitter = mac;

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "AMR Meter");

    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "rtlamr_json_to_phy");

    auto meterdev = 
        basedev->get_sub_as<tracked_meter>(tracked_meter_id);

    if (meterdev == nullptr) {
        meterdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<tracked_meter>(tracked_meter_id);

        basedev->set_manuf(meter_manuf);

        basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Meter"));

        basedev->insert(meterdev);

        meterdev->set_meter_id(id_j);
        meterdev->set_meter_type_code(type_j);

        switch (meterdev->get_meter_type_code()) {
            case 4:
            case 5:
            case 7:
            case 8:
                meterdev->set_meter_type("Electric");
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Electric Meter"));
                break;
            case 2:
            case 9:
            case 12:
                meterdev->set_meter_type("Gas");
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Gas Meter"));
                break;
            case 11:
            case 13:
                meterdev->set_meter_type("Water");
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Water Meter"));
                break;
            default:
                meterdev->set_meter_type("Meter");
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Meter"));
                break;
        }

        basedev->set_devicename(fmt::format("{}-{}", meterdev->get_meter_type(), id_j.get<unsigned int>()));

        _MSG_INFO("Detected new AMR {} id {}",
                basedev->get_type_string(), meterdev->get_meter_id());
    }

    if (!phy_j.is_null())
        meterdev->set_phy_tamper_flags(phy_j);
    if (!end_j.is_null())
        meterdev->set_endpoint_tamper_flags(end_j);

    meterdev->set_consumption(consumption_j);
    meterdev->get_consumption_rrd()->add_sample(meterdev->get_consumption(), Globalreg::globalreg->last_tv_sec);

    return true;
}

/*

DEBUG: JSON data RTL433 {"time": "2023-03-22 20:26:49", "model": "IDM", "PacketTypeID": "0x1C", "PacketLength": 92, "ApplicationVersion": 4, "ERTType": 23, "ERTSerialNumber": 22156790, "ConsumptionIntervalCount": 98, "ModuleProgrammingState": 188, "TamperCounters": "0x020200340A00", "AsynchronousCounters": 0, "PowerOutageFlags": "0x000000000000", "LastConsumptionCount": 6823922, "DifferentialConsumptionIntervals": [11, 9, 8, 7, 40, 30, 4, 7, 7, 8, 8, 8, 7, 6, 5, 5, 5, 5, 5, 6, 5, 6, 6, 8, 7, 8, 6, 7, 7, 6, 5, 5, 6, 6, 5, 6, 7, 8, 8, 8, 6, 6, 8, 6, 9, 7, 6], "TransmitTimeOffset": 1695, "MeterIdCRC": 20090, "PacketCRC": 14134, "MeterType": "Electric", "mic": "CRC", "mod": "ASK", "freq": 915.365, "rssi": -0.454, "snr": 21.437, "noise": -21.891}                         
debug - error processing rtl json [json.exception.type_error.302] type must be number, but is nul
l                                                                                                
DEBUG: JSON data RTL433 {"time": "2023-03-22 20:26:49", "model": "NETIDM", "PacketTypeID": "0x1C"
, "PacketLength": 92, "ApplicationVersion": 4, "ERTType": 23, "ERTSerialNumber": 22156790, "Consu
mptionIntervalCount": 98, "ModuleProgrammingState": 188, "TamperCounters": "0x020200340A00", "Unk
nown_field_1": "0x00000000000000", "LastGenerationCount": 104, "Unknown_field_2": "0x1FF205", "LastConsumptionCount": -2109669263, "DifferentialConsumptionIntervals": [4126, 128, 7182, 513, 32, 897, 8232, 1282, 8272, 2566, 160, 6156, 512, 14368, 769, 12344, 1538, 8272, 3078, 160, 6158, 513, 32, 769, 8256, 1540, 8304], "TransmitTimeOffset": 1695, "MeterIdCRC": 20090, "PacketCRC": 14134, "MeterType": "Electric", "mic": "CRC", "mod": "ASK", "freq": 915.365, "rssi": -0.454, "snr": 21. 437, "noise": -21.891}                                                                           
debug - error processing rtl json [json.exception.type_error.302] type must be number, but is nul
l                                                                                                
DEBUG: JSON data RTL433 {"time": "2023-03-22 20:26:49", "model": "ERT-SCM", "id": 22156790, "physical_tamper": 2, "ert_type": 7, "encoder_tamper": 2, "consumption_data": 6823922, "mic": "CRC", "mod": "ASK", "freq": 915.358, "rssi": -0.571, "snr": 19.871, "noise": -20.442}                   
debug - error processing rtl json [json.exception.type_error.302] type must be string, but is nul
l

*/

bool kis_meter_phy::is_meter(const nlohmann::json &json) { 
    // This list will need to be updated as rtl_433 adds more meter types
    auto model_j = json["model"];

    if (model_j.is_string()) {
        if (model_j == "IDM") 
            return true;
        if (model_j == "NETIDM")
            return true; 
        if (model_j == "ERT-SCM") 
            return true; 
        if (model_j == "SCMplus")
            return true;
        if (model_j == "SCM+")
            return true;
    }

    return false;
}

bool kis_meter_phy::rtl433_json_to_phy(nlohmann::json json, std::shared_ptr<kis_packet> packet) { 
    std::string err;
    std::string v;

    auto id_j = json["id"];
    auto ert_serial_j = json["ERTSerialNumber"];
    auto model_j = json["model"];
    auto type_j = json["MeterType"];
    auto endp_type_j = json["EndpointType"];
    auto ert_type_j = json["ERTType"];
	auto ert_type_2_j = json["ert_type"];
    auto consumption_j = json["consumption"];
    auto consumption_2_j = json["Consumption"];
    auto consumption_data_j = json["consumption_data"];
	auto last_consumption_j = json["LastConsumptionCount"];
	auto freq_j = json["freq"];

    if (model_j.is_null())
        return false;

    uint64_t decoded_id = 0; 
    int64_t decoded_consumption = 0; 
    // internal decoded type
    // 0 unknown 1 elec 2 gas 3 water
    int decoded_type = -1;

	double freq_khz = 0;

    // Look for the ID, consumption records, and type for the different variant types
    if (!id_j.is_null() && id_j.is_number()) { 
        decoded_id = id_j.get<uint64_t>();
    } else if (!ert_serial_j.is_null() && ert_serial_j.is_number()) { 
        decoded_id = ert_serial_j.get<uint64_t>();
    } else { 
        return false;
    }

    if (!consumption_j.is_null() && consumption_j.is_number()) { 
        decoded_consumption = consumption_j.get<int64_t>();
    } else if (!consumption_2_j.is_null() && consumption_2_j.is_number()) { 
        decoded_consumption = consumption_2_j.get<int64_t>();
    } else if (!consumption_data_j.is_null() && consumption_data_j.is_number()) { 
        decoded_consumption = consumption_data_j.get<int64_t>();
	} else if (!last_consumption_j.is_null() && last_consumption_j.is_number()) {
		decoded_consumption = last_consumption_j.get<int64_t>();
    } else { 
        return false;
    }

	// Some meters appear to decode improperly and get a negative consumption; set the 
	// consumption to 0 if that happens but still log that the meter exists
    if (decoded_consumption < 0)
        decoded_consumption = 0;

    if (!type_j.is_null()) {
        if (type_j.get<std::string>() == "Electric") {
            decoded_type = 1;
        } else if (type_j.get<std::string>() == "Gas") {
            decoded_type = 2;
        } else if (type_j.get<std::string>() == "Water") {
            decoded_type = 3;
        } else {
            decoded_type = 0;
        }
    } else if (!model_j.is_null() && model_j.get<std::string>() == "ERT-SCM") { 
        if (!ert_type_j.is_null() && ert_type_j.is_number()) {
            switch (ert_type_j.get<int>()) {
                case 4:
                case 5:
                case 7:
                case 8:
                case 23:
                    decoded_type = 1;
                    break;
                case 2:
                case 9:
                case 12:
                    decoded_type = 2;
                    break;
                case 11:
                case 13:
                    decoded_type = 3;
                    break;
                default:
                    decoded_type = 0;
                    break;
            }
        } else if (!ert_type_2_j.is_null() && ert_type_2_j.is_number()) {
            switch (ert_type_2_j.get<int>()) {
                case 4:
                case 5:
                case 7:
                case 8:
                case 23:
                    decoded_type = 1;
                    break;
                case 2:
                case 9:
                case 12:
                    decoded_type = 2;
                    break;
                case 11:
                case 13:
                    decoded_type = 3;
                    break;
                default:
                    decoded_type = 0;
                    break;
            }

        } else {
            return false; 
        }

    } else {
        return false;
    }

    // synth a mac out of of the type and id
    mac_addr mac = synth_mac(model_j.get<std::string>(), decoded_id);

    if (mac.state.error) {
        return false;
    }

    auto devinfo = packet->fetch<kis_tracked_device_info>(pack_comp_device);
    std::shared_ptr<kis_tracked_device_base> basedev;

    if (devinfo != nullptr) {
        // rf sensor packets should only create a single device, so we'll take a risk 
        // here and assume the first one in the device list is what we want
        if (devinfo->devrefs.size() > 0)
            basedev = devinfo->devrefs.begin()->second;
    }

    auto common = packet->fetch_or_add<kis_common_info>(pack_comp_common);

    if (basedev == nullptr) {
        common->type = packet_basic_data;
        common->phyid = fetch_phy_id();
        common->datasize = 0;

        if (!freq_j.is_null())
            freq_khz = freq_j.get<double>() * 1000;

        if (freq_khz != 0) {
            common->freq_khz = freq_khz;
        }

        if (common->source == mac_addr(0))
            common->source = mac;
        if (common->transmitter == mac_addr(0))
            common->transmitter = mac;

        basedev = devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "AMR Meter");
    }

    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "rtlamr_json_to_phy");

    auto meterdev = 
        basedev->get_sub_as<tracked_meter>(tracked_meter_id);

    if (meterdev == nullptr) {
        meterdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<tracked_meter>(tracked_meter_id);

        basedev->set_manuf(meter_manuf);

        basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Meter"));

        basedev->insert(meterdev);

        meterdev->set_meter_id(decoded_id);
        meterdev->set_meter_type_code(decoded_type);

        if (decoded_type == 1) { 
            meterdev->set_meter_type("Electric");
            basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Electric Meter"));
        } else if (decoded_type == 2) { 
            meterdev->set_meter_type("Gas");
            basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Gas Meter"));
        } else if (decoded_type == 3) { 
            meterdev->set_meter_type("Water");
            basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Water Meter"));
        } else { 
            meterdev->set_meter_type("Meter");
            basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Meter"));
        }

        basedev->set_devicename(fmt::format("{}-{}", meterdev->get_meter_type(), decoded_id));

        _MSG_INFO("Detected new meter {} id {}",
                basedev->get_type_string(), meterdev->get_meter_id());
    }

    meterdev->get_model_vec()->insert(model_j, nullptr);

    // Only set consumption if we're non-zero to trim out error readings
    if (decoded_consumption != 0 && decoded_consumption >= meterdev->get_consumption()) {
        meterdev->set_consumption(decoded_consumption);
        meterdev->get_consumption_rrd()->add_sample(meterdev->get_consumption(), Globalreg::globalreg->last_tv_sec);
    }

    return true;
}

int kis_meter_phy::PacketHandler(CHAINCALL_PARMS) {
    kis_meter_phy *phy = (kis_meter_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto json = in_pack->fetch<kis_json_packinfo>(phy->pack_comp_json);
    if (json == nullptr)
        return 0;

    if (json->type == "RTLamr") {
        std::stringstream ss(json->json_string);
        nlohmann::json device_json;

        try {
            ss >> device_json;

            if (phy->rtlamr_json_to_phy(device_json, in_pack)) {
                auto adata = in_pack->fetch_or_add<packet_metablob>(phy->pack_comp_meta);
                adata->set_data("METER", json->json_string);
            }
        } catch (std::exception& e) {
            fprintf(stderr, "debug - error processing rtl json %s\n", e.what());
            return 0;
        }

        return 1;
    } else if (json->type == "RTL433") {
        std::stringstream ss(json->json_string);
        nlohmann::json device_json;

            ss >> device_json;

            if (phy->rtl433_json_to_phy(device_json, in_pack)) { 
                auto adata = in_pack->fetch_or_add<packet_metablob>(phy->pack_comp_meta);
                adata->set_data("METER", json->json_string);
            }

#if 0
        try {
            ss >> device_json;

            if (phy->rtl433_json_to_phy(device_json, in_pack)) { 
                auto adata = in_pack->fetch_or_add<packet_metablob>(phy->pack_comp_meta);
                adata->set_data("METER", json->json_string);
            }
        } catch (std::exception& e) {
            fprintf(stderr, "debug - error processing rtl json %s\n", e.what());
            return 0;
        }
#endif

        return 1;

	}

    return 0;
}

