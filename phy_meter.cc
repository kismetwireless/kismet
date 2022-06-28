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


mac_addr kis_meter_phy::json_to_mac(Json::Value json) {
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
        *model = json["model"].asUInt();
        *deviceid = json["meterid"].asUInt();
    } catch (const std::exception& e) {
        mac_addr m;
        m.state.error = true;
        return m;
    }

    // Set the local bit
    bytes[0] |= 0x2;

    return mac_addr(bytes, 6);
}

bool kis_meter_phy::rtlamr_json_to_phy(Json::Value json, std::shared_ptr<kis_packet> packet) {
    std::string err;
    std::string v;

    // If we're not valid from the capture engine, drop entirely
    try {
        if (!json["valid"].asBool())
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
    if (id_j.isNull() || type_j.isNull() || consumption_j.isNull())
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

    kis_lock_guard<kis_shared_mutex> lk(devicetracker->get_devicelist_mutex(), "rtlamr_json_to_phy");

    auto meterdev = 
        basedev->get_sub_as<tracked_meter>(tracked_meter_id);

    if (meterdev == nullptr) {
        meterdev = 
            std::make_shared<tracked_meter>(tracked_meter_id);

        basedev->set_manuf(meter_manuf);

        basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Meter"));
        basedev->set_devicename(fmt::format("{}", id_j.asUInt()));

        basedev->insert(meterdev);

        meterdev->set_meter_id(id_j.asUInt());
        meterdev->set_meter_type_code(type_j.asUInt());

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
                meterdev->set_meter_type("Unknown");
                basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Meter"));
                break;
        }

        _MSG_INFO("Detected new AMR {} id {}",
                basedev->get_type_string(), meterdev->get_meter_id());
    }

    if (!phy_j.isNull())
        meterdev->set_phy_tamper_flags(phy_j.asUInt());
    if (!end_j.isNull())
        meterdev->set_endpoint_tamper_flags(end_j.asUInt());

    meterdev->set_consumption(consumption_j.asUInt());
    meterdev->get_consumption_rrd()->add_sample(meterdev->get_consumption(), time(0));

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
        Json::Value device_json;

        try {
            ss >> device_json;

            if (phy->rtlamr_json_to_phy(device_json, in_pack)) {
                auto adata = in_pack->fetch_or_add<packet_metablob>(phy->pack_comp_meta);
                adata->set_data("RTLAMR", json->json_string);
            }
        } catch (std::exception& e) {
            fprintf(stderr, "debug - error processing rtl json %s\n", e.what());
            return 0;
        }

        return 1;
    }

    return 0;
}

