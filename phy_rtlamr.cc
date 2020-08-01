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

#include "phy_rtlamr.h"
#include "devicetracker.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "manuf.h"

kis_rtlamr_phy::kis_rtlamr_phy(global_registry *in_globalreg, int in_phyid) :
    kis_phy_handler(in_globalreg, in_phyid) {

    set_phy_name("RTLAMR");

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

    rtlamr_meter_id =
        Globalreg::globalreg->entrytracker->register_field("rtlamr.device",
                tracker_element_factory<rtlamr_tracked_meter>(),
                "RTLAMR meter");

    // Make the manuf string
    rtl_manuf = Globalreg::globalreg->manufdb->make_manuf("RTLAMR");

    // Register js module for UI
    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_rtlamr", "js/kismet.ui.rtlamr.js");

	packetchain->register_handler(&PacketHandler, this, CHAINPOS_CLASSIFIER, -100);
}

kis_rtlamr_phy::~kis_rtlamr_phy() {
    packetchain->remove_handler(&PacketHandler, CHAINPOS_CLASSIFIER);
}


mac_addr kis_rtlamr_phy::json_to_mac(Json::Value json) {
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
        m.error = true;
        return m;
    }

    // Set the local bit
    bytes[0] |= 0x2;

    return mac_addr(bytes, 6);
}

bool kis_rtlamr_phy::json_to_rtl(Json::Value json, kis_packet *packet) {
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

    common->freq_khz = 912600;
    common->source = rtlmac;
    common->transmitter = rtlmac;

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "AMR Meter");

    local_locker bssidlock(&(basedev->device_mutex));

    auto meterdev = 
        basedev->get_sub_as<rtlamr_tracked_meter>(rtlamr_meter_id);

    if (meterdev == nullptr) {
        meterdev = 
            std::make_shared<rtlamr_tracked_meter>(rtlamr_meter_id);

        basedev->set_manuf(rtl_manuf);

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


int kis_rtlamr_phy::PacketHandler(CHAINCALL_PARMS) {
    kis_rtlamr_phy *rtlamr = (kis_rtlamr_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    kis_json_packinfo *json = in_pack->fetch<kis_json_packinfo>(rtlamr->pack_comp_json);
    if (json == NULL)
        return 0;

    if (json->type != "RTLamr")
        return 0;

    std::stringstream ss(json->json_string);
    Json::Value device_json;

    try {
        ss >> device_json;

        if (rtlamr->json_to_rtl(device_json, in_pack)) {
            packet_metablob *metablob = in_pack->fetch<packet_metablob>(rtlamr->pack_comp_meta);
            if (metablob == NULL) {
                metablob = new packet_metablob("RTLAMR", json->json_string);
                in_pack->insert(rtlamr->pack_comp_meta, metablob);
            }
        }
    } catch (std::exception& e) {
        fprintf(stderr, "debug - error processing rtl json %s\n", e.what());
        return 0;
    }

    return 1;
}

