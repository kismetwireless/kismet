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

#include "phy_zwave.h"
#include "devicetracker.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "manuf.h"
#include "messagebus.h"
#include "kis_httpd_registry.h"

Kis_Zwave_Phy::Kis_Zwave_Phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("Z-Wave");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

	pack_comp_common = 
		packetchain->register_packet_component("COMMON");

    zwave_device_id =
        Globalreg::globalreg->entrytracker->register_field("zwave.device",
                tracker_element_factory<zwave_tracked_device>(),
                "Z-Wave device");

    zwave_manuf = Globalreg::globalreg->manufdb->make_manuf("Z-Wave");

    // Register js module for UI
    auto httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>("WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_zwave", "js/kismet.ui.zwave.js");

    // TODO implement scan source?
}

Kis_Zwave_Phy::~Kis_Zwave_Phy() {

}

mac_addr Kis_Zwave_Phy::id_to_mac(uint32_t in_homeid, uint8_t in_devid) {
    std::stringstream macstr;

    // Lazy!
    macstr << "02" << std::hex << in_homeid << std::hex << (int) in_devid;

    return mac_addr(macstr.str());
}

bool Kis_Zwave_Phy::json_to_record(nlohmann::json json) {
    std::string tempstr;
    std::stringstream converter;

    uint32_t homeid;
    uint8_t devid;
    double frequency;
    double dest_devid;
    double datasize;

    // TODO parse the actual payload
    
  
    auto homeid_j = json["home_id"];

    if (homeid_j.is_string()) {
        tempstr = homeid_j.get<std::string>();
    } else {
        return false;
    }

    converter.str(tempstr);
    converter >> std::hex >> homeid;

    auto source_j = json["source"];
    if (source_j.is_number()) {
        devid = source_j;
    } else {
        return false;
    }


    auto dest_j = json["dest"];
    if (dest_j.is_number()) {
        dest_devid = dest_j;
    } else {
        return false;
    }

    auto freq_j = json["freq_khz"];
    if (freq_j.is_number()) {
        frequency = freq_j;
    } else {
        return false;
    }

    auto datasize_j = json["datasize"];
    if (datasize_j.is_number()) {
        datasize = datasize_j;
    } else {
        return false;
    }

    mac_addr smac = id_to_mac(homeid, devid);
    mac_addr dmac = id_to_mac(homeid, dest_devid);

    if (smac.state.error)
        return false;
    if (dmac.state.error)
        return false;

    auto pack = packetchain->generate_packet();

    struct timeval ts;
    gettimeofday(&ts, nullptr);

    pack->ts.tv_sec = ts.tv_sec;
    pack->ts.tv_usec = ts.tv_usec;

    auto common = std::make_shared<kis_common_info>();

    common->type = packet_basic_data;
    common->phyid = fetch_phy_id();
    common->datasize = datasize;

    common->freq_khz = frequency;
    common->source = smac;
    common->transmitter = smac;
    common->dest = dmac;

    pack->insert(pack_comp_common, common);

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(common, common->source, this, pack,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "Z-Wave Node");

    basedev->set_manuf(zwave_manuf);

    std::string devname;
    std::stringstream devstr;

    devstr << std::hex << homeid;

    devname = "Z-Wave " +
        devstr.str().substr(0, 2) + ":" +
        devstr.str().substr(2, 2) + ":" +
        devstr.str().substr(4, 2);

    devstr.str("");
    devstr << std::hex << (unsigned int) devid;

    devname += " id " + devstr.str();

    basedev->set_devicename(devname);

    auto zdev =
        basedev->get_sub_as<zwave_tracked_device>(zwave_device_id);

    bool newzdev = false;

    if (zdev == NULL) {
        zdev = 
            std::make_shared<zwave_tracked_device>(zwave_device_id);
        basedev->insert(zdev);
        newzdev = true;
    }

    if (newzdev) {
        zdev->set_homeid(homeid);
        zdev->set_deviceid(devid);
    }

    if (newzdev && basedev != NULL) {
        _MSG("Detected new Z-Wave device '" + basedev->get_devicename() + "'",
                MSGFLAG_INFO);
    }

    return true;
}

