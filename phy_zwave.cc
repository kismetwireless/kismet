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
#include "kismet_json.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "manuf.h"
#include "messagebus.h"
#include "kis_httpd_registry.h"

Kis_Zwave_Phy::Kis_Zwave_Phy(GlobalRegistry *in_globalreg, int in_phyid) :
    Kis_Phy_Handler(in_globalreg, in_phyid),
    Kis_Net_Httpd_CPPStream_Handler() {

    SetPhyName("Z-Wave");

    packetchain =
        Globalreg::FetchMandatoryGlobalAs<Packetchain>();
    entrytracker =
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>();
    devicetracker =
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>();

	pack_comp_common = 
		packetchain->RegisterPacketComponent("COMMON");

    zwave_device_id =
        Globalreg::globalreg->entrytracker->RegisterField("zwave.device",
                TrackerElementFactory<zwave_tracked_device>(),
                "Z-Wave device");

    zwave_manuf = Globalreg::globalreg->manufdb->MakeManuf("Z-Wave");

    // Register js module for UI
    auto httpregistry = 
        Globalreg::FetchMandatoryGlobalAs<Kis_Httpd_Registry>("WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_zwave", "js/kismet.ui.zwave.js");
}

Kis_Zwave_Phy::~Kis_Zwave_Phy() {

}

bool Kis_Zwave_Phy::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/phy/phyZwave/post_zwave_json.cmd") == 0)
            return true;
    }

    return false;
}

mac_addr Kis_Zwave_Phy::id_to_mac(uint32_t in_homeid, uint8_t in_devid) {
    std::stringstream macstr;

    // Lazy!
    macstr << "02" << std::hex << in_homeid << std::hex << (int) in_devid;

    return mac_addr(macstr.str());
}

bool Kis_Zwave_Phy::json_to_record(Json::Value json) {
    std::string tempstr;
    std::stringstream converter;

    uint32_t homeid;
    uint8_t devid;
    double frequency;
    double dest_devid;
    double datasize;

    // TODO parse the actual payload
    
  
    auto homeid_j = json["home_id"];

    if (homeid_j.isString()) {
        tempstr = homeid_j.asString();
    } else {
        return false;
    }

    converter.str(tempstr);
    converter >> std::hex >> homeid;

    auto source_j = json["source"];
    if (source_j.isNumeric()) {
        devid = source_j.asInt();
    } else {
        return false;
    }


    auto dest_j = json["dest"];
    if (dest_j.isNumeric()) {
        dest_devid = dest_j.asDouble();
    } else {
        return false;
    }

    auto freq_j = json["freq_khz"];
    if (freq_j.isNumeric()) {
        frequency = freq_j.asDouble();
    } else {
        return false;
    }

    auto datasize_j = json["datasize"];
    if (datasize_j.isNumeric()) {
        datasize = datasize_j.asDouble();
    } else {
        return false;
    }

    mac_addr smac = id_to_mac(homeid, devid);
    mac_addr dmac = id_to_mac(homeid, dest_devid);

    if (smac.error)
        return false;
    if (dmac.error)
        return false;

    kis_packet *pack = new kis_packet(Globalreg::globalreg);

    struct timeval ts;
    gettimeofday(&ts, nullptr);

    pack->ts.tv_sec = ts.tv_sec;
    pack->ts.tv_usec = ts.tv_usec;

    kis_common_info *common = new kis_common_info();

    common->type = packet_basic_data;
    common->phyid = FetchPhyId();
    common->datasize = datasize;

    common->freq_khz = frequency;
    common->source = smac;
    common->transmitter = smac;
    common->dest = dmac;

    pack->insert(pack_comp_common, common);

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->UpdateCommonDevice(common, common->source, this, pack,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "Z-Wave");

    // Get rid of our pseudopacket
    delete(pack);

    basedev->set_manuf(zwave_manuf);
    basedev->set_type_string("Z-Wave Node");

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

void Kis_Zwave_Phy::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    return;
}

int Kis_Zwave_Phy::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {

    // Anything involving POST here requires a login
    if (!httpd->HasValidSession(concls, true)) {
        return 1;
    }

    bool handled = false;

    if (concls->url != "/phy/phyZwave/post_zwave_json.cmd")
        return 1;
   
    if (concls->variable_cache.find("obj") != concls->variable_cache.end()) {
        Json::Value json;

        try {
            std::stringstream ss(concls->variable_cache["obj"]->str());
            ss >> json;
        } catch (std::exception& e) {
            concls->response_stream << "Invalid request: could not parse JSON: " <<
                e.what();
            concls->httpcode = 400;
            return 1;
        }

        // If we can't make sense of it, blow up
        if (!json_to_record(json)) {
            concls->response_stream << 
                "Invalid request:  could not convert to Z-Wave device";
            concls->httpcode = 400;
            handled = false;
        } else {
            handled = true;
        }
    }

    // If we didn't handle it and got here, we don't know what it is, throw an
    // error.
    if (!handled) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
    } else {
        // Return a generic OK.  
        concls->response_stream << "OK";
    }

    return 1;
}


