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

Kis_RTLADSB_Phy::Kis_RTLADSB_Phy(GlobalRegistry *in_globalreg, int in_phyid) :
    Kis_Phy_Handler(in_globalreg, in_phyid) {

    SetPhyName("RTLADSB");

    packetchain =
        Globalreg::FetchMandatoryGlobalAs<Packetchain>();
    entrytracker =
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>();
    devicetracker =
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>();

	pack_comp_common = 
		packetchain->RegisterPacketComponent("COMMON");
    pack_comp_json = 
        packetchain->RegisterPacketComponent("JSON");
    pack_comp_meta =
        packetchain->RegisterPacketComponent("METABLOB");

    rtladsb_holder_id =
        Globalreg::globalreg->entrytracker->RegisterField("rtladsb.device", 
                TrackerElementFactory<TrackerElementMap>(),
                "rtl_adsb device");

    rtladsb_common_id =
        Globalreg::globalreg->entrytracker->RegisterField("rtladsb.device.common",
                TrackerElementFactory<rtladsb_tracked_common>(),
                "Common RTLADSB device info");

    rtladsb_adsb_id =
        Globalreg::globalreg->entrytracker->RegisterField("rtladsb.device.adsb",
                TrackerElementFactory<rtladsb_tracked_adsb>(),
                "RTLADSB adsb");

    // Make the manuf string
    rtl_manuf = Globalreg::globalreg->manufdb->MakeManuf("RTLADSB");

    // Register js module for UI
    auto httpregistry =
        Globalreg::FetchMandatoryGlobalAs<Kis_Httpd_Registry>();
    httpregistry->register_js_module("kismet_ui_rtladsb", "js/kismet.ui.rtladsb.js");

	packetchain->RegisterHandler(&PacketHandler, this, CHAINPOS_CLASSIFIER, -100);
}

Kis_RTLADSB_Phy::~Kis_RTLADSB_Phy() {
    packetchain->RemoveHandler(&PacketHandler, CHAINPOS_CLASSIFIER);
}

mac_addr Kis_RTLADSB_Phy::json_to_mac(Json::Value json) {
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

    *checksum = Adler32Checksum(smodel.c_str(), smodel.length());

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

bool Kis_RTLADSB_Phy::json_to_rtl(Json::Value json, kis_packet *packet) {
    std::string err;
    std::string v;

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
    common->phyid = FetchPhyId();
    common->datasize = 0;

    // If this json record has a channel
    if (json.isMember("channel")) {
        Json::Value c = json["channel"];
        if (c.isNumeric()) {
            common->channel = IntToString(c.asInt());
        } else if (c.isString()) {
            common->channel = MungeToPrintable(c.asString());
        }
    }

    common->freq_khz = 1090000;
    common->source = rtlmac;
    common->transmitter = rtlmac;

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->UpdateCommonDevice(common, common->source, this, packet,
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
    basedev->set_devicename(dn);

    auto rtlholder = basedev->get_sub_as<TrackerElementMap>(rtladsb_holder_id);
    bool newrtl = false;

    if (rtlholder == NULL) {
        rtlholder =
            std::make_shared<TrackerElementMap>(rtladsb_holder_id);
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
            commondev->set_rtlchannel(IntToString(channel_j.asInt()));
        else if (channel_j.isString())
            commondev->set_rtlchannel(MungeToPrintable(channel_j.asString()));
    }

    if (is_adsb(json))
        add_adsb(json, rtlholder);

    if (newrtl && commondev != NULL) {
        std::string info = "Detected new RTLADSB RF device '" + commondev->get_model() + "'";

        if (commondev->get_rtlid() != "") 
            info += " ID " + commondev->get_rtlid();

        if (commondev->get_rtlchannel() != "0")
            info += " Channel " + commondev->get_rtlchannel();

        _MSG(info, MSGFLAG_INFO);
    }

    return true;
}

bool Kis_RTLADSB_Phy::is_adsb(Json::Value json) {

    //fprintf(stderr, "RTLADSB: checking to see if it is a adsb\n");
    auto icao_j = json["icao"];

    if (!icao_j.isNull()) {
        return true;
    }

    return false;
}

void Kis_RTLADSB_Phy::add_adsb(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder) {
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
                adsbdev->set_callsign(callsign_j.asString());
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
    }
}

int Kis_RTLADSB_Phy::PacketHandler(CHAINCALL_PARMS) {
    Kis_RTLADSB_Phy *rtladsb = (Kis_RTLADSB_Phy *) auxdata;

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

