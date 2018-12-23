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
#include "kismet_json.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "manuf.h"

Kis_RTLAMR_Phy::Kis_RTLAMR_Phy(GlobalRegistry *in_globalreg, int in_phyid) :
    Kis_Phy_Handler(in_globalreg, in_phyid) {

    SetPhyName("RTLAMR");

    packetchain =
        Globalreg::FetchMandatoryGlobalAs<Packetchain>();
    entrytracker =
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>();

	pack_comp_common = 
		packetchain->RegisterPacketComponent("COMMON");
    pack_comp_json = 
        packetchain->RegisterPacketComponent("JSON");
    pack_comp_meta =
        packetchain->RegisterPacketComponent("METABLOB");

    rtlamr_holder_id =
        Globalreg::globalreg->entrytracker->RegisterField("rtlamr.device", 
                TrackerElementFactory<TrackerElementMap>(),
                "rtl_amr device");

    rtlamr_common_id =
        Globalreg::globalreg->entrytracker->RegisterField("rtlamr.device.common",
                TrackerElementFactory<rtlamr_tracked_common>(),
                "Common RTLAMR device info");

    rtlamr_powermeter_id =
        Globalreg::globalreg->entrytracker->RegisterField("rtlamr.device.powermeter",
                TrackerElementFactory<rtlamr_tracked_powermeter>(),
                "RTLAMR powermeter");

    // Make the manuf string
    rtl_manuf = Globalreg::globalreg->manufdb->MakeManuf("RTLAMR");

    // Register js module for UI
    std::shared_ptr<Kis_Httpd_Registry> httpregistry = 
        Globalreg::FetchGlobalAs<Kis_Httpd_Registry>(globalreg, "WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_rtlamr", "/js/kismet.ui.rtlamr.js");

	packetchain->RegisterHandler(&PacketHandler, this, CHAINPOS_CLASSIFIER, -100);
}

Kis_RTLAMR_Phy::~Kis_RTLAMR_Phy() {
    packetchain->RemoveHandler(&PacketHandler, CHAINPOS_CLASSIFIER);
}

//double Kis_RTLAMR_Phy::f_to_c(double f) {
//    return (f - 32) / (double) 1.8f;
//}

mac_addr Kis_RTLAMR_Phy::json_to_mac(Json::Value json) {
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

    if (json.isMember("model")) {
        Json::Value m = json["model"];
        if (m.isString()) {
            smodel = m.asString();
        }
    }

    *checksum = Adler32Checksum(smodel.c_str(), smodel.length());

    bool set_model = false;
    if (json.isMember("Message")) {
      auto msgjson = json["Message"];
    

      if (msgjson.isMember("ID")) {
          Json::Value i = msgjson["ID"];
          if (i.isNumeric()) {
              *model = kis_hton16((uint16_t) i.asUInt());
              set_model = true;
          }
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

bool Kis_RTLAMR_Phy::json_to_rtl(Json::Value json) {
    std::string err;
    std::string v;

    // synth a mac out of it
    mac_addr rtlmac = json_to_mac(json);

    if (rtlmac.error) {
        return false;
    }

    // To interact with devicetracker we (currently) need to turn this into
    // something that looks vaguely like a packet
    kis_packet *pack = new kis_packet(globalreg);

    pack->ts.tv_sec = globalreg->timestamp.tv_sec;
    pack->ts.tv_usec = globalreg->timestamp.tv_usec;

    kis_common_info *common = new kis_common_info();

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

    common->freq_khz = 912600;
    common->source = rtlmac;
    common->transmitter = rtlmac;

    pack->insert(pack_comp_common, common);

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->UpdateCommonDevice(common, common->source, this, pack,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "RTLAMR Sensor");

    local_locker bssidlock(&(basedev->device_mutex));

    // Get rid of our pseudopacket
    delete(pack);

    std::string dn = "PowerMeter";

    if (json.isMember("Message")) {
        auto msgjson = json["Message"];
        if (msgjson.isMember("ID")) {
            auto id_j = msgjson["ID"];
            if (id_j.isString()) {
                dn = id_j.asString();
            }
        }
    }

    basedev->set_manuf(rtl_manuf);

    basedev->set_type_string("RTLAMR PowerMeter");
    basedev->set_devicename(dn);

    auto rtlholder = basedev->get_sub_as<TrackerElementMap>(rtlamr_holder_id);
    bool newrtl = false;

    if (rtlholder == NULL) {
        rtlholder =
            std::make_shared<TrackerElementMap>(rtlamr_holder_id);
        basedev->insert(rtlholder);
        newrtl = true;
    }

    auto commondev =
        rtlholder->get_sub_as<rtlamr_tracked_common>(rtlamr_common_id);

    if (commondev == NULL) {
        commondev =
            std::make_shared<rtlamr_tracked_common>(rtlamr_common_id);
        rtlholder->insert(commondev);

        commondev->set_model(dn);

        bool set_id = false;
        //std::fprintf(stderr, "RTLAMR: ID? %d\n", json["Message"]["ID"]);
        if (json.isMember("Message")) {
          //std::fprintf(stderr, "RTLAMR: Detected Message\n");
	  auto msgjson = json["Message"];
          if (msgjson.isMember("ID")) {
              //std::fprintf(stderr, "RTLAMR: ID Detected\n");
              Json::Value id_j = msgjson["ID"];
              //std::fprintf(stderr, "RTLAMR: ID? %d\n", id_j);
              if (id_j.isNumeric()) {
                  std::stringstream ss;
                  //ss << id_j.asDouble();
                  ss << id_j.asString();
                  commondev->set_rtlid(ss.str());
                  set_id = true;
              } else if (id_j.isString()) {
                  commondev->set_rtlid(id_j.asString());
                  set_id = true;
              }
          }

          if (!set_id && msgjson.isMember("Consumption")) {
              Json::Value consumption_j = msgjson["Consumption"];
              //std::fprintf(stderr, "RTLAMR: Consumption Detected\n");
              //std::fprintf(stderr, "RTLAMR: Consumption? %d\n", consumption_j);
              if (consumption_j.isNumeric()) {
                  std::stringstream ss;
                  ss << consumption_j.asDouble();
                  commondev->set_rtlid(ss.str());
                  set_id = true;
              } else if (consumption_j.isString()) {
                  commondev->set_rtlid(consumption_j.asString());
                  set_id = true;
              }
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

    if (is_powermeter(json))
        add_powermeter(json, rtlholder);

    //fprintf(stderr, "RTLAMR: doin something here\n");

    if (newrtl && commondev != NULL) {
        std::string info = "Detected new RTLAMR RF device '" + commondev->get_model() + "'";

        if (commondev->get_rtlid() != "") 
            info += " ID " + commondev->get_rtlid();

        if (commondev->get_rtlchannel() != "0")
            info += " Channel " + commondev->get_rtlchannel();

        _MSG(info, MSGFLAG_INFO);
    }

    return true;
}

bool Kis_RTLAMR_Phy::is_powermeter(Json::Value json) {

    //fprintf(stderr, "RTLAMR: checking to see if it is a powermeter\n");
    auto msgjson = json["Message"];
    auto id_j = msgjson["ID"];
    auto consumption_j = msgjson["Consumption"];

    //std::fprintf(stderr, "RTLAMR: is_powermeter ID / Consumption  %d  %d\n", id_j, consumption_j);

    if (!id_j.isNull() || !consumption_j.isNull()) {
        return true;
    }

    return false;
}

void Kis_RTLAMR_Phy::add_powermeter(Json::Value json, std::shared_ptr<TrackerElementMap> rtlholder) {
    auto msgjson = json["Message"];
    auto id_j = msgjson["ID"];
    auto consumption_j = msgjson["Consumption"];

    //fprintf(stderr, "RTLAMR: Detected new powermeter\n");

    if (!id_j.isNull() || !consumption_j.isNull()) {
        auto powermeterdev = 
            rtlholder->get_sub_as<rtlamr_tracked_powermeter>(rtlamr_powermeter_id);

        if (powermeterdev == NULL) {
            powermeterdev = 
                std::make_shared<rtlamr_tracked_powermeter>(rtlamr_powermeter_id);
            rtlholder->insert(powermeterdev);
        }

        if (id_j.isNumeric()) {
            powermeterdev->set_id(id_j.asDouble());
        }

        if (consumption_j.isNumeric()) {
            powermeterdev->set_consumption(consumption_j.asDouble());
        }

    }
}



int Kis_RTLAMR_Phy::PacketHandler(CHAINCALL_PARMS) {
    Kis_RTLAMR_Phy *rtlamr = (Kis_RTLAMR_Phy *) auxdata;

    //fprintf(stderr, "RTLAMR: packethandler kicked in\n");

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    kis_json_packinfo *json = in_pack->fetch<kis_json_packinfo>(rtlamr->pack_comp_json);
    if (json == NULL)
        return 0;

    //std::fprintf(stderr, "RTLAMR: json type: %s\n", json->type.c_str());
    

    if (json->type != "RTLamr")
        return 0;

    std::stringstream ss(json->json_string);
    Json::Value device_json;

    try {
        ss >> device_json;

        //std::fprintf(stderr, "RTLAMR: json? %s\n", json->json_string.c_str());
        //std::fprintf(stderr, "RTLAMR: json? %s\n", device_json);
        // Copy the JSON as the meta field for logging, if it's valid
        if (rtlamr->json_to_rtl(device_json)) {
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

