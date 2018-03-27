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

#include "phy_rtl433.h"
#include "devicetracker.h"
#include "kismet_json.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"

Kis_RTL433_Phy::Kis_RTL433_Phy(GlobalRegistry *in_globalreg,
        Devicetracker *in_tracker, int in_phyid) :
    Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid) {

    SetPhyName("RTL433");

    packetchain =
        Globalreg::FetchGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");
    entrytracker =
        Globalreg::FetchGlobalAs<EntryTracker>(globalreg, "ENTRY_TRACKER");

	pack_comp_common = 
		packetchain->RegisterPacketComponent("COMMON");
    pack_comp_rtl433 = 
        packetchain->RegisterPacketComponent("RTL433JSON");

    rtl433_holder_id =
        entrytracker->RegisterField("rtl433.device", TrackerMap, 
                "rtl_433 device");

    std::shared_ptr<rtl433_tracked_common> commonbuilder(new rtl433_tracked_common(globalreg, 0));
    rtl433_common_id =
        entrytracker->RegisterField("rtl433.device.common",
                commonbuilder, "Shared RTL433 device info");

    std::shared_ptr<rtl433_tracked_thermometer> thermbuilder(new rtl433_tracked_thermometer(globalreg, 0));
    rtl433_thermometer_id =
        entrytracker->RegisterField("rtl433.device.thermometer",
                thermbuilder, "RTL433 thermometer");

    std::shared_ptr<rtl433_tracked_weatherstation> weatherbuilder(new rtl433_tracked_weatherstation(globalreg, 0));
    rtl433_weatherstation_id =
        entrytracker->RegisterField("rtl433.device.weatherstation",
                weatherbuilder, "RTL433 weather station");

    // Register js module for UI
    std::shared_ptr<Kis_Httpd_Registry> httpregistry = 
        Globalreg::FetchGlobalAs<Kis_Httpd_Registry>(globalreg, "WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_rtl433", 
            "/js/kismet.ui.rtl433.js");

	packetchain->RegisterHandler(&PacketHandler, this, CHAINPOS_CLASSIFIER, -100);
}

Kis_RTL433_Phy::~Kis_RTL433_Phy() {
    packetchain->RemoveHandler(&PacketHandler, CHAINPOS_CLASSIFIER);
}

double Kis_RTL433_Phy::f_to_c(double f) {
    return (f - 32) / (double) 1.8f;
}

mac_addr Kis_RTL433_Phy::json_to_mac(Json::Value json) {
    // Derive a mac addr from the model and device id data
    //
    // We turn the model string into 4 bytes using the adler32 checksum,
    // then we use the model as a (potentially) 16bit int
    //
    // Finally we set the locally assigned bit on the first octet

    uint8_t bytes[6];
    uint16_t *model = (uint16_t *) bytes;
    uint32_t *checksum = (uint32_t *) (bytes + 2);

    std::string smodel = "unk";

    if (json.isMember("model")) {
        Json::Value m = json["model"];
        if (m.isString()) {
            smodel = m.asString();
        }
    }

    *checksum = Adler32Checksum(smodel.c_str(), smodel.length());

    bool set_model = false;
    if (json.isMember("id")) {
        Json::Value i = json["id"];
        if (i.isNumeric()) {
            *model = kis_hton16((uint16_t) i.asUInt());
            set_model = true;
        }
    }

    if (!set_model && json.isMember("device")) {
        Json::Value d = json["device"];
        if (d.isNumeric()) {
            *model = kis_hton16((uint16_t) d.asUInt());
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

bool Kis_RTL433_Phy::json_to_rtl(Json::Value json) {
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

    common->freq_khz = 433920;
    common->source = rtlmac;
    common->transmitter = rtlmac;

    pack->insert(pack_comp_common, common);

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->UpdateCommonDevice(common, common->source, this, pack,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "Sensor");

    // Get rid of our pseudopacket
    delete(pack);

    std::string dn = "Sensor";

    if (json.isMember("model")) {
        dn = MungeToPrintable(json["model"].asString());
    }

    basedev->set_manuf("RTL433");

    basedev->set_type_string("RTL433 Sensor");
    basedev->set_devicename(dn);

    SharedTrackerElement rtlholder = basedev->get_map_value(rtl433_holder_id);

    bool newrtl = false;

    if (rtlholder == NULL) {
        rtlholder = entrytracker->GetTrackedInstance(rtl433_holder_id);
        basedev->add_map(rtlholder);
        newrtl = true;
    }

    std::shared_ptr<rtl433_tracked_common> commondev = 
        std::static_pointer_cast<rtl433_tracked_common>(rtlholder->get_map_value(rtl433_common_id));

    if (commondev == NULL) {
        commondev = 
            std::static_pointer_cast<rtl433_tracked_common>(entrytracker->GetTrackedInstance(rtl433_common_id));
        rtlholder->add_map(commondev);

        commondev->set_model(dn);

        bool set_id = false;
        if (json.isMember("id")) {
            Json::Value id_j = json["id"];
            if (id_j.isNumeric()) {
                std::stringstream ss;
                ss << id_j.asUInt64();
                commondev->set_rtlid(ss.str());
                set_id = true;
            } else if (id_j.isString()) {
                commondev->set_rtlid(id_j.asString());
                set_id = true;
            }
        }

        if (!set_id && json.isMember("device")) {
            Json::Value device_j = json["device"];
            if (device_j.isNumeric()) {
                std::stringstream ss;
                ss << device_j.asUInt64();
                commondev->set_rtlid(ss.str());
                set_id = true;
            } else if (device_j.isString()) {
                commondev->set_rtlid(device_j.asString());
                set_id = true;
            }
        }

        if (!set_id) {
            commondev->set_rtlid(0);
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

    if (json.isMember("battery")) {
        auto battery_j = json["battery"];

        if (battery_j.isString())
            commondev->set_battery(MungeToPrintable(battery_j.asString()));
    }

    auto humidity_j = json["humidity"];
    auto moisture_j = json["moisture"];
    auto temp_f_j = json["temperature_F"];
    auto temp_c_j = json["temperature_C"];

    if (!humidity_j.isNull() || !moisture_j.isNull() || !temp_f_j.isNull() || !temp_c_j.isNull()) {
        std::shared_ptr<rtl433_tracked_thermometer> thermdev = 
            std::static_pointer_cast<rtl433_tracked_thermometer>(rtlholder->get_map_value(rtl433_thermometer_id));

        if (thermdev == NULL) {
            thermdev = 
                std::static_pointer_cast<rtl433_tracked_thermometer>(entrytracker->GetTrackedInstance(rtl433_thermometer_id));
            rtlholder->add_map(thermdev);
        }

        if (humidity_j.isNumeric()) {
            thermdev->set_humidity(humidity_j.asInt());
        }

        if (moisture_j.isNumeric()) {
            thermdev->set_humidity(moisture_j.asInt());
        }

        if (temp_f_j.isNumeric()) {
            thermdev->set_temperature(f_to_c(temp_f_j.asInt()));
        }

        if (temp_c_j.isNumeric()) {
            thermdev->set_temperature(temp_c_j.asInt());
        }
    }

    auto direction_j = json["direction_deg"];
    auto windstrength_j = json["windstrength"];
    auto winddirection_j = json["winddirection"];
    auto windspeed_j = json["speed"];
    auto gust_j = json["gust"];
    auto rain_j = json["rain"];
    auto uv_index_j = json["uv_index"];
    auto lux_j = json["lux"];

    if (!direction_j.isNull() || !windstrength_j.isNull() || !winddirection_j.isNull() ||
            !windspeed_j.isNull() || !gust_j.isNull() || !rain_j.isNull() || !uv_index_j.isNull() ||
            !lux_j.isNull()) {

        std::shared_ptr<rtl433_tracked_weatherstation> weatherdev = 
            std::static_pointer_cast<rtl433_tracked_weatherstation>(rtlholder->get_map_value(rtl433_weatherstation_id));

        if (weatherdev == NULL) {
            weatherdev = 
                std::static_pointer_cast<rtl433_tracked_weatherstation>(entrytracker->GetTrackedInstance(rtl433_weatherstation_id));
            rtlholder->add_map(weatherdev);
        }

        if (direction_j.isNumeric()) {
            weatherdev->set_wind_dir(direction_j.asInt());
            weatherdev->get_wind_dir_rrd()->add_sample(direction_j.asInt(), time(0));
        }

        if (winddirection_j.isNumeric()) {
            weatherdev->set_wind_dir(winddirection_j.asInt());
            weatherdev->get_wind_dir_rrd()->add_sample(winddirection_j.asInt(), time(0));
        }

        if (windspeed_j.isNumeric()) {
            weatherdev->set_wind_speed((int32_t) windspeed_j.asInt());
            weatherdev->get_wind_speed_rrd()->add_sample((int64_t) windspeed_j.asInt(), time(0));
        }

        if (windstrength_j.isNumeric()) {
            weatherdev->set_wind_speed((int32_t) windstrength_j.asInt());
            weatherdev->get_wind_speed_rrd()->add_sample((int64_t) windstrength_j.asInt(),
                    time(0));
        }

        if (gust_j.isNumeric()) {
            weatherdev->set_wind_gust((int32_t) gust_j.asInt());
            weatherdev->get_wind_gust_rrd()->add_sample((int64_t) gust_j.asInt(), time(0));
        }

        if (rain_j.isNumeric()) {
            weatherdev->set_rain((int32_t) rain_j.asInt());
            weatherdev->get_rain_rrd()->add_sample((int64_t) rain_j.asInt(), time(0));
        }

        if (uv_index_j.isNumeric()) {
            weatherdev->set_uv_index((int32_t) uv_index_j.asInt());
            weatherdev->get_uv_index_rrd()->add_sample((int64_t) uv_index_j.asInt(), time(0));
        }

        if (lux_j.isNumeric()) {
            weatherdev->set_lux((int32_t) lux_j.asInt());
            weatherdev->get_lux_rrd()->add_sample((int64_t) lux_j.asInt(), time(0));
        }

    }

    if (newrtl && commondev != NULL) {
        std::string info = "Detected new RTL433 RF device '" + commondev->get_model() + "'";

        if (commondev->get_rtlid() != "") 
            info += " ID " + commondev->get_rtlid();

        if (commondev->get_rtlchannel() != "0")
            info += " Channel " + commondev->get_rtlchannel();

        _MSG(info, MSGFLAG_INFO);
    }

    return true;
}

int Kis_RTL433_Phy::PacketHandler(CHAINCALL_PARMS) {
    Kis_RTL433_Phy *rtl433 = (Kis_RTL433_Phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    packet_info_rtl433 *rtlinfo = (packet_info_rtl433 *) in_pack->fetch(rtl433->pack_comp_rtl433);
    if (rtlinfo == NULL)
        return 0;

    rtl433->json_to_rtl(rtlinfo->json);

    return 1;
}

