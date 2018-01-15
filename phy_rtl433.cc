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
    Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid),
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {

    SetPhyName("RTL433");

    packetchain =
        Globalreg::FetchGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");
    entrytracker =
        Globalreg::FetchGlobalAs<EntryTracker>(globalreg, "ENTRY_TRACKER");

	pack_comp_common = 
		packetchain->RegisterPacketComponent("COMMON");

    rtl433_holder_id =
        entrytracker->RegisterField("rtl433.device", TrackerMap, 
                "rtl_433 device");

    shared_ptr<rtl433_tracked_common> commonbuilder(new rtl433_tracked_common(globalreg, 0));
    rtl433_common_id =
        entrytracker->RegisterField("rtl433.device.common",
                commonbuilder, "Shared RTL433 device info");

    shared_ptr<rtl433_tracked_thermometer> thermbuilder(new rtl433_tracked_thermometer(globalreg, 0));
    rtl433_thermometer_id =
        entrytracker->RegisterField("rtl433.device.thermometer",
                thermbuilder, "RTL433 thermometer");

    shared_ptr<rtl433_tracked_weatherstation> weatherbuilder(new rtl433_tracked_weatherstation(globalreg, 0));
    rtl433_weatherstation_id =
        entrytracker->RegisterField("rtl433.device.weatherstation",
                weatherbuilder, "RTL433 weather station");

    // Register js module for UI
    shared_ptr<Kis_Httpd_Registry> httpregistry = 
        Globalreg::FetchGlobalAs<Kis_Httpd_Registry>(globalreg, "WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_rtl433", 
            "/js/kismet.ui.rtl433.js");

}

Kis_RTL433_Phy::~Kis_RTL433_Phy() {

}

bool Kis_RTL433_Phy::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/phy/phyRTL433/post_sensor_json.cmd") == 0)
            return true;
    }

    return false;
}

double Kis_RTL433_Phy::f_to_c(double f) {
    return (f - 32) / (double) 1.8f;
}

mac_addr Kis_RTL433_Phy::json_to_mac(cppjson::json json) {
    // Derive a mac addr from the model and device id data
    //
    // We turn the model string into 4 bytes using the adler32 checksum,
    // then we use the model as a (potentially) 16bit int
    //
    // Finally we set the locally assigned bit on the first octet

    uint8_t bytes[6];
    uint16_t *model = (uint16_t *) bytes;
    uint32_t *checksum = (uint32_t *) (bytes + 2);

    auto model_j = json.find("model");
    auto id_j = json.find("id");
    auto device_j = json.find("device");

    std::string smodel = "unk";

    if (model_j != json.end() && model_j.value().is_string()) {
        smodel = model_j.value().get<std::string>();
    }
    *checksum = Adler32Checksum(smodel.c_str(), smodel.length());

    if (id_j != json.end() && id_j.value().is_number()) {
        *model = 
            kis_hton16((uint16_t) id_j.value().get<unsigned int>());
    } else if (device_j != json.end() && device_j.value().is_number()) {
        *model =
            kis_hton16((uint16_t) device_j.value().get<unsigned int>());
    } else {
        *model = 0x0000;
    }

    // Set the local bit
    bytes[0] |= 0x2;

    return mac_addr(bytes, 6);
}

bool Kis_RTL433_Phy::json_to_rtl(cppjson::json json) {
    string err;
    string v;

    if (json == NULL)
        return false;

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
    auto channel_j = json.find("channel");

    if (channel_j != json.end() && channel_j.value().is_number()) {
        common->channel = IntToString(channel_j.value().get<int>());
    }

    common->freq_khz = 433920;
    common->source = rtlmac;
    common->transmitter = rtlmac;

    pack->insert(pack_comp_common, common);

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->UpdateCommonDevice(common, common->source, this, pack,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY));

    // Get rid of our pseudopacket
    delete(pack);

    std::string dn = "Sensor";
    auto model_j = json.find("model");

    if (model_j != json.end() && model_j.value().is_string()) {
        dn = MungeToPrintable(model_j.value().get<std::string>());
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

    shared_ptr<rtl433_tracked_common> commondev = 
        static_pointer_cast<rtl433_tracked_common>(rtlholder->get_map_value(rtl433_common_id));

    if (commondev == NULL) {
        commondev = 
            static_pointer_cast<rtl433_tracked_common>(entrytracker->GetTrackedInstance(rtl433_common_id));
        rtlholder->add_map(commondev);

        commondev->set_model(dn);

        auto id_j = json.find("id");
        auto device_j = json.find("device");

        if (id_j != json.end() && id_j.value().is_number()) {
            commondev->set_rtlid((uint64_t) id_j.value().get<unsigned long>());
        } else if (device_j != json.end() && device_j.value().is_number()) {
            commondev->set_rtlid((uint64_t) device_j.value().get<unsigned long>());
        } else {
            commondev->set_rtlid(0);
        }

        commondev->set_rtlchannel("0");
    }

    if (channel_j != json.end() && channel_j.value().is_number()) {
        commondev->set_rtlchannel(IntToString(channel_j.value().get<int>()));
    }

    auto battery_j = json.find("battery");

    if (battery_j != json.end() && battery_j.value().is_string()) {
        commondev->set_battery(MungeToPrintable(battery_j.value().get<std::string>()));
    }

    auto humidity_j = json.find("humidity");
    auto temp_c_j = json.find("temperature_C");
    auto temp_f_j = json.find("temperature_F");

    if (humidity_j != json.end() || temp_c_j != json.end() || temp_f_j != json.end()) {
        shared_ptr<rtl433_tracked_thermometer> thermdev = 
            static_pointer_cast<rtl433_tracked_thermometer>(rtlholder->get_map_value(rtl433_thermometer_id));

        if (thermdev == NULL) {
            thermdev = 
                static_pointer_cast<rtl433_tracked_thermometer>(entrytracker->GetTrackedInstance(rtl433_thermometer_id));
            rtlholder->add_map(thermdev);
        }


        if (humidity_j != json.end() && humidity_j.value().is_number()) {
            thermdev->set_humidity((int32_t) humidity_j.value().get<int>());
        }

        if (temp_f_j != json.end() && temp_f_j.value().is_number()) 
            thermdev->set_temperature(f_to_c(temp_f_j.value().get<double>()));

        if (temp_c_j != json.end() && temp_c_j.value().is_number())
            thermdev->set_temperature(temp_c_j.value().get<double>());
    }

    auto direction_j = json.find("direction_deg");
    auto windstrength_j = json.find("windstrength");
    auto winddirection_j = json.find("winddirection");
    auto windspeed_j = json.find("speed");
    auto gust_j = json.find("gust");
    auto rain_j = json.find("rain");

    if (direction_j != json.end() || windstrength_j != json.end() ||
            winddirection_j != json.end() || windspeed_j != json.end() ||
            gust_j != json.end() || rain_j != json.end()) {

        shared_ptr<rtl433_tracked_weatherstation> weatherdev = 
            static_pointer_cast<rtl433_tracked_weatherstation>(rtlholder->get_map_value(rtl433_weatherstation_id));

        if (weatherdev == NULL) {
            weatherdev = 
                static_pointer_cast<rtl433_tracked_weatherstation>(entrytracker->GetTrackedInstance(rtl433_weatherstation_id));
            rtlholder->add_map(weatherdev);
        }

        if (direction_j != json.end() && direction_j.value().is_number()) {
            weatherdev->set_wind_dir((int32_t) direction_j.value().get<int>());
            weatherdev->get_wind_dir_rrd()->add_sample((int64_t) direction_j.value().get<int>(),
                    time(0));
        }

        if (winddirection_j != json.end() && winddirection_j.value().is_number()) {
            weatherdev->set_wind_dir((int32_t) winddirection_j.value().get<int>());
            weatherdev->get_wind_dir_rrd()->add_sample((int64_t) winddirection_j.value().get<int>(),
                    time(0));
        }

        if (windspeed_j != json.end() && windspeed_j.value().is_number()) {
            weatherdev->set_wind_speed((int32_t) windspeed_j.value().get<int>());
            weatherdev->get_wind_speed_rrd()->add_sample((int64_t) windspeed_j.value().get<int>(),
                    time(0));
        }

        if (windstrength_j != json.end() && windstrength_j.value().is_number()) {
            weatherdev->set_wind_speed((int32_t) windstrength_j.value().get<int>());
            weatherdev->get_wind_speed_rrd()->add_sample((int64_t) windstrength_j.value().get<int>(),
                    time(0));
        }

        if (gust_j != json.end() && gust_j.value().is_number()) {
            weatherdev->set_wind_gust((int32_t) gust_j.value().get<int>());
            weatherdev->get_wind_gust_rrd()->add_sample((int64_t) gust_j.value().get<int>(),
                    time(0));
        }

        if (rain_j != json.end() && rain_j.value().is_number()) {
            weatherdev->set_rain((int32_t) rain_j.value().get<int>());
            weatherdev->get_rain_rrd()->add_sample((int64_t) rain_j.value().get<int>(),
                    globalreg->timestamp.tv_sec);
        }

    }

    if (newrtl && commondev != NULL) {
        string info = "Detected new RTL433 RF device '" + commondev->get_model() + "'";

        if (commondev->get_rtlid() != 0) 
            info += " ID " + IntToString(commondev->get_rtlid());

        if (commondev->get_rtlchannel() != "0")
            info += " Channel " + commondev->get_rtlchannel();

        _MSG(info, MSGFLAG_INFO);
    }

    return true;
}

void Kis_RTL433_Phy::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    return;
}


int Kis_RTL433_Phy::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {

    // Anything involving POST here requires a login
    if (!httpd->HasValidSession(concls, true)) {
        return 1;
    }

    bool handled = false;

    if (concls->url != "/phy/phyRTL433/post_sensor_json.cmd")
        return 1;
   
    if (concls->variable_cache.find("obj") != concls->variable_cache.end()) {
        cppjson::json json;

        try {
            json = cppjson::json::parse(concls->variable_cache["obj"]->str());
        } catch (std::exception& e) {
            concls->response_stream << "Invalid request: could not parse JSON: " <<
                e.what();
            concls->httpcode = 400;
            return 1;
        }

        // If we can't make sense of it, blow up
        if (!json_to_rtl(json)) {
            concls->response_stream << 
                "Invalid request:  could not convert to RTL device";
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
        concls->response_stream << "OK";
    }

    return 1;
}

