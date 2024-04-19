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

#include "phy_sensor.h"
#include "devicetracker.h"
#include "endian_magic.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "manuf.h"
#include "messagebus.h"
#include "phy_meter.h"

kis_sensor_phy::kis_sensor_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("RFSENSOR");

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

    sensor_holder_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device", 
                tracker_element_factory<tracker_element_map>(),
                "rtl_433 device");

    sensor_common_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.common",
                tracker_element_factory<sensor_tracked_common>(),
                "Common sensor device info");

    sensor_thermometer_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.thermometer",
                tracker_element_factory<sensor_tracked_thermometer>(),
                "sensor - thermometer");

    sensor_tpms_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.tpms",
                tracker_element_factory<sensor_tracked_tpms>(),
                "sensor - TPMS tire pressure");
    
    sensor_weatherstation_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.weatherstation",
                tracker_element_factory<sensor_tracked_weatherstation>(),
                "sensor - weather station");

    sensor_switch_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.switch",
                tracker_element_factory<sensor_tracked_switch>(),
                "sensor - power switch");

    sensor_insteon_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.insteon",
                tracker_element_factory<sensor_tracked_insteon>(),
                "sensor - Insteon Device");

    sensor_lightning_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.lightningsensor",
                tracker_element_factory<sensor_tracked_lightningsensor>(),
                "sensor - lightning sensor");

    sensor_moisture_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.moisturesensor",
                tracker_element_factory<sensor_tracked_moisture>(),
                "sensor - moisture");

    sensor_aqi_id =
        Globalreg::globalreg->entrytracker->register_field("sensor.device.aqi",
                tracker_element_factory<sensor_tracked_aqi>(),
                "sensor - aqi");

    // Make the manuf string
    sensor_manuf = Globalreg::globalreg->manufdb->make_manuf("RF Sensor");

    // Register js module for UI
    auto httpregistry =
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_sensor", "js/kismet.ui.sensor.js");

	packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    track_last_record = 
        Globalreg::globalreg->kismet_config->fetch_opt_bool("rtl433_track_last", false);
}

kis_sensor_phy::~kis_sensor_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

double kis_sensor_phy::f_to_c(double f) {
    return (f - 32) / (double) 1.8f;
}

mac_addr kis_sensor_phy::json_to_mac(nlohmann::json json) {
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

    try {
        smodel = json["model"].get<std::string>();
    } catch (...) { }

    *checksum = adler32_checksum(smodel.c_str(), smodel.length());

    bool set_model = false;

    auto idmem = json["id"];
    if (idmem.is_number()) {
        *model = kis_hton16((uint16_t) idmem.get<unsigned int>());
        set_model = true;
    } else if (idmem.is_string()) {
        smodel = munge_to_printable(idmem.get<std::string>());
        *checksum = adler32_checksum(smodel);
        *model = kis_hton16((uint16_t) *checksum);
        set_model = true;
    }

    auto fromid = json["from_id"];
    if (fromid.is_string()) {
        smodel = munge_to_printable(fromid.get<std::string>());
        *checksum = adler32_checksum(smodel);
        *model = kis_hton16((uint16_t) *checksum);
        set_model = true;
    }

    if (!set_model && !json["device"].is_null()) {
        auto d = json["device"];
        if (d.is_number()) {
            *model = kis_hton16((uint16_t) d.get<unsigned int>());
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

bool kis_sensor_phy::json_to_rtl(nlohmann::json json, std::shared_ptr<kis_packet> packet) {
    std::string err;
    std::string v;

    // synth a mac out of it
    mac_addr rtlmac = json_to_mac(json);

    if (rtlmac.state.error) {
        return false;
    }

    auto common = packet->fetch<kis_common_info>(pack_comp_common);

    if (common == NULL) {
        common = std::make_shared<kis_common_info>();
        packet->insert(pack_comp_common, common);
    }

    common->type = packet_basic_data;
    common->phyid = fetch_phy_id();
    common->datasize = 0;

    // If this json record has a channel
    auto channel_j = json["channel"];

    if (channel_j.is_string())
        common->channel = munge_to_printable(channel_j);
    else if (channel_j.is_number()) 
        common->channel = fmt::format("{}", channel_j.get<int>());

    auto freq_j = json["freq"];

    if (!freq_j.is_number())
        freq_j = json["freq1"];

    if (!freq_j.is_number())
        freq_j = json["freq2"];

    if (freq_j.is_number() && freq_j.get<double>() != 0) {
        common->freq_khz = freq_j.get<double>() * 1000;
    }

    common->source = rtlmac;
    common->transmitter = rtlmac;

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(common, common->source, this, packet,
                (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY), "RF Sensor");

    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "sensor_json_to_rtl");

    std::string dn = "Sensor";

    if (json["model"].is_string()) {
        if (json["id"].is_string()) {
            dn = fmt::format("{}-{}", munge_to_printable(json["model"]), 
                    munge_to_printable(json["id"]));
        } else if (json["id"].is_number()) {
            dn = fmt::format("{}-{}", munge_to_printable(json["model"]), 
                    json["id"].get<unsigned int>());
        } else {
            dn = munge_to_printable(json["model"]);
        }
    } else if (json["id"].is_string()) {
        dn = munge_to_printable(json["id"]);
    } else if (json["id"].is_number()) {
        dn = fmt::format("{}", json["id"].get<unsigned int>());
    }

    basedev->set_manuf(sensor_manuf);

    basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("Sensor"));
    basedev->set_devicename(dn);

    auto rtlholder = basedev->get_sub_as<tracker_element_map>(sensor_holder_id);
    bool newrtl = false;

    if (rtlholder == NULL) {
        // make_shared valid here becausse it's just a map
        rtlholder = std::make_shared<tracker_element_map>(sensor_holder_id);
        basedev->insert(rtlholder);
        newrtl = true;
    }

    auto commondev =
        rtlholder->get_sub_as<sensor_tracked_common>(sensor_common_id);

    if (commondev == NULL) {
        commondev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_common>(sensor_common_id);
        rtlholder->insert(commondev);

        commondev->set_model(dn);

        bool set_id = false;
        auto id_j = json["id"];

        if (id_j.is_number())
            commondev->set_rtlid(fmt::format("{}", id_j.get<int>()));
        else if (id_j.is_string()) {
            commondev->set_rtlid(munge_to_printable(id_j));
            set_id = true;
        }

        if (!set_id) {
            auto device_j = json["device"];

            if (device_j.is_number())
                commondev->set_rtlid(fmt::format("{}", device_j.get<int>()));
            else if (device_j.is_string()) {
                commondev->set_rtlid(munge_to_printable(device_j));
                set_id = true;
            }

        }

        if (!set_id) {
            commondev->set_rtlid("");
        }

        commondev->set_subchannel("0");
    }

    if (track_last_record) {
        auto pkt_json = packet->fetch<kis_json_packinfo>(pack_comp_json);
        commondev->set_lastrecord(pkt_json->json_string);
    }


    if (channel_j.is_number())
        commondev->set_subchannel(fmt::format("{}", channel_j.get<int>()));
    else if (channel_j.is_string())
        commondev->set_subchannel(munge_to_printable(channel_j));
    

    auto battery_j = json["battery"];
    if (battery_j.is_null()) {
        battery_j = json["battery_ok"];
    }

    if (battery_j.is_string()) {
        commondev->set_battery(munge_to_printable(battery_j));
    } else if (battery_j.is_number()) {
        commondev->set_battery(fmt::format("{}", battery_j.get<double>()));
    } else if (battery_j.is_boolean()) {
        commondev->set_battery(fmt::format("{}", battery_j.get<bool>()));
    }

    auto rssi_j = json["rssi"];
    if (rssi_j.is_number())
        commondev->set_rssi(fmt::format("{}", rssi_j.get<int>()));
    else if (rssi_j.is_string())
        commondev->set_rssi(munge_to_printable(rssi_j));

    auto snr_j = json["snr"];
    if (snr_j.is_number())
        commondev->set_snr(fmt::format("{}", snr_j.get<int>()));
    else if (snr_j.is_string())
        commondev->set_snr(munge_to_printable(snr_j));


    auto noise_j = json["noise"];
    if (noise_j.is_number())
        commondev->set_noise(fmt::format("{}", noise_j.get<int>()));
    else if (noise_j.is_string())
        commondev->set_noise(munge_to_printable(noise_j));

    if (is_thermometer(json))
        add_thermometer(json, rtlholder);

    if (is_moisture(json))
        add_moisture(json, rtlholder);

    if (is_weather_station(json))
        add_weather_station(json, rtlholder);

    if (is_tpms(json))
        add_tpms(json, rtlholder);

    if (is_switch(json))
        add_switch(json, rtlholder);

    if (is_insteon(json))
        add_insteon(json, rtlholder);

    if (is_lightning(json))
        add_lightning(json, rtlholder);

    if (is_aqi(json))
        add_aqi(json, rtlholder);

    if (newrtl && commondev != NULL) {
        std::string info = "Detected new RF sensor device '" + commondev->get_model() + "'";

        if (commondev->get_rtlid() != "") 
            info += " ID " + commondev->get_rtlid();

        if (commondev->get_subchannel() != "0")
            info += " Channel " + commondev->get_subchannel();

        _MSG(info, MSGFLAG_INFO);
    }

    return true;
}

bool kis_sensor_phy::is_weather_station(nlohmann::json json) {
    if (!json["direction_deg"].is_null())
        return true;

    if (!json["windstrength"].is_null())
        return true;

    if (!json["winddirection"].is_null())
        return true;

    if (!json["wind_dir_deg"].is_null())
        return true;

    if (!json["wind_avg_km_h"].is_null())
        return true;

    if (!json["wind_max_km_h"].is_null())
        return true;

    if (!json["speed"].is_null())
        return true;

    if (!json["gust"].is_null())
        return true;

    if (!json["rain"].is_null())
        return true;

    if (!json["rain_mm"].is_null())
        return true;

    if (!json["rain_raw"].is_null())
        return true;

    if (!json["uv_index"].is_null())
        return true;

    if (!json["lux"].is_null())
        return true;

    return false;
}

bool kis_sensor_phy::is_thermometer(nlohmann::json json) {
    if (!json["temperature_F"].is_null())
        return true;

    if (!json["temperature_C"].is_null())
        return true;

    return false;
}

bool kis_sensor_phy::is_tpms(nlohmann::json json) {
    try {
        return json["type"] == "TPMS";

    } catch (...) {
        return false;
    }

    return false;
}

bool kis_sensor_phy::is_switch(nlohmann::json json) {
    if (!json["switch0"].is_null())
        return true;

    if (!json["switch1"].is_null())
        return true;

    if (!json["switch1"].is_null())
        return true;

    if (!json["switch2"].is_null())
        return true;

    if (!json["switch3"].is_null())
        return true;

    if (!json["switch4"].is_null())
        return true;

    if (!json["switch5"].is_null())
        return true;

    if (!json["switch6"].is_null())
        return true;

    return false;
}

bool kis_sensor_phy::is_insteon(nlohmann::json json) {
    if (!json["from_id"].is_null())
        return true;

    if (!json["to_id"].is_null())
        return true;

    if (!json["msg_type"].is_null())
        return true;

    if (!json["msg_str"].is_null())
        return true;

    if (!json["hopsmax"].is_null())
        return true;

    if (!json["hopsleft"].is_null())
        return true;

    return false;
}

bool kis_sensor_phy::is_lightning(nlohmann::json json) {
    if (!json["strike_count"].is_null())
        return true;

    if (!json["storm_dist"].is_null())
        return true;

    if (!json["active"].is_null())
        return true;

    if (!json["rfi"].is_null())
        return true;

    return false;
}

bool kis_sensor_phy::is_moisture(nlohmann::json json) {
    if (!json["moisture"].is_null())
        return true;

    if (!json["humidity"].is_null())
        return true;

    return false;
}

bool kis_sensor_phy::is_aqi(nlohmann::json json) {
    if (!json["pm2_5_ug_m3"].is_null())
        return true;

    if (!json["estimated_pm10_0_ug_m3"].is_null())
        return true;

    return false;
}

void kis_sensor_phy::add_weather_station(nlohmann::json json, 
        std::shared_ptr<tracker_element_map> rtlholder) {
    auto uv_index_j = json["uv_index"];
    auto lux_j = json["lux"];

    auto weatherdev = 
        rtlholder->get_sub_as<sensor_tracked_weatherstation>(sensor_weatherstation_id);

    if (weatherdev == nullptr) {
        weatherdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_weatherstation>(sensor_weatherstation_id);
        rtlholder->insert(weatherdev);
    }

    // {"time": "2023-07-13 18:31:29", "model": "Fineoffset-WHx080", "subtype": 0, "id": 129, "battery_ok": 1, "temperature_C": 30.9, "humidity": 50, "wind_dir_deg": 180, "wind_avg_km_h": 2.448, "wind_max_km_h": 4.896, "rain_mm": 0.0, "mic": "CRC", "mod": "ASK", "freq": 433.861, "rssi": -0.13, "snr": 15.077, "noise": -15.207}

    try {
        weatherdev->set_wind_dir(json["winddirection"].get<double>());
        weatherdev->get_wind_dir_rrd()->add_sample(json["winddirection"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        weatherdev->set_wind_dir(json["wind_dir_deg"].get<double>());
        weatherdev->get_wind_dir_rrd()->add_sample(json["wind_dir_deg"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        weatherdev->set_wind_speed(json["windspeed"].get<double>());
        weatherdev->get_wind_speed_rrd()->add_sample(json["windspeed"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        weatherdev->set_wind_speed(json["windstrength"].get<double>());
        weatherdev->get_wind_speed_rrd()->add_sample(json["windstrength"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        weatherdev->set_wind_speed(json["wind_avg_km_h"].get<double>());
        weatherdev->get_wind_speed_rrd()->add_sample(json["wind_avg_km_h"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        weatherdev->set_wind_speed(json["speed"].get<double>());
        weatherdev->get_wind_speed_rrd()->add_sample(json["speed"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        weatherdev->set_wind_gust(json["gust"].get<double>());
        weatherdev->get_wind_gust_rrd()->add_sample(json["gust"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        weatherdev->set_wind_gust(json["wind_max_km_h"].get<double>());
        weatherdev->get_wind_gust_rrd()->add_sample(json["wind_max_km_h"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    if (json["rain"].is_number()) {
        try {
            weatherdev->set_rain(json["rain"].get<double>());
            weatherdev->get_rain_rrd()->add_sample(json["rain"].get<double>(), Globalreg::globalreg->last_tv_sec);
        } catch (...) { }
    } else if (json["rain_mm"].is_number()) {
        try {
            weatherdev->set_rain(json["rain_mm"].get<double>());
            weatherdev->get_rain_rrd()->add_sample(json["rain_mm"].get<double>(), 
                    Globalreg::globalreg->last_tv_sec);
        } catch (...) { }
    }

    try {
        weatherdev->set_rain_raw(json["rain_raw"].get<double>());
    } catch (...) { }

    try {
        weatherdev->set_uv_index(json["uv_index"].get<double>());
        weatherdev->get_uv_index_rrd()->add_sample(json["uv_index"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        weatherdev->set_lux(json["lux"].get<double>());
        weatherdev->get_lux_rrd()->add_sample(json["lux"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

}

void kis_sensor_phy::add_thermometer(nlohmann::json json, std::shared_ptr<tracker_element_map> rtlholder) {
    auto thermdev = 
        rtlholder->get_sub_as<sensor_tracked_thermometer>(sensor_thermometer_id);

    if (thermdev == NULL) {
        thermdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_thermometer>(sensor_thermometer_id);
        rtlholder->insert(thermdev);
    }

    try {
        thermdev->set_temperature(f_to_c(json["temperature_F"].get<double>()));
        thermdev->get_temperature_rrd()->add_sample(f_to_c(json["temperature_F"].get<double>()), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        thermdev->set_temperature(json["temperature_C"].get<double>());
        thermdev->get_temperature_rrd()->add_sample(json["temperature_C"].get<double>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

}

void kis_sensor_phy::add_tpms(nlohmann::json json, std::shared_ptr<tracker_element_map> rtlholder) {
    //{"time" : "2023-06-12 11:16:48", "model" : "Schrader-EG53MA4", "type" : "TPMS", "flags" : "4d930078", "id" : "891932", "pressure_kPa" : 220.000, "temperature_F" : 103.000, "mic" : "CHECKSUM", "mod" : "ASK", "freq" : 314.931, "rssi" : -2.296, "snr" : 6.350, "noise" : -8.646}
    //{"time" : "2023-06-12 20:30:58", "model" : "Toyota", "type" : "TPMS", "id" : "da22b333", "status" : 128, "pressure_PSI" : 30.250, "temperature_C" : 20.000, "mic" : "CRC", "mod" : "FSK", "freq1" : 315.009, "freq2" : 314.962, "rssi" : -6.950, "snr" : 26.163, "noise" : -33.113} 
    auto tpmsdev = 
        rtlholder->get_sub_as<sensor_tracked_tpms>(sensor_tpms_id);

    if (tpmsdev == NULL) {
        tpmsdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_tpms>(sensor_tpms_id);
        rtlholder->insert(tpmsdev);
    }

    try {
        tpmsdev->set_temperature(f_to_c(json["temperature_F"].get<double>()));
    } catch (...) { }

    try {
        tpmsdev->set_temperature(json["temperature_C"].get<double>());
    } catch (...) { }

    try {
        tpmsdev->set_pressure_psi(json["pressure_PSI"].get<double>());
    } catch (...) { }

    try {
        tpmsdev->set_pressure_bar(json["pressure_bar"].get<double>());
    } catch (...) { }

    try {
        tpmsdev->set_pressure_kpa(json["pressure_kPa"].get<double>());
    } catch (...) { }

    try {
        tpmsdev->set_flags(munge_to_printable(json["flags"]));
    } catch (...) { }

    try {
        tpmsdev->set_checksum(munge_to_printable(json["mic"]));
    } catch (...) { }

    try {
        tpmsdev->set_state(munge_to_printable(json["state"]));
    } catch (...) { }

    try {
        tpmsdev->set_code(munge_to_printable(json["code"]));
    } catch (...) { }

}

void kis_sensor_phy::add_switch(nlohmann::json json, std::shared_ptr<tracker_element_map> rtlholder) {
    //{"time" : "2021-08-18 16:16:54", "model" : "Interlogix-Security", "subtype" : "contact", "id" : "a55b4b", "battery_ok" : 1, "switch1" : "OPEN", "switch2" : "OPEN", "switch3" : "OPEN", "switch4" : "OPEN", "switch5" : "OPEN", "raw_message" : "2dd4ac"}

    auto switchdev = 
        rtlholder->get_sub_as<sensor_tracked_switch>(sensor_switch_id);

    if (switchdev == nullptr) {
        switchdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_switch>(sensor_switch_id);
        rtlholder->insert(switchdev);
    }

    try {
        switchdev->set_switch1(munge_to_printable(json["switch1"]));
    } catch (...) { }

    try {
        switchdev->set_switch2(munge_to_printable(json["switch2"]));
    } catch (...) { }

    try {
        switchdev->set_switch3(munge_to_printable(json["switch3"]));
    } catch (...) { }

    try {
        switchdev->set_switch4(munge_to_printable(json["switch4"]));
    } catch (...) { }

    try {
        switchdev->set_switch5(munge_to_printable(json["switch5"]));
    } catch (...) { }

    /*
    auto model_j = json["model"];
    auto subtype_j = json["subtype"];
    auto battery_j = json["battery_ok"];
    auto msg_j = json["raw_message"];
    auto sw_id = json["id"];
    */
    
}

void kis_sensor_phy::add_insteon(nlohmann::json json, std::shared_ptr<tracker_element_map> rtlholder) {
    //{"time" : "2021-08-19 18:52:48", "model" : "Insteon", "from_id" : "CCFF79", "to_id" : "9F39E6", "msg_type" : 7, "msg_str" : "NAK of Group Cleanup Direct Message", "extended" : 0, "hopsmax" : 3, "hopsleft" : 0, "formatted" : "E3 : 9F39E6 : CCFF79 : 39 E7  B7", "mic" : "CRC", "payload" : "E3E6399F79FFCC39E7B7", "cmd_dat" : [57, 231], "mod" : "FSK", "freq1" : 914.909, "freq2" : 915.069, "rssi" : -0.212, "snr" : 25.305, "noise" : -25.517}
    
    auto insteondev =
            rtlholder->get_sub_as<sensor_tracked_insteon>(sensor_insteon_id);

    if (insteondev == NULL) {
        insteondev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_insteon>(sensor_insteon_id);
        rtlholder->insert(insteondev);
    }

    try {
        insteondev->set_from_id(munge_to_printable(json["from_id"]));
    } catch (...) { }

    try {
        insteondev->set_to_id(munge_to_printable(json["to_id"]));
    } catch (...) { }

    try {
        insteondev->set_msg_type(munge_to_printable(json["msg_type"]));
    } catch (...) { }

    try {
        insteondev->set_msg_str(munge_to_printable(json["msg_str"]));
    } catch (...) { }

    try {
        insteondev->set_hopsmax(munge_to_printable(json["hopsmax"]));
    } catch (...) { }

    try {
        insteondev->set_hopsleft(munge_to_printable(json["hopsleft"]));
    } catch (...) { }
}


void kis_sensor_phy::add_lightning(nlohmann::json json, std::shared_ptr<tracker_element_map> rtlholder) {
    // {"time" : "2019-02-24 22:12:13", "model" : "Acurite Lightning 6045M", "id" : 15580, "channel" : "B", "temperature_F" : 38.300, "humidity" : 53, "strike_count" : 1, "storm_dist" : 8, "active" : 1, "rfi" : 0, "ussb1" : 0, "battery" : "OK", "exception" : 0, "raw_msg" : "bcdc6f354edb81886e"}
    
    auto lightningdev = 
        rtlholder->get_sub_as<sensor_tracked_lightningsensor>(sensor_lightning_id);

    if (lightningdev == NULL) {
        lightningdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_lightningsensor>(sensor_lightning_id);
        rtlholder->insert(lightningdev);
    }

    try {
        lightningdev->set_strike_count(json["strike_count"].get<unsigned int>());
        lightningdev->get_strike_count_rrd()->add_sample(json["strike_count"].get<unsigned int>(), Globalreg::globalreg->last_tv_sec);
    } catch (...) { }

    try {
        lightningdev->set_storm_distance(json["storm_dist"].get<uint64_t>());
    } catch (...) { }

    try {
        lightningdev->set_storm_active(json["active"].get<unsigned int>());
    } catch (...) { }

    try {
        lightningdev->set_lightning_rfi(json["rfi"].get<unsigned int>());
    } catch (...) { }

}

void kis_sensor_phy::add_moisture(nlohmann::json json, std::shared_ptr<tracker_element_map> rtlholder) {
    auto mdev = 
        rtlholder->get_sub_as<sensor_tracked_moisture>(sensor_moisture_id);

    if (mdev == nullptr) {
        mdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_moisture>(sensor_moisture_id);
        rtlholder->insert(mdev);
    }

    if (json["moisture"].is_number()) {
        try {
            mdev->set_moisture(json["moisture"].get<unsigned int>());
            mdev->get_moisture_rrd()->add_sample(json["moisture"].get<unsigned int>(), Globalreg::globalreg->last_tv_sec);
        } catch (...) { }
    }

    if (json["humidity"].is_number()) {
        try {
            mdev->set_moisture(json["humidity"].get<unsigned int>());
            mdev->get_moisture_rrd()->add_sample(json["humidity"].get<unsigned int>(), Globalreg::globalreg->last_tv_sec);
        } catch (...) { }
    }

}

void kis_sensor_phy::add_aqi(nlohmann::json json, std::shared_ptr<tracker_element_map> rtlholder) {
    auto mdev = 
        rtlholder->get_sub_as<sensor_tracked_aqi>(sensor_aqi_id);

    if (mdev == nullptr) {
        mdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<sensor_tracked_aqi>(sensor_aqi_id);
        rtlholder->insert(mdev);
    }

    if (json["pm2_5_ug_m3"].is_number()) {
        try {
            mdev->set_pm2_5(json["pm2_5_ug_m3"].get<unsigned int>());
            mdev->get_pm2_5_rrd()->add_sample(json["pm2_5_ug_m3"].get<unsigned int>(), Globalreg::globalreg->last_tv_sec);
        } catch (...) { }
    }

    if (json["estimated_pm10_0_ug_m3"].is_number()) {
        try {
            mdev->set_pm10(json["estimated_pm10_0_ug_m3"].get<unsigned int>());
            mdev->get_pm10_rrd()->add_sample(json["estimated_pm10_0_ug_m3"].get<unsigned int>(), Globalreg::globalreg->last_tv_sec);
        } catch (...) { }
    }

}


int kis_sensor_phy::packet_handler(CHAINCALL_PARMS) {
    kis_sensor_phy *sensor = (kis_sensor_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto json = in_pack->fetch<kis_json_packinfo>(sensor->pack_comp_json);
    if (json == NULL)
        return 0;

    if (json->type != "RTL433")
        return 0;

    std::stringstream ss(json->json_string);
    nlohmann::json device_json;

    try {
        ss >> device_json;

        // Manually exclude other phys that also use rtl433 data
        if (kis_meter_phy::is_meter(device_json))
            return 0;

        // _MSG_DEBUG("RTL433 data: {}", json->json_string);

        // Copy the JSON as the meta field for logging, if it's valid
        if (sensor->json_to_rtl(device_json, in_pack)) {
            auto metablob = in_pack->fetch<packet_metablob>(sensor->pack_comp_meta);
            if (metablob == nullptr) {
                metablob = std::make_shared<packet_metablob>("sensor", json->json_string);
                in_pack->insert(sensor->pack_comp_meta, metablob);
            }
        }
    } catch (std::exception& e) {
        _MSG_DEBUG("RTL json error: {}", e.what());
        // fprintf(stderr, "debug - error processing rtl json %s\n", e.what());
        return 0;
    }

    return 1;
}

