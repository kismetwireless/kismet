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

#ifndef __PHY_MESHTASTIC_H__
#define __PHY_MESHTASTIC_H__

#include "config.h"

#include "datasourcetracker.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "kis_net_beast_httpd.h"
#include "phyhandler.h"
#include "trackedelement.h"

#include "aes_ctr.h"
#include "protobuf_decode.h"

// meshtastic messages are an aes-ctr-128 or aes-ctr-256 encrypted protobuf
//
// we decode the protobuf piecemeal from the wire, we don't want to touch
// packaging protobufs back into kismet


class tracked_meshtastic_node : public tracker_component {
public:
    tracked_meshtastic_node() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_meshtastic_node(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_meshtastic_node(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_meshtastic_node");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

protected:
    virtual void register_fields() override {

        register_field("meshtastic.node.nodeid", "Node id", &nodeid_);
        register_field("meshtastic.node.longname", "Node long name", &longname_);
        register_field("meshtastic.node.shortname", "Node short name", &shortname_);

        register_field("meshtastic.node.role", "Meshtastic role (raw int)", &role_);

        register_field("meshtastic.node.manuf", "Manufacturer (raw int id)", &manuf_id_);

        register_field("meshtastic.node.telem.timestamp", "Epoch timestamp", &telem_ts_);
        register_field("meshtastic.node.telem.battery", "Battery percentage", &telem_battery_perc_);
        register_field("meshtastic.node.telem.voltage", "Battery voltage", &telem_battery_voltage_);
        register_field("meshtastic.node.telem.chan_util", "Channel utilization", &telem_chan_util_);
        register_field("meshtastic.node.telem.chan_tx_util", "Channel tx utilization", &telem_chan_tx_util_);
        register_field("meshtastic.node.telem.uptime", "Uptime (seconds)", &telem_uptime_sec_);
    }

    std::shared_ptr<tracker_element_string> nodeid_;

    std::shared_ptr<tracker_element_uint32> role_;

    std::shared_ptr<tracker_element_string> longname_;
    std::shared_ptr<tracker_element_string> shortname_;

    std::shared_ptr<tracker_element_uint32> manuf_id_;

    std::shared_ptr<tracker_element_uint64> telem_ts_;
    std::shared_ptr<tracker_element_uint16> telem_battery_perc_;
    std::shared_ptr<tracker_element_float> telem_battery_voltage_;
    std::shared_ptr<tracker_element_float> telem_chan_util_;
    std::shared_ptr<tracker_element_float> telem_chan_tx_util_;
    std::shared_ptr<tracker_element_uint64> telem_uptime_sec_;

    friend class kis_meshtastic_phy;
};


class kis_meshtastic_phy : public kis_phy_handler {
public:
    virtual ~kis_meshtastic_phy();

    kis_meshtastic_phy() :
        kis_phy_handler() { }

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_meshtastic_phy(in_phyid);
    }

    kis_meshtastic_phy(int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

protected:
    std::shared_ptr<datasource_tracker> datasourcetracker;

    mac_addr mesh_to_mac(uint32_t meshid);

    // lorapipe formated rx
    bool process_lorapipe(nlohmann::json& json, const std::shared_ptr<kis_packet>& packet);

    // obnoxious huge list of model names
    std::shared_ptr<tracker_element_string> model_tlora_v2;
    std::shared_ptr<tracker_element_string> model_tlora_v1;
    std::shared_ptr<tracker_element_string> model_tlora_v2_1_1p6;
    std::shared_ptr<tracker_element_string> model_tbeam;
    std::shared_ptr<tracker_element_string> model_heltec_v2_0;
    std::shared_ptr<tracker_element_string> model_tbeam_v0p7;
    std::shared_ptr<tracker_element_string> model_t_echo;
    std::shared_ptr<tracker_element_string> model_tlora_v1_1p3;
    std::shared_ptr<tracker_element_string> model_rak4631;
    std::shared_ptr<tracker_element_string> model_heltec_v2_1;
    std::shared_ptr<tracker_element_string> model_heltec_v1;
    std::shared_ptr<tracker_element_string> model_lilygo_tbeam_s3_core;
    std::shared_ptr<tracker_element_string> model_rak11200;
    std::shared_ptr<tracker_element_string> model_nano_g1;
    std::shared_ptr<tracker_element_string> model_tlora_v2_1_1p8;
    std::shared_ptr<tracker_element_string> model_tlora_t3_s3;
    std::shared_ptr<tracker_element_string> model_nano_g1_explorer;
    std::shared_ptr<tracker_element_string> model_nano_g2_ultra;
    std::shared_ptr<tracker_element_string> model_lora_type;
    std::shared_ptr<tracker_element_string> model_station_g1;
    std::shared_ptr<tracker_element_string> model_rak11310;
    std::shared_ptr<tracker_element_string> model_senselora_s3;
    std::shared_ptr<tracker_element_string> model_canaryone;
    std::shared_ptr<tracker_element_string> model_rp2040_lora;
    std::shared_ptr<tracker_element_string> model_station_g2;
    std::shared_ptr<tracker_element_string> model_lora_relay_v1;
    std::shared_ptr<tracker_element_string> model_nrf52840dk;
    std::shared_ptr<tracker_element_string> model_ppr;
    std::shared_ptr<tracker_element_string> model_genieblocks;
    std::shared_ptr<tracker_element_string> model_nrf52_unknown;
    std::shared_ptr<tracker_element_string> model_portuino;
    std::shared_ptr<tracker_element_string> model_android_sim;
    std::shared_ptr<tracker_element_string> model_diy_v1;
    std::shared_ptr<tracker_element_string> model_nrf52840_pca10059;
    std::shared_ptr<tracker_element_string> model_dr_dev;
    std::shared_ptr<tracker_element_string> model_m5stack;
    std::shared_ptr<tracker_element_string> model_heltec_v3;
    std::shared_ptr<tracker_element_string> model_heltec_wsl_v3;
    std::shared_ptr<tracker_element_string> model_betafpv_2400_tx;
    std::shared_ptr<tracker_element_string> model_betafpv_900_nano_tx;
    std::shared_ptr<tracker_element_string> model_rpi_pico;
    std::shared_ptr<tracker_element_string> model_heltec_wireless_tracker;
    std::shared_ptr<tracker_element_string> model_heltec_wireless_paper;
    std::shared_ptr<tracker_element_string> model_t_deck;
    std::shared_ptr<tracker_element_string> model_t_watch_s3;
    std::shared_ptr<tracker_element_string> model_picomputer_s3;
    std::shared_ptr<tracker_element_string> model_heltec_ht62;
    std::shared_ptr<tracker_element_string> model_ebyte_esp32_s3;
    std::shared_ptr<tracker_element_string> model_esp32_s3_pico;
    std::shared_ptr<tracker_element_string> model_chatter2;
    std::shared_ptr<tracker_element_string> model_heltec_wireless_paper_v1_0;
    std::shared_ptr<tracker_element_string> model_heltec_wireless_tracker_v1_0;

public:
    // default meshtastic key
    const uint8_t default_key[16] = {
        0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
        0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
    };

    enum class meshtastic_portnum {
        unknown = 0,
        text_message = 1,
        remote_hardware = 2,
        position = 3,
        nodeinfo = 4,
        routing = 5,
        admin = 6,
        text_message_compressed = 7,
        waypoint = 8,
        audio = 9,
        detection_sensor = 10,
        reply = 32,
        ip_tunnel = 33,
        paxcounter = 34,
        serial = 64,
        store_forward = 65,
        range_test = 66,
        telemetry = 67,
        zps = 68,
        simulator = 69,
        traceroute = 70,
        neighborinfo = 71,
        atak = 72,
        map_report = 73,
        private_app = 256,
        atak_forwarder = 257,
        max = 511,
    };

    enum class meshtastic_data_pb {
        fn_unknown = 0,

        fn_portnum = 1, // int, meshtastic_portnum enum
        fn_payload = 2, // bytes
        fn_want_response = 3, // int(bool)
        fn_dest = 4, // int32
        fn_source = 5, // int32
        fn_request_id = 6, // int32
        fn_reply_id = 7, // int32
        fn_emoji = 8, // int32
    };

    enum class meshtastic_hw_model {
        unset = 0,
        tlora_v2 = 1,
        tlora_v1 = 2,
        tlora_v2_1_1p6 = 3,
        tbeam = 4,
        heltec_v2_0 = 5,
        tbeam_v0p7 = 6,
        t_echo = 7,
        tlora_v1_1p3 = 8,
        rak4631 = 9,
        heltec_v2_1 = 10,
        heltec_v1 = 11,
        lilygo_tbeam_s3_core = 12,
        rak11200 = 13,
        nano_g1 = 14,
        tlora_v2_1_1p8 = 15,
        tlora_t3_s3 = 16,
        nano_g1_explorer = 17,
        nano_g2_ultra = 18,
        lora_type = 19,
        station_g1 = 25,
        rak11310 = 26,
        senselora_s3 = 28,
        canaryone = 29,
        rp2040_lora = 30,
        station_g2 = 31,
        lora_relay_v1 = 32,
        nrf52840dk = 33,
        ppr = 34,
        genieblocks = 35,
        nrf52_unknown = 36,
        portuino = 37,
        android_sim = 38,
        diy_v1 = 39,
        nrf52840_pca10059 = 40,
        dr_dev = 41,
        m5stack = 42,
        heltec_v3 = 43,
        heltec_wsl_v3 = 44,
        betafpv_2400_tx = 45,
        betafpv_900_nano_tx = 46,
        rpi_pico = 47,
        heltec_wireless_tracker = 48,
        heltec_wireless_paper = 49,
        t_deck = 50,
        t_watch_s3 = 51,
        picomputer_s3 = 52,
        heltec_ht62 = 53,
        ebyte_esp32_s3 = 54,
        esp32_s3_pico = 55,
        chatter2 = 56,
        heltec_wireless_paper_v1_0 = 57,
        heltec_wireless_tracker_v1_0 = 58,
        private_hw = 255,
    };

    enum class meshtastic_user_pb {
        fn_unknown = 0,

        fn_id = 1, // string
        fn_long_name = 2, // string
        fn_short_name = 3, // string
        fn_macaddr = 4, // bytes, deprecated
        fn_hw_model = 5, // int, hw_model enum
        fn_is_licensed = 6, // int(bool)
        fn_role = 7, // enum deviceconfig
    };

    enum class meshtastic_loc_source {
        unset = 0,
        manual = 1,
        internal = 2,
        external = 3,
    };

    enum class meshtastic_alt_source {
        unset = 0,
        manual = 1,
        internal = 2,
        external = 3,
        barometric = 4,
    };

    enum class meshtastic_position_pb {
        fn_unknown = 0,

        fn_latitude_i = 1, // fixed32, multiply by 1e-7
        fn_longitude_i = 2, // fixed32, multiply by 1e-7
        fn_altitude = 3, // int32, meters
        fn_time = 4, // fixed32
        fn_location_source = 5, // int, enum meshtastic_alt_source
        fn_altitude_source = 6, // int, enum meshtastic_alt_source
        fn_timestamp = 7, // fixed32, epoch seconds
        fn_timestamp_millis_adjust = 8, // int32
        fn_altitude_hae = 9, // int32, meters
        fn_altitude_geoidal_separation = 10, // sint32
        fn_pdop = 11, // uint32 1/100 units pdop=sqrt(hdop^2 + vdop^2)
        fn_hdop = 12, // uint32
        fn_vdop = 13, // uint32
        fn_gps_accuracy = 14, // uint32 accuracy in mm
        fn_ground_speed = 15, // uint32 m/s
        fn_ground_track = 16, // uint32 north track in 1/100 degrees
        fn_fix_quality = 17, // uint32 gps fix quality
        fn_fix_type = 18, // uint32 gps 2d/3d gxgsa
        fn_sats_in_view = 19, // uint32
        fn_sensor_id = 20, // uint32
        fn_next_update = 21, // uint32 time in seconds to update
        fn_seq_number = 22, // uint32
        fn_precision_bits = 23, // uint32
    };

    enum class meshtastic_nodeinfo_pb {
        fn_unknown = 0,

        fn_num = 1, // uint32
        fn_user = 2, // bytes meshtastic_user_pb,
        fn_position = 3, // bytes meshtastic_position_pb,
        fn_snr = 4, // float
        fn_last_heard = 5, // fixed32
        fn_device_metrics = 6, // bytes devicemetrics
        fn_channels = 7, // uint32
        fn_via_mqtt = 8, // uint32 (bool)
        fn_via_hops_away = 9, // uint32
    };

    enum class meshtastic_devicemetrics_pb {
        fn_unknown = 0,

        fn_battery_level = 1, // uint32
        fn_voltage = 2, // float
        fn_channel_utilization = 3, // float
        fn_air_util_tx = 4, // float
        fn_uptime_seconds = 5, // uint32
    };

    enum class meshtastic_environmentmetrics_pb {
        fn_unknown = 0,

        fn_temperature = 1, // float
        fn_relative_humidity = 2, // float
        fn_barometric_pressure = 3, // float, hPA
        fn_gas_resistance = 4, // float, mOhm
        fn_voltage = 5, // float, deprecated
        fn_current = 6, // float, deprecated
    };

    enum class meshtastic_powermetrics_pb {
        fn_unknown = 0,

        fn_ch1_voltage = 1, // float
        fn_ch1_current = 2, // float
        fn_ch2_voltage = 3, // float
        fn_ch2_current = 4, // float
        fn_ch3_voltage = 5, // float
        fn_ch3_current = 6, // float
    };

    enum class meshtastic_airqualitymetrics_pb {
        fn_unknown = 0,

        fn_pm10_standard = 1, // uint32
        fn_pm25_standard = 2, // uint32
        fn_pm100_standard = 3, // uint32
        fn_pm10_environmental = 4, // uint32
        fn_pm25_environmental = 5, // uint32
        fn_pm100_environmental = 6, // uint32
        fn_particles_u3um = 7, // uint32
        fn_particles_u5um = 8, // uint32
        fn_particles_10um = 9, // uint32
        fn_particles_25um = 10, // uint32
        fn_particles_50um = 11, // uint32
        fn_particles_100um = 12, // uint32
    };

    enum class meshtastic_telemetry_pb {
        fn_unknown = 0,

        fn_time = 1, // fixed32
        fn_device_metrics = 2, // bytes, meshtastic_devicemetrics_pb
        fn_environment_metrics = 3, // bytes, meshtastic_environmentmetrics_pb
        fn_airquality_metrics = 4, // bytes, meshtastic_airqualitymetrics_pb
        fn_power_metrics = 5, // bytes, meshtastic_powermetrics_pb
    };

};

#endif /* __PHY_MESHTASTIC_H__ */
