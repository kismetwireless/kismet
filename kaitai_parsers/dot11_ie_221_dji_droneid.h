#ifndef DOT11_IE_221_DJI_DRONEID_H_
#define DOT11_IE_221_DJI_DRONEID_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

/**
 * Drone ID is a standard packet addition proposed by DJI which includes
 * drone identification and telemetry information.  For Wi-Fi drones, 
 * this is put in an IE tag in the standard IEEE802.11 beacon frames,
 * under the OUI 26:37:12.
 * 
 * Two packet types can be sent; packets with a subcommand of 0x10
 * include flight telemetry and location, while packets with a subcommand
 * of 0x11 include user-entered information about the drone and
 * the flight.
 * 
 * The DroneID format was decoded by
 *   Freek van Tienen <freek.v.tienen@gmail.com>
 *   and
 *   Jan Dumon <jan@crossbar.net>
 * 
 * and more details on the packet internals can be found at
 * https://github.com/fvantienen
 */

class dot11_ie_221_dji_droneid_t : public kaitai::kstruct {

public:
    class flight_purpose_t;
    class flight_reg_info_t;
    class state_t;

    dot11_ie_221_dji_droneid_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_dji_droneid_t* p_root = 0);
    ~dot11_ie_221_dji_droneid_t();

    class flight_purpose_t : public kaitai::kstruct {

    public:

        flight_purpose_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_dji_droneid_t* p_root = 0);
        ~flight_purpose_t();

    private:
        std::string m_serialnumber;
        uint64_t m_len;
        std::string m_drone_id;
        uint64_t m_purpose_len;
        std::string m_purpose;
        dot11_ie_221_dji_droneid_t* m__root;
        kaitai::kstruct* m__parent;

    public:
        std::string serialnumber() const { return m_serialnumber; }
        uint64_t len() const { return m_len; }
        std::string drone_id() const { return m_drone_id; }
        uint64_t purpose_len() const { return m_purpose_len; }
        std::string purpose() const { return m_purpose; }
        dot11_ie_221_dji_droneid_t* _root() const { return m__root; }
        kaitai::kstruct* _parent() const { return m__parent; }
    };

    class flight_reg_info_t : public kaitai::kstruct {

    public:

        flight_reg_info_t(kaitai::kstream* p_io, dot11_ie_221_dji_droneid_t* p_parent = 0, dot11_ie_221_dji_droneid_t* p_root = 0);
        ~flight_reg_info_t();

    private:
        bool f_roll;
        double m_roll;

    public:
        double roll();

    private:
        bool f_home_lon;
        double m_home_lon;

    public:
        double home_lon();

    private:
        bool f_lat;
        double m_lat;

    public:
        double lat();

    private:
        bool f_home_lat;
        double m_home_lat;

    public:
        double home_lat();

    private:
        bool f_lon;
        double m_lon;

    public:
        double lon();

    private:
        bool f_yaw;
        double m_yaw;

    public:
        double yaw();

    private:
        bool f_pitch;
        double m_pitch;

    public:
        double pitch();

    private:
        uint8_t m_version;
        uint16_t m_seq;
        state_t* m_state_info;
        std::string m_serialnumber;
        int32_t m_raw_lon;
        int32_t m_raw_lat;
        int16_t m_altitude;
        int16_t m_height;
        int16_t m_v_north;
        int16_t m_v_east;
        int16_t m_v_up;
        int16_t m_raw_pitch;
        int16_t m_raw_roll;
        int16_t m_raw_yaw;
        int32_t m_raw_home_lon;
        int32_t m_raw_home_lat;
        uint8_t m_product_type;
        uint8_t m_uuid_len;
        std::string m_uuid;
        dot11_ie_221_dji_droneid_t* m__root;
        dot11_ie_221_dji_droneid_t* m__parent;

    public:
        uint8_t version() const { return m_version; }
        uint16_t seq() const { return m_seq; }
        state_t* state_info() const { return m_state_info; }
        std::string serialnumber() const { return m_serialnumber; }
        int32_t raw_lon() const { return m_raw_lon; }
        int32_t raw_lat() const { return m_raw_lat; }
        int16_t altitude() const { return m_altitude; }
        int16_t height() const { return m_height; }
        int16_t v_north() const { return m_v_north; }
        int16_t v_east() const { return m_v_east; }
        int16_t v_up() const { return m_v_up; }
        int16_t raw_pitch() const { return m_raw_pitch; }
        int16_t raw_roll() const { return m_raw_roll; }
        int16_t raw_yaw() const { return m_raw_yaw; }
        int32_t raw_home_lon() const { return m_raw_home_lon; }
        int32_t raw_home_lat() const { return m_raw_home_lat; }
        uint8_t product_type() const { return m_product_type; }
        uint8_t uuid_len() const { return m_uuid_len; }
        std::string uuid() const { return m_uuid; }
        dot11_ie_221_dji_droneid_t* _root() const { return m__root; }
        dot11_ie_221_dji_droneid_t* _parent() const { return m__parent; }
    };

    class state_t : public kaitai::kstruct {

    public:

        state_t(kaitai::kstream* p_io, dot11_ie_221_dji_droneid_t::flight_reg_info_t* p_parent = 0, dot11_ie_221_dji_droneid_t* p_root = 0);
        ~state_t();

    private:
        bool m_unk_alt_valid;
        bool m_unk_gps_valid;
        bool m_in_air;
        bool m_motor_on;
        bool m_uuid_set;
        bool m_homepoint_set;
        bool m_private_disabled;
        bool m_serial_valid;
        bool m_unk15;
        bool m_unk14;
        bool m_unk13;
        bool m_unk12;
        bool m_unk11;
        bool m_unk_velocity_z_valid;
        bool m_unk_velocity_x_valid;
        bool m_unk_height_valid;
        dot11_ie_221_dji_droneid_t* m__root;
        dot11_ie_221_dji_droneid_t::flight_reg_info_t* m__parent;

    public:
        bool unk_alt_valid() const { return m_unk_alt_valid; }
        bool unk_gps_valid() const { return m_unk_gps_valid; }
        bool in_air() const { return m_in_air; }
        bool motor_on() const { return m_motor_on; }
        bool uuid_set() const { return m_uuid_set; }
        bool homepoint_set() const { return m_homepoint_set; }
        bool private_disabled() const { return m_private_disabled; }
        bool serial_valid() const { return m_serial_valid; }
        bool unk15() const { return m_unk15; }
        bool unk14() const { return m_unk14; }
        bool unk13() const { return m_unk13; }
        bool unk12() const { return m_unk12; }
        bool unk11() const { return m_unk11; }
        bool unk_velocity_z_valid() const { return m_unk_velocity_z_valid; }
        bool unk_velocity_x_valid() const { return m_unk_velocity_x_valid; }
        bool unk_height_valid() const { return m_unk_height_valid; }
        dot11_ie_221_dji_droneid_t* _root() const { return m__root; }
        dot11_ie_221_dji_droneid_t::flight_reg_info_t* _parent() const { return m__parent; }
    };

private:
    bool f_dot11_ie_221_dji_droneid_oui;
    int32_t m_dot11_ie_221_dji_droneid_oui;

public:
    int32_t dot11_ie_221_dji_droneid_oui();

private:
    uint8_t m_vendor_type;
    uint8_t m_unk1;
    uint8_t m_unk2;
    uint8_t m_subcommand;
    flight_reg_info_t* m_record;
    dot11_ie_221_dji_droneid_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t vendor_type() const { return m_vendor_type; }
    uint8_t unk1() const { return m_unk1; }
    uint8_t unk2() const { return m_unk2; }
    uint8_t subcommand() const { return m_subcommand; }
    flight_reg_info_t* record() const { return m_record; }
    dot11_ie_221_dji_droneid_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_221_DJI_DRONEID_H_
