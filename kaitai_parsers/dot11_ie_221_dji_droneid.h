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
 * under the OUI 26:32:12.
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
    class droneid_flight_purpose_t;
    class droneid_flight_reg_info_t;
    class droneid_state_t;

    dot11_ie_221_dji_droneid_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_dji_droneid_t* p_root = 0);
    ~dot11_ie_221_dji_droneid_t();

    class droneid_flight_purpose_t : public kaitai::kstruct {

    public:

        droneid_flight_purpose_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_dji_droneid_t* p_root = 0);
        ~droneid_flight_purpose_t();

    private:
        std::string m_droneid_serialnumber;
        uint64_t m_droneid_len;
        std::string m_droneid;
        uint64_t m_droneid_purpose_len;
        std::string m_droneid_purpose;
        dot11_ie_221_dji_droneid_t* m__root;
        kaitai::kstruct* m__parent;

    public:
        std::string droneid_serialnumber() const { return m_droneid_serialnumber; }
        uint64_t droneid_len() const { return m_droneid_len; }
        std::string droneid() const { return m_droneid; }
        uint64_t droneid_purpose_len() const { return m_droneid_purpose_len; }
        std::string droneid_purpose() const { return m_droneid_purpose; }
        dot11_ie_221_dji_droneid_t* _root() const { return m__root; }
        kaitai::kstruct* _parent() const { return m__parent; }
    };

    class droneid_flight_reg_info_t : public kaitai::kstruct {

    public:

        droneid_flight_reg_info_t(kaitai::kstream* p_io, dot11_ie_221_dji_droneid_t* p_parent = 0, dot11_ie_221_dji_droneid_t* p_root = 0);
        ~droneid_flight_reg_info_t();

    private:
        bool f_droneid_pitch;
        double m_droneid_pitch;

    public:
        double droneid_pitch();

    private:
        bool f_droneid_home_lat;
        double m_droneid_home_lat;

    public:
        double droneid_home_lat();

    private:
        bool f_droneid_roll;
        double m_droneid_roll;

    public:
        double droneid_roll();

    private:
        bool f_droneid_yaw;
        double m_droneid_yaw;

    public:
        double droneid_yaw();

    private:
        bool f_droneid_lon;
        double m_droneid_lon;

    public:
        double droneid_lon();

    private:
        bool f_droneid_lat;
        double m_droneid_lat;

    public:
        double droneid_lat();

    private:
        bool f_droneid_home_lon;
        double m_droneid_home_lon;

    public:
        double droneid_home_lon();

    private:
        uint8_t m_droneid_version;
        uint16_t m_droneid_seq;
        droneid_state_t* m_droneid_state_info;
        std::string m_droneid_serialnumber;
        int32_t m_droneid_raw_lon;
        int32_t m_droneid_raw_lat;
        int16_t m_droneid_altitude;
        int16_t m_droneid_height;
        int16_t m_droneid_v_north;
        int16_t m_droneid_v_east;
        int16_t m_droneid_v_up;
        int16_t m_droneid_raw_pitch;
        int16_t m_droneid_raw_roll;
        int16_t m_droneid_raw_yaw;
        int32_t m_droneid_raw_home_lon;
        int32_t m_droneid_raw_home_lat;
        uint8_t m_droneid_product_type;
        uint8_t m_droneid_uuid_len;
        std::string m_droneid_uuid;
        dot11_ie_221_dji_droneid_t* m__root;
        dot11_ie_221_dji_droneid_t* m__parent;

    public:
        uint8_t droneid_version() const { return m_droneid_version; }
        uint16_t droneid_seq() const { return m_droneid_seq; }
        droneid_state_t* droneid_state_info() const { return m_droneid_state_info; }
        std::string droneid_serialnumber() const { return m_droneid_serialnumber; }
        int32_t droneid_raw_lon() const { return m_droneid_raw_lon; }
        int32_t droneid_raw_lat() const { return m_droneid_raw_lat; }
        int16_t droneid_altitude() const { return m_droneid_altitude; }
        int16_t droneid_height() const { return m_droneid_height; }
        int16_t droneid_v_north() const { return m_droneid_v_north; }
        int16_t droneid_v_east() const { return m_droneid_v_east; }
        int16_t droneid_v_up() const { return m_droneid_v_up; }
        int16_t droneid_raw_pitch() const { return m_droneid_raw_pitch; }
        int16_t droneid_raw_roll() const { return m_droneid_raw_roll; }
        int16_t droneid_raw_yaw() const { return m_droneid_raw_yaw; }
        int32_t droneid_raw_home_lon() const { return m_droneid_raw_home_lon; }
        int32_t droneid_raw_home_lat() const { return m_droneid_raw_home_lat; }
        uint8_t droneid_product_type() const { return m_droneid_product_type; }
        uint8_t droneid_uuid_len() const { return m_droneid_uuid_len; }
        std::string droneid_uuid() const { return m_droneid_uuid; }
        dot11_ie_221_dji_droneid_t* _root() const { return m__root; }
        dot11_ie_221_dji_droneid_t* _parent() const { return m__parent; }
    };

    class droneid_state_t : public kaitai::kstruct {

    public:

        droneid_state_t(kaitai::kstream* p_io, dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t* p_parent = 0, dot11_ie_221_dji_droneid_t* p_root = 0);
        ~droneid_state_t();

    private:
        bool m_droneid_state_unk_alt_valid;
        bool m_droneid_state_unk_gps_valid;
        bool m_droneid_state_in_air;
        bool m_droneid_state_motor_on;
        bool m_droneid_state_uuid_set;
        bool m_droneid_state_homepoint_set;
        bool m_droneid_state_private_disabled;
        bool m_droneid_state_serial_valid;
        bool m_droneid_state_unk15;
        bool m_droneid_state_unk14;
        bool m_droneid_state_unk13;
        bool m_droneid_state_unk12;
        bool m_droneid_state_unk11;
        bool m_droneid_state_unk_velocity_y_valid;
        bool m_droneid_state_unk_velocity_x_valid;
        bool m_droneid_state_unk_height_valid;
        dot11_ie_221_dji_droneid_t* m__root;
        dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t* m__parent;

    public:
        bool droneid_state_unk_alt_valid() const { return m_droneid_state_unk_alt_valid; }
        bool droneid_state_unk_gps_valid() const { return m_droneid_state_unk_gps_valid; }
        bool droneid_state_in_air() const { return m_droneid_state_in_air; }
        bool droneid_state_motor_on() const { return m_droneid_state_motor_on; }
        bool droneid_state_uuid_set() const { return m_droneid_state_uuid_set; }
        bool droneid_state_homepoint_set() const { return m_droneid_state_homepoint_set; }
        bool droneid_state_private_disabled() const { return m_droneid_state_private_disabled; }
        bool droneid_state_serial_valid() const { return m_droneid_state_serial_valid; }
        bool droneid_state_unk15() const { return m_droneid_state_unk15; }
        bool droneid_state_unk14() const { return m_droneid_state_unk14; }
        bool droneid_state_unk13() const { return m_droneid_state_unk13; }
        bool droneid_state_unk12() const { return m_droneid_state_unk12; }
        bool droneid_state_unk11() const { return m_droneid_state_unk11; }
        bool droneid_state_unk_velocity_y_valid() const { return m_droneid_state_unk_velocity_y_valid; }
        bool droneid_state_unk_velocity_x_valid() const { return m_droneid_state_unk_velocity_x_valid; }
        bool droneid_state_unk_height_valid() const { return m_droneid_state_unk_height_valid; }
        dot11_ie_221_dji_droneid_t* _root() const { return m__root; }
        dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t* _parent() const { return m__parent; }
    };

private:
    uint8_t m_vendor_type;
    uint8_t m_droneid_unk1;
    uint8_t m_droneid_unk2;
    uint8_t m_droneid_subcommand;
    droneid_flight_reg_info_t* m_droneid_record;
    dot11_ie_221_dji_droneid_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t vendor_type() const { return m_vendor_type; }
    uint8_t droneid_unk1() const { return m_droneid_unk1; }
    uint8_t droneid_unk2() const { return m_droneid_unk2; }
    uint8_t droneid_subcommand() const { return m_droneid_subcommand; }
    droneid_flight_reg_info_t* droneid_record() const { return m_droneid_record; }
    dot11_ie_221_dji_droneid_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_221_DJI_DRONEID_H_
