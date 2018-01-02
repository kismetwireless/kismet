// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_221_dji_droneid.h"

#include <iostream>
#include <fstream>

dot11_ie_221_dji_droneid_t::dot11_ie_221_dji_droneid_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_dot11_ie_221_dji_droneid_oui = false;
    f_subcommand_flight_reg_info = false;
    f_subcommand_flight_purpose = false;
    m_vendor_type = m__io->read_u1();
    m_unk1 = m__io->read_u1();
    m_unk2 = m__io->read_u1();
    m_subcommand = m__io->read_u1();
    m_record = m__io->read_bytes_full();
}

dot11_ie_221_dji_droneid_t::~dot11_ie_221_dji_droneid_t() {
}

dot11_ie_221_dji_droneid_t::flight_purpose_t::flight_purpose_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_serialnumber = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(16), 0, false), std::string("ASCII"));
    m_len = m__io->read_u8le();
    m_drone_id = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(10), 0, false), std::string("ASCII"));
    m_purpose_len = m__io->read_u8le();
    m_purpose = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes_full(), 0, false), std::string("ASCII"));
}

dot11_ie_221_dji_droneid_t::flight_purpose_t::~flight_purpose_t() {
}

dot11_ie_221_dji_droneid_t::flight_reg_info_t::flight_reg_info_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    f_state_vup_valid = false;
    f_roll = false;
    f_home_lon = false;
    f_lat = false;
    f_home_lat = false;
    f_state_gps_valid = false;
    f_state_alt_valid = false;
    f_lon = false;
    f_state_pitchroll_valid = false;
    f_yaw = false;
    f_state_horiz_valid = false;
    f_pitch = false;
    f_state_user_private_disabled = false;
    f_state_serial_valid = false;
    f_state_motor_on = false;
    f_state_uuid_set = false;
    f_state_homepoint_set = false;
    f_state_in_air = false;
    f_state_height_valid = false;
    m_version = m__io->read_u1();
    m_seq = m__io->read_u2le();
    m_state_info = m__io->read_u2le();
    m_serialnumber = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(16), 0, false), std::string("ASCII"));
    m_raw_lon = m__io->read_s4le();
    m_raw_lat = m__io->read_s4le();
    m_altitude = m__io->read_s2le();
    m_height = m__io->read_s2le();
    m_v_north = m__io->read_s2le();
    m_v_east = m__io->read_s2le();
    m_v_up = m__io->read_s2le();
    m_raw_pitch = m__io->read_s2le();
    m_raw_roll = m__io->read_s2le();
    m_raw_yaw = m__io->read_s2le();
    m_raw_home_lon = m__io->read_s4le();
    m_raw_home_lat = m__io->read_s4le();
    m_product_type = m__io->read_u1();
    m_uuid_len = m__io->read_u1();
    m_uuid = m__io->read_bytes(20);
}

dot11_ie_221_dji_droneid_t::flight_reg_info_t::~flight_reg_info_t() {
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_vup_valid() {
    if (f_state_vup_valid)
        return m_state_vup_valid;
    m_state_vup_valid = (state_info() & 1024);
    f_state_vup_valid = true;
    return m_state_vup_valid;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::roll() {
    if (f_roll)
        return m_roll;
    m_roll = ((raw_roll() / 100.0) / 57.296);
    f_roll = true;
    return m_roll;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::home_lon() {
    if (f_home_lon)
        return m_home_lon;
    m_home_lon = (raw_home_lon() / 174533.0);
    f_home_lon = true;
    return m_home_lon;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::lat() {
    if (f_lat)
        return m_lat;
    m_lat = (raw_lat() / 174533.0);
    f_lat = true;
    return m_lat;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::home_lat() {
    if (f_home_lat)
        return m_home_lat;
    m_home_lat = (raw_home_lat() / 174533.0);
    f_home_lat = true;
    return m_home_lat;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_gps_valid() {
    if (f_state_gps_valid)
        return m_state_gps_valid;
    m_state_gps_valid = (state_info() & 64);
    f_state_gps_valid = true;
    return m_state_gps_valid;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_alt_valid() {
    if (f_state_alt_valid)
        return m_state_alt_valid;
    m_state_alt_valid = (state_info() & 128);
    f_state_alt_valid = true;
    return m_state_alt_valid;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::lon() {
    if (f_lon)
        return m_lon;
    m_lon = (raw_lon() / 174533.0);
    f_lon = true;
    return m_lon;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_pitchroll_valid() {
    if (f_state_pitchroll_valid)
        return m_state_pitchroll_valid;
    m_state_pitchroll_valid = (state_info() & 2048);
    f_state_pitchroll_valid = true;
    return m_state_pitchroll_valid;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::yaw() {
    if (f_yaw)
        return m_yaw;
    m_yaw = ((raw_yaw() / 100.0) / 57.296);
    f_yaw = true;
    return m_yaw;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_horiz_valid() {
    if (f_state_horiz_valid)
        return m_state_horiz_valid;
    m_state_horiz_valid = (state_info() & 512);
    f_state_horiz_valid = true;
    return m_state_horiz_valid;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::pitch() {
    if (f_pitch)
        return m_pitch;
    m_pitch = ((raw_pitch() / 100.0) / 57.296);
    f_pitch = true;
    return m_pitch;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_user_private_disabled() {
    if (f_state_user_private_disabled)
        return m_state_user_private_disabled;
    m_state_user_private_disabled = (state_info() & 2);
    f_state_user_private_disabled = true;
    return m_state_user_private_disabled;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_serial_valid() {
    if (f_state_serial_valid)
        return m_state_serial_valid;
    m_state_serial_valid = (state_info() & 1);
    f_state_serial_valid = true;
    return m_state_serial_valid;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_motor_on() {
    if (f_state_motor_on)
        return m_state_motor_on;
    m_state_motor_on = (state_info() & 16);
    f_state_motor_on = true;
    return m_state_motor_on;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_uuid_set() {
    if (f_state_uuid_set)
        return m_state_uuid_set;
    m_state_uuid_set = (state_info() & 8);
    f_state_uuid_set = true;
    return m_state_uuid_set;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_homepoint_set() {
    if (f_state_homepoint_set)
        return m_state_homepoint_set;
    m_state_homepoint_set = (state_info() & 4);
    f_state_homepoint_set = true;
    return m_state_homepoint_set;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_in_air() {
    if (f_state_in_air)
        return m_state_in_air;
    m_state_in_air = (state_info() & 32);
    f_state_in_air = true;
    return m_state_in_air;
}

int32_t dot11_ie_221_dji_droneid_t::flight_reg_info_t::state_height_valid() {
    if (f_state_height_valid)
        return m_state_height_valid;
    m_state_height_valid = (state_info() & 256);
    f_state_height_valid = true;
    return m_state_height_valid;
}

int32_t dot11_ie_221_dji_droneid_t::dot11_ie_221_dji_droneid_oui() {
    if (f_dot11_ie_221_dji_droneid_oui)
        return m_dot11_ie_221_dji_droneid_oui;
    m_dot11_ie_221_dji_droneid_oui = 305604096;
    f_dot11_ie_221_dji_droneid_oui = true;
    return m_dot11_ie_221_dji_droneid_oui;
}

bool dot11_ie_221_dji_droneid_t::subcommand_flight_reg_info() {
    if (f_subcommand_flight_reg_info)
        return m_subcommand_flight_reg_info;
    m_subcommand_flight_reg_info = subcommand() == 16;
    f_subcommand_flight_reg_info = true;
    return m_subcommand_flight_reg_info;
}

bool dot11_ie_221_dji_droneid_t::subcommand_flight_purpose() {
    if (f_subcommand_flight_purpose)
        return m_subcommand_flight_purpose;
    m_subcommand_flight_purpose = subcommand() == 17;
    f_subcommand_flight_purpose = true;
    return m_subcommand_flight_purpose;
}
