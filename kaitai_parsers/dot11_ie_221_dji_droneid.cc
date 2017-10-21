// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_221_dji_droneid.h"

#include <iostream>
#include <fstream>

dot11_ie_221_dji_droneid_t::dot11_ie_221_dji_droneid_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_dot11_ie_221_dji_droneid_oui = false;
    m_vendor_type = m__io->read_u1();
    m_unk1 = m__io->read_u1();
    m_unk2 = m__io->read_u1();
    m_subcommand = m__io->read_u1();
    switch (subcommand()) {
    case 16:
        m_record = new flight_reg_info_t(m__io, this, m__root);
        break;
    }
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
    m_purpose = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(100), 0, false), std::string("ASCII"));
}

dot11_ie_221_dji_droneid_t::flight_purpose_t::~flight_purpose_t() {
}

dot11_ie_221_dji_droneid_t::flight_reg_info_t::flight_reg_info_t(kaitai::kstream *p_io, dot11_ie_221_dji_droneid_t *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    f_roll = false;
    f_home_lon = false;
    f_lat = false;
    f_home_lat = false;
    f_lon = false;
    f_yaw = false;
    f_pitch = false;
    m_version = m__io->read_u1();
    m_seq = m__io->read_u2le();
    m_state_info = new state_t(m__io, this, m__root);
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
    delete m_state_info;
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

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::lon() {
    if (f_lon)
        return m_lon;
    m_lon = (raw_lon() / 174533.0);
    f_lon = true;
    return m_lon;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::yaw() {
    if (f_yaw)
        return m_yaw;
    m_yaw = ((raw_yaw() / 100.0) / 57.296);
    f_yaw = true;
    return m_yaw;
}

double dot11_ie_221_dji_droneid_t::flight_reg_info_t::pitch() {
    if (f_pitch)
        return m_pitch;
    m_pitch = ((raw_pitch() / 100.0) / 57.296);
    f_pitch = true;
    return m_pitch;
}

dot11_ie_221_dji_droneid_t::state_t::state_t(kaitai::kstream *p_io, dot11_ie_221_dji_droneid_t::flight_reg_info_t *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_unk_alt_valid = m__io->read_bits_int(1);
    m_unk_gps_valid = m__io->read_bits_int(1);
    m_in_air = m__io->read_bits_int(1);
    m_motor_on = m__io->read_bits_int(1);
    m_uuid_set = m__io->read_bits_int(1);
    m_homepoint_set = m__io->read_bits_int(1);
    m_private_disabled = m__io->read_bits_int(1);
    m_serial_valid = m__io->read_bits_int(1);
    m_unk15 = m__io->read_bits_int(1);
    m_unk14 = m__io->read_bits_int(1);
    m_unk13 = m__io->read_bits_int(1);
    m_unk12 = m__io->read_bits_int(1);
    m_unk11 = m__io->read_bits_int(1);
    m_unk_velocity_z_valid = m__io->read_bits_int(1);
    m_unk_velocity_x_valid = m__io->read_bits_int(1);
    m_unk_height_valid = m__io->read_bits_int(1);
}

dot11_ie_221_dji_droneid_t::state_t::~state_t() {
}

int32_t dot11_ie_221_dji_droneid_t::dot11_ie_221_dji_droneid_oui() {
    if (f_dot11_ie_221_dji_droneid_oui)
        return m_dot11_ie_221_dji_droneid_oui;
    m_dot11_ie_221_dji_droneid_oui = 305604096;
    f_dot11_ie_221_dji_droneid_oui = true;
    return m_dot11_ie_221_dji_droneid_oui;
}
