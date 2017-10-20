// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_221_dji_droneid.h"

#include <iostream>
#include <fstream>

dot11_ie_221_dji_droneid_t::dot11_ie_221_dji_droneid_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_vendor_type = m__io->read_u1();
    m_droneid_unk1 = m__io->read_u1();
    m_droneid_unk2 = m__io->read_u1();
    m_droneid_subcommand = m__io->read_u1();
    switch (droneid_subcommand()) {
    case 16:
        m_droneid_record = new droneid_flight_reg_info_t(m__io, this, m__root);
        break;
    }
}

dot11_ie_221_dji_droneid_t::~dot11_ie_221_dji_droneid_t() {
}

dot11_ie_221_dji_droneid_t::droneid_flight_purpose_t::droneid_flight_purpose_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_droneid_serialnumber = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(16), 0, false), std::string("ASCII"));
    m_droneid_len = m__io->read_u8le();
    m_droneid = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(10), 0, false), std::string("ASCII"));
    m_droneid_purpose_len = m__io->read_u8le();
    m_droneid_purpose = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(100), 0, false), std::string("ASCII"));
}

dot11_ie_221_dji_droneid_t::droneid_flight_purpose_t::~droneid_flight_purpose_t() {
}

dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::droneid_flight_reg_info_t(kaitai::kstream *p_io, dot11_ie_221_dji_droneid_t *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    f_droneid_pitch = false;
    f_droneid_home_lat = false;
    f_droneid_roll = false;
    f_droneid_yaw = false;
    f_droneid_lon = false;
    f_droneid_lat = false;
    f_droneid_home_lon = false;
    m_droneid_version = m__io->read_u1();
    m_droneid_seq = m__io->read_u2le();
    m_droneid_state_info = new droneid_state_t(m__io, this, m__root);
    m_droneid_serialnumber = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(16), 0, false), std::string("ASCII"));
    m_droneid_raw_lon = m__io->read_s4le();
    m_droneid_raw_lat = m__io->read_s4le();
    m_droneid_altitude = m__io->read_s2le();
    m_droneid_height = m__io->read_s2le();
    m_droneid_v_north = m__io->read_s2le();
    m_droneid_v_east = m__io->read_s2le();
    m_droneid_v_up = m__io->read_s2le();
    m_droneid_raw_pitch = m__io->read_s2le();
    m_droneid_raw_roll = m__io->read_s2le();
    m_droneid_raw_yaw = m__io->read_s2le();
    m_droneid_raw_home_lon = m__io->read_s4le();
    m_droneid_raw_home_lat = m__io->read_s4le();
    m_droneid_product_type = m__io->read_u1();
    m_droneid_uuid_len = m__io->read_u1();
    m_droneid_uuid = m__io->read_bytes(20);
}

dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::~droneid_flight_reg_info_t() {
    delete m_droneid_state_info;
}

double dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::droneid_pitch() {
    if (f_droneid_pitch)
        return m_droneid_pitch;
    m_droneid_pitch = ((droneid_raw_pitch() / 100.0) / 57.296);
    f_droneid_pitch = true;
    return m_droneid_pitch;
}

double dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::droneid_home_lat() {
    if (f_droneid_home_lat)
        return m_droneid_home_lat;
    m_droneid_home_lat = (droneid_raw_home_lat() / 174533.0);
    f_droneid_home_lat = true;
    return m_droneid_home_lat;
}

double dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::droneid_roll() {
    if (f_droneid_roll)
        return m_droneid_roll;
    m_droneid_roll = ((droneid_raw_roll() / 100.0) / 57.296);
    f_droneid_roll = true;
    return m_droneid_roll;
}

double dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::droneid_yaw() {
    if (f_droneid_yaw)
        return m_droneid_yaw;
    m_droneid_yaw = ((droneid_raw_yaw() / 100.0) / 57.296);
    f_droneid_yaw = true;
    return m_droneid_yaw;
}

double dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::droneid_lon() {
    if (f_droneid_lon)
        return m_droneid_lon;
    m_droneid_lon = (droneid_raw_lon() / 174533.0);
    f_droneid_lon = true;
    return m_droneid_lon;
}

double dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::droneid_lat() {
    if (f_droneid_lat)
        return m_droneid_lat;
    m_droneid_lat = (droneid_raw_lat() / 174533.0);
    f_droneid_lat = true;
    return m_droneid_lat;
}

double dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t::droneid_home_lon() {
    if (f_droneid_home_lon)
        return m_droneid_home_lon;
    m_droneid_home_lon = (droneid_raw_home_lon() / 174533.0);
    f_droneid_home_lon = true;
    return m_droneid_home_lon;
}

dot11_ie_221_dji_droneid_t::droneid_state_t::droneid_state_t(kaitai::kstream *p_io, dot11_ie_221_dji_droneid_t::droneid_flight_reg_info_t *p_parent, dot11_ie_221_dji_droneid_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_droneid_state_unk_alt_valid = m__io->read_bits_int(1);
    m_droneid_state_unk_gps_valid = m__io->read_bits_int(1);
    m_droneid_state_in_air = m__io->read_bits_int(1);
    m_droneid_state_motor_on = m__io->read_bits_int(1);
    m_droneid_state_uuid_set = m__io->read_bits_int(1);
    m_droneid_state_homepoint_set = m__io->read_bits_int(1);
    m_droneid_state_private_disabled = m__io->read_bits_int(1);
    m_droneid_state_serial_valid = m__io->read_bits_int(1);
    m_droneid_state_unk15 = m__io->read_bits_int(1);
    m_droneid_state_unk14 = m__io->read_bits_int(1);
    m_droneid_state_unk13 = m__io->read_bits_int(1);
    m_droneid_state_unk12 = m__io->read_bits_int(1);
    m_droneid_state_unk11 = m__io->read_bits_int(1);
    m_droneid_state_unk_velocity_y_valid = m__io->read_bits_int(1);
    m_droneid_state_unk_velocity_x_valid = m__io->read_bits_int(1);
    m_droneid_state_unk_height_valid = m__io->read_bits_int(1);
}

dot11_ie_221_dji_droneid_t::droneid_state_t::~droneid_state_t() {
}
