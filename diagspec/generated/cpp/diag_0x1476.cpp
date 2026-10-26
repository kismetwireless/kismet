// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0x1476.h"

diag_0x1476_t::diag_0x1476_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0x1476_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    f_fix_alt_m = false;
    f_is_compact = false;
    f_fix_gps_week = false;
    f_fix_lat_rad = false;
    f_fix_base = false;
    f_payload_size = false;
    f_is_v13_plus = false;
    f_is_mdm9600 = false;
    f_fix_gps_tow_ms = false;
    f_fix_lon_rad = false;
    _read();
}

void diag_0x1476_t::_read() {
    m_version = m__io->read_u1();
    m_f_count = m__io->read_u4le();
    m_pos_source = m__io->read_u1();
    m_reserved1 = m__io->read_u4le();
    m_pos_vel_flag = m__io->read_u2le();
    m_pos_vel_flag2 = m__io->read_u4le();
    m_failure_code = m__io->read_u1();
    m_fix_events = m__io->read_u2le();
    m_fake_align = m__io->read_u4le();
    m_gps_week = m__io->read_u2le();
    m_gps_tow_ms = m__io->read_u4le();
    m_glo_four_year = m__io->read_u1();
    m_glo_days = m__io->read_u2le();
    m_glo_tow_ms = m__io->read_u4le();
    m_pos_count = m__io->read_u4le();
    m_lat_rad = m__io->read_f8le();
    m_lon_rad = m__io->read_f8le();
    m_alt_m = m__io->read_f4le();
    m_heading_rad = m__io->read_f4le();
    m_heading_unc_rad = m__io->read_f4le();
    m_vel_e = m__io->read_f4le();
    m_vel_n = m__io->read_f4le();
    m_vel_u = m__io->read_f4le();
    m_vel_sigma_e = m__io->read_f4le();
    m_vel_sigma_n = m__io->read_f4le();
    m_vel_sigma_u = m__io->read_f4le();
    m_clock_block = m__io->read_bytes(144);
    m_pdop = m__io->read_f4le();
    m_hdop = m__io->read_f4le();
    m_vdop = m__io->read_f4le();
    m_ellipse_confidence = m__io->read_u1();
    m_ellipse_block = m__io->read_bytes(20);
    m_gnss_heading_rad = m__io->read_f4le();
    m_gnss_heading_unc_rad = m__io->read_f4le();
    m_sensor_data_mask = m__io->read_u4le();
    m_sensor_aid_mask = m__io->read_u4le();
    m_num_gps_svs = m__io->read_u1();
    m_total_gps_svs = m__io->read_u1();
    m_num_glo_svs = m__io->read_u1();
    m_total_glo_svs = m__io->read_u1();
    m_num_bds_svs = m__io->read_u1();
    m_total_bds_svs = m__io->read_u1();
}

diag_0x1476_t::~diag_0x1476_t() {
    _clean_up();
}

void diag_0x1476_t::_clean_up() {
    if (f_fix_alt_m) {
    }
    if (f_fix_gps_week) {
    }
    if (f_fix_lat_rad) {
    }
    if (f_fix_gps_tow_ms) {
    }
    if (f_fix_lon_rad) {
    }
}

float diag_0x1476_t::fix_alt_m() {
    if (f_fix_alt_m)
        return m_fix_alt_m;
    std::streampos _pos = m__io->pos();
    m__io->seek((fix_base() + 33));
    m_fix_alt_m = m__io->read_f4le();
    m__io->seek(_pos);
    f_fix_alt_m = true;
    return m_fix_alt_m;
}

bool diag_0x1476_t::is_compact() {
    if (f_is_compact)
        return m_is_compact;
    m_is_compact =  ((version() == 4) || (version() == 6) || (version() == 11) || (version() == 12)) ;
    f_is_compact = true;
    return m_is_compact;
}

uint16_t diag_0x1476_t::fix_gps_week() {
    if (f_fix_gps_week)
        return m_fix_gps_week;
    std::streampos _pos = m__io->pos();
    m__io->seek(fix_base());
    m_fix_gps_week = m__io->read_u2le();
    m__io->seek(_pos);
    f_fix_gps_week = true;
    return m_fix_gps_week;
}

double diag_0x1476_t::fix_lat_rad() {
    if (f_fix_lat_rad)
        return m_fix_lat_rad;
    std::streampos _pos = m__io->pos();
    m__io->seek((fix_base() + 17));
    m_fix_lat_rad = m__io->read_f8le();
    m__io->seek(_pos);
    f_fix_lat_rad = true;
    return m_fix_lat_rad;
}

int8_t diag_0x1476_t::fix_base() {
    if (f_fix_base)
        return m_fix_base;
    m_fix_base = ((is_mdm9600()) ? (19) : (((is_compact()) ? (((version() == 11) ? (23) : (((version() == 12) ? (24) : (19))))) : (((is_v13_plus()) ? (32) : (23))))));
    f_fix_base = true;
    return m_fix_base;
}

int32_t diag_0x1476_t::payload_size() {
    if (f_payload_size)
        return m_payload_size;
    m_payload_size = _io()->size();
    f_payload_size = true;
    return m_payload_size;
}

bool diag_0x1476_t::is_v13_plus() {
    if (f_is_v13_plus)
        return m_is_v13_plus;
    m_is_v13_plus =  ((version() >= 13) && (payload_size() >= 407)) ;
    f_is_v13_plus = true;
    return m_is_v13_plus;
}

bool diag_0x1476_t::is_mdm9600() {
    if (f_is_mdm9600)
        return m_is_mdm9600;
    m_is_mdm9600 =  ((version() == 2) && (payload_size() == 797)) ;
    f_is_mdm9600 = true;
    return m_is_mdm9600;
}

uint32_t diag_0x1476_t::fix_gps_tow_ms() {
    if (f_fix_gps_tow_ms)
        return m_fix_gps_tow_ms;
    std::streampos _pos = m__io->pos();
    m__io->seek((fix_base() + 2));
    m_fix_gps_tow_ms = m__io->read_u4le();
    m__io->seek(_pos);
    f_fix_gps_tow_ms = true;
    return m_fix_gps_tow_ms;
}

double diag_0x1476_t::fix_lon_rad() {
    if (f_fix_lon_rad)
        return m_fix_lon_rad;
    std::streampos _pos = m__io->pos();
    m__io->seek((fix_base() + 25));
    m_fix_lon_rad = m__io->read_f8le();
    m__io->seek(_pos);
    f_fix_lon_rad = true;
    return m_fix_lon_rad;
}
