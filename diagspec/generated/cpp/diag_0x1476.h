// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class diag_0x1476_t : public kaitai::kstruct {

public:

    diag_0x1476_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0x1476_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0x1476_t();

private:
    bool f_fix_alt_m;
    float m_fix_alt_m;

public:
    float fix_alt_m();

private:
    bool f_is_compact;
    bool m_is_compact;

public:
    bool is_compact();

private:
    bool f_fix_gps_week;
    uint16_t m_fix_gps_week;

public:
    uint16_t fix_gps_week();

private:
    bool f_fix_lat_rad;
    double m_fix_lat_rad;

public:
    double fix_lat_rad();

private:
    bool f_fix_base;
    int8_t m_fix_base;

public:
    int8_t fix_base();

private:
    bool f_payload_size;
    int32_t m_payload_size;

public:
    int32_t payload_size();

private:
    bool f_is_v13_plus;
    bool m_is_v13_plus;

public:
    bool is_v13_plus();

private:
    bool f_is_mdm9600;
    bool m_is_mdm9600;

public:
    bool is_mdm9600();

private:
    bool f_fix_gps_tow_ms;
    uint32_t m_fix_gps_tow_ms;

public:
    uint32_t fix_gps_tow_ms();

private:
    bool f_fix_lon_rad;
    double m_fix_lon_rad;

public:
    double fix_lon_rad();

private:
    uint8_t m_version;
    uint32_t m_f_count;
    uint8_t m_pos_source;
    uint32_t m_reserved1;
    uint16_t m_pos_vel_flag;
    uint32_t m_pos_vel_flag2;
    uint8_t m_failure_code;
    uint16_t m_fix_events;
    uint32_t m_fake_align;
    uint16_t m_gps_week;
    uint32_t m_gps_tow_ms;
    uint8_t m_glo_four_year;
    uint16_t m_glo_days;
    uint32_t m_glo_tow_ms;
    uint32_t m_pos_count;
    double m_lat_rad;
    double m_lon_rad;
    float m_alt_m;
    float m_heading_rad;
    float m_heading_unc_rad;
    float m_vel_e;
    float m_vel_n;
    float m_vel_u;
    float m_vel_sigma_e;
    float m_vel_sigma_n;
    float m_vel_sigma_u;
    std::string m_clock_block;
    float m_pdop;
    float m_hdop;
    float m_vdop;
    uint8_t m_ellipse_confidence;
    std::string m_ellipse_block;
    float m_gnss_heading_rad;
    float m_gnss_heading_unc_rad;
    uint32_t m_sensor_data_mask;
    uint32_t m_sensor_aid_mask;
    uint8_t m_num_gps_svs;
    uint8_t m_total_gps_svs;
    uint8_t m_num_glo_svs;
    uint8_t m_total_glo_svs;
    uint8_t m_num_bds_svs;
    uint8_t m_total_bds_svs;
    diag_0x1476_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t version() const { return m_version; }
    uint32_t f_count() const { return m_f_count; }
    uint8_t pos_source() const { return m_pos_source; }
    uint32_t reserved1() const { return m_reserved1; }
    uint16_t pos_vel_flag() const { return m_pos_vel_flag; }
    uint32_t pos_vel_flag2() const { return m_pos_vel_flag2; }
    uint8_t failure_code() const { return m_failure_code; }
    uint16_t fix_events() const { return m_fix_events; }
    uint32_t fake_align() const { return m_fake_align; }
    uint16_t gps_week() const { return m_gps_week; }
    uint32_t gps_tow_ms() const { return m_gps_tow_ms; }
    uint8_t glo_four_year() const { return m_glo_four_year; }
    uint16_t glo_days() const { return m_glo_days; }
    uint32_t glo_tow_ms() const { return m_glo_tow_ms; }
    uint32_t pos_count() const { return m_pos_count; }
    double lat_rad() const { return m_lat_rad; }
    double lon_rad() const { return m_lon_rad; }
    float alt_m() const { return m_alt_m; }
    float heading_rad() const { return m_heading_rad; }
    float heading_unc_rad() const { return m_heading_unc_rad; }
    float vel_e() const { return m_vel_e; }
    float vel_n() const { return m_vel_n; }
    float vel_u() const { return m_vel_u; }
    float vel_sigma_e() const { return m_vel_sigma_e; }
    float vel_sigma_n() const { return m_vel_sigma_n; }
    float vel_sigma_u() const { return m_vel_sigma_u; }
    std::string clock_block() const { return m_clock_block; }
    float pdop() const { return m_pdop; }
    float hdop() const { return m_hdop; }
    float vdop() const { return m_vdop; }
    uint8_t ellipse_confidence() const { return m_ellipse_confidence; }
    std::string ellipse_block() const { return m_ellipse_block; }
    float gnss_heading_rad() const { return m_gnss_heading_rad; }
    float gnss_heading_unc_rad() const { return m_gnss_heading_unc_rad; }
    uint32_t sensor_data_mask() const { return m_sensor_data_mask; }
    uint32_t sensor_aid_mask() const { return m_sensor_aid_mask; }
    uint8_t num_gps_svs() const { return m_num_gps_svs; }
    uint8_t total_gps_svs() const { return m_total_gps_svs; }
    uint8_t num_glo_svs() const { return m_num_glo_svs; }
    uint8_t total_glo_svs() const { return m_total_glo_svs; }
    uint8_t num_bds_svs() const { return m_num_bds_svs; }
    uint8_t total_bds_svs() const { return m_total_bds_svs; }
    diag_0x1476_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
