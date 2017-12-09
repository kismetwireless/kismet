// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_191_vht_capabilities.h"

#include <iostream>
#include <fstream>

dot11_ie_191_vht_capabilities_t::dot11_ie_191_vht_capabilities_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_191_vht_capabilities_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_tx_mcs_s6 = false;
    f_tx_mcs_s3 = false;
    f_tx_mcs_s8 = false;
    f_tx_mcs_s4 = false;
    f_rx_mcs_s4 = false;
    f_tx_mcs_s1 = false;
    f_rx_mcs_s7 = false;
    f_vht_cap_160mhz_supported = false;
    f_tx_mcs_s7 = false;
    f_rx_mcs_s6 = false;
    f_tx_mcs_s2 = false;
    f_rx_mcs_s3 = false;
    f_rx_mcs_s2 = false;
    f_vht_cap_80mhz_shortgi = false;
    f_rx_mcs_s5 = false;
    f_vht_cap_160mhz_shortgi = false;
    f_rx_mcs_s1 = false;
    f_tx_mcs_s5 = false;
    f_rx_mcs_s8 = false;
    m_vht_capabilities = m__io->read_u4le();
    m_rx_mcs_map = m__io->read_u2le();
    m_rx_mcs_set = m__io->read_u2le();
    m_tx_mcs_map = m__io->read_u2le();
    m_tx_mcs_set = m__io->read_u2le();
}

dot11_ie_191_vht_capabilities_t::~dot11_ie_191_vht_capabilities_t() {
}

int32_t dot11_ie_191_vht_capabilities_t::tx_mcs_s6() {
    if (f_tx_mcs_s6)
        return m_tx_mcs_s6;
    m_tx_mcs_s6 = ((tx_mcs_map() & 3072) >> 10);
    f_tx_mcs_s6 = true;
    return m_tx_mcs_s6;
}

int32_t dot11_ie_191_vht_capabilities_t::tx_mcs_s3() {
    if (f_tx_mcs_s3)
        return m_tx_mcs_s3;
    m_tx_mcs_s3 = ((tx_mcs_map() & 48) >> 4);
    f_tx_mcs_s3 = true;
    return m_tx_mcs_s3;
}

int32_t dot11_ie_191_vht_capabilities_t::tx_mcs_s8() {
    if (f_tx_mcs_s8)
        return m_tx_mcs_s8;
    m_tx_mcs_s8 = ((tx_mcs_map() & 49152) >> 14);
    f_tx_mcs_s8 = true;
    return m_tx_mcs_s8;
}

int32_t dot11_ie_191_vht_capabilities_t::tx_mcs_s4() {
    if (f_tx_mcs_s4)
        return m_tx_mcs_s4;
    m_tx_mcs_s4 = ((tx_mcs_map() & 192) >> 6);
    f_tx_mcs_s4 = true;
    return m_tx_mcs_s4;
}

int32_t dot11_ie_191_vht_capabilities_t::rx_mcs_s4() {
    if (f_rx_mcs_s4)
        return m_rx_mcs_s4;
    m_rx_mcs_s4 = ((rx_mcs_map() & 192) >> 6);
    f_rx_mcs_s4 = true;
    return m_rx_mcs_s4;
}

int32_t dot11_ie_191_vht_capabilities_t::tx_mcs_s1() {
    if (f_tx_mcs_s1)
        return m_tx_mcs_s1;
    m_tx_mcs_s1 = (tx_mcs_map() & 3);
    f_tx_mcs_s1 = true;
    return m_tx_mcs_s1;
}

int32_t dot11_ie_191_vht_capabilities_t::rx_mcs_s7() {
    if (f_rx_mcs_s7)
        return m_rx_mcs_s7;
    m_rx_mcs_s7 = ((rx_mcs_map() & 12288) >> 12);
    f_rx_mcs_s7 = true;
    return m_rx_mcs_s7;
}

int32_t dot11_ie_191_vht_capabilities_t::vht_cap_160mhz_supported() {
    if (f_vht_cap_160mhz_supported)
        return m_vht_cap_160mhz_supported;
    m_vht_cap_160mhz_supported = (vht_capabilities() & 12);
    f_vht_cap_160mhz_supported = true;
    return m_vht_cap_160mhz_supported;
}

int32_t dot11_ie_191_vht_capabilities_t::tx_mcs_s7() {
    if (f_tx_mcs_s7)
        return m_tx_mcs_s7;
    m_tx_mcs_s7 = ((tx_mcs_map() & 12288) >> 12);
    f_tx_mcs_s7 = true;
    return m_tx_mcs_s7;
}

int32_t dot11_ie_191_vht_capabilities_t::rx_mcs_s6() {
    if (f_rx_mcs_s6)
        return m_rx_mcs_s6;
    m_rx_mcs_s6 = ((rx_mcs_map() & 3072) >> 10);
    f_rx_mcs_s6 = true;
    return m_rx_mcs_s6;
}

int32_t dot11_ie_191_vht_capabilities_t::tx_mcs_s2() {
    if (f_tx_mcs_s2)
        return m_tx_mcs_s2;
    m_tx_mcs_s2 = ((tx_mcs_map() & 12) >> 2);
    f_tx_mcs_s2 = true;
    return m_tx_mcs_s2;
}

int32_t dot11_ie_191_vht_capabilities_t::rx_mcs_s3() {
    if (f_rx_mcs_s3)
        return m_rx_mcs_s3;
    m_rx_mcs_s3 = ((rx_mcs_map() & 48) >> 4);
    f_rx_mcs_s3 = true;
    return m_rx_mcs_s3;
}

int32_t dot11_ie_191_vht_capabilities_t::rx_mcs_s2() {
    if (f_rx_mcs_s2)
        return m_rx_mcs_s2;
    m_rx_mcs_s2 = ((rx_mcs_map() & 12) >> 2);
    f_rx_mcs_s2 = true;
    return m_rx_mcs_s2;
}

int32_t dot11_ie_191_vht_capabilities_t::vht_cap_80mhz_shortgi() {
    if (f_vht_cap_80mhz_shortgi)
        return m_vht_cap_80mhz_shortgi;
    m_vht_cap_80mhz_shortgi = (vht_capabilities() & 32);
    f_vht_cap_80mhz_shortgi = true;
    return m_vht_cap_80mhz_shortgi;
}

int32_t dot11_ie_191_vht_capabilities_t::rx_mcs_s5() {
    if (f_rx_mcs_s5)
        return m_rx_mcs_s5;
    m_rx_mcs_s5 = ((rx_mcs_map() & 768) >> 8);
    f_rx_mcs_s5 = true;
    return m_rx_mcs_s5;
}

int32_t dot11_ie_191_vht_capabilities_t::vht_cap_160mhz_shortgi() {
    if (f_vht_cap_160mhz_shortgi)
        return m_vht_cap_160mhz_shortgi;
    m_vht_cap_160mhz_shortgi = (vht_capabilities() & 64);
    f_vht_cap_160mhz_shortgi = true;
    return m_vht_cap_160mhz_shortgi;
}

int32_t dot11_ie_191_vht_capabilities_t::rx_mcs_s1() {
    if (f_rx_mcs_s1)
        return m_rx_mcs_s1;
    m_rx_mcs_s1 = (rx_mcs_map() & 3);
    f_rx_mcs_s1 = true;
    return m_rx_mcs_s1;
}

int32_t dot11_ie_191_vht_capabilities_t::tx_mcs_s5() {
    if (f_tx_mcs_s5)
        return m_tx_mcs_s5;
    m_tx_mcs_s5 = ((tx_mcs_map() & 768) >> 8);
    f_tx_mcs_s5 = true;
    return m_tx_mcs_s5;
}

int32_t dot11_ie_191_vht_capabilities_t::rx_mcs_s8() {
    if (f_rx_mcs_s8)
        return m_rx_mcs_s8;
    m_rx_mcs_s8 = ((rx_mcs_map() & 49152) >> 14);
    f_rx_mcs_s8 = true;
    return m_rx_mcs_s8;
}
