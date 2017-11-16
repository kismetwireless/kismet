// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_11_qbss.h"

#include <iostream>
#include <fstream>

dot11_ie_11_qbss_t::dot11_ie_11_qbss_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_11_qbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ie_num = false;
    m_station_count = m__io->read_u2le();
    m_channel_utilization = m__io->read_u1();
    m_available_admissions = m__io->read_u2le();
}

dot11_ie_11_qbss_t::~dot11_ie_11_qbss_t() {
}

int8_t dot11_ie_11_qbss_t::ie_num() {
    if (f_ie_num)
        return m_ie_num;
    m_ie_num = 11;
    f_ie_num = true;
    return m_ie_num;
}
