// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_133_cisco_ccx.h"

#include <iostream>
#include <fstream>

dot11_ie_133_cisco_ccx_t::dot11_ie_133_cisco_ccx_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_133_cisco_ccx_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ie_num = false;
    m_ccx1_unk1 = m__io->read_bytes(10);
    m_ap_name = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(16), 0, false), std::string("ASCII"));
    m_station_count = m__io->read_u1();
    m_ccx1_unk2 = m__io->read_bytes(3);
}

dot11_ie_133_cisco_ccx_t::~dot11_ie_133_cisco_ccx_t() {
}

uint8_t dot11_ie_133_cisco_ccx_t::ie_num() {
    if (f_ie_num)
        return m_ie_num;
    m_ie_num = 133;
    f_ie_num = true;
    return m_ie_num;
}
