// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_221_ms_wmm.h"

#include <iostream>
#include <fstream>

dot11_ie_221_ms_wmm_t::dot11_ie_221_ms_wmm_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_ms_wmm_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ie_num = false;
    m_wme_subtype = m__io->read_u1();
}

dot11_ie_221_ms_wmm_t::~dot11_ie_221_ms_wmm_t() {
}

uint8_t dot11_ie_221_ms_wmm_t::ie_num() {
    if (f_ie_num)
        return m_ie_num;
    m_ie_num = 221;
    f_ie_num = true;
    return m_ie_num;
}
