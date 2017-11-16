// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_221_ms_wmm.h"

#include <iostream>
#include <fstream>

dot11_ie_221_ms_wmm_t::dot11_ie_221_ms_wmm_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_ms_wmm_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_wme_subtype = m__io->read_u1();
}

dot11_ie_221_ms_wmm_t::~dot11_ie_221_ms_wmm_t() {
}
