// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "ie_wmm.h"

#include <iostream>
#include <fstream>

ie_wmm_t::ie_wmm_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, ie_wmm_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_tag_number = m__io->read_u1();
    m_tag_length = m__io->read_u1();
    m_wmm_oui = m__io->ensure_fixed_contents(std::string("\x00\x50\xF2", 3));
    m_wmm_type = m__io->read_u1();
    m_wme_subtype = m__io->read_u1();
    m_wme_version = m__io->read_u1();
}

ie_wmm_t::~ie_wmm_t() {
}
