// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "ie221.h"

#include <iostream>
#include <fstream>

ie221_t::ie221_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, ie221_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_tag_number = m__io->read_u1();
    m_tag_length = m__io->read_u1();
    m_wmm_oui = m__io->ensure_fixed_contents(std::string("\x00\x50\xF2", 3));
    m_vendor_type = m__io->ensure_fixed_contents(std::string("\x75\x31", 2));
}

ie221_t::~ie221_t() {
}
