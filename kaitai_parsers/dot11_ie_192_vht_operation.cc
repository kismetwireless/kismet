// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_192_vht_operation.h"

#include <iostream>
#include <fstream>

dot11_ie_192_vht_operation_t::dot11_ie_192_vht_operation_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_192_vht_operation_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_channel_width = static_cast<dot11_ie_192_vht_operation_t::channel_width_t>(m__io->read_u1());
    m_center1 = m__io->read_u1();
    m_center2 = m__io->read_u1();
    m_basic_mcs_map = new mcs_map_t(m__io, this, m__root);
}

dot11_ie_192_vht_operation_t::~dot11_ie_192_vht_operation_t() {
    delete m_basic_mcs_map;
}

dot11_ie_192_vht_operation_t::mcs_map_t::mcs_map_t(kaitai::kstream *p_io, dot11_ie_192_vht_operation_t *p_parent, dot11_ie_192_vht_operation_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_basic_4 = m__io->read_bits_int(2);
    m_basic_3 = m__io->read_bits_int(2);
    m_basic_2 = m__io->read_bits_int(2);
    m_basic_1 = m__io->read_bits_int(2);
    m_basic_8 = m__io->read_bits_int(2);
    m_basic_7 = m__io->read_bits_int(2);
    m_basic_6 = m__io->read_bits_int(2);
    m_basic_5 = m__io->read_bits_int(2);
}

dot11_ie_192_vht_operation_t::mcs_map_t::~mcs_map_t() {
}
