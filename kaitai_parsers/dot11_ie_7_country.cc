// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_7_country.h"

#include <iostream>
#include <fstream>

dot11_ie_7_country_t::dot11_ie_7_country_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_7_country_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ie_num = false;
    m_country_code = m__io->read_bytes(2);
    m_environment = m__io->read_u1();
    m_country_list = new std::vector<dot11_ie_country_triplet_t*>();
    while (!m__io->is_eof()) {
        m_country_list->push_back(new dot11_ie_country_triplet_t(m__io, this, m__root));
    }
}

dot11_ie_7_country_t::~dot11_ie_7_country_t() {
    for (std::vector<dot11_ie_country_triplet_t*>::iterator it = m_country_list->begin(); it != m_country_list->end(); ++it) {
        delete *it;
    }
    delete m_country_list;
}

dot11_ie_7_country_t::dot11_ie_country_triplet_t::dot11_ie_country_triplet_t(kaitai::kstream *p_io, dot11_ie_7_country_t *p_parent, dot11_ie_7_country_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_first_channel = m__io->read_u1();
    m_num_channels = m__io->read_u1();
    m_max_power = m__io->read_u1();
}

dot11_ie_7_country_t::dot11_ie_country_triplet_t::~dot11_ie_country_triplet_t() {
}

int8_t dot11_ie_7_country_t::ie_num() {
    if (f_ie_num)
        return m_ie_num;
    m_ie_num = 7;
    f_ie_num = true;
    return m_ie_num;
}
