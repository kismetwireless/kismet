// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie.h"

#include <iostream>
#include <fstream>

dot11_ie_t::dot11_ie_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_tag = new std::vector<ieee_80211_tag_t*>();
    while (!m__io->is_eof()) {
        m_tag->push_back(new ieee_80211_tag_t(m__io, this, m__root));
    }
}

dot11_ie_t::~dot11_ie_t() {
    for (std::vector<ieee_80211_tag_t*>::iterator it = m_tag->begin(); it != m_tag->end(); ++it) {
        delete *it;
    }
    delete m_tag;
}

dot11_ie_t::ieee_80211_tag_t::ieee_80211_tag_t(kaitai::kstream *p_io, dot11_ie_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_tag_num = m__io->read_u1();
    m_tag_length = m__io->read_u1();
    m_tag_data = m__io->read_bytes(tag_length());
}

dot11_ie_t::ieee_80211_tag_t::~ieee_80211_tag_t() {
}
