// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_action.h"

#include <iostream>
#include <fstream>

dot11_action_t::dot11_action_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_action_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_category_code = static_cast<dot11_action_t::category_code_type_t>(m__io->read_u1());
    switch (category_code()) {
    case CATEGORY_CODE_TYPE_RADIO_MEASUREMENT:
        m__raw_action_frame = m__io->read_bytes_full();
        m__io__raw_action_frame = new kaitai::kstream(m__raw_action_frame);
        m_action_frame = new action_rmm_t(m__io__raw_action_frame, this, m__root);
        break;
    default:
        m__raw_action_frame = m__io->read_bytes_full();
        break;
    }
}

dot11_action_t::~dot11_action_t() {
}

dot11_action_t::action_rmm_t::action_rmm_t(kaitai::kstream *p_io, dot11_action_t *p_parent, dot11_action_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_rmm_action_code = static_cast<dot11_action_t::rmm_action_type_t>(m__io->read_u1());
    m_dialog_token = m__io->read_u1();
    m_tags = new std::vector<ie_tag_t*>();
    while (!m__io->is_eof()) {
        m_tags->push_back(new ie_tag_t(m__io, this, m__root));
    }
}

dot11_action_t::action_rmm_t::~action_rmm_t() {
    for (std::vector<ie_tag_t*>::iterator it = m_tags->begin(); it != m_tags->end(); ++it) {
        delete *it;
    }
    delete m_tags;
}

dot11_action_t::ie_tag_t::ie_tag_t(kaitai::kstream *p_io, dot11_action_t::action_rmm_t *p_parent, dot11_action_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_ie = m__io->read_u1();
    m_ie_len = m__io->read_u1();
    m_ie_data = m__io->read_bytes(ie_len());
}

dot11_action_t::ie_tag_t::~ie_tag_t() {
}
