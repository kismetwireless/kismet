// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_48_rsn.h"

#include <iostream>
#include <fstream>

dot11_ie_48_rsn_t::dot11_ie_48_rsn_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_48_rsn_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_rsn_version = m__io->read_u2le();
    m_group_cipher = new rsn_cipher_t(m__io, this, m__root);
    m_pairwise_count = m__io->read_u2le();
    int l_pairwise_ciphers = pairwise_count();
    m_pairwise_ciphers = new std::vector<rsn_cipher_t*>();
    m_pairwise_ciphers->reserve(l_pairwise_ciphers);
    for (int i = 0; i < l_pairwise_ciphers; i++) {
        m_pairwise_ciphers->push_back(new rsn_cipher_t(m__io, this, m__root));
    }
    m_akm_count = m__io->read_u2le();
    int l_akm_ciphers = akm_count();
    m_akm_ciphers = new std::vector<rsn_management_t*>();
    m_akm_ciphers->reserve(l_akm_ciphers);
    for (int i = 0; i < l_akm_ciphers; i++) {
        m_akm_ciphers->push_back(new rsn_management_t(m__io, this, m__root));
    }
}

dot11_ie_48_rsn_t::~dot11_ie_48_rsn_t() {
    delete m_group_cipher;
    for (std::vector<rsn_cipher_t*>::iterator it = m_pairwise_ciphers->begin(); it != m_pairwise_ciphers->end(); ++it) {
        delete *it;
    }
    delete m_pairwise_ciphers;
    for (std::vector<rsn_management_t*>::iterator it = m_akm_ciphers->begin(); it != m_akm_ciphers->end(); ++it) {
        delete *it;
    }
    delete m_akm_ciphers;
}

dot11_ie_48_rsn_t::rsn_cipher_t::rsn_cipher_t(kaitai::kstream *p_io, dot11_ie_48_rsn_t *p_parent, dot11_ie_48_rsn_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_cipher_suite_oui = m__io->read_bytes(3);
    m_cipher_type = static_cast<dot11_ie_48_rsn_t::rsn_cipher_types_t>(m__io->read_u1());
}

dot11_ie_48_rsn_t::rsn_cipher_t::~rsn_cipher_t() {
}

dot11_ie_48_rsn_t::rsn_management_t::rsn_management_t(kaitai::kstream *p_io, dot11_ie_48_rsn_t *p_parent, dot11_ie_48_rsn_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_management_suite_oui = m__io->read_bytes(3);
    m_management_type = static_cast<dot11_ie_48_rsn_t::rsn_management_types_t>(m__io->read_u1());
}

dot11_ie_48_rsn_t::rsn_management_t::~rsn_management_t() {
}
