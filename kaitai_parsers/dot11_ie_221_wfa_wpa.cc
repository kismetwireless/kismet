// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_221_wfa_wpa.h"

#include <iostream>
#include <fstream>

dot11_ie_221_wfa_wpa_t::dot11_ie_221_wfa_wpa_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_wfa_wpa_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_vendor_subtype = m__io->read_u1();
    m_wpa_version = m__io->read_u2le();
    m_multicast_cipher = new wpa_v1_cipher_t(m__io, this, m__root);
    m_unicast_count = m__io->read_u2le();
    int l_unicast_ciphers = unicast_count();
    m_unicast_ciphers = new std::vector<wpa_v1_cipher_t*>();
    m_unicast_ciphers->reserve(l_unicast_ciphers);
    for (int i = 0; i < l_unicast_ciphers; i++) {
        m_unicast_ciphers->push_back(new wpa_v1_cipher_t(m__io, this, m__root));
    }
    m_akm_count = m__io->read_u2le();
    int l_akm_ciphers = akm_count();
    m_akm_ciphers = new std::vector<wpa_v1_cipher_t*>();
    m_akm_ciphers->reserve(l_akm_ciphers);
    for (int i = 0; i < l_akm_ciphers; i++) {
        m_akm_ciphers->push_back(new wpa_v1_cipher_t(m__io, this, m__root));
    }
}

dot11_ie_221_wfa_wpa_t::~dot11_ie_221_wfa_wpa_t() {
    delete m_multicast_cipher;
    for (std::vector<wpa_v1_cipher_t*>::iterator it = m_unicast_ciphers->begin(); it != m_unicast_ciphers->end(); ++it) {
        delete *it;
    }
    delete m_unicast_ciphers;
    for (std::vector<wpa_v1_cipher_t*>::iterator it = m_akm_ciphers->begin(); it != m_akm_ciphers->end(); ++it) {
        delete *it;
    }
    delete m_akm_ciphers;
}

dot11_ie_221_wfa_wpa_t::wpa_v1_cipher_t::wpa_v1_cipher_t(kaitai::kstream *p_io, dot11_ie_221_wfa_wpa_t *p_parent, dot11_ie_221_wfa_wpa_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_oui = m__io->read_bytes(3);
    m_cipher_type = m__io->read_u1();
}

dot11_ie_221_wfa_wpa_t::wpa_v1_cipher_t::~wpa_v1_cipher_t() {
}
