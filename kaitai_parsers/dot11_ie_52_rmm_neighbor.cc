// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_52_rmm_neighbor.h"

#include <iostream>
#include <fstream>

dot11_ie_52_rmm_neighbor_t::dot11_ie_52_rmm_neighbor_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_52_rmm_neighbor_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_bssid_mobility_domain = false;
    f_bssid_capability = false;
    f_bssid_reachability = false;
    f_bssid_security = false;
    f_bssid_ht = false;
    f_bssid_keyscope = false;
    m_bssid = m__io->read_bytes(6);
    m_bssid_info = m__io->read_u4le();
    m_operating_class = m__io->read_u1();
    m_channel_number = m__io->read_u1();
    m_phy_type = m__io->read_u1();
}

dot11_ie_52_rmm_neighbor_t::~dot11_ie_52_rmm_neighbor_t() {
}

dot11_ie_52_rmm_neighbor_t::bssid_info_bits_t::bssid_info_bits_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_52_rmm_neighbor_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_reachability = m__io->read_bits_int(2);
    m_security = m__io->read_bits_int(1);
    m_key_scope = m__io->read_bits_int(1);
    m_capability = m__io->read_bits_int(6);
}

dot11_ie_52_rmm_neighbor_t::bssid_info_bits_t::~bssid_info_bits_t() {
}

int32_t dot11_ie_52_rmm_neighbor_t::bssid_mobility_domain() {
    if (f_bssid_mobility_domain)
        return m_bssid_mobility_domain;
    m_bssid_mobility_domain = (bssid_info() & 1024);
    f_bssid_mobility_domain = true;
    return m_bssid_mobility_domain;
}

int32_t dot11_ie_52_rmm_neighbor_t::bssid_capability() {
    if (f_bssid_capability)
        return m_bssid_capability;
    m_bssid_capability = ((bssid_info() & 1008) >> 4);
    f_bssid_capability = true;
    return m_bssid_capability;
}

int32_t dot11_ie_52_rmm_neighbor_t::bssid_reachability() {
    if (f_bssid_reachability)
        return m_bssid_reachability;
    m_bssid_reachability = (bssid_info() & 3);
    f_bssid_reachability = true;
    return m_bssid_reachability;
}

int32_t dot11_ie_52_rmm_neighbor_t::bssid_security() {
    if (f_bssid_security)
        return m_bssid_security;
    m_bssid_security = (bssid_info() & 4);
    f_bssid_security = true;
    return m_bssid_security;
}

int32_t dot11_ie_52_rmm_neighbor_t::bssid_ht() {
    if (f_bssid_ht)
        return m_bssid_ht;
    m_bssid_ht = (bssid_info() & 2048);
    f_bssid_ht = true;
    return m_bssid_ht;
}

int32_t dot11_ie_52_rmm_neighbor_t::bssid_keyscope() {
    if (f_bssid_keyscope)
        return m_bssid_keyscope;
    m_bssid_keyscope = (bssid_info() & 8);
    f_bssid_keyscope = true;
    return m_bssid_keyscope;
}
