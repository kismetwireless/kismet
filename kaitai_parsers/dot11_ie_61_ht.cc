// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_61_ht.h"

#include <iostream>
#include <fstream>

dot11_ie_61_ht_t::dot11_ie_61_ht_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_61_ht_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ie_num = false;
    m_primary_channel = m__io->read_u1();
    m_info_subset_1 = new ht_info_subset_1_t(m__io, this, m__root);
    m_info_subset_2 = new ht_info_subset_2_t(m__io, this, m__root);
    m_info_subset_3 = new ht_info_subset_3_t(m__io, this, m__root);
    m_rx_coding_scheme = m__io->read_u2le();
}

dot11_ie_61_ht_t::~dot11_ie_61_ht_t() {
    delete m_info_subset_1;
    delete m_info_subset_2;
    delete m_info_subset_3;
}

dot11_ie_61_ht_t::ht_info_subset_1_t::ht_info_subset_1_t(kaitai::kstream *p_io, dot11_ie_61_ht_t *p_parent, dot11_ie_61_ht_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_ssi = m__io->read_bits_int(3);
    m_psmp_only = m__io->read_bits_int(1);
    m_rifs = m__io->read_bits_int(1);
    m_channel_width = m__io->read_bits_int(1);
    m_secondary_offset = static_cast<dot11_ie_61_ht_t::secondary_offset_type_t>(m__io->read_bits_int(2));
}

dot11_ie_61_ht_t::ht_info_subset_1_t::~ht_info_subset_1_t() {
}

dot11_ie_61_ht_t::ht_info_subset_2_t::ht_info_subset_2_t(kaitai::kstream *p_io, dot11_ie_61_ht_t *p_parent, dot11_ie_61_ht_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_reserved0 = m__io->read_bits_int(3);
    m_non_ht_present = m__io->read_bits_int(1);
    m_tx_burst_limit = m__io->read_bits_int(1);
    m_non_greenfield_present = m__io->read_bits_int(1);
    m_operating_mode = m__io->read_bits_int(2);
    m_reserved1 = m__io->read_bits_int(8);
}

dot11_ie_61_ht_t::ht_info_subset_2_t::~ht_info_subset_2_t() {
}

dot11_ie_61_ht_t::ht_info_subset_3_t::ht_info_subset_3_t(kaitai::kstream *p_io, dot11_ie_61_ht_t *p_parent, dot11_ie_61_ht_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_dual_cts_required = m__io->read_bits_int(1);
    m_dual_beacon_tx = m__io->read_bits_int(1);
    m_reserved0 = m__io->read_bits_int(6);
    m_reserved1 = m__io->read_bits_int(4);
    m_pco_phase = m__io->read_bits_int(1);
    m_pco_phase_enabled = m__io->read_bits_int(1);
    m_lsig_txop_protection = m__io->read_bits_int(1);
    m_beacon_id = m__io->read_bits_int(1);
}

dot11_ie_61_ht_t::ht_info_subset_3_t::~ht_info_subset_3_t() {
}

int8_t dot11_ie_61_ht_t::ie_num() {
    if (f_ie_num)
        return m_ie_num;
    m_ie_num = 61;
    f_ie_num = true;
    return m_ie_num;
}
