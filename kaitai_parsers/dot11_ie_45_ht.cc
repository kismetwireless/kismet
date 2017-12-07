// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_45_ht.h"

#include <iostream>
#include <fstream>

dot11_ie_45_ht_t::dot11_ie_45_ht_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_45_ht_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ht_cap_40mhz_channel = false;
    f_ht_cap_dss_40mhz = false;
    f_ht_cap_rx_stbc = false;
    f_ht_cap_max_amsdu_len = false;
    f_ht_cap_40mhz_intolerant = false;
    f_ht_cap_sm_powersave = false;
    f_ht_cap_tx_stbc = false;
    f_ht_cap_greenfield = false;
    f_ht_cap_ldpc = false;
    f_ht_cap_20mhz_shortgi = false;
    f_ht_cap_delayed_block_ack = false;
    f_ht_cap_lsig_txop = false;
    f_ht_cap_40mhz_shortgi = false;
    f_ht_cap_psmp_intolerant = false;
    m_ht_capabilities = m__io->read_u2le();
    m_ampdu = m__io->read_u1();
    m_mcs = new rx_mcs_t(m__io, this, m__root);
    m_ht_extended_caps = m__io->read_u2le();
    m_txbf_caps = m__io->read_u4le();
    m_asel_caps = m__io->read_u1();
}

dot11_ie_45_ht_t::~dot11_ie_45_ht_t() {
    delete m_mcs;
}

dot11_ie_45_ht_t::rx_mcs_t::rx_mcs_t(kaitai::kstream *p_io, dot11_ie_45_ht_t *p_parent, dot11_ie_45_ht_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    f_ht_num_streams = false;
    m_rx_mcs_b0 = m__io->read_u1();
    m_rx_mcs_b1 = m__io->read_u1();
    m_rx_mcs_b2 = m__io->read_u1();
    m_rx_mcs_b3 = m__io->read_u1();
    m_rx_mcs_b4 = m__io->read_u1();
    m_rx_mcs_b5 = m__io->read_u1();
    m_rx_mcs_b6 = m__io->read_u1();
    m_rx_mcs_b7 = m__io->read_u1();
    m_rx_mcs_b8 = m__io->read_u1();
    m_rx_mcs_b9 = m__io->read_u1();
    m_supported_data_rate = m__io->read_u2le();
    m_txflags = m__io->read_u1();
}

dot11_ie_45_ht_t::rx_mcs_t::~rx_mcs_t() {
}

int32_t dot11_ie_45_ht_t::rx_mcs_t::ht_num_streams() {
    if (f_ht_num_streams)
        return m_ht_num_streams;
    m_ht_num_streams = (((((rx_mcs_b0() != 0) ? (1) : (0)) + ((rx_mcs_b1() != 0) ? (1) : (0))) + ((rx_mcs_b2() != 0) ? (1) : (0))) + ((rx_mcs_b3() != 0) ? (1) : (0)));
    f_ht_num_streams = true;
    return m_ht_num_streams;
}

int32_t dot11_ie_45_ht_t::ht_cap_40mhz_channel() {
    if (f_ht_cap_40mhz_channel)
        return m_ht_cap_40mhz_channel;
    m_ht_cap_40mhz_channel = (ht_capabilities() & 2);
    f_ht_cap_40mhz_channel = true;
    return m_ht_cap_40mhz_channel;
}

int32_t dot11_ie_45_ht_t::ht_cap_dss_40mhz() {
    if (f_ht_cap_dss_40mhz)
        return m_ht_cap_dss_40mhz;
    m_ht_cap_dss_40mhz = (ht_capabilities() & 4096);
    f_ht_cap_dss_40mhz = true;
    return m_ht_cap_dss_40mhz;
}

int32_t dot11_ie_45_ht_t::ht_cap_rx_stbc() {
    if (f_ht_cap_rx_stbc)
        return m_ht_cap_rx_stbc;
    m_ht_cap_rx_stbc = (ht_capabilities() & 768);
    f_ht_cap_rx_stbc = true;
    return m_ht_cap_rx_stbc;
}

int32_t dot11_ie_45_ht_t::ht_cap_max_amsdu_len() {
    if (f_ht_cap_max_amsdu_len)
        return m_ht_cap_max_amsdu_len;
    m_ht_cap_max_amsdu_len = (ht_capabilities() & 2048);
    f_ht_cap_max_amsdu_len = true;
    return m_ht_cap_max_amsdu_len;
}

int32_t dot11_ie_45_ht_t::ht_cap_40mhz_intolerant() {
    if (f_ht_cap_40mhz_intolerant)
        return m_ht_cap_40mhz_intolerant;
    m_ht_cap_40mhz_intolerant = (ht_capabilities() & 16384);
    f_ht_cap_40mhz_intolerant = true;
    return m_ht_cap_40mhz_intolerant;
}

int32_t dot11_ie_45_ht_t::ht_cap_sm_powersave() {
    if (f_ht_cap_sm_powersave)
        return m_ht_cap_sm_powersave;
    m_ht_cap_sm_powersave = (ht_capabilities() & 12);
    f_ht_cap_sm_powersave = true;
    return m_ht_cap_sm_powersave;
}

int32_t dot11_ie_45_ht_t::ht_cap_tx_stbc() {
    if (f_ht_cap_tx_stbc)
        return m_ht_cap_tx_stbc;
    m_ht_cap_tx_stbc = (ht_capabilities() & 128);
    f_ht_cap_tx_stbc = true;
    return m_ht_cap_tx_stbc;
}

int32_t dot11_ie_45_ht_t::ht_cap_greenfield() {
    if (f_ht_cap_greenfield)
        return m_ht_cap_greenfield;
    m_ht_cap_greenfield = (ht_capabilities() & 16);
    f_ht_cap_greenfield = true;
    return m_ht_cap_greenfield;
}

int32_t dot11_ie_45_ht_t::ht_cap_ldpc() {
    if (f_ht_cap_ldpc)
        return m_ht_cap_ldpc;
    m_ht_cap_ldpc = (ht_capabilities() & 1);
    f_ht_cap_ldpc = true;
    return m_ht_cap_ldpc;
}

int32_t dot11_ie_45_ht_t::ht_cap_20mhz_shortgi() {
    if (f_ht_cap_20mhz_shortgi)
        return m_ht_cap_20mhz_shortgi;
    m_ht_cap_20mhz_shortgi = (ht_capabilities() & 32);
    f_ht_cap_20mhz_shortgi = true;
    return m_ht_cap_20mhz_shortgi;
}

int32_t dot11_ie_45_ht_t::ht_cap_delayed_block_ack() {
    if (f_ht_cap_delayed_block_ack)
        return m_ht_cap_delayed_block_ack;
    m_ht_cap_delayed_block_ack = (ht_capabilities() & 1024);
    f_ht_cap_delayed_block_ack = true;
    return m_ht_cap_delayed_block_ack;
}

int32_t dot11_ie_45_ht_t::ht_cap_lsig_txop() {
    if (f_ht_cap_lsig_txop)
        return m_ht_cap_lsig_txop;
    m_ht_cap_lsig_txop = (ht_capabilities() & 32768);
    f_ht_cap_lsig_txop = true;
    return m_ht_cap_lsig_txop;
}

int32_t dot11_ie_45_ht_t::ht_cap_40mhz_shortgi() {
    if (f_ht_cap_40mhz_shortgi)
        return m_ht_cap_40mhz_shortgi;
    m_ht_cap_40mhz_shortgi = (ht_capabilities() & 64);
    f_ht_cap_40mhz_shortgi = true;
    return m_ht_cap_40mhz_shortgi;
}

int32_t dot11_ie_45_ht_t::ht_cap_psmp_intolerant() {
    if (f_ht_cap_psmp_intolerant)
        return m_ht_cap_psmp_intolerant;
    m_ht_cap_psmp_intolerant = (ht_capabilities() & 8192);
    f_ht_cap_psmp_intolerant = true;
    return m_ht_cap_psmp_intolerant;
}
