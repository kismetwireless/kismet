// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_55_fastbss.h"

#include <iostream>
#include <fstream>

dot11_ie_55_fastbss_t::dot11_ie_55_fastbss_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_55_fastbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ie_num = false;
    m_mic_control = new fastbss_mic_control_t(m__io, this, m__root);
    m_mic = m__io->read_bytes(16);
    m_anonce = m__io->read_bytes(32);
    m_snonce = m__io->read_bytes(32);
    m_subelements = new std::vector<fastbss_subelement_t*>();
    while (!m__io->is_eof()) {
        m_subelements->push_back(new fastbss_subelement_t(m__io, this, m__root));
    }
}

dot11_ie_55_fastbss_t::~dot11_ie_55_fastbss_t() {
    delete m_mic_control;
    for (std::vector<fastbss_subelement_t*>::iterator it = m_subelements->begin(); it != m_subelements->end(); ++it) {
        delete *it;
    }
    delete m_subelements;
}

dot11_ie_55_fastbss_t::fastbss_subelement_t::fastbss_subelement_t(kaitai::kstream *p_io, dot11_ie_55_fastbss_t *p_parent, dot11_ie_55_fastbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_sub_id = m__io->read_u1();
    m_sub_length = m__io->read_u1();
    switch (sub_id()) {
    case 1:
        m__raw_sub_data = m__io->read_bytes(sub_length());
        m__io__raw_sub_data = new kaitai::kstream(m__raw_sub_data);
        m_sub_data = new fastbss_sub_pmk_r1_keyholder_t(m__io__raw_sub_data, this, m__root);
        break;
    case 2:
        m__raw_sub_data = m__io->read_bytes(sub_length());
        m__io__raw_sub_data = new kaitai::kstream(m__raw_sub_data);
        m_sub_data = new fastbss_sub_gtk_t(m__io__raw_sub_data, this, m__root);
        break;
    case 3:
        m__raw_sub_data = m__io->read_bytes(sub_length());
        m__io__raw_sub_data = new kaitai::kstream(m__raw_sub_data);
        m_sub_data = new fastbss_sub_pmk_r0_khid_t(m__io__raw_sub_data, this, m__root);
        break;
    default:
        m__raw_sub_data = m__io->read_bytes(sub_length());
        m__io__raw_sub_data = new kaitai::kstream(m__raw_sub_data);
        m_sub_data = new fastbss_sub_data_t(m__io__raw_sub_data, this, m__root);
        break;
    }
}

dot11_ie_55_fastbss_t::fastbss_subelement_t::~fastbss_subelement_t() {
}

dot11_ie_55_fastbss_t::fastbss_sub_pmk_r1_keyholder_t::fastbss_sub_pmk_r1_keyholder_t(kaitai::kstream *p_io, dot11_ie_55_fastbss_t::fastbss_subelement_t *p_parent, dot11_ie_55_fastbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_keyholder_id = m__io->read_bytes_full();
}

dot11_ie_55_fastbss_t::fastbss_sub_pmk_r1_keyholder_t::~fastbss_sub_pmk_r1_keyholder_t() {
}

dot11_ie_55_fastbss_t::fastbss_sub_data_t::fastbss_sub_data_t(kaitai::kstream *p_io, dot11_ie_55_fastbss_t::fastbss_subelement_t *p_parent, dot11_ie_55_fastbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_data = m__io->read_bytes_full();
}

dot11_ie_55_fastbss_t::fastbss_sub_data_t::~fastbss_sub_data_t() {
}

dot11_ie_55_fastbss_t::fastbss_sub_gtk_t::fastbss_sub_gtk_t(kaitai::kstream *p_io, dot11_ie_55_fastbss_t::fastbss_subelement_t *p_parent, dot11_ie_55_fastbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_gtk_keyinfo = new fastbss_sub_gtk_keyinfo_t(m__io, this, m__root);
    m_gtk_keylen = m__io->read_u1();
    m_gtk_rsc = m__io->read_bytes(8);
    m_gtk_gtk = m__io->read_bytes_full();
}

dot11_ie_55_fastbss_t::fastbss_sub_gtk_t::~fastbss_sub_gtk_t() {
    delete m_gtk_keyinfo;
}

dot11_ie_55_fastbss_t::fastbss_sub_pmk_r0_khid_t::fastbss_sub_pmk_r0_khid_t(kaitai::kstream *p_io, dot11_ie_55_fastbss_t::fastbss_subelement_t *p_parent, dot11_ie_55_fastbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_keyholder_id = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes_full(), 0, false), std::string("ASCII"));
}

dot11_ie_55_fastbss_t::fastbss_sub_pmk_r0_khid_t::~fastbss_sub_pmk_r0_khid_t() {
}

dot11_ie_55_fastbss_t::fastbss_sub_gtk_keyinfo_t::fastbss_sub_gtk_keyinfo_t(kaitai::kstream *p_io, dot11_ie_55_fastbss_t::fastbss_sub_gtk_t *p_parent, dot11_ie_55_fastbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_keyinfo_reserved = m__io->read_bits_int(14);
    m_keyinfo_keyid = m__io->read_bits_int(2);
}

dot11_ie_55_fastbss_t::fastbss_sub_gtk_keyinfo_t::~fastbss_sub_gtk_keyinfo_t() {
}

dot11_ie_55_fastbss_t::fastbss_mic_control_t::fastbss_mic_control_t(kaitai::kstream *p_io, dot11_ie_55_fastbss_t *p_parent, dot11_ie_55_fastbss_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_reserved = m__io->read_u1();
    m_element_count = m__io->read_u1();
}

dot11_ie_55_fastbss_t::fastbss_mic_control_t::~fastbss_mic_control_t() {
}

int8_t dot11_ie_55_fastbss_t::ie_num() {
    if (f_ie_num)
        return m_ie_num;
    m_ie_num = 55;
    f_ie_num = true;
    return m_ie_num;
}
