// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie.h"

#include <iostream>
#include <fstream>
#include "dot11_ie_221_vendor.h"
#include "dot11_ie_7_country.h"
#include "dot11_ie_11_qbss.h"

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

dot11_ie_t::dot11_ie_data_t::dot11_ie_data_t(kaitai::kstream *p_io, dot11_ie_t::ieee_80211_tag_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_data = m__io->read_bytes_full();
}

dot11_ie_t::dot11_ie_data_t::~dot11_ie_data_t() {
}

dot11_ie_t::dot11_ie_tim_t::dot11_ie_tim_t(kaitai::kstream *p_io, dot11_ie_t::ieee_80211_tag_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_dtim_count = m__io->read_u1();
    m_dtim_period = m__io->read_u1();
    m_bitmap_control = new dot11_ie_tim_bitmap_t(m__io, this, m__root);
    m_pv_bitmap = m__io->read_u1();
}

dot11_ie_t::dot11_ie_tim_t::~dot11_ie_tim_t() {
    delete m_bitmap_control;
}

dot11_ie_t::dot11_ie_basicrates_t::dot11_ie_basicrates_t(kaitai::kstream *p_io, dot11_ie_t::ieee_80211_tag_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_basic_rate = new std::vector<uint8_t>();
    while (!m__io->is_eof()) {
        m_basic_rate->push_back(m__io->read_u1());
    }
}

dot11_ie_t::dot11_ie_basicrates_t::~dot11_ie_basicrates_t() {
    delete m_basic_rate;
}

dot11_ie_t::dot11_ie_tim_bitmap_t::dot11_ie_tim_bitmap_t(kaitai::kstream *p_io, dot11_ie_t::dot11_ie_tim_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_bitmap_offset = m__io->read_bits_int(7);
    m_multicast = m__io->read_bits_int(1);
}

dot11_ie_t::dot11_ie_tim_bitmap_t::~dot11_ie_tim_bitmap_t() {
}

dot11_ie_t::dot11_ie_extendedrates_t::dot11_ie_extendedrates_t(kaitai::kstream *p_io, dot11_ie_t::ieee_80211_tag_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_extended_rate = new std::vector<uint8_t>();
    while (!m__io->is_eof()) {
        m_extended_rate->push_back(m__io->read_u1());
    }
}

dot11_ie_t::dot11_ie_extendedrates_t::~dot11_ie_extendedrates_t() {
    delete m_extended_rate;
}

dot11_ie_t::dot11_ie_ds_channel_t::dot11_ie_ds_channel_t(kaitai::kstream *p_io, dot11_ie_t::ieee_80211_tag_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_current_channel = m__io->read_u1();
}

dot11_ie_t::dot11_ie_ds_channel_t::~dot11_ie_ds_channel_t() {
}

dot11_ie_t::dot11_ie_ssid_t::dot11_ie_ssid_t(kaitai::kstream *p_io, dot11_ie_t::ieee_80211_tag_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_ssid = m__io->read_bytes_full();
}

dot11_ie_t::dot11_ie_ssid_t::~dot11_ie_ssid_t() {
}

dot11_ie_t::dot11_ie_cisco_ccx1_ckip_t::dot11_ie_cisco_ccx1_ckip_t(kaitai::kstream *p_io, dot11_ie_t::ieee_80211_tag_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_ccx1_unk1 = m__io->read_bytes(10);
    m_ap_name = kaitai::kstream::bytes_to_str(kaitai::kstream::bytes_terminate(m__io->read_bytes(16), 0, false), std::string("ASCII"));
    m_station_count = m__io->read_u1();
    m_ccx1_unk2 = m__io->read_bytes(3);
}

dot11_ie_t::dot11_ie_cisco_ccx1_ckip_t::~dot11_ie_cisco_ccx1_ckip_t() {
}

dot11_ie_t::ieee_80211_tag_t::ieee_80211_tag_t(kaitai::kstream *p_io, dot11_ie_t *p_parent, dot11_ie_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_tag_num = m__io->read_u1();
    m_tag_length = m__io->read_u1();
    switch (tag_num()) {
    case 0:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_ssid_t(m__io__raw_tag_data, this, m__root);
        break;
    case 7:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_7_country_t(m__io__raw_tag_data);
        break;
    case 1:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_basicrates_t(m__io__raw_tag_data, this, m__root);
        break;
    case 11:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_11_qbss_t(m__io__raw_tag_data);
        break;
    case 3:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_ds_channel_t(m__io__raw_tag_data, this, m__root);
        break;
    case 5:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_tim_t(m__io__raw_tag_data, this, m__root);
        break;
    case 221:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_221_vendor_t(m__io__raw_tag_data);
        break;
    case 133:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_cisco_ccx1_ckip_t(m__io__raw_tag_data, this, m__root);
        break;
    case 50:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_extendedrates_t(m__io__raw_tag_data, this, m__root);
        break;
    default:
        m__raw_tag_data = m__io->read_bytes(tag_length());
        m__io__raw_tag_data = new kaitai::kstream(m__raw_tag_data);
        m_tag_data = new dot11_ie_data_t(m__io__raw_tag_data, this, m__root);
        break;
    }
}

dot11_ie_t::ieee_80211_tag_t::~ieee_80211_tag_t() {
}
