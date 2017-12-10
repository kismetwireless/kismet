// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_221_ms_wps.h"

#include <iostream>
#include <fstream>

dot11_ie_221_ms_wps_t::dot11_ie_221_ms_wps_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ms_wps_oui = false;
    f_ms_wps_subtype = false;
    m_vendor_subtype = m__io->read_u1();
    m_wps_element = new std::vector<wps_de_element_t*>();
    while (!m__io->is_eof()) {
        m_wps_element->push_back(new wps_de_element_t(m__io, this, m__root));
    }
}

dot11_ie_221_ms_wps_t::~dot11_ie_221_ms_wps_t() {
    for (std::vector<wps_de_element_t*>::iterator it = m_wps_element->begin(); it != m_wps_element->end(); ++it) {
        delete *it;
    }
    delete m_wps_element;
}

dot11_ie_221_ms_wps_t::wps_de_uuid_e_t::wps_de_uuid_e_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_uuid_e = m__io->read_bytes_full();
}

dot11_ie_221_ms_wps_t::wps_de_uuid_e_t::~wps_de_uuid_e_t() {
}

dot11_ie_221_ms_wps_t::wps_de_version_t::wps_de_version_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_version = m__io->read_u1();
}

dot11_ie_221_ms_wps_t::wps_de_version_t::~wps_de_version_t() {
}

dot11_ie_221_ms_wps_t::wps_de_state_t::wps_de_state_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    f_wps_state_configured = false;
    m_state = m__io->read_u1();
}

dot11_ie_221_ms_wps_t::wps_de_state_t::~wps_de_state_t() {
}

int8_t dot11_ie_221_ms_wps_t::wps_de_state_t::wps_state_configured() {
    if (f_wps_state_configured)
        return m_wps_state_configured;
    m_wps_state_configured = 2;
    f_wps_state_configured = true;
    return m_wps_state_configured;
}

dot11_ie_221_ms_wps_t::wps_de_vendor_extension_t::wps_de_vendor_extension_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    f_wfa_sub_version = false;
    m_vendor_id = m__io->read_bytes(3);
    m_wfa_sub_id = m__io->read_u1();
    m_wfa_sub_len = m__io->read_u1();
    m_wfa_sub_data = m__io->read_bytes(wfa_sub_len());
}

dot11_ie_221_ms_wps_t::wps_de_vendor_extension_t::~wps_de_vendor_extension_t() {
}

int8_t dot11_ie_221_ms_wps_t::wps_de_vendor_extension_t::wfa_sub_version() {
    if (f_wfa_sub_version)
        return m_wfa_sub_version;
    m_wfa_sub_version = 0;
    f_wfa_sub_version = true;
    return m_wfa_sub_version;
}

dot11_ie_221_ms_wps_t::wps_de_generic_t::wps_de_generic_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_wps_de_data = m__io->read_bytes_full();
}

dot11_ie_221_ms_wps_t::wps_de_generic_t::~wps_de_generic_t() {
}

dot11_ie_221_ms_wps_t::wps_de_rfband_t::wps_de_rfband_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_reserved1 = m__io->read_bits_int(6);
    m_rf_band_5ghz = m__io->read_bits_int(1);
    m_rf_band_24ghz = m__io->read_bits_int(1);
}

dot11_ie_221_ms_wps_t::wps_de_rfband_t::~wps_de_rfband_t() {
}

dot11_ie_221_ms_wps_t::vendor_data_generic_t::vendor_data_generic_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_vendor_data = m__io->read_bytes_full();
}

dot11_ie_221_ms_wps_t::vendor_data_generic_t::~vendor_data_generic_t() {
}

dot11_ie_221_ms_wps_t::wps_de_element_t::wps_de_element_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_wps_de_type = static_cast<dot11_ie_221_ms_wps_t::wps_de_element_t::wps_de_types_t>(m__io->read_u2be());
    m_wps_de_length = m__io->read_u2be();
    switch (wps_de_type()) {
    case WPS_DE_TYPES_AP_SETUP:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_ap_setup_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_STATE:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_state_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_MODEL_NUM:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_rawstr_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_MANUF:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_rawstr_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_SERIAL:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_rawstr_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_VERSION:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_version_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_VENDOR_EXTENSION:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_vendor_extension_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_DEVICE_NAME:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_rawstr_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_UUID_E:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_uuid_e_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_MODEL:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_rawstr_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_PRIMARY_TYPE:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_primary_type_t(m__io__raw_wps_de_content, this, m__root);
        break;
    case WPS_DE_TYPES_RFBANDS:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_rfband_t(m__io__raw_wps_de_content, this, m__root);
        break;
    default:
        m__raw_wps_de_content = m__io->read_bytes(wps_de_length());
        m__io__raw_wps_de_content = new kaitai::kstream(m__raw_wps_de_content);
        m_wps_de_content = new wps_de_generic_t(m__io__raw_wps_de_content, this, m__root);
        break;
    }
}

dot11_ie_221_ms_wps_t::wps_de_element_t::~wps_de_element_t() {
}

dot11_ie_221_ms_wps_t::wps_de_ap_setup_t::wps_de_ap_setup_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_ap_setup_locked = m__io->read_u1();
}

dot11_ie_221_ms_wps_t::wps_de_ap_setup_t::~wps_de_ap_setup_t() {
}

dot11_ie_221_ms_wps_t::wps_de_primary_type_t::wps_de_primary_type_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_category = m__io->read_u2le();
    m_typedata = m__io->read_u4le();
    m_subcategory = m__io->read_u2le();
}

dot11_ie_221_ms_wps_t::wps_de_primary_type_t::~wps_de_primary_type_t() {
}

dot11_ie_221_ms_wps_t::wps_de_rawstr_t::wps_de_rawstr_t(kaitai::kstream *p_io, dot11_ie_221_ms_wps_t::wps_de_element_t *p_parent, dot11_ie_221_ms_wps_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_raw_str = kaitai::kstream::bytes_to_str(m__io->read_bytes_full(), std::string("ASCII"));
}

dot11_ie_221_ms_wps_t::wps_de_rawstr_t::~wps_de_rawstr_t() {
}

int32_t dot11_ie_221_ms_wps_t::ms_wps_oui() {
    if (f_ms_wps_oui)
        return m_ms_wps_oui;
    m_ms_wps_oui = 20722;
    f_ms_wps_oui = true;
    return m_ms_wps_oui;
}

int8_t dot11_ie_221_ms_wps_t::ms_wps_subtype() {
    if (f_ms_wps_subtype)
        return m_ms_wps_subtype;
    m_ms_wps_subtype = 4;
    f_ms_wps_subtype = true;
    return m_ms_wps_subtype;
}
