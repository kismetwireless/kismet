// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "wpaeap.h"

#include <iostream>
#include <fstream>

wpaeap_t::wpaeap_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    m_dot1x_version = m__io->read_u1();
    m_dot1x_type = static_cast<wpaeap_t::dot1x_type_enum_t>(m__io->read_u1());
    m_dot1x_length = m__io->read_u2be();
    switch (dot1x_type()) {
    case DOT1X_TYPE_ENUM_EAP_PACKET:
        m_dot1x_content = new dot1x_eapol_t(m__io, this, m__root);
        break;
    case DOT1X_TYPE_ENUM_KEY:
        m_dot1x_content = new dot1x_key_t(m__io, this, m__root);
        break;
    }
}

wpaeap_t::~wpaeap_t() {
}

wpaeap_t::eapol_rsn_key_info_t::eapol_rsn_key_info_t(kaitai::kstream *p_io, wpaeap_t::eapol_rsn_key_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_unused = m__io->read_bits_int(3);
    m_encrypted_key_data = m__io->read_bits_int(1);
    m_request = m__io->read_bits_int(1);
    m_error = m__io->read_bits_int(1);
    m_secure = m__io->read_bits_int(1);
    m_key_mic = m__io->read_bits_int(1);
    m_key_ack = m__io->read_bits_int(1);
    m_install = m__io->read_bits_int(1);
    m_key_index = m__io->read_bits_int(2);
    m_pairwise_key = m__io->read_bits_int(1);
    m_key_descriptor_version = static_cast<wpaeap_t::key_descriptor_version_enum_t>(m__io->read_bits_int(3));
}

wpaeap_t::eapol_rsn_key_info_t::~eapol_rsn_key_info_t() {
}

wpaeap_t::eapol_field_messagetype_t::eapol_field_messagetype_t(kaitai::kstream *p_io, wpaeap_t::eapol_field_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_messagetype = static_cast<wpaeap_t::eapol_messagetype_enum_t>(m__io->read_u1());
}

wpaeap_t::eapol_field_messagetype_t::~eapol_field_messagetype_t() {
}

wpaeap_t::eapol_field_macaddress_t::eapol_field_macaddress_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_macaddress = m__io->read_bytes(6);
}

wpaeap_t::eapol_field_macaddress_t::~eapol_field_macaddress_t() {
}

wpaeap_t::eapol_field_connection_type_flags_t::eapol_field_connection_type_flags_t(kaitai::kstream *p_io, wpaeap_t::eapol_field_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_unused = m__io->read_bits_int(6);
    m_ibss = m__io->read_bits_int(1);
    m_ess = m__io->read_bits_int(1);
}

wpaeap_t::eapol_field_connection_type_flags_t::~eapol_field_connection_type_flags_t() {
}

wpaeap_t::eapol_rsn_key_t::eapol_rsn_key_t(kaitai::kstream *p_io, wpaeap_t::dot1x_key_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_key_information = new eapol_rsn_key_info_t(m__io, this, m__root);
    m_key_length = m__io->read_u2be();
    m_replay_counter = m__io->read_u8be();
    m_wpa_key_nonce = m__io->read_bytes(32);
    m_key_iv = m__io->read_bytes(16);
    m_wpa_key_rsc = m__io->read_bytes(8);
    m_wpa_key_id = m__io->read_bytes(8);
    m_wpa_key_mic = m__io->read_bytes(16);
    m_wpa_key_data_length = m__io->read_u2be();
    m_wpa_key_data = m__io->read_bytes(wpa_key_data_length());
}

wpaeap_t::eapol_rsn_key_t::~eapol_rsn_key_t() {
    delete m_key_information;
}

wpaeap_t::dot1x_key_t::dot1x_key_t(kaitai::kstream *p_io, wpaeap_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_key_descriptor_type = static_cast<wpaeap_t::dot1x_key_type_enum_t>(m__io->read_u1());
    switch (key_descriptor_type()) {
    case DOT1X_KEY_TYPE_ENUM_EAPOL_RSN_KEY:
        m_key_content = new eapol_rsn_key_t(m__io, this, m__root);
        break;
    }
}

wpaeap_t::dot1x_key_t::~dot1x_key_t() {
}

wpaeap_t::eapol_field_uuid_t::eapol_field_uuid_t(kaitai::kstream *p_io, wpaeap_t::eapol_field_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_uuid = m__io->read_bytes(16);
}

wpaeap_t::eapol_field_uuid_t::~eapol_field_uuid_t() {
}

wpaeap_t::eapol_field_encryption_type_flags_t::eapol_field_encryption_type_flags_t(kaitai::kstream *p_io, wpaeap_t::eapol_field_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_unused = m__io->read_bits_int(12);
    m_aes = m__io->read_bits_int(1);
    m_tkip = m__io->read_bits_int(1);
    m_wep = m__io->read_bits_int(1);
    m_none = m__io->read_bits_int(1);
}

wpaeap_t::eapol_field_encryption_type_flags_t::~eapol_field_encryption_type_flags_t() {
}

wpaeap_t::eapol_field_version_t::eapol_field_version_t(kaitai::kstream *p_io, wpaeap_t::eapol_field_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_version = m__io->read_u1();
}

wpaeap_t::eapol_field_version_t::~eapol_field_version_t() {
}

wpaeap_t::eapol_field_config_methods_t::eapol_field_config_methods_t(kaitai::kstream *p_io, wpaeap_t::eapol_field_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_unused = m__io->read_bits_int(1);
    m_physical_display = m__io->read_bits_int(1);
    m_virtual_display = m__io->read_bits_int(1);
    m_unused2 = m__io->read_bits_int(2);
    m_physical_button = m__io->read_bits_int(1);
    m_virtual_button = m__io->read_bits_int(1);
    m_keypad = m__io->read_bits_int(1);
    m_push_button = m__io->read_bits_int(1);
    m_nfc_interface = m__io->read_bits_int(1);
    m_internal_nfc = m__io->read_bits_int(1);
    m_external_nfc = m__io->read_bits_int(1);
    m_display = m__io->read_bits_int(1);
    m_label = m__io->read_bits_int(1);
    m_ethernet = m__io->read_bits_int(1);
    m_usb = m__io->read_bits_int(1);
}

wpaeap_t::eapol_field_config_methods_t::~eapol_field_config_methods_t() {
}

wpaeap_t::dot1x_eapol_t::dot1x_eapol_t(kaitai::kstream *p_io, wpaeap_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_eapol_type = static_cast<wpaeap_t::eapol_type_enum_t>(m__io->read_u1());
    m_eapol_id = m__io->read_u1();
    m_eapol_length = m__io->read_u2be();
    m_eapol_expanded_type = static_cast<wpaeap_t::eapol_expanded_type_enum_t>(m__io->read_u1());
    switch (eapol_expanded_type()) {
    case EAPOL_EXPANDED_TYPE_ENUM_WFA_WPS:
        m_content = new eapol_extended_wpa_wps_t(m__io, this, m__root);
        break;
    }
}

wpaeap_t::dot1x_eapol_t::~dot1x_eapol_t() {
}

wpaeap_t::eapol_field_t::eapol_field_t(kaitai::kstream *p_io, wpaeap_t::eapol_extended_wpa_wps_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_type = static_cast<wpaeap_t::eapol_field_type_enum_t>(m__io->read_u2be());
    m_field_length = m__io->read_u2be();
    switch (type()) {
    case EAPOL_FIELD_TYPE_ENUM_CONFIG_METHODS:
        m__raw_content = m__io->read_bytes(field_length());
        m__io__raw_content = new kaitai::kstream(m__raw_content);
        m_content = new eapol_field_config_methods_t(m__io__raw_content, this, m__root);
        break;
    case EAPOL_FIELD_TYPE_ENUM_UUID:
        m__raw_content = m__io->read_bytes(field_length());
        m__io__raw_content = new kaitai::kstream(m__raw_content);
        m_content = new eapol_field_uuid_t(m__io__raw_content, this, m__root);
        break;
    case EAPOL_FIELD_TYPE_ENUM_VERSION:
        m__raw_content = m__io->read_bytes(field_length());
        m__io__raw_content = new kaitai::kstream(m__raw_content);
        m_content = new eapol_field_version_t(m__io__raw_content, this, m__root);
        break;
    case EAPOL_FIELD_TYPE_ENUM_ENCRYPTION_TYPE_FLAGS:
        m__raw_content = m__io->read_bytes(field_length());
        m__io__raw_content = new kaitai::kstream(m__raw_content);
        m_content = new eapol_field_encryption_type_flags_t(m__io__raw_content, this, m__root);
        break;
    case EAPOL_FIELD_TYPE_ENUM_AUTH_TYPE_FLAGS:
        m__raw_content = m__io->read_bytes(field_length());
        m__io__raw_content = new kaitai::kstream(m__raw_content);
        m_content = new eapol_field_auth_type_flags_t(m__io__raw_content, this, m__root);
        break;
    case EAPOL_FIELD_TYPE_ENUM_MESSAGE_TYPE:
        m__raw_content = m__io->read_bytes(field_length());
        m__io__raw_content = new kaitai::kstream(m__raw_content);
        m_content = new eapol_field_messagetype_t(m__io__raw_content, this, m__root);
        break;
    case EAPOL_FIELD_TYPE_ENUM_CONNECTION_TYPE_FLAGS:
        m__raw_content = m__io->read_bytes(field_length());
        m__io__raw_content = new kaitai::kstream(m__raw_content);
        m_content = new eapol_field_connection_type_flags_t(m__io__raw_content, this, m__root);
        break;
    default:
        m__raw_content = m__io->read_bytes(field_length());
        break;
    }
}

wpaeap_t::eapol_field_t::~eapol_field_t() {
}

wpaeap_t::eapol_extended_wpa_wps_t::eapol_extended_wpa_wps_t(kaitai::kstream *p_io, wpaeap_t::dot1x_eapol_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_vendor_id = m__io->ensure_fixed_contents(std::string("\x00\x37\x2A", 3));
    m_vendor_type = static_cast<wpaeap_t::eapol_wfa_vendortype_enum_t>(m__io->read_u4be());
    m_opcode = static_cast<wpaeap_t::eapol_wfa_opcode_t>(m__io->read_u1());
    m_flags = m__io->read_u1();
    m_fields = new std::vector<eapol_field_t*>();
    while (!m__io->is_eof()) {
        m_fields->push_back(new eapol_field_t(m__io, this, m__root));
    }
}

wpaeap_t::eapol_extended_wpa_wps_t::~eapol_extended_wpa_wps_t() {
    for (std::vector<eapol_field_t*>::iterator it = m_fields->begin(); it != m_fields->end(); ++it) {
        delete *it;
    }
    delete m_fields;
}

wpaeap_t::eapol_field_auth_type_flags_t::eapol_field_auth_type_flags_t(kaitai::kstream *p_io, wpaeap_t::eapol_field_t *p_parent, wpaeap_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_unused = m__io->read_bits_int(10);
    m_wpa2psk = m__io->read_bits_int(1);
    m_wpa2 = m__io->read_bits_int(1);
    m_wpa = m__io->read_bits_int(1);
    m_shared = m__io->read_bits_int(1);
    m_wpapsk = m__io->read_bits_int(1);
    m_open = m__io->read_bits_int(1);
}

wpaeap_t::eapol_field_auth_type_flags_t::~eapol_field_auth_type_flags_t() {
}
