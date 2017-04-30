#ifndef WPAEAP_H_
#define WPAEAP_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class wpaeap_t : public kaitai::kstruct {

public:
    class eapol_rsn_key_info_t;
    class eapol_field_messagetype_t;
    class eapol_field_macaddress_t;
    class eapol_field_connection_type_flags_t;
    class eapol_rsn_key_t;
    class dot1x_key_t;
    class eapol_field_uuid_t;
    class eapol_field_encryption_type_flags_t;
    class eapol_field_version_t;
    class eapol_field_config_methods_t;
    class dot1x_eapol_t;
    class eapol_field_t;
    class eapol_extended_wpa_wps_t;
    class eapol_field_auth_type_flags_t;

    enum dot1x_key_type_enum_t {
        DOT1X_KEY_TYPE_ENUM_EAPOL_RSN_KEY = 2
    };

    enum eapol_messagetype_enum_t {
        EAPOL_MESSAGETYPE_ENUM_M2 = 4,
        EAPOL_MESSAGETYPE_ENUM_M3 = 7,
        EAPOL_MESSAGETYPE_ENUM_M4 = 8,
        EAPOL_MESSAGETYPE_ENUM_WSC_NACK = 14
    };

    enum eapol_type_enum_t {
        EAPOL_TYPE_ENUM_REQUEST = 1,
        EAPOL_TYPE_ENUM_RESPONSE = 2
    };

    enum eapol_field_type_enum_t {
        EAPOL_FIELD_TYPE_ENUM_AUTH_TYPE_FLAGS = 4100,
        EAPOL_FIELD_TYPE_ENUM_AUTHENTICATOR = 4101,
        EAPOL_FIELD_TYPE_ENUM_CONFIG_METHODS = 4104,
        EAPOL_FIELD_TYPE_ENUM_CONNECTION_TYPE_FLAGS = 4109,
        EAPOL_FIELD_TYPE_ENUM_ENCRYPTION_TYPE_FLAGS = 4112,
        EAPOL_FIELD_TYPE_ENUM_E_HASH1 = 4116,
        EAPOL_FIELD_TYPE_ENUM_E_HASH2 = 4117,
        EAPOL_FIELD_TYPE_ENUM_E_NONCE = 4122,
        EAPOL_FIELD_TYPE_ENUM_MAC_ADDRESS = 4128,
        EAPOL_FIELD_TYPE_ENUM_MANUFACTURER = 4129,
        EAPOL_FIELD_TYPE_ENUM_MESSAGE_TYPE = 4130,
        EAPOL_FIELD_TYPE_ENUM_MODEL_NAME = 4131,
        EAPOL_FIELD_TYPE_ENUM_MODEL_NUMBER = 4132,
        EAPOL_FIELD_TYPE_ENUM_PUBLIC_KEY = 4146,
        EAPOL_FIELD_TYPE_ENUM_REGSTRAR_NONCE = 4153,
        EAPOL_FIELD_TYPE_ENUM_SERIAL_NUMBER = 4162,
        EAPOL_FIELD_TYPE_ENUM_UUID = 4167,
        EAPOL_FIELD_TYPE_ENUM_VENDOR_EXTENSION = 4169,
        EAPOL_FIELD_TYPE_ENUM_VERSION = 4170
    };

    enum key_descriptor_version_enum_t {
        KEY_DESCRIPTOR_VERSION_ENUM_RC4_HMAC_MD5 = 1,
        KEY_DESCRIPTOR_VERSION_ENUM_AES_HMAC_SHA1 = 2,
        KEY_DESCRIPTOR_VERSION_ENUM_AES_HMAC_AES128_CMAC = 3
    };

    enum eapol_wfa_vendortype_enum_t {
        EAPOL_WFA_VENDORTYPE_ENUM_SIMPLECONFIG = 1
    };

    enum dot1x_type_enum_t {
        DOT1X_TYPE_ENUM_EAP_PACKET = 0,
        DOT1X_TYPE_ENUM_KEY = 3
    };

    enum eapol_expanded_type_enum_t {
        EAPOL_EXPANDED_TYPE_ENUM_WFA_WPS = 254
    };

    enum eapol_wfa_opcode_t {
        EAPOL_WFA_OPCODE_WSC_MSG = 4
    };

    wpaeap_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, wpaeap_t* p_root = 0);
    ~wpaeap_t();

    class eapol_rsn_key_info_t : public kaitai::kstruct {

    public:

        eapol_rsn_key_info_t(kaitai::kstream* p_io, wpaeap_t::eapol_rsn_key_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_rsn_key_info_t();

    private:
        uint64_t m_unused;
        bool m_encrypted_key_data;
        bool m_request;
        bool m_error;
        bool m_secure;
        bool m_key_mic;
        bool m_key_ack;
        bool m_install;
        uint64_t m_key_index;
        bool m_pairwise_key;
        key_descriptor_version_enum_t m_key_descriptor_version;
        wpaeap_t* m__root;
        wpaeap_t::eapol_rsn_key_t* m__parent;

    public:
        uint64_t unused() const { return m_unused; }
        bool encrypted_key_data() const { return m_encrypted_key_data; }
        bool request() const { return m_request; }
        bool error() const { return m_error; }
        bool secure() const { return m_secure; }
        bool key_mic() const { return m_key_mic; }
        bool key_ack() const { return m_key_ack; }
        bool install() const { return m_install; }
        uint64_t key_index() const { return m_key_index; }
        bool pairwise_key() const { return m_pairwise_key; }
        key_descriptor_version_enum_t key_descriptor_version() const { return m_key_descriptor_version; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_rsn_key_t* _parent() const { return m__parent; }
    };

    class eapol_field_messagetype_t : public kaitai::kstruct {

    public:

        eapol_field_messagetype_t(kaitai::kstream* p_io, wpaeap_t::eapol_field_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_messagetype_t();

    private:
        eapol_messagetype_enum_t m_messagetype;
        wpaeap_t* m__root;
        wpaeap_t::eapol_field_t* m__parent;

    public:
        eapol_messagetype_enum_t messagetype() const { return m_messagetype; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_field_t* _parent() const { return m__parent; }
    };

    class eapol_field_macaddress_t : public kaitai::kstruct {

    public:

        eapol_field_macaddress_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_macaddress_t();

    private:
        std::string m_macaddress;
        wpaeap_t* m__root;
        kaitai::kstruct* m__parent;

    public:
        std::string macaddress() const { return m_macaddress; }
        wpaeap_t* _root() const { return m__root; }
        kaitai::kstruct* _parent() const { return m__parent; }
    };

    class eapol_field_connection_type_flags_t : public kaitai::kstruct {

    public:

        eapol_field_connection_type_flags_t(kaitai::kstream* p_io, wpaeap_t::eapol_field_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_connection_type_flags_t();

    private:
        uint64_t m_unused;
        bool m_ibss;
        bool m_ess;
        wpaeap_t* m__root;
        wpaeap_t::eapol_field_t* m__parent;

    public:
        uint64_t unused() const { return m_unused; }
        bool ibss() const { return m_ibss; }
        bool ess() const { return m_ess; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_field_t* _parent() const { return m__parent; }
    };

    class eapol_rsn_key_t : public kaitai::kstruct {

    public:

        eapol_rsn_key_t(kaitai::kstream* p_io, wpaeap_t::dot1x_key_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_rsn_key_t();

    private:
        eapol_rsn_key_info_t* m_key_information;
        uint16_t m_key_length;
        uint64_t m_replay_counter;
        std::string m_wpa_key_nonce;
        std::string m_key_iv;
        std::string m_wpa_key_rsc;
        std::string m_wpa_key_id;
        std::string m_wpa_key_mic;
        uint16_t m_wpa_key_data_length;
        std::string m_wpa_key_data;
        wpaeap_t* m__root;
        wpaeap_t::dot1x_key_t* m__parent;

    public:
        eapol_rsn_key_info_t* key_information() const { return m_key_information; }
        uint16_t key_length() const { return m_key_length; }
        uint64_t replay_counter() const { return m_replay_counter; }
        std::string wpa_key_nonce() const { return m_wpa_key_nonce; }
        std::string key_iv() const { return m_key_iv; }
        std::string wpa_key_rsc() const { return m_wpa_key_rsc; }
        std::string wpa_key_id() const { return m_wpa_key_id; }
        std::string wpa_key_mic() const { return m_wpa_key_mic; }
        uint16_t wpa_key_data_length() const { return m_wpa_key_data_length; }
        std::string wpa_key_data() const { return m_wpa_key_data; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::dot1x_key_t* _parent() const { return m__parent; }
    };

    class dot1x_key_t : public kaitai::kstruct {

    public:

        dot1x_key_t(kaitai::kstream* p_io, wpaeap_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~dot1x_key_t();

    private:
        dot1x_key_type_enum_t m_key_descriptor_type;
        eapol_rsn_key_t* m_key_content;
        wpaeap_t* m__root;
        wpaeap_t* m__parent;

    public:
        dot1x_key_type_enum_t key_descriptor_type() const { return m_key_descriptor_type; }
        eapol_rsn_key_t* key_content() const { return m_key_content; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t* _parent() const { return m__parent; }
    };

    class eapol_field_uuid_t : public kaitai::kstruct {

    public:

        eapol_field_uuid_t(kaitai::kstream* p_io, wpaeap_t::eapol_field_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_uuid_t();

    private:
        std::string m_uuid;
        wpaeap_t* m__root;
        wpaeap_t::eapol_field_t* m__parent;

    public:
        std::string uuid() const { return m_uuid; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_field_t* _parent() const { return m__parent; }
    };

    class eapol_field_encryption_type_flags_t : public kaitai::kstruct {

    public:

        eapol_field_encryption_type_flags_t(kaitai::kstream* p_io, wpaeap_t::eapol_field_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_encryption_type_flags_t();

    private:
        uint64_t m_unused;
        bool m_aes;
        bool m_tkip;
        bool m_wep;
        bool m_none;
        wpaeap_t* m__root;
        wpaeap_t::eapol_field_t* m__parent;

    public:
        uint64_t unused() const { return m_unused; }
        bool aes() const { return m_aes; }
        bool tkip() const { return m_tkip; }
        bool wep() const { return m_wep; }
        bool none() const { return m_none; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_field_t* _parent() const { return m__parent; }
    };

    class eapol_field_version_t : public kaitai::kstruct {

    public:

        eapol_field_version_t(kaitai::kstream* p_io, wpaeap_t::eapol_field_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_version_t();

    private:
        uint8_t m_version;
        wpaeap_t* m__root;
        wpaeap_t::eapol_field_t* m__parent;

    public:
        uint8_t version() const { return m_version; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_field_t* _parent() const { return m__parent; }
    };

    class eapol_field_config_methods_t : public kaitai::kstruct {

    public:

        eapol_field_config_methods_t(kaitai::kstream* p_io, wpaeap_t::eapol_field_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_config_methods_t();

    private:
        bool m_unused;
        bool m_physical_display;
        bool m_virtual_display;
        uint64_t m_unused2;
        bool m_physical_button;
        bool m_virtual_button;
        bool m_keypad;
        bool m_push_button;
        bool m_nfc_interface;
        bool m_internal_nfc;
        bool m_external_nfc;
        bool m_display;
        bool m_label;
        bool m_ethernet;
        bool m_usb;
        wpaeap_t* m__root;
        wpaeap_t::eapol_field_t* m__parent;

    public:
        bool unused() const { return m_unused; }
        bool physical_display() const { return m_physical_display; }
        bool virtual_display() const { return m_virtual_display; }
        uint64_t unused2() const { return m_unused2; }
        bool physical_button() const { return m_physical_button; }
        bool virtual_button() const { return m_virtual_button; }
        bool keypad() const { return m_keypad; }
        bool push_button() const { return m_push_button; }
        bool nfc_interface() const { return m_nfc_interface; }
        bool internal_nfc() const { return m_internal_nfc; }
        bool external_nfc() const { return m_external_nfc; }
        bool display() const { return m_display; }
        bool label() const { return m_label; }
        bool ethernet() const { return m_ethernet; }
        bool usb() const { return m_usb; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_field_t* _parent() const { return m__parent; }
    };

    class dot1x_eapol_t : public kaitai::kstruct {

    public:

        dot1x_eapol_t(kaitai::kstream* p_io, wpaeap_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~dot1x_eapol_t();

    private:
        eapol_type_enum_t m_eapol_type;
        uint8_t m_eapol_id;
        uint16_t m_eapol_length;
        eapol_expanded_type_enum_t m_eapol_expanded_type;
        eapol_extended_wpa_wps_t* m_content;
        wpaeap_t* m__root;
        wpaeap_t* m__parent;

    public:
        eapol_type_enum_t eapol_type() const { return m_eapol_type; }
        uint8_t eapol_id() const { return m_eapol_id; }
        uint16_t eapol_length() const { return m_eapol_length; }
        eapol_expanded_type_enum_t eapol_expanded_type() const { return m_eapol_expanded_type; }
        eapol_extended_wpa_wps_t* content() const { return m_content; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t* _parent() const { return m__parent; }
    };

    class eapol_field_t : public kaitai::kstruct {

    public:

        eapol_field_t(kaitai::kstream* p_io, wpaeap_t::eapol_extended_wpa_wps_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_t();

    private:
        eapol_field_type_enum_t m_type;
        uint16_t m_field_length;
        kaitai::kstruct* m_content;
        wpaeap_t* m__root;
        wpaeap_t::eapol_extended_wpa_wps_t* m__parent;
        std::string m__raw_content;
        kaitai::kstream* m__io__raw_content;

    public:
        eapol_field_type_enum_t type() const { return m_type; }
        uint16_t field_length() const { return m_field_length; }
        kaitai::kstruct* content() const { return m_content; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_extended_wpa_wps_t* _parent() const { return m__parent; }
        std::string _raw_content() const { return m__raw_content; }
        kaitai::kstream* _io__raw_content() const { return m__io__raw_content; }
    };

    class eapol_extended_wpa_wps_t : public kaitai::kstruct {

    public:

        eapol_extended_wpa_wps_t(kaitai::kstream* p_io, wpaeap_t::dot1x_eapol_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_extended_wpa_wps_t();

    private:
        std::string m_vendor_id;
        eapol_wfa_vendortype_enum_t m_vendor_type;
        eapol_wfa_opcode_t m_opcode;
        uint8_t m_flags;
        std::vector<eapol_field_t*>* m_fields;
        wpaeap_t* m__root;
        wpaeap_t::dot1x_eapol_t* m__parent;

    public:
        std::string vendor_id() const { return m_vendor_id; }
        eapol_wfa_vendortype_enum_t vendor_type() const { return m_vendor_type; }
        eapol_wfa_opcode_t opcode() const { return m_opcode; }
        uint8_t flags() const { return m_flags; }
        std::vector<eapol_field_t*>* fields() const { return m_fields; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::dot1x_eapol_t* _parent() const { return m__parent; }
    };

    class eapol_field_auth_type_flags_t : public kaitai::kstruct {

    public:

        eapol_field_auth_type_flags_t(kaitai::kstream* p_io, wpaeap_t::eapol_field_t* p_parent = 0, wpaeap_t* p_root = 0);
        ~eapol_field_auth_type_flags_t();

    private:
        uint64_t m_unused;
        bool m_wpa2psk;
        bool m_wpa2;
        bool m_wpa;
        bool m_shared;
        bool m_wpapsk;
        bool m_open;
        wpaeap_t* m__root;
        wpaeap_t::eapol_field_t* m__parent;

    public:
        uint64_t unused() const { return m_unused; }
        bool wpa2psk() const { return m_wpa2psk; }
        bool wpa2() const { return m_wpa2; }
        bool wpa() const { return m_wpa; }
        bool shared() const { return m_shared; }
        bool wpapsk() const { return m_wpapsk; }
        bool open() const { return m_open; }
        wpaeap_t* _root() const { return m__root; }
        wpaeap_t::eapol_field_t* _parent() const { return m__parent; }
    };

private:
    uint8_t m_dot1x_version;
    dot1x_type_enum_t m_dot1x_type;
    uint16_t m_dot1x_length;
    kaitai::kstruct* m_dot1x_content;
    wpaeap_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t dot1x_version() const { return m_dot1x_version; }
    dot1x_type_enum_t dot1x_type() const { return m_dot1x_type; }
    uint16_t dot1x_length() const { return m_dot1x_length; }
    kaitai::kstruct* dot1x_content() const { return m_dot1x_content; }
    wpaeap_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // WPAEAP_H_
