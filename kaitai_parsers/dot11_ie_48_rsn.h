#ifndef DOT11_IE_48_RSN_H_
#define DOT11_IE_48_RSN_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

/**
 * IE tag 48 defines the 802.11i RSN (Robust Security Network) settings
 */

class dot11_ie_48_rsn_t : public kaitai::kstruct {

public:
    class rsn_cipher_t;
    class rsn_management_t;

    enum rsn_cipher_types_t {
        RSN_CIPHER_TYPES_RSN_NONE = 0,
        RSN_CIPHER_TYPES_RSN_WEP_40 = 1,
        RSN_CIPHER_TYPES_RSN_TKIP = 2,
        RSN_CIPHER_TYPES_RSN_AES_OCB = 3,
        RSN_CIPHER_TYPES_RSN_AES_CCM = 4,
        RSN_CIPHER_TYPES_RSN_WEP_104 = 5,
        RSN_CIPHER_TYPES_RSN_BIP = 6,
        RSN_CIPHER_TYPES_RSN_NO_GROUP = 7,
        RSN_CIPHER_TYPES_RSN_GCMP = 8
    };

    enum rsn_management_types_t {
        RSN_MANAGEMENT_TYPES_MGMT_NONE = 0,
        RSN_MANAGEMENT_TYPES_MGMT_WPA = 1,
        RSN_MANAGEMENT_TYPES_MGMT_PSK = 2,
        RSN_MANAGEMENT_TYPES_MGMT_FT_DOT1X = 3,
        RSN_MANAGEMENT_TYPES_MGMT_FT_PSK = 4,
        RSN_MANAGEMENT_TYPES_MGMT_WPA_SHA256 = 5,
        RSN_MANAGEMENT_TYPES_MGMT_PSK_SHA256 = 6,
        RSN_MANAGEMENT_TYPES_MGMT_TDLS_TPK = 7
    };

    dot11_ie_48_rsn_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_48_rsn_t* p_root = 0);
    ~dot11_ie_48_rsn_t();

    class rsn_cipher_t : public kaitai::kstruct {

    public:

        rsn_cipher_t(kaitai::kstream* p_io, dot11_ie_48_rsn_t* p_parent = 0, dot11_ie_48_rsn_t* p_root = 0);
        ~rsn_cipher_t();

    private:
        std::string m_cipher_suite_oui;
        rsn_cipher_types_t m_cipher_type;
        dot11_ie_48_rsn_t* m__root;
        dot11_ie_48_rsn_t* m__parent;

    public:
        std::string cipher_suite_oui() const { return m_cipher_suite_oui; }
        rsn_cipher_types_t cipher_type() const { return m_cipher_type; }
        dot11_ie_48_rsn_t* _root() const { return m__root; }
        dot11_ie_48_rsn_t* _parent() const { return m__parent; }
    };

    class rsn_management_t : public kaitai::kstruct {

    public:

        rsn_management_t(kaitai::kstream* p_io, dot11_ie_48_rsn_t* p_parent = 0, dot11_ie_48_rsn_t* p_root = 0);
        ~rsn_management_t();

    private:
        std::string m_management_suite_oui;
        rsn_management_types_t m_management_type;
        dot11_ie_48_rsn_t* m__root;
        dot11_ie_48_rsn_t* m__parent;

    public:
        std::string management_suite_oui() const { return m_management_suite_oui; }
        rsn_management_types_t management_type() const { return m_management_type; }
        dot11_ie_48_rsn_t* _root() const { return m__root; }
        dot11_ie_48_rsn_t* _parent() const { return m__parent; }
    };

private:
    bool f_ie_num;
    int8_t m_ie_num;

public:
    int8_t ie_num();

private:
    uint16_t m_rsn_version;
    rsn_cipher_t* m_group_cipher;
    uint16_t m_pairwise_count;
    std::vector<rsn_cipher_t*>* m_pairwise_ciphers;
    uint16_t m_akm_count;
    std::vector<rsn_management_t*>* m_akm_ciphers;
    dot11_ie_48_rsn_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint16_t rsn_version() const { return m_rsn_version; }
    rsn_cipher_t* group_cipher() const { return m_group_cipher; }
    uint16_t pairwise_count() const { return m_pairwise_count; }
    std::vector<rsn_cipher_t*>* pairwise_ciphers() const { return m_pairwise_ciphers; }
    uint16_t akm_count() const { return m_akm_count; }
    std::vector<rsn_management_t*>* akm_ciphers() const { return m_akm_ciphers; }
    dot11_ie_48_rsn_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_48_RSN_H_
