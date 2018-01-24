#ifndef DOT11_IE_221_WFA_WPA_H_
#define DOT11_IE_221_WFA_WPA_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_221_wfa_wpa_t : public kaitai::kstruct {

public:
    class wpa_v1_cipher_t;

    enum wfa_wpa_cipher_t {
        WFA_WPA_CIPHER_NONE = 0,
        WFA_WPA_CIPHER_WEP_40 = 1,
        WFA_WPA_CIPHER_TKIP = 2,
        WFA_WPA_CIPHER_AES_OCB = 3,
        WFA_WPA_CIPHER_AES_CCM = 4,
        WFA_WPA_CIPHER_WEP_104 = 5,
        WFA_WPA_CIPHER_BIP = 6,
        WFA_WPA_CIPHER_NO_GROUP = 7
    };

    enum wfa_wpa_mgmt_t {
        WFA_WPA_MGMT_NONE = 0,
        WFA_WPA_MGMT_WPA = 1,
        WFA_WPA_MGMT_PSK = 2,
        WFA_WPA_MGMT_FT_DOT1X = 3,
        WFA_WPA_MGMT_FT_PSK = 4,
        WFA_WPA_MGMT_WPA_SHA256 = 5,
        WFA_WPA_MGMT_PSK_SHA256 = 6,
        WFA_WPA_MGMT_TDLS_TPK = 7
    };

    dot11_ie_221_wfa_wpa_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_wfa_wpa_t* p_root = 0);
    ~dot11_ie_221_wfa_wpa_t();

    class wpa_v1_cipher_t : public kaitai::kstruct {

    public:

        wpa_v1_cipher_t(kaitai::kstream* p_io, dot11_ie_221_wfa_wpa_t* p_parent = 0, dot11_ie_221_wfa_wpa_t* p_root = 0);
        ~wpa_v1_cipher_t();

    private:
        std::string m_oui;
        uint8_t m_cipher_type;
        dot11_ie_221_wfa_wpa_t* m__root;
        dot11_ie_221_wfa_wpa_t* m__parent;

    public:
        std::string oui() const { return m_oui; }
        uint8_t cipher_type() const { return m_cipher_type; }
        dot11_ie_221_wfa_wpa_t* _root() const { return m__root; }
        dot11_ie_221_wfa_wpa_t* _parent() const { return m__parent; }
    };

private:
    uint8_t m_vendor_subtype;
    uint16_t m_wpa_version;
    wpa_v1_cipher_t* m_multicast_cipher;
    uint16_t m_unicast_count;
    std::vector<wpa_v1_cipher_t*>* m_unicast_ciphers;
    uint16_t m_akm_count;
    std::vector<wpa_v1_cipher_t*>* m_akm_ciphers;
    dot11_ie_221_wfa_wpa_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t vendor_subtype() const { return m_vendor_subtype; }
    uint16_t wpa_version() const { return m_wpa_version; }
    wpa_v1_cipher_t* multicast_cipher() const { return m_multicast_cipher; }
    uint16_t unicast_count() const { return m_unicast_count; }
    std::vector<wpa_v1_cipher_t*>* unicast_ciphers() const { return m_unicast_ciphers; }
    uint16_t akm_count() const { return m_akm_count; }
    std::vector<wpa_v1_cipher_t*>* akm_ciphers() const { return m_akm_ciphers; }
    dot11_ie_221_wfa_wpa_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_221_WFA_WPA_H_
