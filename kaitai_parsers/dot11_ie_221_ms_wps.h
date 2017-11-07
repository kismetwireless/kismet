#ifndef DOT11_IE_221_MS_WPS_H_
#define DOT11_IE_221_MS_WPS_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_221_ms_wps_t : public kaitai::kstruct {

public:
    class wps_de_uuid_e_t;
    class wps_de_version_t;
    class wps_de_state_t;
    class wps_de_vendor_extension_t;
    class wps_de_generic_t;
    class wps_de_rfband_t;
    class vendor_data_generic_t;
    class wps_de_element_t;
    class wps_de_ap_setup_t;

    dot11_ie_221_ms_wps_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
    ~dot11_ie_221_ms_wps_t();

    class wps_de_uuid_e_t : public kaitai::kstruct {

    public:

        wps_de_uuid_e_t(kaitai::kstream* p_io, dot11_ie_221_ms_wps_t::wps_de_element_t* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~wps_de_uuid_e_t();

    private:
        std::string m_uuid_e;
        dot11_ie_221_ms_wps_t* m__root;
        dot11_ie_221_ms_wps_t::wps_de_element_t* m__parent;

    public:
        std::string uuid_e() const { return m_uuid_e; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        dot11_ie_221_ms_wps_t::wps_de_element_t* _parent() const { return m__parent; }
    };

    class wps_de_version_t : public kaitai::kstruct {

    public:

        wps_de_version_t(kaitai::kstream* p_io, dot11_ie_221_ms_wps_t::wps_de_element_t* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~wps_de_version_t();

    private:
        uint8_t m_version;
        dot11_ie_221_ms_wps_t* m__root;
        dot11_ie_221_ms_wps_t::wps_de_element_t* m__parent;

    public:
        uint8_t version() const { return m_version; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        dot11_ie_221_ms_wps_t::wps_de_element_t* _parent() const { return m__parent; }
    };

    class wps_de_state_t : public kaitai::kstruct {

    public:

        wps_de_state_t(kaitai::kstream* p_io, dot11_ie_221_ms_wps_t::wps_de_element_t* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~wps_de_state_t();

    private:
        bool f_wps_state_configured;
        int8_t m_wps_state_configured;

    public:
        int8_t wps_state_configured();

    private:
        uint8_t m_state;
        dot11_ie_221_ms_wps_t* m__root;
        dot11_ie_221_ms_wps_t::wps_de_element_t* m__parent;

    public:
        uint8_t state() const { return m_state; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        dot11_ie_221_ms_wps_t::wps_de_element_t* _parent() const { return m__parent; }
    };

    class wps_de_vendor_extension_t : public kaitai::kstruct {

    public:

        wps_de_vendor_extension_t(kaitai::kstream* p_io, dot11_ie_221_ms_wps_t::wps_de_element_t* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~wps_de_vendor_extension_t();

    private:
        bool f_wfa_sub_version;
        int8_t m_wfa_sub_version;

    public:
        int8_t wfa_sub_version();

    private:
        std::string m_vendor_id;
        uint8_t m_wfa_sub_id;
        uint8_t m_wfa_sub_len;
        std::string m_wfa_sub_data;
        dot11_ie_221_ms_wps_t* m__root;
        dot11_ie_221_ms_wps_t::wps_de_element_t* m__parent;

    public:
        std::string vendor_id() const { return m_vendor_id; }
        uint8_t wfa_sub_id() const { return m_wfa_sub_id; }
        uint8_t wfa_sub_len() const { return m_wfa_sub_len; }
        std::string wfa_sub_data() const { return m_wfa_sub_data; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        dot11_ie_221_ms_wps_t::wps_de_element_t* _parent() const { return m__parent; }
    };

    class wps_de_generic_t : public kaitai::kstruct {

    public:

        wps_de_generic_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~wps_de_generic_t();

    private:
        std::string m_wps_de_data;
        dot11_ie_221_ms_wps_t* m__root;
        kaitai::kstruct* m__parent;

    public:
        std::string wps_de_data() const { return m_wps_de_data; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        kaitai::kstruct* _parent() const { return m__parent; }
    };

    class wps_de_rfband_t : public kaitai::kstruct {

    public:

        wps_de_rfband_t(kaitai::kstream* p_io, dot11_ie_221_ms_wps_t::wps_de_element_t* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~wps_de_rfband_t();

    private:
        uint64_t m_reserved1;
        bool m_rf_band_5ghz;
        bool m_rf_band_24ghz;
        dot11_ie_221_ms_wps_t* m__root;
        dot11_ie_221_ms_wps_t::wps_de_element_t* m__parent;

    public:
        uint64_t reserved1() const { return m_reserved1; }
        bool rf_band_5ghz() const { return m_rf_band_5ghz; }
        bool rf_band_24ghz() const { return m_rf_band_24ghz; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        dot11_ie_221_ms_wps_t::wps_de_element_t* _parent() const { return m__parent; }
    };

    class vendor_data_generic_t : public kaitai::kstruct {

    public:

        vendor_data_generic_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~vendor_data_generic_t();

    private:
        std::string m_vendor_data;
        dot11_ie_221_ms_wps_t* m__root;
        kaitai::kstruct* m__parent;

    public:
        std::string vendor_data() const { return m_vendor_data; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        kaitai::kstruct* _parent() const { return m__parent; }
    };

    class wps_de_element_t : public kaitai::kstruct {

    public:

        enum wps_de_types_t {
            WPS_DE_TYPES_WPS_DE_TYPE_RFBANDS = 4156,
            WPS_DE_TYPES_WPS_DE_TYPE_STATE = 4164,
            WPS_DE_TYPES_WPS_DE_TYPE_UUID_E = 4167,
            WPS_DE_TYPES_WPS_DE_TYPE_VENDOR_EXTENSION = 4169,
            WPS_DE_TYPES_WPS_DE_TYPE_VERSION = 4170,
            WPS_DE_TYPES_WPS_DE_TYPE_AP_SETUP = 4183
        };

        wps_de_element_t(kaitai::kstream* p_io, dot11_ie_221_ms_wps_t* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~wps_de_element_t();

    private:
        wps_de_types_t m_wps_de_type;
        uint16_t m_wps_de_length;
        kaitai::kstruct* m_wps_de_content;
        dot11_ie_221_ms_wps_t* m__root;
        dot11_ie_221_ms_wps_t* m__parent;
        std::string m__raw_wps_de_content;
        kaitai::kstream* m__io__raw_wps_de_content;

    public:
        wps_de_types_t wps_de_type() const { return m_wps_de_type; }
        uint16_t wps_de_length() const { return m_wps_de_length; }
        kaitai::kstruct* wps_de_content() const { return m_wps_de_content; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        dot11_ie_221_ms_wps_t* _parent() const { return m__parent; }
        std::string _raw_wps_de_content() const { return m__raw_wps_de_content; }
        kaitai::kstream* _io__raw_wps_de_content() const { return m__io__raw_wps_de_content; }
    };

    class wps_de_ap_setup_t : public kaitai::kstruct {

    public:

        wps_de_ap_setup_t(kaitai::kstream* p_io, dot11_ie_221_ms_wps_t::wps_de_element_t* p_parent = 0, dot11_ie_221_ms_wps_t* p_root = 0);
        ~wps_de_ap_setup_t();

    private:
        uint8_t m_ap_setup_locked;
        dot11_ie_221_ms_wps_t* m__root;
        dot11_ie_221_ms_wps_t::wps_de_element_t* m__parent;

    public:
        uint8_t ap_setup_locked() const { return m_ap_setup_locked; }
        dot11_ie_221_ms_wps_t* _root() const { return m__root; }
        dot11_ie_221_ms_wps_t::wps_de_element_t* _parent() const { return m__parent; }
    };

private:
    std::vector<wps_de_element_t*>* m_wps_element;
    dot11_ie_221_ms_wps_t* m__root;
    kaitai::kstruct* m__parent;

public:
    std::vector<wps_de_element_t*>* wps_element() const { return m_wps_element; }
    dot11_ie_221_ms_wps_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_221_MS_WPS_H_
