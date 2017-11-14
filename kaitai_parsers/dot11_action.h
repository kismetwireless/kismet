#ifndef DOT11_ACTION_H_
#define DOT11_ACTION_H_

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
 * IEEE802.11 action frames; they look a lot like management frames
 * but with a custom frame control header.
 * 
 * Some of the IE tag parsing overlaps with existing IE tag parsers
 */

class dot11_action_t : public kaitai::kstruct {

public:
    class action_rmm_t;
    class ie_tag_t;

    enum category_code_type_t {
        CATEGORY_CODE_TYPE_SPECTRUM_MANAGEMENT = 0,
        CATEGORY_CODE_TYPE_QOS = 1,
        CATEGORY_CODE_TYPE_DLS = 2,
        CATEGORY_CODE_TYPE_BLOCK_ACK = 3,
        CATEGORY_CODE_TYPE_PUBLIC = 4,
        CATEGORY_CODE_TYPE_RADIO_MEASUREMENT = 5,
        CATEGORY_CODE_TYPE_FASTBSS = 6,
        CATEGORY_CODE_TYPE_HT = 7,
        CATEGORY_CODE_TYPE_SA_QUERY = 8,
        CATEGORY_CODE_TYPE_PUBLIC_PROTECTED = 9,
        CATEGORY_CODE_TYPE_WNM = 10,
        CATEGORY_CODE_TYPE_UNPROTECTED_WNM = 11,
        CATEGORY_CODE_TYPE_TLDS = 12,
        CATEGORY_CODE_TYPE_MESH = 13,
        CATEGORY_CODE_TYPE_MULTIHOP = 14,
        CATEGORY_CODE_TYPE_SELF_PROTECTED = 15,
        CATEGORY_CODE_TYPE_DMG = 16,
        CATEGORY_CODE_TYPE_MGMT_NOTIFICATION = 17,
        CATEGORY_CODE_TYPE_FAST_SESSION_TRANSFER = 18,
        CATEGORY_CODE_TYPE_ROBUST_AV_STREAMING = 19,
        CATEGORY_CODE_TYPE_UNPROTECTED_DMG = 20,
        CATEGORY_CODE_TYPE_VHT = 21,
        CATEGORY_CODE_TYPE_VENDOR_SPECIFIC_PROTECTED = 126,
        CATEGORY_CODE_TYPE_VENDOR_SPECIFIC = 127
    };

    enum rmm_action_type_t {
        RMM_ACTION_TYPE_MEASUREMENT_REQ = 0,
        RMM_ACTION_TYPE_MEASUREMENT_REPORT = 1,
        RMM_ACTION_TYPE_LINK_MEASUREMENT_REQ = 2,
        RMM_ACTION_TYPE_LINK_MEASUREMENT_REPORT = 3,
        RMM_ACTION_TYPE_NEIGHBOR_REQ = 4,
        RMM_ACTION_TYPE_NEIGHBOR_REPORT = 5
    };

    dot11_action_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_action_t* p_root = 0);
    ~dot11_action_t();

    class action_rmm_t : public kaitai::kstruct {

    public:

        action_rmm_t(kaitai::kstream* p_io, dot11_action_t* p_parent = 0, dot11_action_t* p_root = 0);
        ~action_rmm_t();

    private:
        rmm_action_type_t m_rmm_action_code;
        uint8_t m_dialog_token;
        std::vector<ie_tag_t*>* m_tags;
        dot11_action_t* m__root;
        dot11_action_t* m__parent;

    public:
        rmm_action_type_t rmm_action_code() const { return m_rmm_action_code; }
        uint8_t dialog_token() const { return m_dialog_token; }
        std::vector<ie_tag_t*>* tags() const { return m_tags; }
        dot11_action_t* _root() const { return m__root; }
        dot11_action_t* _parent() const { return m__parent; }
    };

    class ie_tag_t : public kaitai::kstruct {

    public:

        ie_tag_t(kaitai::kstream* p_io, dot11_action_t::action_rmm_t* p_parent = 0, dot11_action_t* p_root = 0);
        ~ie_tag_t();

    private:
        uint8_t m_ie;
        uint8_t m_ie_len;
        std::string m_ie_data;
        dot11_action_t* m__root;
        dot11_action_t::action_rmm_t* m__parent;

    public:
        uint8_t ie() const { return m_ie; }
        uint8_t ie_len() const { return m_ie_len; }
        std::string ie_data() const { return m_ie_data; }
        dot11_action_t* _root() const { return m__root; }
        dot11_action_t::action_rmm_t* _parent() const { return m__parent; }
    };

private:
    category_code_type_t m_category_code;
    action_rmm_t* m_action_frame;
    dot11_action_t* m__root;
    kaitai::kstruct* m__parent;
    std::string m__raw_action_frame;
    kaitai::kstream* m__io__raw_action_frame;

public:
    category_code_type_t category_code() const { return m_category_code; }
    action_rmm_t* action_frame() const { return m_action_frame; }
    dot11_action_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
    std::string _raw_action_frame() const { return m__raw_action_frame; }
    kaitai::kstream* _io__raw_action_frame() const { return m__io__raw_action_frame; }
};

#endif  // DOT11_ACTION_H_
