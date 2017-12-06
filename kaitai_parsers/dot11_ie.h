#ifndef DOT11_IE_H_
#define DOT11_IE_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_t : public kaitai::kstruct {

public:
    class ieee_80211_tag_t;

    dot11_ie_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_t* p_root = 0);
    ~dot11_ie_t();

    class ieee_80211_tag_t : public kaitai::kstruct {

    public:

        ieee_80211_tag_t(kaitai::kstream* p_io, dot11_ie_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~ieee_80211_tag_t();

    private:
        uint8_t m_tag_num;
        uint8_t m_tag_length;
        std::string m_tag_data;
        dot11_ie_t* m__root;
        dot11_ie_t* m__parent;

    public:
        uint8_t tag_num() const { return m_tag_num; }
        uint8_t tag_length() const { return m_tag_length; }
        std::string tag_data() const { return m_tag_data; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t* _parent() const { return m__parent; }
    };

private:
    std::vector<ieee_80211_tag_t*>* m_tag;
    dot11_ie_t* m__root;
    kaitai::kstruct* m__parent;

public:
    std::vector<ieee_80211_tag_t*>* tag() const { return m_tag; }
    dot11_ie_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_H_
