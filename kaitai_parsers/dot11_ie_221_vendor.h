#ifndef DOT11_IE_221_VENDOR_H_
#define DOT11_IE_221_VENDOR_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_221_vendor_t : public kaitai::kstruct {

public:
    class vendor_oui_bytes_t;
    class ieee_221_vendor_tag_t;

    dot11_ie_221_vendor_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_vendor_t* p_root = 0);
    ~dot11_ie_221_vendor_t();

    class vendor_oui_bytes_t : public kaitai::kstruct {

    public:

        vendor_oui_bytes_t(kaitai::kstream* p_io, dot11_ie_221_vendor_t* p_parent = 0, dot11_ie_221_vendor_t* p_root = 0);
        ~vendor_oui_bytes_t();

    private:
        uint8_t m_oui1;
        uint8_t m_oui2;
        uint8_t m_oui3;
        dot11_ie_221_vendor_t* m__root;
        dot11_ie_221_vendor_t* m__parent;

    public:
        uint8_t oui1() const { return m_oui1; }
        uint8_t oui2() const { return m_oui2; }
        uint8_t oui3() const { return m_oui3; }
        dot11_ie_221_vendor_t* _root() const { return m__root; }
        dot11_ie_221_vendor_t* _parent() const { return m__parent; }
    };

    class ieee_221_vendor_tag_t : public kaitai::kstruct {

    public:

        ieee_221_vendor_tag_t(kaitai::kstream* p_io, dot11_ie_221_vendor_t* p_parent = 0, dot11_ie_221_vendor_t* p_root = 0);
        ~ieee_221_vendor_tag_t();

    private:
        std::string m_vendor_data;
        dot11_ie_221_vendor_t* m__root;
        dot11_ie_221_vendor_t* m__parent;

    public:
        std::string vendor_data() const { return m_vendor_data; }
        dot11_ie_221_vendor_t* _root() const { return m__root; }
        dot11_ie_221_vendor_t* _parent() const { return m__parent; }
    };

private:
    bool f_vendor_oui_extract;
    vendor_oui_bytes_t* m_vendor_oui_extract;

public:
    vendor_oui_bytes_t* vendor_oui_extract();

private:
    bool f_vendor_oui_int;
    int32_t m_vendor_oui_int;

public:
    int32_t vendor_oui_int();

private:
    bool f_vendor_oui_type;
    uint8_t m_vendor_oui_type;

public:
    uint8_t vendor_oui_type();

private:
    std::string m_vendor_oui;
    ieee_221_vendor_tag_t* m_vendor_tag;
    dot11_ie_221_vendor_t* m__root;
    kaitai::kstruct* m__parent;

public:
    std::string vendor_oui() const { return m_vendor_oui; }
    ieee_221_vendor_tag_t* vendor_tag() const { return m_vendor_tag; }
    dot11_ie_221_vendor_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_221_VENDOR_H_
