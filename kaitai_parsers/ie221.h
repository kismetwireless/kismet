#ifndef IE221_H_
#define IE221_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class ie221_t : public kaitai::kstruct {

public:

    ie221_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, ie221_t* p_root = 0);
    ~ie221_t();

private:
    uint8_t m_tag_length;
    std::string m_vendor_oui;
    uint8_t m_vendor_type;
    ie221_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t tag_length() const { return m_tag_length; }
    std::string vendor_oui() const { return m_vendor_oui; }
    uint8_t vendor_type() const { return m_vendor_type; }
    ie221_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // IE221_H_
