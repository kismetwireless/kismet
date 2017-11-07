#ifndef DOT11_IE_221_MS_WMM_H_
#define DOT11_IE_221_MS_WMM_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_221_ms_wmm_t : public kaitai::kstruct {

public:

    dot11_ie_221_ms_wmm_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_221_ms_wmm_t* p_root = 0);
    ~dot11_ie_221_ms_wmm_t();

private:
    uint8_t m_wme_subtype;
    dot11_ie_221_ms_wmm_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t wme_subtype() const { return m_wme_subtype; }
    dot11_ie_221_ms_wmm_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_221_MS_WMM_H_
