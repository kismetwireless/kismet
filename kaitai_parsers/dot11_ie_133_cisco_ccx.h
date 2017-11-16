#ifndef DOT11_IE_133_CISCO_CCX_H_
#define DOT11_IE_133_CISCO_CCX_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_133_cisco_ccx_t : public kaitai::kstruct {

public:

    dot11_ie_133_cisco_ccx_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_133_cisco_ccx_t* p_root = 0);
    ~dot11_ie_133_cisco_ccx_t();

private:
    std::string m_ccx1_unk1;
    std::string m_ap_name;
    uint8_t m_station_count;
    std::string m_ccx1_unk2;
    dot11_ie_133_cisco_ccx_t* m__root;
    kaitai::kstruct* m__parent;

public:
    std::string ccx1_unk1() const { return m_ccx1_unk1; }
    std::string ap_name() const { return m_ap_name; }
    uint8_t station_count() const { return m_station_count; }
    std::string ccx1_unk2() const { return m_ccx1_unk2; }
    dot11_ie_133_cisco_ccx_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_133_CISCO_CCX_H_
