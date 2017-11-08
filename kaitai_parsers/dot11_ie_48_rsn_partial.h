#ifndef DOT11_IE_48_RSN_PARTIAL_H_
#define DOT11_IE_48_RSN_PARTIAL_H_

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
 * Implementation of the basic stub version of a RSN IE tag, used for
 * WIDS sensing of insane pairwise counts
 */

class dot11_ie_48_rsn_partial_t : public kaitai::kstruct {

public:

    dot11_ie_48_rsn_partial_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_48_rsn_partial_t* p_root = 0);
    ~dot11_ie_48_rsn_partial_t();

private:
    uint16_t m_rsn_version;
    std::string m_group_cipher;
    uint16_t m_pairwise_count;
    dot11_ie_48_rsn_partial_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint16_t rsn_version() const { return m_rsn_version; }
    std::string group_cipher() const { return m_group_cipher; }
    uint16_t pairwise_count() const { return m_pairwise_count; }
    dot11_ie_48_rsn_partial_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_48_RSN_PARTIAL_H_
