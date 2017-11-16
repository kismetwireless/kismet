#ifndef DOT11_IE_52_RMM_NEIGHBOR_H_
#define DOT11_IE_52_RMM_NEIGHBOR_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_52_rmm_neighbor_t : public kaitai::kstruct {

public:
    class bssid_info_bits_t;

    dot11_ie_52_rmm_neighbor_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_52_rmm_neighbor_t* p_root = 0);
    ~dot11_ie_52_rmm_neighbor_t();

    class bssid_info_bits_t : public kaitai::kstruct {

    public:

        bssid_info_bits_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_52_rmm_neighbor_t* p_root = 0);
        ~bssid_info_bits_t();

    private:
        uint64_t m_reachability;
        bool m_security;
        bool m_key_scope;
        uint64_t m_capability;
        dot11_ie_52_rmm_neighbor_t* m__root;
        kaitai::kstruct* m__parent;

    public:
        uint64_t reachability() const { return m_reachability; }
        bool security() const { return m_security; }
        bool key_scope() const { return m_key_scope; }
        uint64_t capability() const { return m_capability; }
        dot11_ie_52_rmm_neighbor_t* _root() const { return m__root; }
        kaitai::kstruct* _parent() const { return m__parent; }
    };

private:
    bool f_bssid_mobility_domain;
    int32_t m_bssid_mobility_domain;

public:
    int32_t bssid_mobility_domain();

private:
    bool f_bssid_capability;
    int32_t m_bssid_capability;

public:
    int32_t bssid_capability();

private:
    bool f_bssid_reachability;
    int32_t m_bssid_reachability;

public:
    int32_t bssid_reachability();

private:
    bool f_bssid_security;
    int32_t m_bssid_security;

public:
    int32_t bssid_security();

private:
    bool f_bssid_ht;
    int32_t m_bssid_ht;

public:
    int32_t bssid_ht();

private:
    bool f_bssid_keyscope;
    int32_t m_bssid_keyscope;

public:
    int32_t bssid_keyscope();

private:
    std::string m_bssid;
    uint32_t m_bssid_info;
    uint8_t m_operating_class;
    uint8_t m_channel_number;
    uint8_t m_phy_type;
    dot11_ie_52_rmm_neighbor_t* m__root;
    kaitai::kstruct* m__parent;

public:
    std::string bssid() const { return m_bssid; }
    uint32_t bssid_info() const { return m_bssid_info; }
    uint8_t operating_class() const { return m_operating_class; }
    uint8_t channel_number() const { return m_channel_number; }
    uint8_t phy_type() const { return m_phy_type; }
    dot11_ie_52_rmm_neighbor_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_52_RMM_NEIGHBOR_H_
