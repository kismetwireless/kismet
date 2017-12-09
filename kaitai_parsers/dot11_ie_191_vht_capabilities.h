#ifndef DOT11_IE_191_VHT_CAPABILITIES_H_
#define DOT11_IE_191_VHT_CAPABILITIES_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_191_vht_capabilities_t : public kaitai::kstruct {

public:

    dot11_ie_191_vht_capabilities_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_191_vht_capabilities_t* p_root = 0);
    ~dot11_ie_191_vht_capabilities_t();

private:
    bool f_tx_mcs_s6;
    int32_t m_tx_mcs_s6;

public:
    int32_t tx_mcs_s6();

private:
    bool f_tx_mcs_s3;
    int32_t m_tx_mcs_s3;

public:
    int32_t tx_mcs_s3();

private:
    bool f_tx_mcs_s8;
    int32_t m_tx_mcs_s8;

public:
    int32_t tx_mcs_s8();

private:
    bool f_tx_mcs_s4;
    int32_t m_tx_mcs_s4;

public:
    int32_t tx_mcs_s4();

private:
    bool f_rx_mcs_s4;
    int32_t m_rx_mcs_s4;

public:
    int32_t rx_mcs_s4();

private:
    bool f_tx_mcs_s1;
    int32_t m_tx_mcs_s1;

public:
    int32_t tx_mcs_s1();

private:
    bool f_rx_mcs_s7;
    int32_t m_rx_mcs_s7;

public:
    int32_t rx_mcs_s7();

private:
    bool f_vht_cap_160mhz_supported;
    int32_t m_vht_cap_160mhz_supported;

public:
    int32_t vht_cap_160mhz_supported();

private:
    bool f_tx_mcs_s7;
    int32_t m_tx_mcs_s7;

public:
    int32_t tx_mcs_s7();

private:
    bool f_rx_mcs_s6;
    int32_t m_rx_mcs_s6;

public:
    int32_t rx_mcs_s6();

private:
    bool f_tx_mcs_s2;
    int32_t m_tx_mcs_s2;

public:
    int32_t tx_mcs_s2();

private:
    bool f_rx_mcs_s3;
    int32_t m_rx_mcs_s3;

public:
    int32_t rx_mcs_s3();

private:
    bool f_rx_mcs_s2;
    int32_t m_rx_mcs_s2;

public:
    int32_t rx_mcs_s2();

private:
    bool f_vht_cap_80mhz_shortgi;
    int32_t m_vht_cap_80mhz_shortgi;

public:
    int32_t vht_cap_80mhz_shortgi();

private:
    bool f_rx_mcs_s5;
    int32_t m_rx_mcs_s5;

public:
    int32_t rx_mcs_s5();

private:
    bool f_vht_cap_160mhz_shortgi;
    int32_t m_vht_cap_160mhz_shortgi;

public:
    int32_t vht_cap_160mhz_shortgi();

private:
    bool f_rx_mcs_s1;
    int32_t m_rx_mcs_s1;

public:
    int32_t rx_mcs_s1();

private:
    bool f_tx_mcs_s5;
    int32_t m_tx_mcs_s5;

public:
    int32_t tx_mcs_s5();

private:
    bool f_rx_mcs_s8;
    int32_t m_rx_mcs_s8;

public:
    int32_t rx_mcs_s8();

private:
    uint32_t m_vht_capabilities;
    uint16_t m_rx_mcs_map;
    uint16_t m_rx_mcs_set;
    uint16_t m_tx_mcs_map;
    uint16_t m_tx_mcs_set;
    dot11_ie_191_vht_capabilities_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint32_t vht_capabilities() const { return m_vht_capabilities; }
    uint16_t rx_mcs_map() const { return m_rx_mcs_map; }
    uint16_t rx_mcs_set() const { return m_rx_mcs_set; }
    uint16_t tx_mcs_map() const { return m_tx_mcs_map; }
    uint16_t tx_mcs_set() const { return m_tx_mcs_set; }
    dot11_ie_191_vht_capabilities_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_191_VHT_CAPABILITIES_H_
