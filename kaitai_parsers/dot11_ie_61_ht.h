#ifndef DOT11_IE_61_HT_H_
#define DOT11_IE_61_HT_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_61_ht_t : public kaitai::kstruct {

public:

    dot11_ie_61_ht_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_61_ht_t* p_root = 0);
    ~dot11_ie_61_ht_t();

private:
    bool f_ht_info_chan_offset_below;
    bool m_ht_info_chan_offset_below;

public:
    bool ht_info_chan_offset_below();

private:
    bool f_ht_info_chan_offset_none;
    bool m_ht_info_chan_offset_none;

public:
    bool ht_info_chan_offset_none();

private:
    bool f_ht_info_shortest_psmp;
    int32_t m_ht_info_shortest_psmp;

public:
    int32_t ht_info_shortest_psmp();

private:
    bool f_ht_info_chanwidth;
    int32_t m_ht_info_chanwidth;

public:
    int32_t ht_info_chanwidth();

private:
    bool f_ht_info_chan_offset_above;
    bool m_ht_info_chan_offset_above;

public:
    bool ht_info_chan_offset_above();

private:
    bool f_ht_info_chan_offset;
    int32_t m_ht_info_chan_offset;

public:
    int32_t ht_info_chan_offset();

private:
    bool f_ht_info_psmp_station;
    int32_t m_ht_info_psmp_station;

public:
    int32_t ht_info_psmp_station();

private:
    bool f_ht_info_rifs;
    int32_t m_ht_info_rifs;

public:
    int32_t ht_info_rifs();

private:
    uint8_t m_primary_channel;
    uint8_t m_info_subset_1;
    uint16_t m_info_subset_2;
    uint16_t m_info_subset_3;
    uint16_t m_rx_coding_scheme;
    dot11_ie_61_ht_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t primary_channel() const { return m_primary_channel; }
    uint8_t info_subset_1() const { return m_info_subset_1; }
    uint16_t info_subset_2() const { return m_info_subset_2; }
    uint16_t info_subset_3() const { return m_info_subset_3; }
    uint16_t rx_coding_scheme() const { return m_rx_coding_scheme; }
    dot11_ie_61_ht_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_61_HT_H_
