// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_61_ht.h"

#include <iostream>
#include <fstream>

dot11_ie_61_ht_t::dot11_ie_61_ht_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_61_ht_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ht_info_chan_offset_below = false;
    f_ht_info_chan_offset_none = false;
    f_ht_info_shortest_psmp = false;
    f_ht_info_chanwidth = false;
    f_ht_info_chan_offset_above = false;
    f_ht_info_chan_offset = false;
    f_ht_info_psmp_station = false;
    f_ht_info_rifs = false;
    m_primary_channel = m__io->read_u1();
    m_info_subset_1 = m__io->read_u1();
    m_info_subset_2 = m__io->read_u2be();
    m_info_subset_3 = m__io->read_u2be();
    m_rx_coding_scheme = m__io->read_u2le();
}

dot11_ie_61_ht_t::~dot11_ie_61_ht_t() {
}

bool dot11_ie_61_ht_t::ht_info_chan_offset_below() {
    if (f_ht_info_chan_offset_below)
        return m_ht_info_chan_offset_below;
    m_ht_info_chan_offset_below = (info_subset_1() & 3) == 3;
    f_ht_info_chan_offset_below = true;
    return m_ht_info_chan_offset_below;
}

bool dot11_ie_61_ht_t::ht_info_chan_offset_none() {
    if (f_ht_info_chan_offset_none)
        return m_ht_info_chan_offset_none;
    m_ht_info_chan_offset_none = (info_subset_1() & 3) == 0;
    f_ht_info_chan_offset_none = true;
    return m_ht_info_chan_offset_none;
}

int32_t dot11_ie_61_ht_t::ht_info_shortest_psmp() {
    if (f_ht_info_shortest_psmp)
        return m_ht_info_shortest_psmp;
    m_ht_info_shortest_psmp = ((info_subset_1() & 224) >> 5);
    f_ht_info_shortest_psmp = true;
    return m_ht_info_shortest_psmp;
}

int32_t dot11_ie_61_ht_t::ht_info_chanwidth() {
    if (f_ht_info_chanwidth)
        return m_ht_info_chanwidth;
    m_ht_info_chanwidth = (info_subset_1() & 4);
    f_ht_info_chanwidth = true;
    return m_ht_info_chanwidth;
}

bool dot11_ie_61_ht_t::ht_info_chan_offset_above() {
    if (f_ht_info_chan_offset_above)
        return m_ht_info_chan_offset_above;
    m_ht_info_chan_offset_above = (info_subset_1() & 3) == 1;
    f_ht_info_chan_offset_above = true;
    return m_ht_info_chan_offset_above;
}

int32_t dot11_ie_61_ht_t::ht_info_chan_offset() {
    if (f_ht_info_chan_offset)
        return m_ht_info_chan_offset;
    m_ht_info_chan_offset = (info_subset_1() & 3);
    f_ht_info_chan_offset = true;
    return m_ht_info_chan_offset;
}

int32_t dot11_ie_61_ht_t::ht_info_psmp_station() {
    if (f_ht_info_psmp_station)
        return m_ht_info_psmp_station;
    m_ht_info_psmp_station = (info_subset_1() & 16);
    f_ht_info_psmp_station = true;
    return m_ht_info_psmp_station;
}

int32_t dot11_ie_61_ht_t::ht_info_rifs() {
    if (f_ht_info_rifs)
        return m_ht_info_rifs;
    m_ht_info_rifs = (info_subset_1() & 8);
    f_ht_info_rifs = true;
    return m_ht_info_rifs;
}
