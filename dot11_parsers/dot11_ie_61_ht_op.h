/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __DOT11_IE_61_HT_OP_H__
#define __DOT11_IE_61_HT_OP_H__

/* dot11 ie HT operations
 *
 * Defines 802.11n speeds
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>

class dot11_ie_61_ht_op {
public:
    dot11_ie_61_ht_op() { }
    ~dot11_ie_61_ht_op() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    uint8_t primary_channel() {
        return m_primary_channel;
    }

    uint8_t info_subset_1() {
        return m_info_subset_1;
    }

    uint16_t info_subset_2() {
        return m_info_subset_2;
    }

    uint16_t info_subset_3() {
        return m_info_subset_3;
    }

    uint16_t rx_coding_scheme() {
        return m_rx_coding_scheme;
    }

    unsigned int ht_info_chan_offset() {
        return info_subset_1() & 0x03;
    }

    unsigned int ht_info_chan_offset_none() {
        return ht_info_chan_offset() == 0x00;
    }

    unsigned int ht_info_chan_offset_above() {
        return ht_info_chan_offset() == 0x01;
    }

    unsigned int ht_info_chan_offset_below() {
        return ht_info_chan_offset() == 0x03;
    }

    unsigned int ht_info_chanwidth() {
        return info_subset_1() & 0x04;
    }

    unsigned int ht_info_rifs() {
        return info_subset_1() & 0x08;
    }

    unsigned int ht_info_psmp_station() {
        return info_subset_1() & 0x10;
    }

    unsigned int ht_info_shortest_psmp() {
        return (info_subset_1() & 0xe0) >> 5;
    }

protected:
    uint8_t m_primary_channel;
    uint8_t m_info_subset_1;
    uint16_t m_info_subset_2;
    uint16_t m_info_subset_3;
    uint16_t m_rx_coding_scheme;

};


#endif

