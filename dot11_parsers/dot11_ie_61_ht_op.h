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
#include "multi_constexpr.h"

class dot11_ie_61_ht_op {
public:
    dot11_ie_61_ht_op() { }
    ~dot11_ie_61_ht_op() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint8_t primary_channel() const {
        return m_primary_channel;
    }

    constexpr17 uint8_t info_subset_1() const {
        return m_info_subset_1;
    }

    constexpr17 uint16_t info_subset_2() const {
        return m_info_subset_2;
    }

    constexpr17 uint16_t info_subset_3() const {
        return m_info_subset_3;
    }

    constexpr17 uint16_t rx_coding_scheme() const {
        return m_rx_coding_scheme;
    }

    constexpr17 unsigned int ht_info_chan_offset() const {
        return info_subset_1() & 0x03;
    }

    constexpr17 unsigned int ht_info_chan_offset_none() const {
        return ht_info_chan_offset() == 0x00;
    }

    constexpr17 unsigned int ht_info_chan_offset_above() const {
        return ht_info_chan_offset() == 0x01;
    }

    constexpr17 unsigned int ht_info_chan_offset_below() const {
        return ht_info_chan_offset() == 0x03;
    }

    constexpr17 unsigned int ht_info_chanwidth() const {
        return info_subset_1() & 0x04;
    }

    constexpr17 unsigned int ht_info_rifs() const {
        return info_subset_1() & 0x08;
    }

    constexpr17 unsigned int ht_info_psmp_station() const {
        return info_subset_1() & 0x10;
    }

    constexpr17 unsigned int ht_info_shortest_psmp() const {
        return (info_subset_1() & 0xe0) >> 5;
    }

    void reset() {
        m_primary_channel = 0;
        m_info_subset_1 = 0;
        m_info_subset_2 = 0;
        m_info_subset_3 = 0;
        m_rx_coding_scheme = 0;
    }

protected:
    uint8_t m_primary_channel;
    uint8_t m_info_subset_1;
    uint16_t m_info_subset_2;
    uint16_t m_info_subset_3;
    uint16_t m_rx_coding_scheme;

};


#endif

