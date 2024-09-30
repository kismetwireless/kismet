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

#ifndef __DOT11_IE_192_VHT_OP_H__
#define __DOT11_IE_192_VHT_OP_H__

/* dot11 ie 192 VHT Operation
 *
 * 802.11AC VHT operational speeds
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_192_vht_op {
public:
    dot11_ie_192_vht_op() { }
    ~dot11_ie_192_vht_op() { }

    enum ch_channel_width {
        ch_20_40 = 0,
        ch_80 = 1,
        ch_160 = 2,
        ch_80_80 = 3
    };

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 ch_channel_width channel_width() const {
        return (ch_channel_width) m_channel_width;
    }

    constexpr17 uint8_t center1() const {
        return m_center1;
    }

    constexpr17 uint8_t center2() const {
        return m_center2;
    }

    constexpr17 uint16_t basic_mcs_map() const {
        return m_basic_mcs_map;
    }

    constexpr17 unsigned int basic_mcs_1() const {
        return basic_mcs_map() & 0x3;
    }

    constexpr17 unsigned int basic_mcs_2() const {
        return basic_mcs_map() & 0xC;
    }

    constexpr17 unsigned int basic_mcs_3() const {
        return basic_mcs_map() & 0x30;
    }

    constexpr17 unsigned int basic_mcs_4() const {
        return basic_mcs_map() & 0xC0;
    }

    constexpr17 unsigned int basic_mcs_5() const {
        return basic_mcs_map() & 0x300;
    }

    constexpr17 unsigned int basic_mcs_6() const {
        return basic_mcs_map() & 0xC00;
    }

    constexpr17 unsigned int basic_mcs_7() const {
        return basic_mcs_map() & 0x3000;
    }

    void reset() {
        m_channel_width = 0;
        m_center1 = 0;
        m_center2 = 0;
        m_basic_mcs_map = 0;
    }

protected:
    uint8_t m_channel_width;
    uint8_t m_center1;
    uint8_t m_center2;
    uint16_t m_basic_mcs_map;

};


#endif

