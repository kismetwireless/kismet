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

#ifndef __DOT11_IE_191_VHT_CAP_H__
#define __DOT11_IE_191_VHT_CAP_H__

/* dot11 ie 191 VHT Capabilities
 *
 * 802.11AC VHT capabilities
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_191_vht_cap {
public:
    dot11_ie_191_vht_cap() { } 
    ~dot11_ie_191_vht_cap() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    constexpr uint32_t vht_capabilities() const {
        return m_vht_capabilities;
    }

    constexpr uint16_t rx_mcs_map() const {
        return m_rx_mcs_map;
    }

    constexpr uint16_t rx_mcs_set() const {
        return m_rx_mcs_set;
    }

    constexpr uint16_t tx_mcs_map() const {
        return m_tx_mcs_map;
    }
    
    constexpr uint16_t tx_mcs_set() const {
        return m_tx_mcs_set;
    }

    constexpr unsigned int vht_cap_160mhz() const {
        return vht_capabilities() & 0xC;
    }

    constexpr unsigned int vht_cap_80mhz_shortgi() const {
        return vht_capabilities() & 0x20;
    }

    constexpr unsigned int vht_cap_160mhz_shortgi() const {
        return vht_capabilities() & 0x40;
    }

    constexpr unsigned int rx_mcs_s1() const {
        return (rx_mcs_map() & 0x3);
    }

    constexpr unsigned int rx_mcs_s2() const {
        return (rx_mcs_map() & 0xC) >> 2;
    }

    constexpr unsigned int rx_mcs_s3() const {
        return (rx_mcs_map() & 0x30) >> 4;
    }

    constexpr unsigned int rx_mcs_s4() const {
        return (rx_mcs_map() & 0xC0) >> 6;
    }

    constexpr unsigned int rx_mcs_s5() const {
        return (rx_mcs_map() & 0x300) >> 8;
    }

    constexpr unsigned int rx_mcs_s6() const {
        return (rx_mcs_map() & 0xC00) >> 10;
    }

    constexpr unsigned int rx_mcs_s7() const {
        return (rx_mcs_map() & 0x3000) >> 12;
    }
    
    constexpr unsigned int rx_mcs_s8() const {
        return (rx_mcs_map() & 0xC000) >> 14;
    }

    constexpr unsigned int tx_mcs_s1() const {
        return (tx_mcs_map() & 0x3);
    }

    constexpr unsigned int tx_mcs_s2() const {
        return (tx_mcs_map() & 0xC) >> 2;
    }

    constexpr unsigned int tx_mcs_s3() const {
        return (tx_mcs_map() & 0x30) >> 4;
    }

    constexpr unsigned int tx_mcs_s4() const {
        return (tx_mcs_map() & 0xC0) >> 6;
    }

    constexpr unsigned int tx_mcs_s5() const {
        return (tx_mcs_map() & 0x300) >> 8;
    }

    constexpr unsigned int tx_mcs_s6() const {
        return (tx_mcs_map() & 0xC00) >> 10;
    }

    constexpr unsigned int tx_mcs_s7() const {
        return (tx_mcs_map() & 0x3000) >> 12;
    }

    constexpr unsigned int tx_mcs_s8() const {
        return (tx_mcs_map() & 0xC000) >> 14;
    }

protected: 
    uint32_t m_vht_capabilities;
    uint16_t m_rx_mcs_map;
    uint16_t m_rx_mcs_set;
    uint16_t m_tx_mcs_map;
    uint16_t m_tx_mcs_set;

};


#endif

