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
    dot11_ie_191_vht_cap() { 
        m_vht_capabilities = 0;
        m_rx_mcs_map = 0;
        m_rx_mcs_set = 0;
        m_tx_mcs_map = 0;
        m_tx_mcs_set = 0;
    } 
    ~dot11_ie_191_vht_cap() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint32_t vht_capabilities() const {
        return m_vht_capabilities;
    }

    constexpr17 uint16_t rx_mcs_map() const {
        return m_rx_mcs_map;
    }

    constexpr17 uint16_t rx_mcs_set() const {
        return m_rx_mcs_set;
    }

    constexpr17 uint16_t tx_mcs_map() const {
        return m_tx_mcs_map;
    }
    
    constexpr17 uint16_t tx_mcs_set() const {
        return m_tx_mcs_set;
    }

    constexpr17 unsigned int max_mpdu_len() const {
        switch (m_vht_capabilities & 0x03) {
            case 0:
                return 3895;
            case 1:
                return 7991;
            case 2:
                return 11454;
            default:
                return 0;
        }
    }

    constexpr17 unsigned int vht_cap_160mhz() const {
        return (m_vht_capabilities & 0x0C) >> 2;
    }

    constexpr17 bool vht_support_160mhz() const {
        return vht_cap_160mhz();
    }

    constexpr17 bool vht_support_80_80mhz() const {
        return vht_cap_160mhz() == 2;
    }

    constexpr17 bool rx_ldpc() const {
        return m_vht_capabilities & 0x10;
    }

    constexpr17 bool vht_cap_80mhz_shortgi() const {
        return m_vht_capabilities & 0x20;
    }

    constexpr17 bool vht_cap_160mhz_shortgi() const {
        return m_vht_capabilities & 0x40;
    }

    constexpr17 bool tx_stbc() const {
        return m_vht_capabilities & 0x80;
    }

    constexpr17 unsigned int rx_stbc_streams() const {
        return (m_vht_capabilities & 0x700) >> 8;
    }

    constexpr17 bool su_beamformer() const {
        return m_vht_capabilities & 0x800;
    }

    constexpr17 bool su_beamformee() const {
        return m_vht_capabilities & 0x1000;
    }

    constexpr17 unsigned int beamformee_sts_streams() const {
        return ((m_vht_capabilities & 0xE000) >> 13) + 1;
    }

    constexpr17 unsigned int sounding_dimensions() const { 
        return ((m_vht_capabilities & 0x70000) >> 16) + 1;
    }
    
    constexpr17 bool mu_beamformer() const {
        return m_vht_capabilities & 0x80000;
    }

    constexpr17 bool mu_beamformee() const {
        return m_vht_capabilities & 0x100000;
    }

    constexpr17 bool txop_ps() const {
        return m_vht_capabilities & 0x200000;
    }

    constexpr17 bool htc_vht() const {
        return m_vht_capabilities & 0x400000;
    }

    constexpr17 unsigned int rx_mcs_s1() const {
        return (rx_mcs_map() & 0x4);
    }

    constexpr17 unsigned int rx_mcs_s2() const {
        return (rx_mcs_map() & 0xC) >> 2;
    }

    constexpr17 unsigned int rx_mcs_s3() const {
        return (rx_mcs_map() & 0x30) >> 4;
    }

    constexpr17 unsigned int rx_mcs_s4() const {
        return (rx_mcs_map() & 0xC0) >> 6;
    }

    constexpr17 unsigned int rx_mcs_s5() const {
        return (rx_mcs_map() & 0x300) >> 8;
    }

    constexpr17 unsigned int rx_mcs_s6() const {
        return (rx_mcs_map() & 0xC00) >> 10;
    }

    constexpr17 unsigned int rx_mcs_s7() const {
        return (rx_mcs_map() & 0x3000) >> 12;
    }
    
    constexpr17 unsigned int rx_mcs_s8() const {
        return (rx_mcs_map() & 0xC000) >> 14;
    }

    constexpr17 unsigned int tx_mcs_s1() const {
        return (tx_mcs_map() & 0x3);
    }

    constexpr17 unsigned int tx_mcs_s2() const {
        return (tx_mcs_map() & 0xC) >> 2;
    }

    constexpr17 unsigned int tx_mcs_s3() const {
        return (tx_mcs_map() & 0x30) >> 4;
    }

    constexpr17 unsigned int tx_mcs_s4() const {
        return (tx_mcs_map() & 0xC0) >> 6;
    }

    constexpr17 unsigned int tx_mcs_s5() const {
        return (tx_mcs_map() & 0x300) >> 8;
    }

    constexpr17 unsigned int tx_mcs_s6() const {
        return (tx_mcs_map() & 0xC00) >> 10;
    }

    constexpr17 unsigned int tx_mcs_s7() const {
        return (tx_mcs_map() & 0x3000) >> 12;
    }

    constexpr17 unsigned int tx_mcs_s8() const {
        return (tx_mcs_map() & 0xC000) >> 14;
    }

    void reset() { 
        m_vht_capabilities = 0;
        m_rx_mcs_map = 0;
        m_rx_mcs_set = 0;
        m_tx_mcs_set = 0;
        m_tx_mcs_map = 0;
    }

protected: 
    uint32_t m_vht_capabilities;
    uint16_t m_rx_mcs_map;
    uint16_t m_rx_mcs_set;
    uint16_t m_tx_mcs_map;
    uint16_t m_tx_mcs_set;

};


#endif

