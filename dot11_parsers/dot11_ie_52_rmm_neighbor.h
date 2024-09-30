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

#ifndef __DOT11_IE_52_RMM_NEIGHBOR_H__
#define __DOT11_IE_52_RMM_NEIGHBOR_H__

/* dot11 ie QBSS
 *
 * 802.11 QOS BSS includes station count and channel utilization information
 * reported by an AP
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_52_rmm {
public:
    dot11_ie_52_rmm() { }

    ~dot11_ie_52_rmm() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 const std::string& bssid() const {
        return m_bssid;
    }

    constexpr17 uint32_t bssid_info() const {
        return m_bssid_info;
    }

    constexpr17 uint8_t operating_class() const {
        return m_operating_class;
    }

    constexpr17 uint8_t channel_number() const {
        return m_channel_number;
    }

    constexpr17 uint8_t phy_type() const {
        return m_phy_type;
    }

    constexpr17 unsigned int bssid_reachability() const {
        return bssid_info() & 0x03;
    }

    constexpr17 unsigned int bssid_security() const {
        return bssid_info() & 0x04;
    }

    constexpr17 unsigned int bssid_keyscope() const {
        return bssid_info() & 0x08;
    }

    constexpr17 unsigned int bssid_capability() const {
        return (bssid_info() & 0x3F0) >> 4;
    }

    constexpr17 unsigned int bssid_mobility_domain() const {
        return bssid_info() & 0x400;
    }

    constexpr17 unsigned int bssid_ht() const {
        return bssid_info() & 0x800;
    }


protected:
    std::string m_bssid;
    uint32_t m_bssid_info;
    uint8_t m_operating_class;
    uint8_t m_channel_number;
    uint8_t m_phy_type;

};


#endif

