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

#ifndef __DOT11_IE_133_CISCO_CCX_H__
#define __DOT11_IE_133_CISCO_CCX_H__

/* dot11 ie 133 Cisco CCX
 *
 * Cisco embeds a human-readable name into beacons under the CCX tag
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_133_cisco_ccx {
public:
    dot11_ie_133_cisco_ccx() { }
    ~dot11_ie_133_cisco_ccx() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 const std::string& ccx_unk1() const {
        return m_ccx_unk1;
    }

    constexpr17 const std::string& ap_name() const {
        return m_ap_name;
    }

    constexpr17 uint8_t station_count() const {
        return m_station_count;
    }

    constexpr17 const std::string& ccx_unk2() const {
        return m_ccx_unk2;
    }

    void reset() { 
        m_ccx_unk1 = "";
        m_ap_name = "";
        m_station_count = 0;
        m_ccx_unk2 = "";
    }

protected:
    std::string m_ccx_unk1;
    std::string m_ap_name;
    uint8_t m_station_count;
    std::string m_ccx_unk2;
};


#endif

