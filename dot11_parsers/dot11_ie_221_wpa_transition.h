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

#ifndef __DOT11_IE_221_OWE_TRANSITION__
#define __DOT11_IE_221_OWE_TRANSITION__ 

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"
#include "macaddr.h"

class dot11_ie_221_owe_transition {
public:
    dot11_ie_221_owe_transition() { }
    ~dot11_ie_221_owe_transition() { }

    constexpr17 static unsigned int vendor_oui() {
        return 0x506f9a;
    }

    constexpr17 static unsigned int owe_transition_subtype() {
        return 28;
    }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint8_t vendor_type() const {
        return m_vendor_type;
    }

    constexpr17 mac_addr bssid() const {
        return m_bssid;
    }

    constexpr17 const std::string& ssid() const {
        return m_ssid;
    }

    void reset() {
        m_vendor_type = 0;
        m_bssid = mac_addr();
        m_ssid = "";
    }

protected:
    uint8_t m_vendor_type;
    mac_addr m_bssid;
    std::string m_ssid;
};

#endif /* ifndef DOT11_IE_221_OWE_TRANSITION */
