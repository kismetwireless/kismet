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

#ifndef __DOT11_IE_221_WFA_H__
#define __DOT11_IE_221_WFA_H__

/* dot11 ie 221 WFA 
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_221_wfa {
public:
    dot11_ie_221_wfa() { }
    ~dot11_ie_221_wfa() { }

    constexpr17 static uint32_t wfa_oui() {
        return 0x506F9A;
    }

    constexpr17 static uint8_t wfa_sub_subscription_remediation() {
        return 0;
    }

    constexpr17 static uint8_t wfa_sub_deauth_imminent() {
        return 1;
    }

    constexpr17 static uint8_t wfa_sub_p2p() {
        return 9;
    }

    constexpr17 static uint8_t wfa_sub_wifi_display() {
        return 10;
    }

    constexpr17 static uint8_t wfa_sub_hs20_indication() {
        return 16;
    }

    constexpr17 static uint8_t wfa_sub_hs20_anqp() {
        return 17;
    }

    constexpr17 static uint8_t wfa_sub_osen() {
        return 18;
    }

    constexpr17 static uint8_t wfa_sub_dpp() {
        return 26;
    }

    constexpr17 static uint8_t wfa_sub_ieee1905_multi_ap() {
        return 27;
    }

    constexpr17 static uint8_t wfa_owe_transition_mode() {
        return 28;
    }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);
    
    constexpr17 uint8_t wfa_subtype() const {
        return m_wfa_subtype;
    }

	constexpr17 const std::string& wfa_content() const {
		return m_wfa_content;
	}

    void reset() {
        m_wfa_subtype = 0;
        m_wfa_content = "";
    }

protected:
    uint8_t m_wfa_subtype;
    std::string m_wfa_content;
};


#endif
