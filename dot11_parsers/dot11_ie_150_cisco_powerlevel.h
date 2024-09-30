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

#ifndef __DOT11_IE_150_CISCO_POWERLEVEL_H__
#define __DOT11_IE_150_CISCO_POWERLEVEL_H__

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_150_cisco_powerlevel {
public:
    dot11_ie_150_cisco_powerlevel() { }
    ~dot11_ie_150_cisco_powerlevel() { }

    constexpr17 static uint32_t cisco_oui() {
        return 0x004096;
    }

    constexpr17 static uint8_t cisco_subtype() {
        return 0x00;
    }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    unsigned int cisco_ccx_txpower() {
        return m_txpower;
    }

    void reset() {
        m_txpower = 0;
    }

protected:
    uint8_t m_txpower;
};

#endif

