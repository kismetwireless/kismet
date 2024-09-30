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

#ifndef __DOT11_IE_221_CISCO_CLIENT_MFP_H__
#define __DOT11_IE_221_CISCO_CLIENT_MFP_H__

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_221_cisco_client_mfp {
public:
    dot11_ie_221_cisco_client_mfp() { }
    ~dot11_ie_221_cisco_client_mfp() { }

    constexpr17 static uint32_t cisco_oui() {
        return 0x004096;
    }

    constexpr17 static uint8_t client_mfp_subtype() {
        return 0x14;
    }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 bool client_mfp() {
        return m_client_mfp;
    }

protected:
    bool m_client_mfp;

};

#endif

