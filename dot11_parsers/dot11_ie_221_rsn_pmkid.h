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

#ifndef __DOT11_IE_221_RSN_PMKID__
#define __DOT11_IE_221_RSN_PMKID__ 

#include <string>
#include <memory>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_221_rsn_pmkid {
public:
    dot11_ie_221_rsn_pmkid() { }
    virtual ~dot11_ie_221_rsn_pmkid() { }

    constexpr17 static unsigned int vendor_oui() {
        return 0x000fac;
    }

    constexpr17 static unsigned int rsnpmkid_subtype() {
        return 4;
    }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint8_t vendor_type() const {
        return m_vendor_type;
    }

    constexpr17 const std::string& pmkid() const {
        return m_pmkid;
    }

private:
    uint8_t m_vendor_type;
    std::string m_pmkid;

};


#endif /* ifndef DOT11_IE_221_RSN_PMKID */
