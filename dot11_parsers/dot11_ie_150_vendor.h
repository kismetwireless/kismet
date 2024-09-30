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

#ifndef __DOT11_IE_150_VENDOR_H__
#define __DOT11_IE_150_VENDOR_H__

/* dot11 ie 150
 *
 * Generic IE150 vendor parser used to prep tags for consumption by other parsers
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_150_vendor {
public:
    dot11_ie_150_vendor() { } 
    ~dot11_ie_150_vendor() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    const std::string& vendor_oui() const {
        return m_vendor_oui;
    }

    const std::string& vendor_tag() const {
        return m_vendor_tag;
    }

    // Process the vendor tag 
    uint32_t vendor_oui_int() const {
        return (uint32_t) (
                ((vendor_oui()[0] & 0xFF) << 16) + 
                ((vendor_oui()[1] & 0xFF) << 8) +
                ((vendor_oui()[2] & 0xFF)));
    }

    constexpr17 uint8_t vendor_oui_type() const {
        return m_vendor_oui_type;
    }

    void reset() {
        m_vendor_oui = "";
        m_vendor_tag = "";
        m_vendor_oui_type = 0;
    }

protected:
    std::string m_vendor_oui;
    std::string m_vendor_tag;
    uint8_t m_vendor_oui_type;
};

#endif

