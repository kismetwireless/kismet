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

#ifndef __DOT11_IE_221_VENDOR__H__
#define __DOT11_IE_221_VENDOR__H__

/* dot11 ie 221
 *
 * Generic IE221 Vendor parser used to prep tags for consumption by other
 * parsers
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>

class dot11_ie_221_vendor {
public:
    dot11_ie_221_vendor() { } 
    ~dot11_ie_221_vendor() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    std::string vendor_oui() {
        return m_vendor_oiu;
    }

    std::string vendor_tag() {
        return m_vendor_tag;
    }

    std::shared_ptr<kaitai::kstream> vendor_tag_stream() {
        return m_vendor_tag_stream;
    }

    // Process the vendor tag 
    uint32_t vendor_oui_int() {
        return (uint32_t) (
                (vendor_tag()[0] << 16) + 
                (vendor_tag()[1] << 8) +
                (vendor_tag()[2]));
    }

protected:
    std::string m_vendor_oiu;
    std::string m_vendor_tag;
    std::shared_ptr<kaitai::kstream> m_vendor_tag_stream;

};


#endif

