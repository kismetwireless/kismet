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

#ifndef __DOT11_IE_7_COUNTRY_H__
#define __DOT11_IE_7_COUNTRY_H__

/* dot11 ie 7 country
 *
 * 80211d is deprecated.
 *
 * Some APs seem to return bogus country strings which don't include a valid
 * set of triplets.
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>

class dot11_ie_33_power {
public:
    dot11_ie_33_power() {
        m_min_power = 0;
        m_max_power = 0;
    }
    ~dot11_ie_33_power() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    uint8_t min_power() {
        return m_min_power;
    }

    uint8_t max_power() {
        return m_max_power;
    }


protected:
    uint8_t m_min_power;
    uint8_t m_max_power;
};


#endif

