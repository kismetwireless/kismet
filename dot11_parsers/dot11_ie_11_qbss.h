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

#ifndef __DOT11_IE_11_QBSS_H__
#define __DOT11_IE_11_QBSS_H__

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

class dot11_ie_11_qbss {
public:
    dot11_ie_11_qbss() { }
    ~dot11_ie_11_qbss() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    uint16_t station_count() {
        return m_station_count;
    }

    uint8_t channel_utilization() {
        return m_channel_utilization;
    }

    uint16_t available_admissions() {
        return m_available_admissions;
    }

protected:
    uint16_t m_station_count;
    uint8_t m_channel_utilization;
    uint16_t m_available_admissions;

};


#endif

