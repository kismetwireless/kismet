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

#ifndef __DOT11_IE_214_SHORT_BEACON_INTERVAL_H__
#define __DOT11_IE_214_SHORT_BEACON_INTERVAL_H__

#include <kaitai/kaitaistream.h>

class dot11_ie_214_short_beacon_interval {
public:
    dot11_ie_214_short_beacon_interval() : m_parsed{false} { }
    ~dot11_ie_214_short_beacon_interval() { }

    constexpr bool parsed() const {
        return m_parsed;
    }

    void parse(const std::string_view *view);

    constexpr uint16_t interval() const {
        return m_interval;
    }

    void reset() {
        m_parsed = false;
    }

protected:
    bool m_parsed;

    uint16_t m_interval;
};

#endif /* __DOT11_IE_214_SHORT_BEACON_INTERVAL_H__ */
