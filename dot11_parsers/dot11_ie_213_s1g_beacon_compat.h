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

#ifndef __DOT11_IE_213_S1G_BEACON_COMPAT_H__
#define __DOT11_IE_213_S1G_BEACON_COMPAT_H__

#include <kaitai/kaitaistream.h>

class dot11_ie_213_s1g_beacon_compat {
public:
    dot11_ie_213_s1g_beacon_compat() {
        m_parsed = false;
    }
    ~dot11_ie_213_s1g_beacon_compat() { }

    constexpr bool parsed() const {
        return m_parsed;
    }

    void parse(const std::string_view *view);

    constexpr uint16_t info() const {
        return m_info;
    }

    constexpr uint16_t beacon_interval() const {
        return m_beaconinterval;
    }

    constexpr uint32_t tsf_completion() const {
        return m_tsf_completion;
    }

    void reset() {
        m_parsed = false;
        m_info = 0;
        m_beaconinterval = 0;
        m_tsf_completion = 0;
    }

protected:
    bool m_parsed;

    uint16_t m_info;
    uint16_t m_beaconinterval;
    uint32_t m_tsf_completion;
};

#endif /* __DOT11_IE_213_S1G_BEACON_COMPAT_H__ */
