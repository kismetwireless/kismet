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

#ifndef __DOT11_IE_217_S1G_CAPABILITIES_H__
#define __DOT11_IE_217_S1G_CAPABILITIES_H__

#include <kaitai/kaitaistream.h>

class dot11_ie_217_s1g_capabilities {
public:
    dot11_ie_217_s1g_capabilities() {
        m_parsed = false;
    }
    ~dot11_ie_217_s1g_capabilities() { }

    constexpr bool parsed() const {
        return m_parsed;
    }

    void parse(const std::string_view *view);

    constexpr uint8_t byte1() const {
        return m_byte1;
    }

    constexpr uint8_t byte2() const {
        return m_byte2;
    }

    constexpr uint8_t byte3() const {
        return m_byte3;
    }

    constexpr uint8_t byte4() const {
        return m_byte4;
    }

    constexpr uint8_t byte5() const {
        return m_byte5;
    }

    constexpr uint8_t byte6() const {
        return m_byte6;
    }

    constexpr uint8_t byte7() const {
        return m_byte7;
    }

    constexpr uint8_t byte8() const {
        return m_byte8;
    }

    constexpr uint8_t byte9() const {
        return m_byte9;
    }

    constexpr uint8_t byte10() const {
        return m_byte10;
    }

    constexpr bool sig_long() const {
        return (m_byte1 & 0x01);
    }

    constexpr bool short_gi_1mhz() const {
        return (m_byte1 & 0x02);
    }

    constexpr bool short_gi_2mhz() const {
        return (m_byte1 & 0x04);
    }

    constexpr bool short_gi_4mhz() const {
        return (m_byte1 & 0x08);
    }

    constexpr bool short_gi_8mhz() const {
        return (m_byte1 & 0x10);
    }

    constexpr bool short_gi_16mhz() const {
        return (m_byte1 & 0x20);
    }

    constexpr uint8_t supported_widths() const {
        return (m_byte1 & 0xC0) >> 6;
    }

    // TODO all the other fields

    void reset() {
        m_parsed = false;

        m_byte1 = 0;
        m_byte2 = 0;
        m_byte3 = 0;
        m_byte4 = 0;
        m_byte5 = 0;
        m_byte6 = 0;
        m_byte7 = 0;
        m_byte8 = 0;
        m_byte9 = 0;
        m_byte10 = 0;

        m_s1g_mcs_nss = 0;
    }

protected:
    bool m_parsed;

    uint8_t m_byte1;
    uint8_t m_byte2;
    uint8_t m_byte3;
    uint8_t m_byte4;
    uint8_t m_byte5;
    uint8_t m_byte6;
    uint8_t m_byte7;
    uint8_t m_byte8;
    uint8_t m_byte9;
    uint8_t m_byte10;

    uint64_t m_s1g_mcs_nss;
};

#endif /* __DOT11_IE_213_S1G_BEACON_COMPAT_H__ */
