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

#ifndef __DOT11_IE_232_S1G_OPERATION_H__
#define __DOT11_IE_232_S1G_OPERATION_H__

#include <kaitai/kaitaistream.h>

class dot11_ie_232_s1g_operation {
public:
    class channel_width {
    public:
        channel_width() :
            m_width{0} { }
        ~channel_width() { }

        void parse(uint8_t w) {
            m_width = 0;
        }

        constexpr uint8_t primary_width_subfield() const {
            return (m_width & 0x01);
        }

        constexpr uint8_t secondary_width_subfield() const {
            return (m_width & 0x1E) >> 1;
        }

        constexpr uint8_t primary_width() const {
            if (!primary_width_subfield()) {
                return 2;
            } else {
                return 1;
            }
        }

        constexpr uint8_t secondary_width() const {
            if (!primary_width_subfield()) {
                switch (secondary_width_subfield()) {
                    case 1: return 2;
                    case 3: return 4;
                    case 7: return 8;
                    case 15: return 16;
                    default: return 0;
                }
            } else {
                switch (secondary_width_subfield()) {
                    case 0: return 1;
                    case 1: return 2;
                    case 3: return 4;
                    case 7: return 8;
                    case 15: return 16;
                    default: return 0;
                }
            }
        }

        constexpr uint8_t width() {
            return primary_width() + secondary_width();
        }

        constexpr uint8_t primary_location() {
            return (m_width & 0x20) >> 5;
        }

        constexpr uint8_t mcs10_possible() const {
            return (m_width & 0x80) >> 7;
        }

        void reset() {
            m_width = 0;
        }
    protected:
        uint8_t m_width;
    };

    dot11_ie_232_s1g_operation() : m_parsed{false} { }
    ~dot11_ie_232_s1g_operation() { }

    constexpr bool parsed() const {
        return m_parsed;
    }

    void parse(const std::string& data);

    const channel_width& width() const {
        return m_width;
    }

    constexpr uint8_t operating_class() const {
        return m_opclass;
    }

    constexpr uint8_t primary_channel() const {
        return m_primary;
    }

    constexpr uint8_t channel_center() const {
        return m_channel_center;
    }

    constexpr uint16_t mcs_nss_set() const {
        return m_mcs_nss_set;
    }

    void reset() {
        m_parsed = false;

        m_width.reset();
    }

protected:
    bool m_parsed;

    channel_width m_width;
    uint8_t m_opclass;
    uint8_t m_primary;
    uint8_t m_channel_center;
    uint16_t m_mcs_nss_set;

};

#endif /* __DOT11_IE_232_S1G_OPERATION_H__ */
