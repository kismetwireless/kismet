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

#ifndef __DOT11_IE_221_MIKROTIK_H__
#define __DOT11_IE_221_MIKROTIK_H__

/* dot11 ie 221 Vendor: MikroTik / RouterBoard
 *
 * Cleartext, under OUI 00:0C:42:
 *   type(1) unknown(2) sub_ie*
 *   sub_ie: subtype(1) len(1) data(len)
 *
 * Subtype 1 carries a 10-byte prefix and the NUL-padded device name.
 *
 * Based on wiremax (https://github.com/infobyte/wiremax) and pyrmax,
 * MIT licensed, Copyright (c) 2026 Faraday Security
 */

#include <string>
#include <kaitai/kaitaistream.h>

#include "multi_constexpr.h"

class dot11_ie_221_mikrotik {
public:
    dot11_ie_221_mikrotik() {
        reset();
    }
    ~dot11_ie_221_mikrotik() { }

    constexpr static uint32_t vendor_oui() {
        return 0x000c42;
    }

    // Parse the vendor tag content following the OUI
    void parse(const std::string& data);

    constexpr bool parsed() const {
        return m_parsed;
    }

    constexpr uint8_t mikrotik_type() const {
        return m_type;
    }

    constexpr17 const std::string& device_name() const {
        return m_device_name;
    }

    void reset() {
        m_parsed = false;
        m_type = 0;
        m_device_name.clear();
    }

protected:
    constexpr static uint8_t subtype_identity = 1;
    constexpr static size_t identity_prefix_len = 10;

    bool m_parsed;
    uint8_t m_type;
    std::string m_device_name;
};

#endif /* __DOT11_IE_221_MIKROTIK_H__ */
