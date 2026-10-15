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

#ifndef __DOT11_IE_221_UBNT_AIRMAX_M_H__
#define __DOT11_IE_221_UBNT_AIRMAX_M_H__

/* dot11 ie 221 Vendor: Ubiquiti AirMAX M
 *
 * OUI 00:15:6D and OUI type FF FF FF, followed by the ciphertext.
 *
 * Only the first 9 bytes of the decrypted payload are known:
 *   version(1) msg_type(1) src_mac(6) enable(1)
 *
 * The message type space isn't fully mapped; 1 is seen on beacons and probe responses.
 *
 * Based on wiremax (https://github.com/infobyte/wiremax) and pyrmax,
 * MIT licensed, Copyright (c) 2026 Faraday Security
 */

#include <string>
#include <kaitai/kaitaistream.h>

#include "macaddr.h"
#include "multi_constexpr.h"

class dot11_ie_221_ubnt_airmax_m {
public:
    dot11_ie_221_ubnt_airmax_m() {
        reset();
    }
    ~dot11_ie_221_ubnt_airmax_m() { }

    constexpr static uint32_t vendor_oui() {
        return 0x00156d;
    }

    // Parse the vendor tag content following the OUI
    void parse(const std::string& data);

    // Parse decrypted payload; throws if it's truncated
    void parse_payload(const std::string& plaintext);

    constexpr bool parsed() const {
        return m_parsed;
    }

    constexpr bool payload_parsed() const {
        return m_payload_parsed;
    }

    constexpr17 const std::string& ciphertext() const {
        return m_ciphertext;
    }

    constexpr uint8_t version() const {
        return m_version;
    }

    constexpr uint8_t msg_type() const {
        return m_msg_type;
    }

    constexpr17 const mac_addr& src_mac() const {
        return m_src_mac;
    }

    constexpr uint8_t enable() const {
        return m_enable;
    }

    void reset() {
        m_parsed = false;
        m_ciphertext.clear();
        reset_payload();
    }

protected:
    void reset_payload() {
        m_payload_parsed = false;
        m_version = 0;
        m_msg_type = 0;
        m_src_mac = mac_addr{};
        m_enable = 0;
    }

    bool m_parsed;
    bool m_payload_parsed;

    std::string m_ciphertext;

    uint8_t m_version;
    uint8_t m_msg_type;
    mac_addr m_src_mac;
    uint8_t m_enable;
};

#endif /* __DOT11_IE_221_UBNT_AIRMAX_M_H__ */
