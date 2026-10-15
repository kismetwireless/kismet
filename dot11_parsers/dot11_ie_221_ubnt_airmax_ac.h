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

#ifndef __DOT11_IE_221_UBNT_AIRMAX_AC_H__
#define __DOT11_IE_221_UBNT_AIRMAX_AC_H__

/* dot11 ie 221 Vendor: Ubiquiti AirMAX AC
 *
 * Cleartext outer header under OUI 00:27:22 and OUI type FF FF FF:
 *   flags(1) msg_type(1) enc_len(u16be) ciphertext(enc_len)
 *
 * The decrypted payload is version(u16be) src_mac(6), then a body selected by the
 * message type, with fields gated on the version.  Name TLVs are [tag][len][value];
 * tag 1 is the radio name, 2 the SSID, and 3 the firmware name.
 *
 * Only the beacon and probe request layouts have been verified against captures.
 *
 * Based on wiremax (https://github.com/infobyte/wiremax) and pyrmax,
 * MIT licensed, Copyright (c) 2026 Faraday Security
 */

#include <string>
#include <kaitai/kaitaistream.h>

#include "macaddr.h"
#include "multi_constexpr.h"

class dot11_ie_221_ubnt_airmax_ac {
public:
    enum class airmax_msg : uint8_t {
        beacon = 0x01,
        assoc_req = 0x02,
        assoc_resp = 0x03,
        probe_req = 0x04,
        deauth = 0x0c,
    };

    dot11_ie_221_ubnt_airmax_ac() {
        reset();
    }
    ~dot11_ie_221_ubnt_airmax_ac() { }

    constexpr static uint32_t vendor_oui() {
        return 0x002722;
    }

    constexpr static uint8_t flag_encrypted = 0x02;

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

    constexpr uint8_t flags() const {
        return m_flags;
    }

    constexpr bool encrypted() const {
        return m_flags & flag_encrypted;
    }

    constexpr airmax_msg msg_type() const {
        return static_cast<airmax_msg>(m_msg_type);
    }

    constexpr17 const std::string& ciphertext() const {
        return m_ciphertext;
    }

    constexpr uint16_t version() const {
        return m_version;
    }

    // Deauth source MACs are un-masked
    constexpr17 const mac_addr& src_mac() const {
        return m_src_mac;
    }

    constexpr17 const mac_addr& radio_mac() const {
        return m_radio_mac;
    }

    constexpr uint32_t cap_flags() const {
        return m_cap_flags;
    }

    constexpr uint32_t mixed_mode() const {
        return m_mixed_mode;
    }

    constexpr uint8_t tx_chainmask() const {
        return m_tx_chainmask;
    }

    constexpr uint8_t rx_chainmask() const {
        return m_rx_chainmask;
    }

    constexpr bool has_txpower() const {
        return m_has_txpower;
    }

    constexpr uint8_t txpower() const {
        return m_txpower;
    }

    constexpr17 const std::string& radioname() const {
        return m_radioname;
    }

    constexpr17 const std::string& ssid() const {
        return m_ssid;
    }

    constexpr17 const std::string& fwname() const {
        return m_fwname;
    }

    void reset() {
        m_parsed = false;
        m_flags = 0;
        m_msg_type = 0;
        m_ciphertext.clear();
        reset_payload();
    }

protected:
    // Names longer than these are truncated, as the firmware does
    constexpr static size_t name_max_tagged = 0x40;
    constexpr static size_t name_max_untagged = 0x20;

    // Version gates
    constexpr static uint16_t v_tagged_names = 2;
    constexpr static uint16_t v_extra_word = 3;
    constexpr static uint16_t v_rssi = 4;
    constexpr static uint16_t v_fwname = 9;

    constexpr static uint8_t tlv_radioname = 1;
    constexpr static uint8_t tlv_ssid = 2;
    constexpr static uint8_t tlv_fwname = 3;

    void reset_payload() {
        m_payload_parsed = false;
        m_version = 0;
        m_src_mac = mac_addr{};
        m_radio_mac = mac_addr{};
        m_cap_flags = 0;
        m_mixed_mode = 0;
        m_tx_chainmask = 0;
        m_rx_chainmask = 0;
        m_has_txpower = false;
        m_txpower = 0;
        m_radioname.clear();
        m_ssid.clear();
        m_fwname.clear();
    }

    void parse_names(kaitai::kstream& p_io);
    bool parse_tlv(kaitai::kstream& p_io, uint8_t tag, std::string& out);
    void parse_fwname_txpower(kaitai::kstream& p_io);

    bool m_parsed;
    bool m_payload_parsed;

    uint8_t m_flags;
    uint8_t m_msg_type;
    std::string m_ciphertext;

    uint16_t m_version;
    mac_addr m_src_mac;
    mac_addr m_radio_mac;
    uint32_t m_cap_flags;
    uint32_t m_mixed_mode;
    uint8_t m_tx_chainmask;
    uint8_t m_rx_chainmask;
    bool m_has_txpower;
    uint8_t m_txpower;
    std::string m_radioname;
    std::string m_ssid;
    std::string m_fwname;
};

#endif /* __DOT11_IE_221_UBNT_AIRMAX_AC_H__ */
