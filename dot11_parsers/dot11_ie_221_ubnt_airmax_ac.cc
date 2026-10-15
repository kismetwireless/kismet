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

#include <algorithm>

#include "util.h"

#include "dot11_ie_221_ubnt_airmax_ac.h"

void dot11_ie_221_ubnt_airmax_ac::parse(const std::string& data) {
    membuf d_membuf(data.data(), data.data() + data.length());
    std::istream is(&d_membuf);
    kaitai::kstream p_io(&is);

    reset();

    // 00:27:22 is used for other Ubiquiti IEs as well
    if (p_io.read_bytes(3) != "\xff\xff\xff")
        return;

    m_flags = p_io.read_u1();
    m_msg_type = p_io.read_u1();

    const auto enc_len = p_io.read_u2be();
    m_ciphertext = p_io.read_bytes(enc_len);

    m_parsed = true;
}

bool dot11_ie_221_ubnt_airmax_ac::parse_tlv(kaitai::kstream& p_io, uint8_t tag, std::string& out) {
    const auto start = p_io.pos();

    if (p_io.size() - start < 2)
        return false;

    if (p_io.read_u1() != tag) {
        p_io.seek(start);
        return false;
    }

    // A length past the end of the payload takes what's there
    const auto len = std::min<uint64_t>(p_io.read_u1(), p_io.size() - p_io.pos());

    out = p_io.read_bytes(len);

    if (out.length() > name_max_tagged)
        out.resize(name_max_tagged);

    return true;
}

void dot11_ie_221_ubnt_airmax_ac::parse_names(kaitai::kstream& p_io) {
    if (m_version < v_tagged_names) {
        // Untagged radio name only
        if (p_io.is_eof())
            return;

        const auto len = std::min<uint64_t>(p_io.read_u1(), p_io.size() - p_io.pos());

        m_radioname = p_io.read_bytes(len);

        if (m_radioname.length() > name_max_untagged)
            m_radioname.resize(name_max_untagged);

        return;
    }

    if (parse_tlv(p_io, tlv_radioname, m_radioname))
        parse_tlv(p_io, tlv_ssid, m_ssid);
}

void dot11_ie_221_ubnt_airmax_ac::parse_fwname_txpower(kaitai::kstream& p_io) {
    if (m_version < v_fwname)
        return;

    parse_tlv(p_io, tlv_fwname, m_fwname);

    m_txpower = p_io.read_u1();
    m_has_txpower = true;
}

void dot11_ie_221_ubnt_airmax_ac::parse_payload(const std::string& plaintext) {
    membuf d_membuf(plaintext.data(), plaintext.data() + plaintext.length());
    std::istream is(&d_membuf);
    kaitai::kstream p_io(&is);

    reset_payload();

    m_version = p_io.read_u2be();

    auto src_raw = p_io.read_bytes(6);

    switch (msg_type()) {
        case airmax_msg::beacon:
            m_radio_mac = mac_addr(p_io.read_bytes(6).data(), 6);
            m_cap_flags = p_io.read_u4be();
            m_mixed_mode = p_io.read_u4be();
            parse_names(p_io);
            break;

        case airmax_msg::assoc_req:
            m_tx_chainmask = p_io.read_u1();
            m_rx_chainmask = p_io.read_u1();
            m_cap_flags = p_io.read_u4be();
            // Unknown
            p_io.read_u4be();
            parse_names(p_io);

            if (m_version >= v_extra_word)
                p_io.read_u4be();

            // RSSI, in an unknown encoding
            if (m_version >= v_rssi)
                p_io.read_bytes(2);

            parse_fwname_txpower(p_io);
            break;

        case airmax_msg::assoc_resp:
            // Unknown
            p_io.read_bytes(2);

            if (m_version >= v_extra_word)
                p_io.read_u4be();

            if (m_version >= v_rssi)
                p_io.read_bytes(2);

            parse_fwname_txpower(p_io);
            break;

        case airmax_msg::deauth: {
            // The source is masked with the big-endian jiffies nonce; the remaining 16 bytes
            // are an opaque token
            const auto jiffies = p_io.read_bytes(4);
            p_io.read_bytes(16);

            for (size_t i = 0; i < src_raw.length(); i++)
                src_raw[i] ^= jiffies[i % jiffies.length()];

            break;
        }

        case airmax_msg::probe_req:
        default:
            // Header only, or unknown
            break;
    }

    m_src_mac = mac_addr(src_raw.data(), 6);

    m_payload_parsed = true;
}
