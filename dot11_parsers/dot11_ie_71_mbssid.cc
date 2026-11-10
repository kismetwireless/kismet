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

#include <utility>

#include "util.h"

#include "dot11_ie.h"
#include "dot11_ie_71_mbssid.h"

void dot11_ie_71_mbssid::parse(const std::string& data) {
    membuf d_membuf(data.data(), data.data() + data.length());
    std::istream is(&d_membuf);
    kaitai::kstream p_io(&is);

    uint8_t indicator;

    // Read every subelement before changing anything, so a truncated element adds nothing;
    // it does end any open profile, which can't continue past it
    std::vector<std::pair<uint8_t, std::string>> subs;

    try {
        indicator = p_io.read_u1();

        while (!p_io.is_eof()) {
            uint8_t sub_id = p_io.read_u1();
            uint8_t sub_len = p_io.read_u1();
            subs.emplace_back(sub_id, p_io.read_bytes(sub_len));
        }
    } catch (...) {
        m_profile_open = false;
        throw;
    }

    if (m_num_elements == 0)
        m_max_bssid_indicator = indicator;
    else if (indicator != m_max_bssid_indicator)
        m_indicator_invalid = true;

    if (indicator < 1 || indicator > 8)
        m_indicator_invalid = true;

    m_num_elements++;

    // Only the first subelement may continue a profile left open by the previous element;
    // a continuation is a profile which doesn't start with the nontransmitted capability
    bool may_continue = m_profile_open;
    m_profile_open = false;

    for (auto& s : subs) {
        if (s.first == 0) {
            bool starts_cap = s.second.length() >= 1 && (uint8_t) s.second[0] == 83;

            if (!starts_cap && may_continue && !m_profiles.empty()) {
                auto& p = m_profiles.back();
                p.m_elements.append(s.second);
                p.decode();
            } else {
                auto& p = m_profiles.emplace_back();
                p.m_elements = std::move(s.second);
                p.decode();
            }

            m_profile_open = true;
        } else {
            if (s.first == 221)
                m_vendor.push_back(vendor_subelement{s.first, std::move(s.second)});

            m_profile_open = false;
        }

        may_continue = false;
    }
}

void dot11_ie_71_mbssid::nontransmitted_profile::decode() {
    m_has_capability = false;
    m_capability = 0;
    m_has_ssid = false;
    m_ssid.clear();
    m_has_index = false;
    m_bssid_index = 0;
    m_has_dtim = false;
    m_dtim_period = 0;
    m_dtim_count = 0;
    m_non_inherit_ids.clear();
    m_non_inherit_ext_ids.clear();
    m_malformed = false;

    dot11_ie ie;

    try {
        ie.parse(m_elements);
    } catch (const std::exception& e) {
        m_malformed = true;
        return;
    }

    for (const auto& t : ie.tags()) {
        const auto& d = t.tag_data();

        switch (t.tag_num()) {
            case 0:
                if (m_has_ssid || d.length() > 32) {
                    m_malformed = true;
                    break;
                }

                m_has_ssid = true;
                m_ssid = d;
                break;

            case 71:
                // A profile can't hold another multiple bssid element
                m_malformed = true;
                break;

            case 83:
                if (m_has_capability || d.length() != 2) {
                    m_malformed = true;
                    break;
                }

                m_has_capability = true;
                m_capability = (uint8_t) d[0] | ((uint8_t) d[1] << 8);
                break;

            case 85:
                if (m_has_index || (d.length() != 1 && d.length() != 3)) {
                    m_malformed = true;
                    break;
                }

                m_has_index = true;
                m_bssid_index = (uint8_t) d[0];

                if (d.length() == 3) {
                    m_has_dtim = true;
                    m_dtim_period = (uint8_t) d[1];
                    m_dtim_count = (uint8_t) d[2];
                }
                break;

            case 255:
                // Non-inheritance: ext id 56, then a length-prefixed list of tag ids and
                // a length-prefixed list of ext tag ids
                if (d.length() >= 1 && (uint8_t) d[0] == 56) {
                    size_t pos = 1;

                    if (pos >= d.length()) {
                        m_malformed = true;
                        break;
                    }

                    size_t n = (uint8_t) d[pos++];

                    if (n > d.length() - pos) {
                        m_malformed = true;
                        break;
                    }

                    m_non_inherit_ids.assign(d.begin() + pos, d.begin() + pos + n);
                    pos += n;

                    if (pos >= d.length()) {
                        m_malformed = true;
                        break;
                    }

                    n = (uint8_t) d[pos++];

                    if (n > d.length() - pos) {
                        m_malformed = true;
                        break;
                    }

                    m_non_inherit_ext_ids.assign(d.begin() + pos, d.begin() + pos + n);
                }
                break;

            default:
                break;
        }
    }
}
