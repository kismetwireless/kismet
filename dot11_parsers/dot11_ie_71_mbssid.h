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

#ifndef __DOT11_IE_71_MBSSID__
#define __DOT11_IE_71_MBSSID__

/* dot11 ie 71 multiple bssid
 *
 * An AP hosting several BSSs on one radio advertises the others (the nontransmitted
 * BSSIDs) inside the beacons and probe responses of the transmitted BSSID.  Each
 * nontransmitted BSSID profile is a list of IE tags which differ from the transmitted
 * BSSID; anything not listed is inherited, unless named in a non-inheritance element.
 *
 * A profile too long for one element continues in the next mbssid element of the same
 * frame, so one parser instance collects every ie 71 tag of a frame in order.
 */

#include <string>
#include <vector>
#include <cstdint>

class dot11_ie_71_mbssid {
public:
    class nontransmitted_profile {
    public:
        friend class dot11_ie_71_mbssid;

        nontransmitted_profile() { reset(); }
        ~nontransmitted_profile() { }

        // Raw IE tags of the profile, with any split parts joined
        const std::string& elements() const {
            return m_elements;
        }

        constexpr bool has_capability() const {
            return m_has_capability;
        }

        constexpr uint16_t capability() const {
            return m_capability;
        }

        constexpr bool has_ssid() const {
            return m_has_ssid;
        }

        // Raw SSID bytes, at most 32
        const std::string& ssid() const {
            return m_ssid;
        }

        constexpr bool has_index() const {
            return m_has_index;
        }

        constexpr uint8_t bssid_index() const {
            return m_bssid_index;
        }

        // DTIM fields are only present in beacons
        constexpr bool has_dtim() const {
            return m_has_dtim;
        }

        constexpr uint8_t dtim_period() const {
            return m_dtim_period;
        }

        constexpr uint8_t dtim_count() const {
            return m_dtim_count;
        }

        // Tags of the transmitted BSSID this profile does not inherit
        const std::vector<uint8_t>& non_inherit_ids() const {
            return m_non_inherit_ids;
        }

        const std::vector<uint8_t>& non_inherit_ext_ids() const {
            return m_non_inherit_ext_ids;
        }

        // Profile elements didn't parse, or carried an invalid capability, ssid, or index
        constexpr bool malformed() const {
            return m_malformed;
        }

        // A profile names a BSS when it has a capability and a usable index
        constexpr bool valid(uint8_t max_indicator) const {
            return !m_malformed && m_has_capability && m_has_index && m_bssid_index != 0 &&
                max_indicator >= 1 && max_indicator <= 8 &&
                m_bssid_index < (1U << max_indicator);
        }

        void reset() {
            m_elements.clear();
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
        }

    protected:
        void decode();

        std::string m_elements;
        bool m_has_capability;
        uint16_t m_capability;
        bool m_has_ssid;
        std::string m_ssid;
        bool m_has_index;
        uint8_t m_bssid_index;
        bool m_has_dtim;
        uint8_t m_dtim_period;
        uint8_t m_dtim_count;
        std::vector<uint8_t> m_non_inherit_ids;
        std::vector<uint8_t> m_non_inherit_ext_ids;
        bool m_malformed;
    };

    class vendor_subelement {
    public:
        uint8_t id;
        std::string content;
    };

    dot11_ie_71_mbssid() { reset(); }
    ~dot11_ie_71_mbssid() { }

    // Add one ie 71 tag; throws on a truncated element, keeping the profiles of
    // earlier elements
    void parse(const std::string& data);

    constexpr bool parsed() const {
        return m_num_elements > 0;
    }

    constexpr unsigned int num_elements() const {
        return m_num_elements;
    }

    // n, where the BSS set holds 2^n BSSIDs
    constexpr uint8_t max_bssid_indicator() const {
        return m_max_bssid_indicator;
    }

    constexpr unsigned int max_bssids() const {
        if (m_max_bssid_indicator < 1 || m_max_bssid_indicator > 8)
            return 0;
        return 1U << m_max_bssid_indicator;
    }

    // Elements in one frame disagreed about the indicator, or it was out of range
    constexpr bool indicator_invalid() const {
        return m_indicator_invalid;
    }

    const std::vector<nontransmitted_profile>& profiles() const {
        return m_profiles;
    }

    const std::vector<vendor_subelement>& vendor_subelements() const {
        return m_vendor;
    }

    // BSSID of index i in the set of 2^n BSSIDs around the transmitted BSSID, as
    // 48 bits; the low n bits count up from the transmitted BSSID and wrap
    static constexpr uint64_t derive_bssid(uint64_t transmitted, uint8_t max_indicator,
            uint8_t index) {
        if (max_indicator < 1 || max_indicator > 8)
            return transmitted;

        const uint64_t mask = (1ULL << max_indicator) - 1;
        return (transmitted & ~mask & 0xFFFFFFFFFFFFULL) |
            (((transmitted & mask) + index) & mask);
    }

    void reset() {
        m_num_elements = 0;
        m_max_bssid_indicator = 0;
        m_indicator_invalid = false;
        m_profile_open = false;
        m_profiles.clear();
        m_vendor.clear();
    }

protected:
    unsigned int m_num_elements;
    uint8_t m_max_bssid_indicator;
    bool m_indicator_invalid;

    // The last profile ended its element, so the next element may continue it
    bool m_profile_open;

    std::vector<nontransmitted_profile> m_profiles;
    std::vector<vendor_subelement> m_vendor;
};

#endif /* ifndef DOT11_IE_71_MBSSID */
