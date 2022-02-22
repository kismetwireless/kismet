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

/* 
 * mbssid non-advertised bssid frame
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"
#include "dot11_ie.h"

// ie 71 mbssid
// contains:
//  Fixed bssid # info
//  Nested list of sub-elements
//    id 0 - nontransmitted bssid profile
//    other - vendor specific
class dot11_ie_71_mbssid {
public:
    class dot11_ie_71_sub_0_profile;
    class dot11_ie_71_sub_generic;
    using sub_profile_vector = std::vector<std::shared_ptr<dot11_ie_71_sub_0_profile>>;
    using sub_generic_vector = std::vector<std::shared_ptr<dot11_ie_71_sub_generic>>;

    dot11_ie_71_mbssid() { }
    ~dot11_ie_71_mbssid() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    // Encoded # of bssids
    constexpr17 uint8_t max_bssid_indicator() const {
        return m_max_bssid_indicator;
    }

    // Actual # of bssids
    constexpr17 uint8_t max_bssids() const {
        return max_bssid_indicator() << 2;
    }

    std::shared_ptr<sub_profile_vector> profiles() const {
        return m_profiles;
    }

    std::shared_ptr<sub_generic_vector> generics() const {
        return m_generics;
    }

    void reset() {
        m_profiles->clear();
        m_generics->clear();
    }

protected:
    uint8_t m_max_bssid_indicator;
    std::shared_ptr<sub_profile_vector> m_profiles;
    std::shared_ptr<sub_generic_vector> m_generics;

public:
    // Non-advertised bssid profile, is its own set of IE tags
    class dot11_ie_71_sub_0_profile : public dot11_ie {
    public:
        dot11_ie_71_sub_0_profile() { }
        ~dot11_ie_71_sub_0_profile() { }
    };

    // Generic un-parsed profile
    class dot11_ie_71_sub_generic {
    public:
        friend class dot11_ie_71_mbssid;

        dot11_ie_71_sub_generic() { }
        ~dot11_ie_71_sub_generic() { }

        void parse(std::shared_ptr<kaitai::kstream> p_io);

        constexpr17 uint8_t id() const {
            return m_id;
        }

        std::string content() const {
            return m_content;
        }

        void reset() {
            m_content = "";
        }

    protected:
        uint8_t m_id;
        std::string m_content;

    };


};


#endif /* ifndef DOT11_IE_71_MBSSID */
