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

#ifndef __DOT11_IE_7_COUNTRY_H__
#define __DOT11_IE_7_COUNTRY_H__

/* dot11 ie 7 country
 *
 * 80211d is deprecated.
 *
 * Some APs seem to return bogus country strings which don't include a valid
 * set of triplets.
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_7_country {
public:
    class dot11d_country_triplet;
    typedef std::vector<std::shared_ptr<dot11d_country_triplet> > shared_dot11d_country_triplet_vector;

    dot11_ie_7_country() {
        i_allow_fragments = false;
    }
    ~dot11_ie_7_country() { }

    // Some APs send bogon lists w/ a non-triplet set of channels at the
    // end when sending long, weird ranges of single-channel ranges.
    // If we allow fragments, we silently fail the last channel being
    // invalid
    void set_allow_fragments(bool in_f) {
        i_allow_fragments = in_f;
    }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);
    void parse_channels(const std::string& data);

    const std::string& country_code() const {
        return m_country_code;
    }

    constexpr17 uint8_t environment() const {
        return m_environment;
    }

    std::shared_ptr<shared_dot11d_country_triplet_vector> country_list() const {
        return m_country_list;
    }

protected:
    std::string m_country_code;
    uint8_t m_environment;
    std::shared_ptr<shared_dot11d_country_triplet_vector> m_country_list;

    bool i_allow_fragments;

public:
    class dot11d_country_triplet {
    public:
        dot11d_country_triplet() {}
        ~dot11d_country_triplet() {}

		void parse(kaitai::kstream& p_io);

        constexpr17 uint8_t first_channel() const {
            return m_first_channel;
        }

        constexpr17 uint8_t num_channels() const {
            return m_num_channels;
        }

        constexpr17 uint8_t max_power() const {
            return m_max_power;
        }

    protected:
        uint8_t m_first_channel;
        uint8_t m_num_channels;
        uint8_t m_max_power;
    };


};


#endif

