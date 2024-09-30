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

#ifndef __DOT11_WFA_P2P_IE_H__
#define __DOT11_WFA_P2P_IE_H__

/*
 * Handle the alternate IE tags found in a dot11 IE 221 WFA P2P frame, consisting of
 * 1 byte ID
 * 2 byte length 
 * N byte body
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_wfa_p2p_ie {
public:
    class dot11_wfa_p2p_ie_tag;
    typedef std::vector<std::shared_ptr<dot11_wfa_p2p_ie_tag> > shared_ie_tag_vector;

    dot11_wfa_p2p_ie() { }
    ~dot11_wfa_p2p_ie() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    std::shared_ptr<shared_ie_tag_vector> tags() const {
        return m_tags;
    }

    void reset() {
        m_tags->clear();
    }

protected:
    std::shared_ptr<shared_ie_tag_vector> m_tags;

public:
    class dot11_wfa_p2p_ie_tag {
    public:
        dot11_wfa_p2p_ie_tag() { } 
        ~dot11_wfa_p2p_ie_tag() { }

        void parse(kaitai::kstream& p_io);

        constexpr17 uint8_t tag_num() const {
            return m_tag_num;
        }

        constexpr17 uint16_t tag_len() const {
            return m_tag_len;
        }

        constexpr17 const std::string& tag_data() const {
            return m_tag_data;
        }

        void reset() {
            m_tag_num = 0;
            m_tag_len = 0;
            m_tag_data = "";
        }

    protected:
        uint8_t m_tag_num;
        uint16_t m_tag_len;
        std::string m_tag_data;
    };
};


#endif

