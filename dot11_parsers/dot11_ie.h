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

#ifndef __DOT11_IE_H__
#define __DOT11_IE_H__

/* Parse a dot11 ie stream into individual objects.
 *
 * This uses the kaitai stream buffer from the kaitai runtime as it is a 
 * solid implementation of buffer-bounded operations and data extraction.
 *
 * Much of this is modeled on how kaitai generates parsers.
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>

class dot11_ie {
public:
    class dot11_ie_tag;
    typedef std::vector<std::shared_ptr<dot11_ie_tag> > shared_ie_tag_vector;

    dot11_ie() {

    }

    ~dot11_ie() {

    }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    std::shared_ptr<shared_ie_tag_vector> tags() {
        return m_tags;
    }

protected:
    std::shared_ptr<shared_ie_tag_vector> m_tags;

public:
    class dot11_ie_tag {
    public:
        dot11_ie_tag() {

        }

        ~dot11_ie_tag() {

        }

        void parse(std::shared_ptr<kaitai::kstream> p_io);

        uint8_t tag_num() {
            return m_tag_num;
        }

        uint8_t tag_len() {
            return m_tag_len;
        }

        std::string tag_data() {
            return m_tag_data;
        }

    protected:
        uint8_t m_tag_num;
        uint8_t m_tag_len;
        std::string m_tag_data;
    };

};


#endif

