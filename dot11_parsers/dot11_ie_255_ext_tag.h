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

#ifndef __DOT11_IE_255_EXT_TAG__
#define __DOT11_IE_255_EXT_TAG__ 

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_255_ext {
public:
    dot11_ie_255_ext() { }
    ~dot11_ie_255_ext() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint8_t subtag_num() const {
        return m_subtag_num;
    }

    constexpr17 const std::string& tag_data() const {
        return m_subtag_data;
    }

protected:
    uint8_t m_subtag_num;
    std::string m_subtag_data;
};

#endif /* ifndef DOT11_IE_255_EXT_TAG */
