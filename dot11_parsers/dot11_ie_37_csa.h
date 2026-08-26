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

#ifndef __DOT11_IE_37_CSA__
#define __DOT11_IE_37_CSA__

#include <string>
#include <memory>
#include <kaitai/kaitaistream.h>
#include <multi_constexpr.h>

class dot11_ie_37_csa {
public:
    dot11_ie_37_csa() { reset(); }
    ~dot11_ie_37_csa() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
    void parse(const std::string& data);

    void reset() {
        m_parsed = false;
        m_mode = 0;
        m_newchan = 0;
        m_count = 0;
    }

    constexpr bool parsed() { return m_parsed; }

    constexpr uint8_t mode() { return m_mode; }
    constexpr uint8_t new_channel() { return m_newchan; }
    constexpr uint8_t count() { return m_count; }

protected:
    bool m_parsed;

    uint8_t m_mode;
    uint8_t m_newchan;
    uint8_t m_count;
};


#endif /* __DOT11_IE_37_CSA__ */
