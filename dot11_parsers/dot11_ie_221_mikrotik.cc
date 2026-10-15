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

#include "util.h"

#include "dot11_ie_221_mikrotik.h"

void dot11_ie_221_mikrotik::parse(const std::string& data) {
    membuf d_membuf(data.data(), data.data() + data.length());
    std::istream is(&d_membuf);
    kaitai::kstream p_io(&is);

    reset();

    m_type = p_io.read_u1();
    // Unknown
    p_io.read_bytes(2);

    const auto len = p_io.size();

    while (len - p_io.pos() >= 2) {
        const auto subtype = p_io.read_u1();
        const auto sub_len = p_io.read_u1();

        if (sub_len > len - p_io.pos())
            break;

        auto sub_data = p_io.read_bytes(sub_len);

        if (subtype == subtype_identity && m_device_name.empty() &&
                sub_data.length() > identity_prefix_len) {
            m_device_name = sub_data.substr(identity_prefix_len);

            const auto nul = m_device_name.find('\0');
            if (nul != std::string::npos)
                m_device_name.resize(nul);
        }
    }

    m_parsed = true;
}
