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

#include "fmt.h"
#include "util.h"

#include "dot11_ie_11_qbss.h"

void dot11_ie_11_qbss::parse(std::shared_ptr<kaitai::kstream> p_io) {
    // V1
    if (p_io->size() == 4) {
        m_station_count = p_io->read_u2le();
        m_channel_utilization = p_io->read_u1();
        m_available_admissions = p_io->read_u1();
        return;
    } 

    // V2
    if (p_io->size() == 5) {
        m_station_count = p_io->read_u2le();
        m_channel_utilization = p_io->read_u1();
        m_available_admissions = p_io->read_u2le();
        return;
    }

    throw std::runtime_error(fmt::format("dot11_ie_11_qbss expected v1 (4 bytes) or v2 (5 bytes), "
                "got {} bytes", p_io->size()));
}

void dot11_ie_11_qbss::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    // V1
    if (p_io.size() == 4) {
        m_station_count = p_io.read_u2le();
        m_channel_utilization = p_io.read_u1();
        m_available_admissions = p_io.read_u1();
        return;
    } 

    // V2
    if (p_io.size() == 5) {
        m_station_count = p_io.read_u2le();
        m_channel_utilization = p_io.read_u1();
        m_available_admissions = p_io.read_u2le();
        return;
    }

    throw std::runtime_error(fmt::format("dot11_ie_11_qbss expected v1 (4 bytes) or v2 (5 bytes), "
                "got {} bytes", p_io.size()));
}
