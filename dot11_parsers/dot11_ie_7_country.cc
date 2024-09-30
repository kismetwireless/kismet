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
#include "dot11_ie_7_country.h"

void dot11_ie_7_country::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_country_code = p_io->read_bytes(2);
    m_environment = p_io->read_u1();
    m_country_list.reset(new shared_dot11d_country_triplet_vector());
}

void dot11_ie_7_country::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_country_code = p_io.read_bytes(2);
    m_environment = p_io.read_u1();
    m_country_list.reset(new shared_dot11d_country_triplet_vector());
}

void dot11_ie_7_country::parse_channels(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    p_io.read_bytes(2);
    p_io.read_u1();

    while (!p_io.is_eof()) {
        // Do our best to read all the channel codings; if we allow broken
        // country tags, read as far as we can and then stop, otherwise
        // pass the error upstream
        try {
            std::shared_ptr<dot11d_country_triplet> c(new dot11d_country_triplet());
            c->parse(p_io);
            m_country_list->push_back(c);
        } catch (std::exception& e) {
            if (i_allow_fragments)
                break;
            else
                throw(e);
        }
    }
}

void dot11_ie_7_country::dot11d_country_triplet::parse(kaitai::kstream& p_io) {
    m_first_channel = p_io.read_u1();
    m_num_channels = p_io.read_u1();
    m_max_power = p_io.read_u1();
}

