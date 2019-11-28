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

#include "dot11_p2p_ie.h"

void dot11_wfa_p2p_ie::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_tags.reset(new shared_ie_tag_vector());

    while (!p_io->is_eof()) {
        std::shared_ptr<dot11_wfa_p2p_ie_tag> t(new dot11_wfa_p2p_ie_tag());
        t->parse(p_io);
        m_tags->push_back(t);
    }
}

void dot11_wfa_p2p_ie::dot11_wfa_p2p_ie_tag::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_tag_num = p_io->read_u1();
    m_tag_len = p_io->read_u2le();
    m_tag_data = p_io->read_bytes(tag_len());
    m_tag_data_stream.reset(new kaitai::kstream(m_tag_data));
}

