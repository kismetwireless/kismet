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

#include "globalregistry.h"
#include "dot11_s1g.h"
#include "util.h"

void dot11_s1g::parse(const std::string_view *view) {
    membuf view_membuf(view->data(), view->data() + view->length());
    std::istream istream_view(&view_membuf);
    auto p_io = kaitai::kstream(&istream_view);

    m_framecontrol = p_io.read_u2be();
    m_duration = p_io.read_u2be();

    m_addr0 = p_io.read_bytes(6);

    m_fixparm_ts = p_io.read_u4be();
    m_fixparm_cs = p_io.read_u1();

    if (fc_next_tbtt_present()) {
        m_fixparm_next_tbtt = p_io.read_bits_int_be(8*3);
    }

    if (fc_compressed_ssid_present()) {
        m_fixparm_compressed_ssid = p_io.read_u4be();
    }

    if (fc_ano_present()) {
        m_fixparm_ano = p_io.read_u1();
    }

    m_tag_data = p_io.read_bytes_full();
}
