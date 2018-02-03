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

#include "dot11_ie_55_fastbss.h"

void dot11_ie_55_fastbss::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_mic_control.reset(new sub_mic_control());
    m_mic_control->parse(p_io);
    m_mic = p_io->read_bytes(16);
    m_anonce = p_io->read_bytes(32);
    m_snonce = p_io->read_bytes(32);
    m_subelements.reset(new shared_sub_element_vector());
    while (!p_io->is_eof()) {
        std::shared_ptr<sub_element> e(new sub_element());
        e->parse(p_io);
        m_subelements->push_back(e);
    }
}

void dot11_ie_55_fastbss::sub_mic_control::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_reserved = p_io->read_u1();
    m_element_count = p_io->read_u1();
}

void dot11_ie_55_fastbss::sub_element::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_sub_id = p_io->read_u1();
    m_sub_len = p_io->read_u1();
    m_raw_sub_data = p_io->read_bytes(sub_len());
    m_raw_sub_data_stream.reset(new kaitai::kstream(m_raw_sub_data));

    if (sub_id() == sub_pmk_r1_keyholder) {
        std::shared_ptr<sub_element_data_pmk_r1_keyholder> r1kh(new sub_element_data_pmk_r1_keyholder());
        r1kh->parse(m_raw_sub_data_stream);
        m_sub_data = r1kh;
    } else if (sub_id() == sub_pmk_gtk) {
        std::shared_ptr<sub_element_data_gtk> gtk(new sub_element_data_gtk());
        gtk->parse(m_raw_sub_data_stream);
        m_sub_data = gtk;
    } else if (sub_id() == sub_pmk_r0_kh_id) {
        std::shared_ptr<sub_element_data_pmk_r0_kh_id> r0khid(new sub_element_data_pmk_r0_kh_id());
        r0khid->parse(m_raw_sub_data_stream);
        m_sub_data = r0khid;
    } else {
        std::shared_ptr<sub_element_data_generic> g(new sub_element_data_generic());
        g->parse(m_raw_sub_data_stream);
        m_sub_data = g;
    }
}

void dot11_ie_55_fastbss::sub_element::sub_element_data_pmk_r1_keyholder::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_keyholder_id = p_io->read_bytes_full();
}

void dot11_ie_55_fastbss::sub_element::sub_element_data_pmk_r0_kh_id::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_keyholder_id = p_io->read_bytes_full();
}

void dot11_ie_55_fastbss::sub_element::sub_element_data_gtk::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_gtk_keyinfo.reset(new sub_element_data_gtk_sub_keyinfo());
    m_gtk_keyinfo->parse(p_io);
    m_keylen = p_io->read_u1();
    m_gtk_rsc = p_io->read_bytes(8);
    // Use the remaining length instead of the keylen
    m_gtk_gtk = p_io->read_bytes_full();
}

void dot11_ie_55_fastbss::sub_element::sub_element_data_gtk::sub_element_data_gtk_sub_keyinfo::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_keyinfo = p_io->read_u2le();
}

void dot11_ie_55_fastbss::sub_element::sub_element_data_generic::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_data = p_io->read_bytes_full();
}

