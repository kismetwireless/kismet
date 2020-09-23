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

#include "dot11_ie_221_ms_wps.h"

void dot11_ie_221_ms_wps::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_vendor_subtype = p_io->read_u1();
    m_wps_elements.reset(new shared_wps_de_sub_element_vector());
    while (!p_io->is_eof()) {
        std::shared_ptr<wps_de_sub_element> e(new wps_de_sub_element());
        e->parse(p_io);
        m_wps_elements->push_back(e);
    }
}

void dot11_ie_221_ms_wps::wps_de_sub_element::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_wps_de_type = p_io->read_u2be();
    m_wps_de_len = p_io->read_u2be();
    m_wps_de_content = p_io->read_bytes(wps_de_len());
    m_wps_de_content_data_stream.reset(new kaitai::kstream(m_wps_de_content));

    if (wps_de_type() == wps_de_device_name) {
        std::shared_ptr<wps_de_sub_string> s(new wps_de_sub_string());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_manuf) {
        std::shared_ptr<wps_de_sub_string> s(new wps_de_sub_string());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_model) {
        std::shared_ptr<wps_de_sub_string> s(new wps_de_sub_string());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_model_num) {
        std::shared_ptr<wps_de_sub_string> s(new wps_de_sub_string());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_rfbands) {
        std::shared_ptr<wps_de_sub_rfband> s(new wps_de_sub_rfband());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_serial) {
        std::shared_ptr<wps_de_sub_string> s(new wps_de_sub_string());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_version) {
        std::shared_ptr<wps_de_sub_version> s(new wps_de_sub_version());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_state) {
        std::shared_ptr<wps_de_sub_state> s(new wps_de_sub_state());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_ap_setup) {
        std::shared_ptr<wps_de_sub_ap_setup> s(new wps_de_sub_ap_setup());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_config_methods) {
        std::shared_ptr<wps_de_sub_config_methods> s(new wps_de_sub_config_methods());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else if (wps_de_type() == wps_de_uuid_e) {
        std::shared_ptr<wps_de_sub_uuid_e> s(new wps_de_sub_uuid_e());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    } else {
        std::shared_ptr<wps_de_sub_generic> s(new wps_de_sub_generic());
        s->parse(m_wps_de_content_data_stream);
        m_sub_element = s;
    }
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_string::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_str = p_io->read_bytes_full();
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_rfband::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_rfband = p_io->read_u1();
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_state::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_state = p_io->read_u1();
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_uuid_e::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_uuid = p_io->read_bytes_full();
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_primary_type::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_category = p_io->read_u2be();
    m_typedata = p_io->read_u4be();
    m_subcategory = p_io->read_u2be();
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_vendor_extension::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_vendor_id = p_io->read_bytes(3);
    m_wfa_sub_id = p_io->read_u1();
    m_wfa_sub_len = p_io->read_u1();
    m_wfa_sub_data = p_io->read_bytes(wfa_sub_len());
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_version::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_version = p_io->read_u1();
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_ap_setup::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_ap_setup_locked = p_io->read_u1();
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_config_methods::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_config_methods = p_io->read_u2be();
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_generic::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_wps_de_data = p_io->read_bytes_full();
}


