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
#include "util.h"

#include "dot11_ie_221_ms_wps.h"

void dot11_ie_221_ms_wps::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_vendor_subtype = p_io->read_u1();
    while (!p_io->is_eof()) {
        auto& e = m_wps_elements.emplace_back();
        e.parse(*p_io);
    }
}

void dot11_ie_221_ms_wps::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_vendor_subtype = p_io.read_u1();
    while (!p_io.is_eof()) {
        auto& e = m_wps_elements.emplace_back();
        e.parse(p_io);
    }
}

void dot11_ie_221_ms_wps::wps_de_sub_element::parse(kaitai::kstream& p_io) {
    m_wps_de_type = p_io.read_u2be();
    m_wps_de_len = p_io.read_u2be();
    m_wps_de_content = p_io.read_bytes(wps_de_len());

    switch (wps_de_type()) {
        case wps_de_device_name:
        case wps_de_manuf:
        case wps_de_model:
        case wps_de_model_num:
        case wps_de_serial:
            m_sub_string.parse(m_wps_de_content);
            break;
        case wps_de_rfbands:
            m_sub_rfband.parse(m_wps_de_content);
            break;
        case wps_de_version:
            m_sub_version.parse(m_wps_de_content);
            break;
        case wps_de_state:
            m_sub_state.parse(m_wps_de_content);
            break;
        case wps_de_ap_setup:
            m_sub_ap_setup.parse(m_wps_de_content);
            break;
        case wps_de_config_methods:
            m_sub_config_methods.parse(m_wps_de_content);
            break;
        case wps_de_uuid_e:
            m_sub_uuid_e.parse(m_wps_de_content);
            break;
        default:
            m_sub_generic.parse(m_wps_de_content);
            break;
    }
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_string::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_str = p_io.read_bytes_full();
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_rfband::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);

	kaitai::kstream p_io(&is);
    m_rfband = p_io.read_u1();
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_state::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_state = p_io.read_u1();
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_uuid_e::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_uuid = p_io.read_bytes_full();
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_primary_type::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_category = p_io.read_u2be();
    m_typedata = p_io.read_u4be();
    m_subcategory = p_io.read_u2be();
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_vendor_extension::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_vendor_id = p_io.read_bytes(3);
    m_wfa_sub_id = p_io.read_u1();
    m_wfa_sub_len = p_io.read_u1();
    m_wfa_sub_data = p_io.read_bytes(wfa_sub_len());
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_version::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_version = p_io.read_u1();
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_ap_setup::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_ap_setup_locked = p_io.read_u1();
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_config_methods::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_config_methods = p_io.read_u2be();
    m_parsed = true;
}

void dot11_ie_221_ms_wps::wps_de_sub_element::wps_de_sub_generic::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_wps_de_data = p_io.read_bytes_full();
    m_parsed = true;
}

