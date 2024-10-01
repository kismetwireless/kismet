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

#include "dot11_wpa_eap.h"

void dot11_wpa_eap::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_dot1x_version = p_io->read_u1();
    m_dot1x_type = p_io->read_u1();
    m_dot1x_len = p_io->read_u2be();
    m_dot1x_data = p_io->read_bytes(dot1x_len());

    if (dot1x_type() == dot1x_type_eap_packet) {
        std::shared_ptr<dot1x_eap_packet> p(new dot1x_eap_packet());
        m_dot1x_content = p;
    } else if (dot1x_type() == dot1x_type_eap_key) {
        std::shared_ptr<dot1x_key> k(new dot1x_key());
        m_dot1x_content = k;
    }
}

void dot11_wpa_eap::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_dot1x_version = p_io.read_u1();
    m_dot1x_type = p_io.read_u1();
    m_dot1x_len = p_io.read_u2be();
    m_dot1x_data = p_io.read_bytes(dot1x_len());

    if (dot1x_type() == dot1x_type_eap_packet) {
        std::shared_ptr<dot1x_eap_packet> p(new dot1x_eap_packet());
        m_dot1x_content = p;
    } else if (dot1x_type() == dot1x_type_eap_key) {
        std::shared_ptr<dot1x_key> k(new dot1x_key());
        m_dot1x_content = k;
    }
}

void dot11_wpa_eap::dot1x_key::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_key_descriptor_type = p_io.read_u1();
    m_key_content_data = p_io.read_bytes_full();

    if (key_descriptor_type() == dot1x_key_type_eapol_rsn) {
        std::shared_ptr<eapol_key_rsn> k(new eapol_key_rsn());
        m_key_content = k;
    }
}

void dot11_wpa_eap::dot1x_key::eapol_key_rsn::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_key_info = p_io.read_u2be();
    m_key_len = p_io.read_u2be();
    m_replay_counter = p_io.read_u8be();
    m_wpa_key_nonce = p_io.read_bytes(32);
    m_wpa_key_iv = p_io.read_bytes(16);
    m_wpa_key_rsc = p_io.read_bytes(8);
    m_wpa_key_id = p_io.read_bytes(8);
    m_wpa_key_mic = p_io.read_bytes(16);
    m_wpa_key_data_len = p_io.read_u2be();
    m_wpa_key_data = p_io.read_bytes(wpa_key_data_len());
}

void dot11_wpa_eap::dot1x_eap_packet::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_eapol_type = p_io.read_u1();
    m_eapol_id = p_io.read_u1();
    m_eapol_len = p_io.read_u2be();
    m_eapol_expanded_type = p_io.read_u1();
    m_eapol_content_data = p_io.read_bytes_full();

    if (eapol_expanded_type() == eapol_expanded_wfa_wps) {
        std::shared_ptr<eapol_extended_wpa_wps> e(new eapol_extended_wpa_wps());
        e->parse(m_eapol_content_data);
        m_eapol_content = e;
    }
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_vendor_id = p_io.read_bytes(3);
    m_vendor_type = p_io.read_u4be();
    m_opcode = p_io.read_u1();
    m_flags = p_io.read_u1();
    m_fields.reset(new shared_eapol_wpa_field_vector);
    while (!p_io.is_eof()) {
        std::shared_ptr<eapol_wpa_field> f(new eapol_wpa_field);
        f->parse(p_io);
        m_fields->push_back(f);
    }
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::parse(kaitai::kstream& p_io) {
    m_type = p_io.read_u2be();
    m_len = p_io.read_u2be();
    m_content_data = p_io.read_bytes(len());

    if (type() == wpa_field_type_version) {
        std::shared_ptr<eapol_field_version> f(new eapol_field_version());
        f->parse(m_content_data);
        m_content = f;
    } else if (type() == wpa_field_type_wpa_message_type) {
        std::shared_ptr<eapol_field_message_type> f(new eapol_field_message_type());
        f->parse(m_content_data);
        m_content = f;
    } else if (type() == wpa_field_type_wpa_uuid) {
        std::shared_ptr<eapol_field_uuid> f(new eapol_field_uuid());
        f->parse(m_content_data);
        m_content = f;
    } else if (type() == wpa_field_type_auth_flags) {
        std::shared_ptr<eapol_field_auth_type_flags> f(new eapol_field_auth_type_flags());
        f->parse(m_content_data);
        m_content = f;
    } else if (type() == wpa_field_type_encryption_flags) {
        std::shared_ptr<eapol_field_encryption_type_flags> f(new eapol_field_encryption_type_flags());
        f->parse(m_content_data);
        m_content = f;
    } else if (type() == wpa_field_type_connection_flags) {
        std::shared_ptr<eapol_field_connection_type_flags> f(new eapol_field_connection_type_flags());
        f->parse(m_content_data);
        m_content = f;
    } else if (type() == wpa_field_type_config_methods) {
        std::shared_ptr<eapol_field_config_methods> f(new eapol_field_config_methods());
        f->parse(m_content_data);
        m_content = f;
    }
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::eapol_field_version::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_version = p_io.read_u1();
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::eapol_field_message_type::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_messagetype = p_io.read_u1();
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::eapol_field_uuid::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_uuid = p_io.read_bytes(16);
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::eapol_field_auth_type_flags::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_flags = p_io.read_u2be();
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::eapol_field_encryption_type_flags::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_flags = p_io.read_u2be();
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::eapol_field_connection_type_flags::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_flags = p_io.read_u1();
}

void dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::eapol_field_config_methods::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_flags = p_io.read_u2be();
}

