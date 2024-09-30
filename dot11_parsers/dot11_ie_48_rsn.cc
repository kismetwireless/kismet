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

#include "dot11_ie_48_rsn.h"

void dot11_ie_48_rsn::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_rsn_version = p_io->read_u2le();
    m_group_cipher = Globalreg::new_from_pool<dot11_ie_48_rsn::dot11_ie_48_rsn_rsn_cipher>();
    m_group_cipher->parse(*p_io);
    m_pairwise_count = p_io->read_u2le();
    m_pairwise_ciphers.reset(new shared_rsn_cipher_vector());
    m_pairwise_ciphers = Globalreg::new_from_pool<shared_rsn_cipher_vector>();
    for (unsigned int i = 0; i < pairwise_count(); i++) {
        auto c = Globalreg::new_from_pool<dot11_ie_48_rsn_rsn_cipher>();
        c->parse(*p_io);
        m_pairwise_ciphers->push_back(c);
    }
    m_akm_count = p_io->read_u2le();
    m_akm_ciphers.reset(new shared_rsn_management_vector());
    for (unsigned int i = 0; i < akm_count(); i++) {
        auto a = Globalreg::new_from_pool<dot11_ie_48_rsn_rsn_management>();
        a->parse(*p_io);
        m_akm_ciphers->push_back(a);
    }
    m_rsn_capabilities = p_io->read_u2le();
}

void dot11_ie_48_rsn::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_rsn_version = p_io.read_u2le();
    m_group_cipher = Globalreg::new_from_pool<dot11_ie_48_rsn::dot11_ie_48_rsn_rsn_cipher>();
    m_group_cipher->parse(p_io);
    m_pairwise_count = p_io.read_u2le();
    m_pairwise_ciphers.reset(new shared_rsn_cipher_vector());
    m_pairwise_ciphers = Globalreg::new_from_pool<shared_rsn_cipher_vector>();
    for (unsigned int i = 0; i < pairwise_count(); i++) {
        auto c = Globalreg::new_from_pool<dot11_ie_48_rsn_rsn_cipher>();
        c->parse(p_io);
        m_pairwise_ciphers->push_back(c);
    }
    m_akm_count = p_io.read_u2le();
    m_akm_ciphers.reset(new shared_rsn_management_vector());
    for (unsigned int i = 0; i < akm_count(); i++) {
        auto a = Globalreg::new_from_pool<dot11_ie_48_rsn_rsn_management>();
        a->parse(p_io);
        m_akm_ciphers->push_back(a);
    }
    m_rsn_capabilities = p_io.read_u2le();

}

void dot11_ie_48_rsn::dot11_ie_48_rsn_rsn_cipher::parse(kaitai::kstream& p_io) {
    m_cipher_suite_oui = p_io.read_bytes(3);
    m_cipher_type = p_io.read_u1();
}

void dot11_ie_48_rsn::dot11_ie_48_rsn_rsn_management::parse(kaitai::kstream& p_io) {
    m_management_suite_oui = p_io.read_bytes(3);
    m_management_type = p_io.read_u1();
}

void dot11_ie_48_rsn_partial::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_rsn_version = p_io->read_u2le();
    m_group_cipher = p_io->read_bytes(4);
    m_pairwise_count = p_io->read_u2le();
}

void dot11_ie_48_rsn_partial::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_rsn_version = p_io.read_u2le();
    m_group_cipher = p_io.read_bytes(4);
    m_pairwise_count = p_io.read_u2le();
}

