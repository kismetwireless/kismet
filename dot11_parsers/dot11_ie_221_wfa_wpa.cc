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

#include "dot11_ie_221_wfa_wpa.h"

void dot11_ie_221_wfa_wpa::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_vendor_subtype = p_io->read_u1();
    m_wpa_version = p_io->read_u2le();
    m_multicast_cipher.reset(new wpa_v1_cipher());
    m_multicast_cipher->parse(p_io);
    m_unicast_count = p_io->read_u2le();
    m_unicast_ciphers.reset(new shared_wpa_v1_cipher_vector());
    for (uint16_t i = 0; i < unicast_count(); i++) {
        std::shared_ptr<wpa_v1_cipher> c(new wpa_v1_cipher());
        c->parse(p_io);
        m_unicast_ciphers->push_back(c);
    }
    m_akm_count = p_io->read_u2le();
    m_akm_ciphers.reset(new shared_wpa_v1_cipher_vector());
    for (uint16_t i = 0; i < akm_count(); i++) {
        std::shared_ptr<wpa_v1_cipher> c(new wpa_v1_cipher());
        c->parse(p_io);
        m_akm_ciphers->push_back(c);
    }
}

void dot11_ie_221_wfa_wpa::wpa_v1_cipher::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_oui = p_io->read_bytes(3);
    m_cipher_type = p_io->read_u1();
}
