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

#include "dot11_ie_45_ht_cap.h"

void dot11_ie_45_ht_cap::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_ht_capabilities = p_io->read_u2le();
    m_ampdu = p_io->read_u1();
    m_mcs = Globalreg::new_from_pool<dot11_ie_45_rx_mcs>();
    m_mcs->parse(*p_io);
    m_ht_extended_caps = p_io->read_u2be();
    m_txbf_caps = p_io->read_u4be();
    m_asel_caps = p_io->read_u1();
}

void dot11_ie_45_ht_cap::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_ht_capabilities = p_io.read_u2le();
    m_ampdu = p_io.read_u1();
    m_mcs = Globalreg::new_from_pool<dot11_ie_45_rx_mcs>();
    m_mcs->parse(p_io);
    m_ht_extended_caps = p_io.read_u2be();
    m_txbf_caps = p_io.read_u4be();
    m_asel_caps = p_io.read_u1();

}

void dot11_ie_45_ht_cap::dot11_ie_45_rx_mcs::parse(kaitai::kstream& p_io) {
    m_rx_mcs = p_io.read_bytes(10);
    m_supported_data_rate = p_io.read_u2le();
    m_txflags = p_io.read_u4be();
}

