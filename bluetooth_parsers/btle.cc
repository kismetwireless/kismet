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

#include "btle.h"

void bluetooth_btle::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_advertised_data = std::make_shared<shared_advdata_vector>();

    m_access_address = p_io->read_u4le();
    m_packet_header = p_io->read_u1();
    m_length = p_io->read_u1();

    // BTLE stores the MAC address backwards 
    m_advertising_address = p_io->read_bytes(6);
    m_advertising_address = kaitai::kstream::reverse(m_advertising_address);

    while (p_io->pos() < p_io->size() - 3) {
        auto adv_datum = std::make_shared<bluetooth_btle_advdata>();
        adv_datum->parse(p_io);
        m_advertised_data->push_back(adv_datum);
    }
}

void bluetooth_btle::bluetooth_btle_advdata::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_length = p_io->read_u1();
    m_type = p_io->read_u1();

    m_data = p_io->read_bytes(length() - 1);
    m_data_stream = std::make_shared<kaitai::kstream>(m_data);
}

