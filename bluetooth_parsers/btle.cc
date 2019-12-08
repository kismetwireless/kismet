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
    m_access_address = p_io->read_u4le();
    m_packet_header = p_io->read_u2le();
    m_length = p_io->read_u1();

    // BTLE stores the MAC address backwards so we have to read it to a temp value and
    // swap it around
    auto raw_advertising_address = p_io->read_bytes(6);
    m_advertising_address = "000000";
    for (unsigned int i = 0; i < 6; i++) {
        m_advertising_address[i] = raw_advertising_address[5 - i];
    }
}

