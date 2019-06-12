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

#include "bluetooth_parsers/bt_rfinfo.h"

void bluetooth_radio_info::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_rf_channel = p_io->read_u1();
    m_dbm_signal = p_io->read_u1();
    m_dbm_noise = p_io->read_u1();
    m_address_offenses = p_io->read_u1();
    m_ref_access_address = mac_addr(p_io->read_bytes(4));
    m_flags = p_io->read_u2le();
}

