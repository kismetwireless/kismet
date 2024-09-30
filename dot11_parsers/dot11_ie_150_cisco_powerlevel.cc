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

#include "dot11_ie_150_cisco_powerlevel.h"

void dot11_ie_150_cisco_powerlevel::parse(std::shared_ptr<kaitai::kstream> p_io) {
    // Throw away IE type field
    p_io->read_u1();

    m_txpower = p_io->read_u1();
}

void dot11_ie_150_cisco_powerlevel::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    p_io.read_u1();
    m_txpower = p_io.read_u1();
}
