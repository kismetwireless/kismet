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

#include "dot11_ie_221_ubnt_airmax_m.h"

void dot11_ie_221_ubnt_airmax_m::parse(const std::string& data) {
    membuf d_membuf(data.data(), data.data() + data.length());
    std::istream is(&d_membuf);
    kaitai::kstream p_io(&is);

    reset();

    // 00:15:6D is shared with other Ubiquiti IEs, sometimes in the same frame
    if (p_io.read_bytes(3) != "\xff\xff\xff")
        return;

    m_ciphertext = p_io.read_bytes_full();

    m_parsed = true;
}

void dot11_ie_221_ubnt_airmax_m::parse_payload(const std::string& plaintext) {
    membuf d_membuf(plaintext.data(), plaintext.data() + plaintext.length());
    std::istream is(&d_membuf);
    kaitai::kstream p_io(&is);

    reset_payload();

    m_version = p_io.read_u1();
    m_msg_type = p_io.read_u1();
    m_src_mac = mac_addr(p_io.read_bytes(6).data(), 6);
    m_enable = p_io.read_u1();

    m_payload_parsed = true;
}
