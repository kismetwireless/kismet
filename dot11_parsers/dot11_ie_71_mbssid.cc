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
#include "dot11_ie_71_mbssid.h"

void dot11_ie_71_mbssid::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_generics = Globalreg::new_from_pool<sub_generic_vector>();
    m_profiles = Globalreg::new_from_pool<sub_profile_vector>();

    m_max_bssid_indicator = p_io->read_u1();

    while (!p_io->is_eof()) {
        uint8_t sub_id = p_io->read_u1();
        uint8_t sub_len = p_io->read_u1();

        if (sub_id == 0) {
            // Parse profiles as IE tags
            auto profile = Globalreg::new_from_pool<dot11_ie_71_sub_0_profile>();
            profile->parse(p_io);
            m_profiles->push_back(profile);
        } else {
            // Parse generic as content
            auto generic = Globalreg::new_from_pool<dot11_ie_71_sub_generic>();
            generic->m_id = sub_id;
            generic->m_content = p_io->read_bytes(sub_len);
            m_generics->push_back(generic);
        }

    }
}
