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

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "globalregistry.h"
#include "macaddr.h"
#include "packet.h"
#include "packetchain.h"
#include "packet_ieee80211.h"


kis_packet::kis_packet() {
    packet_no = 0;
	error = 0;
    crc_ok = 0;
	filtered = 0;
    duplicate = 0;
    hash = 0;

    raw_data.reserve(MAX_PACKET_LEN);
    data = nonstd::string_view(raw_data);
}

kis_packet::~kis_packet() { }
   
void kis_packet::insert(const unsigned int index, std::shared_ptr<packet_component> data) {
	if (index >= MAX_PACKET_COMPONENTS) 
        throw std::runtime_error(fmt::format("Attempted to reference packet component index {} "
                    "outside of the maximum bounds {}; this implies the pack_comp_x or _PCM "
                    "index is corrupt.", index, MAX_PACKET_COMPONENTS));

	if (content_vec[index] != nullptr)
        _MSG_ERROR("Losing packet component {}/{}, inserting on top of existing component",
                index, Globalreg::globalreg->packetchain->fetch_packet_component_name(index));

	content_vec[index] = data;
}

std::shared_ptr<packet_component> kis_packet::fetch(const unsigned int index) const {
	if (index >= MAX_PACKET_COMPONENTS)
		return nullptr;

	return content_vec[index];
}

void kis_packet::erase(const unsigned int index) {
	if (index >= MAX_PACKET_COMPONENTS)
		return;

    content_vec[index].reset();
}

