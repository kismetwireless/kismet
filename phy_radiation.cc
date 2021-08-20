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

#include "phy_radiation.h"
#include "devicetracker.h"
#include "macaddr.h"

kis_radiation_phy::kis_radiation_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("RADIATION");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

	pack_comp_common = 
		packetchain->register_packet_component("COMMON");
    pack_comp_json = 
        packetchain->register_packet_component("JSON");
    pack_comp_meta =
        packetchain->register_packet_component("METABLOB");

	packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);
}

kis_radiation_phy::~kis_radiation_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

int kis_radiation_phy::packet_handler(CHAINCALL_PARMS) {
    kis_radiation_phy *radphy = (kis_radiation_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto json = in_pack->fetch<kis_json_packinfo>(radphy->pack_comp_json);

    if (json == nullptr)
        return 0;

    if (json->type != "radiation")
        return 0;

    in_pack->fetch_or_add<packet_metablob>(radphy->pack_comp_meta, "radiation", json->json_string);

    return 1;
}

