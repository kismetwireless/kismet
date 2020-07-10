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

#include "datasourcetracker.h"
#include "datasource_virtual.h"
#include "datasource_tzsp.h"

tzsp_source::tzsp_source() :
    lifetime_global() {

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    datasourcetracker =
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();

	pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");
	pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");

}

tzsp_source::~tzsp_source() {
    Globalreg::globalreg->RemoveGlobal(global_name());
}

