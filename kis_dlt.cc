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

/* DLT handler framework */

#include "config.h"

#include "globalregistry.h"
#include "packet.h"
#include "packetchain.h"
#include "kis_dlt.h"

kis_dlt_handler::kis_dlt_handler() :
    lifetime_global(), 
    dlt_name {"UNASSIGNED"},
    dlt {-1} {

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();

	chainid = 
        packetchain->register_handler([](void *auxdata, const std::shared_ptr<kis_packet>& p) -> int {
                auto dlthandler = reinterpret_cast<kis_dlt_handler *>(auxdata);
                return dlthandler->handle_packet(p);
            }, this, CHAINPOS_POSTCAP, 0);

	pack_comp_linkframe =
		packetchain->register_packet_component("LINKFRAME");
    pack_comp_l1data =
        packetchain->register_packet_component("L1RAW");
	pack_comp_decap =
		packetchain->register_packet_component("DECAP");
	pack_comp_datasrc =
		packetchain->register_packet_component("KISDATASRC");
	pack_comp_radiodata = 
		packetchain->register_packet_component("RADIODATA");
    pack_comp_l1_agg = 
        packetchain->register_packet_component("RADIODATA_AGG");
	pack_comp_gps =
		packetchain->register_packet_component("GPS");
	pack_comp_checksum =
		packetchain->register_packet_component("CHECKSUM");

}

kis_dlt_handler::~kis_dlt_handler() {
	if (packetchain != nullptr)
		packetchain->remove_handler(chainid, CHAINPOS_POSTCAP);
}

