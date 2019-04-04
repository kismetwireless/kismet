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

int kis_dlt_packethook(CHAINCALL_PARMS) {
	return ((Kis_DLT_Handler *) auxdata)->HandlePacket(in_pack);
}

Kis_DLT_Handler::Kis_DLT_Handler() :
    LifetimeGlobal(), 
    dlt_name {"UNASSIGNED"},
    dlt {-1} {

    auto packetchain =
        Globalreg::FetchMandatoryGlobalAs<Packetchain>();

	chainid = 
		packetchain->RegisterHandler(&kis_dlt_packethook, this,
                CHAINPOS_POSTCAP, 0);

	pack_comp_linkframe =
		packetchain->RegisterPacketComponent("LINKFRAME");
	pack_comp_decap =
		packetchain->RegisterPacketComponent("DECAP");
	pack_comp_datasrc =
		packetchain->RegisterPacketComponent("KISDATASRC");
	pack_comp_radiodata = 
		packetchain->RegisterPacketComponent("RADIODATA");
	pack_comp_gps =
		packetchain->RegisterPacketComponent("GPS");
	pack_comp_checksum =
		packetchain->RegisterPacketComponent("CHECKSUM");

}

Kis_DLT_Handler::~Kis_DLT_Handler() {
    auto packetchain = 
        Globalreg::FetchGlobalAs<Packetchain>();

	if (packetchain != nullptr) 
		packetchain->RemoveHandler(chainid, CHAINPOS_POSTCAP);

	chainid = -1;
}

