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

#include "globalregistry.h"
#include "packetchain.h"

#include "packet_dot15d4.h"
#include "tracker_dot15d4.h"

extern int pack_comp_dot15d4;

int dot15d4_chain_hook(CHAINCALL_PARMS) {
	return ((Tracker_Dot15d4 *) auxdata)->chain_handler(in_pack);
}

Tracker_Dot15d4::Tracker_Dot15d4(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	globalreg->packetchain->RegisterHandler(&dot15d4_chain_hook, this,
											CHAINPOS_CLASSIFIER, 0);
}

int Tracker_Dot15d4::chain_handler(kis_packet *in_pack) {
	dot15d4_packinfo *d15d4 = (dot15d4_packinfo *) in_pack->fetch(pack_comp_dot15d4);

	if (d15d4 == NULL)
		return 0;

	dot15d4_network_id netid(d15d4);
	dot15d4_network *net = NULL;

	map<dot15d4_network_id, dot15d4_network *>::iterator titr = tracked_devs.find(netid);

	if (titr == tracked_devs.end()) {
		net = new dot15d4_network();
		net->first_time = globalreg->timestamp.tv_sec;
		net->netid = netid;

		tracked_devs[netid] = net;
	} else {
		net = titr->second;
	}

	net->last_time = globalreg->timestamp.tv_sec;
	net->num_packets++;

	if (d15d4->type == d15d4_type_beacon) {
		net->num_beacons++;
	} else if (d15d4->type == d15d4_type_data) {
		net->num_data++;
	} else if (d15d4->type == d15d4_type_command) {
		net->num_cmd++;
	}

	return 1;
}

