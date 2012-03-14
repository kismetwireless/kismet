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

#include <globalregistry.h>
#include <packetchain.h>

#include "packet_dot15d4.h"
#include "tracker_dot15d4.h"

extern int pack_comp_dot15d4;

enum D15D4DEV_fields {
	D15D4DEV_srcaddr, D15D4DEV_dstaddr, D15D4DEV_srcpan,
	D15D4DEV_dstpan, D15D4DEV_crypt, D15D4DEV_channel,
	D15D4DEV_firsttime, D15D4DEV_lasttime, D15D4DEV_packets,
	D15D4DEV_beacons, D15D4DEV_data, D15D4DEV_cmd,
	D15D4DEV_maxfield
};

const char *D15D4DEV_fields_text[] = {
	"srcaddr", "dstaddr", "srcpan", 
	"dstpan", "crypt", "channel",
	"firsttime", "lasttime", "packets",
	"beacons", "data", "command",
	NULL
};

int Protocol_D15D4DEV(PROTO_PARMS) {
	dot15d4_network *net = (dot15d4_network *) data;
	ostringstream osstr;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];

		if (fnum >= D15D4DEV_maxfield) {
			out_string = "Unknown field requested.";
			return -1;
		}

		osstr.str("");

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		switch (fnum) {
			case D15D4DEV_srcaddr:
				// TODO - fix these for endian swaps, output as bytes in a fixed order
				osstr << net->netid.source_addr;
				break;
			case D15D4DEV_dstaddr:
				// TODO - fix these for endian swaps, output as bytes in a fixed order
				osstr << net->netid.dest_addr;
				break;
			case D15D4DEV_srcpan:
				osstr << net->netid.source_pan;
				break;
			case D15D4DEV_dstpan:
				osstr << net->netid.dest_pan;
				break;
			case D15D4DEV_crypt:
				osstr << net->netid.crypt;
				break;
			case D15D4DEV_channel:
				osstr << net->netid.channel;
				break;
			case D15D4DEV_firsttime:
				osstr << net->first_time;
				break;
			case D15D4DEV_lasttime:
				osstr << net->last_time;
				break;
			case D15D4DEV_packets:
				osstr << net->num_packets;
				break;
			case D15D4DEV_beacons:
				osstr << net->num_beacons;
				break;
			case D15D4DEV_data:
				osstr << net->num_data;
				break;
			case D15D4DEV_cmd:
				osstr << net->num_cmd;
				break;
		}

		out_string += osstr.str() + " ";
		cache->Cache(fnum, osstr.str());
	}

	return 1;
}

void Protocol_D15D4DEV_enable(PROTO_ENABLE_PARMS) {
	((Tracker_Dot15d4 *) data)->BlitDevices(in_fd);
}

int d15tracktimer(TIMEEVENT_PARMS) {
	((Tracker_Dot15d4 *) auxptr)->BlitDevices(-1);
	return 1;
}

int dot15d4_chain_hook(CHAINCALL_PARMS) {
	return ((Tracker_Dot15d4 *) auxdata)->chain_handler(in_pack);
}

Tracker_Dot15d4::Tracker_Dot15d4(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	globalreg->packetchain->RegisterHandler(&dot15d4_chain_hook, this,
											CHAINPOS_CLASSIFIER, 0);
	
	D15D4DEV_ref = 
		globalreg->kisnetserver->RegisterProtocol("D15D4DEV", 0, 1,
												  D15D4DEV_fields_text,
												  &Protocol_D15D4DEV,
												  &Protocol_D15D4DEV_enable,
												  this);

	timer_ref =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &d15tracktimer, this);
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

	net->dirty = 1;

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

void Tracker_Dot15d4::BlitDevices(int in_fd) {
	map<dot15d4_network_id, dot15d4_network *>::iterator x;

	for (x = tracked_devs.begin(); x != tracked_devs.end(); x++) {
		kis_protocol_cache cache;

		if (in_fd == -1) {
			if (x->second->dirty == 0)
				continue;

			x->second->dirty = 0;

			if (globalreg->kisnetserver->SendToAll(D15D4DEV_ref,
												   (void *) x->second) < 0)
				break;

		} else {
			if (globalreg->kisnetserver->SendToClient(in_fd, D15D4DEV_ref,
													  (void *) x->second,
													  &cache) < 0)
				break;
		}
	}
}


