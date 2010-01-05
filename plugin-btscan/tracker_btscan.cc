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
#include <gpscore.h>

#include "packet_btscan.h"
#include "tracker_btscan.h"

extern int pack_comp_btscan;

enum BTSCANDEV_fields {
	BTSCANDEV_bdaddr, BTSCANDEV_name, BTSCANDEV_class, 
	BTSCANDEV_firsttime, BTSCANDEV_lasttime, BTSCANDEV_packets,
	GPS_COMMON_FIELDS(BTSCANDEV),
	BTSCANDEV_maxfield
};

const char *BTSCANDEV_fields_text[] = {
	"bdaddr", "name", "class", 
	"firsttime", "lasttime", "packets",
	GPS_COMMON_FIELDS_TEXT,
	NULL
};

int Protocol_BTSCANDEV(PROTO_PARMS) {
	btscan_network *bt = (btscan_network *) data;
	ostringstream osstr;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];

		if (fnum >= BTSCANDEV_maxfield) {
			out_string = "Unknown field requested.";
			return -1;
		}

		osstr.str("");

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		switch (fnum) {
			case BTSCANDEV_bdaddr:
				osstr << bt->bd_addr.Mac2String();
				break;
			case BTSCANDEV_firsttime:
				osstr << bt->first_time;
				break;
			case BTSCANDEV_lasttime:
				osstr << bt->last_time;
				break;
			case BTSCANDEV_packets:
				osstr << bt->packets;
				break;
			case BTSCANDEV_name:
				osstr << "\001" + bt->bd_name + "\001";
				break;
			case BTSCANDEV_class:
				osstr << "\001" + bt->bd_class + "\001";
				break;
			case BTSCANDEV_gpsfixed:
				osstr << bt->gpsdata.gps_valid;
				break;
			case BTSCANDEV_minlat:
				osstr << bt->gpsdata.min_lat;
				break;
			case BTSCANDEV_maxlat:
				osstr << bt->gpsdata.max_lat;
				break;
			case BTSCANDEV_minlon:
				osstr << bt->gpsdata.min_lon;
				break;
			case BTSCANDEV_maxlon:
				osstr << bt->gpsdata.max_lon;
				break;
			case BTSCANDEV_minalt:
				osstr << bt->gpsdata.min_alt;
				break;
			case BTSCANDEV_maxalt:
				osstr << bt->gpsdata.max_alt;
				break;
			case BTSCANDEV_minspd:
				osstr << bt->gpsdata.min_spd;
				break;
			case BTSCANDEV_maxspd:
				osstr << bt->gpsdata.max_spd;
				break;
			case BTSCANDEV_agglat:
				osstr << bt->gpsdata.aggregate_lat;
				break;
			case BTSCANDEV_agglon:
				osstr << bt->gpsdata.aggregate_lon;
				break;
			case BTSCANDEV_aggalt:
				osstr << bt->gpsdata.aggregate_alt;
				break;
			case BTSCANDEV_aggpoints:
				osstr <<bt->gpsdata.aggregate_points;
				break;
		}

		out_string += osstr.str() + " ";
		cache->Cache(fnum, osstr.str());
	}

	return 1;
}

void Protocol_BTSCANDEV_enable(PROTO_ENABLE_PARMS) {
	((Tracker_BTScan *) data)->BlitDevices(in_fd);
}

int btscantracktimer(TIMEEVENT_PARMS) {
	((Tracker_BTScan *) parm)->BlitDevices(-1);
	return 1;
}

int btscan_chain_hook(CHAINCALL_PARMS) {
	return ((Tracker_BTScan *) auxdata)->chain_handler(in_pack);
}

Tracker_BTScan::Tracker_BTScan(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	globalreg->packetchain->RegisterHandler(&btscan_chain_hook, this,
											CHAINPOS_CLASSIFIER, 0);
	
	BTSCANDEV_ref = 
		globalreg->kisnetserver->RegisterProtocol("BTSCANDEV", 0, 1,
												  BTSCANDEV_fields_text,
												  &Protocol_BTSCANDEV,
												  &Protocol_BTSCANDEV_enable,
												  this);

	timer_ref =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &btscantracktimer, this);
}

int Tracker_BTScan::chain_handler(kis_packet *in_pack) {
	btscan_packinfo *bti = (btscan_packinfo *) in_pack->fetch(pack_comp_btscan);

	if (bti == NULL)
		return 0;

	btscan_network *btnet = NULL;

	map<mac_addr, btscan_network *>::iterator titr = tracked_devs.find(bti->bd_addr);

	if (titr == tracked_devs.end()) {
		btnet = new btscan_network();
		btnet->first_time = globalreg->timestamp.tv_sec;
		btnet->bd_addr = bti->bd_addr;
		btnet->bd_name = MungeToPrintable(bti->bd_name);
		btnet->bd_class = MungeToPrintable(bti->bd_class);

		tracked_devs[bti->bd_addr] = btnet;

		_MSG("Detected new bluetooth device \"" + btnet->bd_name + "\", MAC " +
			 btnet->bd_addr.Mac2String() + " class " + btnet->bd_class, MSGFLAG_INFO);
	} else {
		btnet = titr->second;
	}

	kis_gps_packinfo *gpsinfo = (kis_gps_packinfo *) 
		in_pack->fetch(_PCM(PACK_COMP_GPS));

	if (gpsinfo != NULL && gpsinfo->gps_fix) {
		btnet->gpsdata += gpsinfo;
	}

	btnet->last_time = globalreg->timestamp.tv_sec;
	btnet->packets++;

	btnet->dirty = 1;

	return 1;
}

void Tracker_BTScan::BlitDevices(int in_fd) {
	map<mac_addr, btscan_network *>::iterator x;

	for (x = tracked_devs.begin(); x != tracked_devs.end(); x++) {
		kis_protocol_cache cache;

		if (in_fd == -1) {
			if (x->second->dirty == 0)
				continue;

			x->second->dirty = 0;

			if (globalreg->kisnetserver->SendToAll(BTSCANDEV_ref,
												   (void *) x->second) < 0)
				break;

		} else {
			if (globalreg->kisnetserver->SendToClient(in_fd, BTSCANDEV_ref,
													  (void *) x->second,
													  &cache) < 0)
				break;
		}
	}
}


