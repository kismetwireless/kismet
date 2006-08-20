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

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "kis_panel_bssid.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"

// Callbacks into the classes proper
void KisNetlist_Configured(CLICONF_CB_PARMS) {
	((Kis_Netlist *) auxptr)->NetClientConfigure(kcli, recon);
}

void KisNetlist_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Kis_Netlist *) auxptr)->NetClientAdd(netcli, add);
}

void KisNetlist_BSSID(CLIPROTO_CB_PARMS) {
	((Kis_Netlist *) auxptr)->Proto_BSSID(globalreg, proto_string,
										  proto_parsed, srccli, auxptr);
}

Kis_Netlist::Kis_Netlist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	kpinterface = in_panel->FetchPanelInterface();

	v_dirty = 0;
	vc_dirty = 0;
	all_dirty = 0;
	viewable_size = 0;

	sortmode = KIS_SORT_AUTO;


	// Add the addcli reference.  This also kicks off adding it for any
	// active clients, so we'd better be ready (IE, leave this at the end 
	// of the constructor)....
	//
	// New (and current) clients -> AddCli
	// AddCli -> Netlist instance AddCli
	// NetlistAddcli -> Add ConfigureCB
	// ConfigureCB -> Netlist instance ConfigureCB
	// NetlistConfigureCB -> RegisterProtoHandler
	//
	// Good crap.
	addref = kpinterface->Add_NetCli_AddCli_CB(KisNetlist_AddCli, (void *) this);
}

Kis_Netlist::~Kis_Netlist() {
	// Remove the callback
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	// Remove the callback the hard way from anyone still using it
	kpinterface->Remove_AllNetcli_ProtoHandler("BSSID", KisNetlist_BSSID, this);
}

void Kis_Netlist::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	if (in_recon)
		return;

	if (in_cli->RegisterProtoHandler("BSSID", KCLI_BSSID_FIELDS,
									 KisNetlist_BSSID, this) < 0) {
		_MSG("Could not register BSSID protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}

}

void Kis_Netlist::NetClientAdd(KisNetClient *in_cli, int add) {
	if (add == 0) {
		// Ignore remove events for now
		return;
	}

	// Add a client configured callback to the new client so we can load
	// our protocols
	in_cli->AddConfCallback(KisNetlist_Configured, 1, this);
}

void Kis_Netlist::SetPosition(int isx, int isy, int iex, int iey) {
	Kis_Panel_Component::SetPosition(isx, isy, iex, iey);

	// Catch and reset the size and flag us as dirty if we changed
	if (viewable_size != 0 && viewable_size != ey - 1) {
			all_dirty = 1;
	}
		
	viewable_size = ey - 1;
}

void Kis_Netlist::SetSortMode(int in_mode) {
	// Flag as dirty if we're changing the mode
	if (sortmode != in_mode)
		all_dirty = 1;

	sortmode = in_mode;
}

void Kis_Netlist::Proto_BSSID(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < KCLI_BSSID_NUMFIELDS) {
		return;
	}
	
	Netracker::tracked_network *net = new Netracker::tracked_network;

	int tint;
	float tfloat;
	long double tlf;
	long long unsigned int tlld;
	mac_addr tmac;

	// BSSID
	tmac = mac_addr((*proto_parsed)[0].word.c_str());
	if (tmac.error) {
		delete net;
		return;
	}
	net->bssid = tmac;

	// Type
	if (sscanf((*proto_parsed)[1].word.c_str(), "%d", &tint) != 1) {
		delete net;
		return;
	}
	net->type = (network_type) tint;

	// Packet counts
	if (sscanf((*proto_parsed)[2].word.c_str(), "%d", &(net->llc_packets)) != 1) {
		delete net;
		return;
	}
	if (sscanf((*proto_parsed)[3].word.c_str(), "%d", &(net->data_packets)) != 1) {
		delete net;
		return;
	}
	if (sscanf((*proto_parsed)[4].word.c_str(), "%d", &(net->crypt_packets)) != 1) {
		delete net;
		return;
	}

	// Channel
	if (sscanf((*proto_parsed)[5].word.c_str(), "%d", &(net->channel)) != 1) {
		delete net;
		return;
	}

	// Times
	if (sscanf((*proto_parsed)[6].word.c_str(), "%d", &tint) != 1) {
		delete net;
		return;
	}
	net->first_time = tint;
	if (sscanf((*proto_parsed)[7].word.c_str(), "%d", &tint) != 1) {
		delete net;
		return;
	}
	net->last_time = tint;

	// Atype
	if (sscanf((*proto_parsed)[8].word.c_str(), "%d", &tint) != 1) {
		delete net;
		return;
	}
	net->guess_ipdata.ip_type = (ipdata_type) tint;

	// Rangeip
	if (inet_aton((*proto_parsed)[9].word.c_str(), 
				  &(net->guess_ipdata.ip_addr_block)) == 0) {
		delete net;
		return;
	}

	// Maskip
	if (inet_aton((*proto_parsed)[10].word.c_str(),
				  &(net->guess_ipdata.ip_netmask)) == 0) {
		delete net;
		return;
	}

	// Gateip
	if (inet_aton((*proto_parsed)[11].word.c_str(),
				  &(net->guess_ipdata.ip_gateway)) == 0) {
		delete net;
		return;
	}

	// GPS
	if (sscanf((*proto_parsed)[12].word.c_str(), "%d",
			   &(net->gpsdata.gps_valid)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[13].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.min_lat = tfloat;

	if (sscanf((*proto_parsed)[14].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.min_lon = tfloat;

	if (sscanf((*proto_parsed)[15].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.min_alt = tfloat;

	if (sscanf((*proto_parsed)[16].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.min_spd = tfloat;

	if (sscanf((*proto_parsed)[17].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.max_lat = tfloat;

	if (sscanf((*proto_parsed)[18].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.max_lon = tfloat;
	
	if (sscanf((*proto_parsed)[19].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.max_alt = tfloat;

	if (sscanf((*proto_parsed)[20].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.max_spd = tfloat;

	// Signal levels
	if (sscanf((*proto_parsed)[21].word.c_str(), "%d", 
			   &(net->snrdata.last_signal)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[22].word.c_str(), "%d",
			   &(net->snrdata.last_noise)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[23].word.c_str(), "%d",
			   &(net->snrdata.min_signal)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[24].word.c_str(), "%d",
			   &(net->snrdata.min_noise)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[25].word.c_str(), "%d",
			   &(net->snrdata.max_signal)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[26].word.c_str(), "%d",
			   &(net->snrdata.max_noise)) != 1) {
		delete net;
		return;
	}

	// SNR lat/lon
	if (sscanf((*proto_parsed)[27].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->snrdata.peak_lat = tfloat;

	if (sscanf((*proto_parsed)[28].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->snrdata.peak_lon = tfloat;

	if (sscanf((*proto_parsed)[29].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->snrdata.peak_alt = tfloat;

	// gpsdata aggregates
	if (sscanf((*proto_parsed)[30].word.c_str(), "%Lf", &tlf) != 1) {
		delete net;
		return;
	}
	net->gpsdata.aggregate_lat = tlf;

	if (sscanf((*proto_parsed)[31].word.c_str(), "%Lf", &tlf) != 1) {
		delete net;
		return;
	}
	net->gpsdata.aggregate_lon = tlf;

	if (sscanf((*proto_parsed)[32].word.c_str(), "%Lf", &tlf) != 1) {
		delete net;
		return;
	}
	net->gpsdata.aggregate_alt = tlf;

	if (sscanf((*proto_parsed)[33].word.c_str(), "%ld", 
			   &(net->gpsdata.aggregate_points)) != 1) {
		delete net;
		return;
	}

	// Data size
	if (sscanf((*proto_parsed)[34].word.c_str(), "%llu", &tlld) != 1) {
		delete net;
		return;
	}
	net->datasize = tlld;

	// We don't handle turbocell yet, so ignore it
	// 35 tcnid
	// 36 tcmode
	// 37 tcsat
	
	// SNR carrierset
	if (sscanf((*proto_parsed)[38].word.c_str(), "%d", 
			   &(net->snrdata.carrierset)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[39].word.c_str(), "%d",
			   &(net->snrdata.maxseenrate)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[40].word.c_str(), "%d",
			   &(net->snrdata.encodingset)) != 1) {
		delete net;
		return;
	}

	// Decrypted
	if (sscanf((*proto_parsed)[41].word.c_str(), "%d", &(net->decrypted)) != 1) {
		delete net;
		return;
	}

	// Dupeiv
	if (sscanf((*proto_parsed)[42].word.c_str(), "%d", &(net->dupeiv_packets)) != 1) {
		delete net;
		return;
	}

	// BSS time stamp
	if (sscanf((*proto_parsed)[43].word.c_str(), "%llu", &tlld) != 1) {
		delete net;
		return;
	}
	net->bss_timestamp = tlld;

	// CDP data
	net->cdp_dev_id = MungeToPrintable((*proto_parsed)[44].word);
	net->cdp_port_id = MungeToPrintable((*proto_parsed)[45].word);

	// Fragments
	if (sscanf((*proto_parsed)[46].word.c_str(), "%d", &(net->fragments)) != 1) {
		delete net;
		return;
	}

	// Retries
	if (sscanf((*proto_parsed)[47].word.c_str(), "%d", &(net->retries)) != 1) {
		delete net;
		return;
	}

	// New packets
	if (sscanf((*proto_parsed)[48].word.c_str(), "%d", &(net->new_packets)) != 1) {
		delete net;
		return;
	}

	map<mac_addr, Netracker::tracked_network *>::iterator ti;
	// simple case -- we're not tracked yet
	if ((ti = bssid_map.find(net->bssid)) == bssid_map.end()) {
		bssid_map[net->bssid] = net;
		all_bssid.push_back(net);
		all_dirty = 1;

		// If the viewable vec is smaller than the possible size, anything
		// new goes into it
		if ((int) viewable_bssid.size() < viewable_size) { 
			viewable_bssid.push_back(net);
			// Use field2 to indicate visible
			net->field2 = 1;
			v_dirty = 1;

			_MSG("debug - pushed new net into small viewable list", MSGFLAG_INFO);
		} else {
			// Compare with the viewable vec fields for the current sort
			ViewSortFitBSSID(net);
		}

		return;
	}

	Netracker::tracked_network *onet = ti->second;
	int merge_potential = 0;

	// Onet content will always be dirty, so update it if its viewable
	if (onet->field2)
		vc_dirty = 1;

	// Check the sort-relevant fields and if they're dirty, flag this as
	// a potential merge
	// Irrelevant: BSSID, firsttime.  Neither should change.
	if (onet->type != net->type && sortmode == KIS_SORT_TYPE)
		merge_potential = 1;
	else if (onet->channel != net->channel && sortmode == KIS_SORT_CHANNEL)
		merge_potential = 1;
	else if (onet->last_time != net->last_time && 
			 (sortmode == KIS_SORT_LAST || sortmode == KIS_SORT_LAST_D))
		merge_potential = 1;
	else if ((onet->llc_packets + onet->data_packets) != 
			 (net->llc_packets + net->data_packets) && 
			 (sortmode == KIS_SORT_PACKETS || sortmode == KIS_SORT_PACKETS_D))
		merge_potential = 1;
	
	// Merge the new data into the old data
	onet->type = net->type;
	onet->llc_packets = net->llc_packets;
	onet->data_packets = net->data_packets;
	onet->crypt_packets = net->crypt_packets;
	onet->channel = net->channel;
	onet->last_time = net->last_time;
	onet->decrypted = net->decrypted;
	onet->client_disconnects = net->client_disconnects;
	onet->last_sequence = net->last_sequence;
	onet->bss_timestamp = net->bss_timestamp;
	onet->datasize = net->datasize;
	onet->dupeiv_packets = net->dupeiv_packets;
	onet->fragments = net->fragments;
	onet->retries = net->retries;
	onet->new_packets = net->new_packets;

	// So by now, if the net is new, it's (maybe) tacked into the viewable array.
	// If it's one we have, and it's viewable, the viewable list is set to
	// dirty straight off.  If something has changed that might affect the
	// viewable vector, try to merge it into the viewable list
	ViewSortFitBSSID(onet);
}

void Kis_Netlist::ViewSortFitBSSID(Netracker::tracked_network *net) {
	Netracker::tracked_network *first = viewable_bssid[0];
	Netracker::tracked_network *last = viewable_bssid[viewable_bssid.size() - 1];
	int merge = 0;

	// If we're already viewed, we don't need to think about a merge at all
	if (net->field2 == 1)
		return;

	if (sortmode == KIS_SORT_AUTO) {
		if (net->last_time >= last->last_time)
			merge = 1;
	} else if (sortmode == KIS_SORT_TYPE) {
		if ((int) net->type >= (int) first->type &&
			(int) net->type <= (int) last->type)
			merge = 1;
	} else if (sortmode == KIS_SORT_CHANNEL) {
		if (net->channel >= first->channel && net->channel <= last->channel)
			merge = 1;
	} else if (sortmode == KIS_SORT_FIRST) {
		if (net->first_time >= first->first_time && 
			net->first_time <= last->first_time)
			merge = 1;
	} else if (sortmode == KIS_SORT_FIRST_D) {
		if (net->first_time <= first->first_time &&
			net->first_time >= last->first_time)
			merge = 1;
	} else if (sortmode == KIS_SORT_LAST) {
		if (net->last_time >= first->last_time && 
			net->last_time <= last->last_time)
			merge = 1;
	} else if (sortmode == KIS_SORT_LAST_D) {
		if (net->last_time <= first->last_time &&
			net->last_time >= last->last_time)
			merge = 1;
	} else if (sortmode == KIS_SORT_BSSID) {
		if (net->bssid <= first->bssid == 0 &&
			net->bssid <= last->bssid)
			merge = 1;
	} else if (sortmode == KIS_SORT_SSID) {
		// Fix me somehow
	} else if (sortmode == KIS_SORT_PACKETS) {
		if ((net->llc_packets + net->data_packets) >= 
			(first->llc_packets + first->data_packets) && 
			(net->llc_packets + net->data_packets) <=
			(last->llc_packets + last->data_packets))
			merge = 1;
	}

	if (merge) {
		viewable_bssid.push_back(net);
		// Set the viewable field
		net->field2 = 1;
		v_dirty = 1;
		_MSG("debug - pushed new net into sorted viewable list", MSGFLAG_INFO);
	}

}

void Kis_Netlist::DrawComponent() {

}

void Kis_Netlist::Activate(int subcomponent) {

}

void Kis_Netlist::Deactivate() {

}

int Kis_Netlist::KeyPress(int in_key) {

	return 0;
}

#endif // panel

