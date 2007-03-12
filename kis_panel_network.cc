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

#include "kis_panel_network.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"
#include "kis_panel_netsort.h"

// Netgroup management
Kis_Display_NetGroup::Kis_Display_NetGroup() {
	fprintf(stderr, "FATAL OOPS: Kis_Netlist_Group()\n");
	exit(1);
}

Kis_Display_NetGroup::Kis_Display_NetGroup(Netracker::tracked_network *in_net) {
	local_metanet = 0;
	metanet = in_net;
	meta_vec.push_back(in_net);
	dirty = 0;
	dispdirty = 1;
	linecache = "";
}

Kis_Display_NetGroup::~Kis_Display_NetGroup() {
	// Only delete the metanet if it's a local construct
	if (local_metanet) {
		delete metanet;
		metanet = NULL;
	}
}

void Kis_Display_NetGroup::Update() {
	if (dirty == 0)
		return;

	dispdirty = 1;

	// if we've gained networks and don't have a local metanet, we
	// just gained one.
	if (meta_vec.size() > 1 && local_metanet == 0) {
		local_metanet = 1;
		metanet = new Netracker::tracked_network;
	}

	// If we don't have a local meta network, just bail, because the
	// network we present is the same as the tcp network.  In the future
	// this might hold an update of the cached line.
	if (local_metanet == 0) {
		// We're not dirty, the comprising network isn't dirty, we're
		// done here.
		dirty = 0;
		metanet->dirty = 0;
		return;
	}

	int first = 1;
	for (unsigned int x = 0; x < meta_vec.size(); x++) {
		Netracker::tracked_network *mv = meta_vec[x];
		if (first) {
			metanet->llc_packets = mv->llc_packets;
			metanet->data_packets = mv->data_packets;
			metanet->crypt_packets = mv->crypt_packets;
			metanet->channel = 0;
			metanet->last_time = mv->last_time;
			metanet->first_time = mv->first_time;
			metanet->decrypted = mv->decrypted;
			
			metanet->gpsdata = mv->gpsdata;
			metanet->snrdata = mv->snrdata;
			metanet->guess_ipdata = mv->guess_ipdata;

			metanet->client_disconnects = mv->client_disconnects;
			metanet->last_sequence = 0;
			metanet->bss_timestamp = 0;

			metanet->datasize = mv->datasize;

			metanet->dupeiv_packets = mv->dupeiv_packets;

			metanet->fragments = mv->fragments;
			metanet->retries = mv->retries;

			metanet->new_packets = mv->new_packets;

			metanet->ssid_map = mv->ssid_map;
			metanet->lastssid = mv->lastssid;
		} else {
			metanet->llc_packets += mv->llc_packets;
			metanet->data_packets += mv->data_packets;
			metanet->crypt_packets += mv->crypt_packets;

			if (mv->first_time < metanet->first_time)
				metanet->first_time = mv->first_time;
			if (mv->last_time > metanet->last_time)
				metanet->last_time = mv->last_time;

			metanet->decrypted += mv->decrypted;

			// Mmm overloaded
			metanet->gpsdata += mv->gpsdata;
			metanet->snrdata += mv->snrdata;
			// metanet->guess_ipdata += mv->guess_ipdata;

			metanet->client_disconnects += mv->client_disconnects;
			
			metanet->datasize += mv->datasize;

			metanet->fragments += mv->fragments;
			metanet->retries += mv->retries;

			metanet->new_packets += mv->new_packets;

			if (mv->lastssid != NULL) {
				if (metanet->lastssid == NULL)
					metanet->lastssid = mv->lastssid;
				else if (mv->lastssid->last_time > metanet->lastssid->last_time)
					metanet->lastssid = mv->lastssid;
			} else {
				metanet->lastssid = NULL;
			}

			// We don't combine CDP data
		}

		first = 0;

		// The net is no longer dirty
		mv->dirty = 0;
	}

	dirty = 0;
}

string Kis_Display_NetGroup::GetName() {
	if (name == "" && metanet != NULL) {
#if 0
		if (metanet->ssid_map.size() != 0) {
			Netracker::adv_ssid_data *asd = (metanet->ssid_map.begin())->second;

			if (asd->ssid_cloaked)
				return "<" + asd->ssid + ">";

			return asd->ssid;
#endif
		if (metanet->lastssid != NULL) {
			if (metanet->lastssid->ssid.length() == 0)
				return "<No SSID>";
			else if (metanet->lastssid->ssid_cloaked)
				return "<" + metanet->lastssid->ssid + ">";

			return metanet->lastssid->ssid;
		} else {
			// return metanet->bssid.Mac2String();
			return "<No SSID>";
		}
	} else {
		return name;
	}

	return "<Unknown>";
}

void Kis_Display_NetGroup::SetName(string in_name) {
	name = in_name;
	dispdirty = 1;
}

Netracker::tracked_network *Kis_Display_NetGroup::FetchNetwork() {
	return metanet;
}

void Kis_Display_NetGroup::AddNetwork(Netracker::tracked_network *in_net) {
	// Assume they won't call us without checking an external map
	// so this net isn't attached to any other groups
	//
	// Otherwise, adding a network is really simple, we just stick
	// it in the vec and flag dirty, more fun happens during the update
	
	meta_vec.push_back(in_net);

	dirty = 1;
}

void Kis_Display_NetGroup::DelNetwork(Netracker::tracked_network *in_net) {
	// Maybe we need to replace this in the future if we do a lot of removal,
	// but on the assumption that most removal will really be destruction of
	// the entire network, we'll just do a linear search
	for (unsigned int x = 0; x < meta_vec.size(); x++) {
		if (meta_vec[x] == in_net) {
			meta_vec.erase(meta_vec.begin() + x);
			dirty = 1;
			return;
		}
	}
}

void Kis_Display_NetGroup::DirtyNetwork(Netracker::tracked_network *in_net) {
	// No real reason to take a network, at the moment, but why not
	dirty = 1;
}

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

void KisNetlist_SSID(CLIPROTO_CB_PARMS) {
	((Kis_Netlist *) auxptr)->Proto_SSID(globalreg, proto_string,
										 proto_parsed, srccli, auxptr);
}

// Event callbacks
int Event_Netlist_Update(TIMEEVENT_PARMS) {
	((Kis_Netlist *) parm)->UpdateTrigger();
	return 1;
}

Kis_Netlist::Kis_Netlist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	kpinterface = in_panel->FetchPanelInterface();

	viewable_lines = 0;
	viewable_cols = 0;

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

	updateref = globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC,
													  NULL, 1, 
													  &Event_Netlist_Update,
													  (void *) this);

	hpos = 0;
	selected_line = -1;
	first_line = 0;
	last_line = 0;

	// Set default preferences for BSSID columns if we don't have any in the
	// preferences file, then update the column vector
	UpdateBColPrefs();
	UpdateBExtPrefs();
	UpdateSortPrefs();
}

Kis_Netlist::~Kis_Netlist() {
	// Remove the callback
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	// Remove the callback the hard way from anyone still using it
	kpinterface->Remove_AllNetcli_ProtoHandler("BSSID", KisNetlist_BSSID, this);
	kpinterface->Remove_AllNetcli_ProtoHandler("SSID", KisNetlist_SSID, this);
	// Remove the timer
	globalreg->timetracker->RemoveTimer(updateref);
	
	// TODO - clean up the display vector incase for some reason we're being
	// destroyed without exiting the program
}

int Kis_Netlist::UpdateBColPrefs() {
	string pcols;

	// Use a default set of columns if we don't find one
	if ((pcols = kpinterface->GetPref("NETLIST_COLUMNS")) == "") {
		pcols = "decay,name,nettype,crypt,channel,packets,datasize";
		kpinterface->SetPref("NETLIST_COLUMNS", pcols, 1);
	}

	if (kpinterface->GetPrefDirty("NETLIST_COLUMNS") == 0)
		return 0;

	kpinterface->SetPrefDirty("NETLIST_COLUMNS", 0);

	display_bcols.clear();

	vector<string> toks = StrTokenize(pcols, ",");
	string t;

	// Clear the cached headers
	colhdr_cache = "";

	for (unsigned int x = 0; x < toks.size(); x++) {
		t = StrLower(toks[x]);

		if (t == "decay")
			display_bcols.push_back(bcol_decay);
		else if (t == "name")
			display_bcols.push_back(bcol_name);
		else if (t == "shortname")
			display_bcols.push_back(bcol_shortname);
		else if (t == "nettype")
			display_bcols.push_back(bcol_nettype);
		else if (t == "crypt")
			display_bcols.push_back(bcol_crypt);
		else if (t == "channel")
			display_bcols.push_back(bcol_channel);
		else if (t == "datapack")
			display_bcols.push_back(bcol_packdata);
		else if (t == "llcpack")
			display_bcols.push_back(bcol_packllc);
		else if (t == "cryptpack")
			display_bcols.push_back(bcol_packcrypt);
		else if (t == "bssid")
			display_bcols.push_back(bcol_bssid);
		else if (t == "packets")
			display_bcols.push_back(bcol_packets);
		else if (t == "clients")
			display_bcols.push_back(bcol_clients);
		else if (t == "datasize")
			display_bcols.push_back(bcol_datasize);
		else if (t == "bcol_signalbar")
			display_bcols.push_back(bcol_signalbar);
		else
			_MSG("Unknown display column '" + t + "', skipping.",
				 MSGFLAG_INFO);
	}

	return 1;
}

int Kis_Netlist::UpdateBExtPrefs() {
	string pcols;

	// Use a default set of columns if we don't find one
	if ((pcols = kpinterface->GetPref("NETLIST_EXTRAS")) == "") {
		pcols = "lastseen,crypt,ip,manuf,model";
		kpinterface->SetPref("NETLIST_EXTRAS", pcols, 1);
	}

	if (kpinterface->GetPrefDirty("NETLIST_EXTRAS") == 0)
		return 0;

	kpinterface->SetPrefDirty("NETLIST_EXTRAS", 0);

	display_bexts.clear();

	vector<string> toks = StrTokenize(pcols, ",");
	string t;

	for (unsigned int x = 0; x < toks.size(); x++) {
		t = StrLower(toks[x]);

		if (t == "lastseen") 
			display_bexts.push_back(bext_lastseen);
		else if (t == "crypt")
			display_bexts.push_back(bext_crypt);
		else if (t == "ip")
			display_bexts.push_back(bext_ip);
		else if (t == "manuf")
			display_bexts.push_back(bext_manuf);
		else if (t == "model")
			display_bexts.push_back(bext_manuf);
		else
			_MSG("Unknown display extra field '" + t + "', skipping.",
				 MSGFLAG_INFO);
	}

	return 1;
}

int Kis_Netlist::UpdateSortPrefs() {
	string sort;

	// Use a default set of columns if we don't find one
	if ((sort = kpinterface->GetPref("NETLIST_SORT")) == "") {
		sort = "auto";
		kpinterface->SetPref("NETLIST_SORT", sort, 1);
	}

	if (kpinterface->GetPrefDirty("NETLIST_SORT") == 0)
		return 0;

	kpinterface->SetPrefDirty("NETLIST_SORT", 0);

	sort = StrLower(sort);

	if (sort == "auto")
		sort_mode = netsort_autofit;
	else if (sort == "type")
		sort_mode = netsort_type;
	else if (sort == "channel")
		sort_mode = netsort_channel;
	else if (sort == "first")
		sort_mode = netsort_first;
	else if (sort == "first_desc")
		sort_mode = netsort_first_desc;
	else if (sort == "last")
		sort_mode = netsort_last;
	else if (sort == "last_desc")
		sort_mode = netsort_last;
	else if (sort == "bssid")
		sort_mode = netsort_bssid;
	else if (sort == "ssid")
		sort_mode = netsort_ssid;
	else if (sort == "packets")
		sort_mode = netsort_packets;
	else if (sort == "packets_desc")
		sort_mode = netsort_packets_desc;
	else
		sort_mode = netsort_autofit;

	return 1;
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

	if (in_cli->RegisterProtoHandler("SSID", KCLI_SSID_FIELDS,
									 KisNetlist_SSID, this) < 0) {
		_MSG("Could not register SSID protocol with remote server, connection "
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
		
	viewable_lines = ey - 1;
	viewable_cols = ex;
}

void Kis_Netlist::SetSortMode(int in_mode) {
	sortmode = in_mode;
}

void Kis_Netlist::Proto_BSSID(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < KCLI_BSSID_NUMFIELDS) {
		return;
	}

	int fnum = 0;
	
	Netracker::tracked_network *net = new Netracker::tracked_network;

	int tint;
	float tfloat;
	long double tlf;
	long long unsigned int tlld;
	mac_addr tmac;

	// BSSID
	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		delete net;
		return;
	}
	net->bssid = tmac;

	// Type
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete net;
		return;
	}
	net->type = (network_type) tint;

	// Packet counts
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(net->llc_packets)) != 1) {
		delete net;
		return;
	}
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(net->data_packets)) != 1) {
		delete net;
		return;
	}
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(net->crypt_packets)) != 1) {
		delete net;
		return;
	}

	// Channel
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(net->channel)) != 1) {
		delete net;
		return;
	}

	// Times
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete net;
		return;
	}
	net->first_time = tint;
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete net;
		return;
	}
	net->last_time = tint;

	// Atype
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete net;
		return;
	}
	net->guess_ipdata.ip_type = (ipdata_type) tint;

	// Rangeip
	if (inet_aton((*proto_parsed)[fnum++].word.c_str(), 
				  &(net->guess_ipdata.ip_addr_block)) == 0) {
		delete net;
		return;
	}

	// Maskip
	if (inet_aton((*proto_parsed)[fnum++].word.c_str(),
				  &(net->guess_ipdata.ip_netmask)) == 0) {
		delete net;
		return;
	}

	// Gateip
	if (inet_aton((*proto_parsed)[fnum++].word.c_str(),
				  &(net->guess_ipdata.ip_gateway)) == 0) {
		delete net;
		return;
	}

	// GPS
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->gpsdata.gps_valid)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.min_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.min_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.min_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.min_spd = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.max_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.max_lon = tfloat;
	
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.max_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->gpsdata.max_spd = tfloat;

	// Signal levels
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(net->snrdata.last_signal)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.last_noise)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.min_signal)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.min_noise)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.max_signal)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.max_noise)) != 1) {
		delete net;
		return;
	}

	// SNR lat/lon
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->snrdata.peak_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->snrdata.peak_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete net;
		return;
	}
	net->snrdata.peak_alt = tfloat;

	// gpsdata aggregates
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%Lf", &tlf) != 1) {
		delete net;
		return;
	}
	net->gpsdata.aggregate_lat = tlf;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%Lf", &tlf) != 1) {
		delete net;
		return;
	}
	net->gpsdata.aggregate_lon = tlf;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%Lf", &tlf) != 1) {
		delete net;
		return;
	}
	net->gpsdata.aggregate_alt = tlf;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%ld", 
			   &(net->gpsdata.aggregate_points)) != 1) {
		delete net;
		return;
	}

	// Data size
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%llu", &tlld) != 1) {
		delete net;
		return;
	}
	net->datasize = tlld;

	// We don't handle turbocell yet, so ignore it
	// 35 tcnid
	// 36 tcmode
	// 37 tcsat
	fnum += 3;
	
	// SNR carrierset
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(net->snrdata.carrierset)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.maxseenrate)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.encodingset)) != 1) {
		delete net;
		return;
	}

	// Decrypted
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(net->decrypted)) != 1) {
		delete net;
		return;
	}

	// Dupeiv
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(net->dupeiv_packets)) != 1) {
		delete net;
		return;
	}

	// BSS time stamp
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%llu", &tlld) != 1) {
		delete net;
		return;
	}
	net->bss_timestamp = tlld;

	// CDP data
	net->cdp_dev_id = MungeToPrintable((*proto_parsed)[fnum++].word);
	net->cdp_port_id = MungeToPrintable((*proto_parsed)[fnum++].word);

	// Fragments
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(net->fragments)) != 1) {
		delete net;
		return;
	}

	// Retries
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(net->retries)) != 1) {
		delete net;
		return;
	}

	// New packets
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(net->new_packets)) != 1) {
		delete net;
		return;
	}

	// Determine if we're going to just merge data with the old network, and then
	// determine what we have to do for repositioning the record in the viewable
	// list
	macmap<Netracker::tracked_network *>::iterator ti =
		bssid_raw_map.find(net->bssid);

	if (ti == bssid_raw_map.end()) {
		// Flag dirty, add to vector, we'll deal with it later
		net->dirty = 1;
		dirty_raw_vec.push_back(net);
		bssid_raw_map.insert(net->bssid, net);
		return;
	}

	Netracker::tracked_network *onet = *(ti->second);

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

	delete net;

	// Push a dirty net into the vec, collapse multiple updates to a 
	// net within a single draw update by not pushing already dirty data
	if (onet->dirty == 0) {
		onet->dirty = 1;
		dirty_raw_vec.push_back(onet);
	}

	return;
}

void Kis_Netlist::Proto_SSID(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < KCLI_SSID_NUMFIELDS) {
		return;
	}

	int fnum = 0;

	Netracker::adv_ssid_data *asd = new Netracker::adv_ssid_data;
	Netracker::tracked_network *net = NULL;

	int tint;
	float tfloat;
	mac_addr tmac;

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		delete asd;
		return;
	}

	// Try to find the network this belongs to, if for some reason we don't have
	// a record of it, throw it out and stop processing
	macmap<Netracker::tracked_network *>::iterator tni = bssid_raw_map.find(tmac);

	if (tni == bssid_raw_map.end()) {
		delete asd;
		return;
	}
	net = *(tni->second);

	asd->mac = tmac;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->checksum = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->type = (ssid_type) tint;

	asd->ssid = MungeToPrintable((*proto_parsed)[fnum++].word);
	asd->beacon_info = MungeToPrintable((*proto_parsed)[fnum++].word);

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->cryptset = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->ssid_cloaked = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->first_time = (time_t) tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->last_time = (time_t) tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete asd;
		return;
	}
	asd->maxrate = (double) tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->beaconrate = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->packets = tint;

	map<uint32_t, Netracker::adv_ssid_data *>::iterator asi =
		net->ssid_map.find(asd->checksum);

	// Just add us if we don't exist in the network map
	if (asi == net->ssid_map.end()) {
		asd->dirty = 1;
		net->ssid_map[asd->checksum] = asd;
		net->lastssid = asd;
	} else {
		// Otherwise we need to copy all our stuff into the existing record
		Netracker::adv_ssid_data *oasd = asi->second;

		*oasd = *asd;

		net->lastssid = oasd;
		delete asd;
	}

	// Set the net dirty and push it into the dirty vec if it isn't there already
	if (net->dirty == 0) {
		net->dirty = 1;
		dirty_raw_vec.push_back(net);
	}

	return;
}

void Kis_Netlist::UpdateTrigger(void) {
	// Process the dirty vector and update all our stuff.  This only happens
	// at regular intervals, not every network update
	
	// This code exposes some nasty problems with the macmap iterators,
	// namely that they're always pointers no matter what.  Some day, this
	// could get fixed.

	if (UpdateSortPrefs() == 0 && dirty_raw_vec.size() == 0)
		return;

	vector<Kis_Display_NetGroup *> dirty_vec;

	for (unsigned int x = 0; x < dirty_raw_vec.size(); x++) {
		Netracker::tracked_network *net = dirty_raw_vec[x];

		net->dirty = 0;

		// Is it already assigned to a group?  If it is, we can just 
		// flag the display group as dirty and be done
		if (net->groupptr != NULL) {
			((Kis_Display_NetGroup *) net->groupptr)->DirtyNetwork(net);
			((Kis_Display_NetGroup *) net->groupptr)->Update();
			continue;
		}

		// We have no group.  That means we have to:
		// 	Be assigned to a group and that group updated,
		// 	Be assigned to a pre-defined group and that group updated,
		//  or get a new group all our own
		Kis_Display_NetGroup *ng = NULL;
		macmap<mac_addr>::iterator nsmi = netgroup_stored_map.find(net->bssid);

		// We don't belong to an existing network at all, make a new one
		if (nsmi == netgroup_stored_map.end()) {
			ng = new Kis_Display_NetGroup(net);
			netgroup_asm_map.insert(net->bssid, ng);
			display_vec.push_back(ng);
			net->groupptr = ng;
			continue;
		}

		// We see if we're already allocated
		macmap<Kis_Display_NetGroup *>::iterator nami =
			netgroup_asm_map.find(*(nsmi->second));
		if (nami != netgroup_asm_map.end()) {
			net->groupptr = *(nami->second);
			// Assign before adding since adding makes it dirty
			if ((*(nami->second))->Dirty() == 0)
				dirty_vec.push_back(*(nami->second));
			(*(nami->second))->AddNetwork(net);
		} else {
			// We need to make the group, add it to the allocation, then
			// add our network to it...  it doesn't need to be added to the
			// dirty vector, because it gets linked instantly
			Kis_Display_NetGroup *ng = new Kis_Display_NetGroup(net);
			net->groupptr = ng;
			netgroup_asm_map.insert(*(nsmi->second), ng);
			display_vec.push_back(ng);
		}
	}

	// Update all the dirty groups (compress multiple active nets into a 
	// single group update)
	for (unsigned int x = 0; x < dirty_vec.size(); x++) {
		dirty_vec[x]->Update();
	}

	// We've handled it all
	dirty_raw_vec.clear();

	switch (sort_mode) {
		case netsort_type:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_Type());
			break;
		case netsort_channel:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_Channel());
			break;
		case netsort_first:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_First());
			break;
		case netsort_first_desc:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_FirstDesc());
			break;
		case netsort_last:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_Last());
			break;
		case netsort_last_desc:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_LastDesc());
			break;
		case netsort_bssid:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_Bssid());
			break;
		case netsort_ssid:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_Ssid());
			break;
		case netsort_packets:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_Packets());
			break;
		case netsort_packets_desc:
			stable_sort(display_vec.begin(), display_vec.end(), 
						KisNetlist_Sort_PacketsDesc());
			break;
		default:
			break;
	}
}

void Kis_Netlist::DrawComponent() {
	if (visible == 0)
		return;

	// This is the largest we should ever expect a window to be wide, so
	// we'll consider it a reasonable static line size
	char rline[1024];
	int rofft = 0;

	// Printed line and a temp string to hold memory, used for cache
	// aliasing
	char *pline;
	string pt;

	// Column headers
	if (colhdr_cache == "") {
		rofft = 0;
		for (unsigned c = 0; c < display_bcols.size(); c++) {
			bssid_columns b = display_bcols[c];

			if (b == bcol_decay) {
				snprintf(rline + rofft, 1024 - rofft, " ");
				rofft += 1;
			} else if (b == bcol_name) {
				snprintf(rline + rofft, 1024 - rofft, "%-20.20s", "Name");
				rofft += 20;
			} else if (b == bcol_shortname) {
				snprintf(rline + rofft, 1024 - rofft, "%-10.10s", "Name");
				rofft += 10;
			} else if (b == bcol_nettype) {
				snprintf(rline + rofft, 1024 - rofft, "T");
				rofft += 1;
			} else if (b == bcol_crypt) {
				snprintf(rline + rofft, 1024 - rofft, "C");
				rofft += 1;
			} else if (b == bcol_channel) {
				snprintf(rline + rofft, 1024 - rofft, " Ch");
				rofft += 3;
			} else if (b == bcol_packdata) {
				snprintf(rline + rofft, 1024 - rofft, " Data");
				rofft += 5;
			} else if (b == bcol_packllc) {
				snprintf(rline + rofft, 1024 - rofft, "  LLC");
				rofft += 5;
			} else if (b == bcol_packcrypt) {
				snprintf(rline + rofft, 1024 - rofft, "Crypt");
				rofft += 5;
			} else if (b == bcol_bssid) {
				snprintf(rline + rofft, 1024 - rofft, "%-17s", "BSSID");
				rofft += 17;
			} else if (b == bcol_packets) {
				snprintf(rline + rofft, 1024 - rofft, " Pkts");
				rofft += 5;
			} else if (b == bcol_clients) {
				snprintf(rline + rofft, 1024 - rofft, "Clnt");
				rofft += 4;
			} else if (b == bcol_datasize) {
				snprintf(rline + rofft, 1024 - rofft, " Size");
				rofft += 5;
			} else if (b == bcol_datasize) {
				snprintf(rline + rofft, 1024 - rofft, "Signal  ");
				rofft += 8;
			}

			if (rofft < 1023) {
				// Update the endline conditions
				rline[rofft++] = ' ';
				rline[rofft] = '\0';
			} else {
				break;
			}
		}

		colhdr_cache = rline;
	}

	// Draw the cached header
	string pcache = colhdr_cache + string(ex - sx - colhdr_cache.length(), ' ');
	Kis_Panel_Specialtext::Mvwaddnstr(window, sy, sx, 
									  "\004u" + pcache + "\004U", 
									  ex);

	// For as many lines as we can fit
	int dpos = 1;
	for (unsigned int x = first_line; x < display_vec.size() && 
		 dpos <= viewable_lines; x++) {
		Kis_Display_NetGroup *ng = display_vec[x];
		Netracker::tracked_network *meta = ng->FetchNetwork();

		// Recompute the output line if the display for that network is dirty
		// or if the network has changed recently enough.  No sense caching whats
		// going to keep thrashing every update
		if (ng->DispDirty() || 
			(meta != NULL && (time(0) - meta->last_time) < 10)) {
			rofft = 0;
			for (unsigned c = 0; c < display_bcols.size(); c++) {
				bssid_columns b = display_bcols[c];

				if (b == bcol_decay) {
					char d;
					int to;

					to = time(0) - meta->last_time;

					if (to < 3)
						d = '!';
					else if (to < 5)
						d = '.';
					else
						d = ' ';

					snprintf(rline + rofft, 1024 - rofft, "%c", d);
					rofft += 1;
				} else if (b == bcol_name) {
					snprintf(rline + rofft, 1024 - rofft, "%-20.20s", 
							 ng->GetName().c_str());
					rofft += 20;
				} else if (b == bcol_shortname) {
					snprintf(rline + rofft, 1024 - rofft, "%-10.10s", 
							 ng->GetName().c_str());
					rofft += 10;
				} else if (b == bcol_nettype) {
					char d;

					if (meta->type == network_ap)
						d = 'A';
					else if (meta->type == network_adhoc)
						d = 'H';
					else if (meta->type == network_probe)
						d = 'P';
					else if (meta->type == network_turbocell)
						d = 'T';
					else if (meta->type == network_data)
						d = 'D';
					else if (meta->type == network_mixed)
						d = 'M';
					else
						d = '?';

					snprintf(rline + rofft, 1024 - rofft, "%c", d);
					rofft += 1;
				} else if (b == bcol_crypt) {
					char d;

					if (meta->lastssid == NULL) {
						d = '?';
					} else {
						if (meta->lastssid->cryptset == crypt_wep)
							d = 'W';
						else if (meta->lastssid->cryptset)
							d = 'O';
						else
							d = 'N';
					}

					snprintf(rline + rofft, 1024 - rofft, "%c", d);
					rofft += 1;
				} else if (b == bcol_channel) {
					snprintf(rline + rofft, 1024 - rofft, "%3d", meta->channel);
					rofft += 3;
				} else if (b == bcol_packdata) {
					snprintf(rline + rofft, 1024 - rofft, "%5d", meta->data_packets);
					rofft += 5;
				} else if (b == bcol_packllc) {
					snprintf(rline + rofft, 1024 - rofft, "%5d", meta->llc_packets);
					rofft += 5;
				} else if (b == bcol_packcrypt) {
					snprintf(rline + rofft, 1024 - rofft, "%5d", meta->crypt_packets);
					rofft += 5;
				} else if (b == bcol_bssid) {
					snprintf(rline + rofft, 1024 - rofft, "%-17s", 
							 meta->bssid.Mac2String().c_str());
					rofft += 17;
				} else if (b == bcol_packets) {
					snprintf(rline + rofft, 1024 - rofft, "%5d",
							 meta->llc_packets + meta->data_packets);
					rofft += 5;
				} else if (b == bcol_clients) {
					// TODO - handle clients
					snprintf(rline + rofft, 1024 - rofft, "%4d", 0);
					rofft += 4;
				} else if (b == bcol_datasize) {
					char dt = ' ';
					long int ds = 0;

					if (meta->datasize < 1024) {
						ds = meta->datasize;
						dt = 'B';
					} else if (meta->datasize < (1024*1024)) {
						ds = meta->datasize / 1024;
						dt = 'K';
					} else {
						ds = meta->datasize / 1024 / 1024;
						dt = 'M';
					}

					snprintf(rline + rofft, 1024 - rofft, "%4ld%c", ds, dt);
					rofft += 5;
				} else if (b == bcol_datasize) {
					// TODO - signalbar
					snprintf(rline + rofft, 1024 - rofft, "TODO    ");
					rofft += 8;
				} else {
					_MSG("debug - unknown coltype", MSGFLAG_INFO);
					continue;
				}

				if (rofft < 1023) {
					// Update the endline conditions
					rline[rofft++] = ' ';
					rline[rofft] = '\0';
				} else {
					break;
				}
			} // column loop

			ng->SetLineCache(rline);
			pline = rline;
		} else {
			// Pull the cached line
			pt = ng->GetLineCache();
			pline = (char *) pt.c_str();
		}

		// Draw the line
		if (selected_line == (int) x)
			wattron(window, WA_REVERSE);

		// Kis_Panel_Specialtext::Mvwaddnstr(window, sy + dpos, sx, pline, ex);
		// We don't use our specialtext here since we don't want something that
		// snuck into the SSID to affect the printing
		mvwaddnstr(window, sy + dpos, sx, pline, ex - 1);

		if (selected_line == (int) x)
			wattroff(window, WA_REVERSE);

		dpos++;
		last_line = x;

	} // Netlist 

}

void Kis_Netlist::Activate(int subcomponent) {
	active = 1;
}

void Kis_Netlist::Deactivate() {
	active = 0;
}

int Kis_Netlist::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	ostringstream osstr;

	// Selected is the literal selected line in the display vector, not the 
	// line # on the screen, so when we scroll, we need to scroll it as well

	// Autofit gets no love
	if (sort_mode == netsort_autofit)
		return 0;

	// If we haven't selected anything, kick us into the first line on the
	// screen
	if ((in_key == KEY_DOWN || in_key == KEY_NPAGE ||
		 in_key == KEY_UP || in_key == KEY_PPAGE) &&
		(selected_line < 0 || selected_line > last_line)) {
		selected_line = first_line;
		return 0;
	}

	if (in_key == KEY_DOWN) {
		// If we're at the bottom and we can go further, slide the selection
		// and the first line down
		if (selected_line == last_line &&
			last_line < (int) display_vec.size() - 1) {
			selected_line++;
			first_line++;
		} else if (selected_line != last_line) {
			// Otherwise we just move the selected line
			selected_line++;
		}
	} else if (in_key == KEY_UP) {
		// If we're at the top and we can go further, slide the selection
		// and the first line UP
		if (selected_line == first_line && first_line > 0) {
			selected_line--;
			first_line--;
		} else if (selected_line != first_line) {
			// Just slide up the selection
			selected_line--;
		}
	}

	return 0;
}

#endif // panel

