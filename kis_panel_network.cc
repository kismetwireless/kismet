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

const char *bssid_column_details[][2] = {
	{ "decay", "Recent activity" },
	{ "name", "Name or SSID" },
	{ "shortname", "Shortened name or SSID" },
	{ "nettype", "Type of network" },
	{ "crypt", "Encryption options" },
	{ "channel", "Channel" },
	{ "packets", "Total packets" },
	{ "packdata", "Number of data packets" },
	{ "packllc", "Number of LLC/Management packets" },
	{ "packcrypt", "Number of encrypted data packets" },
	{ "bssid", "BSSID" },
	{ "clients", "Number of associated clients" },
	{ "datasize", "Amount of data seen" },
	{ "beaconperc", "Percentage of expected beacons seen" },
	{ "signal_dbm", "Signal (in dBm, depends on source" },
	{ "signal_rssi", "Signal (in RSSI, depends on source" },
	{ "freq_mhz", "Frequency (MHz)" },
	{ NULL, NULL }
};

const char *Kis_Netlist::bssid_columns_text[] = {
	"decay", "name", "shortname", "nettype",
	"crypt", "channel", "packdata", "packllc", "packcrypt",
	"bssid", "packets", "clients", "datasize", "signalbar",
	"beaconperc", "signal_dbm", "signal_rssi", "freq_mhz",
	NULL
};

const char *bssid_extras_details[][2] = {
	{ "lastseen", "Last seen timestamp" },
	{ "bssid", "BSSID" },
	{ "crypt", "Encryption types" },
	{ "manuf", "Manufacturer info" },
	{ "model", "Model" },
	{ NULL, NULL}
};

const char *bssid_fields[] = {
	"bssid", "type", "llcpackets", "datapackets", "cryptpackets", 
	"channel", "firsttime", "lasttime", "atype", "rangeip", "netmaskip",
	"gatewayip", "gpsfixed", "minlat", "minlon", "minalt", "minspd", 
	"maxlat", "maxlon", "maxalt", "maxspd", "signal_dbm", "noise_dbm", 
	"minsignal_dbm", "minnoise_dbm", "maxsignal_dbm", "maxnoise_dbm",
	"signal_rssi", "noise_rssi", "minsignal_rssi", "minnoise_rssi",
	"maxsignal_rssi", "maxnoise_rssi", "bestlat", "bestlon", "bestalt", 
	"agglat", "agglon", "aggalt", "aggpoints", "datasize", "turbocellnid",
	"turbocellmode", "turbocellsat", "carrierset", "maxseenrate", 
	"encodingset", "decrypted", "dupeivpackets", "bsstimestamp", 
	"cdpdevice", "cdpport", "fragments", "retries", "newpackets", "freqmhz",
	NULL
};

const char *ssid_fields[] = {
	"mac", "checksum", "type", "ssid", "beaconinfo", "cryptset",
	"cloaked", "firsttime", "lasttime", "maxrate", "beaconrate", 
	"packets", "beacons", NULL
};

const char *client_fields[] = {
	"bssid", "mac", "type", "firsttime", "lasttime", "llcpackets", "datapackets",
	"cryptpackets", 

	"signal_dbm", "noise_dbm", "minsignal_dbm", 
	"minnoise_dbm", "maxsignal_dbm", "maxnoise_dbm", 

	"signal_rssi", "noise_rssi", "minsignal_rssi",
	"minnoise_rssi", "maxsignal_rssi", "maxnoise_rssi",

	"gpsfixed",

	"bestlat", "bestlon", "bestalt", 

	"agglat", "agglon", "aggalt", "aggpoints",

	"minlat", "minlon", "minalt",
	"maxlat", "maxlon", "maxalt",
	
	"atype", "ip", "gatewayip", "datasize",
	"maxseenrate", "encodingset", "carrierset", "decrypted", 
	"channel", "fragments", "retries", "newpackets", "freqmhz", 
	"cdpdevice", "cdpport",
	NULL
};

const char *time_fields[] = { "timesec", NULL };

const char *info_fields[] = { "networks", "packets", "rate", "filtered", NULL };

// Netgroup management
Kis_Display_NetGroup::Kis_Display_NetGroup() {
	local_metanet = 0;
	metanet = NULL;
	dirty = 0;
	dispdirty = 0;
	linecache = "";
	expanded = 0;
	color = -1;
}

Kis_Display_NetGroup::Kis_Display_NetGroup(Netracker::tracked_network *in_net) {
	local_metanet = 0;
	metanet = in_net;
	meta_vec.push_back(in_net);
	dirty = 0;
	expanded = 0;
	ClearSetDirty();
	in_net->groupptr = this;
}

Kis_Display_NetGroup::~Kis_Display_NetGroup() {
	// Only delete the metanet if it's a local construct
	if (local_metanet) {
		delete metanet;
		metanet = NULL;
	}
}

void Kis_Display_NetGroup::ClearSetDirty() {
	dispdirty = 1;
	linecache = "";
	detcache.clear();
	grpcache.clear();
}

// Update merged network
//
// meta Group will not have update map of clients since they can collide between networks
void Kis_Display_NetGroup::Update() {
	if (dirty == 0)
		return;

	// Shortcut stripping the last network.  This ought to only happen 
	// to the autogroup nets but its possible it will occur in other situations
	if (meta_vec.size() == 0) {
		if (local_metanet)
			delete metanet;

		metanet = NULL;
		dirty = 0;
		return;
	}

	ClearSetDirty();

	// if we've gained networks and don't have a local metanet, we
	// just gained one.
	if (meta_vec.size() > 1 && local_metanet == 0) {
		local_metanet = 1;
		metanet = new Netracker::tracked_network;
	}

	// If we don't have a local meta network, just bail, because the
	// network we present is the same as the tcp network.  
	if (local_metanet == 0) {
		// We're not dirty, the comprising network isn't dirty, we're
		// done here.
		dirty = 0;
		if (metanet != NULL)
			metanet->dirty = 0;
		return;
	}

	int first = 1;
	for (unsigned int x = 0; x < meta_vec.size(); x++) {
		Netracker::tracked_network *mv = meta_vec[x];
		if (first) {
			metanet->bssid = mv->bssid;

			metanet->type = mv->type;

			metanet->llc_packets = mv->llc_packets;
			metanet->data_packets = mv->data_packets;
			metanet->crypt_packets = mv->crypt_packets;
			metanet->channel = 0;

			// Merge the frequency counts for everything
			for (map<unsigned int, unsigned int>::const_iterator fmi = mv->freq_mhz_map.begin(); fmi != mv->freq_mhz_map.end(); ++fmi) {
				if (metanet->freq_mhz_map.find(fmi->first) != 
					metanet->freq_mhz_map.end())
					metanet->freq_mhz_map[fmi->first] += fmi->second;
				else
					metanet->freq_mhz_map[fmi->first] = fmi->second;
			}

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

			first = 0;
		} else {
			// Mask the BSSIDs
			metanet->bssid.longmac &= mv->bssid.longmac;

			if (metanet->type != mv->type)
				metanet->type = network_mixed;

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

		// The net is no longer dirty
		mv->dirty = 0;
	}

	if (metanet == NULL)
		dispdirty = 0;

	dirty = 0;
}

string Kis_Display_NetGroup::GetName() {
	return GetName(metanet);
}

string Kis_Display_NetGroup::GetName(Netracker::tracked_network *net) {
	int usenet = 1;

	if (net == NULL) {
		if (name != "") 
			return name;
		net = metanet;
		usenet = 0;
	}

	if (net != NULL && (usenet || name == "")) {
		Netracker::adv_ssid_data *ssid = net->lastssid;

		// Return a sanely constructed name if we don't have any
		if (ssid == NULL || (ssid != NULL && ssid->ssid.length() == 0 &&
							 net->ssid_map.size() == 1)) {
			if (net->type == network_probe)
				return "<Any>";
			else if (net->type == network_data)
				return "<Unknown>";
			else
				return "<Hidden SSID>";
		}

		// If the map only has 2 items, and one of them is cloaked, then
		// display it with a "decloaked" identifier
		if (net->ssid_map.size() == 2) {
			int cloaked = -1;
			string clear;

			for (map<uint32_t, Netracker::adv_ssid_data *>::iterator i = 
				 net->ssid_map.begin(); i != net->ssid_map.end(); ++i) {
				if (i->second->ssid_cloaked)
					cloaked = 1;
				else
					clear = i->second->ssid;
			}

			if (cloaked == 1 && clear.length() > 0 && net->type != network_probe) {
				return string("<") + clear + string(">");
			} else if (clear.length() > 0) {
				return clear;
			}
		}

		/* If the last one we found was clean, return that */
		if (net->lastssid->ssid.length() > 0)
			return net->lastssid->ssid;

		/* Find a clear one */
		for (map<uint32_t, Netracker::adv_ssid_data *>::iterator i = 
			 net->ssid_map.begin(); i != net->ssid_map.end(); ++i) {
			if (i->second->ssid_cloaked)
				continue;
			else
				return i->second->ssid;
		}

		return "<Hidden SSID>";
	} else {
		if (name == "") {
			return "<Hidden SSID>";
		}

		return name;
	}

	return "<Unknown>";
}

void Kis_Display_NetGroup::SetName(string in_name) {
	name = in_name;
	ClearSetDirty();
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
	in_net->groupptr = this;

	dirty = 1;
	ClearSetDirty();
}

void Kis_Display_NetGroup::DelNetwork(Netracker::tracked_network *in_net) {
	// Maybe we need to replace this in the future if we do a lot of removal,
	// but on the assumption that most removal will really be destruction of
	// the entire network, we'll just do a linear search
	for (unsigned int x = 0; x < meta_vec.size(); x++) {
		if (meta_vec[x] == in_net) {
			meta_vec.erase(meta_vec.begin() + x);
			dirty = 1;
			break;
		}
	}

	in_net->groupptr = NULL;
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

void KisNetlist_CLIENT(CLIPROTO_CB_PARMS) {
	((Kis_Netlist *) auxptr)->Proto_CLIENT(globalreg, proto_string,
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

	sort_mode = netsort_autofit;

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

	probe_autogroup = adhoc_autogroup = data_autogroup = NULL;

	for (int x = 0; x < 5; x++)
		color_map[x] = 0;
	color_inactive = 0;

	// Assemble our protocol lines
	asm_bssid_num = TokenNullJoin(&asm_bssid_fields, bssid_fields);
	asm_ssid_num = TokenNullJoin(&asm_ssid_fields, ssid_fields);
	asm_client_num = TokenNullJoin(&asm_client_fields, client_fields);

	// Set default preferences for BSSID columns if we don't have any in the
	// preferences file, then update the column vector
	UpdateBColPrefs();
	UpdateBExtPrefs();
	UpdateSortPrefs();
}

Kis_Netlist::~Kis_Netlist() {
	// Remove the callback
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(KisNetlist_Configured);
	// Remove the callback the hard way from anyone still using it
	kpinterface->Remove_AllNetcli_ProtoHandler("BSSID", KisNetlist_BSSID, this);
	kpinterface->Remove_AllNetcli_ProtoHandler("SSID", KisNetlist_SSID, this);
	kpinterface->Remove_AllNetcli_ProtoHandler("CLIENT", KisNetlist_CLIENT, this);
	// Remove the timer
	globalreg->timetracker->RemoveTimer(updateref);
	
	// TODO - clean up the display vector incase for some reason we're being
	// destroyed without exiting the program
}

int Kis_Netlist::UpdateBColPrefs() {
	string pcols;

	// Use a default set of columns if we don't find one
	if ((pcols = kpinterface->prefs.FetchOpt("NETLIST_COLUMNS")) == "") {
		pcols = "decay,name,nettype,crypt,channel,packets,datasize";
		kpinterface->prefs.SetOpt("NETLIST_COLUMNS", pcols, 1);
	}

	if (kpinterface->prefs.FetchOptDirty("NETLIST_COLUMNS") == 0)
		return 0;

	kpinterface->prefs.SetOptDirty("NETLIST_COLUMNS", 0);

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
		else if (t == "signalbar")
			display_bcols.push_back(bcol_signalbar);
		else if (t == "beaconperc")
			display_bcols.push_back(bcol_beaconperc);
		else if (t == "signal_dbm")
			display_bcols.push_back(bcol_signal_dbm);
		else if (t == "signal_rssi")
			display_bcols.push_back(bcol_signal_rssi);
		else if (t == "freq_mhz")
			display_bcols.push_back(bcol_freq_mhz);
		else
			_MSG("Unknown display column '" + t + "', skipping.",
				 MSGFLAG_INFO);
	}
	
	for (unsigned int x = 0; x < display_vec.size(); x++) {
		display_vec[x]->SetDispDirty(1);
	}

	return 1;
}

int Kis_Netlist::UpdateBExtPrefs() {
	string pcols;

	// Use a default set of columns if we don't find one
	if ((pcols = kpinterface->prefs.FetchOpt("NETLIST_EXTRAS")) == "") {
		pcols = "bssid,lastseen,crypt,ip,manuf,model";
		kpinterface->prefs.SetOpt("NETLIST_EXTRAS", pcols, 1);
	}

	if (kpinterface->prefs.FetchOptDirty("NETLIST_EXTRAS") == 0)
		return 0;

	kpinterface->prefs.SetOptDirty("NETLIST_EXTRAS", 0);

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
		else if (t == "bssid")
			display_bexts.push_back(bext_bssid);
		else
			_MSG("Unknown display extra field '" + t + "', skipping.",
				 MSGFLAG_INFO);
	}

	return 1;
}

int Kis_Netlist::UpdateSortPrefs() {
	string sort;

	// Use a default set of columns if we don't find one
	if ((sort = kpinterface->prefs.FetchOpt("NETLIST_SORT")) == "") {
		sort = "auto";
		kpinterface->prefs.SetOpt("NETLIST_SORT", sort, 1);
	}

	if (kpinterface->prefs.FetchOptDirty("NETLIST_SORT") == 0)
		return 0;

	kpinterface->prefs.SetOptDirty("NETLIST_SORT", 0);

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
		sort_mode = netsort_last_desc;
	else if (sort == "bssid")
		sort_mode = netsort_bssid;
	else if (sort == "ssid")
		sort_mode = netsort_ssid;
	else if (sort == "packets")
		sort_mode = netsort_packets;
	else if (sort == "packets_desc")
		sort_mode = netsort_packets_desc;
	else if (sort == "crypt_type")
		sort_mode = netsort_crypt;
	else
		sort_mode = netsort_autofit;

	return 1;
}

void Kis_Netlist::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	void (*null_proto)(CLIPROTO_CB_PARMS) = NULL;
	
	if (in_recon)
		return;

	if (in_cli->RegisterProtoHandler("NETWORK", "*", null_proto, this) >= 0) {
		_MSG("This looks like an old kismet-stable server, the Kismet-newcore "
			 "client can only talk to Kismet-newcore servers, connection will "
			 "be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	if (in_cli->RegisterProtoHandler("BSSID", asm_bssid_fields, 
									 KisNetlist_BSSID, this) < 0) {
		_MSG("Could not register BSSID protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	if (in_cli->RegisterProtoHandler("SSID", asm_ssid_fields,
									 KisNetlist_SSID, this) < 0) {
		_MSG("Could not register SSID protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	if (in_cli->RegisterProtoHandler("CLIENT", asm_client_fields,
									 KisNetlist_CLIENT, this) < 0) {
		_MSG("Could not register CLIENT protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}
}

void Kis_Netlist::NetClientAdd(KisNetClient *in_cli, int add) {
	if (add == 0) {
		// Ignore remove events for now
		return;
	}

	// Assume we only have one server at a time (true) then we need to clear
	// on a connection add event
	//
	// We have to do it here because on a reconnect event we'll get issues where
	// the network deltas come from the protocol cache before we get the connect
	// event
	for (macmap<Netracker::tracked_network *>::iterator x = bssid_raw_map.begin();
		 x != bssid_raw_map.end(); ++x) {
		// Ugly hack to deal with "broken" macmap iterators which are really pointers
		delete *(x->second);
	}
	bssid_raw_map.clear();
	dirty_raw_vec.clear();

	for (unsigned int x = 0; x < display_vec.size(); x++) {
		delete display_vec[x];
	}
	display_vec.clear();
	netgroup_asm_map.clear();

	probe_autogroup = NULL;
	adhoc_autogroup = NULL;
	data_autogroup = NULL;

	// Add a client configured callback to the new client so we can load
	// our protocols
	in_cli->AddConfCallback(KisNetlist_Configured, 1, this);
}

void Kis_Netlist::SetPosition(int isx, int isy, int iex, int iey) {
	Kis_Panel_Component::SetPosition(isx, isy, iex, iey);
		
	viewable_lines = ly - 1;
	viewable_cols = ex;
}

void Kis_Netlist::Proto_BSSID(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) asm_bssid_num) {
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
			   &(net->snrdata.last_signal_dbm)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.last_noise_dbm)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.min_signal_dbm)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.min_noise_dbm)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.max_signal_dbm)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.max_noise_dbm)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(net->snrdata.last_signal_rssi)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.last_noise_rssi)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.min_signal_rssi)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.min_noise_rssi)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.max_signal_rssi)) != 1) {
		delete net;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(net->snrdata.max_noise_rssi)) != 1) {
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

	// Frequency packed field
	vector<string> freqtoks = StrTokenize((*proto_parsed)[fnum++].word, "*");
	for (unsigned int fi = 0; fi < freqtoks.size(); fi++) {
		unsigned int freq, count;

		// Just ignore parse errors
		if (sscanf(freqtoks[fi].c_str(), "%u:%u", &freq, &count) != 2)
			continue;

		net->freq_mhz_map[freq] = count;
	}

	/*
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(net->freq_mhz)) != 1) {
		delete net;
		return;
	}
	*/

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
	onet->freq_mhz_map = net->freq_mhz_map;
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

	onet->snrdata = net->snrdata;
	onet->gpsdata = net->gpsdata;

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
	if (proto_parsed->size() < (unsigned int) asm_ssid_num) {
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

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete asd;
		return;
	}
	asd->beacons = tint;


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

void Kis_Netlist::Proto_CLIENT(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) asm_client_num) {
		return;
	}

	int fnum = 0;
	
	Netracker::tracked_client *cli = new Netracker::tracked_client;
	Netracker::tracked_network *pnet = NULL;

	int tint;
	float tfloat;
	long double tlf;
	long long unsigned int tlld;
	mac_addr tmac;

	// BSSID
	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		delete cli;
		return;
	}
	// Reject if we don't know the network
	if (bssid_raw_map.find(tmac) == bssid_raw_map.end()) {
		delete cli;
		return;
	}
	pnet = bssid_raw_map[tmac];
	cli->bssid = tmac;

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		delete cli;
		return;
	}
	cli->mac = tmac;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete cli;
		return;
	}
	cli->type = (client_type) tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete cli;
		return;
	}
	cli->first_time = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete cli;
		return;
	}
	cli->last_time = tint;

	// Packet counts
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(cli->llc_packets)) != 1) {
		delete cli;
		return;
	}
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(cli->data_packets)) != 1) {
		delete cli;
		return;
	}
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(cli->crypt_packets)) != 1) {
		delete cli;
		return;
	}

	// Signal levels
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(cli->snrdata.last_signal_dbm)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.last_noise_dbm)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.min_signal_dbm)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.min_noise_dbm)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.max_signal_dbm)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.max_noise_dbm)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(cli->snrdata.last_signal_rssi)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.last_noise_rssi)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.min_signal_rssi)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.min_noise_rssi)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.max_signal_rssi)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.max_noise_rssi)) != 1) {
		delete cli;
		return;
	}

	// GPS
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->gpsdata.gps_valid)) != 1) {
		delete cli;
		return;
	}

	// SNR lat/lon
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->snrdata.peak_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->snrdata.peak_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->snrdata.peak_alt = tfloat;

	// gpsdata aggregates
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%Lf", &tlf) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.aggregate_lat = tlf;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%Lf", &tlf) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.aggregate_lon = tlf;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%Lf", &tlf) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.aggregate_alt = tlf;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%ld", 
			   &(cli->gpsdata.aggregate_points)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.min_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.min_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.min_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.max_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.max_lon = tfloat;
	
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) {
		delete cli;
		return;
	}
	cli->gpsdata.max_alt = tfloat;

	// Atype
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete cli;
		return;
	}
	cli->guess_ipdata.ip_type = (ipdata_type) tint;

	// Rangeip
	if (inet_aton((*proto_parsed)[fnum++].word.c_str(), 
				  &(cli->guess_ipdata.ip_addr_block)) == 0) {
		delete cli;
		return;
	}

	// Maskip
	if (inet_aton((*proto_parsed)[fnum++].word.c_str(),
				  &(cli->guess_ipdata.ip_netmask)) == 0) {
		delete cli;
		return;
	}

	// Gateip
	if (inet_aton((*proto_parsed)[fnum++].word.c_str(),
				  &(cli->guess_ipdata.ip_gateway)) == 0) {
		delete cli;
		return;
	}

	// Data size
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%llu", &tlld) != 1) {
		delete cli;
		return;
	}
	cli->datasize = tlld;

	// SNR carrierset
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.maxseenrate)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d",
			   &(cli->snrdata.encodingset)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(cli->snrdata.carrierset)) != 1) {
		delete cli;
		return;
	}

	// Decrypted
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(cli->decrypted)) != 1) {
		delete cli;
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(cli->channel)) != 1) {
		delete cli;
		return;
	}

	// Fragments
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(cli->fragments)) != 1) {
		delete cli;
		return;
	}

	// Retries
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &(cli->retries)) != 1) {
		delete cli;
		return;
	}

	// New packets
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", 
			   &(cli->new_packets)) != 1) {
		delete cli;
		return;
	}

	// Frequency packed field
	vector<string> freqtoks = StrTokenize((*proto_parsed)[fnum++].word, "*");
	for (unsigned int fi = 0; fi < freqtoks.size(); fi++) {
		unsigned int freq, count;

		// Just ignore parse errors
		if (sscanf(freqtoks[fi].c_str(), "%u:%u", &freq, &count) != 2)
			continue;

		cli->freq_mhz_map[freq] = count;
	}

	// CDP data
	cli->cdp_dev_id = MungeToPrintable((*proto_parsed)[fnum++].word);
	cli->cdp_port_id = MungeToPrintable((*proto_parsed)[fnum++].word);

	// Merge or new
	map<mac_addr, Netracker::tracked_client *>::iterator ti =
		pnet->client_map.find(cli->mac);

	if (ti == pnet->client_map.end()) {
		// Flag dirty, add to vector, we'll deal with it later
		if (pnet->dirty == 0) {
			pnet->dirty = 1;
			dirty_raw_vec.push_back(pnet);
		}
		pnet->client_map.insert(make_pair(cli->mac, cli));
		return;
	}

	Netracker::tracked_client *ocli = ti->second;

	// Merge the new data into the old data - don't replace the pointer since we have
	// other things referencing it
	ocli->type = cli->type;
	ocli->last_time = cli->last_time;
	ocli->decrypted = cli->decrypted;

	ocli->bssid = cli->bssid;
	ocli->channel = cli->channel;

	ocli->freq_mhz_map = cli->freq_mhz_map;

	ocli->llc_packets = cli->llc_packets;
	ocli->data_packets = cli->data_packets;
	ocli->crypt_packets = cli->crypt_packets;

	ocli->last_sequence = cli->last_sequence;

	ocli->datasize = cli->datasize;

	ocli->fragments = cli->fragments;
	ocli->retries = cli->retries;

	ocli->cdp_dev_id = cli->cdp_dev_id;
	ocli->cdp_port_id = cli->cdp_port_id;

	ocli->new_packets = cli->new_packets;

	ocli->guess_ipdata = cli->guess_ipdata;
	ocli->snrdata = cli->snrdata;
	ocli->gpsdata = cli->gpsdata;

	delete cli;

	// We don't do anything as fancy with client dirty tracking since we'll only
	// be displaying them in sub-windows

	return;
}

int Kis_Netlist::DeleteGroup(Kis_Display_NetGroup *in_group) {
	for (unsigned int x = 0; x < display_vec.size(); x++) {
		if (display_vec[x] == in_group) {
			display_vec.erase(display_vec.begin() + x);
			break;
		}
	}

	vector<Netracker::tracked_network *> *nv = in_group->FetchNetworkVec();

	// Shift all the networks into the dirty vector, unlink them from the
	// additional group tracking methods
	for (unsigned int x = 0; x < nv->size(); x++) {
		(*nv)[x]->groupptr = NULL;

		if ((*nv)[x]->dirty == 0) {
			dirty_raw_vec.push_back((*nv)[x]);
			(*nv)[x]->dirty = 1;
		}

		if (netgroup_stored_map.find((*nv)[x]->bssid) != netgroup_stored_map.end())
			netgroup_stored_map.erase((*nv)[x]->bssid);

		if (netgroup_asm_map.find((*nv)[x]->bssid) != netgroup_asm_map.end())
			netgroup_asm_map.erase((*nv)[x]->bssid);
	}

	delete in_group;

	return 1;
}

void Kis_Netlist::UpdateTrigger(void) {
	// Use the same timer to update the source stuff from the info list
	// We'd normally do this somewhere else but since we own the infobits
	// segment we'll do it here

	// Process the dirty vector and update all our stuff.  This only happens
	// at regular intervals, not every network update
	
	// This code exposes some nasty problems with the macmap iterators,
	// namely that they're always pointers no matter what.  Some day, this
	// could get fixed.
	
	// Show extended info?
	if (kpinterface->prefs.FetchOpt("NETLIST_SHOWEXT") == "0")
		show_ext_info = 0;
	else
		show_ext_info = 1;

	if (UpdateSortPrefs() == 0 && dirty_raw_vec.size() == 0)
		return;

	vector<Kis_Display_NetGroup *> dirty_vec;

	for (unsigned int x = 0; x < dirty_raw_vec.size(); x++) {
		Netracker::tracked_network *net = dirty_raw_vec[x];

		net->dirty = 0;

		Kis_Display_NetGroup *dng = (Kis_Display_NetGroup *) net->groupptr;

		// Handle the autogrouping code
		if (net->type == network_probe) {
			// Delete it from any group its in already
			if (net->groupptr != probe_autogroup) {
				if (net->groupptr != NULL) {
					if (dng->Dirty() == 0)
						dirty_vec.push_back(dng);
					dng->DelNetwork(net);
				}
			}
		
			// Make the group if we need to, otherwise add to it
			if (probe_autogroup == NULL) {
				probe_autogroup = new Kis_Display_NetGroup(net);
				probe_autogroup->SetName("Autogroup Probe");
				netgroup_asm_map.insert(net->bssid, probe_autogroup);
				display_vec.push_back(probe_autogroup);
			} else if (probe_autogroup != net->groupptr){
				if (probe_autogroup->Dirty() == 0)
					dirty_vec.push_back(probe_autogroup);
				probe_autogroup->AddNetwork(net);
			}

			continue;
		} else if (net->type != network_probe && net->groupptr == probe_autogroup &&
				   net->groupptr != NULL) {
			if (probe_autogroup->Dirty() == 0)
				dirty_vec.push_back(probe_autogroup);

			probe_autogroup->DelNetwork(net);
		}

		if (net->type == network_adhoc) {
			if (net->groupptr != adhoc_autogroup) {
				if (net->groupptr != NULL) {
					if (dng->Dirty() == 0)
						dirty_vec.push_back(dng);
					dng->DelNetwork(net);
				}
			}
		
			if (adhoc_autogroup == NULL) {
				adhoc_autogroup = new Kis_Display_NetGroup(net);
				adhoc_autogroup->SetName("Autogroup Adhoc");
				netgroup_asm_map.insert(net->bssid, adhoc_autogroup);
				display_vec.push_back(adhoc_autogroup);
			} else if (adhoc_autogroup != net->groupptr){
				if (adhoc_autogroup->Dirty() == 0)
					dirty_vec.push_back(adhoc_autogroup);
				adhoc_autogroup->AddNetwork(net);
			}

			continue;
		} else if (net->type != network_adhoc && net->groupptr == adhoc_autogroup &&
				   net->groupptr != NULL) {
			if (adhoc_autogroup->Dirty() == 0)
				dirty_vec.push_back(adhoc_autogroup);

			adhoc_autogroup->DelNetwork(net);
		}

		if (net->type == network_data) {
			if (net->groupptr != data_autogroup) {
				if (net->groupptr != NULL) {
					if (dng->Dirty() == 0)
						dirty_vec.push_back(dng);
					dng->DelNetwork(net);
				}
			}
		
			if (data_autogroup == NULL) {
				data_autogroup = new Kis_Display_NetGroup(net);
				data_autogroup->SetName("Autogroup Data");
				netgroup_asm_map.insert(net->bssid, data_autogroup);
				display_vec.push_back(data_autogroup);
			} else if (data_autogroup != net->groupptr){
				if (data_autogroup->Dirty() == 0)
					dirty_vec.push_back(data_autogroup);

				data_autogroup->AddNetwork(net);
			}

			continue;
		} else if (net->type != network_data && net->groupptr == data_autogroup &&
				   net->groupptr != NULL) {
			if (data_autogroup->Dirty() == 0)
				dirty_vec.push_back(data_autogroup);

			data_autogroup->DelNetwork(net);
		}

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
			continue;
		}

		// We see if we're already allocated
		macmap<Kis_Display_NetGroup *>::iterator nami =
			netgroup_asm_map.find(*(nsmi->second));
		if (nami != netgroup_asm_map.end()) {
			// Assign before adding since adding makes it dirty
			if ((*(nami->second))->Dirty() == 0)
				dirty_vec.push_back(*(nami->second));
			(*(nami->second))->AddNetwork(net);
		} else {
			// We need to make the group, add it to the allocation, then
			// add our network to it...  it doesn't need to be added to the
			// dirty vector, because it gets linked instantly
			Kis_Display_NetGroup *ng = new Kis_Display_NetGroup(net);
			netgroup_asm_map.insert(*(nsmi->second), ng);
			display_vec.push_back(ng);
		}
	}

	// Update all the dirty groups (compress multiple active nets into a 
	// single group update)
	int delnet = 0;
	for (unsigned int x = 0; x < dirty_vec.size(); x++) {
		dirty_vec[x]->Update();
		if (dirty_vec[x]->FetchNumNetworks() == 0) {
			delnet |= DeleteGroup(dirty_vec[x]);

			// Update the autogroups
			if (dirty_vec[x] == probe_autogroup)
				probe_autogroup = NULL;
			else if (dirty_vec[x] == adhoc_autogroup)
				adhoc_autogroup = NULL;
			else if (dirty_vec[x] == data_autogroup)
				data_autogroup = NULL;
		}
	}

	// If we deleted a network, we need to re-run the trigger since we might
	// have disassembled groups
	if (delnet) {
		UpdateTrigger();
		return;
	}

	// We've handled it all
	dirty_raw_vec.clear();

	switch (sort_mode) {
		case netsort_autofit:
			stable_sort(display_vec.begin(), display_vec.end(),
						KisNetlist_Sort_LastDesc());
			break;
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
		case netsort_crypt:
			stable_sort(display_vec.begin(), display_vec.end(),
						KisNetlist_Sort_Crypt());
		default:
			break;
	}
}

int Kis_Netlist::PrintNetworkLine(Kis_Display_NetGroup *ng, 
								  Netracker::tracked_network *net,
								  int rofft, char *rline, int max) {
	// Are we using the passed net, or the derived meta?  (for name fetching)
	int usenet = 1;

	Netracker::tracked_network *meta = ng->FetchNetwork();

	if (meta == NULL)
		return rofft;

	if (net == NULL) {
		net = meta;
		usenet = 0;
	}

	for (unsigned c = 0; c < display_bcols.size(); c++) {
		bssid_columns b = display_bcols[c];

		if (b == bcol_decay) {
			char d;
			int to;

			to = time(0) - net->last_time;

			if (to < 3)
				d = '!';
			else if (to < 5)
				d = '.';
			else
				d = ' ';

			snprintf(rline + rofft, max - rofft, "%c", d);
			rofft += 1;
		} else if (b == bcol_name) {
			string name;

			if (usenet)
				name = ng->GetName(net);
			else
				name = ng->GetName(NULL);

			snprintf(rline + rofft, max - rofft, "%-20.20s", 
					 name.c_str());
			rofft += 20;
		} else if (b == bcol_shortname) {
			string name;

			if (usenet)
				name = ng->GetName(net);
			else
				name = ng->GetName(NULL);
			snprintf(rline + rofft, max - rofft, "%-10.10s", 
					 name.c_str());
			rofft += 10;
		} else if (b == bcol_nettype) {
			char d;

			if (net->type == network_ap)
				d = 'A';
			else if (net->type == network_adhoc)
				d = 'H';
			else if (net->type == network_probe)
				d = 'P';
			else if (net->type == network_turbocell)
				d = 'T';
			else if (net->type == network_data)
				d = 'D';
			else if (net->type == network_mixed)
				d = 'M';
			else
				d = '?';

			snprintf(rline + rofft, max - rofft, "%c", d);
			rofft += 1;
		} else if (b == bcol_crypt) {
			char d;

			if (net->lastssid == NULL) {
				d = '?';
			} else {
				if (net->lastssid->cryptset == crypt_wep)
					d = 'W';
				else if (net->lastssid->cryptset)
					d = 'O';
				else
					d = 'N';
			}

			snprintf(rline + rofft, max - rofft, "%c", d);
			rofft += 1;
		} else if (b == bcol_channel) {
			if (net->channel == 0) {
				snprintf(rline + rofft, max - rofft, "%3s", "---");
			} else {
				snprintf(rline + rofft, max - rofft, "%3d", net->channel);
			}
			rofft += 3;
		} else if (b == bcol_freq_mhz) {
			unsigned int maxmhz = 0, maxval = 0;

			for (map<unsigned int, unsigned int>::const_iterator fmi = net->freq_mhz_map.begin(); fmi != net->freq_mhz_map.end(); ++fmi) {
				if (fmi->second > maxval)
					maxmhz = fmi->first;
			}

			if (maxmhz == 0) {
				snprintf(rline + rofft, max - rofft, "%4s", "----");
			} else {
				snprintf(rline + rofft, max - rofft, "%4d", maxmhz);
			}
			rofft += 4;
		} else if (b == bcol_packdata) {
			snprintf(rline + rofft, max - rofft, "%5d", net->data_packets);
			rofft += 5;
		} else if (b == bcol_packllc) {
			snprintf(rline + rofft, max - rofft, "%5d", net->llc_packets);
			rofft += 5;
		} else if (b == bcol_packcrypt) {
			snprintf(rline + rofft, max - rofft, "%5d", net->crypt_packets);
			rofft += 5;
		} else if (b == bcol_bssid) {
			snprintf(rline + rofft, max - rofft, "%-17s", 
					 net->bssid.Mac2String().c_str());
			rofft += 17;
		} else if (b == bcol_packets) {
			snprintf(rline + rofft, max - rofft, "%5d",
					 net->llc_packets + net->data_packets);
			rofft += 5;
		} else if (b == bcol_beaconperc) {
			if (net->lastssid == NULL ||
				(net->lastssid != NULL && (net->lastssid->beaconrate == 0)) ||
				time(0) - net->last_time > 5) {
				snprintf(rline + rofft, max - rofft, "%-4s", " ---");
			} else {
				// Kluge the beacons down to the rate, revisit this later if we
				// want to add IDS sensitivity based on an over-abundance of 
				// beacons or something
				if (net->lastssid->beacons > net->lastssid->beaconrate)
					net->lastssid->beacons = net->lastssid->beaconrate;
				snprintf(rline + rofft, max - rofft, "%3.0f%%",
						 ((double) net->lastssid->beacons / 
						  (double) net->lastssid->beaconrate) * 100);
			}
			rofft += 4;
		} else if (b == bcol_clients) {
			// TODO - handle clients
			snprintf(rline + rofft, max - rofft, "%4d", 0);
			rofft += 4;
		} else if (b == bcol_datasize) {
			char dt = ' ';
			long int ds = 0;

			if (net->datasize < 1024) {
				ds = net->datasize;
				dt = 'B';
			} else if (net->datasize < (1024*1024)) {
				ds = net->datasize / 1024;
				dt = 'K';
			} else {
				ds = net->datasize / 1024 / 1024;
				dt = 'M';
			}

			snprintf(rline + rofft, max - rofft, "%4ld%c", ds, dt);
			rofft += 5;
		} else if (b == bcol_signalbar) {
			// TODO - signalbar
			snprintf(rline + rofft, max - rofft, "TODO    ");
			rofft += 8;
		} else if (b == bcol_signal_dbm) {
			if (time(0) - net->last_time > 5) {
				snprintf(rline + rofft, max - rofft, "---");
			} else {
				snprintf(rline + rofft, max - rofft, "%3d", 
						 net->snrdata.last_signal_dbm);
			}
			rofft += 3;
		} else if (b == bcol_signal_rssi) {
			if (time(0) - net->last_time > 5) {
				snprintf(rline + rofft, max - rofft, "---");
			} else {
				snprintf(rline + rofft, max - rofft, "%3d", 
						 net->snrdata.last_signal_rssi);
			}
			rofft += 3;
		} else {
			continue;
		}

		if (rofft < (max - 1)) {
			// Update the endline conditions
			rline[rofft++] = ' ';
			rline[rofft] = '\0';
		} else {
			break;
		}
	} // column loop

	return rofft;
}

void Kis_Netlist::DrawComponent() {
	if (visible == 0)
		return;

	parent_panel->InitColorPref("panel_textdis_color", "grey,black");
	parent_panel->ColorFromPref(color_inactive, "panel_textdis_color");

	parent_panel->InitColorPref("netlist_normal_color", "green,black");
	parent_panel->ColorFromPref(color_map[kis_netlist_color_normal], 
								"netlist_normal_color");
	parent_panel->InitColorPref("netlist_crypt_color", "yellow,black");
	parent_panel->ColorFromPref(color_map[kis_netlist_color_crypt], 
								"netlist_crypt_color");
	parent_panel->InitColorPref("netlist_group_color", "blue,black");
	parent_panel->ColorFromPref(color_map[kis_netlist_color_group], 
								"netlist_group_color");
	parent_panel->InitColorPref("netlist_factory_color", "red,black");
	parent_panel->ColorFromPref(color_map[kis_netlist_color_factory], 
								"netlist_factory_color");
	parent_panel->InitColorPref("netlist_header_color", "blue,black");
	parent_panel->ColorFromPref(color_map[kis_netlist_color_header], 
								"netlist_header_color");

	// This is the largest we should ever expect a window to be wide, so
	// we'll consider it a reasonable static line size
	char rline[1024];
	int rofft = 0;

	// Used to track number of lines needed for expanded info
	int nlines = 0;
	int recovered_lines = 0;
	int redraw = 0;

	time_t now = time(0);

	// Printed line and a temp string to hold memory, used for cache
	// aliasing
	char *pline;
	string pt;

	if ((sort_mode != netsort_autofit && sort_mode != netsort_recent) &&
		(selected_line < first_line || selected_line > (int) display_vec.size()))
		selected_line = first_line;

	// Get any updated columns
	UpdateBColPrefs();
	UpdateBExtPrefs();

	// Column headers
	if (colhdr_cache == "") {
		// Space for the group indicator
		rofft = 1;
		rline[0] = ' ';

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
			} else if (b == bcol_freq_mhz) {
				snprintf(rline + rofft, 1024 - rofft, "Freq");
				rofft += 4;
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
			} else if (b == bcol_signalbar) {
				snprintf(rline + rofft, 1024 - rofft, "Signal  ");
				rofft += 8;
			} else if (b == bcol_beaconperc) {
				snprintf(rline + rofft, 1024 - rofft, "Bprc");
				rofft += 4;
			} else if (b == bcol_signal_dbm) {
				snprintf(rline + rofft, 1024 - rofft, "Sig");
				rofft += 3;
			} else if (b == bcol_signal_rssi) {
				snprintf(rline + rofft, 1024 - rofft, "Sig");
				rofft += 3;
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

	if (active)
		wattrset(window, color_map[kis_netlist_color_header]);

	Kis_Panel_Specialtext::Mvwaddnstr(window, sy, sx, 
									  "\004u" + pcache + "\004U", 
									  ex - sx);

	if (display_vec.size() == 0) {
		if (active)
			wattrset(window, color_map[kis_netlist_color_normal]);
		vector<KisNetClient *> *clivec = kpinterface->FetchNetClientVecPtr();
		int con = 0;

		for (unsigned int c = 0; c < clivec->size(); c++) {
			if ((*clivec)[c]->Valid()) {
				con = 1;
				break;
			}
		}

		if (con == 0) {
			mvwaddnstr(window, sy + 2, sx, 
					   "[ --- Not connected to a Kismet server --- ]", lx);
		} else {
			mvwaddnstr(window, sy + 2, sx, "[ --- No networks seen --- ]", 
					   ex - sx);
		}
		return;
	}


	if (sort_mode == netsort_autofit)
		first_line = 0;

	// For as many lines as we can fit
	int dpos = 1;
	for (unsigned int x = first_line; x < display_vec.size() && 
		 dpos <= viewable_lines; x++) {
		Kis_Display_NetGroup *ng = display_vec[x];
		Netracker::tracked_network *meta = ng->FetchNetwork();
		int color = -1;

		nlines = 0;

		// Recompute the output line if the display for that network is dirty
		// or if the network has changed recently enough.  No sense caching whats
		// going to keep thrashing every update
		if (meta != NULL && (ng->DispDirty() || 
			((now - meta->last_time) < 10))) {
			// Space for the group indicator
			rofft = 1;
			if (ng->FetchNumNetworks() > 1) {
				if (ng->GetExpanded()) {
					rline[0] = '-';
				} else {
					rline[0] = '+';
				}

				color = kis_netlist_color_group;
			} else {
				rline[0] = ' ';
			}

			rofft = PrintNetworkLine(ng, NULL, rofft, rline, 1024);

			// Fill to the end if we need to for highlighting
			if (rofft < (ex - sx) && ((ex - sx) - rofft) < 1024) {
				memset(rline + rofft, ' ', (ex - sx) - rofft);
				rline[(ex - sx)] = '\0';
			}

			if (color < 0 && meta->lastssid != NULL && 
				meta->lastssid->cryptset != 0)
				color = kis_netlist_color_crypt;

			ng->SetColor(color);
			ng->SetLineCache(rline);
			pline = rline;
		} else {
			// Pull the cached line
			pt = ng->GetLineCache();
			pline = (char *) pt.c_str();
			color = ng->GetColor();
		}

		nlines++;

		if (color <= 0)
			color = kis_netlist_color_normal;

		if (active)
			wattrset(window, color_map[color]);

		// Draw the line
		if (selected_line == (int) x && sort_mode != netsort_autofit && active)
			wattron(window, WA_REVERSE);

		// Kis_Panel_Specialtext::Mvwaddnstr(window, sy + dpos, sx, pline, ex);
		// We don't use our specialtext here since we don't want something that
		// snuck into the SSID to affect the printing
		mvwaddnstr(window, sy + dpos, sx, pline, ex - sx);
		dpos++;

		// Draw the expanded info for the network
		if (selected_line == (int) x && sort_mode != netsort_autofit &&
			show_ext_info && ng->GetExpanded() == 0) {
			// Cached print lines (also a direct shortcut into the cache
			// storage system)
			vector<string> *pevcache;
			// Reset the offset we're printing into on rline
			rofft = 0;

			pevcache = ng->GetDetCache();

			// If we're dirty, we don't have details cached, or it's been
			// w/in 10 seconds, we recalc the details
			if (ng->DispDirty() || 
				(meta != NULL && (now - meta->last_time) < 10) ||
				pevcache->size() == 0) {

				// Directly manipulate the cache ptr, probably bad
				pevcache->clear();

				rofft = 1;
				rline[0] = ' ';

				// Offset for decay if we have it
				if (display_bcols[0] == bcol_decay) {
					snprintf(rline + rofft, 1024 - rofft, "  ");
					rofft += 2;
				}

				for (unsigned int c = 0; c < display_bexts.size(); c++) {
					bssid_extras e = display_bexts[c];

					if (e == bext_lastseen) {
						snprintf(rline + rofft, 1024 - rofft, "Last seen: %.15s",
								 ctime((const time_t *) &(meta->last_time)) + 4);
						rofft += 26;
					} else if (e == bext_crypt) {
						snprintf(rline + rofft, 1024 - rofft, "Crypt:");
						rofft += 6;
					
						if (meta->lastssid == NULL) {
							snprintf(rline + rofft, 1024 - rofft, " Unknown");
							rofft += 8;
						} else {
							if ((meta->lastssid->cryptset == 0)) {
								snprintf(rline + rofft, 1024 - rofft, " None");
								rofft += 5;
							}
							if ((meta->lastssid->cryptset == crypt_wep)) {
								snprintf(rline + rofft, 1024 - rofft, " WEP");
								rofft += 4;
							} 
							if ((meta->lastssid->cryptset & crypt_layer3)) {
								snprintf(rline + rofft, 1024 - rofft, " L3");
								rofft += 3;
							} 
							if ((meta->lastssid->cryptset & crypt_wep40)) {
								snprintf(rline + rofft, 1024 - rofft, " WEP40");
								rofft += 6;
							} 
							if ((meta->lastssid->cryptset & crypt_wep104)) {
								snprintf(rline + rofft, 1024 - rofft, " WEP104");
								rofft += 7;
							} 
							if ((meta->lastssid->cryptset & crypt_tkip)) {
								snprintf(rline + rofft, 1024 - rofft, " TKIP");
								rofft += 5;
							} 
							if ((meta->lastssid->cryptset & crypt_wpa)) {
								snprintf(rline + rofft, 1024 - rofft, " WPA");
								rofft += 4;
							} 
							if ((meta->lastssid->cryptset & crypt_psk)) {
								snprintf(rline + rofft, 1024 - rofft, " PSK");
								rofft += 4;
							} 
							if ((meta->lastssid->cryptset & crypt_aes_ocb)) {
								snprintf(rline + rofft, 1024 - rofft, " AESOCB");
								rofft += 7;
							} 
							if ((meta->lastssid->cryptset & crypt_aes_ccm)) {
								snprintf(rline + rofft, 1024 - rofft, " AESCCM");
								rofft += 7;
							} 
							if ((meta->lastssid->cryptset & crypt_leap)) {
								snprintf(rline + rofft, 1024 - rofft, " LEAP");
								rofft += 5;
							} 
							if ((meta->lastssid->cryptset & crypt_ttls)) {
								snprintf(rline + rofft, 1024 - rofft, " TTLS");
								rofft += 5;
							} 
							if ((meta->lastssid->cryptset & crypt_tls)) {
								snprintf(rline + rofft, 1024 - rofft, " TLS");
								rofft += 4;
							} 
							if ((meta->lastssid->cryptset & crypt_peap)) {
								snprintf(rline + rofft, 1024 - rofft, " PEAP");
								rofft += 5;
							} 
							if ((meta->lastssid->cryptset & crypt_isakmp)) {
								snprintf(rline + rofft, 1024 - rofft, " ISAKMP");
								rofft += 7;
							} 
							if ((meta->lastssid->cryptset & crypt_pptp)) {
								snprintf(rline + rofft, 1024 - rofft, " PPTP");
								rofft += 5;
							}
							if (meta->lastssid->cryptset & crypt_fortress) {
								snprintf(rline + rofft, 1024 - rofft, " Fortress");
								rofft += 5;
							}
							if (meta->lastssid->cryptset & crypt_keyguard) {
								snprintf(rline + rofft, 1024 - rofft, " Keyguard");
								rofft += 5;
							}
						} 
					} else if (e == bext_bssid) {
						snprintf(rline + rofft, 1024 - rofft, "BSSID: %s",
								 meta->bssid.Mac2String().c_str());
						rofft += 24;
					} else if (e == bext_manuf) {
						// TODO - manuf stuff
						continue;
					} else if (e == bext_model) {
						// TODO - manuf stuff
						continue;
					} else {
						continue;
					}

					if (rofft < 1023) {
						// Update the endline conditions
						rline[rofft++] = ' ';
						rline[rofft] = '\0';
					} else {
						break;
					}
				}

				// Fill to the end if we need to for highlighting
				if (rofft < (ex - sx) && ((ex - sx) - rofft) < 1024) {
					memset(rline + rofft, ' ', (ex - sx) - rofft);
					rline[(ex - sx)] = '\0';
				}

				pevcache->push_back(rline);
			}

			/* Handle scrolling down if we're at the end.  Yeah, this is 
			 * obnoxious. */
			

			for (unsigned int d = 0; d < pevcache->size(); d++) {
				nlines++;

				// If we need to get more space...
				if (dpos >= viewable_lines && (int) x != first_line) {
					// We're going to have to redraw this whole thing anyhow
					redraw = 1;

					// If we've recovered enough lines, we just take some away.
					// Don't try to take away from the first one - if it doesn't
					// fit, TFB.
					if (recovered_lines > 0) {
						recovered_lines--;
					} else {
						// Otherwise we need to start sliding down the list to
						// recover some lines.  selected is the raw # in dv,
						// not the visual offset, so we don't have to play any
						// games there.
						recovered_lines += display_vec[first_line]->GetNLines();
						first_line++;
					}
				}

				// Only draw if we don't need to redraw everything, but always
				// increment the dpos so we know how many lines we need to recover
				if (redraw == 0 && dpos < viewable_lines)
					mvwaddnstr(window, sy + dpos, sx, (*pevcache)[d].c_str(), 
							   ex - sx);
				dpos++;
			}

		} else if (sort_mode != netsort_autofit && ng->GetExpanded()) {
			vector<string> *gevcache;

			rofft = 0;

			gevcache = ng->GetGrpCache();

			if (ng->DispDirty() || 
				(meta != NULL && (now - meta->last_time) < 10) ||
				gevcache->size() == 0) {
				vector<Netracker::tracked_network *> *nv = ng->FetchNetworkVec();

				// Directly manipulate the cache ptr, probably bad
				gevcache->clear();

				for (unsigned int n = 0; n < nv->size(); n++) {
					rofft = 2;
					rline[0] = ' ';
					rline[1] = ' ';

					rofft = PrintNetworkLine(ng, (*nv)[n], rofft, rline, 1024);

					// Fill to the end if we need to for highlighting
					if (rofft < (ex - sx) && ((ex - sx) - rofft) < 1024) {
						memset(rline + rofft, ' ', (ex - sx) - rofft);
						rline[(ex - sx)] = '\0';
					}

					gevcache->push_back(rline);
				}
			}

			for (unsigned int d = 0; d < gevcache->size(); d++) {
				nlines++;

				if (dpos >= viewable_lines && (int) x != first_line) {
					redraw = 1;
					if (recovered_lines > 0) {
						recovered_lines--;
					} else {
						recovered_lines += display_vec[first_line]->GetNLines();
						first_line++;
					}
				}

				if (redraw == 0 && dpos < viewable_lines)
					mvwaddnstr(window, sy + dpos, sx, (*gevcache)[d].c_str(), 
							   ex - sx);
				dpos++;
			}

		}

		if (selected_line == (int) x && sort_mode != netsort_autofit && active)
			wattroff(window, WA_REVERSE);

		ng->SetNLines(nlines);

		last_line = x;

		// Set it no longer dirty (we've cached everything along the way
		// so this is safe to do here regardless)
		ng->SetDispDirty(0);
	} // Netlist 

	// Call ourselves again and redraw if we have to.  Only loop on 1, -1 used
	// for first-line overflow
	if (redraw == 1) {
		DrawComponent();
	}
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

	if (in_key == KEY_DOWN || in_key == '+') {
		if (selected_line < first_line || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}

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
	} else if (in_key == KEY_UP || in_key == '-') {
		if (selected_line < first_line || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}

		// If we're at the top and we can go further, slide the selection
		// and the first line UP
		if (selected_line == first_line && first_line > 0) {
			selected_line--;
			first_line--;
		} else if (selected_line != first_line) {
			// Just slide up the selection
			selected_line--;
		}
	} else if (in_key == KEY_PPAGE) {
		if (selected_line < 0 || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}
	
		first_line = kismax(0, first_line - viewable_lines);
		selected_line = first_line;
	} else if (in_key == KEY_NPAGE) {
		if (selected_line < 0 || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}

		first_line = kismin((int) display_vec.size() - 1, 
							first_line + viewable_lines);
		selected_line = first_line;
	} else if (in_key == ' ') {
		if (selected_line < 0 || selected_line > last_line ||
			selected_line >= (int) display_vec.size()) {
			return 0;
		}

		Kis_Display_NetGroup *ng = display_vec[selected_line];

		if (ng->FetchNumNetworks() <= 1)
			return 0;

		ng->SetExpanded(!ng->GetExpanded());
	} else if (in_key == '\n' || in_key == KEY_ENTER) {
		if (cb_activate != NULL) 
			(*cb_activate)(this, 1, cb_activate_aux, globalreg);
	}

	return 0;
}

Kis_Display_NetGroup *Kis_Netlist::FetchSelectedNetgroup() {
	if (selected_line < 0 || selected_line >= (int) display_vec.size())
		return NULL;

	return display_vec[selected_line];
}

const char *info_bits_details[][2] = {
	{ "elapsed", "Elapsed time" },
	{ "numnets", "Number of networks" },
	{ "numpkts", "Number of packets" },
	{ "pktrate", "Packet rate" },
	{ "numfilter", "Number of filtered packets" },
	{ "sources", "Packet sources" },
	{ NULL, NULL}
};

// Callbacks
void KisInfobits_Configured(CLICONF_CB_PARMS) {
	((Kis_Info_Bits *) auxptr)->NetClientConfigure(kcli, recon);
}

void KisInfobits_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Kis_Info_Bits *) auxptr)->NetClientAdd(netcli, add);
}

void KisInfobits_INFO(CLIPROTO_CB_PARMS) {
	((Kis_Info_Bits *) auxptr)->Proto_INFO(globalreg, proto_string,
										   proto_parsed, srccli, auxptr);
}

void KisInfobits_TIME(CLIPROTO_CB_PARMS) {
	((Kis_Info_Bits *) auxptr)->Proto_TIME(globalreg, proto_string, 
										   proto_parsed, srccli, auxptr);
}

Kis_Info_Bits::Kis_Info_Bits(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Packbox(in_globalreg, in_panel) {
	kpinterface = in_panel->FetchPanelInterface();

	num_networks = num_packets = packet_rate = filtered_packets = 0;

	addref = kpinterface->Add_NetCli_AddCli_CB(KisInfobits_AddCli, (void *) this);

	// Set up our inherited vbox attributes
	SetPackV();
	SetHomogenous(0);
	SetSpacing(1);

	info_color_normal = -1;

	title = new Kis_Free_Text(globalreg, parent_panel);
	title->SetText("\004uKismet\004U");
	title->SetAlignment(1);
	title->Show();
	Pack_End(title, 0, 0);

	asm_time_num = TokenNullJoin(&asm_time_fields, time_fields);
	asm_info_num = TokenNullJoin(&asm_info_fields, info_fields);

	UpdatePrefs();
}

Kis_Info_Bits::~Kis_Info_Bits() {
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(KisInfobits_Configured);
	kpinterface->Remove_AllNetcli_ProtoHandler("TIME", KisInfobits_TIME, this);
	kpinterface->Remove_AllNetcli_ProtoHandler("INFO", KisInfobits_INFO, this);
}

int Kis_Info_Bits::UpdatePrefs() {
	string ibits;

	if ((ibits = kpinterface->prefs.FetchOpt("NETINFO_ITEMS")) == "") {
		ibits = "elapsed,numnets,numpkts,pktrate,numfilter";
		kpinterface->prefs.SetOpt("NETINFO_ITEMS", ibits, 1);
	}

	if (kpinterface->prefs.FetchOptDirty("NETINFO_ITEMS") == 0) {
		return 0;
	}

	kpinterface->prefs.SetOptDirty("NETINFO_ITEMS", 0);

	infovec.clear();

	// Unpack the vbox and remove the widgets
	for (map<int, Kis_Free_Text *>::iterator x = infowidgets.begin();
		 x != infowidgets.end(); ++x) {
		Pack_Remove(x->second);
		delete(x->second);
	}
	infowidgets.clear();

	vector<string> toks = StrTokenize(ibits, ",");
	string t;

	int optnum;
	Kis_Free_Text *ft;

	for (unsigned int x = 0; x < toks.size(); x++) {
		t = StrLower(toks[x]);

		if (t == "elapsed") {
			optnum = info_elapsed;
			infovec.push_back(info_elapsed);
		} else if (t == "numnets") {
			optnum = info_numnets;
		} else if (t == "numpkts") {
			optnum = info_numpkts;
		} else if (t == "pktrate") {
			optnum = info_pktrate;
		} else if (t == "numfilter") {
			optnum = info_filtered;
		} else {
			_MSG("Unknown info panel item '" + t + "', skipping.",
				 MSGFLAG_INFO);
			continue;
		}

		infovec.push_back(optnum);
		ft = new Kis_Free_Text(globalreg, parent_panel);
		ft->Show();
		ft->SetAlignment(1);
		Pack_End(ft, 0, 0);
		infowidgets[optnum] = ft;
	}

	return 1;
}

void Kis_Info_Bits::DrawComponent() {
	UpdatePrefs();

	if (kpinterface->FetchFirstNetclient() == NULL ||
		(kpinterface->FetchFirstNetclient() != NULL &&
		 kpinterface->FetchFirstNetclient()->Valid() <= 0)) {
		vector<string> titletext = title->GetText();
		if (titletext.size() == 1) {
			titletext.push_back("\004rNot\004R");
			titletext.push_back("\004rConnected\004R");
			title->SetText(titletext);
		}
	}

	parent_panel->InitColorPref("info_normal_color", "white,black");
	parent_panel->ColorFromPref(info_color_normal, "info_normal_color");

	wattrset(window, info_color_normal);

	Kis_Panel_Packbox::DrawComponent();
}

void Kis_Info_Bits::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	first_time = in_cli->FetchServerStarttime();
	
	title->SetText("\004u" + in_cli->FetchServerName() + "\004U");

	if (in_recon)
		return;

	if (in_cli->RegisterProtoHandler("TIME", asm_time_fields,
									 KisInfobits_TIME, this) < 0) {
		_MSG("Could not register TIME protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}

	if (in_cli->RegisterProtoHandler("INFO", asm_info_fields,
									 KisInfobits_INFO, this) < 0) {
		_MSG("Could not register INFO protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
}

void Kis_Info_Bits::NetClientAdd(KisNetClient *in_cli, int add) {
	if (add == 0)
		return;

	in_cli->AddConfCallback(KisInfobits_Configured, 1, this);
}

void Kis_Info_Bits::Proto_TIME(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) asm_time_num) {
		return;
	}

	unsigned int ttime;
	if (sscanf((*proto_parsed)[0].word.c_str(), "%u", &ttime) != 1) {
		return;
	}

	last_time = ttime;

	if (infowidgets.find(info_elapsed) != infowidgets.end()) {
		vector<string> it;
		char t[20];
		time_t el = last_time - first_time;

		it.push_back("\004bElapsed\004B");
		snprintf(t, 20, "%02d:%02d.%02d", 
				 (int) (el / 60) / 60,
				 (int) (el / 60) % 60,
				 (int) (el % 60));
		it.push_back(t);

		infowidgets[info_elapsed]->SetText(it);
	}
}

void Kis_Info_Bits::Proto_INFO(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) asm_info_num) {
		return;
	}

	int tint;
	int fnum = 0;

	vector<string> it(2);
	char n[20];

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}
	num_networks = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}
	num_packets = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}
	packet_rate = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}
	filtered_packets = tint;

	if (infowidgets.find(info_numnets) != infowidgets.end()) {
		it[0] = "\004bNetworks\004B";
		snprintf(n, 20, "%d", num_networks);
		it[1] = n;
		infowidgets[info_numnets]->SetText(it);
	}

	if (infowidgets.find(info_numpkts) != infowidgets.end()) {
		it[0] = "\004bPackets\004B";
		snprintf(n, 20, "%d", num_packets);
		it[1] = n;
		infowidgets[info_numpkts]->SetText(it);
	}

	if (infowidgets.find(info_pktrate) != infowidgets.end()) {
		it[0] = "\004bPkt/Sec\004B";
		snprintf(n, 20, "%d", packet_rate);
		it[1] = n;
		infowidgets[info_pktrate]->SetText(it);
	}

	if (infowidgets.find(info_filtered) != infowidgets.end()) {
		it[0] = "\004bFiltered\004B";
		snprintf(n, 20, "%d", filtered_packets);
		it[1] = n;
		infowidgets[info_filtered]->SetText(it);
	}
}

#endif // panel

