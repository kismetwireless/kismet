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

#ifndef __KIS_PANEL_NETWORK_H__
#define __KIS_PANEL_NETWORK_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "netracker.h"
#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"
#include "kis_panel_preferences.h"

// Core network display list
//
// Spun off from the main widgets files due to its size and complexity, I felt
// like being organized for once.  This also minimally reduces weird dependency
// thrash.
//
// This is the primary logic of the old kismet frontend, moved into a modular
// widget.  
//
// This widget (like others) will tunnel all the way to the main interface
// class and then configure callbacks for all configured clients to 
// set up the BSSID protocols.  From then on, BSSID updates bypass the
// rest of the client system and come directly to the widget for processing.
//
// This widget attempts to make use of several methods of smartly sorting
// the data during mod and insert, and only parsing as much of the incoming
// data is necessary to do its job.  The primary goal is to minimize or
// eliminate the massive CPU loads of hundreds or thousands of networks,
// since the bulk of them will not be updating.  There is no reason to sort
// or recalculate networks which are unchanging.

// TODO - add SSID handling and group naming
class Kis_Display_NetGroup {
public:
	Kis_Display_NetGroup();
	Kis_Display_NetGroup(Netracker::tracked_network *in_net);
	~Kis_Display_NetGroup();

	// Return a network suitable for display, which could be a single network
	// or a virtual network aggregated
	Netracker::tracked_network *FetchNetwork();

	// Update the group if there are any dirty networks
	void Update();

	// Add a network to the group
	void AddNetwork(Netracker::tracked_network *in_net);

	// Remove a network.  Not efficient, so try not to do this too often.
	void DelNetwork(Netracker::tracked_network *in_net);

	// Get the number of networks
	int FetchNumNetworks() { return meta_vec.size(); }

	// Get the raw network vec
	vector<Netracker::tracked_network *> *FetchNetworkVec() { return &meta_vec; }

	// Let us know a network has been dirtied
	void DirtyNetwork(Netracker::tracked_network *in_net);

	int Dirty() { return dirty; }

	// Display dirty variables, set after an update
	int DispDirty() { return dispdirty; }
	void SetDispDirty(int dd) { dispdirty = dd; }

	int GetColor() { return color; }
	void SetColor(int in_c) { color = in_c; }

	// Cache manipulation, for the header line and sublines.
	// Details cache is for cached expanded details lines
	// Grpcache is cached expanded details
	string GetLineCache() { return linecache; }
	void SetLineCache(string ic) { linecache = ic; }
	vector<string> *GetDetCache() { return &detcache; }
	void SetDetCache(vector<string>& is) { detcache = is; }
	vector<string> *GetGrpCache() { return &grpcache; }
	void SetGrpCache(vector<string>& is) { grpcache = is; }

	// Group name
	string GetName();
	// Hack to get a network name the same way
	string GetName(Netracker::tracked_network *net);
	// Set the group name
	void SetName(string in_name);

	// Are we expanded in the view?
	int GetExpanded() { return expanded; }
	void SetExpanded(int e) { if (e != expanded) ClearSetDirty(); expanded = e; }

	// Number of lines used in the display, used to recalculate for scrolling
	void SetNLines(int nl) { nline = nl; }
	int GetNLines() { return nline; }

protected:
	// Do we need to update?
	int dirty; 

	// Name
	string name;

	// Color
	int color;

	// Cached display lines
	int dispdirty;
	string linecache;
	vector<string> detcache;
	vector<string> grpcache;

	int nline;

	// Are we expanded
	int expanded;

	// Do we have a local meta network? (ie, do we need to destroy it on our
	// way our, take special care of it, etc)
	int local_metanet;

	// Pointer to the network we return, could be allocated locally, or it could
	// be a pointer to a network from somewhere else
	Netracker::tracked_network *metanet;

	// Vector of networks which compose the metanet.  THESE SHOULD NEVER BE FREED,
	// BECAUSE THEY MAY BE REFERENCED ELSEWHERE.
	vector<Netracker::tracked_network *> meta_vec;

	// Vector of tracked clients, should never be freed here because they can be
	// referenced elsewhere
	vector<Netracker::tracked_client *> client_vec;

	// Clear display data and set dirty
	void ClearSetDirty();
};


// Smart drawing component which bundles up the networks and displays them
// in a fast-sort method which hopefully uses less CPU
enum netsort_opts {
	netsort_autofit, netsort_recent, netsort_type, netsort_channel, 
	netsort_first, netsort_first_desc, netsort_last, netsort_last_desc, 
	netsort_bssid, netsort_ssid, netsort_packets, netsort_packets_desc,
	netsort_crypt, netsort_sdbm
};

/* color array positions */
#define kis_netlist_color_normal 	0
#define kis_netlist_color_crypt 	1
#define kis_netlist_color_group 	2
#define kis_netlist_color_decrypt 	3
#define kis_netlist_color_header 	4
#define kis_netlist_color_wep 		5
#define kis_netlist_color_max		6

// Network columns
enum bssid_columns {
	bcol_decay, bcol_name, bcol_shortname, bcol_nettype,
	bcol_crypt, bcol_channel, bcol_packdata, bcol_packllc, bcol_packcrypt,
	bcol_bssid, bcol_packets, bcol_clients, bcol_datasize, bcol_signalbar,
	bcol_beaconperc, bcol_signal_dbm, bcol_signal_rssi, bcol_freq_mhz,
	bcol_manuf, bcol_11dcountry, bcol_seenby, bcol_ip, bcol_iprange
};

// Do not expect this to be in numerical order with the above enum, this is
// for setting up the preferences panels, etc
extern const common_col_pref bssid_column_details[];

// Extra display options per-line
enum bssid_extras {
	bext_lastseen, bext_bssid, bext_crypt, bext_ip, bext_manuf, bext_seenby
};

extern const common_col_pref bssid_extras_details[];

class Kis_Netlist : public Kis_Panel_Component {
public:
	Kis_Netlist() {

		// Vector actually being drawn
		fprintf(stderr, "FATAL OOPS: Kis_Netlist() called w/out globalreg\n");
		exit(1);
	}
	Kis_Netlist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Netlist();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	virtual void SetPosition(int isx, int isy, int iex, int iey);

	// Network callback
	void NetClientConfigure(KisNetClient *in_cli, int in_recon);

	// Added a client in the panel interface
	void NetClientAdd(KisNetClient *in_cli, int add);

	// Filter display (vector of MAC/Mac-masks to filter, display_only == 1 for
	// only displaying networks which match the filter, 0 for only which do not
	void SetFilter(vector<mac_addr> filter, int display_only);

	// Kismet protocol parsers
	void Proto_BSSID(CLIPROTO_CB_PARMS);
	void Proto_SSID(CLIPROTO_CB_PARMS);
	void Proto_CLIENT(CLIPROTO_CB_PARMS);
	void Proto_BSSIDSRC(CLIPROTO_CB_PARMS);
	void Proto_CLISRC(CLIPROTO_CB_PARMS);
	void Proto_NETTAG(CLIPROTO_CB_PARMS);
	void Proto_CLITAG(CLIPROTO_CB_PARMS);

	// Trigger a sort and redraw update
	void UpdateTrigger(void);

	// Fetch a pointer to the currently selected group
	Kis_Display_NetGroup *FetchSelectedNetgroup();

	// Fetch a pointer to the display vector (don't change this!  bad things will
	// happen!)
	vector<Kis_Display_NetGroup *> *FetchDisplayVector() { return draw_vec; }

	// Return sort mode
	netsort_opts FetchSortMode() { return sort_mode; }

	// Network column text
	static const char *bssid_columns_text[]; 


	// Parse the bssid columns preferences
	int UpdateBColPrefs();
	// Parse the bssid extras
	int UpdateBExtPrefs();
	// Parse the sort type
	int UpdateSortPrefs();

protected:
	int color_map[kis_netlist_color_max];
	int color_inactive;

	time_t bcol_pref_t, bext_pref_t, sort_pref_t;
	time_t last_mouse_click;

	// Sort modes
	// Sort type
	netsort_opts sort_mode;

	// Addclient hook reference
	int addref;
	
	// Event reference for update trigger
	int updateref;

	// Interface
	KisPanelInterface *kpinterface;

	// Drawing offsets into the display vector & other drawing trackers
	int viewable_lines;
	int viewable_cols;

	int first_line, last_line, selected_line;
	// Horizontal position
	int hpos;

	// Assembled protocol fields
	string asm_ssid_fields, asm_bssid_fields, asm_client_fields,
		   asm_bssidsrc_fields, asm_clisrc_fields;
	int asm_ssid_num, asm_bssid_num, asm_client_num, asm_bssidsrc_num,
		asm_clisrc_num;

	// We try to optimize our memory usage so that there is only
	// one copy of the TCP data network, as well as only one copy of
	// the display group network.
	//
	// Sorting is optimized to only occur on a full draw update, not during
	// reception of *BSSID stanzas.  Sorting should only occur on the visible
	// network group (or the visible network group plus or minus a few as
	// new data is added)
	//
	
	// Raw map of all BSSIDs seen so far from *BSSID sentences
	macmap<Netracker::tracked_network *> bssid_raw_map;

	// Vector of dirty networks which must be considered for re-sorting
	vector<Netracker::tracked_network *> dirty_raw_vec;
	
	// Vector of displayed network groups
	vector<Kis_Display_NetGroup *> display_vec;
	// Vector of filtered displayed network groups
	vector<Kis_Display_NetGroup *> filter_display_vec;

	// Vector actually being draw
	vector<Kis_Display_NetGroup *> *draw_vec;

	// Assembled groups - GID to Group object
	macmap<Kis_Display_NetGroup *> netgroup_asm_map;

	// Defined groups, BSSID to GID mapping
	macmap<mac_addr> netgroup_stored_map;

	// Columns we display
	vector<bssid_columns> display_bcols;
	// Extras we display
	vector<bssid_extras> display_bexts;

	// Filtering
	vector<mac_addr> filter_vec;
	int display_filter_only, filter_dirty;

	// Show extended info
	int show_ext_info;

	// Cached column headers
	string colhdr_cache;

	// Probe, adhoc, and data groups
	Kis_Display_NetGroup *probe_autogroup, *adhoc_autogroup, *data_autogroup;

	int DeleteGroup(Kis_Display_NetGroup *in_group);

	int PrintNetworkLine(Kis_Display_NetGroup *ng, Netracker::tracked_network *net,
						 int rofft, char *rline, int max);
};

enum clientsort_opts {
	clientsort_autofit, clientsort_recent, clientsort_first, 
	clientsort_first_desc, clientsort_last, clientsort_last_desc, 
	clientsort_mac, clientsort_type, clientsort_packets, 
	clientsort_packets_desc,
};

// client columns
enum client_columns {
	ccol_decay, ccol_mac, ccol_bssid, ccol_ssid,
	ccol_packdata, ccol_packllc, ccol_packcrypt,
	ccol_packets, ccol_datasize, ccol_signal_dbm, ccol_signal_rssi,
	ccol_freq_mhz, ccol_manuf, ccol_type, ccol_dhcphost, ccol_dhcpvendor,
	ccol_ip
};

/* color array positions */
#define kis_clientlist_color_normal 	0
#define kis_clientlist_color_ap			1
#define kis_clientlist_color_wireless	2
#define kis_clientlist_color_adhoc		3
#define kis_clientlist_color_header		4

// Do not expect this to be in numerical order with the above enum, this is
// for setting up the preferences panels, etc
extern const common_col_pref client_column_details[];

// Extra display options per-line
enum client_extras {
	cext_lastseen, cext_crypt, cext_ip, cext_manuf, cext_dhcphost, cext_dhcpvendor
};

extern const common_col_pref client_extras_details[];

class Kis_Clientlist : public Kis_Panel_Component {
public:
	Kis_Clientlist() {
		fprintf(stderr, "FATAL OOPS: Kis_Clientlist() called w/out globalreg\n");
		exit(1);
	}
	Kis_Clientlist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Clientlist();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	virtual void SetPosition(int isx, int isy, int iex, int iey);

	// Trigger a sort and redraw update
	void UpdateTrigger(void);

	// We want to pull a new display group from the current network
	void UpdateDNG(void);

	// We want to follow the dng every update (default: no, we don't)
	void FollowDNG(int in_follow) { followdng = in_follow; }

	// Fetch a pointer to the currently drawing group
	Kis_Display_NetGroup *FetchSelectedNetgroup();

	// Fetch a pointer to the current client
	Netracker::tracked_client *FetchSelectedClient();

	// Return sort mode
	clientsort_opts FetchSortMode() { return sort_mode; }

	static const char *client_columns_text[]; 

	struct display_client {
		Netracker::tracked_client *cli;
		string cached_line;
		vector<string> cached_details;
		int num_lines;
		int color;
	};

	// Parse the bssid columns preferences
	int UpdateCColPrefs();
	// Parse the bssid extras
	int UpdateCExtPrefs();
	// Parse the sort type
	int UpdateSortPrefs();

protected:
	int color_map[5];
	int color_inactive;

	time_t ccol_pref_t, cext_pref_t, sort_pref_t;
	time_t last_mouse_click;

	clientsort_opts sort_mode;

	// Event reference for update trigger
	int updateref;

	// Do we follow the DNG and update it continually?
	int followdng;

	// Interface
	KisPanelInterface *kpinterface;

	// Group we're displaying
	Kis_Display_NetGroup *dng;

	// Drawing offsets into the display vector & other drawing trackers
	int viewable_lines;
	int viewable_cols;

	int first_line, last_line, selected_line;
	// Horizontal position
	int hpos;

	// Vector of displayed network clients
	vector<display_client> display_vec;

	// Columns we display
	vector<client_columns> display_ccols;
	// Extras we display
	vector<client_extras> display_cexts;

	// Show extended info
	int show_ext_info;

	// Cached column headers
	string colhdr_cache;

	int PrintClientLine(Netracker::tracked_client *cli,
						 int rofft, char *rline, int max);
};

enum info_items {
	info_elapsed, info_numnets, info_numpkts, info_pktrate, info_filtered 
};

extern const char *info_bits_details[][2];

// Infobits main info pane widget is derived from a packbox - we contain our 
// own sub-widgets and pack them into ourselves, and let all the other normal
// code take care of things like spacing and such.  Plugins can then append
// after the main info block.
class Kis_Info_Bits : public Kis_Panel_Packbox {
public:
	Kis_Info_Bits() {
		fprintf(stderr, "FATAL OOPS: Kis_Info_Bits()\n");
		exit(1);
	}
	Kis_Info_Bits(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Info_Bits();

	void NetClientConfigure(KisNetClient *in_cli, int in_recon);
	void NetClientAdd(KisNetClient *in_cli, int add);
	void Proto_INFO(CLIPROTO_CB_PARMS);
	void Proto_TIME(CLIPROTO_CB_PARMS);

	void DrawComponent();

	int UpdatePrefs();

protected:
	int addref;

	KisPanelInterface *kpinterface;

	vector<int> infovec;
	map<int, Kis_Free_Text *> infowidgets;
	Kis_Free_Text *title;
	time_t first_time;
	time_t last_time;

	int num_networks;
	int num_packets;
	int packet_rate;
	int filtered_packets;

	int info_color_normal;

	string asm_time_fields, asm_info_fields;
	int asm_time_num, asm_info_num;
};

#endif // panel
#endif // header

