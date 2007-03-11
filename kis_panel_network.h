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

// What we expect from the client
#define KCLI_BSSID_FIELDS	"bssid,type,llcpackets,datapackets,cryptpackets," \
	"channel,firsttime,lasttime,atype,rangeip,netmaskip,gatewayip,gpsfixed," \
	"minlat,minlon,minalt,minspd,maxlat,maxlon,maxalt,maxspd,signal,noise," \
	"minsignal,minnoise,maxsignal,maxnoise,bestlat,bestlon,bestalt,agglat," \
	"agglon,aggalt,aggpoints,datasize,turbocellnid,turbocellmode,turbocellsat," \
	"carrierset,maxseenrate,encodingset,decrypted,dupeivpackets,bsstimestamp," \
	"cdpdevice,cdpport,fragments,retries,newpackets"
#define KCLI_BSSID_NUMFIELDS	49

#define KCLI_SSID_FIELDS	"mac,checksum,type,ssid,beaconinfo,cryptset," \
	"cloaked,firsttime,lasttime,maxrate,beaconrate,packets"
#define KCLI_SSID_NUMFIELDS		12

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

	// Let us know a network has been dirtied
	void DirtyNetwork(Netracker::tracked_network *in_net);

	int Dirty() { return dirty; }

	// Display dirty variables, set after an update
	int DispDirty() { return dispdirty; }
	string GetLineCache() { return linecache; }
	void SetLineCache(string ic) { linecache = ic; dispdirty = 0; }

	// Group name
	string GetName();
	void SetName(string in_name);

protected:
	// Do we need to update?
	int dirty; 

	// Name
	string name;

	// Cached display lines
	int dispdirty;
	string linecache;

	// Do we have a local meta network? (ie, do we need to destroy it on our
	// way our, take special care of it, etc)
	int local_metanet;

	// Pointer to the network we return, could be allocated locally, or it could
	// be a pointer to a network from somewhere else
	Netracker::tracked_network *metanet;

	// Vector of networks which compose the metanet.  THESE SHOULD NEVER BE FREED,
	// BECAUSE THEY MAY BE REFERENCED ELSEWHERE.
	vector<Netracker::tracked_network *> meta_vec;
};


// Smart drawing component which bundles up the networks and displays them
// in a fast-sort method which hopefully uses less CPU
class Kis_Netlist : public Kis_Panel_Component {
public:
	Kis_Netlist() {
		fprintf(stderr, "FATAL OOPS: Kis_Netlist() called w/out globalreg\n");
		exit(1);
	}
	Kis_Netlist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Netlist();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);

	virtual void SetPosition(int isx, int isy, int iex, int iey);

	// Set the sort mode
	void SetSortMode(int in_sortmode);

	// Network callback
	void NetClientConfigure(KisNetClient *in_cli, int in_recon);

	// Added a client in the panel interface
	void NetClientAdd(KisNetClient *in_cli, int add);

	// Kismet protocol parsers
	void Proto_BSSID(CLIPROTO_CB_PARMS);
	void Proto_SSID(CLIPROTO_CB_PARMS);

	// Trigger a sort and redraw update
	void UpdateTrigger(void);

protected:
	// Columns we accept
	enum bssid_columns {
		bcol_decay, bcol_name, bcol_shortname, bcol_nettype,
		bcol_crypt, bcol_channel, bcol_packdata, bcol_packllc, bcol_packcrypt,
		bcol_bssid, bcol_packets, bcol_clients, bcol_datasize, bcol_signalbar
	};

	// Extra display options per-line
	enum bssid_extras {
		bext_lastseen, bext_crypt, bext_ip, bext_manuf, bext_model
	};

	// Addclient hook reference
	int addref;
	
	// Event reference for update trigger
	int updateref;

	// Interface
	KisPanelInterface *kpinterface;

	// Sorting
	int sortmode;

	// Drawing offsets into the display vector & other drawing trackers
	int viewable_lines;
	int viewable_cols;

	int first_line, last_line, selected_line;
	// Horizontal position
	int hpos;

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

	// Assembled groups - GID to Group object
	macmap<Kis_Display_NetGroup *> netgroup_asm_map;

	// Defined groups, BSSID to GID mapping
	macmap<mac_addr> netgroup_stored_map;

	// Columns we display
	vector<bssid_columns> display_bcols;
	// Extras we display
	vector<bssid_extras> display_bexts;

	// Parse the bssid columns preferences
	void UpdateBColPrefs();
	// Parse the bssid extras
	void UpdateBExtPrefs();

	// Cached column headers
	string colhdr_cache;
};

#endif // panel
#endif // header

