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

#ifndef __KIS_PANEL_BSSID_H__
#define __KIS_PANEL_BSSID_H__

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

class Kis_Netlist_Group {
public:
	Kis_Netlist_Group();
	Kis_Netlist_Group(Netracker::tracked_network *in_net);

	// Fetch the network out, could be a standard single network, could be
	// the meta-group network
	Netracker::tracked_network *FetchNetwork();

	// Merge a network into the meta-group network
	void MergeNetwork();

	// Delete a network from a meta-group network
	void DelNetwork();

	// Mark that we need to recalculate some fields
	void UpdateNetwork(Netracker::tracked_network *in_net);

protected:
	// Do we have a local meta network? (ie, do we need to destroy it on our
	// way our, take special care of it, etc)
	int local_metanet;

	// Pointer to the network we return, could be allocated locally, or it could
	// be a pointer to a network from somewhere else
	Netracker::tracked_network *metanet;
};

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
	// BSSID protocol parser
	void Proto_BSSID(CLIPROTO_CB_PARMS);

	// Sort the network list
	void ViewSortFitBSSID(Netracker::tracked_network *net);

protected:
	// Addclient hook reference
	int addref;
	// Interface
	KisPanelInterface *kpinterface;

	// Sorting
	int sortmode;

	// The map of all BSSIDs seen
	map<mac_addr, Netracker::tracked_network *> bssid_map;
	// Viewable vector
	vector<Netracker::tracked_network *> viewable_bssid;
	// All networks, as a vector
	vector<Netracker::tracked_network *> all_bssid;
	// Dirty flags for viewable and all.  The viewable vector is only
	// dirty if a new network is added to it or if something changes w/in the
	// sorting type.  Content dirty means we need to regenerate our display
	// text, but not resort.
	int v_dirty, all_dirty, vc_dirty;
	// Viewable size
	int viewable_size;
};

#endif // panel
#endif // header

