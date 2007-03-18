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

#ifndef __KIS_PANEL_FRONTEND_H__
#define __KIS_PANEL_FRONTEND_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include <stdio.h>
#include <string>
#include <vector>
#include <map>

#include "uuid.h"

#include "pollable.h"
#include "messagebus.h"
#include "kis_panel_widgets.h"
#include "kis_panel_windows.h"

#include "kis_clinetframe.h"

#include "kis_panel_plugin.h"

class KisPanelInterface;

// Our specialized actual kismet frontend
// Most of the drawing is inherited from the generic case panel interface,
// but we need to add our own tracking systems and such here.
//
// This also implements all the hooks which get linked to the clients to
// process protocols.

#define KPI_ADDCLI_CB_PARMS		GlobalRegistry *globalreg, KisNetClient *netcli, \
	int add, void *auxptr
typedef void (*KPI_AddCli_Callback)(KPI_ADDCLI_CB_PARMS);

class KisPanelInterface : public PanelInterface {
public:
	KisPanelInterface();
	KisPanelInterface(GlobalRegistry *in_globalreg);
	virtual ~KisPanelInterface();

	virtual void AddPanel(Kis_Panel *in_panel);

	virtual int LoadPreferences();
	virtual int SavePreferences();

	// Add a new client
	virtual int AddNetClient(string in_host, int in_reconnect);
	virtual int Add_NetCli_AddCli_CB(KPI_AddCli_Callback in_cb, void *in_aux);
	virtual void Remove_Netcli_AddCli_CB(int in_cbref);

	// Fetch a list of clients
	virtual vector<KisNetClient *> FetchNetClientVec();
	virtual vector<KisNetClient *> *FetchNetClientVecPtr();
	// Remove a client
	virtual int RemoveNetClient(KisNetClient *in_cli);
	// Configured client callback
	virtual void NetClientConfigure(KisNetClient *in_cli, int in_recon);

	// Callthroughs to operate on the entire list of clients, so that panels
	// and, via them, widgets, can manipulate protocols, etc
	virtual int Remove_AllNetcli_ProtoHandler(string in_proto,
											  CliProto_Callback in_cb,
											  void *in_aux);

	// Bring up a modal alert
	virtual void RaiseAlert(string in_title, string in_text);

	// Bring up a modal picker for connected servers -- This is generic
	// enough that it's worth having a main hook here for other panels
	// to get access to the common code
	virtual void RaiseServerPicker(string in_title, kpi_sl_cb_hook in_hook,
								   void *in_aux);

	// Internal structure for tracking cards
	typedef struct knc_card {
		// Last time this record got updated
		time_t last_update;

		// Hash for the UUID, used as a placeholder in the table since
		// we need just an int there.  We hope this never collides, and if it
		// does, we'll figure out some other way to deal with this
		uint32_t uuid_hash;

		string interface;
		string type;
		string username;

		// We need a copy of this anyhow
		uuid carduuid; 

		int channel;
		int packets;
		int hopping;

		// Once we add it to the server we need to support storing the
		// list of channels supported and screen channel locks to the
		// appropriate sources
	};

	// Internal parser for the CARD proto, linked to the callback
	void NetClientCARD(CLIPROTO_CB_PARMS);
	// Fetch the list of cards from the system
	map<uuid, KisPanelInterface::knc_card *> *FetchNetCardMap();

	typedef struct addcli_cb_rec {
		int refnum;
		KPI_AddCli_Callback cb;
		void *auxptr;
	};

	vector<panel_plugin_meta *> *FetchPluginVec() { return &plugin_vec; }

	// Public so we don't have pointless wrappers
	ConfigFile prefs;

protected:
	vector<KisNetClient *> netclient_vec;

	// Map of UUIDs of sources to representations
	map<uuid, KisPanelInterface::knc_card *> netcard_map;

	int addcb_ref;
	vector<KisPanelInterface::addcli_cb_rec *> addclicb_vec;

	// Map of all the settings and prefs

	vector<panel_plugin_meta *> plugin_vec;
	KisPanelPluginData plugdata;
};

#endif // panel
#endif // header

