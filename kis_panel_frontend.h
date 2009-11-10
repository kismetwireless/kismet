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

#include "configfile.h"

#include "popenclient.h"
#include "text_cliframe.h"

#define WIN_CENTER(h, w)	(LINES / 2) - ((h) / 2), (COLS / 2) - ((w) / 2), (h), (w)

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

// Plugin version information, v1
// This holds revision information for the KISMET THE PLUGIN WAS COMPILED WITH,
// NOT THE PLUGIN VERSION (plugin version is passed in the info struct!)
struct panel_plugin_revision {
	// V1 data 

	// Versioned for possible updates to the version api
	int version_api_revision;

	string major;
	string minor;
	string tiny;

	// End V1 data
};

#define KIS_PANEL_PLUGIN_VREVISION		1

// Plugin revision call.  If the kis_plugin_revision  symbol is available in the plugin,
// then it will be passed an allocated plugin_revision struct, with the version_api_rev
// set appropriately.  Plugins MUST ONLY use fields in the negotiated plugin version
// record.  This record is not expected to change significantly over time, BUT IT MAY,
// should it become necessary to add more complex data.
typedef void (*panel_plugin_revisioncall)(panel_plugin_revision *);

class KisPanelInterface : public PanelInterface {
public:
	KisPanelInterface();
	KisPanelInterface(GlobalRegistry *in_globalreg);
	virtual ~KisPanelInterface();

	virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset);

	virtual int Poll(fd_set& in_rset, fd_set& in_wset);

	virtual void Shutdown();

	virtual void AddPanel(Kis_Panel *in_panel);
	virtual void KillPanel(Kis_Panel *in_panel); 

	virtual int LoadPreferences();
	virtual int SavePreferences();

	// Connect to a network client & register callbacks for when one is added
	virtual int AddNetClient(string in_host, int in_reconnect);
	virtual void RemoveNetClient();

	virtual int Add_NetCli_AddCli_CB(KPI_AddCli_Callback in_cb, void *in_aux);
	virtual void Remove_Netcli_AddCli_CB(int in_cbref);
	virtual void Remove_All_Netcli_Conf_CB(CliConf_Callback in_cb);
	virtual void Remove_All_Netcli_Cmd_CB(CliCmd_Callback in_cb, void *in_aux);
	virtual int Remove_All_Netcli_ProtoHandler(string in_proto,
											   CliProto_Callback in_cb,
											   void *in_aux);

	// Fetch the client
	KisNetClient *FetchNetClient() { return network_client; }

	// Are we connected to a client?
	int FetchNetConnected() {
		if (network_client && network_client->Valid())
			return 1;
		return 0;
	}
	
	// Configured client callback
	virtual void NetClientConfigure(KisNetClient *in_cli, int in_recon);

	// Bring up a modal alert (may be queued if an alert is already displayed)
	virtual void RaiseAlert(string in_title, string in_text);
	// Queue a modal panel, we only display one modal panel at a time.
	// Alerts are modal, prompt boxes should almost always be considered modal.
	virtual void QueueModalPanel(Kis_Panel *in_panel);

	// We track cards at the interface level because we need instant feedback on them
	// without waiting for individual widgets to do their own activate and poll, though
	// a widget CAN still directly talk the SOURCE protocol if it needs to
	struct knc_card {
		// Last time this record got updated
		time_t last_update;

		// Hash for the UUID, used as a placeholder in the select table since
		// we need just an int there.  We hope this never collides, and if it
		// does, we'll figure out some other way to deal with this
		uint32_t uuid_hash;

		string interface;
		string type;
		string name;

		// We need a copy of this anyhow
		uuid carduuid; 

		int channel;
		int packets;
		int hopping;
		int hopvelocity;
		int dwell;

		struct timeval hop_tm;

		// Store as a string since we don't necessarily care
		string channellist;

		// Are we in an error state?
		int error;

		// Do we have a warning?
		string warning;
	};

	struct knc_alert {
		struct timeval tv;
		string alertname;
		mac_addr bssid, source, dest, other;
		int channel;
		string text;
	};

	// Internal parser for ALERT proto
	void proto_ALERT(CLIPROTO_CB_PARMS);
	vector<KisPanelInterface::knc_alert *> *FetchAlertVec() { return &alert_vec; }

	// Internal parser for the CARD proto, linked to the callback
	void proto_SOURCE(CLIPROTO_CB_PARMS);
	// Fetch the list of cards from the system
	map<uuid, KisPanelInterface::knc_card *> *FetchNetCardMap();

	void proto_INFO(CLIPROTO_CB_PARMS);

	struct addcli_cb_rec {
		int refnum;
		KPI_AddCli_Callback cb;
		void *auxptr;
	};

	void LoadPlugin(string in_fname, string in_objname);
	vector<panel_plugin_meta *> *FetchPluginVec() { return &plugin_vec; }
	void ScanPlugins();
	void LoadPlugins();

	Kis_Main_Panel *FetchMainPanel() { return mainp; }

	// Public so we don't have pointless wrappers
	ConfigFile *prefs;
	Kis_Panel_Color colors;

	// Interface level since it's independent of the UI
	void SpawnServer(string in_parm);
	void SpawnServer();
	void KillServer();
	// These need to be exposed to the callbacks for clean shutdown
	TextCliFrame *FetchServerFramework() { return server_framework; }
	PopenClient *FetchServerPopen() { return server_popen; }
	vector<string> *FetchServerConsole() { return &server_console; }
	
	void ResetWarnAllClear() { 
		warned_cleared = 1; 
		warned_all_errors_consec = 0; 
		warned_all_errors = time(0);
	}

protected:
	int shutdown_mode; 

	// Only allow one server, I don't think anyone really used multiple
	// simultaneous servers and if they did, too bad, it introduced way too
	// much hassle
	KisNetClient *network_client;

	// Map of UUIDs of sources to representations
	map<uuid, KisPanelInterface::knc_card *> netcard_map;

	// Alerts
	vector<KisPanelInterface::knc_alert *> alert_vec;

	int addcb_ref;
	vector<KisPanelInterface::addcli_cb_rec *> addclicb_vec;

	// Map of all the settings and prefs

	vector<panel_plugin_meta *> plugin_vec;
	KisPanelPluginData plugdata;

	Kis_Main_Panel *mainp;

	// Server monitoring stuff
	TextCliFrame *server_framework;
	PopenClient *server_popen;
	string server_parm;
	vector<string> server_console;
	int server_text_cb;

	// Have we yelled at the user for not having any sources enabled?
	int warned_no_sources;

	// Or are they all broken?
	int warned_all_errors, warned_all_errors_consec, warned_cleared;

	vector<Kis_Panel *> modal_vec;
};

#endif // panel
#endif // header

