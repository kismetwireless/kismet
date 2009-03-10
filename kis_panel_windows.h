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

#ifndef __KIS_PANEL_WINDOWS_H__
#define __KIS_PANEL_WINDOWS_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "globalregistry.h"
#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"
#include "kis_panel_network.h"

#include "kis_panel_plugin.h"

class KisPanelInterface;

// Callback for the frontend to pick a server
#define KPI_SL_CB_PARMS GlobalRegistry *globalreg, KisPanelInterface *kpi, \
	KisNetClient *picked, void *auxptr
typedef void (*kpi_sl_cb_hook)(KPI_SL_CB_PARMS);

class Kis_Main_Panel : public Kis_Panel {
public:
	Kis_Main_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Main_Panel() called w/out globalreg\n");
		exit(1);
	}
	Kis_Main_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_intf);
	virtual ~Kis_Main_Panel();

	// separate function for post-add startups so that we exist in the panel
	// vect and we can make new windows properly
	virtual void Startup();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	// Passthrough to the display group
	virtual Kis_Display_NetGroup *FetchSelectedNetgroup();
	virtual vector<Kis_Display_NetGroup *> *FetchDisplayNetgroupVector();
	virtual Kis_Netlist *FetchDisplayNetlist() { return netlist; }

	// Add a plugin to the plugin menu
	virtual int AddPluginMenuItem(string in_name, int (*callback)(void *),
								   void *auxptr);

	virtual void SetPluginMenuItemChecked(int in_mi, int in_checked) {
		menu->SetMenuItemChecked(in_mi, in_checked);
	}

	// Passthroughs to the plugin-relevant packing boxes used to build the UI
	// Network box (contains network and gps-line)
	Kis_Panel_Packbox *FetchNetBox() { return netbox; }
	// Fetch info box (contains network totals, time, etc)
	Kis_Panel_Packbox *FetchInfoBox() { return optbox; }
	// Fetch gps line box (contains gps, battery, etc)
	Kis_Panel_Packbox *FetchLineBox() { return linebox; }

	// Passthrough to color handling
	void AddColorPref(string in_pref, string in_txt);

	struct plugin_menu_opt {
		int menuitem;
		int (*callback)(void *);
		void *auxptr;
	};

	struct colorpref {
		string pref;
		string text;
	};

	void MenuAction(int opt);

	// Network protocol handlers for INFO for the packet graph
	void NetClientConfigure(KisNetClient *in_cli, int in_recon);
	void NetClientAdd(KisNetClient *in_cli, int add);
	void Proto_INFO(CLIPROTO_CB_PARMS);
	void Proto_GPS(CLIPROTO_CB_PARMS);

protected:
	int mn_file, mi_startserver, mi_serverconsole, mi_connect, mi_disconnect, 
		mi_addcard, mi_conf, mi_quit;

	int mn_plugins, mi_addplugin, mi_noplugins;

	int mn_preferences, mi_startprefs, mi_serverprefs, mi_colorprefs, mi_netcolprefs,
		mi_netextraprefs, mi_infoprefs, mi_gpsprefs;

	int mn_sort, mi_sort_auto, mi_sort_type, mi_sort_chan, mi_sort_crypt, mi_sort_first, 
		mi_sort_first_d, mi_sort_last, mi_sort_last_d, mi_sort_bssid, mi_sort_ssid,
		mi_sort_packets, mi_sort_packets_d;

	int mn_view, mi_shownetworks, mi_showclients, mi_showsummary, mi_showstatus, 
		mi_showgps, mi_showpps, mi_showsources;

	int mn_windows, mi_netdetails, mi_clientlist, mi_chandetails, mi_gps;

	int connect_enable;

	int sortmode;

	KisStatusText_Messageclient *statuscli;
	Kis_Status_Text *statustext;
	Kis_Netlist *netlist;
	Kis_Clientlist *clientlist;
	Kis_Info_Bits *infobits;
	Kis_Free_Text *sourceinfo, *gpsinfo;

	Kis_Panel_Packbox *netbox, *optbox, *linebox, *hbox, *vbox;

	vector<Kis_Main_Panel::plugin_menu_opt> plugin_menu_vec;

	virtual void UpdateSortMenu();
	virtual void UpdateViewMenu(int mi);

	virtual void SpawnColorPrefs();
	virtual void SpawnServerPrefs();
	virtual void SpawnNetcolPrefs();
	virtual void SpawnNetextraPrefs();
	virtual void SpawnInfoPrefs();

	vector<colorpref> color_pref_vec;

	Kis_IntGraph *packetrate;
	vector<int> pps, datapps;
	int lastpackets, lastdata;

	int addref;

	string agg_gps_fields;
	int agg_gps_num;
};

#define KIS_PROMPT_CB_PARMS	GlobalRegistry *globalreg, int ok, void *auxptr
typedef void (*ksp_prompt_cb)(KIS_PROMPT_CB_PARMS);

class Kis_Prompt_Panel : public Kis_Panel {
public:
	Kis_Prompt_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Prompt_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Prompt_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	
	virtual ~Kis_Prompt_Panel();

	void SetDefaultButton(int in_ok);
	void SetButtonText(string in_oktext, string in_notext);
	void SetCallback(ksp_prompt_cb in_callback, void *in_auxptr);
	void SetDisplayText(vector<string> in_text);

	void ButtonAction(Kis_Panel_Component *component);

protected:
	void *auxptr;
	ksp_prompt_cb callback;

	Kis_Free_Text *ftext;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox;
};

class Kis_Connect_Panel : public Kis_Panel {
public:
	Kis_Connect_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Connect_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Connect_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_Connect_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	void ButtonAction(Kis_Panel_Component *component);

protected:
	Kis_Single_Input *hostname;
	Kis_Single_Input *hostport;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox;
};

class Kis_Spawn_Panel : public Kis_Panel {
public:
	Kis_Spawn_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Spawn_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Spawn_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_Spawn_Panel();

	void ButtonAction(Kis_Panel_Component *component);

	void SpawnConsole(int in_console) { spawn_console = in_console; }

protected:
	Kis_Single_Input *options, *logname;
	Kis_Checkbox *logging_check, *console_check;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox;

	int spawn_console;
};

class Kis_Console_Panel : public Kis_Panel {
public:
	Kis_Console_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Consol_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Console_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_Console_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);

	void ButtonAction(Kis_Panel_Component *component);

	void AddConsoleText(string in_text);

protected:
	Kis_Free_Text *constext;
	Kis_Button *okbutton, *killbutton;

	Kis_Panel_Packbox *vbox, *bbox;
	
	int textcb;
};

class Kis_AddCard_Panel : public Kis_Panel {
public:
	Kis_AddCard_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_AddCard_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_AddCard_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_AddCard_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	void ButtonAction(Kis_Panel_Component *in_button);

protected:
	KisNetClient *target_cli;

	Kis_Single_Input *srcopts;
	Kis_Single_Input *srciface;
	Kis_Single_Input *srcname;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox;
};

// AddCard callback to trigger building the window
void sp_addcard_cb(KPI_SL_CB_PARMS);

class Kis_ServerList_Panel : public Kis_Panel {
public:
	Kis_ServerList_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_ServerList_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_ServerList_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_intf);
	virtual ~Kis_ServerList_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual int KeyPress(int in_key);

protected:
	Kis_Scrollable_Table *srvlist;
	Kis_Menu *menu;
};

class Kis_CardList_Panel : public Kis_Panel {
public:
	Kis_CardList_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_CardList_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_CardList_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_intf);
	virtual ~Kis_CardList_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

protected:
	Kis_Scrollable_Table *cardlist;
};

class Kis_ModalAlert_Panel : public Kis_Panel {
public:
	Kis_ModalAlert_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_ModalAlert_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_ModalAlert_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_intf);
	virtual ~Kis_ModalAlert_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	virtual void ConfigureAlert(string in_title, string in_text);

	virtual void AckAction();

protected:
	Kis_Free_Text *ftxt;
	Kis_Button *ackbutton;
};

class Kis_Plugin_Picker : public Kis_Panel {
	// Plugin picker lists .so files in the plugin director(ies) and lets 
	// the user pick one to load.
public:
	Kis_Plugin_Picker() {
		fprintf(stderr, "FATAL OOPS: Kis_Plugin_Picker called w/out globalreg\n");
		exit(1);
	}

	Kis_Plugin_Picker(GlobalRegistry *in_globalreg, KisPanelInterface *in_intf);
	virtual ~Kis_Plugin_Picker();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual void ButtonAction(Kis_Panel_Component *in_button);

protected:
	Kis_Scrollable_Table *pluglist;
	Kis_Free_Text *helptext;
	Kis_Button *okbutton;
	Kis_Panel_Packbox *vbox, *bbox;

	vector<panel_plugin_meta *> *plugins;
};

class Kis_NetDetails_Panel : public Kis_Panel {
public:
	Kis_NetDetails_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_NetDetails_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_NetDetails_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_NetDetails_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual void ButtonAction(Kis_Panel_Component *in_button);
	virtual void MenuAction(int opt);

	virtual int GraphTimer();

protected:
	int AppendNetworkInfo(int k, Kis_Display_NetGroup *tng, 
						  Netracker::tracked_network *net);
	int AppendSSIDInfo(int k, Netracker::tracked_network *net, 
					   Netracker::adv_ssid_data *ssid);

	virtual void UpdateViewMenu(int mi);
	void ClearGraphVectors();
	void UpdateGraphVectors(int signal, int pps, int retry);
	
	int DeriveDisplayUpdate();

	Kis_Panel_Packbox *vbox, *bbox;
	Kis_Scrollable_Table *netdetails;

	Kis_IntGraph *siggraph, *packetgraph, *retrygraph;
	vector<int> sigpoints, packetpps, retrypps;
	int lastpackets;

	time_t last_dirty;
	mac_addr last_mac;
	Kis_Display_NetGroup *dng;
	Kis_Button *closebutton, *prevbutton, *nextbutton;

	int mn_network, mi_nextnet, mi_prevnet, mi_close;
	int mn_view, mi_net, mi_clients, mi_graphsig, mi_graphpacket, mi_graphretry;

	int grapheventid;
};

#define KCLI_CHANDETAILS_CHANNEL_FIELDS		"channel,time_on,packets,packetsdelta," \
	"usecused,bytes,bytesdelta,networks,activenetworks,maxsignal_dbm,maxsignal_rssi," \
	"maxnoise_dbm,maxnoise_rssi"
#define KCLI_CHANDETAILS_CHANNEL_NUMFIELDS	13

class Kis_ChanDetails_Panel : public Kis_Panel {
public:
	Kis_ChanDetails_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_ChanDetails_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_ChanDetails_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_ChanDetails_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual void ButtonAction(Kis_Panel_Component *in_button);
	virtual void MenuAction(int opt);

	virtual int GraphTimer();

	void NetClientConfigured(KisNetClient *in_cli, int in_recon);
	void NetClientAdd(KisNetClient *in_cli, int add);
	void Proto_CHANNEL(CLIPROTO_CB_PARMS);

	struct chan_sig_info {
		chan_sig_info() {
			last_updated = 0;
			channel = 0;
			channel_time_on = 0;
			packets = 0;
			packets_delta = 0;
			usec_used = 0;
			bytes_seen = 0;
			bytes_delta = 0;
			sig_dbm = 0;
			sig_rssi = 0;
			noise_dbm = 0;
			noise_rssi = 0;
			networks = 0;
			networks_active = 0;
		}

		time_t last_updated;

		int channel;
		int channel_time_on;
		int packets;
		int packets_delta;
		long int usec_used;
		long int bytes_seen;
		long int bytes_delta;

		int sig_dbm;
		int sig_rssi;
		int noise_dbm;
		int noise_rssi;

		int networks;
		int networks_active;
	};

protected:
	virtual void UpdateViewMenu(int mi);
	
	Kis_Panel_Packbox *vbox;
	Kis_Scrollable_Table *chansummary;

	Kis_IntGraph *siggraph, *packetgraph, *bytegraph, *netgraph;

	// Graph data pools
	vector<int> sigvec, noisevec, packvec, bytevec, netvec, anetvec;
	vector<Kis_IntGraph::graph_label> graph_label_vec;

	// Channel records
	map<uint32_t, chan_sig_info *> channel_map;

	time_t last_dirty;

	int mn_channels, mi_lock, mi_hop, mi_close;
	int mn_view, mi_chansummary, mi_signal, mi_packets, mi_traffic, mi_networks;

	int grapheventid;
	int addref;
};

class Kis_Chanconf_Panel : public Kis_Panel {
public:
	Kis_Chanconf_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Chanconf_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Chanconf_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_Chanconf_Panel();

	virtual void DrawPanel();

	void ButtonAction(Kis_Panel_Component *component);

protected:
	Kis_Scrollable_Table *cardlist;
	Kis_Single_Input *inpchannel, *inprate;

	Kis_Radiobutton *lockrad, *hoprad, *dwellrad;

	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox, *cbox;

	int last_selected, radio_changed;
	Kis_Radiobutton *last_radio;
};

class Kis_Gps_Panel : public Kis_Panel {
public:
	Kis_Gps_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Gps_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Gps_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_Gps_Panel();

	void ButtonAction(Kis_Panel_Component *component);

	void Proto_GPS(CLIPROTO_CB_PARMS);

protected:
	Kis_IntGraph *gpssiggraph;
	// Kis_PolarGraph *gpspolgraph;
	Kis_Free_Text *gpslocinfo, *gpsmoveinfo, *gpssatinfo;
	
	Kis_Button *okbutton;

	Kis_Panel_Packbox *vbox; //, *tbox, *hbox;

	vector<int> sat_info_vec;
	vector<Kis_IntGraph::graph_label> sat_label_vec;

	string agg_gps_fields;
	int agg_gps_num;

	int addref;
};

class Kis_Clientlist_Panel : public Kis_Panel {
public:
	Kis_Clientlist_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Clientlist_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Clientlist_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_Clientlist_Panel();

	virtual void ButtonAction(Kis_Panel_Component *in_button);
	virtual void MenuAction(int opt);

	virtual int GraphTimer();

protected:
	virtual void UpdateViewMenu(int mi);
	virtual void UpdateSortMenu();
	
	Kis_Panel_Packbox *vbox;
	Kis_Clientlist *clientlist;

	int mn_clients, mi_nextnet, mi_prevnet, mi_close;
	int mn_sort, mi_sort_auto, mi_sort_type, mi_sort_first, mi_sort_first_d, 
		mi_sort_last, mi_sort_last_d, mi_sort_mac, 
		mi_sort_packets, mi_sort_packets_d;
	int mn_view, mi_details;

	int grapheventid;
};

class Kis_ClientDetails_Panel : public Kis_Panel {
public:
	Kis_ClientDetails_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_ClientDetails_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_ClientDetails_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_ClientDetails_Panel();

	virtual void DrawPanel();
	virtual void ButtonAction(Kis_Panel_Component *in_button);
	virtual void MenuAction(int opt);

	virtual int GraphTimer();

	virtual void SetClientlist(Kis_Clientlist *in_list) {
		clientlist = in_list;
	}

protected:
	virtual void UpdateViewMenu(int mi);
	void ClearGraphVectors();
	void UpdateGraphVectors(int signal, int pps, int retry);
	
	int DeriveDisplayUpdate();

	Kis_Panel_Packbox *vbox, *bbox;
	Kis_Scrollable_Table *clientdetails;

	Kis_IntGraph *siggraph, *packetgraph, *retrygraph;
	vector<int> sigpoints, packetpps, retrypps;
	int lastpackets;

	time_t last_dirty;
	mac_addr last_mac;
	Kis_Display_NetGroup *dng;
	Netracker::tracked_client *dcli;

	int mn_client, mi_nextcli, mi_prevcli, mi_close;
	int mn_view, mi_cli, mi_graphsig, mi_graphpacket, mi_graphretry;

	int grapheventid;

	Kis_Clientlist *clientlist;
};

#endif

#endif
