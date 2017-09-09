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
#include "kis_panel_device.h"
#include "kis_panel_info.h"

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

	// Add a plugin to the plugin menu
	virtual int AddPluginMenuItem(string in_name, int (*callback)(void *),
								   void *auxptr);

	// Toggle check (mostly unused, plugins should add to the main menus now)
	virtual void SetPluginMenuItemChecked(int in_mi, int in_checked) {
		menu->SetMenuItemChecked(in_mi, in_checked);
	}

	// Add a divider to the View menu to add plugin view options (should be
	// called by every plugin, will only add the separator once)
	virtual void AddViewSeparator();
	
	// Get the last added sort view option
	virtual int FetchLastViewMenuItem() { return mi_lastview; }
	virtual void SetLastViewMenuItem(int in_last) { mi_lastview = in_last; }

	// Passthroughs to the plugin-relevant packing boxes used to build the UI
	// Network box (contains network and gps-line)
	Kis_Panel_Packbox *FetchNetBox() { return netbox; }
	// Fetch info box (contains network totals, time, etc)
	Kis_Panel_Packbox *FetchInfoBox() { return optbox; }
	// Fetch gps line box (contains gps, battery, etc)
	Kis_Panel_Packbox *FetchLineBox() { return linebox; }

	// Passthrough to color handling
	void AddColorPref(string in_pref, string in_txt);

	// Load sound prefrences from config file
	void LoadAudioPrefs();
	// Speak a keyed string (ugly way to do it but there's no other quick way
	// and speech happens so rarely it's not worth doing an integer lookup
	// table for the speech keys)
	void SpeakString(string type, vector<string> text);

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
	void Proto_BATTERY(CLIPROTO_CB_PARMS);
	void Proto_ALERT(CLIPROTO_CB_PARMS);

protected:
	int mn_file, mi_startserver, mi_serverconsole, mi_connect, mi_disconnect, 
		mi_addcard, mi_conf, mi_quit;

	int mn_plugins, mi_addplugin, mi_noplugins;

	int mn_preferences, mi_startprefs, mi_serverprefs, mi_colorprefs, mi_netcolprefs,
		mi_netextraprefs, mi_clicolprefs, mi_cliextraprefs, mi_infoprefs, mi_gpsprefs,
		mi_audioprefs, mi_warnprefs;
	
	int mn_sort;

	int mn_view, 
		mi_viewplaceholder, mi_lastview,
		// Filter submenu
		mn_filter,
		mi_showdevice, mi_showsummary, mi_showstatus, 
		mi_showgps, mi_showbattery, mi_showpps, mi_showsources;
	int mn_view_appended;

	int mn_windows, mi_netdetails, mi_addnote, mi_clientlist, 
		mi_chandetails, mi_gps, mi_alerts;

	int connect_enable;

	int sortmode;

	KisStatusText_Messageclient *statuscli;
	Kis_Status_Text *statustext;
	Kis_Devicelist *devicelist;
	Kis_Info_Bits *infobits;
	Kis_Free_Text *sourceinfo, *gpsinfo, *batteryinfo;

	Kis_Panel_Packbox *netbox, *optbox, *linebox, *hbox, *vbox;

	vector<Kis_Main_Panel::plugin_menu_opt> plugin_menu_vec;

	virtual void UpdateViewMenu(int mi);

	virtual void SpawnColorPrefs();
	virtual void SpawnServerPrefs();
	virtual void SpawnInfoPrefs();

	vector<colorpref> color_pref_vec;

	Kis_IntGraph *packetrate;
	vector<int> pps, datapps;
	int lastpackets, lastdata;

	int addref;

	string agg_gps_fields;
	int agg_gps_num;

	// Sound options
	int snd_new, snd_packet, snd_gpslock, snd_gpslost, snd_alert;
	string sound_prefix;
	string spk_new, spk_alert, spk_gpslost, spk_gpslock;
};

#define KIS_PROMPT_CB_PARMS	GlobalRegistry *globalreg, int ok, int check, void *auxptr
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
	void SetCheckText(string in_text1);
	void SetChecked(int in_checked);
	void SetCallback(ksp_prompt_cb in_callback, void *in_auxptr);
	void SetDisplayText(vector<string> in_text);

	void ButtonAction(Kis_Panel_Component *component);

protected:
	void *auxptr;
	ksp_prompt_cb callback;

	Kis_Free_Text *ftext;
	Kis_Button *okbutton, *cancelbutton;
	Kis_Checkbox *check;

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

	virtual void DrawPanel();
	virtual void ButtonAction(Kis_Panel_Component *in_button);

	virtual void Proto_PLUGIN(CLIPROTO_CB_PARMS);
	virtual void Proto_PLUGIN_complete();

protected:
	Kis_Scrollable_Table *pluglist;
	Kis_Scrollable_Table *spluglist;
	Kis_Free_Text *helptext, *shelptext;
	Kis_Button *okbutton;
	Kis_Panel_Packbox *vbox, *bbox;

	int net_plugin_ref;

	int srv_plugin_info;

	vector<panel_plugin_meta *> *plugins;
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

class Kis_AddDevNote_Panel : public Kis_Panel {
public:
	Kis_AddDevNote_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_AddNetNote_Panel()\n");
		exit(1);
	}

	Kis_AddDevNote_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_AddDevNote_Panel();

	virtual void SetTarget(mac_addr in_target) {
		bssid = in_target;
	}

	virtual void DrawPanel();
	virtual void Action(Kis_Panel_Component *in_button, int in_state);

protected:
	Kis_Panel_Packbox *vbox, *bbox;
	Kis_Single_Input *notetxt;
	Kis_Checkbox *permanent;
	Kis_Button *cancelbutton, *okbutton, *delbutton;

	mac_addr bssid;
};

#endif

#endif
