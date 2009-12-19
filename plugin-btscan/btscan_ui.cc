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

#include <config.h>

#include <stdio.h>

#include <string>
#include <sstream>

#include <globalregistry.h>
#include <kis_panel_plugin.h>
#include <kis_panel_frontend.h>
#include <kis_panel_windows.h>
#include <kis_panel_network.h>
#include <kis_panel_widgets.h>
#include <version.h>

#include "tracker_btscan.h"

const char *btscandev_fields[] = {
	"bdaddr", "name", "class", "firsttime", "lasttime", "packets",
	NULL
};

struct btscan_data {
	int mi_plugin_btscan, mi_showbtscan;

	map<mac_addr, btscan_network *> btdev_map;

	Kis_Scrollable_Table *btdevlist;

	int cliaddref;

	int timerid;

	string asm_btscandev_fields;
	int asm_btscandev_num;

	KisPanelPluginData *pdata;
	Kis_Menu *menu;
};

// Menu events
int Btscan_plugin_menu_cb(void *auxptr);
void Btscan_show_menu_cb(MENUITEM_CB_PARMS);

// Network events
void BtscanCliAdd(KPI_ADDCLI_CB_PARMS);
void BtscanCliConfigured(CLICONF_CB_PARMS);

// List select
void BtscanDevlistCB(COMPONENT_CALLBACK_PARMS);

// List content timer
int BtscanTimer(TIMEEVENT_PARMS);

extern "C" {

int panel_plugin_init(GlobalRegistry *globalreg, KisPanelPluginData *pdata) {
	_MSG("Loading Kismet BTSCAN plugin", MSGFLAG_INFO);

	btscan_data *btscan = new btscan_data;

	pdata->pluginaux = (void *) btscan;

	btscan->pdata = pdata;

	btscan->asm_btscandev_num = 
		TokenNullJoin(&(btscan->asm_btscandev_fields), btscandev_fields);

	btscan->cliaddref =
		pdata->kpinterface->Add_NetCli_AddCli_CB(BtscanCliAdd, (void *) btscan);

	btscan->mi_plugin_btscan =
		pdata->mainpanel->AddPluginMenuItem("BT Scan", Btscan_plugin_menu_cb, pdata);


	btscan->btdevlist = new Kis_Scrollable_Table(globalreg, pdata->mainpanel);

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;

	t.width = 17;
	t.title = "BD Addr";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 15;
	t.title = "Name";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 9;
	t.title = "Class";
	t.alignment = 0;
	titles.push_back(t);

	btscan->btdevlist->AddTitles(titles);
	btscan->btdevlist->SetPreferredSize(0, 10);

	pdata->mainpanel->AddComponentVec(btscan->btdevlist, 
									  (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									   KIS_PANEL_COMP_TAB));
	pdata->mainpanel->FetchNetBox()->Pack_After_Named("KIS_MAIN_NETLIST",
													  btscan->btdevlist, 1, 0);

	btscan->menu = pdata->kpinterface->FetchMainPanel()->FetchMenu();
	int mn_view = btscan->menu->FindMenu("View");

	pdata->kpinterface->FetchMainPanel()->AddViewSeparator();
	btscan->mi_showbtscan = btscan->menu->AddMenuItem("BT Scan", mn_view, 0);
	btscan->menu->SetMenuItemCallback(btscan->mi_showbtscan, Btscan_show_menu_cb, 
									  btscan);

	string opt = pdata->kpinterface->prefs->FetchOpt("PLUGIN_BTSCAN_SHOW");
	if (opt == "true" || opt == "") {
		btscan->btdevlist->Show();
		btscan->menu->SetMenuItemChecked(btscan->mi_showbtscan, 1);
	} else {
		btscan->btdevlist->Hide();
		btscan->menu->SetMenuItemChecked(btscan->mi_showbtscan, 0);
	}

	return 1;
}

// Plugin version control
void kis_revision_info(panel_plugin_revision *prev) {
	if (prev->version_api_revision >= 1) {
		prev->version_api_revision = 1;
		prev->major = string(VERSION_MAJOR);
		prev->minor = string(VERSION_MINOR);
		prev->tiny = string(VERSION_TINY);
	}
}

}

int Btscan_plugin_menu_cb(void *auxptr) {
	KisPanelPluginData *pdata = (KisPanelPluginData *) auxptr;

	pdata->kpinterface->RaiseAlert("BT Scan",
			"BT Scan UI " + string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
				string(VERSION_TINY) + "\n"
			"\n"
			"Display Bluetooth/802.15.1 devices found by the\n"
			"BTSCAN active scanning Kismet plugin\n");
	return 1;
}

void Btscan_show_menu_cb(MENUITEM_CB_PARMS) {
	btscan_data *btscan = (btscan_data *) auxptr;

	if (btscan->pdata->kpinterface->prefs->FetchOpt("PLUGIN_BTSCAN_SHOW") == "true" ||
		btscan->pdata->kpinterface->prefs->FetchOpt("PLUGIN_BTSCAN_SHOW") == "") {

		btscan->pdata->kpinterface->prefs->SetOpt("PLUGIN_BTSCAN_SHOW", "false", 1);

		btscan->btdevlist->Hide();

		btscan->menu->SetMenuItemChecked(btscan->mi_showbtscan, 0);
	} else {
		btscan->pdata->kpinterface->prefs->SetOpt("PLUGIN_BTSCAN_SHOW", "true", 1);

		btscan->btdevlist->Show();

		btscan->menu->SetMenuItemChecked(btscan->mi_showbtscan, 1);
	}

	return;
}

void BtscanProtoBTSCANDEV(CLIPROTO_CB_PARMS) {
	btscan_data *btscan = (btscan_data *) auxptr;

	if (proto_parsed->size() < btscan->asm_btscandev_num) {
		_MSG("Invalid BTSCANDEV sentence from server", MSGFLAG_INFO);
		return;
	}

	int fnum = 0;

	btscan_network *btn = NULL;

	mac_addr ma;

	ma = mac_addr((*proto_parsed)[fnum++].word);

	if (ma.error)
		return;

	map<mac_addr, btscan_network *>::iterator bti;
	string tstr;
	unsigned int tuint;

	if ((bti = btscan->btdev_map.find(ma)) == btscan->btdev_map.end()) {
		btn = new btscan_network;
		btn->bd_addr = ma;

		btscan->btdev_map[ma] = btn;
	} else {
		btn = bti->second;
	}

	tstr = MungeToPrintable((*proto_parsed)[fnum++].word);
	if (btn->bd_name != "" && btn->bd_name != tstr) {
		// alert on BT dev name change?
	}
	btn->bd_name = tstr;

	tstr = MungeToPrintable((*proto_parsed)[fnum++].word);
	if (btn->bd_class != "" && btn->bd_class != tstr) {
		// Alert on BT dev class change?
	}
	btn->bd_class = tstr;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		return;
	btn->first_time = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		return;
	btn->last_time = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		return;
	btn->packets = 1;

	// TODO - gps
}

void BtscanCliConfigured(CLICONF_CB_PARMS) {
	btscan_data *btscan = (btscan_data *) auxptr;

	if (recon)
		return;

	if (kcli->RegisterProtoHandler("BTSCANDEV", btscan->asm_btscandev_fields,
								   BtscanProtoBTSCANDEV, auxptr) < 0) {
		_MSG("Could not register BTSCANDEV protocol with remote server", MSGFLAG_ERROR);

		globalreg->panel_interface->RaiseAlert("No BTSCAN protocol",
				"The BTSCAN UI was unable to register the required\n"
				"BTSCANDEV protocol.  Either it is unavailable\n"
				"(you didn't load the BTSCAN server plugin) or you\n"
				"are using an older server plugin.\n");
		return;
	}
}

void BtscanCliAdd(KPI_ADDCLI_CB_PARMS) {
	if (add == 0)
		return;

	netcli->AddConfCallback(BtscanCliConfigured, 1, auxptr);
}

