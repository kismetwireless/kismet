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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>

#include <sstream>
#include <iomanip>

#include "kis_panel_widgets.h"
#include "kis_panel_frontend.h"
#include "kis_panel_windows.h"
#include "kis_panel_preferences.h"

#define WIN_CENTER(h, w)	(LINES / 2) - ((h) / 2), (COLS / 2) - ((w) / 2), (h), (w)

int MenuActivateCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Main_Panel *) aux)->MenuAction(status);
	return 1;
}

void KisMainPanel_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->NetClientAdd(netcli, add);
}

void KisMainPanel_Configured(CLICONF_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->NetClientConfigure(kcli, recon);
}

void KisMainPanel_INFO(CLIPROTO_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->Proto_INFO(globalreg, proto_string,
											proto_parsed, srccli, auxptr);
}

Kis_Main_Panel::Kis_Main_Panel(GlobalRegistry *in_globalreg, 
							   KisPanelInterface *in_intf) : 
	Kis_Panel(in_globalreg, in_intf) {

	menu = new Kis_Menu(globalreg, this);

	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, MenuActivateCB, this);

	mn_file = menu->AddMenu("Kismet", 0);
	mi_connect = menu->AddMenuItem("Connect...", mn_file, 'C');
	mi_disconnect = menu->AddMenuItem("Disconnect", mn_file, 'D');
	menu->AddMenuItem("-", mn_file, 0);

	mi_addcard = menu->AddMenuItem("Add Source...", mn_file, 'A');

	menu->AddMenuItem("-", mn_file, 0);

	mn_plugins = menu->AddSubMenuItem("Plugins", mn_file, 'x');
	mi_addplugin = menu->AddMenuItem("Add Plugin...", mn_plugins, 'P');
	menu->AddMenuItem("-", mn_plugins, 0);
	mi_noplugins = menu->AddMenuItem("No plugins available...", mn_plugins, 0);
	menu->DisableMenuItem(mi_noplugins);

	mn_preferences = menu->AddSubMenuItem("Preferences", mn_file, 'P');
	mi_serverprefs = menu->AddMenuItem("Servers...", mn_preferences, 'S');
	mi_colorprefs = menu->AddMenuItem("Colors...", mn_preferences, 'C');
	mi_netcolprefs = menu->AddMenuItem("Network Columns...", mn_preferences, 'N');
	mi_netextraprefs = menu->AddMenuItem("Network Extras...", mn_preferences, 'E');
	mi_infoprefs = menu->AddMenuItem("Info Pane...", mn_preferences, 'I');

	menu->AddMenuItem("-", mn_file, 0);

	mi_quit = menu->AddMenuItem("Quit", mn_file, 'Q');

	menu->EnableMenuItem(mi_connect);
	menu->DisableMenuItem(mi_disconnect);
	connect_enable = 1;

	mn_sort = menu->AddMenu("Sort", 0);
	mi_sort_auto = menu->AddMenuItem("Auto-fit", mn_sort, 'a');
	menu->AddMenuItem("-", mn_sort, 0);
	mi_sort_type = menu->AddMenuItem("Type", mn_sort, 't');
	mi_sort_chan = menu->AddMenuItem("Channel", mn_sort, 'c');
	mi_sort_first = menu->AddMenuItem("First Seen", mn_sort, 'f');
	mi_sort_first_d = menu->AddMenuItem("First Seen (descending)", mn_sort, 'F');
	mi_sort_last = menu->AddMenuItem("Latest Seen", mn_sort, 'l');
	mi_sort_last_d = menu->AddMenuItem("Latest Seen (descending)", mn_sort, 'L');
	mi_sort_bssid = menu->AddMenuItem("BSSID", mn_sort, 'b');
	mi_sort_ssid = menu->AddMenuItem("SSID", mn_sort, 's');
	mi_sort_packets = menu->AddMenuItem("Packets", mn_sort, 'p');
	mi_sort_packets_d = menu->AddMenuItem("Packets (descending)", mn_sort, 'P');

	mn_view = menu->AddMenu("View", 0);
	mi_netdetails = menu->AddMenuItem("Network Details", mn_view, 'd');
	menu->AddMenuItem("-", mn_view, 0);
	mi_showsummary = menu->AddMenuItem("Info Pane", mn_view, 'S');
	mi_showstatus = menu->AddMenuItem("Status Pane", mn_view, 's');
	mi_showpps = menu->AddMenuItem("Packet Rate", mn_view, 'p');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	// Make a hbox to hold the network list and additional info widgets,
	// and the vertical stack of optional widgets
	hbox = new Kis_Panel_Packbox(globalreg, this);
	hbox->SetPackH();
	hbox->SetHomogenous(0);
	hbox->SetSpacing(1);
	hbox->Show();

	// Make a vbox to hold the hbox we just made, and the status text
	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	// Make the network pack box which holds the network widget and the 
	// extra info line widget
	netbox = new Kis_Panel_Packbox(globalreg, this);
	netbox->SetPackV();
	netbox->SetSpacing(0);
	netbox->SetHomogenous(0);
	netbox->SetName("KIS_MAIN_NETBOX");
	netbox->Show();

	// Make the one-line horizontal box which holds GPS, battery, etc
	linebox = new Kis_Panel_Packbox(globalreg, this);
	linebox->SetPackH();
	linebox->SetSpacing(1);
	linebox->SetHomogenous(0);
	linebox->SetName("KIS_MAIN_LINEBOX");
	linebox->SetPreferredSize(0, 1);
	linebox->Show();

	// Make the vertical box holding things like the # of networks
	optbox = new Kis_Panel_Packbox(globalreg, this);
	optbox->SetPackV();
	optbox->SetSpacing(1);
	optbox->SetHomogenous(0);
	optbox->SetName("KIS_MAIN_OPTBOX");
	optbox->SetPreferredSize(10, 0);
	optbox->Show();

	statustext = new Kis_Status_Text(globalreg, this);
	statuscli = new KisStatusText_Messageclient(globalreg, statustext);
	globalreg->messagebus->RegisterClient(statuscli, MSGFLAG_ALL);

	// We only want 5 lines of status text
	statustext->SetPreferredSize(0, 5);
	statustext->SetName("KIS_MAIN_STATUS");
	statustext->Show();

	netlist = new Kis_Netlist(globalreg, this);
	netlist->SetName("KIS_MAIN_NETLIST");
	netlist->Show();

	// Set up the packet rate graph as over/under linked to the
	// packets per second
	packetrate = new Kis_IntGraph(globalreg, this);
	packetrate->SetName("PPS_GRAPH");
	packetrate->SetPreferredSize(0, 8);
	packetrate->SetScale(0, 0);
	packetrate->SetInterpolation(1);
	packetrate->SetMode(1);
	packetrate->Show();
	packetrate->AddExtDataVec("Packets", 4, "graph_pps", "yellow,yellow", 
							  ' ', ' ', 1, &pps);
	packetrate->AddExtDataVec("Data", 4, "graph_datapps", "red,red", 
							  ' ', ' ', -1, &datapps);
	for (unsigned int x = 0; x < 50; x++) {
		pps.push_back(0);
		datapps.push_back(0);
	}
	lastpackets = lastdata = 0;

	infobits = new Kis_Info_Bits(globalreg, this);
	infobits->SetName("KIS_MAIN_INFOBITS");
	infobits->Show();

	optbox->Pack_End(infobits, 1, 0);

	// Pack our boxes together
	hbox->Pack_End(netbox, 1, 0);
	hbox->Pack_End(optbox, 0, 0);

	netbox->Pack_End(netlist, 1, 0);
	netbox->Pack_End(linebox, 0, 0);
	netbox->Pack_End(packetrate, 0, 0);

	vbox->Pack_End(hbox, 1, 0);
	vbox->Pack_End(statustext, 0, 0);

	active_component = netlist;
	netlist->Activate(0);

	AddComponentVec(vbox, KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_DRAW);

	if (kpinterface->prefs.FetchOpt("LOADEDFROMFILE") != "1") {
		_MSG("Failed to load preferences file, will use defaults", MSGFLAG_INFO);
	}

	AddColorPref("panel_text_color", "Text");
	AddColorPref("panel_textdis_color", "Text-Inactive");
	AddColorPref("panel_border_color", "Window Border");
	AddColorPref("menu_text_color", "Menu Text");
	AddColorPref("menu_disable_color", "Menu Disabled");
	AddColorPref("menu_border_color", "Menu Border");
	AddColorPref("netlist_header_color", "Netlist Header");
	AddColorPref("netlist_normal_color", "Netlist Normal");
	AddColorPref("netlist_crypt_color", "Netlist Encrypted");
	AddColorPref("netlist_group_color", "Netlist Group");
	AddColorPref("netlist_factory_color", "Netlist Factory");
	AddColorPref("status_normal_color", "Status Text");
	AddColorPref("info_normal_color", "Info Pane");
	AddColorPref("graph_pps", "PPS Graph");
	AddColorPref("graph_datapps", "PPS Data Graph");

	UpdateViewMenu(-1);

	addref = 
		kpinterface->Add_NetCli_AddCli_CB(KisMainPanel_AddCli, (void *) this);
}

Kis_Main_Panel::~Kis_Main_Panel() {
	globalreg->messagebus->RemoveClient(statuscli);
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_AllNetcli_ProtoHandler("INFO",
											   KisMainPanel_INFO, this);
}

void Kis_Main_Panel::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	if (in_recon)
		return;

	if (in_cli->RegisterProtoHandler("INFO", "packets,llcpackets,",
									 KisMainPanel_INFO, this) < 0) {
		_MSG("Could not register INFO protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
}

void Kis_Main_Panel::NetClientAdd(KisNetClient *in_cli, int add) {
	if (add == 0)
		return;

	in_cli->AddConfCallback(KisMainPanel_Configured, 1, this);
}

void Kis_Main_Panel::Proto_INFO(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < 2)
		return;

	int pkts, datapkts;

	if (sscanf((*proto_parsed)[0].word.c_str(), "%d", &pkts) != 1) 
		return;

	if (sscanf((*proto_parsed)[1].word.c_str(), "%d", &datapkts) != 1) 
		return;

	if (lastpackets == 0)
		lastpackets = pkts;
	if (lastdata == 0)
		lastdata = datapkts;

	pps.push_back(pkts - lastpackets);
	datapps.push_back(datapkts - lastdata);

	if (pps.size() > 50) 
		pps.erase(pps.begin(), pps.begin() + pps.size() - 50);
	if (datapps.size() > 50) 
		datapps.erase(datapps.begin(), datapps.begin() + datapps.size() - 50);
	lastpackets = pkts;
	lastdata = datapkts;
}

void Kis_Main_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	menu->SetPosition(1, 0, 0, 0);

	// All we have to do is position the main box now
	vbox->SetPosition(1, 1, in_x - 1, in_y - 2);

	/*
	netlist->SetPosition(in_sx + 2, in_sy + 1, in_x - 15, in_y - 8);
	statustext->SetPosition(in_sx + 1, in_y - 7, in_x - 2, 5);
	*/
}

void Kis_Main_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	wattrset(win, text_color);
	for (unsigned int x = 0; x < pan_comp_vec.size(); x++) {
		if ((pan_comp_vec[x].comp_flags & KIS_PANEL_COMP_DRAW) == 0)
			continue;

		pan_comp_vec[x].comp->DrawComponent();
	}

	UpdateSortMenu();

	menu->DrawComponent();

	wmove(win, 0, 0);
}

int Kis_Main_Panel::MouseEvent(MEVENT *mevent) {
	vector<KisNetClient *> *clivec = kpinterface->FetchNetClientVecPtr();

	if (clivec->size() == 0 && connect_enable == 0) {
		menu->EnableMenuItem(mi_connect);
		menu->DisableMenuItem(mi_disconnect);
		connect_enable = 1;
	} else if (clivec->size() > 0 && connect_enable) {
		menu->EnableMenuItem(mi_disconnect);
		menu->DisableMenuItem(mi_connect);
		connect_enable = 0;
	}

	return Kis_Panel::MouseEvent(mevent);
}

int Kis_Main_Panel::KeyPress(int in_key) {
	vector<KisNetClient *> *clivec = kpinterface->FetchNetClientVecPtr();

	if (clivec->size() == 0 && connect_enable == 0) {
		menu->EnableMenuItem(mi_connect);
		menu->DisableMenuItem(mi_disconnect);
		connect_enable = 1;
	} else if (clivec->size() > 0 && connect_enable) {
		menu->EnableMenuItem(mi_disconnect);
		menu->DisableMenuItem(mi_connect);
		connect_enable = 0;
	}

	return Kis_Panel::KeyPress(in_key);
}

void Kis_Main_Panel::MenuAction(int opt) {
	vector<KisNetClient *> *clivec = kpinterface->FetchNetClientVecPtr();

	// Menu processed an event, do something with it
	if (opt == mi_quit) {
		globalreg->fatal_condition = 1;
		_MSG("Quitting...", MSGFLAG_INFO);
		return;
	} else if (opt == mi_connect) {
		Kis_Connect_Panel *cp = new Kis_Connect_Panel(globalreg, kpinterface);
		cp->Position(WIN_CENTER(8, 40));
		kpinterface->AddPanel(cp);
	} else if (opt == mi_disconnect) {
		if (clivec->size() > 0) {
			kpinterface->RemoveNetClient((*clivec)[0]);
		}
	} else if (opt == mi_sort_auto) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "auto", 1);
	} else if (opt == mi_sort_type) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "type", 1);
	} else if (opt == mi_sort_chan) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "channel", 1);
	} else if (opt == mi_sort_first) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "first", 1);
	} else if (opt == mi_sort_first_d) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "first_desc", 1);
	} else if (opt == mi_sort_last) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "last", 1);
	} else if (opt == mi_sort_last_d) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "last_desc", 1);
	} else if (opt == mi_sort_bssid) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "bssid", 1);
	} else if (opt == mi_sort_ssid) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "ssid", 1);
	} else if (opt == mi_sort_packets) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "packets", 1);
	} else if (opt == mi_sort_packets_d) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "packets_desc", 1);
	} else if (opt == mi_netdetails) {
		Kis_NetDetails_Panel *dp = new Kis_NetDetails_Panel(globalreg, kpinterface);
		dp->Position(WIN_CENTER(LINES, COLS));
		kpinterface->AddPanel(dp);
	} else if (opt == mi_showsummary ||
			   opt == mi_showstatus ||
			   opt == mi_showpps) {
		UpdateViewMenu(opt);
	} else if (opt == mi_addcard) {
		vector<KisNetClient *> *cliref = kpinterface->FetchNetClientVecPtr();
		if (cliref->size() == 0) {
			kpinterface->RaiseAlert("No servers",
									"There are no servers.  You must\n"
									"connect to a server before adding\n"
									"cards.\n");
		} else if (cliref->size() == 1) {
			sp_addcard_cb(globalreg, kpinterface, (*cliref)[0], NULL);
		} else {
			kpinterface->RaiseServerPicker("Choose server", sp_addcard_cb,
										   NULL);
		}

	} else if (opt == mi_addplugin) {
		Kis_Plugin_Picker *pp = new Kis_Plugin_Picker(globalreg, kpinterface);
		pp->Position((LINES / 2) - 8, (COLS / 2) - 20, 16, 50);
		kpinterface->AddPanel(pp);
	} else if (opt == mi_colorprefs) {
		SpawnColorPrefs();
	} else if (opt == mi_serverprefs) {
		SpawnServerPrefs();
	} else if (opt == mi_netcolprefs) {
		SpawnNetcolPrefs();
	} else if (opt == mi_netextraprefs) {
		SpawnNetextraPrefs();
	} else if (opt == mi_infoprefs) {
		SpawnInfoPrefs();
	} else {
		for (unsigned int p = 0; p < plugin_menu_vec.size(); p++) {
			if (opt == plugin_menu_vec[p].menuitem) {
				(*(plugin_menu_vec[p].callback))(plugin_menu_vec[p].auxptr);
				break;
			}
		}
	}
}

void Kis_Main_Panel::AddPluginMenuItem(string in_name, int (*callback)(void *),
									   void *auxptr) {
	plugin_menu_opt mo;

	// Hide the "no plugins" menu and make our own item
	menu->SetMenuItemVis(mi_noplugins, 0);
	mo.menuitem = menu->AddMenuItem(in_name, mn_plugins, 0);
	mo.callback = callback;
	mo.auxptr = auxptr;

	plugin_menu_vec.push_back(mo);
}

void Kis_Main_Panel::AddColorPref(string in_pref, string in_text) {
	colorpref cp;

	for (unsigned int x = 0; x < color_pref_vec.size(); x++) {
		if (color_pref_vec[x].pref == in_pref)
			return;
	}

	cp.pref = in_pref;
	cp.text = in_text;

	color_pref_vec.push_back(cp);
}

void Kis_Main_Panel::SpawnColorPrefs() {
	Kis_ColorPref_Panel *cpp = new Kis_ColorPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; x < color_pref_vec.size(); x++) {
		cpp->AddColorPref(color_pref_vec[x].pref, color_pref_vec[x].text);
	}

	cpp->Position((LINES / 2) - 7, (COLS / 2) - 20, 14, 40);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnNetcolPrefs() {
	Kis_ColumnPref_Panel *cpp = new Kis_ColumnPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; bssid_column_details[x][0] != NULL; x++) {
		cpp->AddColumn(bssid_column_details[x][0],
					   bssid_column_details[x][1]);
	}

	cpp->ColumnPref("netlist_columns", "Network List");

	cpp->Position((LINES / 2) - 9, (COLS / 2) - 30, 18, 60);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnNetextraPrefs() {
	Kis_ColumnPref_Panel *cpp = new Kis_ColumnPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; bssid_extras_details[x][0] != NULL; x++) {
		cpp->AddColumn(bssid_extras_details[x][0],
					   bssid_extras_details[x][1]);
	}

	cpp->ColumnPref("netlist_extras", "Network Extras");

	cpp->Position((LINES / 2) - 9, (COLS / 2) - 30, 18, 60);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnInfoPrefs() {
	Kis_ColumnPref_Panel *cpp = new Kis_ColumnPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; info_bits_details[x][0] != NULL; x++) {
		cpp->AddColumn(info_bits_details[x][0],
					   info_bits_details[x][1]);
	}

	cpp->ColumnPref("netinfo_items", "Info Pane");

	cpp->Position((LINES / 2) - 9, (COLS / 2) - 30, 18, 60);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnServerPrefs() {
	Kis_AutoConPref_Panel *cpp = new Kis_AutoConPref_Panel(globalreg, kpinterface);

	cpp->Position((LINES / 2) - 5, (COLS / 2) - 20, 11, 40);
	kpinterface->AddPanel(cpp);
}

Kis_Display_NetGroup *Kis_Main_Panel::FetchSelectedNetgroup() {
	if (netlist == NULL)
		return NULL;

	return netlist->FetchSelectedNetgroup();
}

vector<Kis_Display_NetGroup *> *Kis_Main_Panel::FetchDisplayNetgroupVector() {
	if (netlist == NULL)
		return NULL;

	return netlist->FetchDisplayVector();
}

void Kis_Main_Panel::UpdateSortMenu() {
	netsort_opts so = netlist->FetchSortMode();

	if (so == netsort_autofit)
		menu->SetMenuItemChecked(mi_sort_auto, 1);
	else
		menu->SetMenuItemChecked(mi_sort_auto, 0);

	if (so == netsort_type)
		menu->SetMenuItemChecked(mi_sort_type, 1);
	else
		menu->SetMenuItemChecked(mi_sort_type, 0);

	if (so == netsort_channel)
		menu->SetMenuItemChecked(mi_sort_chan, 1);
	else
		menu->SetMenuItemChecked(mi_sort_chan, 0);

	if (so == netsort_first)
		menu->SetMenuItemChecked(mi_sort_first, 1);
	else
		menu->SetMenuItemChecked(mi_sort_first, 0);

	if (so == netsort_first_desc)
		menu->SetMenuItemChecked(mi_sort_first_d, 1);
	else
		menu->SetMenuItemChecked(mi_sort_first_d, 0);

	if (so == netsort_last)
		menu->SetMenuItemChecked(mi_sort_last, 1);
	else
		menu->SetMenuItemChecked(mi_sort_last, 0);

	if (so == netsort_last_desc)
		menu->SetMenuItemChecked(mi_sort_last_d, 1);
	else
		menu->SetMenuItemChecked(mi_sort_last_d, 0);

	if (so == netsort_bssid)
		menu->SetMenuItemChecked(mi_sort_bssid, 1);
	else
		menu->SetMenuItemChecked(mi_sort_bssid, 0);

	if (so == netsort_ssid)
		menu->SetMenuItemChecked(mi_sort_ssid, 1);
	else
		menu->SetMenuItemChecked(mi_sort_ssid, 0);

	if (so == netsort_packets)
		menu->SetMenuItemChecked(mi_sort_packets, 1);
	else
		menu->SetMenuItemChecked(mi_sort_packets, 0);

	if (so == netsort_packets_desc)
		menu->SetMenuItemChecked(mi_sort_packets_d, 1);
	else
		menu->SetMenuItemChecked(mi_sort_packets_d, 0);
}

void Kis_Main_Panel::UpdateViewMenu(int mi) {
	string opt;

	if (mi == mi_showsummary) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSUMMARY");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWSUMMARY", "false", 1);
			menu->SetMenuItemChecked(mi_showsummary, 0);
			optbox->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWSUMMARY", "true", 1);
			menu->SetMenuItemChecked(mi_showsummary, 1);
			optbox->Show();
		}
	} else if (mi == mi_showstatus) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSTATUS");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWSTATUS", "false", 1);
			menu->SetMenuItemChecked(mi_showstatus, 0);
			statustext->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWSTATUS", "true", 1);
			menu->SetMenuItemChecked(mi_showstatus, 1);
			statustext->Show();
		}
	} else if (mi == mi_showpps) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWPPS");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWPPS", "false", 1);
			menu->SetMenuItemChecked(mi_showpps, 0);
			packetrate->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWPPS", "true", 1);
			menu->SetMenuItemChecked(mi_showpps, 1);
			packetrate->Show();
		}
	}

	if (mi == -1) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSUMMARY");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_showsummary, 1);
			optbox->Show();
		} else {
			menu->SetMenuItemChecked(mi_showsummary, 0);
			optbox->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSTATUS");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_showstatus, 1);
			statustext->Show();
		} else {
			menu->SetMenuItemChecked(mi_showstatus, 0);
			statustext->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWPPS");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_showpps, 1);
			packetrate->Show();
		} else {
			menu->SetMenuItemChecked(mi_showpps, 0);
			packetrate->Hide();
		}
	}
}

int ConnectButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Connect_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_Connect_Panel::Kis_Connect_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	hostname = new Kis_Single_Input(globalreg, this);
	hostport = new Kis_Single_Input(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);

	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ConnectButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ConnectButtonCB, this);

	tab_pos = 0;

	active_component = hostname;
	hostname->Activate(0);

	SetTitle("Connect to Server");

	hostname->SetLabel("Host", LABEL_POS_LEFT);
	hostname->SetTextLen(120);
	hostname->SetCharFilter(FILTER_ALPHANUMSYM);
	hostname->SetText(kpinterface->prefs.FetchOpt("default_host"), -1, -1);

	hostport->SetLabel("Port", LABEL_POS_LEFT);
	hostport->SetTextLen(5);
	hostport->SetCharFilter(FILTER_NUM);
	hostport->SetText(kpinterface->prefs.FetchOpt("default_port"), -1, -1);

	okbutton->SetText("Connect");
	cancelbutton->SetText("Cancel");

	hostname->Show();
	hostport->Show();
	okbutton->Show();
	cancelbutton->Show();

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	vbox->Show();

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(1);
	bbox->SetCenter(1);
	bbox->Show();

	bbox->Pack_End(cancelbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);

	vbox->Pack_End(hostname, 0, 0);
	vbox->Pack_End(hostport, 0, 0);
	vbox->Pack_End(bbox, 1, 0);

	AddComponentVec(hostname, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(hostport, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	active_component = hostname;
	hostname->Activate(1);
}

Kis_Connect_Panel::~Kis_Connect_Panel() {
}

void Kis_Connect_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	vbox->SetPosition(1, 2, in_x - 2, in_y - 3);
}

void Kis_Connect_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	wattrset(win, text_color);

	for (unsigned int x = 0; x < pan_comp_vec.size(); x++) {
		if ((pan_comp_vec[x].comp_flags & KIS_PANEL_COMP_DRAW) == 0)
			continue;

		pan_comp_vec[x].comp->DrawComponent();
	}

	wmove(win, 0, 0);
}

void Kis_Connect_Panel::ButtonAction(Kis_Panel_Component *component) {
	if (component == okbutton) {
		if (hostname->GetText() == "")  {
			kpinterface->RaiseAlert("No hostname",
									"No hostname was provided for creating a\n"
									"new client connect to a Kismet server.\n"
									"A valid host name or IP is required.\n");
			return;
		}

		if (hostport->GetText() == "")  {
			kpinterface->RaiseAlert("No port",
									"No port number was provided for creating a\n"
									"new client connect to a Kismet server.\n"
									"A valid port number is required.\n");
			return;
		}

		// Try to add a client
		string clitxt = "tcp://" + hostname->GetText() + ":" +
			hostport->GetText();

		if (kpinterface->AddNetClient(clitxt, 1) < 0) 
			kpinterface->RaiseAlert("Connect failed", 
									"Failed to create new client connection\n"
									"to a Kismet server.  Check the status\n"
									"pane for more information about what\n"
									"went wrong.\n");

		globalreg->panel_interface->KillPanel(this);
	} else if (component == cancelbutton) {
		// Cancel and close
		globalreg->panel_interface->KillPanel(this);
	}
}

int ModalAckCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ModalAlert_Panel *) aux)->AckAction();
}

Kis_ModalAlert_Panel::Kis_ModalAlert_Panel(GlobalRegistry *in_globalreg, 
										   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	tab_pos = 0;

	ftxt = new Kis_Free_Text(globalreg, this);
	ackbutton = new Kis_Button(globalreg, this);

	AddComponentVec(ftxt, KIS_PANEL_COMP_DRAW);
	AddComponentVec(ackbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								KIS_PANEL_COMP_EVT));

	active_component = ackbutton;
	ackbutton->Activate(0);

	SetTitle("");

	ackbutton->SetText("OK");

	ackbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ModalAckCB, this);
}

Kis_ModalAlert_Panel::~Kis_ModalAlert_Panel() {
}

void Kis_ModalAlert_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	ftxt->SetPosition(1, 1, in_x - 2, in_y - 3);
	ackbutton->SetPosition((in_x / 2) - 7, in_y - 2, (in_x / 2) + 7, in_y - 1);

	ackbutton->Activate(1);
	active_component = ackbutton;

	ftxt->Show();
	ackbutton->Show();
}

void Kis_ModalAlert_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	wattrset(win, text_color);
	DrawTitleBorder();

	for (unsigned int x = 0; x < pan_comp_vec.size(); x++) {
		if ((pan_comp_vec[x].comp_flags & KIS_PANEL_COMP_DRAW) == 0)
			continue;

		pan_comp_vec[x].comp->DrawComponent();
	}

	wmove(win, 0, 0);
}

void Kis_ModalAlert_Panel::AckAction() {
	// We're done
	globalreg->panel_interface->KillPanel(this);
}

void Kis_ModalAlert_Panel::ConfigureAlert(string in_title, string in_text) {
	SetTitle(in_title);
	ftxt->SetText(in_text);
}

Kis_ServerList_Picker::Kis_ServerList_Picker(GlobalRegistry *in_globalreg, 
											 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	// Grab the pointer to the list of clients maintained
	netcliref = kpinterface->FetchNetClientVecPtr();

	srvlist = new Kis_Scrollable_Table(globalreg, this);

	AddComponentVec(srvlist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));

	// TODO -- Add name parsing to KISMET proto in netclient, add support here
	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 16;
	t.title = "Host";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 5;
	t.title = "Port";
	t.alignment = 2;
	titles.push_back(t);
	t.width = 4;
	t.title = "Cntd";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 3;
	t.title = "Rdy";
	t.alignment = 0;
	titles.push_back(t);
	srvlist->AddTitles(titles);

	// Population is done during draw

	active_component = srvlist;
	srvlist->Activate(1);

	SetTitle("");

	cb_hook = NULL;
	cb_aux = NULL;
}

Kis_ServerList_Picker::~Kis_ServerList_Picker() {
}

void Kis_ServerList_Picker::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	srvlist->SetPosition(1, 1, in_x - 2, in_y - 2);

	srvlist->Show();
}

void Kis_ServerList_Picker::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	wattrset(win, text_color);

	DrawTitleBorder();

	// Grab the list of servers and populate with it.  We'll assume that the number
	// of servers, and their order, cannot change while we're in the picker, since
	// the user can't get at it.  We WILL have to handle updating the connection
	// status based on the position key.  This is NOT A SAFE ASSUMPTION for any other
	// of the picker types (like cards), so don't blind-copy this code later.
	vector<string> td;
	ostringstream osstr;
	for (unsigned int x = 0; x < netcliref->size(); x++) {
		td.clear();

		td.push_back((*netcliref)[x]->FetchHost());

		osstr << (*netcliref)[x]->FetchPort();
		td.push_back(osstr.str());
		osstr.str("");

		if ((*netcliref)[x]->Valid()) {
			td.push_back("Yes");
			if ((*netcliref)[x]->FetchConfigured() < 0)
				td.push_back("Tes");
			else
				td.push_back("No");
		} else {
			td.push_back("No");
			td.push_back("No");
		}

		srvlist->ReplaceRow(x, td);
	}


	for (unsigned int x = 0; x < pan_comp_vec.size(); x++) {
		if ((pan_comp_vec[x].comp_flags & KIS_PANEL_COMP_DRAW) == 0)
			continue;

		pan_comp_vec[x].comp->DrawComponent();
	}

	wmove(win, 0, 0);
}

int Kis_ServerList_Picker::KeyPress(int in_key) {
	int ret;
	int listkey;
	
	// Rotate through the tabbed items
	if (in_key == '\n' || in_key == '\r') {
		listkey = srvlist->GetSelected();

		// Sanity check, even though nothing should be able to change this
		// while we're open since we claim the input.
		// We could raise an alert but theres nothing the user could do 
		// about it so we'll just silently close the window
		if (listkey >= 0 && listkey < (int) netcliref->size()) {
			(*cb_hook)(globalreg, kpinterface, (*netcliref)[listkey], cb_aux);
		}

		globalreg->panel_interface->KillPanel(this);
	}

	// Otherwise the menu didn't touch the key, so pass it to the top
	// component
	if (active_component != NULL) {
		ret = active_component->KeyPress(in_key);
	}

	return 0;
}

void Kis_ServerList_Picker::ConfigurePicker(string in_title, kpi_sl_cb_hook in_hook,
											void *in_aux) {
	SetTitle(in_title);
	cb_hook = in_hook;
	cb_aux = in_aux;
}

// Addcard callback is used to actually build the addcard window once
// we've picked a source.  This will be called directly from the main
// menu handlers if there aren't any sources.
void sp_addcard_cb(KPI_SL_CB_PARMS) {
	Kis_AddCard_Panel *acp = new Kis_AddCard_Panel(globalreg, kpi);

	acp->Position((LINES / 2) - 5, (COLS / 2) - (40 / 2), 10, 40);

	acp->SetTargetClient(picked);

	kpi->AddPanel(acp);
}

int AddCardButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_AddCard_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_AddCard_Panel::Kis_AddCard_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	srctype = new Kis_Single_Input(globalreg, this);
	srciface = new Kis_Single_Input(globalreg, this);
	srcname = new Kis_Single_Input(globalreg, this);

	okbutton = new Kis_Button(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);

	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AddCardButtonCB, this);
	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AddCardButtonCB, this);

	AddComponentVec(srctype, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));
	AddComponentVec(srciface, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	AddComponentVec(srcname, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));

	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));

	tab_pos = 0;
	active_component = srctype;
	srctype->Activate(0);

	SetTitle("Add Source");

	srctype->SetLabel("Type", LABEL_POS_LEFT);
	srctype->SetTextLen(32);
	srctype->SetCharFilter(FILTER_ALPHANUMSYM);
	srctype->Show();

	srciface->SetLabel("Intf", LABEL_POS_LEFT);
	srciface->SetTextLen(32);
	srciface->SetCharFilter(FILTER_ALPHANUMSYM);
	srciface->Show();
		
	srcname->SetLabel("Name", LABEL_POS_LEFT);
	srcname->SetTextLen(32);
	srcname->SetCharFilter(FILTER_ALPHANUMSYM);
	srcname->Show();

	okbutton->SetText("Add");
	okbutton->Show();
	cancelbutton->SetText("Cancel");
	cancelbutton->Show();

	target_cli = NULL;

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	vbox->Show();

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(1);
	bbox->SetCenter(1);
	bbox->Show();

	bbox->Pack_End(cancelbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);

	vbox->Pack_End(srctype, 0, 0);
	vbox->Pack_End(srciface, 0, 0);
	vbox->Pack_End(srcname, 0, 0);
	vbox->Pack_End(bbox, 1, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
}

Kis_AddCard_Panel::~Kis_AddCard_Panel() {
}

void Kis_AddCard_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);
	vbox->SetPosition(1, 2, in_x - 1, in_y - 2);
}

void Kis_AddCard_Panel::SetTargetClient(KisNetClient *in_cli) {
	target_cli = in_cli;

	ostringstream osstr;
	osstr << "Add Source to " << in_cli->FetchHost() << ":" << in_cli->FetchPort();

	SetTitle(osstr.str());
}

void Kis_AddCard_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	wattrset(win, text_color);

	DrawTitleBorder();

	for (unsigned int x = 0; x < pan_comp_vec.size(); x++) {
		if ((pan_comp_vec[x].comp_flags & KIS_PANEL_COMP_DRAW) == 0)
			continue;

		pan_comp_vec[x].comp->DrawComponent();
	}

	wmove(win, 0, 0);
}

void Kis_AddCard_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		if (srctype->GetText() == "") {
			kpinterface->RaiseAlert("No source type",
									"No source type was provided for\n"
									"creating a new source.  A source\n"
									"type is required.\n");
			return;
		}

		if (srciface->GetText() == "") {
			kpinterface->RaiseAlert("No source interface",
									"No source interface was provided for\n"
									"creating a new source.  A source\n"
									"interface is required.\n");
			return;
		}

		if (srcname->GetText() == "") {
			kpinterface->RaiseAlert("No source name",
									"No source name was provided for\n"
									"reating a new source.  A source name\n"
									"is required.\n");
			return;
		}

		if (target_cli == NULL) {
			globalreg->panel_interface->KillPanel(this);
			return;
		}

		if (target_cli->Valid() == 0) {
			kpinterface->RaiseAlert("Server unavailable",
									"The selected server is not available.\n");
			return;
		}

		// Build a command and inject it
		string srccmd;
		srccmd = "ADDSOURCE " + srctype->GetText() + "," +
			srciface->GetText() + "," + srcname->GetText();

		target_cli->InjectCommand(srccmd);

		globalreg->panel_interface->KillPanel(this);
	} else if (in_button == cancelbutton) {
		// Cancel and close
		globalreg->panel_interface->KillPanel(this);
	}

	return; 
}

Kis_Plugin_Picker::Kis_Plugin_Picker(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	pluglist = new Kis_Scrollable_Table(globalreg, this);

	AddComponentVec(pluglist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 55;
	t.title = "Plugin";
	t.alignment = 0;
	titles.push_back(t);

	pluglist->AddTitles(titles);

	// Grab the list of plugins we have loaded already, then combine it with the
	// plugins we scan from the directories.  This is anything but fast and
	// efficient, but we're not doing it very often -- not even every window
	// draw -- so whatever.
	vector<panel_plugin_meta *> *runningplugins = kpinterface->FetchPluginVec();
	vector<string> plugdirs = kpinterface->prefs.FetchOptVec("PLUGINDIR");

	for (unsigned int x = 0; x < runningplugins->size(); x++) {
		panel_plugin_meta pm;
		pm.filename = (*runningplugins)[x]->filename;
		pm.objectname = (*runningplugins)[x]->objectname;
		pm.dlfileptr = (void *) 0x1;
		listedplugins.push_back(pm);
	}

	for (unsigned int x = 0; x < plugdirs.size(); x++) {
		DIR *plugdir;
		struct dirent *plugfile;
		string expanddir = ConfigFile::ExpandLogPath(plugdirs[x], "", "", 0, 1);

		if ((plugdir = opendir(expanddir.c_str())) == NULL) {
			continue;
		}

		while ((plugfile = readdir(plugdir)) != NULL) {
			int loaded = 0;

			if (plugfile->d_name[0] == '.')
				continue;

			string fname = plugfile->d_name;

			if (fname.find(".so") == fname.length() - 3) {
				for (unsigned int y = 0; y < listedplugins.size(); y++) {
					if (listedplugins[y].filename == expanddir + fname) {
						loaded = 1;
						break;
					}
				}

				if (loaded)
					continue;

				panel_plugin_meta pm;
				pm.filename = expanddir + fname;
				pm.objectname = fname;
				pm.dlfileptr = (void *) 0x0;
				listedplugins.push_back(pm);
			}
		}

		closedir(plugdir);
	}

	for (unsigned int x = 0; x < listedplugins.size(); x++) {
		vector<string> td;
		string en = "";

		if (listedplugins[x].dlfileptr != (void *) 0x0)
			en = " (Loaded)";

		td.push_back(listedplugins[x].objectname + en);

		pluglist->ReplaceRow(x, td);
	}

	if (listedplugins.size() > 0) {
		vector<string> td;
		td.push_back("Cancel");
		pluglist->ReplaceRow(listedplugins.size(), td);
	}

	if (listedplugins.size() == 0) {
		vector<string> td;
		td.push_back(" ");
		td.push_back("No plugins found");
		pluglist->ReplaceRow(0, td);
	}

	active_component = pluglist;
	pluglist->Activate(1);

	SetTitle("");
}

Kis_Plugin_Picker::~Kis_Plugin_Picker() {
}

void Kis_Plugin_Picker::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	pluglist->SetPosition(2, 1, in_x - 4, in_y - 2);

	pluglist->Show();
}

void Kis_Plugin_Picker::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	wattrset(win, text_color);

	for (unsigned int x = 0; x < pan_comp_vec.size(); x++) {
		if ((pan_comp_vec[x].comp_flags & KIS_PANEL_COMP_DRAW) == 0)
			continue;

		pan_comp_vec[x].comp->DrawComponent();
	}

	wmove(win, 0, 0);
}

int Kis_Plugin_Picker::KeyPress(int in_key) {
	int ret;
	int listkey;
	
	// Rotate through the tabbed items
	if (in_key == '\n' || in_key == '\r') {
		listkey = pluglist->GetSelected();

		if (listkey >= 0 && listkey <= (int) listedplugins.size()) {
			if (listkey < (int) listedplugins.size()) {
				if (listedplugins[listkey].dlfileptr == 0x0) {
					kpinterface->LoadPlugin(listedplugins[listkey].filename,
											listedplugins[listkey].objectname);
				}
			}
		}

		globalreg->panel_interface->KillPanel(this);
	}

	// Otherwise the menu didn't touch the key, so pass it to the top
	// component
	if (active_component != NULL) {
		ret = active_component->KeyPress(in_key);
	}

	return 0;
}

int NetDetailsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_NetDetails_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_NetDetails_Panel::Kis_NetDetails_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	// Details scroll list doesn't get the current one highlighted and
	// doesn't draw titles, also lock to fit inside the window
	netdetails = new Kis_Scrollable_Table(globalreg, this);
	netdetails->SetHighlightSelected(0);
	netdetails->SetLockScrollTop(1);
	netdetails->SetDrawTitles(0);
	AddComponentVec(netdetails, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								 KIS_PANEL_COMP_TAB));

	// We need to populate the titles even if we don't use them so that
	// the row handler knows how to draw them
	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 12;
	t.title = "field";
	t.alignment = 2;
	titles.push_back(t);
	t.width = 0;
	t.title = "value";
	t.alignment = 0;
	titles.push_back(t);

	netdetails->AddTitles(titles);

	active_component = netdetails;
	netdetails->Show();
	netdetails->Activate(1);

	closebutton = new Kis_Button(globalreg, this);
	closebutton->SetText("Close");
	closebutton->Show();
	closebutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetDetailsButtonCB, this);

	nextbutton = new Kis_Button(globalreg, this);
	nextbutton->SetText("Next");
	nextbutton->Show();
	nextbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetDetailsButtonCB, this);

	prevbutton = new Kis_Button(globalreg, this);
	prevbutton->SetText("Prev");
	prevbutton->Show();
	prevbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetDetailsButtonCB, this);

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(1);
	bbox->SetCenter(1);
	bbox->Show();

	bbox->Pack_End(closebutton, 0, 0);
	bbox->Pack_End(prevbutton, 0, 0);
	bbox->Pack_End(nextbutton, 0, 0);

	SetTitle("");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	vbox->Pack_End(netdetails, 1, 0);
	vbox->Pack_End(bbox, 0, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	AddComponentVec(closebutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								  KIS_PANEL_COMP_EVT));
	AddComponentVec(prevbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								  KIS_PANEL_COMP_EVT));
	AddComponentVec(nextbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								  KIS_PANEL_COMP_EVT));

	tab_pos = 0;

	last_dirty = 0;
	last_mac = mac_addr(0);
	dng = NULL;

	vector<string> td;
	td.push_back("");
	td.push_back("No network selected / Empty network selected");
	netdetails->AddRow(0, td);
}

Kis_NetDetails_Panel::~Kis_NetDetails_Panel() {

}

void Kis_NetDetails_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	// All we have to do is position the main box now
	vbox->SetPosition(1, 1, in_x - 1, in_y - 2);
}

int Kis_NetDetails_Panel::AppendNetworkInfo(int k, Kis_Display_NetGroup *tng,
											Netracker::tracked_network *net) {
	vector<string> td;
	ostringstream osstr;

	td.push_back("");
	td.push_back("");

	td[0] = "Name:";
	td[1] = tng->GetName(net);
	netdetails->AddRow(k++, td);

	td[0] = "# Networks:";
	osstr.str("");
	osstr << tng->FetchNetworkVec()->size();
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	// Use the display metanet if we haven't been given one
	if (net == NULL)
		net = dng->FetchNetwork();

	// Catch nulls just incase
	if (net == NULL)
		return k;

	td[0] = "BSSID:";
	td[1] = net->bssid.Mac2String();
	netdetails->AddRow(k++, td);

	td[0] = "First Seen:";
	osstr.str("");
	osstr << setw(14) << left << 
		(string(ctime((const time_t *) &(net->first_time)) + 4).substr(0, 15));
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Last Seen:";
	osstr.str("");
	osstr << setw(14) << left << 
		(string(ctime((const time_t *) &(net->last_time)) + 4).substr(0, 15));
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Type:";
	if (net->type == network_ap)
		td[1] = "Access Point (Managed/Infrastructure)";
	else if (net->type == network_probe)
		td[1] = "Probe (Client)";
	else if (net->type == network_turbocell)
		td[1] = "Turbocell";
	else if (net->type == network_data)
		td[1] = "Data Only (No management)";
	else if (net->type == network_mixed)
		td[1] = "Mixed (Multiple network types in group)";
	else
		td[1] = "Unknown";
	netdetails->AddRow(k++, td);

	td[0] = "Channel:";
	osstr.str("");
	if (net->channel != 0)
		osstr << net->channel;
	else
		osstr << "No channel identifying information seen";
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	if (net->lastssid != NULL) {
		td[0] = "Last ssid:";
		td[1] = net->lastssid->ssid;
		netdetails->AddRow(k++, td);

		td[0] = "Encryption:";
		td[1] = "";
		if (net->lastssid->cryptset == 0)
			td[1] = "None (Open)";
		if (net->lastssid->cryptset == crypt_wep)
			td[1] = "WEP (Privacy bit set)";
		if (net->lastssid->cryptset & crypt_layer3)
			td[1] += " Layer3";
		if (net->lastssid->cryptset & crypt_wep40)
			td[1] += " WEP40";
		if (net->lastssid->cryptset & crypt_wep104)
			td[1] += " WEP104";
		if (net->lastssid->cryptset & crypt_wpa)
			td[1] += " WPA";
		if (net->lastssid->cryptset & crypt_tkip)
			td[1] += " TKIP";
		if (net->lastssid->cryptset & crypt_psk)
			td[1] += " PSK";
		if (net->lastssid->cryptset & crypt_aes_ocb)
			td[1] += " AES-OCB";
		if (net->lastssid->cryptset & crypt_aes_ccm)
			td[1] += " AES-CCM";
		if (net->lastssid->cryptset & crypt_leap)
			td[1] += " LEAP";
		if (net->lastssid->cryptset & crypt_ttls)
			td[1] += " TTLS";
		if (net->lastssid->cryptset & crypt_tls)
			td[1] += " TLS";
		if (net->lastssid->cryptset & crypt_peap)
			td[1] += " PEAP";
		if (net->lastssid->cryptset & crypt_isakmp)
			td[1] += " ISA-KMP";
		if (net->lastssid->cryptset & crypt_pptp)
			td[1] += " PPTP";
		netdetails->AddRow(k++, td);

		td[0] = "Beacon %:";
		if (net->lastssid->beacons > net->lastssid->beaconrate)
			net->lastssid->beacons = net->lastssid->beaconrate;
		osstr.str("");
		osstr << setw(3) << left << ((double) net->lastssid->beacons /
				  (double) net->lastssid->beaconrate) * 100;
		td[1] = osstr.str();
		netdetails->AddRow(k++, td);

	} else {
		td[0] = "Encryption:";
		td[1] = "No info available";
		netdetails->AddRow(k++, td);
	}

	td[0] = "Channel:";
	if (net->channel) {
		osstr.str("");
		osstr << net->channel;
		td[1] = osstr.str();
	} else {
		td[1] = "No channel info available";
	}
	netdetails->AddRow(k++, td);

	td[0] = "Packets:";
	osstr.str("");
	osstr << net->llc_packets + net->data_packets;
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Data Pkts:";
	osstr.str("");
	osstr << net->data_packets;
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Mgmt Pkts:";
	osstr.str("");
	osstr << net->llc_packets;
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Crypt Pkts:";
	osstr.str("");
	osstr << net->crypt_packets;
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Fragments:";
	osstr.str("");
	osstr << net->fragments << "/sec";
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Retries:";
	osstr.str("");
	osstr << net->retries << "/sec";
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Bytes:";
	osstr.str("");
	if (net->datasize < 1024) 
		osstr << net->datasize << "B";
	else if (net->datasize < (1024 * 1024)) 
		osstr << (int) (net->datasize / 1024) << "K";
	else 
		osstr << (int) (net->datasize / 1024 / 1024) << "M";
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	return k;
}

void Kis_NetDetails_Panel::DrawPanel() {
	Kis_Display_NetGroup *tng;
	Netracker::tracked_network *meta, *tmeta;
	int update = 0;
	vector<string> td;

	int k = 0;

	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	// Figure out if we've changed
	tng = kpinterface->FetchMainPanel()->FetchSelectedNetgroup();
	if (tng != NULL) {
		if (dng == NULL) {
			dng = tng;
			update = 1;
		} else {
			meta = dng->FetchNetwork();
			tmeta = tng->FetchNetwork();

			if (meta == NULL && tmeta != NULL) {
				// We didn't have a valid metagroup before - we get the new one
				dng = tng;
				update = 1;
			} else if (tmeta != NULL && last_mac != tmeta->bssid) {
				// We weren't the same network before - we get the new one
				dng = tng;
				update = 1;
			} else if (meta != NULL && last_dirty < meta->last_time) {
				// The network has changed time - just update
				update = 1;
			}
		}
	} else if (dng != NULL) {
		// We've lost a selected network entirely, drop to null and update
		dng = NULL;
		update = 1;
	}

	if (update) {
		netdetails->Clear();
		meta = dng->FetchNetwork();
		k = 0;
		td.push_back("");
		td.push_back("");

		if (dng != NULL) {
			td[0] = "";
			td[1] = "Group";
			netdetails->AddRow(k++, td);

			k = AppendNetworkInfo(k, tng, NULL);
		} else {
			td[0] = "";
			td[1] = "No network selected / Empty network selected";
			netdetails->AddRow(0, td);
		}
	}

	wattrset(win, text_color);
	for (unsigned int x = 0; x < pan_comp_vec.size(); x++) {
		if ((pan_comp_vec[x].comp_flags & KIS_PANEL_COMP_DRAW) == 0)
			continue;

		pan_comp_vec[x].comp->DrawComponent();
	}
}

void Kis_NetDetails_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == closebutton) {
		globalreg->panel_interface->KillPanel(this);
	} else if (in_button == nextbutton) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_DOWN);
		dng = NULL;
	} else if (in_button == prevbutton) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_UP);
		dng = NULL;
	}
}

#endif

