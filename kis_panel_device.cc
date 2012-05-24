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

#include "kis_panel_device.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"
#include "kis_panel_widgets.h"
#include "kis_devicelist_sort.h"

#include "soundcontrol.h"

void KDL_TIME(CLIPROTO_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->Proto_TIME();
}

void KDL_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->NetClientAdd(netcli, add);
}

void KDL_ConfigureCli(CLICONF_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->NetClientConfigure(kcli, recon);
}

void KDL_DeviceRX(DEVICERX_PARMS) {
	((Kis_Devicelist *) aux)->DeviceRX(device);
}

void KDL_PhyRX(PHYRX_PARMS) {
	((Kis_Devicelist *) aux)->PhyRX(phy_id);
}

void KDL_FilterMenuCB(MENUITEM_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->FilterMenuAction(menuitem);
}

void KDL_ColorMenuCB(MENUITEM_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->SpawnColorPrefWindow();
}

void KDL_ViewMenuCB(MENUITEM_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->ViewMenuAction(menuitem);
}

void KDL_ColumnMenuCB(MENUITEM_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->SpawnColumnPrefWindow(false);
}

void KDL_ExtraMenuCB(MENUITEM_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->SpawnColumnPrefWindow(true);
}

void KDL_SortMenuCB(MENUITEM_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->SortMenuAction(menuitem);
}

void KDL_ColumnRefresh(KISPANEL_COMPLETECB_PARMS) {
	if (rc)
		((Kis_Devicelist *) auxptr)->ParseColumnConfig();
}

string KDL_Common_Column_Cb(KDL_COLUMN_PARMS) {
	return ((Kis_Devicelist *) aux)->CommonColumn(device, columnid, header);
}

string KDL_Common_Subcolumn_Cb(KDL_COLUMN_PARMS) {
	return ((Kis_Devicelist *) aux)->CommonSubColumn(device, columnid, header);
}

void KDL_Common_Sort(KDL_SORT_PARMS) {
	stable_sort(dev_vec->begin(), dev_vec->end(), 
				KDL_Sort_Proxy(*((KDL_Sort_Abstract *) aux)));
}

Kis_Devicelist::Kis_Devicelist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {

	globalreg->InsertGlobal("MAIN_DEVICELIST", this);

	kpinterface = in_panel->FetchPanelInterface();

	devicetracker = (Client_Devicetracker *) globalreg->FetchGlobal("CLIENT_DEVICE_TRACKER");

	if (devicetracker == NULL) {
		fprintf(stderr, "FATAL OOPS: Missing devicetracker in devicelist\n");
		exit(1);
	}

	cli_addref = kpinterface->Add_NetCli_AddCli_CB(KDL_AddCli, (void *) this);

	devcomp_ref_common = devicetracker->RegisterDeviceComponent("COMMON");

	draw_dirty = false;

	// Get new devices
	newdevref = devicetracker->RegisterDevicerxCallback(KDL_DeviceRX, this);
	// Get new phys but not phy updates
	newphyref = devicetracker->RegisterPhyrxCallback(KDL_PhyRX, this, false);

	viewable_lines = 0;
	viewable_cols = 0;

	first_line = last_line = selected_line = hpos = 0;

	next_column_id = 1;
	next_sort_id = 1;

	// Register all our local columns
	col_active = RegisterColumn("Active", "Recently active", 1,
								LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_name = RegisterColumn("Name", "Name", 20,
							  LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_phy = RegisterColumn("Phy", "Phy", 10,
							 LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_addr = RegisterColumn("Address", "MAC or Identifier", 17,
							  LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_type = RegisterColumn("Typestring", "Device type", 10,
							  LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_basictype = RegisterColumn("BasicType", "Basic type", 10,
								   LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_cryptstr = RegisterColumn("Cryptstring", "Device encryption", 4,
								  LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_basiccrypt = RegisterColumn("BasicCrypt", "Basic encryption", 1,
								   LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_packets = RegisterColumn("Packets", "Packets", 5,
								 LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_llc = RegisterColumn("LinkPackets", "Link packets", 5,
							 LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_error = RegisterColumn("ErrorPackets", "Error packets", 5,
							   LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_data = RegisterColumn("DataPackets", "Data packets", 5,
							  LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_crypt = RegisterColumn("CryptPackets", "Encrypted packets", 5,
							   LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_datasize = RegisterColumn("Datasize", "Data size", 6,
								  LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_newpackets = RegisterColumn("Packetrate", "Packet rate", 5,
									LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_channel = RegisterColumn("Channel", "Channel", 4,
								 LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_freq = RegisterColumn("Frequency", "Frequency", 4,
							  LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_alerts = RegisterColumn("Alerts", "Number of alerts", 3,
								LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_manuf = RegisterColumn("Manuf", "Manufacturer", 12,
							   LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);

	// Subcolumns take as much room as they want, it's not fixed
	col_sub_lastseen = RegisterColumn("LastSeen", "Last seen time", 0, 
									  LABEL_POS_LEFT, KDL_Common_Subcolumn_Cb, 
									  this, true);
	col_sub_addr = RegisterColumn("Address", "MAC or identifier", 0, 
								  LABEL_POS_LEFT, KDL_Common_Subcolumn_Cb, this, true);
	col_sub_basiccrypt = RegisterColumn("BasicCrypt", "Basic encryption info", 0, 
										LABEL_POS_LEFT, KDL_Common_Subcolumn_Cb, 
										this, true);
	col_sub_ip = RegisterColumn("IP", "IP data", 0, 
								LABEL_POS_LEFT, KDL_Common_Subcolumn_Cb, this, true);
	col_sub_manuf = RegisterColumn("Manuf", "Manufacturer type", 0, 
								   LABEL_POS_LEFT, KDL_Common_Subcolumn_Cb, this, true);
	col_sub_seenby = RegisterColumn("Seenby", "Capture sources list", 0, 
								   LABEL_POS_LEFT, KDL_Common_Subcolumn_Cb, this, true);
	col_sub_phy = RegisterColumn("Phyname", "Phy layer name", 0,
								 LABEL_POS_LEFT, KDL_Common_Subcolumn_Cb, this, true);
	

	// We now resolve via the globalreg name-resolution
	menu = (Kis_Menu *) globalreg->FetchGlobal("KISUI_MAIN_MENU");
	mn_filter = menu->FindMenu("Filter");

	// Don't show the filter menu until we have multiple phy types
	menu->SetMenuVis(mn_filter, 0);

	mn_preferences = menu->FindMenu("Preferences");

	mi_colorpref = 
		menu->AddMenuItem("Device Colors", mn_preferences, 'c');
	mi_columnpref =
		menu->AddMenuItem("Device Columns", mn_preferences, 'd');
	mi_extrapref =
		menu->AddMenuItem("Device Extras", mn_preferences, 'e');

	menu->SetMenuItemCallback(mi_colorpref, KDL_ColorMenuCB, this);
	menu->SetMenuItemCallback(mi_columnpref, KDL_ColumnMenuCB, this);
	menu->SetMenuItemCallback(mi_extrapref,KDL_ExtraMenuCB, this);

	for (int x = 0; x < KDL_COLOR_MAX; x++)
		color_map[x] = 0;
	color_inactive = 0;

	mn_sort = menu->FindMenu("Sort");

	RegisterSort("First time", "Sort by first time seen",
				 KDL_Common_Sort, new KDL_Sort_First(devcomp_ref_common));
	RegisterSort("First time (desc)", "Sort by first time (descending)",
				 KDL_Common_Sort, new KDL_Sort_FirstDesc(devcomp_ref_common));
	RegisterSort("Last time", "Sort by last time seen",
				 KDL_Common_Sort, new KDL_Sort_Last(devcomp_ref_common));
	RegisterSort("Last time (desc)", "Sort by last time (descending)",
				 KDL_Common_Sort, new KDL_Sort_LastDesc(devcomp_ref_common));
	RegisterSort("Basic crypt", "Sort by basic encryption",
				 KDL_Common_Sort, new KDL_Sort_Crypt(devcomp_ref_common));
	RegisterSort("Basic Type", "Sort by type",
				 KDL_Common_Sort, new KDL_Sort_Type(devcomp_ref_common));
	RegisterSort("Channel", "Sort by channel",
				 KDL_Common_Sort, new KDL_Sort_Channel(devcomp_ref_common));
	RegisterSort("Packets", "Sort by number of packets",
				 KDL_Common_Sort, new KDL_Sort_Packets(devcomp_ref_common));
	RegisterSort("Packets (desc)", "Sort by number of packets (descending)",
				 KDL_Common_Sort, new KDL_Sort_PacketsDesc(devcomp_ref_common));
	RegisterSort("Phy type", "Sort by Phy layer type",
				 KDL_Common_Sort, new KDL_Sort_Phy(devcomp_ref_common));

	Kis_Main_Panel *mainp = (Kis_Main_Panel *) globalreg->FetchGlobal("KISUI_MAIN_PANEL");

	int mi_next = mainp->FetchLastViewMenuItem();

	mn_view = menu->FindMenu("View");
	mi_next = mi_view_network =
		menu->AddMenuItem("Display Networks", mn_view, 'e', mi_next);
	mi_next = mi_view_wireless = 
		menu->AddMenuItem("Display Wireless", mn_view, 'w', mi_next);
	mi_next = mi_view_devices =
		menu->AddMenuItem("Display Devices", mn_view, 'd', mi_next);

	menu->SetMenuItemCheckSymbol(mi_view_network, '*');
	menu->SetMenuItemCheckSymbol(mi_view_wireless, '*');
	menu->SetMenuItemCheckSymbol(mi_view_devices, '*');

	menu->SetMenuItemCallback(mi_view_network, KDL_ViewMenuCB, this);
	menu->SetMenuItemCallback(mi_view_wireless, KDL_ViewMenuCB, this);
	menu->SetMenuItemCallback(mi_view_devices, KDL_ViewMenuCB, this);

	mainp->SetLastViewMenuItem(mi_next);

	string viewmode = StrLower(kpinterface->prefs->FetchOpt("MAIN_VIEWSTYLE"));

	if (viewmode == "network") {
		mi_lastview = mi_view_network;
		menu->SetMenuItemChecked(mi_view_network, 1);
		display_mode = KDL_DISPLAY_NETWORKS;
	} else if (viewmode == "device") {
		mi_lastview = mi_view_devices;
		menu->SetMenuItemChecked(mi_view_devices, 1);
		display_mode = KDL_DISPLAY_DEVICES;
	} else if (viewmode == "wirelessdevice") {
		mi_lastview = mi_view_wireless;
		menu->SetMenuItemChecked(mi_view_wireless, 1);
		display_mode = KDL_DISPLAY_WIRELESSDEVICES;
	} else {
		mi_lastview = mi_view_network;
		menu->SetMenuItemChecked(mi_view_network, 1);
		display_mode = KDL_DISPLAY_NETWORKS;
	}

	devicetracker->PanelInitialized();

	ParseColumnConfig();
}

void Kis_Devicelist::ParseColumnConfig() {
	string cols = 
		kpinterface->prefs->FetchOpt("devlist_columns");

	string extcols =
		kpinterface->prefs->FetchOpt("devlist_extline");

	if (cols == "") {
		cols = "active,phy,name,type,basiccrypt,address,"
			"packets,datasize,channel,alerts";
		kpinterface->prefs->SetOpt("devlist_columns", cols, 1);
	}

	if (extcols == "") {
		extcols = "lastseen,basiccrypt,manuf,seenby,phyname";
		kpinterface->prefs->SetOpt("devlist_extline", extcols, 1);
	}

	vector<string> toks = StrTokenize(cols, ",");
	string t;

	configured_column_vec.clear();

	for (unsigned int x = 0; x < toks.size(); x++) {
		t = StrLower(toks[x]);
		bool set = 0;

		// Sucks but only happens rarely
		for (map<int, kdl_column *>::iterator i = registered_column_map.begin();
			 i != registered_column_map.end(); ++i) {
			if (StrLower(i->second->name) == t && !i->second->subcolumn) {
				set = true;
				configured_column_vec.push_back(i->second);
				break;
			}
		}

		if (!set) {
			_MSG("Unknown column '" + t + "'", MSGFLAG_INFO);
		}
	}

	toks = StrTokenize(extcols, ",");

	configured_subcolumn_vec.clear();

	for (unsigned int x = 0; x < toks.size(); x++) {
		t = StrLower(toks[x]);
		bool set = 0;

		// Sucks but only happens rarely
		for (map<int, kdl_column *>::iterator i = registered_column_map.begin();
			 i != registered_column_map.end(); ++i) {
			if (StrLower(i->second->name) == t && i->second->subcolumn) {
				set = true;
				configured_subcolumn_vec.push_back(i->second);
				break;
			}
		}

		if (!set) {
			_MSG("Unknown extraline option '" + t + "'", MSGFLAG_INFO);
		}
	}

	for (unsigned int x = 0; x < draw_vec.size(); x++)
		draw_vec[x]->dirty = true;

	draw_dirty = true;

	colheadercache = "";
}

Kis_Devicelist::~Kis_Devicelist() {
	globalreg->InsertGlobal("MAIN_DEVICELIST", NULL);
	devicetracker->RemoveDevicerxCallback(newdevref);
	devicetracker->RemovePhyrxCallback(newphyref);
	kpinterface->Remove_Netcli_AddCli_CB(cli_addref);
	kpinterface->Remove_All_Netcli_Conf_CB(KDL_ConfigureCli);
}

void Kis_Devicelist::SetViewMode(int in_mode) {
	string mode = "network";
	if (in_mode != display_mode) {
		if (in_mode == KDL_DISPLAY_NETWORKS)
			mode = "network";
		else if (in_mode == KDL_DISPLAY_WIRELESSDEVICES)
			mode = "wirelessdevice";
		else if (in_mode == KDL_DISPLAY_DEVICES)
			mode = "device";

		kpinterface->prefs->SetOpt("MAIN_VIEWSTYLE", mode, 1);

		display_mode = in_mode;
		draw_dirty = true;
		RefreshDisplayList();
	}
}

void Kis_Devicelist::NetClientAdd(KisNetClient *in_cli, int add) {
	// TODO figure out how to resolve PHY#s on reconnect
	if (add == 0)
		return;

	in_cli->AddConfCallback(KDL_ConfigureCli, 1, this);
}

void Kis_Devicelist::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	if (in_cli->RegisterProtoHandler("TIME", "timesec",
									 KDL_TIME, this) < 0) {
		_MSG("KDL couldn't register *TIME?  Something is broken, badly.",
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}
}

void Kis_Devicelist::DeviceRX(kis_tracked_device *device) {
	map<mac_addr, kdl_display_device *>::iterator ddmi =
		display_dev_map.find(device->key);

	// Updated devices force us to re-sort
	draw_dirty = true;

	// TODO - intelligent add to display list, etc
	if (ddmi == display_dev_map.end()) {
		kdl_display_device *dd = new kdl_display_device;
		dd->device = device;
		dd->dirty = true;

		display_dev_map[device->key] = dd;
		display_dev_vec.push_back(dd);

		// Determine if we put it in our draw vec
		kis_device_common *common =
			(kis_device_common *) device->fetch(devcomp_ref_common);

		// No common?  Fail
		if (common == NULL) {
			// fprintf(stderr, "debug - DeviceRX no common\n");
			return;
		}

		// Don't add it to our device list if it's not a network
		// If we're in device mode we get everything so don't filter
		if (display_mode == KDL_DISPLAY_NETWORKS &&
			(common->basic_type_set & KIS_DEVICE_BASICTYPE_AP) == 0) {
			// fprintf(stderr, "debug - Devicerx display network, type not network\n");
			return;
		}

		// Don't add it to our device list if it's flagged as wired
		if (display_mode == KDL_DISPLAY_WIRELESSDEVICES &&
			(common->basic_type_set & (KIS_DEVICE_BASICTYPE_WIRED)) != 0)
			return;


		// See if we're filtered, but only if we have more than one phy
		if (filter_phy_map.size() > 1) {
			map<int, bool>::iterator fpmi =
				filter_phy_map.find(device->phy_type);
			if (fpmi != filter_phy_map.end() &&
				fpmi->second)
				return;
		}

		// Add it to the list of networks we consider for display
		draw_vec.push_back(dd);
	} else {
		ddmi->second->dirty = 1;
	}
}

void Kis_Devicelist::PhyRX(int phy_id) {
	string phyname = devicetracker->FetchPhyName(phy_id);

	if (phyname == "") {
		_MSG("KDL got new phy but empty phyname", MSGFLAG_ERROR);
		return;
	}

	// If we've never seen this phyname or we want to show it, set the
	// filter map to 0 to allow it
	if (kpinterface->prefs->FetchOptBoolean("DEVICEFILTER_" + phyname, 1)) {
		filter_phy_map[phy_id] = false;
	} else {
		filter_phy_map[phy_id] = true;
	}

	if (filter_phy_map.size() > 1)
		menu->SetMenuVis(mn_filter, 1);

	int mi_filteritem = 
		menu->AddMenuItem(phyname, mn_filter, 0);

	menu->SetMenuItemChecked(mi_filteritem, !(filter_phy_map[phy_id]));
	
	menu->SetMenuItemCallback(mi_filteritem, KDL_FilterMenuCB, this);

	// Link menu ID to phy ID
	menu_phy_map[mi_filteritem] = phy_id;

}

int Kis_Devicelist::RegisterSort(string in_name, string in_desc, 
								   KDL_Sort_Callback in_cb, void *in_aux) {
	for (map<int, kdl_sort *>::iterator x = sort_map.begin();
		 x != sort_map.end(); ++x) {
		if (StrLower(x->second->name) == StrLower(in_name))
			return x->first;
	}

	next_sort_id++;

	kdl_sort *news = new kdl_sort;
	news->name = in_name;
	news->description = in_desc;
	news->id = next_sort_id;
	news->callback = in_cb;
	news->cb_aux = in_aux;

	news->menu_id =
		menu->AddMenuItem(news->name, mn_sort, 0);

	menu->SetMenuItemCallback(news->menu_id, KDL_SortMenuCB, this);

	menu->SetMenuItemCheckSymbol(news->menu_id, '*');

	if (StrLower(kpinterface->prefs->FetchOpt("MAIN_SORT")) == StrLower(in_name)) {
		current_sort = news;
		menu->SetMenuItemChecked(news->menu_id, 1);
	}

	sort_map[news->id] = news;

	return news->id;
}

void Kis_Devicelist::RemoveSort(int in_id) {
	if (sort_map.find(in_id) != sort_map.end()) {
		kdl_sort *s = sort_map[in_id];

		// Make the menu item invisible
		menu->SetMenuItemVis(s->menu_id, 0);

		delete(s);
		sort_map.erase(in_id);
	}
}

int Kis_Devicelist::RegisterColumn(string in_name, string in_desc, 
								   int in_width, KisWidget_LabelPos in_align,
								   KDL_Column_Callback in_cb, void *in_aux,
								   bool in_sub) {
	kdl_column *newc = NULL;

	for (map<int, kdl_column *>::iterator x = registered_column_map.begin();
		 x != registered_column_map.end(); ++x) {
		if (StrLower(x->second->name) == StrLower(in_name) &&
			x->second->subcolumn == in_sub) {
			// If we don't match auxptr we need to overwrite this column
			if (x->second->cb_aux != in_aux)
				newc = x->second;
			else
				return x->first;
		}
	}

	// Otherwise we're replacing a column
	if (newc == NULL) {
		newc = new kdl_column;
		next_column_id++;
	}

	newc->name = in_name;
	newc->description = in_desc;
	newc->width = in_width;
	newc->subcolumn = in_sub;
	newc->id = next_column_id;
	newc->callback = in_cb;
	newc->cb_aux = in_aux;

	registered_column_map[newc->id] = newc;

	return newc->id;
}

void Kis_Devicelist::RemoveColumn(int in_id) {
	if (registered_column_map.find(in_id) != registered_column_map.end()) {
		kdl_column *c = registered_column_map[in_id];

		for (unsigned int x = 0; x < configured_column_vec.size(); x++) {
			if (configured_column_vec[x] == c) {
				configured_column_vec.erase(configured_column_vec.begin() + x);
				x = 0;
			}
		}
		
		for (unsigned int x = 0; x < configured_subcolumn_vec.size(); x++) {
			if (configured_subcolumn_vec[x] == c) {
				configured_subcolumn_vec.erase(configured_subcolumn_vec.begin() + x);
				x = 0;
			}
		}

		delete registered_column_map[in_id];
		registered_column_map.erase(in_id);
	}
}

kdl_column *Kis_Devicelist::FetchColumn(int in_id) {
	map<int, kdl_column *>::iterator ci = registered_column_map.find(in_id);

	if (ci == registered_column_map.end())
		return NULL;

	return ci->second;
}

void Kis_Devicelist::DrawComponent() {
	if (visible == 0)
		return;

	parent_panel->ColorFromPref(color_inactive, "panel_textdis_color");

	parent_panel->InitColorPref("devlist_normal_color", "green,black");
	parent_panel->ColorFromPref(color_map[KDL_COLOR_NORMAL],
								"devlist_normal_color");

	parent_panel->InitColorPref("devlist_crypt_color", "yellow,black");
	parent_panel->ColorFromPref(color_map[KDL_COLOR_CRYPT],
								"devlist_crypt_color");

	parent_panel->InitColorPref("devlist_decrypt_color", "hi-magenta,black");
	parent_panel->ColorFromPref(color_map[KDL_COLOR_DECRYPT],
								"devlist_decrypt_color");

	parent_panel->InitColorPref("devlist_header_color", "blue,black");
	parent_panel->ColorFromPref(color_map[KDL_COLOR_HEADER],
								"devlist_header_color");

	parent_panel->InitColorPref("devlist_insecure_color", "red,black");
	parent_panel->ColorFromPref(color_map[KDL_COLOR_INSECURE],
								"devlist_insecure_color");

	string hdr = colheadercache;

	if (hdr == "") {
		hdr = " ";

		for (unsigned int x = hpos; x < configured_column_vec.size(); x++) {
			/*
			   if (hdr.length() + configured_column_vec[x]->width > viewable_cols)
			   break;
			   */

			hdr += "\004u" +
				(*(configured_column_vec[x]->callback))(
							NULL,
							configured_column_vec[x]->cb_aux,
							globalreg,
							configured_column_vec[x]->id,
							true) + 
				"\004U ";
		}

		colheadercache = hdr;
	} else {
		// hdr[0] = 'C';
	}

	if (active)
		wattrset(window, color_map[KDL_COLOR_HEADER]);

	Kis_Panel_Specialtext::Mvwaddnstr(window, sy, sx, hdr.c_str(), 
									  lx - 1, parent_panel);

	if (active)
		wattrset(window, color_map[KDL_COLOR_NORMAL]);

	if (kpinterface->FetchNetClient() == NULL ||
		(kpinterface->FetchNetClient() != NULL && !kpinterface->FetchNetClient()->Valid())) {
		mvwaddnstr(window, sy + 2, sx + 1, 
				   "[ --- Not connected to a Kismet server --- ]", lx);
		return;
	} else if (display_dev_vec.size() == 0) {
		mvwaddnstr(window, sy + 2, sx + 1, 
				   "[ --- No devices seen by Kismet --- ]", 
				   ex - sx);
		return;
	}

	if (draw_vec.size() == 0 && display_dev_vec.size() != 0) {
		Kis_Panel_Specialtext::Mvwaddnstr(window, sy + 2, sx + 1, 
			"[ --- All devices filtered, change filtering with View->Filter --- ]", 
										  lx - 1, parent_panel);
		return;
	}

	if (draw_dirty && current_sort != NULL) {
		(*(current_sort->callback))(&draw_vec, current_sort->cb_aux, 
									current_sort, globalreg);
		draw_dirty = false;
	}

	int dy = 0;
	string display_line;
	string extra_line;

	for (unsigned int x = first_line; dy < viewable_lines && 
		 x < draw_vec.size(); x++) {

		kis_device_common *common = NULL;
		common = 
			(kis_device_common *) draw_vec[x]->device->fetch(devcomp_ref_common);

		if (common == NULL)
			continue;

		int oft = globalreg->timestamp.tv_sec - common->last_time;

		if (!draw_vec[x]->dirty && draw_vec[x]->columncache != "" && oft > 6) {
			display_line = draw_vec[x]->columncache;
			extra_line = draw_vec[x]->extcache;
			// display_line[0] = 'C';
		} else {
			display_line = " ";

			for (unsigned int c = hpos; c < configured_column_vec.size(); c++) {
				if ((int) (display_line.length() + 
						   configured_column_vec[c]->width) > viewable_cols)
					break;

				display_line += 
					(*(configured_column_vec[c]->callback))(
											draw_vec[x],
											configured_column_vec[c]->cb_aux,
											globalreg,
											configured_column_vec[c]->id,
											false) + 
									" ";
			}
		
			if ((int) display_line.length() < viewable_cols)
				display_line += string(viewable_cols - display_line.length(), ' ');

			// Clear the extra cache if we knew we were dirtied
			extra_line = "";

			draw_vec[x]->dirty = false;
			draw_vec[x]->columncache = display_line;
		}

		dy++;

		// We have to look at the device status for coloring here, external
		// of columns.  Only color if active.
		if (active) {
			wattrset(window, color_map[KDL_COLOR_NORMAL]);

			if (common != NULL) {
				if (common->basic_crypt_set) {
					// fprintf(stderr, "draw %s cryptset %d\n", draw_vec[x]->device->key.Mac2String().c_str(), common->basic_crypt_set);
					wattrset(window, color_map[KDL_COLOR_CRYPT]);
				}
			}
		}

		if (selected_line == (int) x && active) {
			wattron(window, WA_REVERSE);

			// Recompute the extra line
			if (extra_line == "") {
				extra_line = " ";

				for (unsigned int c = 0; c < configured_subcolumn_vec.size(); c++) {
					if ((int) extra_line.length() > viewable_cols)
						break;

					string f =  
						(*(configured_subcolumn_vec[c]->callback))(
										draw_vec[x],
										configured_subcolumn_vec[c]->cb_aux,
										globalreg,
										configured_subcolumn_vec[c]->id,
										false);

					if (f != "")
						extra_line += " [" + f + "]";
				}

				if ((int) extra_line.length() < viewable_cols)
					extra_line +=  string(viewable_cols - extra_line.length(), ' ');

				draw_vec[x]->extcache = extra_line;
			}
		}

		Kis_Panel_Specialtext::Mvwaddnstr(window, sy + dy, sx, 
										  display_line, 
										  lx - 1, parent_panel);

		if (selected_line == (int) x && active) {
			dy++;
			Kis_Panel_Specialtext::Mvwaddnstr(window, sy + dy, sx, 
											  extra_line, 
											  lx - 1, parent_panel);
			
			wattroff(window, WA_REVERSE);
		}

		last_line = x;

	}
}

void Kis_Devicelist::Activate(int subcomponent) {
	// _MSG("Activate devlist", MSGFLAG_INFO);
	active = 1;
}

void Kis_Devicelist::Deactivate() {
	active = 0;
}

void Kis_Devicelist::Proto_TIME() {
	DrawComponent();

	for (unsigned int x = 0; x < display_dev_vec.size(); x++) {
		display_dev_vec[x]->dirty = false;
	}
}

int Kis_Devicelist::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	// _MSG("Keypress devlist", MSGFLAG_INFO);

	if (in_key == KEY_DOWN || in_key == '+') {
		if (selected_line < first_line || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}

		// If we're at the bottom and can go further, slide the selection
		// and the first line down
		if (selected_line == last_line &&
			last_line < (int) draw_vec.size() - 1) {
			selected_line++;
			first_line++;
		} else if (selected_line != last_line) {
			// Otherwise we just slide the selected line down
			selected_line++;
		}
	} else if (in_key == KEY_UP || in_key == '-') {
		if (selected_line < first_line || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}

		// if we're at the top and can go further, slide the selection
		// and first line of our view up
		if (selected_line == first_line && first_line > 0) {
			selected_line--;
			first_line--;
		} else if (selected_line != first_line) {
			// just move the selected line up
			selected_line--;
		}
	} else if (in_key == KEY_PPAGE) {
		if (selected_line < 0 || selected_line > last_line) {
			selected_line = first_line;
			_MSG("OOB, selected=first, " + IntToString(selected_line), MSGFLAG_INFO);
			return 0;
		}
	
		_MSG("setting first,  " + IntToString( kismax(0, first_line - viewable_lines)) + " first: " + IntToString(first_line) + " viewable: " + IntToString(viewable_lines), MSGFLAG_INFO);
		first_line = kismax(0, first_line - viewable_lines);
		selected_line = first_line;
	} else if (in_key == KEY_NPAGE) {
		if (selected_line < 0 || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}

		first_line = kismin((int) draw_vec.size() - 1, 
							first_line + viewable_lines);
		selected_line = first_line;
	} else if (in_key == KEY_ENTER || in_key == '\n') {
		Kis_DevDetails_Panel *dp =
			new Kis_DevDetails_Panel(globalreg, kpinterface);
		dp->Position(WIN_CENTER(LINES, COLS));

		if (selected_line >= 0 && selected_line < (int) display_dev_vec.size()) {
			kdl_display_device *dd = draw_vec[selected_line];
			kis_tracked_device *sd = dd->device;

			dp->SetTargetDevice(dd);

			if (sd != NULL) {
				Client_Phy_Handler *cliphy =
					devicetracker->FetchPhyHandler(sd->phy_type);

				if (cliphy != NULL)
					cliphy->PanelDetails(dp, sd);
			}
		}

		kpinterface->AddPanel(dp);
	}

	return 0;
}

int Kis_Devicelist::MouseEvent(MEVENT *mevent) {
	int mwx, mwy;
	getbegyx(window, mwy, mwx);

	mwx = mevent->x - mwx;
	mwy = mevent->y - mwy;

	// Not in our bounds at all
	if ((mevent->bstate != 4 && mevent->bstate != 8) || 
		mwy < sy || mwy > ey || mwx < sx || mwx > ex)
		return 0;

	// Not in a selectable mode, we consume it but do nothing
//	if (sort_mode == netsort_autofit)
//		return 1;
//
	// Modify coordinates to be inside the widget
	mwy -= sy;

	int vpos = first_line + mwy - 1; 

	if ((int) selected_line < vpos)
		vpos--;

	if (vpos < 0 || vpos > (int) draw_vec.size())
		return 1;

	// Double-click, trigger the activation callback
	/*
	if ((last_mouse_click - globalreg->timestamp.tv_sec < 1 &&
		 selected_line == vpos) || mevent->bstate == 8) {
		if (cb_activate != NULL) 
			(*cb_activate)(this, 1, cb_activate_aux, globalreg);
		return 1;
	}
	*/

	last_mouse_click = globalreg->timestamp.tv_sec;

	// Otherwise select it and center the network list on it
	selected_line = vpos;

	first_line = selected_line - (ly / 2);

	if (first_line < 0)
		first_line = 0;

	return 1;
}

void Kis_Devicelist::SetPosition(int isx, int isy, int iex, int iey) {
	Kis_Panel_Component::SetPosition(isx, isy, iex, iey);

	viewable_lines = ly - 1;
	viewable_cols = ex;

	colheadercache = "";
	RefreshDisplayList();
}

string Kis_Devicelist::CommonColumn(kdl_display_device *in_dev, int in_columnid, 
									bool header) {
	char hdr[16];
	char buf[64];
	kdl_column *col = NULL;

	map<int, kdl_column *>::iterator ci = registered_column_map.find(in_columnid);

	if (ci == registered_column_map.end())
		return "[INVALID]";

	kis_device_common *common = NULL;

	col = ci->second;

	if (col->alignment == LABEL_POS_LEFT)
		snprintf(hdr, 16, "%%%ds", col->width);
	else
		snprintf(hdr, 16, "%%-%d.%ds", col->width, col->width);

	snprintf(buf, 64, hdr, "Unk");

	if (!header) {
		if (in_dev != NULL && in_dev->device != NULL)
			common = (kis_device_common *) in_dev->device->fetch(devcomp_ref_common);

		if (common == NULL) {
			snprintf(buf, 64, hdr, "NULL");
			return buf;
		}
	}

	if (in_columnid == col_active) {
		if (header) {
			snprintf(buf, 64, "A");
		} else {
			int oft = globalreg->timestamp.tv_sec - common->last_time;
			
			if (oft < 3)
				snprintf(buf, 64, "!");
			else if (oft < 6)
				snprintf(buf, 64, ".");
			else
				snprintf(buf, 64, " ");
		}
	} else if (in_columnid == col_phy) {
		if (header) {
			snprintf(buf, 64, hdr, "Phy");
		} else {
			snprintf(buf, 64, hdr, devicetracker->FetchPhyName(in_dev->device->phy_type).c_str());
		}
	} else if (in_columnid == col_addr) {
		if (header) {
			snprintf(buf, 64, hdr, "Addr");
		} else {
			snprintf(buf, 64, hdr, in_dev->device->key.Mac2String().c_str());
		}
	} else if (in_columnid == col_name) {
		if (header) {
			snprintf(buf, 64, hdr, "Name");
		} else {
			snprintf(buf, 64, hdr, common->name.c_str());
		}
	} else if (in_columnid == col_type) {
		if (header) {
			snprintf(buf, 64, hdr, "Type");
		} else {
			if (common->type_string != "") {
				snprintf(buf, 64, hdr, common->type_string.c_str());
			} else {
				if (common->basic_type_set & KIS_DEVICE_BASICTYPE_PEER)
					snprintf(buf, 64, hdr, "Peer");
				else if (common->basic_type_set & KIS_DEVICE_BASICTYPE_AP)
					snprintf(buf, 64, hdr, "AP");
				else if (common->basic_type_set & KIS_DEVICE_BASICTYPE_WIRED)
					snprintf(buf, 64, hdr, "Wired");
				else if (common->basic_type_set & KIS_DEVICE_BASICTYPE_CLIENT)
					snprintf(buf, 64, hdr, "Client");
			}
		}
	} else if (in_columnid == col_basictype) {
		if (header) {
			snprintf(buf, 64, hdr, "Basic");
		} else {
			if (common->basic_type_set == KIS_DEVICE_BASICTYPE_DEVICE)
				snprintf(buf, 64, hdr, "Device");
	
			// Order important for display
			if (common->basic_type_set & KIS_DEVICE_BASICTYPE_PEER)
				snprintf(buf, 64, hdr, "Peer");
			else if (common->basic_type_set & KIS_DEVICE_BASICTYPE_AP)
				snprintf(buf, 64, hdr, "AP");
			else if (common->basic_type_set & KIS_DEVICE_BASICTYPE_WIRED)
				snprintf(buf, 64, hdr, "Wired");
			else if (common->basic_type_set & KIS_DEVICE_BASICTYPE_CLIENT)
				snprintf(buf, 64, hdr, "Client");
		} 
	} else if (in_columnid == col_cryptstr) {
		if (header) {
			snprintf(buf, 64, hdr, "Crpt");
		} else {
			if (common->crypt_string != "") {
				snprintf(buf, 64, hdr, common->crypt_string.c_str());
			} else {
				if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L2)
					snprintf(buf, 64, hdr, "L2");
				else if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L3)
					snprintf(buf, 64, hdr, "L3");
				else if (common->basic_crypt_set == 0)
					snprintf(buf, 64, hdr, "None");
			}
		}
	} else if (in_columnid == col_basiccrypt) {
		if (header) {
			snprintf(buf, 64, hdr, "C");
		} else {
			// Default to yes for less interesting l2/l3/etc
			if (common->basic_crypt_set == KIS_DEVICE_BASICCRYPT_NONE)
				snprintf(buf, 64, hdr, "N");
			else if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_DECRYPTED)
				snprintf(buf, 64, hdr, "D");
			else if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_WEAKCRYPT)
				snprintf(buf, 64, hdr, "!");
			else if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_ENCRYPTED)
				snprintf(buf, 64, hdr, "Y");
		}
	} else if (in_columnid == col_packets) {
		if (header) {
			snprintf(buf, 64, hdr, "Pkts");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->packets).c_str());
		}
	} else if (in_columnid == col_llc) {
		if (header) {
			snprintf(buf, 64, hdr, "Link");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->llc_packets).c_str());
		}
	} else if (in_columnid == col_error) {
		if (header) {
			snprintf(buf, 64, hdr, "Err");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->error_packets).c_str());
		}
	} else if (in_columnid == col_data) {
		if (header) {
			snprintf(buf, 64, hdr, "Data");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->data_packets).c_str());
		}
	} else if (in_columnid == col_crypt) {
		if (header) {
			snprintf(buf, 64, hdr, "Crypt");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->crypt_packets).c_str());
		}
	} else if (in_columnid == col_datasize) {
		if (header) {
			snprintf(buf, 64, hdr, "Size");
		} else {
			if (common->datasize < 1024)
				snprintf(buf, 64, hdr, 
						 string(IntToString(common->datasize) + "B").c_str());
			else if (common->datasize < (1024 * 1024)) 
				snprintf(buf, 64, hdr,
						 string(IntToString(common->datasize / 1024) + "K").c_str());
			else if (common->datasize < (1024 * 1024 * 1024))
				snprintf(buf, 64, hdr,
						 string(IntToString(common->datasize / 1024 / 1024) + 
								"M").c_str());
			else
				snprintf(buf, 64, hdr,
						 string(IntToString(common->datasize / 1024 / 1024 / 1024) +
								"G").c_str());
		}
	} else if (in_columnid == col_newpackets) {
		if (header) 
			snprintf(buf, 64, hdr, "New");
		else
			snprintf(buf, 64, hdr, IntToString(common->new_packets).c_str());
	} else if (in_columnid == col_channel) {
		if (header)
			snprintf(buf, 64, hdr, "Chan");
		else
			snprintf(buf, 64, hdr, IntToString(common->channel).c_str());
	} else if (in_columnid == col_freq) {
		if (header)
			snprintf(buf, 64, hdr, "Freq");
		else
			snprintf(buf, 64, hdr, IntToString(common->frequency).c_str());
	} else if (in_columnid == col_alerts) {
		if (header)
			snprintf(buf, 64, hdr, "Alrt");
		else
			snprintf(buf, 64, hdr, IntToString(common->alert).c_str());
	} else if (in_columnid == col_manuf) {
		if (header)
			snprintf(buf, 64, hdr, "Manuf");
		else
			snprintf(buf, 64, hdr, common->manuf.c_str());
	} else if (in_columnid == col_signal) {
		if (header) {
			snprintf(buf, 64, hdr, "Sig");
		} else {

		}
	}

	return buf;
}

string Kis_Devicelist::CommonSubColumn(kdl_display_device *in_dev, int in_columnid,
									   bool header) {
	char buf[64];
	int offt = 0;

	if (header)
		return "";

	map<int, kdl_column *>::iterator ci = registered_column_map.find(in_columnid);

	if (ci == registered_column_map.end())
		return "[INVALID]";

	kis_device_common *common = NULL;

	buf[0] = '\0';

	if (in_dev != NULL && in_dev->device != NULL)
		common = (kis_device_common *) in_dev->device->fetch(devcomp_ref_common);

	if (common == NULL) {
		return "NULL";
	}

	if (in_columnid == col_sub_lastseen) {
		snprintf(buf, 64, "Last seen: %.15s",
				 ctime((const time_t *) &(common->last_time)) + 4);
	} else if (in_columnid == col_sub_addr) {
		snprintf(buf, 64, "%s", in_dev->device->key.Mac2String().c_str());
	} else if (in_columnid == col_sub_basiccrypt) {
		snprintf(buf, 64, "Crypt:");
		offt = 6;

		if (common->basic_crypt_set == KIS_DEVICE_BASICCRYPT_NONE) {
			snprintf(buf + offt, 64-offt, " None");
		} else {
			if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L2) {
				snprintf(buf + offt, 64 - offt, " L2");
				offt += 3;
			} 

			if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L3) {
				snprintf(buf + offt, 64 - offt, " L3");
				offt += 3;
			}

			if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_WEAKCRYPT) {
				snprintf(buf + offt, 64 - offt, " Weak");
				offt += 5;
			} 

			if (common->basic_crypt_set & KIS_DEVICE_BASICCRYPT_DECRYPTED) {
				snprintf(buf + offt, 64 - offt, " Decrypted");
				offt += 10;
			}
		}
	} else if (in_columnid == col_sub_manuf) {
		snprintf(buf, 64, "%s", common->manuf.c_str());
	} else if (in_columnid == col_sub_seenby) {
		map<uuid, KisPanelInterface::knc_card *> *cardmap = 
			kpinterface->FetchNetCardMap();
		map<uuid, KisPanelInterface::knc_card *>::iterator kci;

		offt = 0;

		for (map<uuid, kis_seenby_data *>::iterator smi = common->seenby_map.begin();
			 smi != common->seenby_map.end(); ++smi) {
			if ((kci = cardmap->find(smi->first)) != cardmap->end()) {
				snprintf(buf + offt, 64 - offt, "%s ",
						 kci->second->name.c_str());
				offt += kci->second->name.length() + 1;
			}
		}

		buf[offt] = '\0';
	} else if (in_columnid == col_sub_phy) {
		snprintf(buf, 64, "%s", 
				 devicetracker->FetchPhyName(in_dev->device->phy_type).c_str());
	}

	return buf;
}

void Kis_Devicelist::RefreshDisplayList() {
	// _MSG("refresh display\n", MSGFLAG_INFO);

	draw_vec.clear();

	draw_dirty = 1;

	// fprintf(stderr, "debug - refreshing display list for view mode %d\n", display_mode);
	
	first_line = selected_line = 0;

	for (unsigned int x = 0; x < display_dev_vec.size(); x++) {
		// Determine if we put it in our draw vec
		kis_device_common *common =
			(kis_device_common *) display_dev_vec[x]->device->fetch(devcomp_ref_common);

		// No common?  Fail
		if (common == NULL) {
			// fprintf(stderr, "debug - refresh, no common, skipping\n");
			continue;
		}

		// Don't add it to our device list if it's not a network
		// Devices get everything
		if (display_mode == KDL_DISPLAY_NETWORKS &&
			!(common->basic_type_set & KIS_DEVICE_BASICTYPE_AP)) {
			// fprintf(stderr, "debug - network refresh, not an AP, skipping\n");
			continue;
		}

		// Don't add it to our device list if it's flagged as wired
		if (display_mode == KDL_DISPLAY_WIRELESSDEVICES &&
			(common->basic_type_set & (KIS_DEVICE_BASICTYPE_WIRED)) != 0) {
			continue;
		}

		// See if we're filtered, but only if we have more than one phy
		// so we can't filter the only phy the server has
		if (filter_phy_map.size() > 1) {
			map<int, bool>::iterator fpmi =
				filter_phy_map.find(display_dev_vec[x]->device->phy_type);
			if (fpmi != filter_phy_map.end() &&
				fpmi->second)
				continue;
		}

		draw_vec.push_back(display_dev_vec[x]);
		display_dev_vec[x]->dirty = 1;
	}

}

void Kis_Devicelist::FilterMenuAction(int menuitem) {
	map<int, int>::iterator mpmi =
		menu_phy_map.find(menuitem);

	menu->SetMenuItemChecked(menuitem, !(menu->GetMenuItemChecked(menuitem)));

	if (mpmi != menu_phy_map.end()) {
		_MSG("Filter menu Phy# " + IntToString(mpmi->second), MSGFLAG_INFO);
		int set;
		
		set = filter_phy_map[mpmi->second] = !(menu->GetMenuItemChecked(menuitem));

		string phyname = devicetracker->FetchPhyName(mpmi->second);

		if (phyname == "") {
			_MSG("KDL filter menu empty phyname", MSGFLAG_ERROR);
			return;
		}

		// Set the preference
		kpinterface->prefs->SetOpt("DEVICEFILTER_" + phyname, 
								   set ? "false" : "true", 1);

		RefreshDisplayList();
	}
}

void Kis_Devicelist::SortMenuAction(int menuitem) {
	map<int, kdl_sort *>::iterator i;

	if (current_sort != NULL && current_sort->menu_id == menuitem)
		return;

	// This is dumb but happens rarely
	for (i = sort_map.begin(); i != sort_map.end(); ++i) {
		if ((int) i->second->menu_id == menuitem) {
			// _MSG("Found sort option", MSGFLAG_INFO);
			// Uncheck the old menu
			if (current_sort != NULL) 
				menu->SetMenuItemChecked(current_sort->menu_id, 0);

			menu->SetMenuItemChecked(menuitem, 1);

			// Check the new
			current_sort = i->second;

			kpinterface->prefs->SetOpt("MAIN_SORT", StrLower(i->second->name), 1); 

			break;
		}
	}

	RefreshDisplayList();
}

void Kis_Devicelist::ViewMenuAction(int menuitem) {
	_MSG("In item " + IntToString(menuitem) + " last " + IntToString(mi_lastview), MSGFLAG_INFO);

	if (menuitem == mi_lastview) 
		return;

	menu->SetMenuItemChecked(mi_lastview, 0);
	menu->SetMenuItemChecked(menuitem, 1);
	mi_lastview = menuitem;

	_MSG("trigger " + IntToString(menuitem) + " network item " + IntToString(mi_view_network), MSGFLAG_INFO);

	if (menuitem == mi_view_network) {
		_MSG("View network", MSGFLAG_INFO);
		SetViewMode(KDL_DISPLAY_NETWORKS);
	} else if (menuitem == mi_view_wireless) {
		_MSG("View wireless", MSGFLAG_INFO);
		SetViewMode(KDL_DISPLAY_WIRELESSDEVICES);
	} else if (menuitem == mi_view_devices) {
		_MSG("View devices", MSGFLAG_INFO);
		SetViewMode(KDL_DISPLAY_DEVICES);
	}
}

void Kis_Devicelist::SpawnColorPrefWindow() {
	Kis_ColorPref_Panel *cpp = new Kis_ColorPref_Panel(globalreg, kpinterface);

	cpp->AddColorPref("devlist_normal_color", "Normal device");
	cpp->AddColorPref("devlist_crypt_color", "Encrypted device");
	cpp->AddColorPref("devlist_decrypt_color", "Decrypted device");
	cpp->AddColorPref("devlist_header_color", "Column titles");
	cpp->AddColorPref("devlist_insecure_color", "Insecure device");

	kpinterface->AddPanel(cpp);
}

void Kis_Devicelist::SpawnColumnPrefWindow(bool extracols) {
	Kis_ColumnPref_Panel *cpp = new Kis_ColumnPref_Panel(globalreg, kpinterface);

	for (map<int, kdl_column *>::iterator x = registered_column_map.begin();
		 x != registered_column_map.end(); ++x) {
		if (x->second->subcolumn == extracols)
			cpp->AddColumn(x->second->name, x->second->description);
	}

	if (!extracols)
		cpp->ColumnPref("devlist_columns", "Device List Columns");
	else
		cpp->ColumnPref("devlist_extline", "Device List Extras");

	cpp->SetCompleteCallback(KDL_ColumnRefresh, this);

	kpinterface->AddPanel(cpp);
}

int KDLD_MenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_DevDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

int KDLD_GraphTimer(TIMEEVENT_PARMS) {
	return ((Kis_DevDetails_Panel *) auxptr)->GraphTimer();
}

Kis_DevDetails_Panel::Kis_DevDetails_Panel(GlobalRegistry *in_globalreg,
										   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	devicetracker = 
		(Client_Devicetracker *) globalreg->FetchGlobal("CLIENT_DEVICE_TRACKER");
	devcomp_ref_common = devicetracker->RegisterDeviceComponent("COMMON");

	grapheventid =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  KDLD_GraphTimer, (void *) this);

	// Make the menu, default cb us
	menu = new Kis_Menu(globalreg, this);
	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, KDLD_MenuCB, (void *) this);

	mn_device = menu->AddMenu("Device", 0);
	mi_addnote = menu->AddMenuItem("Device Note...", mn_device, 'N');
	menu->AddMenuItem("-", mn_device, 0);
	mi_close = menu->AddMenuItem("Close window", mn_device, 'w');

	mn_view = menu->AddMenu("View", 0);
	mi_dev = menu->AddMenuItem("Device details", mn_view, 'd');
	menu->AddMenuItem("-", mn_view, 0);

	mi_graphsig = menu->AddMenuItem("Signal Level", mn_view, 's');
	mi_graphpacket = menu->AddMenuItem("Packet Rate", mn_view, 'p');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	netdetailt = new Kis_Free_Text(globalreg, this);
	AddComponentVec(netdetailt, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								 KIS_PANEL_COMP_TAB));

	siggraph = new Kis_IntGraph(globalreg, this);
	siggraph->SetName("DETAIL_SIG");
	siggraph->SetPreferredSize(0, 8);
	siggraph->SetScale(-110, -40);
	siggraph->SetInterpolation(1);
	siggraph->SetMode(0);
	siggraph->Show();
	siggraph->AddExtDataVec("Signal", 4, "graph_detail_sig", "yellow,yellow", 
		 					  ' ', ' ', 1, &sigpoints);
	AddComponentVec(siggraph, KIS_PANEL_COMP_EVT);

	packetgraph = new Kis_IntGraph(globalreg, this);
	packetgraph->SetName("DETAIL_PPS");
	packetgraph->SetPreferredSize(0, 8);
	packetgraph->SetScale(0, 0);
	packetgraph->SetInterpolation(1);
	packetgraph->SetMode(0);
	packetgraph->Show();
	packetgraph->AddExtDataVec("Packet Rate", 4, "graph_detail_pps", "green,green", 
							  ' ', ' ', 1, &packetpps);
	AddComponentVec(packetgraph, KIS_PANEL_COMP_EVT);

	ClearGraphVectors();

	SetTitle("");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	vbox->Pack_End(siggraph, 0, 0);
	vbox->Pack_End(packetgraph, 0, 0);

	vbox->Pack_End(netdetailt, 1, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	last_dirty = 0;
	last_mac = mac_addr(0);
	displaydev = NULL;
	displaycommon = NULL;

	vector<string> td;
	td.push_back("");
	td.push_back("No device selected");
	td.push_back("Change sort order to anything other than \"Auto Fit\"");
	td.push_back("and highlight a device.");

	netdetailt->SetText(td);

	UpdateViewMenu(-1);

	SetActiveComponent(netdetailt);

	main_component = vbox;

	Position(WIN_CENTER(LINES, COLS));
}

Kis_DevDetails_Panel::~Kis_DevDetails_Panel() {
	if (grapheventid >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(grapheventid);
}

void Kis_DevDetails_Panel::SetTargetDevice(kdl_display_device *in_device) {
	displaydev = in_device;

	if (displaydev == NULL) {
		displaycommon = NULL;
		return;
	}

	if (displaydev->device != NULL) {
		displaycommon = 
			(kis_device_common *) displaydev->device->fetch(devcomp_ref_common);
	} else {
		displaycommon = NULL;
	}
}

void Kis_DevDetails_Panel::ClearGraphVectors() {
	lastpackets = 0;
	sigpoints.clear();
	packetpps.clear();
	for (unsigned int x = 0; x < 120; x++) {
		sigpoints.push_back(-256);
		packetpps.push_back(0);
	}
}

void Kis_DevDetails_Panel::UpdateGraphVectors(int signal, int pps) {
	sigpoints.push_back(signal);
	if (sigpoints.size() > 120)
		sigpoints.erase(sigpoints.begin(), sigpoints.begin() + sigpoints.size() - 120);

	if (lastpackets == 0)
		lastpackets = pps;
	packetpps.push_back(pps - lastpackets);
	lastpackets = pps;
	if (packetpps.size() > 120)
		packetpps.erase(packetpps.begin(), packetpps.begin() + packetpps.size() - 120);

}


void Kis_DevDetails_Panel::UpdateViewMenu(int mi) {
	if (mi == mi_dev) {
		if (kpinterface->prefs->FetchOptBoolean("DETAILS_SHOWDEV", 1)) {
			kpinterface->prefs->SetOpt("DETAILS_SHOWDEV", "false", 1);
			menu->SetMenuItemChecked(mi_dev, 0);
			netdetailt->Hide();
		} else {
			kpinterface->prefs->SetOpt("DETAILS_SHOWDEV", "true", 1);
			menu->SetMenuItemChecked(mi_dev, 1);
			netdetailt->Show();
		}
	} else if (mi == mi_graphsig) {
		if (kpinterface->prefs->FetchOptBoolean("DETAILS_SHOWGRAPHSIG", 0)) {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHSIG", "false", 1);
			menu->SetMenuItemChecked(mi_graphsig, 0);
			siggraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHSIG", "true", 1);
			menu->SetMenuItemChecked(mi_graphsig, 1);
			siggraph->Show();
		}
	} else if (mi == mi_graphpacket) {
		if (kpinterface->prefs->FetchOptBoolean("DETAILS_SHOWGRAPHPACKET", 1)) {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHPACKET", "false", 1);
			menu->SetMenuItemChecked(mi_graphpacket, 0);
			packetgraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHPACKET", "true", 1);
			menu->SetMenuItemChecked(mi_graphpacket, 1);
			packetgraph->Show();
		}
	} else if (mi == -1) {
		if (kpinterface->prefs->FetchOptBoolean("DETAILS_SHOWDEV", 1)) {
			menu->SetMenuItemChecked(mi_dev, 1);
			netdetailt->Show();
		} else {
			menu->SetMenuItemChecked(mi_dev, 0);
			netdetailt->Hide();
		}

		if (kpinterface->prefs->FetchOptBoolean("DETAILS_SHOWGRAPHSIG", 0)) {
			menu->SetMenuItemChecked(mi_graphsig, 1);
			siggraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphsig, 0);
			siggraph->Hide();
		}

		if (kpinterface->prefs->FetchOptBoolean("DETAILS_SHOWGRAPHPACKET", 0)) {
			menu->SetMenuItemChecked(mi_graphpacket, 1);
			packetgraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphpacket, 0);
			packetgraph->Hide();
		}
	}
}

void Kis_DevDetails_Panel::MenuAction(int opt) {
	if (opt == mi_close) {
		globalreg->panel_interface->KillPanel(this);
		return;
	}

	if (opt == mi_addnote) {
		// TODO fix adding notes
		return;
	}

	if (opt == mi_dev || opt == mi_graphsig || opt == mi_graphpacket) {
		UpdateViewMenu(opt);
		return;
	}
}

int Kis_DevDetails_Panel::GraphTimer() {
	if (displaycommon != NULL) {
		if (displaycommon->last_time != last_dirty) {
			last_dirty = displaycommon->last_time;

			UpdateGraphVectors(displaycommon->snrdata.last_signal_dbm == -256 ?
							   displaycommon->snrdata.last_signal_rssi :
							   displaycommon->snrdata.last_signal_dbm,
							   displaycommon->packets);
		}
	}

	return 1;
}

void Kis_DevDetails_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	vector<string> td;
	
	if (displaycommon == NULL) {
		td.push_back("No common tracking data for selected device");
	} else {
		td.push_back(AlignString("Name: ", ' ', 2, 16) + displaycommon->name);
		td.push_back("");
		td.push_back(AlignString("First time: ", ' ', 2, 16) + 
					 string(ctime((const time_t *) 
								  &(displaycommon->first_time)) + 4).substr(0, 15));
		td.push_back(AlignString("Last time: ", ' ', 2, 16) + 
					 string(ctime((const time_t *) 
								  &(displaycommon->last_time)) + 4).substr(0, 15));
		td.push_back("");
		td.push_back(AlignString("MAC: ", ' ', 2, 16) + 
					 displaycommon->device->key.Mac2String());
		td.push_back(AlignString("Phy: ", ' ', 2, 16) +
					 devicetracker->FetchPhyName(displaycommon->device->phy_type));

		td.push_back("");
		if (displaycommon->snrdata.last_signal_dbm == KIS_SIGNAL_DBM_BOGUS_MIN &&
			displaycommon->snrdata.last_signal_rssi == KIS_SIGNAL_RSSI_BOGUS_MIN) {
			td.push_back(AlignString("Signal: ", ' ', 2, 16) +
						 "No signal data reported");
		} 

		if (displaycommon->snrdata.last_signal_dbm != KIS_SIGNAL_DBM_BOGUS_MIN) 
			td.push_back(AlignString("Signal: ", ' ', 2, 16) +
						 IntToString(displaycommon->snrdata.last_signal_dbm) + "dBm");
		
		if (displaycommon->snrdata.last_signal_rssi != KIS_SIGNAL_RSSI_BOGUS_MIN) 
			td.push_back(AlignString("Signal: ", ' ', 2, 16) +
						 IntToString(displaycommon->snrdata.last_signal_dbm) + "RSSI");

		if (displaycommon->snrdata.last_noise_dbm == KIS_SIGNAL_DBM_BOGUS_MIN &&
			displaycommon->snrdata.last_noise_rssi == KIS_SIGNAL_RSSI_BOGUS_MIN)
			td.push_back(AlignString("Noise: ", ' ', 2, 16) +
						 "No noise data reported");

		if (displaycommon->snrdata.last_noise_dbm != KIS_SIGNAL_DBM_BOGUS_MIN)
			td.push_back(AlignString("Noise: ", ' ', 2, 16) + 
						 IntToString(displaycommon->snrdata.last_noise_dbm) + "dBm");

		if (displaycommon->snrdata.last_noise_rssi != KIS_SIGNAL_RSSI_BOGUS_MIN)
			td.push_back(AlignString("Noise: ", ' ', 2, 16) +
						 IntToString(displaycommon->snrdata.last_noise_rssi) + "RSSI");

		td.push_back("");
		if (displaycommon->type_string != "")
			td.push_back(AlignString("Type: ", ' ', 2, 16) +
						 displaycommon->type_string);
		else
			td.push_back(AlignString("Type: ", ' ', 2, 16) + "Device");

		if (displaycommon->basic_type_set & KIS_DEVICE_BASICTYPE_AP)
			td.push_back(AlignString("", ' ', 2, 16) + "AP/Coordinator");
		if (displaycommon->basic_type_set & KIS_DEVICE_BASICTYPE_CLIENT)
			td.push_back(AlignString("", ' ', 2, 16) + "Wireless client");
		if (displaycommon->basic_type_set & KIS_DEVICE_BASICTYPE_WIRED)
			td.push_back(AlignString("", ' ', 2, 16) + "Wired bridge");
		if (displaycommon->basic_type_set & KIS_DEVICE_BASICTYPE_PEER)
			td.push_back(AlignString("", ' ', 2, 16) + "Ad-Hoc/Peer");

		td.push_back("");
		if (displaycommon->crypt_string != "")
			td.push_back(AlignString("Encryption: ", ' ', 2, 16) +
						 displaycommon->crypt_string);
		else
			td.push_back(AlignString("Encryption: ", ' ', 2, 16) + "None");
		if (displaycommon->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L2)
			td.push_back(AlignString("", ' ', 2, 16) + "L2 / Phy link encryption");
		if (displaycommon->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L3)
			td.push_back(AlignString("", ' ', 2, 16) + "L3 / Data link encryption");
		if (displaycommon->basic_crypt_set & KIS_DEVICE_BASICCRYPT_WEAKCRYPT)
			td.push_back(AlignString("", ' ', 2, 16) + "Known weak encryption");
		if (displaycommon->basic_crypt_set & KIS_DEVICE_BASICCRYPT_DECRYPTED)
			td.push_back(AlignString("", ' ', 2, 16) + "Decrypted");
		
		td.push_back(AlignString("Channel: ", ' ', 2, 16) + 
					 IntToString(displaycommon->channel));

		td.push_back("");
		td.push_back(AlignString("Packets: ", ' ', 2, 16) +
					 IntToString(displaycommon->packets));
		if (displaycommon->tx_packets != 0 || displaycommon->rx_packets != 0) {
			td.push_back(AlignString("Packets (tx): ", ' ', 2, 18) +
						 IntToString(displaycommon->tx_packets));
			td.push_back(AlignString("Packets (rx): ", ' ', 2, 18) +
						 IntToString(displaycommon->tx_packets));
		}
		td.push_back(AlignString("Phy/LLC: ", ' ', 2, 18) +
					 IntToString(displaycommon->llc_packets));
		td.push_back(AlignString("Error: ", ' ', 2, 18) +
					 IntToString(displaycommon->error_packets));
		td.push_back(AlignString("Data: ", ' ', 2, 18) +
					 IntToString(displaycommon->data_packets));
		td.push_back(AlignString("Encrypted: ", ' ', 2, 18) +
					 IntToString(displaycommon->crypt_packets));
		td.push_back(AlignString("Filtered: ", ' ', 2, 18) +
					 IntToString(displaycommon->filter_packets));

		td.push_back("");

		if (displaycommon->datasize < 1024)
			td.push_back(AlignString("Data: ", ' ', 2, 16) +
						 LongIntToString(displaycommon->datasize) + "B");
		else if (displaycommon->datasize < (1024 * 1024))
			td.push_back(AlignString("Data: ", ' ', 2, 16) +
						 LongIntToString(displaycommon->datasize / 1024) + "KB");
		else if (displaycommon->datasize < (1024 * 1024 * 1024))
			td.push_back(AlignString("Data: ", ' ', 2, 16) +
						 LongIntToString(displaycommon->datasize / 1024 / 1024) + "MB");
		
	}

	netdetailt->SetText(td);

	if (displaydev != NULL && displaydev->device != NULL) {
		Client_Phy_Handler *cliphy =
			devicetracker->FetchPhyHandler(displaydev->device->phy_type);

		if (cliphy != NULL)
			cliphy->PanelDetailsText(netdetailt, displaydev->device);
	}

	DrawComponentVec();

	wmove(win, 0, 0);
}

#endif // ncurses

