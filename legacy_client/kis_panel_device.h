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

#ifndef __KIS_PANEL_DEVICE_H__
#define __KIS_PANEL_DEVICE_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "netracker.h"
#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"
#include "kis_panel_preferences.h"
#include "kis_client_devicetracker.h"

class kdl_display_device;
class kdl_sort;

#define KDL_COLUMN_PARMS	kdl_display_device *device, void *aux, \
	GlobalRegistry *globalreg, int columnid, bool header
typedef string (*KDL_Column_Callback)(KDL_COLUMN_PARMS);

#define KDL_SORT_PARMS		vector<kdl_display_device *> *dev_vec, void *aux, \
	kdl_sort *sort_opt, GlobalRegistry *globalreg
typedef void (*KDL_Sort_Callback)(KDL_SORT_PARMS);

class kdl_display_device {
public:
	kis_tracked_device *device;

	string columncache;
	string extcache;

	bool dirty;
};

class kdl_column {
public:
	string name;
	string description;

	// Subcolumns appear in the highlighted details; they're so similar that we
	// let them use the same storage
	bool subcolumn;

	int width;
	KisWidget_LabelPos alignment;

	unsigned int id;

	KDL_Column_Callback callback;
	void *cb_aux;
};

class kdl_sort {
public:
	string name;
	string description;

	unsigned int id;

	int menu_id;

	KDL_Sort_Callback callback;
	void *cb_aux;
};

// Display mode, filter by networks, or devices, or whatever
#define KDL_DISPLAY_NETWORKS			0
#define KDL_DISPLAY_DEVICES				1
#define KDL_DISPLAY_WIRELESSDEVICES		2

// Color slots in the array
#define KDL_COLOR_NORMAL			0
#define KDL_COLOR_CRYPT				1
#define KDL_COLOR_DECRYPT			2
#define KDL_COLOR_HEADER			3
#define KDL_COLOR_INSECURE			4
#define KDL_COLOR_MAX				5

class Kis_Devicelist : public Kis_Panel_Component {
public:
	Kis_Devicelist() {
		fprintf(stderr, "FATAL OOPS: Kis_Devicelist()\n");
		exit(1);
	}

	Kis_Devicelist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Devicelist();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	virtual void SetPosition(int isx, int isy, int iex, int iey);

	// We sync to the *TIME sentence to know when we should draw the list
	void NetClientConfigure(KisNetClient *in_cli, int in_recon);
	void NetClientAdd(KisNetClient *in_cli, int add);
	void Proto_TIME();

	void DeviceRX(kis_tracked_device *device);
	void PhyRX(int phy_id);

	int RegisterSort(string in_name, string in_desc, KDL_Sort_Callback in_cb,
					 void *in_aux);
	void RemoveSort(int in_id);

	int RegisterColumn(string in_name, string in_desc, int in_width,
					   KisWidget_LabelPos in_align, KDL_Column_Callback in_cb,
					   void *in_aux, bool in_sub);
	void RemoveColumn(int in_id);
	kdl_column *FetchColumn(int in_id);

	string CommonColumn(kdl_display_device *in_dev, int columnid, bool header);
	string CommonSubColumn(kdl_display_device *in_dev, int columnid, bool header);

	void ParseColumnConfig();

	void SetViewMode(int in_mode);

	void RefreshDisplayList();

	void SortMenuAction(int menuitem);

	void FilterMenuAction(int menuitem);
	void ViewMenuAction(int menuitem);

	void SpawnColorPrefWindow();
	void SpawnColumnPrefWindow(bool extracols);

protected:
	vector<kdl_display_device *> display_dev_vec;
	map<mac_addr, kdl_display_device *> display_dev_map;

	bool draw_dirty;

	int newdevref, newphyref;

	KisPanelInterface *kpinterface;
	Client_Devicetracker *devicetracker;

	// Viewable region for simplification
	int viewable_lines, viewable_cols;
	// Positional 
	int first_line, last_line, selected_line;
	unsigned int hpos;

	int devcomp_ref_common;

	int cli_addref;

	// Filtered display by phy...  phy not present in map implies not filtered,
	// map indicates positive-filtering (true = not displayed / is filtered)
	// When there is only one entry in the filter map, we do not filter.  This
	// prevents the user from seeing the only visible data in weird situatons
	map<int, bool> filter_phy_map;
	// Map of menu IDs to phy IDs
	map<int, int> menu_phy_map;

	// Sort options
	int next_sort_id;
	map<int, kdl_sort *> sort_map;
	kdl_sort *current_sort;

	// Possible columns
	int next_column_id;
	map<int, kdl_column *> registered_column_map;
	// Enabled columns
	vector<kdl_column *> configured_column_vec;
	vector<kdl_column *> configured_subcolumn_vec;
	// Vector of devices we're actually eligible for displaying
	// (post-filter, etc)
	vector<kdl_display_device *> draw_vec;

	int col_active, col_addr, col_name, col_type, col_basictype, col_basiccrypt,
		col_packets, col_llc, col_error, col_data, col_crypt, col_datasize, 
		col_newpackets, col_channel, col_freq, col_alerts, col_manuf, col_phy, 
		col_signal, col_cryptstr;

	int col_sub_lastseen, col_sub_addr, col_sub_basiccrypt, col_sub_ip,
		col_sub_manuf, col_sub_seenby, col_sub_phy;

	int display_mode;

	Kis_Menu *menu;
	int mn_filter, mn_preferences, mn_sort, mn_view;
	int mi_colorpref, mi_columnpref, mi_extrapref;
	int mi_view_network, mi_view_devices, mi_view_wireless, mi_lastview;

	int sort_mode;

	time_t last_mouse_click;

	// Allocated arrays
	int color_map[KDL_COLOR_MAX];
	int color_inactive;

	// Column header cache
	string colheadercache;
};

class Kis_DevDetails_Panel : public Kis_Panel {
public:
	Kis_DevDetails_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_DevDetails_Panel()\n");
		exit(1);
	}

	Kis_DevDetails_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_DevDetails_Panel();

	virtual void DrawPanel();
	virtual void MenuAction(int opt);

	virtual int GraphTimer();

	void SetTargetDevice(kdl_display_device *in_device);

protected:
	Client_Devicetracker *devicetracker;

	virtual void UpdateViewMenu(int mi);
	void ClearGraphVectors();
	void UpdateGraphVectors(int signal, int pps);
	
	int DeriveDisplayUpdate();

	Kis_Panel_Packbox *vbox, *bbox;
	Kis_Free_Text *netdetailt;

	Kis_IntGraph *siggraph, *packetgraph;
	vector<int> sigpoints, packetpps;
	int lastpackets;

	time_t last_dirty;
	mac_addr last_mac;

	int devcomp_ref_common;
	kdl_display_device *displaydev;
	kis_device_common *displaycommon;

	int mn_device, mi_addnote, mi_close;
	int mn_view, mi_dev, mi_graphsig, mi_graphpacket;

	int grapheventid;
};

#endif // ncurses

#endif
