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

#ifndef __KIS_PANEL_DEVICELIST_H__
#define __KIS_PANEL_DEVICELIST_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "netracker.h"
#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"
#include "kis_panel_preferences.h"
#include "kis_client_devicetracker.h"

class kdl_display_device;

#define KDL_COLUMN_PARMS	kdl_display_device *device, void *aux, \
	GlobalRegistry *globalreg, int columnid, bool header
typedef string (*KDL_Column_Callback)(KDL_COLUMN_PARMS);

class kdl_display_device {
public:
	kis_tracked_device *device;
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

	int RegisterColumn(string in_name, string in_desc, int in_width,
					   KisWidget_LabelPos in_align, KDL_Column_Callback in_cb,
					   void *in_aux, bool in_sub);
	void RemoveColumn(int in_id);

	string CommonColumn(kdl_display_device *in_dev, int columnid, bool header);

	void ParseColumnConfig();

protected:
	vector<kdl_display_device *> display_dev_vec;
	map<mac_addr, kdl_display_device *> display_dev_map;

	bool draw_dirty;

	int newdevref;

	KisPanelInterface *kpinterface;
	Client_Devicetracker *devicetracker;

	// Viewable region for simplification
	unsigned int viewable_lines, viewable_cols;
	// Positional 
	unsigned int first_line, last_line, selected_line;
	unsigned int hpos;

	int devcomp_ref_common;

	int cli_addref;

	// Possible columns
	int next_column_id;
	map<int, kdl_column *> registered_column_map;
	// Enabled columns
	vector<kdl_column *> configured_column_vec;
	vector<kdl_column *> configured_subcolumn_vec;
	// Vector of devices we're actually eligible for displaying
	// (post-filter, etc)
	vector<kdl_display_device *> draw_vec;

	int col_active, col_addr, col_name, col_type, col_basictype, col_packets, col_llc, 
		col_error, col_data, col_crypt, col_datasize, col_newpackets, col_channel,
		col_freq, col_alerts, col_manuf, col_phy, col_signal;
};


#endif // ncurses

#endif
