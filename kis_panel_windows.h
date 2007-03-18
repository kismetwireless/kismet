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

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual int KeyPress(int in_key);

protected:
	int mn_file, mn_sort, mn_tools, mn_plugins;
	int mi_connect, mi_disconnect, mi_quit;

	int mi_sort_auto, mi_sort_type, mi_sort_chan, mi_sort_first, mi_sort_first_d,
		mi_sort_last, mi_sort_last_d, mi_sort_bssid, mi_sort_ssid,
		mi_sort_packets, mi_sort_packets_d;

	int mi_addcard;

	int mi_addplugin, mi_noplugins;

	int connect_enable;

	int sortmode;

	KisStatusText_Messageclient *statuscli;
	Kis_Status_Text *statustext;
	Kis_Netlist *netlist;
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
	virtual int KeyPress(int in_key);

protected:
	Kis_Single_Input *hostname;
	Kis_Single_Input *hostport;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	vector<Kis_Panel_Component *> tab_components;
	int tab_pos;
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
	virtual int KeyPress(int in_key);

	virtual void SetTargetClient(KisNetClient *in_cli);

protected:
	KisNetClient *target_cli;

	Kis_Single_Input *srctype;
	Kis_Single_Input *srciface;
	Kis_Single_Input *srcname;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	vector<Kis_Panel_Component *> tab_components;
	int tab_pos;
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
	virtual int KeyPress(int in_key);

protected:
	Kis_Scrollable_Table *cardlist;
};

class Kis_ServerList_Picker : public Kis_Panel {
public:
	Kis_ServerList_Picker() {
		fprintf(stderr, "FATAL OOPS: Kis_ServerList_Picker called w/out globalreg\n");
		exit(1);
	}

	Kis_ServerList_Picker(GlobalRegistry *in_globalreg, KisPanelInterface *in_intf);
	virtual ~Kis_ServerList_Picker();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual int KeyPress(int in_key);

	virtual void ConfigurePicker(string in_title, kpi_sl_cb_hook in_hook,
								 void *in_aux);

protected:
	Kis_Scrollable_Table *srvlist;

	kpi_sl_cb_hook cb_hook;
	void *cb_aux;
	vector<KisNetClient *> *netcliref;
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
	virtual int KeyPress(int in_key);

	virtual void ConfigureAlert(string in_title, string in_text);

protected:
	Kis_Free_Text *ftxt;
	Kis_Button *ackbutton;

	vector<Kis_Panel_Component *> tab_components;
	int tab_pos;
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
	virtual int KeyPress(int in_key);

protected:
	Kis_Scrollable_Table *pluglist;
};

#endif

#endif
