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

#ifndef __KIS_PANEL_PREFERENCES_H__
#define __KIS_PANEL_PREFERENCES_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "netracker.h"
#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"

// Color picker - draws all the colors and lets you pick one with 
// left/right/space|enter
class Kis_ColorPref_Component : public Kis_Panel_Component {
public:
	Kis_ColorPref_Component() { 
		fprintf(stderr, "FATAL OOPS: Kis_ColorPref_Component()\n");
		exit(1);
	}
	Kis_ColorPref_Component(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_ColorPref_Component();

	virtual void DrawComponent();
	virtual void Activate(int sub);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);

	virtual void SetColor(string in_color);
	virtual string GetColor();

protected:
	int active;
	int cpos;
	int colors[16];
	int text_color;
};

class Kis_OrderlistPref_Component : public Kis_Scrollable_Table {
public:
	Kis_OrderlistPref_Component() {
		fprintf(stderr, "FATAL OOPS: Kis_OrderlistPref_Component()\n");
		exit(1);
	}

	Kis_OrderlistPref_Component(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_OrderlistPref_Component();

	virtual int KeyPress(int in_key);

	virtual void SetOrderable(int in_order);

	// Set the field of the columns which controls enabled, we dynamically
	// alter the row_data here.  Set the "Yes" "No" field text, this is
	// also used to compare for enabled fields
	virtual void SetEnableField(int in_field, string in_yes, string in_no);
	// Set the string order field (ie, column name)
	virtual void SetColumnField(int in_field);
	// Get a config-file style ordered string of the enabled columns
	virtual string GetStringOrderList();

protected:
	int orderable;
	int enable_fid, column_fid;
	string field_yes, field_no;
};

// I'm un-thrilled about this approach but it'll do
class Kis_ColorPref_Picker : public Kis_Panel {
public:
	Kis_ColorPref_Picker() {
		fprintf(stderr, "FATAL OOPS:  Kis_ColorPref_Picker()\n");
		exit(1);
	}
	Kis_ColorPref_Picker(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_ColorPref_Picker();
	
	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	virtual void LinkColorPref(string in_prefname);

	virtual void ButtonAction(Kis_Panel_Component *in_button);

protected:
	Kis_Button *okbutton, *cancelbutton;
	Kis_ColorPref_Component *fgcolor, *bgcolor;

	Kis_Panel_Packbox *vbox, *hbox;

	string prefname;
};

class Kis_ColorPref_Panel : public Kis_Panel {
	// Plugin picker lists .so files in the plugin director(ies) and lets 
	// the user pick one to load.
public:
	Kis_ColorPref_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_ColorPref_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_ColorPref_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_intf);
	virtual ~Kis_ColorPref_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	virtual void AddColorPref(string pref, string name);

	virtual void SelectedAction(int listkey);

	struct cprefpair {
		string text, pref;
	};

protected:
	Kis_Scrollable_Table *colorlist;
	vector<Kis_ColorPref_Panel::cprefpair> listedcolors;
};

class Kis_AutoConPref_Panel : public Kis_Panel {
public:
	Kis_AutoConPref_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Connect_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_AutoConPref_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_AutoConPref_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	virtual void ButtonAction(Kis_Panel_Component *in_button);

protected:
	Kis_Single_Input *hostname;
	Kis_Single_Input *hostport;
	Kis_Checkbox *autoconcheck;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox;
};

class Kis_ColumnPref_Panel : public Kis_Panel {
public:
	Kis_ColumnPref_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_ColumnPref_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_ColumnPref_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_ColumnPref_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	// Add a column to the understood options.  These should ALL be populated
	// BEFORE calling ColumnPref to link it to a pref value
	virtual void AddColumn(string colname, string description);

	// Link to a column preference field
	virtual void ColumnPref(string pref, string name);

	virtual void ButtonAction(Kis_Panel_Component *in_button);

	struct pref_cols{
		string colname;
		string description;
		int queued;
	}; 

protected:
	Kis_OrderlistPref_Component *orderlist;
	Kis_Free_Text *helptext;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox;

	string pref, prefname;

	vector<Kis_ColumnPref_Panel::pref_cols> pref_vec;
};

class Kis_Keyshort_Panel : public Kis_Panel {
public:
	Kis_Keyshort_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Keyshort_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Keyshort_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_Keyshort_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	// Add a shortcut name 
	virtual void AddShortcut(string prefname, string dispname);

	virtual void ButtonAction(Kis_Panel_Component *in_button);

	struct pref_shorts {
		string prefname;
		string dispname;
		char key;
	}; 

protected:
	Kis_OrderlistPref_Component *orderlist;
	Kis_Free_Text *helptext;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox;

	vector<Kis_Keyshort_Panel::pref_shorts> pref_vec;
};

class Kis_GpsPref_Panel : public Kis_Panel {
public:
	Kis_GpsPref_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Gps_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_GpsPref_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_GpsPref_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();

	virtual void ButtonAction(Kis_Panel_Component *in_button);

protected:
	Kis_Radiobutton *metrad, *engrad;
	Kis_Free_Text *helptext;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *cbox, *bbox;
};

#endif // curses

#endif // prefs

