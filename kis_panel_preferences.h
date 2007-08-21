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
	virtual int KeyPress(int in_key);

	virtual void LinkColorPref(string in_prefname);

protected:
	Kis_Button *okbutton, *cancelbutton;
	Kis_ColorPref_Component *fgcolor, *bgcolor;

	Kis_Panel_Packbox *vbox, *hbox;

	vector<Kis_Panel_Component *> tab_components;
	int tab_pos;

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
	virtual int KeyPress(int in_key);

	virtual void AddColorPref(string pref, string name);

	typedef struct cprefpair {
		string text, pref;
	};

protected:
	Kis_Scrollable_Table *colorlist;
	vector<Kis_ColorPref_Panel::cprefpair> listedcolors;
};

class Kis_Column_Picker : public Kis_Panel {
public:
	Kis_Column_Picker() {
		fprintf(stderr, "FATAL OOPS:  Kis_Column_Picker()\n");
		exit(1);
	}
	Kis_Column_Picker(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_Column_Picker();
	
	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual int KeyPress(int in_key);

	virtual void AddColumn(string in_colname, string in_coltext);
	virtual void LinkPrefValue(string in_prefval);

	typedef struct colprefpair {
		string colname;
		string coltext;
		int enable;
	};

protected:
	Kis_Button *okbutton, *cancelbutton;
	Kis_Scrollable_Table *colist;

	Kis_Panel_Packbox *vbox, *hbox;

	vector<Kis_Column_Picker::colprefpair> listedcols;

	vector<Kis_Panel_Component *> tab_components;
	int tab_pos;

	string prefname;
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
	virtual int KeyPress(int in_key);

protected:
	Kis_Single_Input *hostname;
	Kis_Single_Input *hostport;
	Kis_Checkbox *autoconcheck;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	Kis_Panel_Packbox *vbox, *bbox;

	vector<Kis_Panel_Component *> tab_components;
	int tab_pos;
};

#endif // curses

#endif // prefs

