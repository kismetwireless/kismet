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

#include "kis_panel_widgets.h"
#include "kis_panel_frontend.h"
#include "kis_panel_windows.h"
#include "kis_panel_preferences.h"

#include "soundcontrol.h"

const char *coloransi[] = {
	"white", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
	"hi-black", "hi-red", "hi-green", "hi-yellow", 
	"hi-blue", "hi-magenta", "hi-cyan", "hi-white"
};

const char *colortext[] = {
	"Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White",
	"Grey", "Hi-Red", "Hi-Green", "Hi-Yellow", 
	"Hi-Blue", "Hi-Magenta", "Hi-Cyan", "Hi-White"
};

Kis_ColorPref_Component::Kis_ColorPref_Component(GlobalRegistry *in_globalreg,
												 Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	active = 0;

	for (int x = 0; x < 16; x++) {
		colors[x] = parent_panel->AddColor(coloransi[x]);
	}

	cpos = 0;

	text_color = 0;

	SetPreferredSize(32, 2);
}

Kis_ColorPref_Component::~Kis_ColorPref_Component() {

}

void Kis_ColorPref_Component::Activate(int sub) {
	active = 1;
}

void Kis_ColorPref_Component::Deactivate() {
	active = 0;
}

void Kis_ColorPref_Component::DrawComponent() {
	if (visible == 0)
		return;

	parent_panel->ColorFromPref(text_color, "text_color");

	wattrset(window, text_color);
	if (active)
		mvwaddch(window, sy, sx, '>');

	int hpos = 2;

	for (int x = 0; x < 16; x++) {
		hpos++;
		wattrset(window, text_color);
		if (x == cpos) {
			mvwaddch(window, sy, sx + hpos, '[');
			hpos++;
		}

		wattrset(window, colors[x]);
		mvwaddch(window, sy, sx + hpos, 'X');
		hpos++;

		wattrset(window, text_color);
		if (x == cpos) {
			mvwaddch(window, sy, sx + hpos, ']');
			hpos++;
		}
	}

	wattrset(window, text_color);
	mvwaddstr(window, sy, sx + hpos + 1, colortext[cpos]);
}

int Kis_ColorPref_Component::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	if (in_key == KEY_RIGHT) {
		cpos++;
		if (cpos >= 16)
			cpos = 0;
		return cpos + 1;
	}

	if (in_key == KEY_LEFT) {
		cpos--;
		if (cpos < 0)
			cpos = 15;
		return cpos + 1;
	}

	return 0;
}

void Kis_ColorPref_Component::SetColor(string in_color) {
	string s = StrLower(in_color);

	for (unsigned int x = 0; x < 16; x++) {
		if (s == StrLower(colortext[x])) {
			cpos = x;
			return;
		}
	}
}

string Kis_ColorPref_Component::GetColor() {
	if (cpos < 0 || cpos >= 16)
		return "black";

	return string(colortext[cpos]);
}

int ColorprefButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ColorPref_Picker *) aux)->ButtonAction(component);
	return 1;
}

Kis_ColorPref_Picker::Kis_ColorPref_Picker(GlobalRegistry *in_globalreg,
										   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	fgcolor = new Kis_ColorPref_Component(globalreg, this);
	bgcolor = new Kis_ColorPref_Component(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);

	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ColorprefButtonCB, this);
	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ColorprefButtonCB, this);

	AddComponentVec(fgcolor, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
							  KIS_PANEL_COMP_EVT));
	AddComponentVec(bgcolor, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
							  KIS_PANEL_COMP_EVT));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
							   KIS_PANEL_COMP_EVT));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								   KIS_PANEL_COMP_EVT));
	tab_pos = 0;

	active_component = fgcolor;
	fgcolor->Activate(1);

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	vbox->Show();

	hbox = new Kis_Panel_Packbox(globalreg, this);
	hbox->SetPackH();
	hbox->SetHomogenous(1);
	hbox->SetSpacing(1);
	hbox->SetCenter(1);
	hbox->Show();

	hbox->Pack_End(cancelbutton, 0, 0);
	hbox->Pack_End(okbutton, 0, 0);

	vbox->Pack_End(fgcolor, 0, 0);
	vbox->Pack_End(bgcolor, 0, 0);
	vbox->Pack_End(hbox, 1, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	okbutton->SetText("Save");
	cancelbutton->SetText("Cancel");

	fgcolor->Show();
	bgcolor->Show();
	okbutton->Show();
	cancelbutton->Show();

	text_color = 0;
}

Kis_ColorPref_Picker::~Kis_ColorPref_Picker() {

}

void Kis_ColorPref_Picker::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	vbox->SetPosition(1, 2, in_x - 2, in_y - 3);
}

void Kis_ColorPref_Picker::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");
	wbkgdset(win, text_color);
	werase(win);
	DrawTitleBorder();

	wattrset(win, text_color);
	mvwaddstr(win, 1, 5, "Foregound:");
	mvwaddstr(win, 3, 5, "Background:");

	for (unsigned int x = 0; x < pan_comp_vec.size(); x++) {
		if ((pan_comp_vec[x].comp_flags & KIS_PANEL_COMP_DRAW) == 0)
			continue;

		pan_comp_vec[x].comp->DrawComponent();
	}

	wmove(win, 0, 0);
}

void Kis_ColorPref_Picker::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		kpinterface->prefs->SetOpt(prefname,
								  fgcolor->GetColor() + "," +
								  bgcolor->GetColor(), time(0));

		globalreg->panel_interface->KillPanel(this);
		return;
	}

	if (in_button == cancelbutton) {
		globalreg->panel_interface->KillPanel(this);
		return;
	}
}

void Kis_ColorPref_Picker::LinkColorPref(string in_prefname) {
	prefname = in_prefname;

	vector<string> sv = StrTokenize(kpinterface->prefs->FetchOpt(prefname), ",");
	if (sv.size() >= 1)
		fgcolor->SetColor(sv[0]);
	if (sv.size() >= 2)
		bgcolor->SetColor(sv[1]);

}

int ColorPrefCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ColorPref_Panel *) aux)->SelectedAction(component, status);
	return 1;
}

Kis_ColorPref_Panel::Kis_ColorPref_Panel(GlobalRegistry *in_globalref,
										 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalref, in_intf) {

	colorlist = new Kis_Scrollable_Table(globalreg, this);

	colorlist->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ColorPrefCB, this);

	AddComponentVec(colorlist, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 20;
	t.title = "Color";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 20;
	t.title = "Value";
	t.alignment = 0;
	titles.push_back(t);

	colorlist->AddTitles(titles);
	colorlist->Show();

	closebutton = new Kis_Button(globalreg, this);
	closebutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ColorPrefCB, this);
	closebutton->SetText("Close");
	closebutton->Show();
	AddComponentVec(closebutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	vbox->Show();
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	vbox->Pack_End(colorlist, 1, 0);
	vbox->Pack_End(closebutton, 0, 0);

	active_component = colorlist;
	tab_pos = 0;
	colorlist->Activate(0);

	main_component = vbox;

	Position(WIN_CENTER(20, 50));
}

Kis_ColorPref_Panel::~Kis_ColorPref_Panel() {
}

void Kis_ColorPref_Panel::DrawPanel() {
	vector<string> td;
	for (unsigned int x = 0; x < listedcolors.size(); x++) {
		td.clear();
		td.push_back(listedcolors[x].text);
		td.push_back(StrLower(kpinterface->prefs->FetchOpt(listedcolors[x].pref)));
		colorlist->ReplaceRow(x, td);
	}

	Kis_Panel::DrawPanel();
}

void Kis_ColorPref_Panel::SelectedAction(Kis_Panel_Component *component, int listkey) {
	if (component == colorlist) {
		if (listkey >= 0 && listkey <= (int) listedcolors.size()) {
			Kis_ColorPref_Picker *cp = 
				new Kis_ColorPref_Picker(globalreg, kpinterface);
			cp->LinkColorPref(listedcolors[listkey].pref);
			cp->Position((LINES / 2) - 4, (COLS / 2) - 25, 10, 50);
			kpinterface->AddPanel(cp);
		}
	} else if (component == closebutton) {
		globalreg->panel_interface->KillPanel(this);
		return;
	}

	return;
}

void Kis_ColorPref_Panel::AddColorPref(string pref, string name) {
	cprefpair cpp;
	cpp.text = name;
	cpp.pref = pref;

	listedcolors.push_back(cpp);
}

int AutoconprefButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_AutoConPref_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_AutoConPref_Panel::Kis_AutoConPref_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	hostname = new Kis_Single_Input(globalreg, this);
	hostport = new Kis_Single_Input(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);
	autoconcheck = new Kis_Checkbox(globalreg, this);

	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AutoconprefButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AutoconprefButtonCB, this);

	AddComponentVec(hostname, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	AddComponentVec(hostport, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	AddComponentVec(autoconcheck, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));
	tab_pos = 0;

	active_component = hostname;
	hostname->Activate(1);

	SetTitle("Connect to Server");

	hostname->SetLabel("Host", LABEL_POS_LEFT);
	hostname->SetTextLen(120);
	hostname->SetCharFilter(FILTER_ALPHANUMSYM);
	hostname->SetText(kpinterface->prefs->FetchOpt("default_host"), -1, -1);

	hostport->SetLabel("Port", LABEL_POS_LEFT);
	hostport->SetTextLen(5);
	hostport->SetCharFilter(FILTER_NUM);
	hostport->SetText(kpinterface->prefs->FetchOpt("default_port"), -1, -1);

	autoconcheck->SetText("Auto-connect");
	// autoconcheck->SetChecked(kpinterface->prefs->FetchOpt("autoconnect") == "true");
	autoconcheck->SetChecked(kpinterface->prefs->FetchOptBoolean("autoconnect", 0));

	okbutton->SetText("Save");
	cancelbutton->SetText("Cancel");

	hostname->Show();
	hostport->Show();
	autoconcheck->Show();
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
	vbox->Pack_End(autoconcheck, 0, 0);
	vbox->Pack_End(bbox, 1, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	active_component = hostname;
	hostname->Activate(1);
	main_component = vbox;

	Position(WIN_CENTER(11, 40));
}

Kis_AutoConPref_Panel::~Kis_AutoConPref_Panel() {
}

void Kis_AutoConPref_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	vbox->SetPosition(1, 2, in_x - 2, in_y - 3);
}

void Kis_AutoConPref_Panel::DrawPanel() {
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

void Kis_AutoConPref_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		kpinterface->prefs->SetOpt("default_host",
								  hostname->GetText(), 1);

		kpinterface->prefs->SetOpt("default_port",
								  hostport->GetText(), 1);

		kpinterface->prefs->SetOpt("autoconnect",
								  autoconcheck->GetChecked() ?
								  "true" : "false", 1);

		globalreg->panel_interface->KillPanel(this);
	} else if (in_button == cancelbutton) {
		// Cancel and close
		globalreg->panel_interface->KillPanel(this);
	}

	return;
}

Kis_OrderlistPref_Component::Kis_OrderlistPref_Component(GlobalRegistry *in_globalreg,
														 Kis_Panel *in_panel) :
	Kis_Scrollable_Table(in_globalreg, in_panel) {
	globalreg = in_globalreg;

	selected = -1;
	orderable = 0;
	enable_fid = -1;
	field_yes = field_no = "";
}

Kis_OrderlistPref_Component::~Kis_OrderlistPref_Component() {

}

void Kis_OrderlistPref_Component::SetOrderable(int in_order) {
	orderable = in_order;
}

void Kis_OrderlistPref_Component::SetEnableField(int in_field, string in_yes,
												 string in_no) {
	enable_fid = in_field;
	field_yes = in_yes;
	field_no = in_no;
}

void Kis_OrderlistPref_Component::SetColumnField(int in_field) {
	column_fid = in_field;
}

int Kis_OrderlistPref_Component::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	if (orderable) {
		// Just swap fields around and then treat it like a user-keyed move 
		if (in_key == '-' && selected > 0) {
			row_data *bak = data_vec[selected - 1];
			data_vec[selected - 1] = data_vec[selected];
			data_vec[selected] = bak;
			Kis_Scrollable_Table::KeyPress(KEY_UP);
		}

		if (in_key == '+' && selected < (int) data_vec.size() - 1) {
			row_data *bak = data_vec[selected + 1];
			data_vec[selected + 1] = data_vec[selected];
			data_vec[selected] = bak;
			Kis_Scrollable_Table::KeyPress(KEY_DOWN);
		}
	}

	if (enable_fid >= 0) {
		if ((in_key == ' ' || in_key == '\n') &&
			(int) data_vec[selected]->data.size() > enable_fid) {
			// Toggle the enable field of the current row
			if (data_vec[selected]->data[enable_fid] == field_no) 
				data_vec[selected]->data[enable_fid] = field_yes;
			else
				data_vec[selected]->data[enable_fid] = field_no;
		}
	}

	return Kis_Scrollable_Table::KeyPress(in_key);
}

string Kis_OrderlistPref_Component::GetStringOrderList() {
	string ret;

	if (column_fid < 0)
		return "";

	for (unsigned int x = 0; x < data_vec.size(); x++) {
		if (enable_fid >= 0 && (int) data_vec[x]->data.size() > enable_fid &&
			(int) data_vec[x]->data.size() > column_fid) {
			if (data_vec[x]->data[enable_fid] == field_yes) {
				ret += ((x > 0) ? string(",") : string("")) + 
					data_vec[x]->data[column_fid];
			}
		}
	}

	return ret;
}

int ColumnPrefButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ColumnPref_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_ColumnPref_Panel::Kis_ColumnPref_Panel(GlobalRegistry *in_globalreg, 
										   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	orderlist = new Kis_OrderlistPref_Component(globalreg, this);
	helptext = new Kis_Free_Text(globalreg, this);

	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);

	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ColumnPrefButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ColumnPrefButtonCB, this);

	AddComponentVec(orderlist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								KIS_PANEL_COMP_EVT));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
							   KIS_PANEL_COMP_EVT));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								   KIS_PANEL_COMP_EVT));
	tab_pos = 0;

	active_component = orderlist;
	orderlist->Activate(1);

	SetTitle("Column Preferences");

	// Set the titles, pref and enable columns, and re-ordering
	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 16;
	t.title = "Column";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 4;
	t.title = "Show";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 30;
	t.title = "Description";
	t.alignment = 0;
	titles.push_back(t);

	orderlist->AddTitles(titles);
	orderlist->SetColumnField(0);
	orderlist->SetEnableField(1, "Yes", "No");
	orderlist->SetOrderable(1);

	helptext->SetText("Select with space, change order with +/-");

	okbutton->SetText("Save");
	cancelbutton->SetText("Cancel");

	orderlist->Show();
	helptext->Show();
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
	bbox->SetPreferredSize(0, 1);
	bbox->SetMinSize(0, 1);
	bbox->Show();

	bbox->Pack_End(cancelbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);

	vbox->Pack_End(orderlist, 1, 0);
	vbox->Pack_End(helptext, 0, 0);
	vbox->Pack_End(bbox, 0, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	pref = "";

	Position(WIN_CENTER(20, 60));
}

Kis_ColumnPref_Panel::~Kis_ColumnPref_Panel() {
}

void Kis_ColumnPref_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	vbox->SetPosition(1, 2, in_x - 1, in_y - 3);
}

void Kis_ColumnPref_Panel::DrawPanel() {
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

void Kis_ColumnPref_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		if (pref != "") {
			kpinterface->prefs->SetOpt(pref,
									  orderlist->GetStringOrderList(), time(0));
		}

		rc = 1;
		globalreg->panel_interface->KillPanel(this);
	} else if (in_button == cancelbutton) {
		// Cancel and close
		rc = 0;
		globalreg->panel_interface->KillPanel(this);
	}

	return;
}

void Kis_ColumnPref_Panel::AddColumn(string colname, string description) {
	pref_cols p;

	p.colname = colname;
	p.description = description;
	p.queued = 0;

	pref_vec.push_back(p);
}

void Kis_ColumnPref_Panel::ColumnPref(string in_pref, string name) {
	vector<string> curprefs = 
		StrTokenize(kpinterface->prefs->FetchOpt(in_pref), ",");
	vector<string> fdata;
	int k = 0;

	pref = in_pref;

	fdata.push_back("col");
	fdata.push_back("enb");
	fdata.push_back("dsc");

	// Enable the fields
	for (unsigned int cp = 0; cp < curprefs.size(); cp++) {
		for (unsigned int sp = 0; sp < pref_vec.size(); sp++) {
			if (StrLower(pref_vec[sp].colname) == StrLower(curprefs[cp])) {
				fdata[0] = pref_vec[sp].colname;
				fdata[1] = "Yes";
				fdata[2] = pref_vec[sp].description;
				orderlist->ReplaceRow(k++, fdata);
				pref_vec[sp].queued = 1;
			}
		}
	}

	// Add the other fields we know about which weren't in the preferences
	for (unsigned int sp = 0; sp < pref_vec.size(); sp++) {
		if (pref_vec[sp].queued)
			continue;

		fdata[0] = pref_vec[sp].colname;
		fdata[1] = "No";
		fdata[2] = pref_vec[sp].description;
		orderlist->ReplaceRow(k++, fdata);
		pref_vec[sp].queued = 1;
	}

	SetTitle(name + " Column Preferences");
}

int GpsconfButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_GpsPref_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_GpsPref_Panel::Kis_GpsPref_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf):
	Kis_Panel(in_globalreg, in_intf) {

	metrad = new Kis_Radiobutton(globalreg, this);
	metrad->SetText("Metric");
	metrad->SetCallback(COMPONENT_CBTYPE_ACTIVATED, GpsconfButtonCB, this);
	metrad->Show();
	metrad->SetChecked(1);
	AddComponentVec(metrad, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							 KIS_PANEL_COMP_TAB));

	engrad = new Kis_Radiobutton(globalreg, this);
	engrad->SetText("English");
	engrad->SetCallback(COMPONENT_CBTYPE_ACTIVATED, GpsconfButtonCB, this);
	engrad->Show();
	engrad->SetChecked(1);
	AddComponentVec(engrad, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));

	engrad->LinkRadiobutton(metrad);
	metrad->LinkRadiobutton(engrad);

	okbutton = new Kis_Button(globalreg, this);
	okbutton->SetText("OK");
	okbutton->Show();
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	
	cancelbutton = new Kis_Button(globalreg, this);
	cancelbutton->SetText("Cancel");
	cancelbutton->Show();
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));

	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, GpsconfButtonCB, this);
	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, GpsconfButtonCB, this);

	SetTitle("Configure GPS");

	cbox = new Kis_Panel_Packbox(globalreg, this);
	cbox->SetPackH();
	cbox->SetHomogenous(1);
	cbox->SetSpacing(1);
	cbox->SetCenter(1);
	AddComponentVec(cbox, KIS_PANEL_COMP_DRAW);
	cbox->Pack_End(metrad, 0, 0);
	cbox->Pack_End(engrad, 0, 0);
	cbox->Show();

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(0);
	bbox->SetCenter(1);
	AddComponentVec(bbox, KIS_PANEL_COMP_DRAW);

	bbox->Pack_End(cancelbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);
	bbox->Show();

	helptext = new Kis_Free_Text(globalreg, this);
	helptext->SetText("Display GPS in Metric (km) or English (miles)");
	helptext->Show();

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	vbox->Pack_End(helptext, 0, 0);
	vbox->Pack_End(cbox, 1, 0);
	vbox->Pack_End(bbox, 0, 0);
	
	vbox->Show();

	tab_pos = 0;
	metrad->Activate(1);
	active_component = metrad;

	if (StrLower(kpinterface->prefs->FetchOpt("GPSUNIT")) != "metric") {
		engrad->SetChecked(1);
	} else {
		metrad->SetChecked(1);
	}

	main_component = vbox;
	Position(WIN_CENTER(10, 70));
}

Kis_GpsPref_Panel::~Kis_GpsPref_Panel() {
}

void Kis_GpsPref_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	vbox->SetPosition(1, 1, in_x - 1, in_y - 2);
}

void Kis_GpsPref_Panel::DrawPanel() {
	Kis_Panel::DrawPanel();
}

void Kis_GpsPref_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		if (engrad->GetChecked()) {
			kpinterface->prefs->SetOpt("GPSUNIT", "english", 1);
		} else {
			kpinterface->prefs->SetOpt("GPSUNIT", "metric", 1);
		}

		kpinterface->KillPanel(this);
	} else if (in_button == cancelbutton) {
		kpinterface->KillPanel(this);
	}
}

int StartupButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_StartupPref_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_StartupPref_Panel::Kis_StartupPref_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf):
	Kis_Panel(in_globalreg, in_intf) {


	startkis_check = new Kis_Checkbox(globalreg, this);
	startkis_check->SetText("Open Kismet server launch window automatically");
	startkis_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, StartupButtonCB, this);
	startkis_check->Show();
	AddComponentVec(startkis_check, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									 KIS_PANEL_COMP_TAB));

	startkisprompt_check = new Kis_Checkbox(globalreg, this);
	startkisprompt_check->SetText("Ask about launching server on startup");
	startkisprompt_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, StartupButtonCB, this);
	startkisprompt_check->Show();
	AddComponentVec(startkisprompt_check, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									 KIS_PANEL_COMP_TAB));

	startcons_check = new Kis_Checkbox(globalreg, this);
	startcons_check->SetText("Show Kismet server console by default");
	startcons_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, StartupButtonCB, this);
	startcons_check->Show();
	AddComponentVec(startcons_check, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									  KIS_PANEL_COMP_TAB));

	stopkis_check = new Kis_Checkbox(globalreg, this);
	stopkis_check->SetText("Shut down Kismet server on exit automatically");
	stopkis_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, StartupButtonCB, this);
	stopkis_check->Show();
	AddComponentVec(stopkis_check, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									KIS_PANEL_COMP_TAB));

	stopkisprompt_check = new Kis_Checkbox(globalreg, this);
	stopkisprompt_check->SetText("Prompt before shutting down Kismet server");
	stopkisprompt_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, StartupButtonCB, this);
	stopkisprompt_check->Show();
	AddComponentVec(stopkisprompt_check, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
										  KIS_PANEL_COMP_TAB));

	okbutton = new Kis_Button(globalreg, this);
	okbutton->SetText("OK");
	okbutton->Show();
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	
	cancelbutton = new Kis_Button(globalreg, this);
	cancelbutton->SetText("Cancel");
	cancelbutton->Show();
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));

	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, GpsconfButtonCB, this);
	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, GpsconfButtonCB, this);

	SetTitle("Startup Options");

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(0);
	bbox->SetCenter(1);
	AddComponentVec(bbox, KIS_PANEL_COMP_DRAW);

	bbox->Pack_End(cancelbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);
	bbox->Show();

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	vbox->Pack_End(startkis_check, 0, 0);
	vbox->Pack_End(startkisprompt_check, 0, 0);
	vbox->Pack_End(startcons_check, 0, 0);
	vbox->Pack_End(stopkis_check, 0, 0);
	vbox->Pack_End(stopkisprompt_check, 0, 0);
	vbox->Pack_End(bbox, 0, 0);
	
	vbox->Show();

	main_component = vbox;

	tab_pos = 0;
	startkis_check->Activate(1);
	active_component = startkis_check;

	// if (StrLower(kpinterface->prefs->FetchOpt("STARTUP_SERVER")) == "true" ||
	//	kpinterface->prefs->FetchOpt("STARTUP_SERVER") == "") {
	if (kpinterface->prefs->FetchOptBoolean("STARTUP_SERVER", 1)) {
		startkis_check->SetChecked(1);
	} else {
		startkis_check->SetChecked(0);
	}

	// if (StrLower(kpinterface->prefs->FetchOpt("STARTUP_PROMPTSERVER")) == "true" ||
	// 	kpinterface->prefs->FetchOpt("STARTUP_PROMPTSERVER") == "") {
	if (kpinterface->prefs->FetchOptBoolean("STARTUP_PROMPTSERVER", 1)) {
		startkisprompt_check->SetChecked(1);
	} else {
		startkisprompt_check->SetChecked(0);
	}

	// if (StrLower(kpinterface->prefs->FetchOpt("STARTUP_CONSOLE")) == "true" ||
	// 	kpinterface->prefs->FetchOpt("STARTUP_CONSOLE") == "") {
	if (kpinterface->prefs->FetchOptBoolean("STARTUP_CONSOLE", 1)) {
		startcons_check->SetChecked(1);
	} else {
		startcons_check->SetChecked(0);
	}

	// if (StrLower(kpinterface->prefs->FetchOpt("STOP_SERVER")) == "true" ||
	// 	kpinterface->prefs->FetchOpt("STOP_SERVER") == "") {
	if (kpinterface->prefs->FetchOptBoolean("STOP_SERVER", 1)) {
		stopkis_check->SetChecked(1);
	} else {
		stopkis_check->SetChecked(0);
	}

	// if (StrLower(kpinterface->prefs->FetchOpt("STOP_PROMPTSERVER")) == "true" ||
	// 	kpinterface->prefs->FetchOpt("STOP_PROMPTSERVER") == "") {
	if (kpinterface->prefs->FetchOptBoolean("STOP_PROMPTSERVER", 1)) {
		stopkisprompt_check->SetChecked(1);
	} else {
		stopkisprompt_check->SetChecked(0);
	}

	Position(WIN_CENTER(14, 70));
}

Kis_StartupPref_Panel::~Kis_StartupPref_Panel() {
}

void Kis_StartupPref_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		if (startkis_check->GetChecked()) {
			kpinterface->prefs->SetOpt("STARTUP_SERVER", "true", 1);
		} else {
			kpinterface->prefs->SetOpt("STARTUP_SERVER", "false", 1);
		}

		if (startkisprompt_check->GetChecked()) {
			kpinterface->prefs->SetOpt("STARTUP_PROMPTSERVER", "true", 1);
		} else {
			kpinterface->prefs->SetOpt("STARTUP_PROMPTSERVER", "false", 1);
		}

		if (startcons_check->GetChecked()) {
			kpinterface->prefs->SetOpt("STARTUP_CONSOLE", "true", 1);
		} else {
			kpinterface->prefs->SetOpt("STARTUP_CONSOLE", "false", 1);
		} 

		if (stopkis_check->GetChecked()) {
			kpinterface->prefs->SetOpt("STOP_SERVER", "true", 1);
		} else {
			kpinterface->prefs->SetOpt("STOP_SERVER", "false", 1);
		} 

		if (stopkisprompt_check->GetChecked()) {
			kpinterface->prefs->SetOpt("STOP_PROMPTSERVER", "true", 1);
		} else {
			kpinterface->prefs->SetOpt("STOP_PROMPTSERVER", "false", 1);
		}

		kpinterface->KillPanel(this);
	} else if (in_button == cancelbutton) {
		kpinterface->KillPanel(this);
	}
}

#if 0
int AudioPickerCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_AudioPicker_Panel *) aux)->Action(component, status);
	return 1;
}

Kis_AudioPicker_Panel::Kis_AudioPicker_Panel(GlobalRegistry *in_globalreg, 
											 KisPanelInterface *in_intf):
	Kis_Panel(in_globalreg, in_intf) {

	filelist = new Kis_Filepicker(globalreg, this);
	filelist->Show();
	AddComponentVec(filelist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));

	directory = new Kis_Single_Input(globalreg, this);
	directory->SetLabel("Dir:", LABEL_POS_LEFT);
	directory->SetCharFilter(FILTER_ALPHANUMSYM);
	directory->Show();
	AddComponentVec(directory, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								KIS_PANEL_COMP_TAB));
	
	dirbutton = new Kis_Button(globalreg, this);
	dirbutton->SetLabel("Change Dir");
	dirbutton->Show();
	dirbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPickerCB, this);

	enablecheck = new Kis_Checkbox(globalreg, this);
	enablecheck->SetLabel("Play Sound");
	enablecheck->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPickerCB, this);
	AddComponentVec(enablecheck, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));

	okbutton = new Kis_Button(globalreg, this);
	okbutton->SetLabel("Save");
	okbutton->Show();
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPickerCB, this);
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));

	cancelbutton = new Kis_Button(globalreg, this);
	cancelbutton->SetLabel("Cancel");
	cancelbutton->Show();
	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPickerCB, this);
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));

	SetTitle("Pick Sound");

	dbox = new Kis_Panel_Packbox(globalreg, this);
	dbox->SetPackH();
	dbox->SetHomogenous(0);
	dbox->SetSpacing(0);
	dbox->SetCenter(1);
	AddComponentVec(dbox, KIS_PANEL_COMP_DRAW);

	dbox->Pack_End(directory, 1, 0);
	dbox->Pack_End(dirbutton, 0, 0);
	dbox->Show();

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(1);
	bbox->SetCenter(1);
	AddComponentVec(bbox, KIS_PANEL_COMP_DRAW);

	bbox->Pack_End(cancelbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);
	bbox->Show();

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	vbox->Pack_End(filelist, 1, 0);
	vbox->Pack_End(dbox, 0, 0);
	vbox->Pack_End(enablecheck, 0, 0);
	vbox->Pack_End(bbox, 0, 0);
	
	vbox->Show();

	main_component = vbox;

	SetActiveComponent(filelist);

	Position(WIN_CENTER(15, 70));
}

Kis_AudioPicker_Panel::~Kis_AudioPicker_Panel() {

}

void Kis_AudioPicker_Panel::SetPref(string in_trigger, string in_enable, 
									string in_file) {
	trigger = in_trigger;
	size_t dpos;

	enablecheck->SetChecked(in_enable == "true");

	if ((dpos = in_file.rfind("/")) == string::npos) {
		filelist->SetDirectory(kpinterface->prefs->FetchOpt("SOUND_PREFIX"));
		filelist->SetFile(in_file);
		directory->SetText(kpinterface->prefs->FetchOpt("SOUND_PREFIX"), -1, -1);
	} else {
		filelist->SetDirectory(in_file.substr(0, dpos));
		filelist->SetFile(in_file.substr(dpos + 1, in_file.length()));
		directory->SetText(in_file.substr(0, dpos), -1, -1);
	}
}

void Kis_AudioPicker_Panel::Action(Kis_Panel_Component *in_component, int in_status) {
	if (in_component == cancelbutton) {
		kpinterface->KillPanel(this);
		return;
	}

	if (in_component == dirbutton) {
		filelist->SetDirectory(directory->GetText());
		return;
	}

	if (in_component == okbutton) {
		string d = filelist->GetDirectory();
		vector<string> sd = filelist->GetSelectedData();
		struct stat sbuf;

		if (sd.size() == 0) {
			kpinterface->RaiseAlert("No selected file",
				InLineWrap("No file to play was selected, pick one or cancel", 0, 50));
			return;
		}

		if (d == kpinterface->prefs->FetchOpt("SOUND_PREFIX") ||
			(d + "/") == kpinterface->prefs->FetchOpt("SOUND_PREFIX"))
			d = sd[0];
		else
			d += sd[0];

		if (stat(d.c_str(), &sbuf) != 0) {
			kpinterface->RaiseAlert("Selected file missing",
				InLineWrap(string("Selected file is missing (") + 
						   string(strerror(errno)) + string("), pick another or cancel"),
						   0, 50));
			return;
		}

		if (S_ISDIR(sbuf.st_mode)) {
			kpinterface->RaiseAlert("Selected directory",
				InLineWrap("Selected is a directory, pick a file or cancel", 0, 50));
			return;
		}

		kpinterface->prefs->SetOpt("SOUND", trigger + string(",") + 
								   (enablecheck->GetChecked() ? "true" : "false") +
								   string(",") + d, 1);
	}
}

#endif

int AudioPrefCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_AudioPref_Panel *) aux)->Action(component, status);
	return 1;
}

Kis_AudioPref_Panel::Kis_AudioPref_Panel(GlobalRegistry *in_globalreg, 
										 KisPanelInterface *in_intf):
	Kis_Panel(in_globalreg, in_intf) {

	audiolist = new Kis_Scrollable_Table(globalreg, this);

	audiolist->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPrefCB, this);

	AddComponentVec(audiolist, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 0;
	t.title = "Sound";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 4;
	t.title = "Play";
	t.alignment = 0;
	titles.push_back(t);

	audiolist->SetPreferredSize(0, 6);

	audiolist->AddTitles(titles);
	audiolist->Show();

	vector<string> aprefs = kpinterface->prefs->FetchOptVec("SOUND");

	vector<string> tdata;
	tdata.push_back("");
	tdata.push_back("");

	keys.clear();

	for (unsigned int a = 0; a < aprefs.size(); a++) {
		vector<string> pvec = StrTokenize(aprefs[a], ",");
		int valid = 0;
		
		if (pvec.size() != 2)
			continue;

		pvec[0] = StrLower(pvec[0]);

		// Only process the sounds we know about
		if (pvec[0] == "alert") {
			valid = 1;
			tdata[0] = "Alert";
		} else if (pvec[0] == "packet") {
			valid = 1;
			tdata[0] = "Packet";
		} else if (pvec[0] == "newnet") {
			valid = 1;
			tdata[0] = "New Network";
		} else if (pvec[0] == "gpslock") {
			valid = 1;
			tdata[0] = "GPS Lock";
		} else if (pvec[0] == "gpslost") {
			valid = 1;
			tdata[0] = "GPS Lost";
		}

		if (valid) {
			string enable = (StrLower(pvec[1]) == "true") ? "Yes" : "No";
			tdata[1] = enable;

			audiolist->ReplaceRow(a, tdata);
			keys.push_back(a);
		}
	}

	sound_check = new Kis_Checkbox(globalreg, this);
	sound_check->SetText("Enable Sound");
	// sound_check->SetChecked(StrLower(kpinterface->prefs->FetchOpt("SOUNDENABLE")) == 
	// 						"true");
	sound_check->SetChecked(kpinterface->prefs->FetchOptBoolean("SOUNDENABLE", 0));
	sound_check->Show();
	sound_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPrefCB, this);
	AddComponentVec(sound_check, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									 KIS_PANEL_COMP_TAB));

	speech_check = new Kis_Checkbox(globalreg, this);
	speech_check->SetText("Enable Speech");
	// speech_check->SetChecked(StrLower(kpinterface->prefs->FetchOpt("SPEECHENABLE")) ==
	// 						 "true");
	speech_check->SetChecked(kpinterface->prefs->FetchOptBoolean("SPEECHENABLE", 0));
	speech_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPrefCB, this);
	speech_check->Show();
	AddComponentVec(speech_check, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									 KIS_PANEL_COMP_TAB));

	sound_player = new Kis_Single_Input(globalreg, this);
	sound_player->SetLabel("Player", LABEL_POS_LEFT);
	sound_player->SetText(kpinterface->prefs->FetchOpt("SOUNDBIN"), -1, -1);
	sound_player->SetCharFilter(FILTER_ALPHANUMSYM);
	sound_player->SetTextLen(64);
	sound_player->Show();
	AddComponentVec(sound_player, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));

	config_speech_button = new Kis_Button(globalreg, this);
	config_speech_button->SetText("Configure Speech");
	config_speech_button->Show();
	config_speech_button->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPrefCB, this);
	AddComponentVec(config_speech_button, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
										   KIS_PANEL_COMP_TAB));

	close_button = new Kis_Button(globalreg, this);
	close_button->SetText("Close");
	close_button->Show();
	close_button->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AudioPrefCB, this);
	AddComponentVec(close_button, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));
	
	SetTitle("Sound Options");

	cbox = new Kis_Panel_Packbox(globalreg, this);
	cbox->SetPackH();
	cbox->SetHomogenous(1);
	cbox->SetSpacing(0);
	cbox->SetCenter(1);
	AddComponentVec(cbox, KIS_PANEL_COMP_DRAW);

	cbox->Pack_End(sound_check, 0, 0);
	cbox->Pack_End(speech_check, 0, 0);
	cbox->Show();

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	vbox->Pack_End(audiolist, 1, 0);
	vbox->Pack_End(cbox, 0, 0);
	vbox->Pack_End(sound_player, 0, 0);
	vbox->Pack_End(config_speech_button, 0, 0);
	vbox->Pack_End(close_button, 0, 0);
	
	vbox->Show();

	main_component = vbox;

	SetActiveComponent(audiolist);

	Position(WIN_CENTER(15, 50));
}

Kis_AudioPref_Panel::~Kis_AudioPref_Panel() {

}

void Kis_AudioPref_Panel::Action(Kis_Panel_Component *in_component, 
										 int in_status) {
	if (in_component == close_button) {
		vector<string> prefs;
		for (unsigned int x = 0; x < keys.size(); x++) {
			string h;
			vector<string> td = audiolist->GetRow(keys[x]);
			if (td.size() != 2)
				continue;

			if (td[0] == "Alert")
				h = "alert";
			else if (td[0] == "Packet")
				h = "packet";
			else if (td[0] == "New Network")
				h = "newnet";
			else if (td[0] == "GPS Lost")
				h = "gpslost";
			else if (td[0] == "GPS Lock")
				h = "gpslock";
			else  {
				_MSG("INTERNAL ERROR: SNDPREF saw '" + td[0] + "' and didn't know what "
					 "it was", MSGFLAG_ERROR);
				continue;
			}

			prefs.push_back(h + string(",") + (td[1] == "Yes" ? "true" : "false"));
		}
		kpinterface->prefs->SetOptVec("sound", prefs, 1);

		kpinterface->prefs->SetOpt("SOUNDENABLE", 
								   sound_check->GetChecked() ? "true" : "false", 1);
		globalreg->soundctl->SetSoundEnable(sound_check->GetChecked());

		kpinterface->prefs->SetOpt("SPEECHENABLE",
								   speech_check->GetChecked() ? "true" : "false", 1);
		globalreg->soundctl->SetSpeechEnable(sound_check->GetChecked());

		if (sound_player->GetText() != kpinterface->prefs->FetchOpt("SOUNDBIN")) {
			kpinterface->prefs->SetOpt("SOUNDBIN", sound_player->GetText(), 0);
			globalreg->soundctl->SetPlayer(sound_player->GetText());
		}

		// Reload the prefs
		kpinterface->FetchMainPanel()->LoadAudioPrefs();

		kpinterface->KillPanel(this);
		return;
	}

	if (in_component == audiolist) {
		vector<string> selrow = audiolist->GetSelectedData();

		if (selrow.size() == 0)
			return;

		if (selrow[1] == "Yes")
			selrow[1] = "No";
		else
			selrow[1] = "Yes";

		audiolist->ReplaceRow(audiolist->GetSelected(), selrow);
	}

	if (in_component == config_speech_button) {
		Kis_SpeechPref_Panel *sp = new Kis_SpeechPref_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(sp);
	}
}

void Kis_AudioPref_Panel::DrawPanel() {
	Kis_Panel::DrawPanel();
}

int SpeechPrefCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_SpeechPref_Panel *) aux)->Action(component, status);
	return 1;
}

Kis_SpeechPref_Panel::Kis_SpeechPref_Panel(GlobalRegistry *in_globalreg, 
										   KisPanelInterface *in_intf):
	Kis_Panel(in_globalreg, in_intf) {

	vector<string> ft;

	speechtype_text = new Kis_Free_Text(globalreg, this);
	ft.clear();
	ft.push_back("See the Kismet README for how speech strings are expanded");
	speechtype_text->SetText(ft);
	speechtype_text->Show();

	speech_new = new Kis_Single_Input(globalreg, this);
	speech_new->SetLabel("New", LABEL_POS_LEFT);
	speech_new->SetCharFilter(FILTER_ALPHANUMSYM);
	speech_new->SetTextLen(64);
	AddComponentVec(speech_new, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								 KIS_PANEL_COMP_TAB));
	speech_new->Show();

	speech_alert = new Kis_Single_Input(globalreg, this);
	speech_alert->SetLabel("Alert", LABEL_POS_LEFT);
	speech_alert->SetCharFilter(FILTER_ALPHANUMSYM);
	speech_alert->SetTextLen(64);
	AddComponentVec(speech_alert, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));
	speech_alert->Show();

	speech_gpslost = new Kis_Single_Input(globalreg, this);
	speech_gpslost->SetLabel("GPS Lost", LABEL_POS_LEFT);
	speech_gpslost->SetCharFilter(FILTER_ALPHANUMSYM);
	speech_gpslost->SetTextLen(64);
	AddComponentVec(speech_gpslost, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									 KIS_PANEL_COMP_TAB));
	speech_gpslost->Show();

	speech_gpslock = new Kis_Single_Input(globalreg, this);
	speech_gpslock->SetLabel("GPS OK", LABEL_POS_LEFT);
	speech_gpslock->SetCharFilter(FILTER_ALPHANUMSYM);
	speech_gpslock->SetTextLen(64);
	AddComponentVec(speech_gpslock, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									 KIS_PANEL_COMP_TAB));
	speech_gpslock->Show();

	speechplayer_text = new Kis_Free_Text(globalreg, this);
	ft.clear();
	ft.push_back("If using Festival, be sure to enable the Festival mode checkbox");
	speechplayer_text->SetText(ft);
	speechplayer_text->Show();

	speaker = new Kis_Single_Input(globalreg, this);
	speaker->SetLabel("Speech Player", LABEL_POS_LEFT);
	speaker->SetCharFilter(FILTER_ALPHANUMSYM);
	speaker->SetTextLen(64);
	AddComponentVec(speaker, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));
	speaker->Show();
	speaker->SetText(kpinterface->prefs->FetchOpt("SPEECHBIN"), -1, -1);

	fest_check = new Kis_Checkbox(globalreg, this);
	fest_check->SetLabel("Festival Mode");
	AddComponentVec(fest_check, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								 KIS_PANEL_COMP_TAB));
	fest_check->Show();
	fest_check->SetChecked(
		StrLower(kpinterface->prefs->FetchOpt("SPEECHTYPE")) == "festival");


	encode_text = new Kis_Free_Text(globalreg, this);
	ft.clear();
	ft.push_back("SSID encoding:");
	encode_text->SetText(ft);
	encode_text->Show();

	encode_none_radio = new Kis_Radiobutton(globalreg, this);
	encode_none_radio->SetText("Normal");
	encode_none_radio->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpeechPrefCB, this);
	encode_none_radio->Show();
	encode_none_radio->SetChecked(1);
	AddComponentVec(encode_none_radio, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
										KIS_PANEL_COMP_TAB));

	encode_nato_radio = new Kis_Radiobutton(globalreg, this);
	encode_nato_radio->SetText("Nato");
	encode_nato_radio->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpeechPrefCB, this);
	encode_nato_radio->Show();
	encode_nato_radio->SetChecked(1);
	AddComponentVec(encode_nato_radio, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
										KIS_PANEL_COMP_TAB));

	encode_spell_radio = new Kis_Radiobutton(globalreg, this);
	encode_spell_radio->SetText("Spell");
	encode_spell_radio->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpeechPrefCB, this);
	encode_spell_radio->Show();
	encode_spell_radio->SetChecked(1);
	AddComponentVec(encode_spell_radio, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
										 KIS_PANEL_COMP_TAB));

	encode_none_radio->LinkRadiobutton(encode_nato_radio);
	encode_none_radio->LinkRadiobutton(encode_spell_radio);
	encode_nato_radio->LinkRadiobutton(encode_none_radio);
	encode_nato_radio->LinkRadiobutton(encode_spell_radio);
	encode_spell_radio->LinkRadiobutton(encode_nato_radio);
	encode_spell_radio->LinkRadiobutton(encode_none_radio);

	if (StrLower(kpinterface->prefs->FetchOpt("SPEECHENCODING")) == "nato") {
		encode_nato_radio->SetChecked(1);
	} else if (StrLower(kpinterface->prefs->FetchOpt("SPEECHENCODING")) == "spell") {
		encode_spell_radio->SetChecked(1);
	} else {
		encode_none_radio->SetChecked(1);
	}

	close_button = new Kis_Button(globalreg, this);
	close_button->SetText("Close");
	close_button->Show();
	close_button->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpeechPrefCB, this);
	AddComponentVec(close_button, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));
	
	SetTitle("Sound Options");

	rbox = new Kis_Panel_Packbox(globalreg, this);
	rbox->SetPackH();
	rbox->SetHomogenous(1);
	rbox->SetSpacing(0);
	rbox->SetCenter(1);
	AddComponentVec(rbox, KIS_PANEL_COMP_DRAW);

	rbox->Pack_End(encode_none_radio, 0, 0);
	rbox->Pack_End(encode_nato_radio, 0, 0);
	rbox->Pack_End(encode_spell_radio, 0, 0);
	rbox->Show();

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	vbox2 = new Kis_Panel_Packbox(globalreg, this);
	vbox2->SetPackV();
	vbox2->SetHomogenous(0);
	vbox2->SetSpacing(0);
	AddComponentVec(vbox2, KIS_PANEL_COMP_DRAW);
	vbox2->Pack_End(speechtype_text, 0, 0);
	vbox2->Pack_End(speech_new, 0, 0);
	vbox2->Pack_End(speech_alert, 0, 0);
	vbox2->Pack_End(speech_gpslost, 0, 0);
	vbox2->Pack_End(speech_gpslock, 0, 0);
	vbox2->SetPreferredSize(0, 5);
	vbox2->Show();
	vbox->Pack_End(vbox2, 0, 0);

	vbox->Pack_End(speechplayer_text, 0, 0);
	vbox->Pack_End(speaker, 0, 0);
	vbox->Pack_End(fest_check, 0, 0);
	vbox->Pack_End(encode_text, 0, 0);
	vbox->Pack_End(rbox, 0, 0);
	vbox->Pack_End(close_button, 0, 0);

	vbox->Show();

	main_component = vbox;

	SetActiveComponent(speech_new);

	Position(WIN_CENTER(18, 50));

	vector<string> spref = kpinterface->prefs->FetchOptVec("speech");
	vector<string> sf;
	string st;
	for (unsigned int x = 0; x < spref.size(); x++) {
		sf = QuoteStrTokenize(spref[x], ",");

		if (sf.size() != 2)
			continue;

		st = StrLower(sf[0]);

		if (st == "new") 
			speech_new->SetText(sf[1], -1, -1);
		else if (st == "alert")
			speech_alert->SetText(sf[1], -1, -1);
		else if (st == "gpslost")
			speech_gpslost->SetText(sf[1], -1, -1);
		else if (st == "gpslock")
			speech_gpslock->SetText(sf[1], -1, -1);
	}
}

Kis_SpeechPref_Panel::~Kis_SpeechPref_Panel() {

}

void Kis_SpeechPref_Panel::Action(Kis_Panel_Component *in_component, 
								  int in_status) {
	if (in_component == close_button) {
		vector<string> prefs;
		prefs.push_back("new,\"" + speech_new->GetText() + "\"");
		prefs.push_back("alert,\"" + speech_alert->GetText() + "\"");
		prefs.push_back("gpslost,\"" + speech_gpslost->GetText() + "\"");
		prefs.push_back("gpslock,\"" + speech_gpslock->GetText() + "\"");

		kpinterface->prefs->SetOptVec("SPEECH", prefs, 1);

		kpinterface->prefs->SetOpt("SPEECHBIN", speaker->GetText(), 1);

		kpinterface->prefs->SetOpt("SPEECHTYPE",
								   fest_check->GetChecked() ? "festival" : "raw", 1);

		globalreg->soundctl->SetSpeaker(speaker->GetText(),
										fest_check->GetChecked() ? "festival" : "raw");

		if (encode_none_radio->GetChecked()) {
			kpinterface->prefs->SetOpt("SPEECHENCODING", "speech", 1);
			globalreg->soundctl->SetSpeechEncode("speech");
		} else if (encode_nato_radio->GetChecked()) {
			kpinterface->prefs->SetOpt("SPEECHENCODING", "nato", 1);
			globalreg->soundctl->SetSpeechEncode("nato");
		} else if (encode_spell_radio->GetChecked()) { 
			kpinterface->prefs->SetOpt("SPEECHENCODING", "spell", 1);
			globalreg->soundctl->SetSpeechEncode("spell");
		}

		kpinterface->KillPanel(this);
		return;
	}
}

int WarnPrefCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_WarnPref_Panel *) aux)->Action(component, status);
	return 1;
}

Kis_WarnPref_Panel::Kis_WarnPref_Panel(GlobalRegistry *in_globalreg, 
										   KisPanelInterface *in_intf):
	Kis_Panel(in_globalreg, in_intf) {

	warntable = new Kis_Scrollable_Table(globalreg, this);

	warntable->SetCallback(COMPONENT_CBTYPE_ACTIVATED, WarnPrefCB, this);

	AddComponentVec(warntable, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 0;
	t.title = "Warning";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 7;
	t.title = "Display";
	t.alignment = 0;
	titles.push_back(t);

	t.width = -1;
	t.title = "[pref]";
	t.alignment = 0;
	titles.push_back(t);

	warntable->SetPreferredSize(0, 6);

	warntable->AddTitles(titles);
	warntable->Show();

	vector<string> ft;

	closebutton = new Kis_Button(globalreg, this);
	closebutton->SetText("Close");
	closebutton->Show();
	closebutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, WarnPrefCB, this);
	AddComponentVec(closebutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));
	
	SetTitle("Warning Options");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	vbox->Pack_End(warntable, 1, 0);
	vbox->Pack_End(closebutton, 0, 0);

	vbox->Show();

	main_component = vbox;

	SetActiveComponent(warntable);

	Position(WIN_CENTER(10, 45));

	vector<string> td;
	k = 0;

	td.push_back("");
	td.push_back("");
	td.push_back("");

	td[0] = "Source Warnings";
	td[2] = "WARN_SOURCEWARN";
	// if (kpinterface->prefs->FetchOpt(td[2]) != "false") {
	if (kpinterface->prefs->FetchOptBoolean(td[2], 1)) {
		td[1] = "Yes";
	} else {
		td[1] = "No";
	}
	warntable->ReplaceRow(k++, td);

	td[0] = "All Sources Errored";
	td[2] = "WARN_ALLERRSOURCE";
	// if (kpinterface->prefs->FetchOpt(td[2]) != "false") {
	if (kpinterface->prefs->FetchOptBoolean(td[2], 1)) {
		td[1] = "Yes";
	} else {
		td[1] = "No";
	}
	warntable->ReplaceRow(k++, td);

	td[0] = "Running As Root";
	td[2] = "STARTUP_WARNROOT";
	// if (kpinterface->prefs->FetchOpt(td[2]) != "false") {
	if (kpinterface->prefs->FetchOptBoolean(td[2], 1)) {
		td[1] = "Yes";
	} else {
		td[1] = "No";
	}
	warntable->ReplaceRow(k++, td);

}

Kis_WarnPref_Panel::~Kis_WarnPref_Panel() {

}

void Kis_WarnPref_Panel::Action(Kis_Panel_Component *in_component, 
								int in_status) {
	if (in_component == closebutton) {
		for (int x = 0; x < k; x++) {
			vector<string> td = warntable->GetRow(x);
			if (td.size() != 3)
				continue;

			kpinterface->prefs->SetOpt(td[2], td[1] == "Yes" ? "true" : "false", 1);
		}

		kpinterface->KillPanel(this);
		return;
	}

	if (in_component == warntable) {
		vector<string> selrow = warntable->GetSelectedData();

		if (selrow.size() != 3)
			return;

		if (selrow[1] == "Yes")
			selrow[1] = "No";
		else
			selrow[1] = "Yes";

		warntable->ReplaceRow(warntable->GetSelected(), selrow);
	}

}

#endif

