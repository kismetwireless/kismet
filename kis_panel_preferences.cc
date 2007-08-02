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

Kis_ColorPref_Picker::Kis_ColorPref_Picker(GlobalRegistry *in_globalreg,
										   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	fgcolor = new Kis_ColorPref_Component(globalreg, this);
	bgcolor = new Kis_ColorPref_Component(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);

	tab_components.push_back(fgcolor);
	tab_components.push_back(bgcolor);
	tab_components.push_back(okbutton);
	tab_components.push_back(cancelbutton);
	tab_pos = 0;

	fgcolor->Activate(1);
	active_component = fgcolor;

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

	comp_vec.push_back(vbox);

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

	for (unsigned int x = 0; x < comp_vec.size(); x++)
		comp_vec[x]->DrawComponent();

	wmove(win, 0, 0);
}

int Kis_ColorPref_Picker::KeyPress(int in_key) {
	int ret;

	if (in_key == '\t') {
		tab_components[tab_pos]->Deactivate();
		tab_pos++;
		if (tab_pos >= (int) tab_components.size())
			tab_pos = 0;
		tab_components[tab_pos]->Activate(1);
		active_component = tab_components[tab_pos];
	}

	if (active_component != NULL) {
		ret = active_component->KeyPress(in_key);

		if (active_component == okbutton && ret == 1) {
			kpinterface->prefs.SetOpt(prefname,
									  fgcolor->GetColor() + "," +
									  bgcolor->GetColor(), 1);
									   
			globalreg->panel_interface->KillPanel(this);
			return 0;
		}

		if (active_component == cancelbutton && ret == 1) {
			globalreg->panel_interface->KillPanel(this);
			return 0;
		}
	}

	return 0;
}

void Kis_ColorPref_Picker::LinkColorPref(string in_prefname) {
	prefname = in_prefname;

	vector<string> sv = StrTokenize(kpinterface->prefs.FetchOpt(prefname), ",");
	if (sv.size() >= 1)
		fgcolor->SetColor(sv[0]);
	if (sv.size() >= 2)
		bgcolor->SetColor(sv[1]);

}

Kis_ColorPref_Panel::Kis_ColorPref_Panel(GlobalRegistry *in_globalref,
										 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalref, in_intf) {

	colorlist = new Kis_Scrollable_Table(globalreg, this);

	comp_vec.push_back(colorlist);
	active_component = colorlist;

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
}

Kis_ColorPref_Panel::~Kis_ColorPref_Panel() {
}

void Kis_ColorPref_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	colorlist->SetPosition(2, 1, in_x - 4, in_y - 2);

	colorlist->Show();
}

void Kis_ColorPref_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	vector<string> td;
	for (unsigned int x = 0; x < listedcolors.size(); x++) {
		td.clear();
		td.push_back(listedcolors[x].text);
		td.push_back(StrLower(kpinterface->prefs.FetchOpt(listedcolors[x].pref)));
		colorlist->ReplaceRow(x, td);
	}

	td.clear();
	td.push_back("Close");
	td.push_back("");
	colorlist->ReplaceRow(listedcolors.size(), td);

	wbkgdset(win, text_color);

	werase(win);

	DrawTitleBorder();

	wattrset(win, text_color);

	for (unsigned int x = 0; x < comp_vec.size(); x++)
		comp_vec[x]->DrawComponent();

	wmove(win, 0, 0);
}

int Kis_ColorPref_Panel::KeyPress(int in_key) {
	int ret;
	int listkey;

	if (in_key == '\n' || in_key == '\r') {
		listkey = colorlist->GetSelected();

		if (listkey >= 0 && listkey <= (int) listedcolors.size()) {
			if (listkey == (int) listedcolors.size()) {
				globalreg->panel_interface->KillPanel(this);
				return 0;
			}

			Kis_ColorPref_Picker *cp = 
				new Kis_ColorPref_Picker(globalreg, kpinterface);
			cp->LinkColorPref(listedcolors[listkey].pref);
			cp->Position((LINES / 2) - 4, (COLS / 2) - 25, 10, 50);
			kpinterface->AddPanel(cp);
		}
	}

	if (active_component != NULL) {
		ret = active_component->KeyPress(in_key);
	}

	return 0;
}

void Kis_ColorPref_Panel::AddColorPref(string pref, string name) {
	cprefpair cpp;
	cpp.text = name;
	cpp.pref = pref;

	listedcolors.push_back(cpp);
}

#endif

