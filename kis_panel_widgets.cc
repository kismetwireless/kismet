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

#include "kis_panel_widgets.h"
#include "timetracker.h"
#include "messagebus.h"

void Kis_Panel_Specialtext::Mvwaddnstr(WINDOW *win, int y, int x, string str, int n) {
	int npos = 0;
	int escape = 0;

	for (unsigned int pos = 0; pos < str.size(); pos++) {
		if (str[pos] == '\\') {
			escape = 1;
			continue;
		}

		// Handle the attributes
		if (escape) {
			if (str[pos] == 'u') {
				wattron(win, WA_UNDERLINE);
			} else if (str[pos] == 'U') {
				wattroff(win, WA_UNDERLINE);
			} else if (str[pos] == 's') {
				wattron(win, WA_STANDOUT);
			} else if (str[pos] == 'S') {
				wattroff(win, WA_STANDOUT);
			} else if (str[pos] == 'r') {
				wattron(win, WA_REVERSE);
			} else if (str[pos] == 'R') {
				wattroff(win, WA_REVERSE);
			} else if (str[pos] == 'b') {
				wattron(win, WA_BOLD);
			} else if (str[pos] == 'B') {
				wattroff(win, WA_BOLD);
			} else {
				fprintf(stderr, "invalid escape '%c'\n", str[pos]);
				// Backfill the unescaped data
				escape = 0;
				if (npos <= n) {
					mvwaddch(win, y, x + npos, '\\');
					npos++;
				}
				if (npos <= n) {
					mvwaddch(win, y, x + npos, str[npos]);
					npos++;
				}
			}

			escape = 0;
			continue;
		}

		// Otherwise write the character, if we can.  We DON'T abort here,
		// because we need to process to the end of the string to turn off
		// any attributes that were on
		if (npos <= n) {
			mvwaddch(win, y, x + npos, str[pos]);
			npos++;
			continue;
		}
	}
}

int panelint_draw_timer(TIMEEVENT_PARMS) {
	return ((PanelInterface *) parm)->DrawInterface();
}

// Pollable panel interface driver
PanelInterface::PanelInterface() {
	fprintf(stderr, "FATAL OOPS:  PanelInterface() w/ no globalreg\n");
	exit(1);
}

PanelInterface::PanelInterface(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	// Init curses
	initscr();
	cbreak();
	noecho();

	draweventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC / 2,
											  NULL, 1, &panelint_draw_timer,
											  (void *) this);

	globalreg->RegisterPollableSubsys(this);
};

PanelInterface::~PanelInterface() {
	for (unsigned int x = 0; x < live_panels.size(); x++)
		delete live_panels[x];

	globalreg->timetracker->RemoveTimer(draweventid);
	
	globalreg->RemovePollableSubsys(this);

	endwin();
}

unsigned int PanelInterface::MergeSet(unsigned int in_max_fd, fd_set *out_rset, 
									  fd_set *out_wset) {
	if (live_panels.size() == 0)
		return in_max_fd;

	// add stdin to the listen set
	FD_SET(fileno(stdin), out_rset);

	if ((int) in_max_fd < fileno(stdin))
		return fileno(stdin);

	return in_max_fd;
}

int PanelInterface::Poll(fd_set& in_rset, fd_set& in_wset) {
	if (live_panels.size() == 0)
		return 0;

	if (FD_ISSET(fileno(stdin), &in_rset)) {
		// Poll via the top of the stack
		int ret;
		
		ret = live_panels[live_panels.size() - 1]->Poll();
		DrawInterface();

		if (ret < 0)
			globalreg->fatal_condition = 1;
		return ret;
	}

	return 0;
}

int PanelInterface::DrawInterface() {
	// Draw all the panels
	for (unsigned int x = 0; x < live_panels.size(); x++) {
		live_panels[x]->DrawPanel();
	}

	// Call the update
	update_panels();
	doupdate();

	// Delete dead panels from before
	for (unsigned int x = 0; x < dead_panels.size(); x++) {
		delete(dead_panels[x]);
	}
	dead_panels.clear();

	return 1;
}

void PanelInterface::AddPanel(Kis_Panel *in_panel) {
	live_panels.push_back(in_panel);
}

void PanelInterface::KillPanel(Kis_Panel *in_panel) {
	for (unsigned int x = 0; x < live_panels.size(); x++) {
		if (live_panels[x] == in_panel) {
			dead_panels.push_back(in_panel);
			live_panels.erase(live_panels.begin() + x);
		}
	}
}

Kis_Panel_Component::Kis_Panel_Component(GlobalRegistry *in_globalreg, 
										 Kis_Panel *in_panel) {
	globalreg = in_globalreg;
	parent_panel = in_panel;
	window = in_panel->FetchDrawWindow();
	visible = 0;
	active = 0;
}

Kis_Menu::Kis_Menu(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	globalreg = in_globalreg;
	cur_menu = -1;
	cur_item = -1;
	menuwin = NULL;
}

Kis_Menu::~Kis_Menu() {
	ClearMenus();
}

int Kis_Menu::AddMenu(string in_text, int targ_char) {
	_menu *menu = new _menu;

	menu->text = in_text;
	if (targ_char < 0 || targ_char > (int) in_text.length() - 1)
		menu->targchar = -1;
	else
		menu->targchar = targ_char;

	menu->width = 0;

	menu->id = menubar.size();

	menubar.push_back(menu);

	return menu->id;
}

int Kis_Menu::AddMenuItem(string in_text, int menuid, char extra) {
	if (menuid < 0 || menuid > (int) menubar.size() - 1)
		return -1;

	_menuitem *item = new _menuitem;

	item->parentmenu = menuid;
	item->text = in_text;
	item->extrachar = extra;
	item->id = menubar[menuid]->items.size();

	// Auto-disable spacers
	if (item->text[0] != '-')
		item->enabled = 1;
	else
		item->enabled = 0;

	menubar[menuid]->items.push_back(item);

	if ((int) in_text.length() > menubar[menuid]->width)
		menubar[menuid]->width = in_text.length();

	return (menuid * 100) + item->id + 1;
}

void Kis_Menu::DisableMenuItem(int in_item) {
	int mid = in_item / 100;
	int iid = (in_item % 100) - 1;

	if (mid < 0 || mid >= (int) menubar.size())
		return;

	if (iid < 0 || iid > (int) menubar[mid]->items.size())
		return;

	menubar[mid]->items[iid]->enabled = 0;
}

void Kis_Menu::EnableMenuItem(int in_item) {
	int mid = in_item / 100;
	int iid = (in_item % 100) - 1;

	if (mid < 0 || mid >= (int) menubar.size())
		return;

	if (iid < 0 || iid > (int) menubar[mid]->items.size())
		return;

	menubar[mid]->items[iid]->enabled = 1;
}

void Kis_Menu::ClearMenus() {
	// Deconstruct the menubar
	for (unsigned int x = 0; x < menubar.size(); x++) {
		for (unsigned int y = 0; y < menubar[x]->items.size(); y++)
			delete menubar[x]->items[y];
		delete menubar[x];
	}
}

void Kis_Menu::Activate(int subcomponent) {
	cur_menu = subcomponent - 1;
	cur_item = -1;
}

void Kis_Menu::Deactivate() {
	cur_menu = -1;
	cur_item = -1;
}

void Kis_Menu::DrawComponent() {
	if (visible == 0)
		return;

	int hpos = 3;

	if (menuwin == NULL)
		menuwin = derwin(window, 1, 1, 0, 0);

	mvwaddstr(window, sy, sx + 1, "~");

	// Draw the menu bar itself
	for (unsigned int x = 0; x < menubar.size(); x++) {
		// If the current menu is the selected one, hilight it
		if ((int) x == cur_menu)
			wattron(window, WA_REVERSE);

		// Draw the menu
		mvwaddstr(window, sy, sx + hpos, menubar[x]->text.c_str());
		// Set the hilight
		if (menubar[x]->targchar >= 0) {
			wattron(window, WA_UNDERLINE);
			mvwaddch(window, sy, sx + hpos + menubar[x]->targchar,
					 menubar[x]->text[menubar[x]->targchar]);
			wattroff(window, WA_UNDERLINE);
		}

		wattroff(window, WA_REVERSE);

		// Draw the menu itself, if we've got an item selected in it
		if ((int) x == cur_menu && cur_item >= 0) {
			// Resize the menu window
			wresize(menuwin, menubar[x]->items.size() + 2,
					menubar[x]->width + 7);
			// move it
			mvderwin(menuwin, sy + 1, sx + hpos);
			// Draw the box
			box(menuwin, 0, 0);

			for (unsigned int y = 0; y < menubar[x]->items.size(); y++) {
				string menuline;

				// Shortcut out a spacer
				if (menubar[x]->items[y]->text[0] == '-') {
					mvwhline(menuwin, 1 + y, 1, ACS_HLINE, menubar[x]->width + 5);
					mvwaddch(menuwin, 1 + y, 0, ACS_LTEE);
					mvwaddch(menuwin, 1 + y, menubar[x]->width + 6, ACS_RTEE);
					/*
					menuline = string(menubar[x]->width + 5, '-');
					mvwaddstr(menuwin, 1 + y, 1, menuline.c_str());
					*/
					continue;
				}

				// Hilight the current item
				if ((int) y == cur_item)
					wattron(menuwin, WA_REVERSE);

				// Dim a disabled item
				if (menubar[x]->items[y]->enabled == 0)
					wattron(menuwin, WA_DIM);

				// Format it with 'Foo     F'
				menuline = menubar[x]->items[y]->text + " ";
				for (unsigned int z = menuline.length(); 
					 (int) z <= menubar[x]->width + 2; z++) {
					menuline = menuline + string(" ");
				}

				menuline = menuline + " " + menubar[x]->items[y]->extrachar;

				// Print it
				mvwaddstr(menuwin, 1 + y, 1, menuline.c_str());

				// Dim a disabled item
				if (menubar[x]->items[y]->enabled == 0)
					wattroff(menuwin, WA_DIM);

				if ((int) y == cur_item)
					wattroff(menuwin, WA_REVERSE);
			}
		}

		hpos += menubar[x]->text.length() + 1;
	}
}

void Kis_Menu::FindNextEnabledItem() {
	// Handle disabled and spacer items
	if (menubar[cur_menu]->items[cur_item]->enabled == 0) {
		// find the next enabled item
		for (int i = cur_item + 1; i < (int) menubar[cur_menu]->items.size(); i++) {
			// Loop
			if (i >= (int) menubar[cur_menu]->items.size())
				i = 0;

			// Bail on a full loop
			if (i == cur_item) {
				cur_item = -1;
				break;
			}

			if (menubar[cur_menu]->items[i]->enabled) {
				cur_item = i;
				break;
			}
		}
	}
}

void Kis_Menu::FindPrevEnabledItem() {
	// Handle disabled and spacer items
	if (menubar[cur_menu]->items[cur_item]->enabled == 0) {
		// find the next enabled item
		for (int i = cur_item - 1; i >= -1; i--) {
			// Loop
			if (i < 0)
				i = menubar[cur_menu]->items.size() - 1;

			// Bail on a full loop
			if (i == cur_item) {
				cur_item = -1;
				break;
			}

			if (menubar[cur_menu]->items[i]->enabled) {
				cur_item = i;
				break;
			}
		}
	}
}

int Kis_Menu::KeyPress(int in_key) {
	if (visible == 0)
		return -1;

	// Activate menu
	if (in_key == '~' || in_key == '`' || in_key == 0x1B) {
		if (cur_menu < 0)
			Activate(1);
		else
			Deactivate();
		return 0;
	}

	// Menu movement
	if (in_key == KEY_RIGHT && cur_menu < (int) menubar.size() - 1 &&
		cur_menu >= 0) {
		cur_menu++;
		cur_item = 0;
		FindNextEnabledItem();
		return 0;
	}

	if (in_key == KEY_LEFT && cur_menu > 0) {
		cur_menu--;
		cur_item = 0;
		FindNextEnabledItem();
		return 0;
	}

	if (in_key == KEY_DOWN && cur_menu >= 0 &&
		cur_item <= (int) menubar[cur_menu]->items.size() - 1) {

		if (cur_item == (int) menubar[cur_menu]->items.size() - 1) {
			cur_item = 0;
			FindNextEnabledItem();
			return 0;
		}

		cur_item++;

		FindNextEnabledItem();

		return 0;
	}

	if (in_key == KEY_UP && cur_item >= 0) {
		if (cur_item == 0) {
			cur_item = menubar[cur_menu]->items.size() - 1;
			FindPrevEnabledItem();
			return 0;
		}

		cur_item--;

		FindPrevEnabledItem();

		return 0;
	}

	// Space or enter
	if ((in_key == ' ' || in_key == 0x0A || in_key == KEY_ENTER) && cur_menu >= 0) {
		if (cur_item == -1) {
			cur_item = 0;
			FindNextEnabledItem();
			return 0;
		}
		int ret = (cur_menu * 100) + cur_item + 1;
		Deactivate();
		return ret;
	}

	// Key shortcuts
	if (cur_menu >= 0) {
		if (cur_item < 0) {
			// Try w/ the proper case
			for (unsigned int x = 0; x < menubar.size(); x++) {
				if (in_key == menubar[x]->text[menubar[x]->targchar]) {
					cur_menu = x;
					cur_item = 0;
					FindNextEnabledItem();
					return 0;
				}
			}
			// Try with lowercase, if we didn't find one already
			for (unsigned int x = 0; x < menubar.size(); x++) {
				if (tolower(in_key) == 
					tolower(menubar[x]->text[menubar[x]->targchar])) {
					cur_menu = x;
					cur_item = 0;
					FindNextEnabledItem();
					return 0;
				}
			}
			return 0;
		} else {
			for (unsigned int x = 0; x < menubar[cur_menu]->items.size(); x++) {
				if (in_key == menubar[cur_menu]->items[x]->extrachar &&
					menubar[cur_menu]->items[x]->enabled == 1) {
					int ret = (cur_menu * 100) + x + 1;
					Deactivate();
					return ret;
				}
			}
			return 0;
		}
	}

	return -1;
}

Kis_Free_Text::Kis_Free_Text(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	globalreg = in_globalreg;
	scroll_pos = 0;
}

Kis_Free_Text::~Kis_Free_Text() {
	// Nothing
}

void Kis_Free_Text::DrawComponent() {
	if (visible == 0)
		return;

	for (unsigned int x = 0; x < text_vec.size() && (int) x < ey; x++) {
		// Use the special formatter
		Kis_Panel_Specialtext::Mvwaddnstr(window, sy + x, sx, 
										  text_vec[x + scroll_pos],
										  ex - 1);
		// mvwaddnstr(window, sy + x, sx, text_vec[x + scroll_pos].c_str(), ex - 1);
	}

	if ((int) text_vec.size() > ey) {
		// Draw the hash scroll bar
		mvwvline(window, sy, sx + ex - 1, ACS_VLINE, ey);
		// Figure out how far down our text we are
		// int perc = ey * (scroll_pos / text_vec.size());
		float perc = (float) ey * (float) ((float) (scroll_pos) / 
										   (float) (text_vec.size() - ey));
		wattron(window, WA_REVERSE);
		// Draw the solid position
		mvwaddch(window, sy + (int) perc, sx + ex - 1, ACS_BLOCK);

		wattroff(window, WA_REVERSE);
	}
}

void Kis_Free_Text::Activate(int subcomponent) {
	// No magic
}

void Kis_Free_Text::Deactivate() {
	// No magic
}

int Kis_Free_Text::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	int scrollable = 1;

	if ((int) text_vec.size() <= ey)
		scrollable = 0;

	if (scrollable && in_key == KEY_UP && scroll_pos > 0) {
		scroll_pos--;
		return 0;
	}

	if (scrollable && in_key == KEY_DOWN && 
		scroll_pos < ((int) text_vec.size() - ey)) {
		scroll_pos++;
		return 0;
	}

	if (scrollable && in_key == KEY_PPAGE && scroll_pos > 0) {
		scroll_pos -= (ey - 1);
		if (scroll_pos < 0)
			scroll_pos = 0;
		return 0;
	}

	if (scrollable && in_key == KEY_NPAGE) {
		scroll_pos += (ey - 1);
		if (scroll_pos >= ((int) text_vec.size() - ey)) 
			scroll_pos = ((int) text_vec.size() - ey);
		return 0;
	}

	return 1;
}

void Kis_Free_Text::SetText(string in_text) {
	text_vec = StrTokenize(in_text, "\n");
}

void Kis_Free_Text::SetText(vector<string> in_text) {
	text_vec = in_text;
}

void KisStatusText_Messageclient::ProcessMessage(string in_msg, int in_flags) {
	if ((in_flags & MSGFLAG_INFO)) {
		((Kis_Status_Text *) auxptr)->AddLine("\\bINFO\\B: " + in_msg, 6);
	} else if ((in_flags & MSGFLAG_ERROR)) {
		((Kis_Status_Text *) auxptr)->AddLine("\\rERROR\\R: " + in_msg, 7);
	} else if ((in_flags & MSGFLAG_FATAL)) {
		((Kis_Status_Text *) auxptr)->AddLine("\\rFATAL\\R: " + in_msg, 7);
	} else {
		((Kis_Status_Text *) auxptr)->AddLine(in_msg);
	}
}

Kis_Status_Text::Kis_Status_Text(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	globalreg = in_globalreg;
	scroll_pos = 0;
}

Kis_Status_Text::~Kis_Status_Text() {
	// Nothing
}

void Kis_Status_Text::DrawComponent() {
	if (visible == 0)
		return;

	for (unsigned int x = 0; x < text_vec.size() && (int) x < ey; x++) {
		Kis_Panel_Specialtext::Mvwaddnstr(window, sy + (ey - x), sx,
										  text_vec[text_vec.size() - x - 1],
										  ex - 1);
	}
}

void Kis_Status_Text::Activate(int subcomponent) {
	// No magic
}

void Kis_Status_Text::Deactivate() {
	// No magic
}

int Kis_Status_Text::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	return 1;
}

void Kis_Status_Text::AddLine(string in_line, int headeroffset) {
	vector<string> lw = LineWrap(in_line, headeroffset, ex - 1);

	for (unsigned int x = 0; x < lw.size(); x++) {
		text_vec.push_back(lw[x]);
	}

	if ((int) text_vec.size() > ey) {
		text_vec.erase(text_vec.begin(), text_vec.begin() + text_vec.size() - ey);
	}
}

Kis_Field_List::Kis_Field_List(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	globalreg = in_globalreg;
	scroll_pos = 0;
	field_w = 0;
}

Kis_Field_List::~Kis_Field_List() {
	// Nothing
}

void Kis_Field_List::DrawComponent() {
	if (visible == 0)
		return;

	for (unsigned int x = 0; x < field_vec.size() && (int) x < ey; x++) {
		// Set the field name to bold
		wattron(window, WA_BOLD);
		mvwaddnstr(window, sy + x, sx, field_vec[x + scroll_pos].c_str(), field_w);
		mvwaddch(window, sy + x, sx + field_w, ':');
		wattroff(window, WA_BOLD);

		// Draw the data, leave room on the end for the scrollbar
		mvwaddnstr(window, sy + x, sx + field_w + 2, data_vec[x + scroll_pos].c_str(),
				   sx - field_w - 3);
	}

	if ((int) field_vec.size() > ey) {
		// Draw the hash scroll bar
		mvwvline(window, sy, sx + ex - 1, ACS_VLINE, ey);
		// Figure out how far down our text we are
		// int perc = ey * (scroll_pos / text_vec.size());
		float perc = (float) ey * (float) ((float) (scroll_pos) / 
										   (float) (field_vec.size() - ey));
		wattron(window, WA_REVERSE);
		// Draw the solid position
		mvwaddch(window, sy + (int) perc, sx + ex - 1, ACS_BLOCK);

		wattroff(window, WA_REVERSE);
	}
}

void Kis_Field_List::Activate(int subcomponent) {
	// No magic
}

void Kis_Field_List::Deactivate() {
	// No magic
}

int Kis_Field_List::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	int scrollable = 1;

	if ((int) field_vec.size() <= ey)
		scrollable = 0;

	if (scrollable && in_key == KEY_UP && scroll_pos > 0) {
		scroll_pos--;
		return 0;
	}

	if (scrollable && in_key == KEY_DOWN && 
		scroll_pos < ((int) field_vec.size() - ey)) {
		scroll_pos++;
		return 0;
	}

	if (scrollable && in_key == KEY_PPAGE && scroll_pos > 0) {
		scroll_pos -= (ey - 1);
		if (scroll_pos < 0)
			scroll_pos = 0;
		return 0;
	}

	if (scrollable && in_key == KEY_NPAGE) {
		scroll_pos += (ey - 1);
		if (scroll_pos >= ((int) field_vec.size() - ey)) 
			scroll_pos = ((int) field_vec.size() - ey);
		return 0;
	}

	return 1;
}

int Kis_Field_List::AddData(string in_field, string in_data) {
	int pos = field_vec.size();
	field_vec.push_back(in_field);
	data_vec.push_back(in_data);

	if (in_field.length() > field_w)
		field_w = in_field.length();

	return (int) pos;
}

int Kis_Field_List::ModData(unsigned int in_row, string in_field, string in_data) {
	if (in_row >= field_vec.size())
		return -1;

	field_vec[in_row] = in_field;
	data_vec[in_row] = in_data;

	return (int) in_row;
}

Kis_Scrollable_Table::Kis_Scrollable_Table(GlobalRegistry *in_globalreg, 
										   Kis_Panel *in_panel) : 
	Kis_Panel_Component(in_globalreg, in_panel) {

	globalreg = in_globalreg;

	scroll_pos = 0;
	hscroll_pos = 0;
	selected = -1;
}

Kis_Scrollable_Table::~Kis_Scrollable_Table() {
	for (unsigned int x = 0; x < data_vec.size(); x++) {
		delete data_vec[x];
	}
}

void Kis_Scrollable_Table::DrawComponent() {
	if (visible == 0)
		return;

	// Current character position x
	int xcur = 0;
	string ftxt;

	// Print across the titles
	wattron(window, WA_BOLD);
	for (unsigned int x = hscroll_pos; x < title_vec.size() && xcur < ex; x++) {

		int w = title_vec[x].width;

		if (xcur + w >= ex)
			w = ex - xcur;

		// Align the field w/in the width
		ftxt = AlignString(title_vec[x].title, ' ', title_vec[x].alignment, w);
	
		// Write it out
		mvwaddstr(window, sy, sx + xcur, ftxt.c_str());

		// Advance by the width + 1
		xcur += w + 1;
	}
	wattroff(window, WA_BOLD);

	if ((int) data_vec.size() > ey) {
		// Draw the scroll bar
		mvwvline(window, sy, sx + ex - 1, ACS_VLINE, ey);
		float perc = (float) ey * (float) ((float) (scroll_pos) /
										   (float) (data_vec.size() - ey));
		if (perc >= ey - 1)
			perc = ey - 1;
		wattron(window, WA_REVERSE);
		mvwaddch(window, sy + (int) perc, sx + ex - 1, ACS_BLOCK);
		wattroff(window, WA_REVERSE);
	}

	// Jump to the scroll location to start drawing rows
	int ycur = 1;
	for (unsigned int r = scroll_pos; r < data_vec.size() && 
		 ycur < ey; r++) {
		// Print across
		xcur = 0;

		if ((int) r == selected) {
			wattron(window, WA_REVERSE);
			mvwhline(window, sy + ycur, sx, ' ', ex);
		}

		for (unsigned int x = hscroll_pos; x < data_vec[r]->data.size() &&
			 xcur < ex && x < title_vec.size(); x++) {
			int w = title_vec[x].width;

			if (xcur + w >= ex)
				w = ex - xcur;

			ftxt = AlignString(data_vec[r]->data[x], ' ', title_vec[x].alignment, w);

			mvwaddstr(window, sy + ycur, sx + xcur, ftxt.c_str());

			xcur += w + 1;
		}

		if ((int) r == selected)
			wattroff(window, WA_REVERSE);

		ycur += 1;

	}

}

void Kis_Scrollable_Table::Activate(int subcomponent) {
	// no magic 
}

void Kis_Scrollable_Table::Deactivate() {
	// no magic
}

int Kis_Scrollable_Table::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	int scrollable = 1;
	if ((int) data_vec.size() <= ey)
		scrollable = 0;

	// Selected up one, scroll up one if we need to
	if (in_key == KEY_UP && selected > 0) {
		selected--;
		if (scrollable && scroll_pos > 0 && scroll_pos > selected) {
			scroll_pos--;
		}
	}

	if (in_key == KEY_DOWN && selected < (int) data_vec.size() - 1) {
		selected++;
		if (scrollable && scroll_pos + ey - 1 <= selected) {
			scroll_pos++;
		}
	}

	if (in_key == KEY_RIGHT && hscroll_pos < (int) title_vec.size() - 1) {
		hscroll_pos++;
	}

	if (in_key == KEY_LEFT && hscroll_pos > 0) {
		hscroll_pos--;
	}

	return 0;
}

int Kis_Scrollable_Table::GetSelected() {
	if (selected >= 0 && selected < (int) data_vec.size()) {
		return data_vec[selected]->key;
	}

	return -1;
}

int Kis_Scrollable_Table::AddTitles(vector<Kis_Scrollable_Table::title_data> 
									in_titles) {
	title_vec = in_titles;
	return 1;
}

int Kis_Scrollable_Table::AddRow(int in_key, vector<string> in_fields) {
	if (key_map.find(in_key) != key_map.end()) {
		_MSG("Scrollable_Table tried to add row already keyed", MSGFLAG_ERROR);
		return -1;
	}

	if (in_fields.size() != title_vec.size()) {
		_MSG("Scrollable_Table added row with a different number of fields than "
			 "the title", MSGFLAG_ERROR);
	}

	row_data *r = new row_data;
	r->key = in_key;
	r->data = in_fields;

	key_map[in_key] = 1;

	data_vec.push_back(r);

	return 1;
}

int Kis_Scrollable_Table::DelRow(int in_key) {
	if (key_map.find(in_key) == key_map.end()) {
		_MSG("Scrollable_Table tried to del row that doesn't exist", MSGFLAG_ERROR);
		return -1;
	}

	key_map.erase(key_map.find(in_key));
	
	for (unsigned int x = 0; x < data_vec.size(); x++) {
		if (data_vec[x]->key == in_key) {
			delete data_vec[x];
			data_vec.erase(data_vec.begin() + x);
			break;
		}
	}

	if (scroll_pos >= (int) data_vec.size()) {
		scroll_pos = data_vec.size() - 1;
	}

	if (selected >= (int) data_vec.size()) {
		selected = data_vec.size() - 1;
	}

	return 1;
}

int Kis_Scrollable_Table::ReplaceRow(int in_key, vector<string> in_fields) {
	if (key_map.find(in_key) == key_map.end()) {
		// Add a row instead
		return AddRow(in_key, in_fields);

#if 0
		_MSG("Scrollable_Table tried to replace row that doesn't exist", 
			 MSGFLAG_ERROR);
		return -1;
#endif
	}

	for (unsigned int x = 0; x < data_vec.size(); x++) {
		if (data_vec[x]->key == in_key) {
			data_vec[x]->data = in_fields;
			break;
		}
	}

	return 1;
}

Kis_Single_Input::Kis_Single_Input(GlobalRegistry *in_globalreg, 
								   Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	globalreg = in_globalreg;
	curs_pos = 0;
	inp_pos = 0;
	label_pos = LABEL_POS_NONE;
	max_len = 0;
	draw_len = 0;
}

Kis_Single_Input::~Kis_Single_Input() {
	// Nothing
}

void Kis_Single_Input::DrawComponent() {
	if (visible == 0)
		return;

	int xoff = 0;
	int yoff = 0;

	// Draw the label if we can, in bold
	if (ey >= 2 && label_pos == LABEL_POS_TOP) {
		wattron(window, WA_BOLD);
		mvwaddnstr(window, sy, sx, label.c_str(), ex);
		wattroff(window, WA_BOLD);
		yoff = 1;
	} else if (label_pos == LABEL_POS_LEFT) {
		wattron(window, WA_BOLD);
		mvwaddnstr(window, sy, sx, label.c_str(), ex);
		wattroff(window, WA_BOLD);
		xoff += label.length() + 1;
	}

	// set the drawing length
	draw_len = ex - xoff;

	// Clean up any silliness that might be present from initialization
	if (inp_pos - curs_pos >= draw_len)
		curs_pos = inp_pos - draw_len + 1;

	// Invert for the text
	wattron(window, WA_REVERSE);

	/* draw the inverted line */
	mvwhline(window, sy + yoff, sx + xoff, ' ', draw_len);

	/* draw the text from cur to what fits */
	mvwaddnstr(window, sy + yoff, sx + xoff, 
			   text.substr(curs_pos, draw_len).c_str(), draw_len);

	/* Underline & unreverse the last character of the text (or space) */
	wattroff(window, WA_REVERSE);

	if (active) {
		wattron(window, WA_UNDERLINE);
		char ch;
		if (inp_pos < (int) text.length())
			ch = text[inp_pos];
		else
			ch = ' ';

		mvwaddch(window, sy + yoff, sx + xoff + (inp_pos - curs_pos), ch);
		wattroff(window, WA_UNDERLINE);
	}
}

void Kis_Single_Input::Activate(int subcomponent) {
	active = 1;
}

void Kis_Single_Input::Deactivate() {
	active = 0;
}

int Kis_Single_Input::KeyPress(int in_key) {
	if (visible == 0 || draw_len == 0)
		return 0;

	// scroll left, and move the viewing window if we have to
	if (in_key == KEY_LEFT && inp_pos > 0) {
		inp_pos--;
		if (inp_pos < curs_pos)
			curs_pos = inp_pos;
		return 0;
	}

	// scroll right, and move the viewing window if we have to
	if (in_key == KEY_RIGHT && inp_pos < (int) text.length()) {
		inp_pos++;

		if (inp_pos - curs_pos >= draw_len)
			curs_pos = inp_pos - draw_len + 1;

		return 0;
	}

	// Catch home/end (if we can)
	if (in_key == KEY_HOME) {
		inp_pos = 0;
		curs_pos = 0;

		return 0;
	}
	if (in_key == KEY_END) {
		inp_pos = text.length();
		curs_pos = inp_pos - draw_len + 1;

		return 0;
	}

	// Catch deletes
	if ((in_key == KEY_BACKSPACE || in_key == 0x7F) && text.length() > 0) {
		if (inp_pos == 0)
			inp_pos = 1;

		text.erase(text.begin() + (inp_pos - 1));

		if (inp_pos > 0)
			inp_pos--;

		if (inp_pos < curs_pos)
			curs_pos = inp_pos;

		return 0;
	}

	// Lastly, if the character is in our filter of allowed characters for typing,
	// and if we have room, insert it and scroll to the right
	if ((int) text.length() < max_len && 
		filter_map.find(in_key) != filter_map.end()) {
		char ins[2] = { in_key, 0 };
		text.insert(inp_pos, ins);
		inp_pos++;

		if (inp_pos - curs_pos >= draw_len)
			curs_pos = inp_pos - draw_len + 1;

		return 0;
	}

	return 0;
}

void Kis_Single_Input::SetCharFilter(string in_charfilter) {
	filter_map.clear();
	for (unsigned int x = 0; x < in_charfilter.length(); x++) {
		filter_map[in_charfilter[x]] = 1;
	}
}

void Kis_Single_Input::SetLabel(string in_label, KisWidget_LabelPos in_pos) {
	label = in_label;
	label_pos = in_pos;
}

void Kis_Single_Input::SetTextLen(int in_len) {
	max_len = in_len;
}

void Kis_Single_Input::SetText(string in_text, int dpos, int ipos) {
	text = in_text;

	inp_pos = ipos;
	curs_pos = dpos;
}

string Kis_Single_Input::GetText() {
	return text;
}

Kis_Button::Kis_Button(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {
	globalreg = in_globalreg;

	active = 0;
}

Kis_Button::~Kis_Button() {
	// nada
}

void Kis_Button::DrawComponent() {
	if (visible == 0)
		return;

	// Draw the highlighted button area if we're active
	if (active)
		wattron(window, WA_REVERSE);

	mvwhline(window, sy, sx, ' ', ex);

	// Center the text
	int tx = (ex / 2) - (text.length() / 2);
	mvwaddnstr(window, sy, sx + tx, text.c_str(), ex - tx);

	// Add the ticks 
	mvwaddch(window, sy, sx, '[');
	mvwaddch(window, sy, sx + ex, ']');

	if (active)
		wattroff(window, WA_REVERSE);
}

void Kis_Button::Activate(int subcomponent) {
	active = 1;
}

void Kis_Button::Deactivate() {
	active = 0;
}

int Kis_Button::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	if (in_key == KEY_ENTER || in_key == '\n') {
		return 1;
	}

	return 0;
}

void Kis_Button::SetText(string in_text) {
	text = in_text;
}

Kis_Panel::Kis_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_intf) {
	globalreg = in_globalreg;
	kpinterface = in_intf;
	win = newwin(0, 0, 0, 0);
	pan = new_panel(win);
	menu = NULL;

	sx = sy = sizex = sizey = 0;
}

Kis_Panel::~Kis_Panel() {
	for (unsigned int x = 0; x < comp_vec.size(); x++) {
		delete comp_vec[x];
	}

	if (menu != NULL)
		delete menu;
	if (pan != NULL)
		del_panel(pan);
	if (win != NULL)
		delwin(win);
}

void Kis_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	sx = in_sx;
	sy = in_sy;
	sizex = in_x;
	sizey = in_y;

	if (win == NULL) {
		win = newwin(sizey, sizex, sy, sx);
	}

	if (pan == NULL) {
		pan = new_panel(win);
	} else {
		wresize(win, sizey, sizex);
		replace_panel(pan, win);
		move_panel(pan, sy, sx);
	}

	keypad(win, true);
}

int Kis_Panel::Poll() {
	int get = wgetch(win);
	int ret;

	ret = KeyPress(get);

	if (ret < 0)
		return ret;

	return 1;
}

void Kis_Panel::SetTitle(string in_title) {
	title = in_title;
}

void Kis_Panel::DrawTitleBorder() {
	box(win, 0, 0);
	wattron(win, WA_UNDERLINE);
	mvwaddstr(win, 0, 3, title.c_str());
	wattroff(win, WA_UNDERLINE);
}

#endif

