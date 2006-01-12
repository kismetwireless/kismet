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

	return 1;
}

void PanelInterface::AddPanel(Kis_Panel *in_panel) {
	live_panels.push_back(in_panel);
}

void PanelInterface::KillPanel(Kis_Panel *in_panel) {
	for (unsigned int x = 0; x < live_panels.size(); x++)
		if (live_panels[x] == in_panel)
			live_panels.erase(live_panels.begin() + x);
}

Kis_Menu::Kis_Menu() {
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
	menubar[menuid]->items.push_back(item);

	if ((int) in_text.length() > menubar[menuid]->width)
		menubar[menuid]->width = in_text.length();

	return (menuid * 100) + item->id + 1;
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

	int hpos = 1;

	if (menuwin == NULL)
		menuwin = derwin(window, 1, 1, 0, 0);

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

				// Format it with 'Foo     F'
				menuline = menubar[x]->items[y]->text + " ";
				for (unsigned int z = menuline.length(); 
					 (int) z <= menubar[x]->width + 2; z++) {
					menuline = menuline + string(" ");
				}

				menuline = menuline + " " + menubar[x]->items[y]->extrachar;

				// Print it
				mvwaddstr(menuwin, 1 + y, 1, menuline.c_str());

				if ((int) y == cur_item)
					wattroff(menuwin, WA_REVERSE);
			}
		}

		hpos += menubar[x]->text.length() + 1;
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
		return 0;
	}

	if (in_key == KEY_LEFT && cur_menu > 0) {
		cur_menu--;
		cur_item = 0;
		return 0;
	}

	if (in_key == KEY_DOWN && cur_menu >= 0 &&
		cur_item <= (int) menubar[cur_menu]->items.size() - 1) {

		if (cur_item == (int) menubar[cur_menu]->items.size() - 1) {
			cur_item = 0;
			return 0;
		}

		cur_item++;

		// handle '----' spacer items
		if (menubar[cur_menu]->items[cur_item]->text[0] == '-' &&
			cur_item < (int) menubar[cur_menu]->items.size() - 1)
			cur_item++;

		return 0;
	}

	if (in_key == KEY_UP && cur_item >= 0) {
		if (cur_item == 0) {
			cur_item = menubar[cur_menu]->items.size() - 1;
			return 0;
		}

		cur_item--;

		// handle '----' spacer items
		if (menubar[cur_menu]->items[cur_item]->text[0] == '-' && cur_item > 0)
			cur_item--;

		return 0;
	}

	// Space or enter
	if ((in_key == ' ' || in_key == 0x0A || in_key == KEY_ENTER) && cur_menu >= 0) {
		if (cur_item == -1) {
			cur_item = 0;
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
					return 0;
				}
			}
			// Try with lowercase, if we didn't find one already
			for (unsigned int x = 0; x < menubar.size(); x++) {
				if (tolower(in_key) == 
					tolower(menubar[x]->text[menubar[x]->targchar])) {
					cur_menu = x;
					cur_item = 0;
					return 0;
				}
			}
		} else {
			for (unsigned int x = 0; x < menubar[cur_menu]->items.size(); x++) {
				if (in_key == menubar[cur_menu]->items[x]->extrachar) {
					int ret = (cur_menu * 100) + x + 1;
					Deactivate();
					return ret;
				}
			}
		}
	}

	return -1;
}

Kis_Free_Text::Kis_Free_Text() {
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

Kis_Field_List::Kis_Field_List() {
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

Kis_Single_Input::Kis_Single_Input() {
	curs_pos = 0;
	label_pos = -1;
	max_len = 0;
}

Kis_Single_Input::~Kis_Single_Input() {
	// Nothing
}

void Kis_Single_Input::DrawComponent() {
	int xoff = 0;

	// Draw the label if we can, in bold
	if (ey > 2 && label_pos == 0 ) {
		wattron(window, WA_BOLD);
		mvwaddnstr(window, sx, sy, label.c_str(), ex);
		wattroff(window, WA_BOLD);
	} else if (label_pos == 1) {
		wattron(window, WA_BOLD);
		mvwaddnstr(window, sx, sy, label.c_str(), ex);
		wattroff(window, WA_BOLD);
		xoff += label.length();
	}



}

Kis_Panel::Kis_Panel() {
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

	if (pan = NULL) {
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

