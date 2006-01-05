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

#include "kis_panel_components.h"

Kis_Menu::Kis_Menu() {
	cur_menu = 0;
	cur_item = 0;
}

Kis_Menu::~Kis_Menu() {
	ClearMenus();
}

int Kis_Menu::AddMenu(string in_text, int targ_char) {
	_menu *menu = new _menu;

	menu->text = in_text;
	if (targ_char < 0 || targ_char > in_text.length() - 1)
		menu->targchar = -1;
	else
		menu->targchar = targ_char;

	menu->width = 0;

	menu->id = menubar.size();

	menubar.push_back(menu);

	return menu->id;
}

int Kis_Menu::AddMenuItem(string in_text, int menuid, char extra) {
	if (menuid < 0 || menuid > menubar.size() - 1)
		return -1;

	_menuitem *item = new _menuitem;

	item->parentmenu = menuid;
	item->text = in_text;
	item->extrachar = extra;
	item->id = menubar[menuid]->items.size();
	menubar[menuid]->items.push_back(item);

	if (in_text.length() > menubar[menuid]->width)
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
	// Caller is expected to cause a screen redraw once this is called, so
	// just set the stuff up
	int menu = subcomponent / 100;
	int item = (subcomponent % 100) - 1;

	if (menu < 0 || menu > menubar.size() - 1)
		return;
	if (item < 0 || item > menubar[menu]->items.size() - 1)
		return;

	cur_menu = menu;
	cur_item = item;
}

void Kis_Menu::Deactivate() {
	cur_menu = -1;
	cur_item = -1;
}

void Kis_Menu::DrawComponent() {
	int hpos = 1;

	// Draw the menu bar itself
	for (unsigned int x = 0; x < menubar.size(); x++) {
		// If the current menu is the selected one, hilight it
		if (x == cur_menu)
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

		if (x == cur_menu) {
			// turn off hilighting, and draw the menu itself too
			wattroff(window, WA_REVERSE);

			// Resize the menu window
			wresize(menuwin, menubar[x]->items.size() + 2,
					menubar[x]->width + 7);
			// move it
			mvderwin(menuwin, sy + 1, sx + hpos);
			// Draw the box
			box(menuwin, 0, 0);

			// Draw the items in the menu
			for (unsigned int y = 0; y < menubar[x]->items.size(); y++) {
				string menuline;

				// Shortcut out a spacer
				if (menubar[x]->items[y]->text[0] == '-') {
					menuline = string('-', menubar[x]->width + 7);
					mvwaddstr(menuwin, 1 + y, 1, menuline.c_str());
					continue;
				}

				// Hilight the current item
				if (y == cur_item)
					wattron(menuwin, WA_REVERSE);

				// Format it with Foo ... F
				menuline = menubar[x]->items[y]->text + " ";
				for (unsigned int z = menuline.length(); 
					 z <= menubar[x]->width + 2; z++) {
					menuline = menuline + string(".");
				}

				menuline = menuline + " " + menubar[x]->items[y]->extrachar;

				// Print it
				mvwaddstr(menuwin, 1 + y, 1, menuline.c_str());

				if (y == cur_item)
					wattroff(menuwin, WA_REVERSE);
			}
		}

		hpos += menubar[x]->text.length() + 1;
	}
}

int Kis_Menu(int in_key) {
	// Menu movement
	if (in_key == KEY_RIGHT && cur_menu < menubar.size() - 1 &&
		cur_menu >= 0) {
		cur_menu++;
		return 0;
	}

	if (in_key == KEY_LEFT && cur_menu > 0) {
		cur_menu--;
		return 0;
	}

	if (in_key == KEY_DOWN && cur_menu >= 0 &&
		cur_item < menubar[cur_menu]->items.size() - 1) {
		cur_item++;

		// handle '----' spacer items
		if (menubar[cur_menu]->items[cur_item]->text[0] == '-' &&
			cur_item < menubar[cur_menu]->items.size() - 1)
			cur_item++;

		return 0;
	}

	if (in_key == KEY_UP && cur_item > 0) {
		cur_item--;

		// handle '----' spacer items
		if (menubar[cur_menu]->items[cur_item]->text[0] == '-' && cur_item > 0)
			cur_item--;

		return 0;
	}

	if (in_key == ' ' && cur_menu >= 0) {
		return (cur_menu * 100) + cur_item + 1;
	}

	// Key shortcuts
	if (cur_menu >= 0) {
		for (unsigned int x = 0; x < menubar[cur_menu]->items.size(); x++) {
			if (in_key == menubar[cur_menu]->items[x]->extrachar)
				return (cur_menu * 100) + x + 1;
		}
	}

	return 0;
}

