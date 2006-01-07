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

#ifndef __KIS_PANEL_COMPONENTS_H__
#define __KIS_PANEL_COMPONENTS_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#ifdef HAVE_LIBCURSES
#include <curses.h>
#else
#include <ncurses.h>
#endif
#include <panel.h>
#undef erase
#undef clear
#undef move

#include <stdio.h>
#include <string>
#include <vector>

// Basic component super-class that handles drawing a group of items of
// some sort
class Kis_Panel_Component {
public:
	Kis_Panel_Component() { 
		window = NULL;
	};
	virtual ~Kis_Panel_Component() { };

	// Set the position inside a window
	virtual void SetPosition(WINDOW *inwin, int isx, int isy, int iex, int iey) {
		window = inwin;
		sx = isx;
		sy = isy;
		ex = iex;
		ey = iey;
	}

	// Draw the component
	virtual void DrawComponent() = 0;
	// Activate the component (and target a specific sub-component if we have
	// some reason to, like a specific menu)
	virtual void Activate(int subcomponent) = 0;
	// Deactivate the component (this could cause closing of a menu, for example)
	virtual void Deactivate() = 0;

	// Handle a key press
	virtual int KeyPress(int in_key) = 0;

protected:
	// Widow we render to
	WINDOW *window;

	// Position within the window (start xy, end xy)
	int sx, sy, ex, ey;
};

class Kis_Menu : Kis_Panel_Component {
public:
	Kis_Menu();
	virtual ~Kis_Menu();

	// Refresh drawing the menu bar in its current state
	virtual void DrawComponent();

	// Activate a specific menu (using the #*100+item scheme)
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	// menu# * 100 + item#
	virtual int KeyPress(int in_key);

	// Add a menu & the hilighted character offset
	virtual int AddMenu(string in_text, int targ_char);
	// Add an item to a menu ID
	virtual int AddMenuItem(string in_text, int menuid, char extra);
	// Delete all the menus
	virtual void ClearMenus();

	typedef struct _menuitem {
		int parentmenu;
		string text;
		char extrachar;
		int id;
	};

	typedef struct _menu {
		string text;
		int targchar;
		vector<Kis_Menu::_menuitem *> items;
		int width;
		int id;
	};

protected:
	// Menu helper window
	WINDOW *menuwin;
	// Menu bar
	vector<Kis_Menu::_menu *> menubar;
	// Selected items
	int cur_menu;
	int cur_item;
	// Have we moved since we drew?
	int mvdelta;
};

class Kis_Panel {
public:
	Kis_Panel();
	virtual ~Kis_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);

	virtual void PrintPanel() = 0;

	virtual int KeyPress(int in_key) = 0;

	virtual void SetTitle(string in_title);

protected:
	WINDOW *win;
	PANEL *pan;

	string title;

	// Menus get treated specially because they have to be drawn last
	Kis_Menu *menu;

	// Vector of components that can get drawn
	vector<Kis_Panel_Component *> comp_vec;

	// Component which gets the keypress we didn't filter
	Kis_Panel_Component *active_component;

	int sx, sy, sizex, sizey;
};

#endif // panel
#endif // header

