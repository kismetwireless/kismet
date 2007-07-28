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

#ifndef __KIS_PANEL_WIDGETS_H__
#define __KIS_PANEL_WIDGETS_H__

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
#include <list>

#include "pollable.h"
#include "messagebus.h"

// Some standard filters we'd use on input
#define FILTER_ALPHANUM	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
	"abcdefghijklmnopqrstuvwxyz" \
	"0123456789 "
#define FILTER_ALPHANUMSYM "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
	"abcdefghijklmnopqrstuvwxyz" \
	"0123456789 " \
	".,~!@#$%^&*()_-+/:"
#define FILTER_NUM "0123456789"

class Kis_Panel;
class KisPanelInterface;

// Functor-style handler for special text.  Provides an alternate to the
// printstr mvwaddnstr which does color and type formating.
//
// Special string formatting:
// \s .. \S  - Standout
// \u .. \U  - Underline
// \r .. \R  - Reverse
// \d .. \D  - Dim
// \b .. \B  - Bold
class Kis_Panel_Specialtext {
public:
	static void Mvwaddnstr(WINDOW *win, int y, int x, string str, int n);
};

class Kis_Panel_Color {
public:
	Kis_Panel_Color();

	int AddColor(string color);
protected:
	int nextindex;
	map<string, int> color_index_map;
};

// Basic component super-class that handles drawing a group of items of
// some sort
class Kis_Panel_Component {
public:
	Kis_Panel_Component() { 
		fprintf(stderr, "FATAL OOPS:  Component called without globalreg\n");
		exit(1);
	}

	Kis_Panel_Component(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Panel_Component() { };

	// Show/hide
	virtual void Show() {
		if (visible == 0)
			layout_dirty = 1;
		visible = 1;
	}
	virtual void Hide() {
		if (visible)
			layout_dirty = 1;
		visible = 0;
	}

	virtual int GetVisible() {
		return visible;
	}

	virtual void SetName(string in_name) {
		name = in_name;
	}

	virtual string GetName() {
		return name;
	}

	// Set the position inside a window (start x, y, and width, height)
	virtual void SetPosition(int isx, int isy, int iex, int iey) {
		sx = isx;
		sy = isy;
		ex = iex;
		ey = iey;
		lx = ex - sx;
		ly = ey - sy;
		layout_dirty = 1;
	}

	virtual void SetPreferredSize(int ipx, int ipy) {
		px = ipx;
		py = ipy;
		layout_dirty = 1;
	}

	virtual void SetMinSize(int imx, int imy) {
		mx = imx;
		my = imy;
		layout_dirty = 1;
	}

	virtual int GetMinX() {
		return mx;
	}

	virtual int GetMinY() {
		return my;
	}

	virtual int GetPrefX() {
		return px;
	}

	virtual int GetPrefY() {
		return py;
	}

	virtual int GetLayoutDirty() {
		return layout_dirty;
	}

	virtual void SetLayoutDirty(int d) {
		layout_dirty = d;
	}

	// Draw the component
	virtual void DrawComponent() = 0;
	// Activate the component (and target a specific sub-component if we have
	// some reason to, like a specific menu)
	virtual void Activate(int subcomponent) {
		active = 1;
	}

	// Deactivate the component (this could cause closing of a menu, for example)
	virtual void Deactivate() {
		active = 0;
	}

	// Handle a key press
	virtual int KeyPress(int in_key) = 0;

protected:
	GlobalRegistry *globalreg;

	// Are we even visible?
	int visible;

	// Panel we're in
	Kis_Panel *parent_panel;

	// Widow we render to
	WINDOW *window;

	// Position within the window (start xy, size xy)
	int sx, sy, ex, ey, lx, ly, mx, my, px, py;

	int layout_dirty;

	// Are we active?
	int active;

	// Name
	string name;
};

class Kis_Panel_Packbox : public Kis_Panel_Component {
public:
	class packbox_details {
	public:
		Kis_Panel_Component *widget;
		int fill;
		int padding;
	};

	Kis_Panel_Packbox() {
		fprintf(stderr, "FATAL OOPS: Kis_Panel_Packbox() called\n");
		exit(1);
	}

	Kis_Panel_Packbox(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Panel_Packbox();

	// Pack to head, end, before or after a named item, or remove from the pack list
	virtual void Pack_Start(Kis_Panel_Component *in_widget, int fill, int padding);
	virtual void Pack_End(Kis_Panel_Component *in_widget, int in_fill, int padding);

	virtual void Pack_Before_Named(string in_name, Kis_Panel_Component *in_widget,
								   int fill, int padding);
	virtual void Pack_After_Named(string in_name, Kis_Panel_Component *in_widget,
								  int fill, int padding);

	virtual void Pack_Remove(Kis_Panel_Component *in_widget);

	// Homogenous spacing (all elements fit in the same size)
	virtual void SetHomogenous(int in_homog) {
		homogenous = in_homog;
		layout_dirty = 1;
	}

	// Set the spacing between elements (but not trailing): WWWSWWW
	virtual void SetSpacing(int in_space) {
		spacing = in_space;
		layout_dirty = 1;
	}

	virtual void SetCenter(int in_cent) {
		center = in_cent;
		layout_dirty = 1;
	}

	// Are we packing vertical or horizontal?
	virtual void SetPackH() {
		packing = 0;
		layout_dirty = 1;
	}

	virtual void SetPackV() {
		packing = 1;
		layout_dirty = 1;
	}

	virtual int KeyPress(int in_key) {
		return -1;
	}

	virtual void DrawComponent();

protected:
	list<Kis_Panel_Packbox::packbox_details> packed_items;

	virtual void Pack_Widgets();

	int homogenous, packing, spacing, center;
};

class Kis_Menu : public Kis_Panel_Component {
public:
	Kis_Menu() {
		fprintf(stderr, "FATAL OOPS: Kis_Menu called without globalreg\n");
		exit(1);
	}
	Kis_Menu(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
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
	// We can't delete, but we can hide a menu
	virtual void SetMenuVis(int in_menu, int in_vis);

	// Add an item to a menu ID
	virtual int AddMenuItem(string in_text, int menuid, char extra);
	// Add a submenu item to a menu ID, returns a menu we can add things
	// to for them to show up in the submenu
	virtual int AddSubMenuItem(string in_text, int menuid, char extra);
	// Set an item checkable
	virtual void SetMenuItemChecked(int in_item, int in_checked);
	// We can't delete, again, but we can hide
	virtual void SetMenuItemVis(int in_item, int in_vis);

	// Set a menu color
	virtual void SetMenuItemColor(int in_item, string in_color);

	// Delete all the menus
	virtual void ClearMenus();

	virtual void EnableMenuItem(int in_item);
	virtual void DisableMenuItem(int in_item);

	typedef struct _menuitem {
		int parentmenu;
		string text;
		char extrachar;
		int id;
		int enabled;
		int submenu;
		int visible;
		int checked;
		int colorpair;
	};

	typedef struct _menu {
		string text;
		int targchar;
		vector<Kis_Menu::_menuitem *> items;
		int width;
		int id;
		int submenu;
		int visible;
		int checked;
	};

protected:
	// Menu helper window
	WINDOW *menuwin;
	WINDOW *submenuwin;
	// Menu bar
	vector<Kis_Menu::_menu *> menubar;
	// Selected items...  When a sub menu is selected, the current menu gets put
	// into the sub menu record, and operations continue on the current menu.
	// Draw ops treat cur and sub as both "active" menus
	int cur_menu;
	int cur_item;
	int sub_menu;
	int sub_item;

	int text_color, border_color;

	virtual void FindNextEnabledItem();
	virtual void FindPrevEnabledItem();

	virtual void DrawMenu(_menu *menu, WINDOW *win, int hpos, int vpos);
};

// TODO - fix this.  Pop menus don't quite work right yet
class Kis_Pop_Menu : public Kis_Menu {
public:
	Kis_Pop_Menu() {
		fprintf(stderr, "FATAL OOPS: Kis_Pop_Menu called without globalreg\n");
		exit(1);
	}
	Kis_Pop_Menu(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Pop_Menu();

	virtual int KeyPress(int in_key);
	virtual void DrawComponent();
protected:
	virtual void DrawMenu(_menu *menu, WINDOW *win, int hpos, int vpos);
};

// A scrollable list of fields
class Kis_Field_List : public Kis_Panel_Component {
public:
	Kis_Field_List() {
		fprintf(stderr, "FATAL OOPS: Kis_Field_List called without globalreg\n");
		exit(1);
	}
	Kis_Field_List(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Field_List();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);

	// Add a row
	virtual int AddData(string in_field, string in_data);
	virtual int ModData(unsigned int in_row, string in_field, string in_data);

protected:
	// Data
	vector<string> field_vec;
	vector<string> data_vec;

	// Width of field column and scrolling position
	unsigned int field_w;
	int scroll_pos;
};

// A scrollable freetext field
class Kis_Free_Text : public Kis_Panel_Component {
public:
	Kis_Free_Text() {
		fprintf(stderr, "FATAL OOPS: Kis_Free_Text() called w/out globalreg\n");
		exit(1);
	}
	Kis_Free_Text(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Free_Text();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);

	virtual void SetText(string in_text);
	virtual void SetText(vector<string> in_text);

protected:
	vector<string> text_vec;

	int scroll_pos;
};

class KisStatusText_Messageclient : public MessageClient {
public:
	KisStatusText_Messageclient(GlobalRegistry *in_globalreg, void *in_aux) :
		MessageClient(in_globalreg, in_aux) { };
	virtual ~KisStatusText_Messageclient() { }
	void ProcessMessage(string in_msg, int in_flags);
};

// Status message field
class Kis_Status_Text : public Kis_Panel_Component {
public:
	Kis_Status_Text() {
		fprintf(stderr, "FATAL OOPS: Kis_Status_Text() called w/out globalreg\n");
		exit(1);
	}
	Kis_Status_Text(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Status_Text();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);

	virtual void AddLine(string in_line, int headeroffset = 0);
	
protected:
	vector<string> text_vec;

	int scroll_pos;

	int status_color_normal;
};

class Kis_Scrollable_Table : public Kis_Panel_Component {
public:
	Kis_Scrollable_Table() {
		fprintf(stderr, "FATAL OOPS: Kis_Scrollable_Table called w/out globalreg\n");
		exit(1);
	}
	Kis_Scrollable_Table(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Scrollable_Table();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);

	// Title format data
	typedef struct title_data {
		int width;
		string title;
		int alignment;
	};

	// Set the titles based on format data
	virtual int AddTitles(vector<Kis_Scrollable_Table::title_data> in_titles);

	// Add a row of data keyed to an int
	virtual int AddRow(int in_key, vector<string> in_fields);
	// Delete a keyed row
	virtual int DelRow(int in_key);
	// Replace a keyed row
	virtual int ReplaceRow(int in_key, vector<string> in_fields);
	// Get the selected key
	virtual int GetSelected();

	typedef struct row_data {
		int key;
		vector<string> data;
	};

protected:
	vector<title_data> title_vec;
	vector<row_data *> data_vec;
	map<int, int> key_map;

	int scroll_pos;
	int hscroll_pos;
	int selected;
};

enum KisWidget_LabelPos {
	LABEL_POS_NONE = -1,
	LABEL_POS_TOP = 0,
	LABEL_POS_LEFT = 1,
	LABEL_POS_BOT = 2,
	LABEL_POS_RIGHT = 3,
	LABEL_POS_BORDER = 4
};

// Single line input
class Kis_Single_Input : public Kis_Panel_Component {
public:
	Kis_Single_Input() {
		fprintf(stderr, "FATAL OOPS:  Kis_Single_Input called w/out globalreg\n");
		exit(1);
	}
	Kis_Single_Input(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Single_Input();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);

	// Allowed characters filter (mandatory)
	virtual void SetCharFilter(string in_charfilter);
	// Set the label and position
	virtual void SetLabel(string in_label, KisWidget_LabelPos in_pos);
	// Set the length of the text we want (can be more than the size of the
	// widget) (mandatory)
	virtual void SetTextLen(int in_len);

	// Pre-stock the widget text
	virtual void SetText(string in_text, int dpos, int ipos);
	// Get the text from the widget
	virtual string GetText();

protected:
	// Label, position (0 = top, 1 = left)
	string label;
	KisWidget_LabelPos label_pos;

	// Maximum length (may be more than the size of the widget)
	int max_len;

	// Characters we allow
	map<char, int> filter_map;

	/* text itself */
	string text;
	/* Position of the start of the displayed text */
	int curs_pos;
	/* Position of the input character */
	int inp_pos;
	/* drawing length of the text field */
	int draw_len;
};

// A button
class Kis_Button : public Kis_Panel_Component {
public:
	Kis_Button() {
		fprintf(stderr, "FATAL OOPS: Kis_Button() called w/out globalreg\n");
		exit(1);
	}
	Kis_Button(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Button();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);

	virtual void SetText(string in_text);

protected:
	string text;
};

class Kis_Panel {
public:
	Kis_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Panel() called w/out globalreg\n");
		exit(1);
	}
	Kis_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *kpinterface);
	virtual ~Kis_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);

	virtual int FetchSy() { return sy; }
	virtual int FetchSx() { return sx; }
	virtual int FetchSzy() { return sizey; }
	virtual int FetchSzx() { return sizex; }

	virtual int Poll();

	virtual void DrawPanel() = 0;

	virtual int KeyPress(int in_key) = 0;

	virtual void SetTitle(string in_title);

	virtual WINDOW *FetchDrawWindow() { return win; }
	virtual KisPanelInterface *FetchPanelInterface() { return kpinterface; }

	// Map a color pair out of preferences
	virtual void InitColorPref(string in_prefname, string in_def);
	virtual void ColorFromPref(int &clr, string in_prefname);
	virtual int AddColor(string in_color);

protected:
	GlobalRegistry *globalreg;
	KisPanelInterface *kpinterface;

	virtual void DrawTitleBorder();

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

	int text_color, border_color;
};

// Pollable supersystem for handling panels and input
class PanelInterface : public Pollable {
public:
	PanelInterface();
	PanelInterface(GlobalRegistry *in_globalreg);
	virtual ~PanelInterface();

	virtual unsigned int MergeSet(unsigned int in_max_fd, fd_set *out_rset, 
								  fd_set *out_wset);

	virtual int Poll(fd_set& in_rset, fd_set& in_wset);

	virtual int DrawInterface();

	virtual void AddPanel(Kis_Panel *in_panel);
	virtual void KillPanel(Kis_Panel *in_panel);
protected:
	vector<Kis_Panel *> live_panels;
	int draweventid;
	vector<Kis_Panel *> dead_panels;
};

#endif // panel
#endif // header

