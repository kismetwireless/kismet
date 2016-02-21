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
#define FILTER_ALPHA   	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
	"abcdefghijklmnopqrstuvwxyz" \
	"0123456789"
#define FILTER_NUM      "0123456789"
#define FILTER_ALPHANUM	FILTER_ALPHA FILTER_NUM " "
#define FILTER_ALPHANUMSYM FILTER_ALPHA FILTER_NUM \
	" .,~!@#$%^&*()_-+/\\:="

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
	static void Mvwaddnstr(WINDOW *win, int y, int x, string str, int n,
						   Kis_Panel *panel, int colorpair = 0);
	static unsigned int Strlen(string str);
};

class Kis_Panel_Color {
public:
	Kis_Panel_Color();

	int AddColor(string color, string pref);

	// Remap all instances using a color
	void RemapAllColors(string oldcolor, string newcolor, ConfigFile *conf);

	struct color_rec {
		string pref;
		string color[2];
		int colorindex;
	};
protected:
	int nextindex;
	map<string, Kis_Panel_Color::color_rec> color_index_map;
};

// Callback parameters - the component that activated, the status/return
// code it activated with (retval from mouse/kb event)
#define COMPONENT_CALLBACK_PARMS Kis_Panel_Component *component, int status, \
	void *aux, GlobalRegistry *globalreg
// Component is now active (most things won't need to use this since it ought
// to be handled by the panel level key/mouse handlers
#define COMPONENT_CBTYPE_SWITCH		0
// Component was activated - for whatever activated means for that widget.
// Text fields would return activated on enter, buttons on click/enter,
// etc.
#define COMPONENT_CBTYPE_ACTIVATED	1

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

	virtual void Debug() {
		fprintf(stderr, "debug - widget %p sx %d sy %d ex %d ey %d lx %d "
				"ly %d px %d py %d\n", this, sx, sy, ex, ey, lx, ly, px, py);
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

		if (cb_switch != NULL)
			(*cb_switch)(this, 1, cb_switch_aux, globalreg);
	}

	// Deactivate the component (this could cause closing of a menu, for example)
	virtual void Deactivate() {
		active = 0;

		if (cb_switch != NULL)
			(*cb_switch)(this, 0, cb_switch_aux, globalreg);
	}

	// Handle a key press
	virtual int KeyPress(int in_key) = 0;

	// Handle a mouse event (default: Ignore)
	virtual int MouseEvent(MEVENT *mevent) {
		return 0;
	}

	virtual void SetCallback(int cbtype, int (*cb)(COMPONENT_CALLBACK_PARMS),
							 void *aux);
	virtual void ClearCallback(int cbtype);

	virtual void SetColorPrefs(string in_active, string in_inactive) {
		color_active_pref = in_active;
		color_inactive_pref = in_inactive;
	}

protected:
	// Silly function to pick the right color - give it the color you want,
	// and it gives you the inactive color if the widget is inactive
	inline int SetTransColor(int want_color) {
		if (active) {
			wattrset(window, want_color);
			return want_color;
		} else {
			wattrset(window, color_inactive);
			return color_inactive;
		}
	}

	GlobalRegistry *globalreg;

	// Primary colors
	int color_active;
	int color_inactive;

	string color_active_pref, color_inactive_pref;

	// Callbacks
	int (*cb_switch)(COMPONENT_CALLBACK_PARMS);
	void *cb_switch_aux;

	int (*cb_activate)(COMPONENT_CALLBACK_PARMS);
	void *cb_activate_aux;

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

	virtual int GetVisible();

	virtual void DrawComponent();

protected:
	list<Kis_Panel_Packbox::packbox_details> packed_items;

	virtual void Pack_Widgets();

	int homogenous, packing, spacing, center;
};

#define MENUITEM_CB_PARMS	GlobalRegistry *globalreg, int menuitem, void *auxptr
typedef void (*kis_menuitem_cb)(MENUITEM_CB_PARMS);

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
	virtual int MouseEvent(MEVENT *mevent);

	// Add a menu & the hilighted character offset
	virtual int AddMenu(string in_text, int targ_char);
	// We can't delete, but we can hide a menu
	virtual void SetMenuVis(int in_menu, int in_vis);

	// Add an item to a menu ID
	virtual int AddMenuItem(string in_text, int menuid, char extra, int after = -1);
	// Add a submenu item to a menu ID, returns a menu we can add things
	// to for them to show up in the submenu
	virtual int AddSubMenuItem(string in_text, int menuid, char extra);
	// Set an item checkable
	virtual void SetMenuItemChecked(int in_item, int in_checked);
	virtual int GetMenuItemChecked(int in_item);
	// We can't delete, again, but we can hide
	virtual void SetMenuItemVis(int in_item, int in_vis);

	// Set a menu color
	virtual void SetMenuItemColor(int in_item, string in_color);

	// Set a menu item symbol (radio vs check vs ...)
	virtual void SetMenuItemCheckSymbol(int in_item, char in_symbol);

	// Set a menu item callback
	virtual void SetMenuItemCallback(int in_item, kis_menuitem_cb in_cb, void *in_aux);
	virtual void ClearMenuItemCallback(int in_item);

	virtual int FindMenu(string in_menu);

	// Delete all the menus
	virtual void ClearMenus();

	virtual void EnableMenuItem(int in_item);
	virtual void DisableMenuItem(int in_item);

	virtual void EnableAllItems(int in_menu);
	virtual void DisableAllItems(int in_menu);

	struct _menuitem {
		int parentmenu;
		string text;
		char extrachar;
		int id;
		int enabled;
		int submenu;
		int visible;
		int checked;
		int colorpair;
		char checksymbol;

		kis_menuitem_cb callback;
		void *auxptr;
	};

	struct _menu {
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
	int mouse_triggered;

	int text_color, border_color, disable_color;

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

	virtual int KeyPress(int in_key);

	virtual void SetText(string in_text);
	virtual void SetText(vector<string> in_text);
	virtual vector<string> GetText() {
		return text_vec;
	}
	virtual void AppendText(string in_text);
	virtual void AppendText(vector<string> in_text);

	virtual void SetMaxText(int in_max) { max_text = in_max; }

	// Follow the end of the text unless we're scrolled differently
	virtual void SetFollowTail(int in_set) {
		follow_tail = in_set;
	}

	virtual void SetAlignment(int in_alignment) {
		alignment = in_alignment;
	}

protected:
	vector<string> text_vec;

	int scroll_pos;
	int alignment;
	int max_text;
	int follow_tail;
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

	virtual int KeyPress(int in_key);

	// Title format data
	struct title_data {
		int width;
		int draw_width;
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
	// Get a rows data
	virtual vector<string> GetRow(int in_key);
	// Get the selected key
	virtual int GetSelected();
	// Get the selected row data
	virtual vector<string> GetSelectedData();
	// Set a selected row
	virtual int SetSelected(int in_key);
	// Clear all raws
	virtual void Clear();

	// Highlight the selected row
	virtual void SetHighlightSelected(int in_set) {
		draw_highlight_selected = in_set;
	}

	// Lock scrolling to the top of the table, ie keep the bottom
	// visible all the time
	virtual void SetLockScrollTop(int in_set) {
		draw_lock_scroll_top = in_set;
	}

	virtual void SetDrawTitles(int in_set) {
		draw_titles = in_set;
	}

	struct row_data {
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

	int draw_lock_scroll_top, draw_highlight_selected, draw_titles;
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

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

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

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	virtual void SetLabel(string in_text) { SetText(in_text); }
	virtual void SetText(string in_text);

protected:
	string text;
};

// A checkbox
class Kis_Checkbox : public Kis_Panel_Component {
public:
	Kis_Checkbox() {
		fprintf(stderr, "FATAL OOPS: Kis_Checkbox() called w/out globalreg\n");
		exit(1);
	}
	Kis_Checkbox(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Checkbox();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	virtual void SetLabel(string in_text) { SetText(in_text); }
	virtual void SetText(string in_text);

	virtual int GetChecked();
	virtual void SetChecked(int in_check);

protected:
	string text;

	int checked;
};

class Kis_Radiobutton : public Kis_Panel_Component {
public:
	Kis_Radiobutton() {
		fprintf(stderr, "FATAL OOPS: Kis_Radiobutton() called w/out globalreg\n");
		exit(1);
	}
	Kis_Radiobutton(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Radiobutton();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	virtual void SetText(string in_text);

	virtual int GetChecked();
	virtual void SetChecked(int in_check);

	virtual void LinkRadiobutton(Kis_Radiobutton *in_button);

protected:
	string text;

	int checked;

	vector<Kis_Radiobutton *> linked_vec;
};

// Scaling interpolated graph
class Kis_IntGraph : public Kis_Panel_Component {
public:
	struct graph_label {
		string label;
		int position;
		// Used on markers
		int endposition;
	}; 

	struct graph_source {
		int layer;
		string colorpref;
		string colordefault;
		int colorval;
		char line[2];
		char fill[2];
		vector<int> *data;
		string name;
		int overunder;
	};

	Kis_IntGraph() {
		fprintf(stderr, "FATAL OOPS: Kis_IntGraph() called w/out globalreg\n");
		exit(1);
	}
	Kis_IntGraph(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) : 
		Kis_Panel_Component(in_globalreg, in_panel) {
		globalreg = in_globalreg;
		active = 0;
		graph_mode = 0;
		color_fw = 0;
		maxlabel = 0;
		xgraph_size = 0;
		label_x_graphref = -1;
		draw_scale = 1;
		draw_layers = 1;
		min_y = 0;
		max_y = 0;
	}
	virtual ~Kis_IntGraph() { };

	virtual void DrawComponent();

	virtual int KeyPress(int in_key);

	// Min/max values
	virtual void SetScale(int in_miny, int in_maxy) {
		min_y = in_miny;
		max_y = in_maxy;
	}

	// Interpolate graph to fit?
	virtual void SetInterpolation(int in_x) {
		inter_x = in_x;
	}

	virtual void SetXLabels(vector<graph_label> in_xl, string graphname) {
		label_x = in_xl;

		// Figure out which graph we reference
		label_x_graphref = -1;
		for (unsigned int x = 0; x < data_vec.size(); x++) {
			if (data_vec[x].name == graphname) {
				label_x_graphref = x;
				break;
			}
		}

		// Figure out the # of lines we need to save on the graph
		xgraph_size = 0;
		for (unsigned int x = 0; x < label_x.size(); x++) {
			if (xgraph_size < (int) label_x[x].label.size())
				xgraph_size = (int) label_x[x].label.size() + 1;
		}
	}

	virtual void SetMode(int mode) {
		graph_mode = mode;
	}

	virtual void SetDrawScale(int in_draw_scale) {
		draw_scale = in_draw_scale;
	}

	virtual void SetDrawLayers(int in_draw_layers) {
		draw_layers = in_draw_layers;
	}

	// Add a data vector at a layer with a color preference, representation
	// character, over/under (1 over, 0 n/a, -1 under), and external vector.
	// All data sources must share a common min/max representation
	virtual void AddExtDataVec(string name, int layer, string colorpref, 
							   string colordefault, char line, char fill,
							   int overunder, vector<int> *in_dv);
protected:
	// Graph coordinates
	int min_y, max_y;
	// Interpolation
	int inter_x;

	int color_fw;

	// Graph mode
	// 0 = normal
	// 1 = over/under
	int graph_mode;

	int draw_scale, draw_layers;

	// Graph source vector
	vector<graph_source> data_vec;
	
	// Max label length
	unsigned int maxlabel;

	// Labels
	vector<graph_label> label_x;
	int xgraph_size, label_x_graphref;
};

#if 0

// Polar graph
class Kis_PolarGraph : public Kis_Panel_Component {
public:
	struct graph_point {
		int id;

		string colorpref;
		string colordefault;
		int colorval;

		string name;

		double r, theta;
	};

	Kis_PolarGraph() {
		fprintf(stderr, "FATAL OOPS: Kis_PolarGraph() called w/out globalreg\n");
		exit(1);
	}

	Kis_PolarGraph(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) : 
		Kis_Panel_Component(in_globalreg, in_panel) {

		globalreg = in_globalreg;
		active = 0;
		color_fw = 0;

		maxr = 0;
	}
	virtual ~Kis_PolarGraph() { };

	virtual void DrawComponent();

	virtual int KeyPress(int in_key);

	virtual void AddPoint(int id, graph_point gp);
	virtual void DelPoint(int id);
	virtual void ClearPoints();

protected:
	int color_fw;
	double maxr;

	vector<Kis_PolarGraph::graph_point> point_vec;
};

// File picker widget, derivation of the scrollable table
// Due to widget tabbing structure, can't easily nest multiple widgets into a
// virtual packbox so directory changing has to be an external text box
class Kis_Filepicker : public Kis_Scrollable_Table {
public:
	Kis_Filepicker() { fprintf(stderr, "FATAL OOPS: Kis_Filepicker();\n"); exit(1); }

	Kis_Filepicker(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Filepicker();

	virtual void SetDirectory(string in_dir);
	virtual void SetFile(string in_file);
	virtual string GetDirectory() { return cur_directory; }

	virtual int KeyPress(int in_key);

protected:
	string cur_directory, set_file;
};

#endif

// Callbacks for a panel exiting, if any
#define KISPANEL_COMPLETECB_PARMS int rc, void *auxptr, GlobalRegistry *globalreg
typedef void (*KispanelCompleteRx)(KISPANEL_COMPLETECB_PARMS);

class Kis_Panel {
public:
	Kis_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Panel() called w/out globalreg\n");
		exit(1);
	}
	Kis_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *kpinterface);
	virtual ~Kis_Panel();

	virtual void ShowPanel() { show_panel(pan); }
	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);

	virtual int FetchSy() { return sy; }
	virtual int FetchSx() { return sx; }
	virtual int FetchSzy() { return sizey; }
	virtual int FetchSzx() { return sizex; }

	virtual int Poll();

	virtual void ClearPanel() {
		wclear(win);
	}

	virtual void DrawPanel() {
		ColorFromPref(text_color, "panel_text_color");
		ColorFromPref(border_color, "panel_border_color");

		wbkgdset(win, text_color);
		werase(win);

		DrawTitleBorder();
		DrawComponentVec();
		wmove(win, 0, 0);
	}

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	virtual void SetTitle(string in_title);

	virtual WINDOW *FetchDrawWindow() { return win; }
	virtual KisPanelInterface *FetchPanelInterface() { return kpinterface; }

	virtual Kis_Menu *FetchMenu() { return menu; }

	// Map a color pair out of preferences
	virtual void InitColorPref(string in_prefname, string in_def);
	virtual void ColorFromPref(int &clr, string in_prefname);
	virtual void RemapAllColors(string oldcolor, string newcolor);
	virtual int AddColor(string in_color);

	void AddComponentVec(Kis_Panel_Component *in_comp, int in_flags);
	void DelComponentVec(Kis_Panel_Component *in_comp);

	void SetActiveComponent(Kis_Panel_Component *in_comp);

	void SetCompleteCallback(KispanelCompleteRx in_callback, void *in_aux);

	void KillPanel();

protected:
	// Bit values of what components expect to happen
	// COMP_DRAW - issue a draw command to this component during panel draw
	//             components inside a packbox get called by the packbox and
	//             don't need an explicit draw
	// COMP_TAB  - Include in the list of components we tab to and activate,
	//             gets an activate event and becomes the focus for keyboard
	//             input
	// COMP_EVT  - Generates events when triggered but may not necessarily be
	// 			   tabable (menus gets COMP_EVT only)
	// COMP_STATIC Is not freed when the panel is destroyed, used for widgets
	//             managed outside the panel itself
#define KIS_PANEL_COMP_DRAW			1
#define KIS_PANEL_COMP_TAB			2
#define KIS_PANEL_COMP_EVT			4
#define KIS_PANEL_COMP_STATIC		8
	struct component_entry {
		int comp_flags;
		Kis_Panel_Component *comp;
	};

	void DrawComponentVec();

	vector<component_entry> pan_comp_vec;

	GlobalRegistry *globalreg;
	KisPanelInterface *kpinterface;

	virtual void DrawTitleBorder();

	WINDOW *win;
	PANEL *pan;

	string title;

	// Menus get treated specially because they have to be drawn last
	Kis_Menu *menu;

	int tab_pos;

	// Component which gets the keypress we didn't filter
	Kis_Panel_Component *active_component;

	int sx, sy, sizex, sizey;

	int text_color, border_color;

	// Main component sized to the full window (usually a packbox)
	Kis_Panel_Component *main_component;

	int last_key;
	struct timeval last_key_time;

	int escape_timer;

	// Return value and callback, if any
	int rc;
	KispanelCompleteRx rcallback;
	void *raux;
};

// Pollable supersystem for handling panels and input
class PanelInterface : public Pollable {
public:
	PanelInterface();
	PanelInterface(GlobalRegistry *in_globalreg);
	virtual ~PanelInterface();

	virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset);

	virtual int Poll(fd_set& in_rset, fd_set& in_wset);

	virtual int DrawInterface();
	virtual void ResizeInterface();

	virtual void AddPanel(Kis_Panel *in_panel);
	virtual void KillPanel(Kis_Panel *in_panel);
protected:
	vector<Kis_Panel *> live_panels;
	int draweventid;
	vector<Kis_Panel *> dead_panels;
	int hsize, vsize;
};

#endif // panel
#endif // header

