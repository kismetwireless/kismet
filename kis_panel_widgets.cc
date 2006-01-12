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

#include "kis_panel_widgets.h"
#include "timetracker.h"

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

	Kis_Main_Panel *mainp = new Kis_Main_Panel();
	
	mainp->Position(0, 0, LINES, COLS);

	live_panels.push_back(mainp);

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
	for (unsigned int x = 0; x < text_vec.size() && (int) x < ey; x++) {
		mvwaddnstr(window, sy + x, sx, text_vec[x + scroll_pos].c_str(), ex - 1);
	}

	// Draw the hash scroll bar
	mvwvline(window, sy, sx + ex - 1, ACS_BOARD, ey);
	// Figure out how far down our text we are
	// int perc = ey * (scroll_pos / text_vec.size());
	float perc = (float) ey * (float) ((float) (scroll_pos) / 
									 (float) (text_vec.size() - ey));
	wattron(window, WA_REVERSE);
	// Draw the solid position
	mvwaddch(window, sy + (int) perc, sx + ex - 1, ACS_BLOCK);

	wattroff(window, WA_REVERSE);
}

void Kis_Free_Text::Activate(int subcomponent) {
	// No magic
}

void Kis_Free_Text::Deactivate() {
	// No magic
}

int Kis_Free_Text::KeyPress(int in_key) {
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
	mvwaddstr(win, 0, 3, title.c_str());
}

Kis_Main_Panel::Kis_Main_Panel() {
	menu = new Kis_Menu;

	mn_file = menu->AddMenu("Kismet", 0);
	mi_connect = menu->AddMenuItem("Connect...", mn_file, 'C');
	menu->AddMenuItem("-", mn_file, 0);
	mi_quit = menu->AddMenuItem("Quit", mn_file, 'Q');

	mn_sort = menu->AddMenu("Sort", 0);
	menu->AddMenuItem("Auto-fit", mn_sort, 'a');
	menu->AddMenuItem("-", mn_sort, 0);
	menu->AddMenuItem("Channel", mn_sort, 'c');
	menu->AddMenuItem("First Seen", mn_sort, 'f');
	menu->AddMenuItem("First Seen (descending)", mn_sort, 'F');
	menu->AddMenuItem("Latest Seen", mn_sort, 'l');
	menu->AddMenuItem("Latest Seen (descending)", mn_sort, 'L');
	menu->AddMenuItem("BSSID", mn_sort, 'b');
	menu->AddMenuItem("SSID", mn_sort, 's');
	menu->AddMenuItem("Packets", mn_sort, 'p');
	menu->AddMenuItem("Packets (descending)", mn_sort, 'P');

	menu->Show();

	Kis_Free_Text *ftxt = new Kis_Free_Text();
	ftxt->SetPosition(win, 2, 3, 80, 20);
	ftxt->SetText("2.  Quick Start\n"
"\n"
"    PLEASE read the full manual, but for the impatient, here is the BARE\n"
"    MINIMUM needed to get Kismet working:\n"
"\n"
"    * Download Kismet from http://www.kismetwireless.net/download.shtml\n"
"    * Run ``./configure''.  Pay attention to the output!  If Kismet cannot\n"
"      find all the headers and libraries it needs, it won't be able to do\n"
"      many things.\n"
"    * Compile Kismet with ``make''\n"
"    * Install Kismet with either ``make install'' or ``make suidinstall''.\n"
"      YOU MUST READ THE SECTION OF THIS README NAMED \"SUID INSTALLATION &\n"
"      SECURITY\" OR YOUR SYSTEM MAY BE MADE VULNERABLE!!\n"
"    * Edit the config file (standardly in \"/usr/local/etc/kismet.conf\")\n"
"    * Set the user Kismet will drop privileges to by changing the \"suiduser\"\n"
"      configuration option.\n"
"    * Set the capture source by changing the \"source\" configuration option.\n"
"      FOR A LIST OF VALID CAPTURE SOURCES, SEE THE SECTION OF THIS README\n"
"      CALLED \"CAPTURE SOURCES\".  The capture source you should use depends\n"
"      on the operating system and driver that your wireless card uses.\n"
"      USE THE PROPER CAPTURE SOURCE.  No permanent harm will come from using\n"
"      the wrong one, but you won't get the optimal behavior.\n"
"    * Add an absolute path to the \"logtemplate\" configuration option if you\n"
"      want Kismet to always log to the same directory instead of the directory\n"
"      you start it in.\n"
"\n"
"    * Run ``kismet''.  You may need to start Kismet as root.\n"
"    * READ THE REST OF THIS README\n"
"\n"
"3.  Feature Overview\n"
"\n"
"    Kismet has many features useful in different situations for monitoring\n"
"    wireless networks:\n"
"\n"
"    - Ethereal/Tcpdump compatible data logging\n"
"    - Airsnort compatible weak-iv packet logging\n"
"    - Network IP range detection\n"
"    - Built-in channel hopping and multicard split channel hopping\n"
"    - Hidden network SSID decloaking\n"
"    - Graphical mapping of networks\n"
"    - Client/Server architecture allows multiple clients to view a single\n"
"      Kismet server simultaneously\n"
"    - Manufacturer and model identification of access points and clients\n"
"    - Detection of known default access point configurations\n"
"    - Runtime decoding of WEP packets for known networks\n"
"    - Named pipe output for integration with other tools, such as a layer3 IDS\n"
"      like Snort\n"
"    - Multiplexing of multiple simultaneous capture sources on a single Kismet\n"
"      instance\n"
"    - Distributed remote drone sniffing\n"
"    - XML output\n"
"    - Over 20 supported card types\n"
"\n"
"4.  Typical Uses\n"
"\n"
"    Common applications Kismet is useful for:\n"
"\n"
"    - Wardriving:  Mobile detection of wireless networks, logging and mapping\n"
"      of network location, WEP, etc.\n"
"    - Site survey:  Monitoring and graphing signal strength and location.\n"
"    - Distributed IDS:  Multiple Remote Drone sniffers distributed throughout\n"
"      an installation monitored by a single server, possibly combined with a\n"
"      layer3 IDS like Snort.\n"
"    - Rogue AP Detection:  Stationary or mobile sniffers to enforce site policy\n"
"      against rogue access points.\n"
"\n"
"5.  Upgrading from Previous Versions\n"
"\n"
"    Upgrading to Kismet 2005-08-R1:\n"
"      Upgrading from 2005-06-R1 or 2005-07-R1 should have no major changes.\n"
"      See the config file for new settings pertaining to waypoint export.\n"
"\n"
"      For upgrading from previous versions, see the section on upgrading to\n"
"      2005-06-R1 from older releases.\n");
	ftxt->Show();
	active_component = ftxt;
	comp_vec.push_back(ftxt);

	SetTitle("Kismet Newcore Client Test");
}

Kis_Main_Panel::~Kis_Main_Panel() {
}

void Kis_Main_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	menu->SetPosition(win, 1, 1, 0, 0);
}

void Kis_Main_Panel::DrawPanel() {
	werase(win);

	DrawTitleBorder();

	for (unsigned int x = 0; x < comp_vec.size(); x++)
		comp_vec[x]->DrawComponent();

	menu->DrawComponent();

	wmove(win, 0, 0);
}

int Kis_Main_Panel::KeyPress(int in_key) {
	int ret;
	
	// Give the menu first shot, it'll ignore the key if it didn't have 
	// anything open.
	ret = menu->KeyPress(in_key);

	if (ret == 0) {
		// Menu ate the key, let it go
		return 0;
	}

	if (ret > 0) {
		// Menu processed an event, do something with it
		if (ret == mi_quit) {
			return -1;
		}

		return 0;
	}

	// Otherwise the menu didn't touch the key, so pass it to the top
	// component
	if (active_component != NULL) {
		ret = active_component->KeyPress(in_key);

		if (ret == 0)
			return 0;

		return ret;
	}

	return 0;
}

