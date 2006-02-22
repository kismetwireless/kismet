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
#include "kis_panel_frontend.h"
#include "kis_panel_windows.h"

Kis_Main_Panel::Kis_Main_Panel(GlobalRegistry *in_globalreg) :
	Kis_Panel(in_globalreg) {
	globalreg = in_globalreg;
	menu = new Kis_Menu(globalreg);

	mn_file = menu->AddMenu("Kismet", 0);
	mi_connect = menu->AddMenuItem("Connect...", mn_file, 'C');
	menu->AddMenuItem("-", mn_file, 0);
	mi_quit = menu->AddMenuItem("Quit", mn_file, 'Q');

	mn_view = menu->AddMenu("Show", 1);
	mi_showtext = menu->AddMenuItem("Text", mn_view, 't');
	mi_showfields = menu->AddMenuItem("2-Fields", mn_view, '2');
	mi_showinput = menu->AddMenuItem("Input", mn_view, 'i');

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

	mn_tools = menu->AddMenu("Tools", 0);
	menu->DisableMenuItem(menu->AddMenuItem("Network List...", mn_tools, 'n'));
	menu->AddMenuItem("Client List...", mn_tools, 'c');
	menu->DisableMenuItem(menu->AddMenuItem("Details...", mn_tools, 'd'));

	menu->AddMenuItem("-", mn_tools, 0);

	menu->AddMenuItem("Server List...", mn_tools, 'S');
	menu->AddMenuItem("Capture Source List...", mn_tools, 'C');
	menu->AddMenuItem("GPS...", mn_tools, 'G');

	menu->Show();

	sinp = new Kis_Single_Input(globalreg);
	sinp->SetPosition(win, 2, 3, 50, 2);
	sinp->SetText("abacadabamonkeycadabafooblahblahblah", 0, 10);
	sinp->SetLabel("Foo", LABEL_POS_LEFT);
	sinp->SetTextLen(120);
	sinp->SetCharFilter(FILTER_ALPHANUM);
	active_component = sinp;
	comp_vec.push_back(sinp);

	sct = new Kis_Scrollable_Table(globalreg);
	sct->SetPosition(win, 2, 3, 50, 15);

	Kis_Scrollable_Table::title_data td;
	vector<Kis_Scrollable_Table::title_data> titlevec;

	td.width = 6;
	td.title = "Name";
	td.alignment = 1;
	titlevec.push_back(td);

	td.width = 25;
	td.title = "Address";
	td.alignment = 0;
	titlevec.push_back(td);

	td.width = 6;
	td.title = "Port";
	td.alignment = 2;
	titlevec.push_back(td);

	sct->AddTitles(titlevec);

	sct->AddRow(0, StrTokenize("One\001localhost\0012501", "\001"));
	sct->AddRow(1, StrTokenize("Two\001localhost\0012502", "\001"));
	sct->AddRow(2, StrTokenize("Three\001some.host\0012503", "\001"));
	sct->AddRow(3, StrTokenize("Four\001foo.com\0012504", "\001"));
	sct->AddRow(10, StrTokenize("One\001localhost\0012501", "\001"));
	sct->AddRow(11, StrTokenize("Two\001localhost\0012502", "\001"));
	sct->AddRow(12, StrTokenize("Three\001some.host\0012503", "\001"));
	sct->AddRow(13, StrTokenize("Four\001foo.com\0012504", "\001"));
	sct->AddRow(20, StrTokenize("One\001localhost\0012501", "\001"));
	sct->AddRow(21, StrTokenize("Two\001localhost\0012502", "\001"));
	sct->AddRow(22, StrTokenize("Three\001some.host\0012503", "\001"));
	sct->AddRow(23, StrTokenize("Four\001foo.com\0012504", "\001"));
	
	active_component = sct;
	comp_vec.push_back(sct);

	ftxt = new Kis_Free_Text(globalreg);
	ftxt->SetPosition(win, 2, 3, 80, 20);
	ftxt->SetText("2.  Quick Start\n"
"\n"
"    PLEASE \\uread the full manual, but for the impatient\\U, here is the BARE\n"
"    MINIMUM needed to get Kismet working:\n"
"\n"
"    \\b* Download Kismet from http://www.kismetwireless.net/download.shtml\\B\n"
"    * Run ``./configure''.  Pay attention to the output!  If Kismet cannot\n"
"      find all the headers and libraries it needs, it won't be able to do\n"
"      many things.\n"
"    \\r* Compile Kismet with ``make''\\R\n"
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
	active_component = ftxt;
	comp_vec.push_back(ftxt);

	fl = new Kis_Field_List(globalreg);
	fl->SetPosition(win, 2, 3, 80, 20);

	fl->AddData("One", "Data from one");
	fl->AddData("BSSID", "00:11:22:33:44:55");
	fl->AddData("Magic", "Abracadabra");
	fl->AddData("Type", "infrastructure");
	fl->AddData("Carrier","802.11b");
	fl->AddData("Info", "\"None\"");
	fl->AddData("Channel", "01");
	fl->AddData("Encryption", "\"None\"");
	fl->AddData("Maxrate", "11.0");
	fl->AddData("LLC", "114");
	fl->AddData("Data", "56");
	fl->AddData("Crypt", "0");
    fl->AddData("Weak", "0");
    fl->AddData("Dupe IV", "0");
    fl->AddData("Total", "170");
    fl->AddData("First", "\"Sat Aug 20 13:59:33 2005\"");
    fl->AddData("Last", "\"Sat Aug 20 14:00:21 2005\"");
    fl->AddData("Min Loc", "Lat 90.000000 Lon 180.000000 Alt 0.000000 Spd 0.000000");
    fl->AddData("Max Loc", "Lat -90.000000 Lon -180.000000 Alt 0.000000 Spd 0.000000");
	fl->AddData("Crypt", "0");
    fl->AddData("Weak", "0");
    fl->AddData("Dupe IV", "0");
    fl->AddData("Total", "170");
    fl->AddData("First", "\"Sat Aug 20 13:59:33 2005\"");

	active_component = fl;
	comp_vec.push_back(fl);

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

		if (ret == mi_showtext) {
			ftxt->Show();
			fl->Hide();
			// sinp->Hide();
			sct->Hide();
			active_component = ftxt;
		} else if (ret == mi_showfields) {
			ftxt->Hide();
			// sinp->Hide();
			sct->Hide();
			fl->Show();
			active_component = fl;
		} else if (ret == mi_showinput) {
			ftxt->Hide();
			fl->Hide();
			//sinp->Show();
			sct->Show();
			active_component = sct;
		} else if (ret == mi_connect) {
			Kis_Connect_Panel *cp = new Kis_Connect_Panel(globalreg);
			cp->Position((LINES / 2) - 4, (COLS / 2) - 20, 8, 40);
			globalreg->panel_interface->AddPanel(cp);
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

Kis_Connect_Panel::Kis_Connect_Panel(GlobalRegistry *in_globalreg) :
	Kis_Panel(in_globalreg) {
	globalreg = in_globalreg;

	hostname = new Kis_Single_Input(globalreg);
	hostport = new Kis_Single_Input(globalreg);
	okbutton = new Kis_Button(globalreg);

	comp_vec.push_back(hostname);
	comp_vec.push_back(hostport);
	comp_vec.push_back(okbutton);

	tab_components.push_back(hostname);
	tab_components.push_back(hostport);
	tab_components.push_back(okbutton);
	tab_pos = 0;

	active_component = hostname;

	SetTitle("Connect to Server");

	hostname->SetLabel("Host", LABEL_POS_LEFT);
	hostname->SetTextLen(120);
	hostname->SetCharFilter(FILTER_ALPHANUMSYM);

	hostport->SetLabel("Port", LABEL_POS_LEFT);
	hostport->SetTextLen(5);
	hostport->SetCharFilter(FILTER_NUM);

	okbutton->SetText("Connect");
}

Kis_Connect_Panel::~Kis_Connect_Panel() {
}

void Kis_Connect_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	hostname->SetPosition(win, 2, 2, in_x - 6, 1);
	hostport->SetPosition(win, 2, 4, 14, 1);
	okbutton->SetPosition(win, in_x - 15, in_y - 2, 10, 1);

	hostname->Activate(1);
	active_component = hostname;

	hostname->Show();
	hostport->Show();
	okbutton->Show();
}

void Kis_Connect_Panel::DrawPanel() {
	werase(win);

	DrawTitleBorder();

	for (unsigned int x = 0; x < comp_vec.size(); x++)
		comp_vec[x]->DrawComponent();

	wmove(win, 0, 0);
}

int Kis_Connect_Panel::KeyPress(int in_key) {
	int ret;

	// Rotate through the tabbed items
	if (in_key == '\t') {
		tab_components[tab_pos]->Deactivate();
		tab_pos++;
		if (tab_pos >= (int) tab_components.size())
			tab_pos = 0;
		tab_components[tab_pos]->Activate(1);
		active_component = tab_components[tab_pos];
	}

	// Otherwise the menu didn't touch the key, so pass it to the top
	// component
	if (active_component != NULL) {
		ret = active_component->KeyPress(in_key);

		if (active_component == okbutton && ret == 1) {
			// Normally we'd configure the TCP client here
			globalreg->panel_interface->KillPanel(this);
		} else if (active_component == cancelbutton && ret == 1) {
			// Cancel and close
			globalreg->panel_interface->KillPanel(this);
		}

		if (ret == 0)
			return 0;

		return ret;
	}

	return 0;
}

#endif

