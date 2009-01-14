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

#include <sstream>
#include <iomanip>

#include "kis_panel_widgets.h"
#include "kis_panel_frontend.h"
#include "kis_panel_windows.h"
#include "kis_panel_preferences.h"

#define WIN_CENTER(h, w)	(LINES / 2) - ((h) / 2), (COLS / 2) - ((w) / 2), (h), (w)

int MenuActivateCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Main_Panel *) aux)->MenuAction(status);
	return 1;
}

void KisMainPanel_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->NetClientAdd(netcli, add);
}

void KisMainPanel_Configured(CLICONF_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->NetClientConfigure(kcli, recon);
}

void KisMainPanel_INFO(CLIPROTO_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->Proto_INFO(globalreg, proto_string,
											proto_parsed, srccli, auxptr);
}

void KisMainPanel_GPS(CLIPROTO_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->Proto_GPS(globalreg, proto_string,
										   proto_parsed, srccli, auxptr);
}

int NetlistActivateCB(COMPONENT_CALLBACK_PARMS) {
	Kis_NetDetails_Panel *dp = 
		new Kis_NetDetails_Panel(globalreg, 
								 ((Kis_Main_Panel *) aux)->FetchPanelInterface());
	dp->Position(WIN_CENTER(LINES, COLS));
	((Kis_Main_Panel *) aux)->FetchPanelInterface()->AddPanel(dp);

	return 1;
}

const char *gps_fields[] = {
	"fix", "lat", "lon", "alt", "spd", "heading", NULL
};

Kis_Main_Panel::Kis_Main_Panel(GlobalRegistry *in_globalreg, 
							   KisPanelInterface *in_intf) : 
	Kis_Panel(in_globalreg, in_intf) {

	menu = new Kis_Menu(globalreg, this);

	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, MenuActivateCB, this);

	mn_file = menu->AddMenu("Kismet", 0);
	mi_startserver = menu->AddMenuItem("Start Server...", mn_file, 'S');
	mi_serverconsole = menu->AddMenuItem("Server Console...", mn_file, 'c');

	menu->AddMenuItem("-", mn_file, 0);

	mi_connect = menu->AddMenuItem("Connect...", mn_file, 'C');
	mi_disconnect = menu->AddMenuItem("Disconnect", mn_file, 'D');
	menu->AddMenuItem("-", mn_file, 0);

	mi_addcard = menu->AddMenuItem("Add Source...", mn_file, 'A');
	mi_conf = menu->AddMenuItem("Config Channel...", mn_file, 'L');

	menu->AddMenuItem("-", mn_file, 0);

	mn_plugins = menu->AddSubMenuItem("Plugins", mn_file, 'x');
	mi_addplugin = menu->AddMenuItem("Select Plugins...", mn_plugins, 'P');
	menu->AddMenuItem("-", mn_plugins, 0);
	mi_noplugins = menu->AddMenuItem("No plugins loaded...", mn_plugins, 0);
	menu->DisableMenuItem(mi_noplugins);

	mn_preferences = menu->AddSubMenuItem("Preferences", mn_file, 'P');
	mi_startprefs = menu->AddMenuItem("Startup & Shutdown...", mn_preferences, 's');
	mi_serverprefs = menu->AddMenuItem("Servers...", mn_preferences, 'S');
	mi_colorprefs = menu->AddMenuItem("Colors...", mn_preferences, 'C');
	mi_netcolprefs = menu->AddMenuItem("Network Columns...", mn_preferences, 'N');
	mi_netextraprefs = menu->AddMenuItem("Network Extras...", mn_preferences, 'E');
	mi_infoprefs = menu->AddMenuItem("Info Pane...", mn_preferences, 'I');
	mi_gpsprefs = menu->AddMenuItem("GPS...", mn_preferences, 'G');

	menu->AddMenuItem("-", mn_file, 0);

	mi_quit = menu->AddMenuItem("Quit", mn_file, 'Q');

	menu->EnableMenuItem(mi_connect);
	menu->DisableMenuItem(mi_disconnect);
	connect_enable = 1;

	mn_sort = menu->AddMenu("Sort", 0);
	mi_sort_auto = menu->AddMenuItem("Auto-fit", mn_sort, 'a');
	menu->AddMenuItem("-", mn_sort, 0);
	mi_sort_type = menu->AddMenuItem("Type", mn_sort, 't');
	mi_sort_chan = menu->AddMenuItem("Channel", mn_sort, 'c');
	mi_sort_crypt = menu->AddMenuItem("Encryption", mn_sort, 'e');
	mi_sort_first = menu->AddMenuItem("First Seen", mn_sort, 'f');
	mi_sort_first_d = menu->AddMenuItem("First Seen (descending)", mn_sort, 'F');
	mi_sort_last = menu->AddMenuItem("Latest Seen", mn_sort, 'l');
	mi_sort_last_d = menu->AddMenuItem("Latest Seen (descending)", mn_sort, 'L');
	mi_sort_bssid = menu->AddMenuItem("BSSID", mn_sort, 'b');
	mi_sort_ssid = menu->AddMenuItem("SSID", mn_sort, 's');
	mi_sort_packets = menu->AddMenuItem("Packets", mn_sort, 'p');
	mi_sort_packets_d = menu->AddMenuItem("Packets (descending)", mn_sort, 'P');

	mn_view = menu->AddMenu("View", 0);
	mi_netdetails = menu->AddMenuItem("Network Details", mn_view, 'd');
	mi_chandetails = menu->AddMenuItem("Channel Details", mn_view, 'c');
	mi_gps = menu->AddMenuItem("GPS Details", mn_view, 'G');
	menu->AddMenuItem("-", mn_view, 0);
	mi_shownetworks = menu->AddMenuItem("Network List", mn_view, 'n');
	mi_showgps = menu->AddMenuItem("GPS Data", mn_view, 'g');
	mi_showsummary = menu->AddMenuItem("General Info", mn_view, 'S');
	mi_showstatus = menu->AddMenuItem("Status", mn_view, 's');
	mi_showpps = menu->AddMenuItem("Packet Graph", mn_view, 'p');
	mi_showsources = menu->AddMenuItem("Source Info", mn_view, 'C');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	// Make a hbox to hold the network list and additional info widgets,
	// and the vertical stack of optional widgets
	hbox = new Kis_Panel_Packbox(globalreg, this);
	hbox->SetPackH();
	hbox->SetHomogenous(0);
	hbox->SetSpacing(1);
	hbox->Show();

	// Make a vbox to hold the hbox we just made, and the status text
	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	// Make the network pack box which holds the network widget and the 
	// extra info line widget
	netbox = new Kis_Panel_Packbox(globalreg, this);
	netbox->SetPackV();
	netbox->SetSpacing(0);
	netbox->SetHomogenous(0);
	netbox->SetName("KIS_MAIN_NETBOX");
	netbox->Show();

	// Make the one-line horizontal box which holds GPS, battery, etc
	linebox = new Kis_Panel_Packbox(globalreg, this);
	linebox->SetPackH();
	linebox->SetSpacing(1);
	linebox->SetHomogenous(0);
	linebox->SetName("KIS_MAIN_LINEBOX");
	linebox->SetPreferredSize(0, 1);
	linebox->Show();

	// Make the vertical box holding things like the # of networks
	optbox = new Kis_Panel_Packbox(globalreg, this);
	optbox->SetPackV();
	optbox->SetSpacing(1);
	optbox->SetHomogenous(0);
	optbox->SetName("KIS_MAIN_OPTBOX");
	optbox->SetPreferredSize(10, 0);
	optbox->Show();

	statustext = new Kis_Status_Text(globalreg, this);
	statuscli = new KisStatusText_Messageclient(globalreg, statustext);
	globalreg->messagebus->RegisterClient(statuscli, MSGFLAG_ALL);

	// We only want 5 lines of status text
	statustext->SetPreferredSize(0, 5);
	statustext->SetName("KIS_MAIN_STATUS");
	statustext->Show();

	netlist = new Kis_Netlist(globalreg, this);
	netlist->SetName("KIS_MAIN_NETLIST");
	netlist->Show();
	netlist->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetlistActivateCB, this);

	// Set up the packet rate graph as over/under linked to the
	// packets per second
	packetrate = new Kis_IntGraph(globalreg, this);
	packetrate->SetName("PPS_GRAPH");
	packetrate->SetPreferredSize(0, 8);
	packetrate->SetScale(0, 0);
	packetrate->SetInterpolation(1);
	packetrate->SetMode(1);
	packetrate->Show();
	packetrate->AddExtDataVec("Packets", 4, "graph_pps", "yellow,yellow", 
							  ' ', ' ', 1, &pps);
	packetrate->AddExtDataVec("Data", 4, "graph_datapps", "red,red", 
							  ' ', ' ', -1, &datapps);
	for (unsigned int x = 0; x < 50; x++) {
		pps.push_back(0);
		datapps.push_back(0);
	}
	lastpackets = lastdata = 0;

	infobits = new Kis_Info_Bits(globalreg, this);
	infobits->SetName("KIS_MAIN_INFOBITS");
	infobits->Show();

	optbox->Pack_End(infobits, 1, 0);

	sourceinfo = new Kis_Free_Text(globalreg, this);
	sourceinfo->SetName("KIS_MAIN_SOURCEINFO");
	sourceinfo->SetAlignment(1);

	optbox->Pack_End(sourceinfo, 0, 0);

	gpsinfo = new Kis_Free_Text(globalreg, this);
	gpsinfo->SetName("KIS_MAIN_GPSINFO");
	gpsinfo->SetAlignment(1);
	gpsinfo->SetText("No GPS info (GPS not connected)");
	gpsinfo->Show();
	linebox->Pack_End(gpsinfo, 0, 0);

	// Pack our boxes together
	hbox->Pack_End(netbox, 1, 0);
	hbox->Pack_End(optbox, 0, 0);

	netbox->Pack_End(netlist, 1, 0);
	netbox->Pack_End(linebox, 0, 0);
	netbox->Pack_End(packetrate, 0, 0);

	vbox->Pack_End(hbox, 1, 0);
	vbox->Pack_End(statustext, 0, 0);

	active_component = netlist;
	netlist->Activate(0);
	tab_pos = 0;

	AddComponentVec(netlist, KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	if (kpinterface->prefs.FetchOpt("LOADEDFROMFILE") != "1") {
		_MSG("Failed to load preferences file, will use defaults", MSGFLAG_INFO);
	}

	AddColorPref("panel_text_color", "Text");
	AddColorPref("panel_textdis_color", "Text-Inactive");
	AddColorPref("panel_border_color", "Window Border");
	AddColorPref("menu_text_color", "Menu Text");
	AddColorPref("menu_disable_color", "Menu Disabled");
	AddColorPref("menu_border_color", "Menu Border");
	AddColorPref("netlist_header_color", "Netlist Header");
	AddColorPref("netlist_normal_color", "Netlist Unencrypted");
	AddColorPref("netlist_crypt_color", "Netlist Encrypted");
	AddColorPref("netlist_group_color", "Netlist Group");
	AddColorPref("netlist_factory_color", "Netlist Factory");
	AddColorPref("status_normal_color", "Status Text");
	AddColorPref("info_normal_color", "Info Pane");

	AddColorPref("graph_pps", "PPS Graph");
	AddColorPref("graph_datapps", "PPS Data Graph");

	AddColorPref("graph_detail_pps", "Network Packet Graph");
	AddColorPref("graph_detail_retrypps", "Network Retry Graph");
	AddColorPref("graph_detail_sig", "Network Signal Graph");

	UpdateViewMenu(-1);

	agg_gps_num = TokenNullJoin(&agg_gps_fields, gps_fields);

	addref = 
		kpinterface->Add_NetCli_AddCli_CB(KisMainPanel_AddCli, (void *) this);

	if (kpinterface->prefs.FetchOpt("autoconnect") == "true" &&
		kpinterface->prefs.FetchOpt("default_host") != "" &&
		kpinterface->prefs.FetchOpt("default_port") != "") {
		string constr = string("tcp://") +
			kpinterface->prefs.FetchOpt("default_host") + ":" +
			kpinterface->prefs.FetchOpt("default_port");

		_MSG("Auto-connecting to " + constr, MSGFLAG_INFO);

		kpinterface->AddNetClient(constr, 1);
	}
}

Kis_Main_Panel::~Kis_Main_Panel() {
	globalreg->messagebus->RemoveClient(statuscli);
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(KisMainPanel_Configured);
	kpinterface->Remove_AllNetcli_ProtoHandler("INFO",
											   KisMainPanel_INFO, this);
	kpinterface->Remove_AllNetcli_ProtoHandler("GPS",
											   KisMainPanel_GPS, this);
}

void kmp_prompt_startserver(KIS_PROMPT_CB_PARMS) {
	if (ok) {
		Kis_Spawn_Panel *sp = new Kis_Spawn_Panel(globalreg, globalreg->panel_interface);
		sp->Position(WIN_CENTER(6, 40));
		globalreg->panel_interface->AddPanel(sp);
	}
}

void Kis_Main_Panel::Startup() {
	if (kpinterface->prefs.FetchOpt("DEFAULT_HOST") == "") {
		kpinterface->prefs.SetOpt("DEFAULT_HOST", "localhost", 1);
		kpinterface->prefs.SetOpt("DEFAULT_PORT", "2501", 1);
		kpinterface->prefs.SetOpt("AUTOCONNECT", "true", 1);
	}

	if (kpinterface->prefs.FetchOpt("STARTUP_PROMPTSERVER") == "true" ||
		kpinterface->prefs.FetchOpt("STARTUP_PROMPTSERVER") == "") {

		vector<string> t;
		t.push_back("Automatically start Kismet server?");
		t.push_back("Launch Kismet server and connect to it automatically.");
		t.push_back("If you use a Kismet server started elsewhere, choose");
		t.push_back("No and change the Startup preferences.");

		Kis_Prompt_Panel *kpp = 
			new Kis_Prompt_Panel(globalreg, kpinterface);
		kpp->SetTitle("Start Kismet Server");
		kpp->SetDisplayText(t);
		kpp->SetCallback(kmp_prompt_startserver, this);
		kpp->SetDefaultButton(1);
		kpp->Position(WIN_CENTER(7, 50));
		kpinterface->AddPanel(kpp);
	} else if (kpinterface->prefs.FetchOpt("STARTUP_SERVER") == "true" ||
			   kpinterface->prefs.FetchOpt("STARTUP_SERVER") == "") {
		kmp_prompt_startserver(globalreg, 1, this);
	}
}

void Kis_Main_Panel::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	// Reset the GPS text
	gpsinfo->SetText("No GPS info (GPS not connected)");
	
	if (in_recon)
		return;

	if (in_cli->RegisterProtoHandler("INFO", "packets,llcpackets,",
									 KisMainPanel_INFO, this) < 0) {
		_MSG("Could not register INFO protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}

	if (in_cli->RegisterProtoHandler("GPS", agg_gps_fields,
									 KisMainPanel_GPS, this) < 0) {
		_MSG("Could not register GPS protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
}

void Kis_Main_Panel::NetClientAdd(KisNetClient *in_cli, int add) {
	if (add == 0)
		return;

	in_cli->AddConfCallback(KisMainPanel_Configured, 1, this);
}

void Kis_Main_Panel::Proto_INFO(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < 2)
		return;

	int pkts, datapkts;

	if (sscanf((*proto_parsed)[0].word.c_str(), "%d", &pkts) != 1) 
		return;

	if (sscanf((*proto_parsed)[1].word.c_str(), "%d", &datapkts) != 1) 
		return;

	if (lastpackets == 0)
		lastpackets = pkts;
	if (lastdata == 0)
		lastdata = datapkts;

	pps.push_back(pkts - lastpackets);
	datapps.push_back(datapkts - lastdata);

	if (pps.size() > 50) 
		pps.erase(pps.begin(), pps.begin() + pps.size() - 50);
	if (datapps.size() > 50) 
		datapps.erase(datapps.begin(), datapps.begin() + datapps.size() - 50);
	lastpackets = pkts;
	lastdata = datapkts;
}

void Kis_Main_Panel::Proto_GPS(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) agg_gps_num)
		return;

	int fnum = 0, fix;
	float lat, lon, alt, spd;

	string gpstext;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &fix) != 1)
		return;

	if (fix < 2) {
		gpsinfo->SetText("No GPS info (GPS does not have signal)");
		return;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &lat) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &lon) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &alt) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &spd) != 1)
		return;

	int eng = StrLower(kpinterface->prefs.FetchOpt("GPSUNIT")) != "metric";

	if (eng) {
		// Convert speed to feet/sec
		spd /= 3.2808;
		// Convert alt to feet
		alt /= 3.2808;
	}

	gpstext = string("GPS ") + 
		NtoString<float>(lat).Str() + string(" ") + 
		NtoString<float>(lon).Str() + string(" ");

	if (eng) {
		if (spd > 2500)
			gpstext += "Spd: " + NtoString<float>(spd / 5280, 2).Str() + " mph ";
		else
			gpstext += "Spd: " + NtoString<float>(spd, 2).Str() + " fph ";

		if (alt > 2500)
			gpstext += "Alt: " + NtoString<float>(alt / 5280, 2).Str() + " m ";
		else
			gpstext += "Alt: " + NtoString<float>(alt, 2).Str() + " ft ";

	} else {
		if (spd > 1000)
			gpstext += "Spd: " + NtoString<float>(spd / 1000, 2).Str() + "Km/hr ";
		else
			gpstext += "Spd: " + NtoString<float>(spd, 2).Str() + "m/hr ";

		if (alt > 1000)
			gpstext += "Alt: " + NtoString<float>(alt / 1000, 2).Str() + "Km ";
		else
			gpstext += "Alt: " + NtoString<float>(alt, 2).Str() + "m ";
	}

	
	gpsinfo->SetText(gpstext + IntToString(fix) + string("d fix"));
}

void Kis_Main_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	menu->SetPosition(1, 0, 0, 0);

	// All we have to do is position the main box now
	vbox->SetPosition(1, 1, in_x - 1, in_y - 2);

	/*
	netlist->SetPosition(in_sx + 2, in_sy + 1, in_x - 15, in_y - 8);
	statustext->SetPosition(in_sx + 1, in_y - 7, in_x - 2, 5);
	*/
}

void Kis_Main_Panel::DrawPanel() {
	// Set up the source list
	vector<string> sourceinfotxt;
	map<uuid, KisPanelInterface::knc_card *> *cardmap =
		kpinterface->FetchNetCardMap();

	for (map<uuid, KisPanelInterface::knc_card *>::iterator x = cardmap->begin();
		 x != cardmap->end(); ++x) {
		sourceinfotxt.push_back("\004u" + x->second->name + "\004U");
		if (x->second->hopping)
			sourceinfotxt.push_back("Hop");
		else
			sourceinfotxt.push_back(IntToString(x->second->channel));
	}

	sourceinfo->SetText(sourceinfotxt);

	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	UpdateSortMenu();

	DrawComponentVec();

	menu->DrawComponent();

	wmove(win, 0, 0);
}

int Kis_Main_Panel::MouseEvent(MEVENT *mevent) {
	vector<KisNetClient *> *clivec = kpinterface->FetchNetClientVecPtr();

	if (clivec->size() == 0 && connect_enable == 0) {
		menu->EnableMenuItem(mi_connect);
		menu->DisableMenuItem(mi_disconnect);
		connect_enable = 1;
	} else if (clivec->size() > 0 && connect_enable) {
		menu->EnableMenuItem(mi_disconnect);
		menu->DisableMenuItem(mi_connect);
		connect_enable = 0;
	}

	if (kpinterface->FetchServerFramework() == NULL) {
		menu->EnableMenuItem(mi_startserver);
	} else {
		menu->DisableMenuItem(mi_startserver);
	}

	return Kis_Panel::MouseEvent(mevent);
}

int Kis_Main_Panel::KeyPress(int in_key) {
	vector<KisNetClient *> *clivec = kpinterface->FetchNetClientVecPtr();

	if (clivec->size() == 0 && connect_enable == 0) {
		menu->EnableMenuItem(mi_connect);
		menu->DisableMenuItem(mi_disconnect);
		connect_enable = 1;
	} else if (clivec->size() > 0 && connect_enable) {
		menu->EnableMenuItem(mi_disconnect);
		menu->DisableMenuItem(mi_connect);
		connect_enable = 0;
	}

	return Kis_Panel::KeyPress(in_key);
}


// Dump text to stderr
void kmp_textcli_stderr(TEXTCLI_PARMS) {
	fprintf(stderr, "%s\n", text.c_str());
}

// Set fatal condition on error
void kmp_spawnserver_fail(CLIFRAME_FAIL_CB_PARMS) {
	fprintf(stderr, "Spawned Kismet server has exited\n");
	globalreg->fatal_condition = 1;
}

// This function is "fun".
//
// In any case, we're shutting down.
//
// If the user says "yes, kill the server", and we started the server locally,
// we teardown the UI structure, set a callback that prints to stderr on the server,
// and set a death callback that sets the system to fatal and turns us off entirely.
//
// Otherwise, we just set the server to teardown.
void kmp_prompt_killserver(KIS_PROMPT_CB_PARMS) {
	// Kis_Main_Panel *kmp = (Kis_Main_Panel *) auxptr;
	TextCliFrame *cf = globalreg->panel_interface->FetchServerFramework();
	PopenClient *po = globalreg->panel_interface->FetchServerPopen();
	KisNetClient *knc = globalreg->panel_interface->FetchFirstNetclient();

	_MSG("Quitting...", MSGFLAG_ERROR);

	if (ok && knc != NULL) {
		// fprintf(stderr, "debug - injecting shutdown command\n");
		knc->InjectCommand("SHUTDOWN");
	}

	// This kicks off the curses teardown entirely
	globalreg->panel_interface->Shutdown();

	if (ok && cf != NULL) {
		cf->RegisterCallback(kmp_textcli_stderr, NULL);
		cf->RegisterFailCB(kmp_spawnserver_fail, NULL);
		if (po != NULL) {
			po->SoftKillConnection();
		}
	} else {
		globalreg->fatal_condition = 1;
	}
}

void Kis_Main_Panel::MenuAction(int opt) {
	vector<KisNetClient *> *clivec = kpinterface->FetchNetClientVecPtr();

	// Menu processed an event, do something with it
	if (opt == mi_quit) {
		if (kpinterface->FetchFirstNetclient() == NULL &&
			kpinterface->FetchServerFramework() == NULL) {
			globalreg->fatal_condition = 1;
			_MSG("Quitting...", MSGFLAG_INFO);
		}

		if ((kpinterface->prefs.FetchOpt("STOP_PROMPTSERVER") == "true" ||
			 kpinterface->prefs.FetchOpt("STOP_PROMPTSERVER") == "") &&
			(kpinterface->prefs.FetchOpt("STOP_SERVER") == "true" ||
			 kpinterface->prefs.FetchOpt("STOP_SERVER") == "")) {

			vector<string> t;
			t.push_back("Stop Kismet server before quitting?");
			t.push_back("This will stop capture & shut down any other");
			t.push_back("clients that might be connected to this server");

			Kis_Prompt_Panel *kpp = 
				new Kis_Prompt_Panel(globalreg, kpinterface);
			kpp->SetTitle("Stop Kismet Server");
			kpp->SetDisplayText(t);
			kpp->SetCallback(kmp_prompt_killserver, this);
			kpp->SetDefaultButton(1);
			kpp->Position(WIN_CENTER(7, 50));
			kpinterface->AddPanel(kpp);
			return;
		} else if (kpinterface->prefs.FetchOpt("STOP_SERVER") == "true" ||
				   kpinterface->prefs.FetchOpt("STOP_SERVER") == "") {
			// if we're stopping the server without prompt, just call the
			// prompt handler and tell it OK
			kmp_prompt_killserver(globalreg, 1, NULL);
		} else {
			globalreg->fatal_condition = 1;
			_MSG("Quitting...", MSGFLAG_INFO);
		}

		return;
	} else if (opt == mi_connect) {
		Kis_Connect_Panel *cp = new Kis_Connect_Panel(globalreg, kpinterface);
		cp->Position(WIN_CENTER(8, 40));
		kpinterface->AddPanel(cp);
	} else if (opt == mi_startserver) {
		Kis_Spawn_Panel *sp = new Kis_Spawn_Panel(globalreg, kpinterface);
		sp->Position(WIN_CENTER(6, 40));
		kpinterface->AddPanel(sp);
	} else if (opt == mi_serverconsole) {
		Kis_Console_Panel *cp = new Kis_Console_Panel(globalreg, kpinterface);
		cp->Position(WIN_CENTER(LINES, COLS));
		kpinterface->AddPanel(cp);
	} else if (opt == mi_disconnect) {
		if (clivec->size() > 0) {
			kpinterface->RemoveNetClient((*clivec)[0]);
		}
	} else if (opt == mi_sort_auto) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "auto", 1);
	} else if (opt == mi_sort_type) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "type", 1);
	} else if (opt == mi_sort_chan) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "channel", 1);
	} else if (opt == mi_sort_crypt) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "crypt_type", 1);
	} else if (opt == mi_sort_first) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "first", 1);
	} else if (opt == mi_sort_first_d) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "first_desc", 1);
	} else if (opt == mi_sort_last) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "last", 1);
	} else if (opt == mi_sort_last_d) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "last_desc", 1);
	} else if (opt == mi_sort_bssid) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "bssid", 1);
	} else if (opt == mi_sort_ssid) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "ssid", 1);
	} else if (opt == mi_sort_packets) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "packets", 1);
	} else if (opt == mi_sort_packets_d) {
		kpinterface->prefs.SetOpt("NETLIST_SORT", "packets_desc", 1);
	} else if (opt == mi_netdetails) {
		Kis_NetDetails_Panel *dp = new Kis_NetDetails_Panel(globalreg, kpinterface);
		dp->Position(WIN_CENTER(LINES, COLS));
		kpinterface->AddPanel(dp);
	} else if (opt == mi_chandetails) {
		Kis_ChanDetails_Panel *dp = new Kis_ChanDetails_Panel(globalreg, kpinterface);
		dp->Position(WIN_CENTER(LINES, COLS));
		kpinterface->AddPanel(dp);
	} else if (opt == mi_gps) {
		Kis_Gps_Panel *gp = new Kis_Gps_Panel(globalreg, kpinterface);
		gp->Position(WIN_CENTER(20, 60));
		kpinterface->AddPanel(gp);
	} else if (opt == mi_showsummary ||
			   opt == mi_showstatus ||
			   opt == mi_showpps ||
			   opt == mi_showgps ||
			   opt == mi_showsources ||
			   opt == mi_shownetworks) {
		UpdateViewMenu(opt);
	} else if (opt == mi_addcard) {
		vector<KisNetClient *> *cliref = kpinterface->FetchNetClientVecPtr();
		if (cliref->size() == 0) {
			kpinterface->RaiseAlert("No servers",
									"There are no servers.  You must\n"
									"connect to a server before adding\n"
									"cards.\n");
		} else if (cliref->size() == 1) {
			sp_addcard_cb(globalreg, kpinterface, (*cliref)[0], NULL);
		} else {
			kpinterface->RaiseServerPicker("Choose server", sp_addcard_cb,
										   NULL);
		} 
	} else if (opt == mi_conf) {
		vector<KisNetClient *> *cliref = kpinterface->FetchNetClientVecPtr();
		if (cliref->size() == 0) {
			kpinterface->RaiseAlert("No servers",
									"There are no servers.  You must\n"
									"connect to a server before setting\n"
									"channels.\n");
		} else {
			Kis_Chanconf_Panel *cp = new Kis_Chanconf_Panel(globalreg, kpinterface);
			cp->Position(WIN_CENTER(14, 50));
			kpinterface->AddPanel(cp);
		}
	} else if (opt == mi_addplugin) {
		Kis_Plugin_Picker *pp = new Kis_Plugin_Picker(globalreg, kpinterface);
		pp->Position(WIN_CENTER(16, 70));
		kpinterface->AddPanel(pp);
	} else if (opt == mi_colorprefs) {
		SpawnColorPrefs();
	} else if (opt == mi_startprefs) {
		Kis_StartupPref_Panel *sp = new Kis_StartupPref_Panel(globalreg, kpinterface);
		sp->Position(WIN_CENTER(14, 70));
		kpinterface->AddPanel(sp);
	} else if (opt == mi_serverprefs) {
		SpawnServerPrefs();
	} else if (opt == mi_netcolprefs) {
		SpawnNetcolPrefs();
	} else if (opt == mi_netextraprefs) {
		SpawnNetextraPrefs();
	} else if (opt == mi_infoprefs) {
		SpawnInfoPrefs();
	} else if (opt == mi_gpsprefs) {
		Kis_GpsPref_Panel *pp = new Kis_GpsPref_Panel(globalreg, kpinterface);
		pp->Position(WIN_CENTER(10, 70));
		kpinterface->AddPanel(pp);
	} else {
		for (unsigned int p = 0; p < plugin_menu_vec.size(); p++) {
			if (opt == plugin_menu_vec[p].menuitem) {
				(*(plugin_menu_vec[p].callback))(plugin_menu_vec[p].auxptr);
				break;
			}
		}
	}
}

int Kis_Main_Panel::AddPluginMenuItem(string in_name, int (*callback)(void *),
									  void *auxptr) {
	plugin_menu_opt mo;

	// Hide the "no plugins" menu and make our own item
	menu->SetMenuItemVis(mi_noplugins, 0);
	mo.menuitem = menu->AddMenuItem(in_name, mn_plugins, 0);
	mo.callback = callback;
	mo.auxptr = auxptr;

	plugin_menu_vec.push_back(mo);

	return mo.menuitem;
}

void Kis_Main_Panel::AddColorPref(string in_pref, string in_text) {
	colorpref cp;

	for (unsigned int x = 0; x < color_pref_vec.size(); x++) {
		if (color_pref_vec[x].pref == in_pref)
			return;
	}

	cp.pref = in_pref;
	cp.text = in_text;

	color_pref_vec.push_back(cp);
}

void Kis_Main_Panel::SpawnColorPrefs() {
	Kis_ColorPref_Panel *cpp = new Kis_ColorPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; x < color_pref_vec.size(); x++) {
		cpp->AddColorPref(color_pref_vec[x].pref, color_pref_vec[x].text);
	}

	cpp->Position((LINES / 2) - 10, (COLS / 2) - 25, 20, 50);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnNetcolPrefs() {
	Kis_ColumnPref_Panel *cpp = new Kis_ColumnPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; bssid_column_details[x][0] != NULL; x++) {
		cpp->AddColumn(bssid_column_details[x][0],
					   bssid_column_details[x][1]);
	}

	cpp->ColumnPref("netlist_columns", "Network List");

	cpp->Position((LINES / 2) - 9, (COLS / 2) - 30, 18, 60);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnNetextraPrefs() {
	Kis_ColumnPref_Panel *cpp = new Kis_ColumnPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; bssid_extras_details[x][0] != NULL; x++) {
		cpp->AddColumn(bssid_extras_details[x][0],
					   bssid_extras_details[x][1]);
	}

	cpp->ColumnPref("netlist_extras", "Network Extras");

	cpp->Position((LINES / 2) - 9, (COLS / 2) - 30, 18, 60);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnInfoPrefs() {
	Kis_ColumnPref_Panel *cpp = new Kis_ColumnPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; info_bits_details[x][0] != NULL; x++) {
		cpp->AddColumn(info_bits_details[x][0],
					   info_bits_details[x][1]);
	}

	cpp->ColumnPref("netinfo_items", "Info Pane");

	cpp->Position((LINES / 2) - 9, (COLS / 2) - 30, 18, 60);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnServerPrefs() {
	Kis_AutoConPref_Panel *cpp = new Kis_AutoConPref_Panel(globalreg, kpinterface);

	cpp->Position((LINES / 2) - 5, (COLS / 2) - 20, 11, 40);
	kpinterface->AddPanel(cpp);
}

Kis_Display_NetGroup *Kis_Main_Panel::FetchSelectedNetgroup() {
	if (netlist == NULL)
		return NULL;

	return netlist->FetchSelectedNetgroup();
}

vector<Kis_Display_NetGroup *> *Kis_Main_Panel::FetchDisplayNetgroupVector() {
	if (netlist == NULL)
		return NULL;

	return netlist->FetchDisplayVector();
}

void Kis_Main_Panel::UpdateSortMenu() {
	netsort_opts so = netlist->FetchSortMode();

	if (so == netsort_autofit)
		menu->SetMenuItemChecked(mi_sort_auto, 1);
	else
		menu->SetMenuItemChecked(mi_sort_auto, 0);

	if (so == netsort_type)
		menu->SetMenuItemChecked(mi_sort_type, 1);
	else
		menu->SetMenuItemChecked(mi_sort_type, 0);

	if (so == netsort_channel)
		menu->SetMenuItemChecked(mi_sort_chan, 1);
	else
		menu->SetMenuItemChecked(mi_sort_chan, 0);

	if (so == netsort_crypt)
		menu->SetMenuItemChecked(mi_sort_crypt, 1);
	else
		menu->SetMenuItemChecked(mi_sort_crypt, 0);

	if (so == netsort_first)
		menu->SetMenuItemChecked(mi_sort_first, 1);
	else
		menu->SetMenuItemChecked(mi_sort_first, 0);

	if (so == netsort_first_desc)
		menu->SetMenuItemChecked(mi_sort_first_d, 1);
	else
		menu->SetMenuItemChecked(mi_sort_first_d, 0);

	if (so == netsort_last)
		menu->SetMenuItemChecked(mi_sort_last, 1);
	else
		menu->SetMenuItemChecked(mi_sort_last, 0);

	if (so == netsort_last_desc)
		menu->SetMenuItemChecked(mi_sort_last_d, 1);
	else
		menu->SetMenuItemChecked(mi_sort_last_d, 0);

	if (so == netsort_bssid)
		menu->SetMenuItemChecked(mi_sort_bssid, 1);
	else
		menu->SetMenuItemChecked(mi_sort_bssid, 0);

	if (so == netsort_ssid)
		menu->SetMenuItemChecked(mi_sort_ssid, 1);
	else
		menu->SetMenuItemChecked(mi_sort_ssid, 0);

	if (so == netsort_packets)
		menu->SetMenuItemChecked(mi_sort_packets, 1);
	else
		menu->SetMenuItemChecked(mi_sort_packets, 0);

	if (so == netsort_packets_desc)
		menu->SetMenuItemChecked(mi_sort_packets_d, 1);
	else
		menu->SetMenuItemChecked(mi_sort_packets_d, 0);
}

void Kis_Main_Panel::UpdateViewMenu(int mi) {
	string opt;

	if (mi == mi_showsummary) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSUMMARY");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWSUMMARY", "false", 1);
			menu->SetMenuItemChecked(mi_showsummary, 0);
			optbox->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWSUMMARY", "true", 1);
			menu->SetMenuItemChecked(mi_showsummary, 1);
			optbox->Show();
		}
	} else if (mi == mi_showstatus) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSTATUS");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWSTATUS", "false", 1);
			menu->SetMenuItemChecked(mi_showstatus, 0);
			statustext->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWSTATUS", "true", 1);
			menu->SetMenuItemChecked(mi_showstatus, 1);
			statustext->Show();
		}
	} else if (mi == mi_showgps) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWGPS");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWGPS", "false", 1);
			menu->SetMenuItemChecked(mi_showgps, 0);
			linebox->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWGPS", "true", 1);
			menu->SetMenuItemChecked(mi_showgps, 1);
			linebox->Show();
		}
	} else if (mi == mi_showpps) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWPPS");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWPPS", "false", 1);
			menu->SetMenuItemChecked(mi_showpps, 0);
			packetrate->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWPPS", "true", 1);
			menu->SetMenuItemChecked(mi_showpps, 1);
			packetrate->Show();
		}
	} else if (mi == mi_showsources) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSOURCE");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWSOURCE", "false", 1);
			menu->SetMenuItemChecked(mi_showsources, 0);
			sourceinfo->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWSOURCE", "true", 1);
			menu->SetMenuItemChecked(mi_showsources, 1);
			sourceinfo->Show();
		}
	} else if (mi == mi_shownetworks) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWNETLIST");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("MAIN_SHOWNETLIST", "false", 1);
			menu->SetMenuItemChecked(mi_shownetworks, 0);
			netlist->Hide();
		} else {
			kpinterface->prefs.SetOpt("MAIN_SHOWNETLIST", "true", 1);
			menu->SetMenuItemChecked(mi_shownetworks, 1);
			netlist->Show();
		}
	}

	if (mi == -1) {
		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSUMMARY");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_showsummary, 1);
			optbox->Show();
		} else {
			menu->SetMenuItemChecked(mi_showsummary, 0);
			optbox->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSTATUS");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_showstatus, 1);
			statustext->Show();
		} else {
			menu->SetMenuItemChecked(mi_showstatus, 0);
			statustext->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWPPS");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_showpps, 1);
			packetrate->Show();
		} else {
			menu->SetMenuItemChecked(mi_showpps, 0);
			packetrate->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWGPS");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_showgps, 1);
			linebox->Show();
		} else {
			menu->SetMenuItemChecked(mi_showgps, 0);
			linebox->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWSOURCE");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_showsources, 1);
			sourceinfo->Show();
		} else {
			menu->SetMenuItemChecked(mi_showsources, 0);
			sourceinfo->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("MAIN_SHOWNETLIST");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_shownetworks, 1);
			netlist->Show();
		} else {
			menu->SetMenuItemChecked(mi_shownetworks, 0);
			netlist->Hide();
		}
	}
}

int ConnectButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Connect_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_Connect_Panel::Kis_Connect_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	hostname = new Kis_Single_Input(globalreg, this);
	hostport = new Kis_Single_Input(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);

	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ConnectButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ConnectButtonCB, this);

	tab_pos = 0;

	active_component = hostname;
	hostname->Activate(0);

	SetTitle("Connect to Server");

	hostname->SetLabel("Host", LABEL_POS_LEFT);
	hostname->SetTextLen(120);
	hostname->SetCharFilter(FILTER_ALPHANUMSYM);
	hostname->SetText(kpinterface->prefs.FetchOpt("default_host"), -1, -1);

	hostport->SetLabel("Port", LABEL_POS_LEFT);
	hostport->SetTextLen(5);
	hostport->SetCharFilter(FILTER_NUM);
	hostport->SetText(kpinterface->prefs.FetchOpt("default_port"), -1, -1);

	okbutton->SetText("Connect");
	cancelbutton->SetText("Cancel");

	hostname->Show();
	hostport->Show();
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
	vbox->Pack_End(bbox, 1, 0);

	AddComponentVec(hostname, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(hostport, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	active_component = hostname;
	hostname->Activate(1);
}

Kis_Connect_Panel::~Kis_Connect_Panel() {
}

void Kis_Connect_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	vbox->SetPosition(1, 2, in_x - 2, in_y - 3);
}

void Kis_Connect_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	DrawComponentVec();

	wmove(win, 0, 0);
}

void Kis_Connect_Panel::ButtonAction(Kis_Panel_Component *component) {
	if (component == okbutton) {
		if (hostname->GetText() == "")  {
			kpinterface->RaiseAlert("No hostname",
									"No hostname was provided for creating a\n"
									"new client connect to a Kismet server.\n"
									"A valid host name or IP is required.\n");
			return;
		}

		if (hostport->GetText() == "")  {
			kpinterface->RaiseAlert("No port",
									"No port number was provided for creating a\n"
									"new client connect to a Kismet server.\n"
									"A valid port number is required.\n");
			return;
		}

		// Try to add a client
		string clitxt = "tcp://" + hostname->GetText() + ":" +
			hostport->GetText();

		if (kpinterface->AddNetClient(clitxt, 1) < 0) 
			kpinterface->RaiseAlert("Connect failed", 
									"Failed to create new client connection\n"
									"to a Kismet server.  Check the status\n"
									"pane for more information about what\n"
									"went wrong.\n");

		globalreg->panel_interface->KillPanel(this);
	} else if (component == cancelbutton) {
		// Cancel and close
		globalreg->panel_interface->KillPanel(this);
	}
}

int PromptButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Prompt_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_Prompt_Panel::Kis_Prompt_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	ftext = new Kis_Free_Text(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);

	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, PromptButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, PromptButtonCB, this);

	okbutton->SetText("OK");
	cancelbutton->SetText("Cancel");

	ftext->Show();
	okbutton->Show();
	cancelbutton->Show();

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(1);
	bbox->SetCenter(1);
	bbox->Show();

	bbox->Pack_End(cancelbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);

	vbox->Pack_End(ftext, 1, 0);
	vbox->Pack_End(bbox, 0, 0);

	AddComponentVec(ftext, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	main_component = vbox;

	auxptr = NULL;
	callback = NULL;

	SetDefaultButton(1);
}

void Kis_Prompt_Panel::SetDefaultButton(int in_ok) {
	if (in_ok) {
		okbutton->Activate(0);
		active_component = okbutton;
		tab_pos = 1;
	} else {
		cancelbutton->Activate(0);
		active_component = okbutton;
		tab_pos = 2;
	}
}

void Kis_Prompt_Panel::SetButtonText(string in_oktext, string in_notext) {
	if (in_oktext == "")
		okbutton->Hide();
	else if (in_notext == "")
		cancelbutton->Hide();
}

void Kis_Prompt_Panel::SetCallback(ksp_prompt_cb in_callback, void *in_auxptr) {
	auxptr = in_auxptr;
	callback = in_callback;
}

void Kis_Prompt_Panel::SetDisplayText(vector<string> in_text) {
	ftext->SetText(in_text);
}

Kis_Prompt_Panel::~Kis_Prompt_Panel() {
}

void Kis_Prompt_Panel::ButtonAction(Kis_Panel_Component *component) {
	if (component == okbutton) {
		if (callback != NULL)
			(*callback)(globalreg, 1, auxptr);

		kpinterface->KillPanel(this);
	} else if (component == cancelbutton) {
		if (callback != NULL)
			(*callback)(globalreg, 0, auxptr);

		kpinterface->KillPanel(this);
	}
}

int SpawnButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Spawn_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_Spawn_Panel::Kis_Spawn_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	options = new Kis_Single_Input(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);

	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpawnButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpawnButtonCB, this);

	tab_pos = 0;
	active_component = options;
	options->Activate(0);

	SetTitle("Start Kismet Server");

	options->SetLabel("Options", LABEL_POS_LEFT);
	options->SetTextLen(120);
	options->SetCharFilter(FILTER_ALPHANUMSYM);
	options->SetText(kpinterface->prefs.FetchOpt("default_server_options"), -1, -1);

	okbutton->SetText("Start");
	cancelbutton->SetText("Cancel");

	options->Show();
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

	vbox->Pack_End(options, 0, 0);
	vbox->Pack_End(bbox, 1, 0);

	AddComponentVec(options, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	main_component = vbox;
}

Kis_Spawn_Panel::~Kis_Spawn_Panel() {
}

void Kis_Spawn_Panel::ButtonAction(Kis_Panel_Component *component) {
	if (component == okbutton) {
		kpinterface->SpawnServer(options->GetText());
		kpinterface->KillPanel(this);

		Kis_Console_Panel *cp = new Kis_Console_Panel(globalreg, kpinterface);
		cp->Position(WIN_CENTER(LINES, COLS));
		kpinterface->AddPanel(cp);
	} else if (component == cancelbutton) {
		// Cancel and close
		kpinterface->KillPanel(this);
	}
}

int ConsoleButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Console_Panel *) aux)->ButtonAction(component);
	return 1;
}

void ConsoleTextCB(TEXTCLI_PARMS) {
	((Kis_Console_Panel *) auxptr)->AddConsoleText(text);
}

Kis_Console_Panel::Kis_Console_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	constext = new Kis_Free_Text(globalreg, this);
	killbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);

	killbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ConsoleButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ConsoleButtonCB, this);

	tab_pos = 0;

	active_component = constext; 
	constext->Activate(0);

	SetTitle("Kismet Server Console");

	// Import the existing console
	constext->SetFollowTail(1);
	constext->SetMaxText(50);
	if (kpinterface->FetchServerFramework() == NULL)  {
		constext->SetText("Kismet server not started (or not started via this client)");
		textcb = -1;
	} else {
		constext->SetText(*(kpinterface->FetchServerConsole()));
		textcb = 
			kpinterface->FetchServerFramework()->RegisterCallback(ConsoleTextCB, this);
	}

	okbutton->SetText("Close Console Window");
	killbutton->SetText("Kill Server");

	constext->Show();
	okbutton->Show();
	killbutton->Show();

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

	bbox->Pack_End(killbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);

	vbox->Pack_End(constext, 1, 0);
	vbox->Pack_End(bbox, 0, 0);

	AddComponentVec(constext, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(killbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
}

Kis_Console_Panel::~Kis_Console_Panel() {
	if (kpinterface->FetchServerFramework() != NULL)  {
		kpinterface->FetchServerFramework()->RemoveCallback(textcb);
	}
}

void Kis_Console_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	vbox->SetPosition(1, 2, in_x - 2, in_y - 3);
}

void Kis_Console_Panel::ButtonAction(Kis_Panel_Component *component) {
	if (component == okbutton) {
		kpinterface->KillPanel(this);
	}
}

void Kis_Console_Panel::AddConsoleText(string in_text) {
	constext->AppendText(in_text);
}

int ModalAckCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ModalAlert_Panel *) aux)->AckAction();

	return 1;
}

Kis_ModalAlert_Panel::Kis_ModalAlert_Panel(GlobalRegistry *in_globalreg, 
										   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	tab_pos = 0;

	ftxt = new Kis_Free_Text(globalreg, this);
	ackbutton = new Kis_Button(globalreg, this);

	AddComponentVec(ftxt, KIS_PANEL_COMP_DRAW);
	AddComponentVec(ackbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								KIS_PANEL_COMP_EVT));

	active_component = ackbutton;
	ackbutton->Activate(0);

	SetTitle("");

	ackbutton->SetText("OK");

	ackbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ModalAckCB, this);
}

Kis_ModalAlert_Panel::~Kis_ModalAlert_Panel() {
}

void Kis_ModalAlert_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	ftxt->SetPosition(1, 1, in_x - 2, in_y - 3);
	ackbutton->SetPosition((in_x / 2) - 7, in_y - 2, (in_x / 2) + 7, in_y - 1);

	ackbutton->Activate(1);
	active_component = ackbutton;

	ftxt->Show();
	ackbutton->Show();
}

void Kis_ModalAlert_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	DrawComponentVec();

	wmove(win, 0, 0);
}

void Kis_ModalAlert_Panel::AckAction() {
	// We're done
	globalreg->panel_interface->KillPanel(this);
}

void Kis_ModalAlert_Panel::ConfigureAlert(string in_title, string in_text) {
	SetTitle(in_title);
	ftxt->SetText(in_text);
}

Kis_ServerList_Picker::Kis_ServerList_Picker(GlobalRegistry *in_globalreg, 
											 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	// Grab the pointer to the list of clients maintained
	netcliref = kpinterface->FetchNetClientVecPtr();

	srvlist = new Kis_Scrollable_Table(globalreg, this);

	AddComponentVec(srvlist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));

	// TODO -- Add name parsing to KISMET proto in netclient, add support here
	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 16;
	t.title = "Host";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 5;
	t.title = "Port";
	t.alignment = 2;
	titles.push_back(t);
	t.width = 4;
	t.title = "Cntd";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 3;
	t.title = "Rdy";
	t.alignment = 0;
	titles.push_back(t);
	srvlist->AddTitles(titles);

	// Population is done during draw

	active_component = srvlist;
	srvlist->Activate(1);

	SetTitle("");

	cb_hook = NULL;
	cb_aux = NULL;
}

Kis_ServerList_Picker::~Kis_ServerList_Picker() {
}

void Kis_ServerList_Picker::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	srvlist->SetPosition(1, 1, in_x - 2, in_y - 2);

	srvlist->Show();
}

void Kis_ServerList_Picker::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	wattrset(win, text_color);

	DrawTitleBorder();

	// Grab the list of servers and populate with it.  We'll assume that the number
	// of servers, and their order, cannot change while we're in the picker, since
	// the user can't get at it.  We WILL have to handle updating the connection
	// status based on the position key.  This is NOT A SAFE ASSUMPTION for any other
	// of the picker types (like cards), so don't blind-copy this code later.
	vector<string> td;
	ostringstream osstr;
	for (unsigned int x = 0; x < netcliref->size(); x++) {
		td.clear();

		td.push_back((*netcliref)[x]->FetchHost());

		osstr << (*netcliref)[x]->FetchPort();
		td.push_back(osstr.str());
		osstr.str("");

		if ((*netcliref)[x]->Valid()) {
			td.push_back("Yes");
			if ((*netcliref)[x]->FetchConfigured() < 0)
				td.push_back("Tes");
			else
				td.push_back("No");
		} else {
			td.push_back("No");
			td.push_back("No");
		}

		srvlist->ReplaceRow(x, td);
	}

	DrawComponentVec();

	wmove(win, 0, 0);
}

int Kis_ServerList_Picker::KeyPress(int in_key) {
	int ret;
	int listkey;
	
	// Rotate through the tabbed items
	if (in_key == '\n' || in_key == '\r') {
		listkey = srvlist->GetSelected();

		// Sanity check, even though nothing should be able to change this
		// while we're open since we claim the input.
		// We could raise an alert but theres nothing the user could do 
		// about it so we'll just silently close the window
		if (listkey >= 0 && listkey < (int) netcliref->size()) {
			(*cb_hook)(globalreg, kpinterface, (*netcliref)[listkey], cb_aux);
		}

		globalreg->panel_interface->KillPanel(this);
	}

	// Otherwise the menu didn't touch the key, so pass it to the top
	// component
	if (active_component != NULL) {
		ret = active_component->KeyPress(in_key);
	}

	return 0;
}

void Kis_ServerList_Picker::ConfigurePicker(string in_title, kpi_sl_cb_hook in_hook,
											void *in_aux) {
	SetTitle(in_title);
	cb_hook = in_hook;
	cb_aux = in_aux;
}

// Addcard callback is used to actually build the addcard window once
// we've picked a source.  This will be called directly from the main
// menu handlers if there aren't any sources.
void sp_addcard_cb(KPI_SL_CB_PARMS) {
	Kis_AddCard_Panel *acp = new Kis_AddCard_Panel(globalreg, kpi);

	acp->Position((LINES / 2) - 5, (COLS / 2) - (40 / 2), 10, 40);

	acp->SetTargetClient(picked);

	kpi->AddPanel(acp);
}

int AddCardButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_AddCard_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_AddCard_Panel::Kis_AddCard_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	srcopts = new Kis_Single_Input(globalreg, this);
	srciface = new Kis_Single_Input(globalreg, this);
	srcname = new Kis_Single_Input(globalreg, this);

	okbutton = new Kis_Button(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);

	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AddCardButtonCB, this);
	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AddCardButtonCB, this);

	AddComponentVec(srciface, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	AddComponentVec(srcname, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));
	AddComponentVec(srcopts, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));

	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));

	tab_pos = 0;

	SetTitle("Add Source");

	srciface->SetLabel("Intf", LABEL_POS_LEFT);
	srciface->SetTextLen(32);
	srciface->SetCharFilter(FILTER_ALPHANUMSYM);
	srciface->Show();
		
	active_component = srciface;
	srciface->Activate(0);

	srcname->SetLabel("Name", LABEL_POS_LEFT);
	srcname->SetTextLen(32);
	srcname->SetCharFilter(FILTER_ALPHANUMSYM);
	srcname->Show();

	srcopts->SetLabel("Opts", LABEL_POS_LEFT);
	srcopts->SetTextLen(64);
	srcopts->SetCharFilter(FILTER_ALPHANUMSYM);
	srcopts->Show();

	okbutton->SetText("Add");
	okbutton->Show();
	cancelbutton->SetText("Cancel");
	cancelbutton->Show();

	target_cli = NULL;

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

	vbox->Pack_End(srciface, 0, 0);
	vbox->Pack_End(srcname, 0, 0);
	vbox->Pack_End(srcopts, 0, 0);
	vbox->Pack_End(bbox, 1, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
}

Kis_AddCard_Panel::~Kis_AddCard_Panel() {
}

void Kis_AddCard_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);
	vbox->SetPosition(1, 2, in_x - 1, in_y - 2);
}

void Kis_AddCard_Panel::SetTargetClient(KisNetClient *in_cli) {
	target_cli = in_cli;

	ostringstream osstr;
	osstr << "Add Source to " << in_cli->FetchHost() << ":" << in_cli->FetchPort();

	SetTitle(osstr.str());
}

void Kis_AddCard_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	wattrset(win, text_color);

	DrawTitleBorder();

	DrawComponentVec();

	wmove(win, 0, 0);
}

void Kis_AddCard_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		string srcdef;

		if (srciface->GetText() == "") {
			kpinterface->RaiseAlert("No source interface",
									"No source interface was provided for\n"
									"creating a new source.  A source\n"
									"interface is required.\n");
			return;
		}

		srcdef = srciface->GetText() + ":";

		if (srcname->GetText() != "") {
			srcdef += "name=" + srcname->GetText() + ",";
		}

		if (srcopts->GetText() != "") {
			srcdef += srcopts->GetText();
		}

		if (target_cli == NULL) {
			globalreg->panel_interface->KillPanel(this);
			return;
		}

		if (target_cli->Valid() == 0) {
			kpinterface->RaiseAlert("Server unavailable",
									"The selected server is not available.\n");
			return;
		}

		// Build a command and inject it
		string srccmd;
		srccmd = "ADDSOURCE " + srcdef;

		target_cli->InjectCommand(srccmd);

		globalreg->panel_interface->KillPanel(this);
	} else if (in_button == cancelbutton) {
		// Cancel and close
		globalreg->panel_interface->KillPanel(this);
	}

	return; 
}

int PluginPickerButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Plugin_Picker *) aux)->ButtonAction(component);
	return 1;
}

Kis_Plugin_Picker::Kis_Plugin_Picker(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	pluglist = new Kis_Scrollable_Table(globalreg, this);

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 40;
	t.title = "Plugin";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 9;
	t.title = "Auto Load";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 7;
	t.title = "Loaded";
	t.alignment = 0;
	titles.push_back(t);
	pluglist->AddTitles(titles);
	pluglist->SetCallback(COMPONENT_CBTYPE_ACTIVATED, PluginPickerButtonCB, this);
	pluglist->Show();
	AddComponentVec(pluglist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));


	okbutton = new Kis_Button(globalreg, this);
	okbutton->SetText("Close");
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, PluginPickerButtonCB, this);
	okbutton->Show();
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));

	helptext = new Kis_Free_Text(globalreg, this);
	helptext->Show();
	vector<string> ht;
	ht.push_back("Select plugins to load at startup");
	ht.push_back("To unload a plugin, disable auto-loading for that plugin");
	ht.push_back("and restart the client (quit and run it again)");
	helptext->SetText(ht);
	AddComponentVec(helptext, (KIS_PANEL_COMP_DRAW));

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->SetCenter(0);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	vbox->Pack_End(pluglist, 1, 0);
	vbox->Pack_End(helptext, 0, 0);
	vbox->Pack_End(okbutton, 0, 0);
	vbox->Show();

	plugins = kpinterface->FetchPluginVec();

	for (unsigned int x = 0; x < plugins->size(); x++) {
		vector<string> td;
		vector<string> prefs = kpinterface->prefs.FetchOptVec("plugin_autoload");
		string en = "";

		td.push_back((*plugins)[x]->objectname);
		td.push_back("no");

		// Figure out if we're going to autoload it
		for (unsigned int p = 0; p < prefs.size(); p++) {
			if (prefs[p] == (*plugins)[x]->objectname) {
				td[1] = "yes";
				break;
			}
		}
		
		if ((*plugins)[x]->dlfileptr == (void *) 0x0)
			td.push_back("no");
		else
			td.push_back("yes");

		pluglist->ReplaceRow(x, td);
	}

	if (plugins->size() == 0) {
		vector<string> td;
		td.push_back("No plugins found");
		td.push_back("");
		td.push_back("");
		pluglist->ReplaceRow(0, td);
	}

	tab_pos = 0;
	active_component = pluglist;
	pluglist->Activate(1);

	SetTitle("");
}

Kis_Plugin_Picker::~Kis_Plugin_Picker() {
}

void Kis_Plugin_Picker::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	vbox->SetPosition(1, 1, in_x - 1, in_y - 2);
}

void Kis_Plugin_Picker::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	DrawComponentVec();

	wmove(win, 0, 0);
}

void Kis_Plugin_Picker::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		vector<string> ldata;
		vector<string> autoload;

		for (unsigned int x = 0; x < plugins->size(); x++) {
			ldata = pluglist->GetRow(x);
			
			if (ldata.size() < 3)
				continue;

			if (ldata[1] == "yes" && (*plugins)[x]->dlfileptr == 0x0) {
				kpinterface->LoadPlugin((*plugins)[x]->filename,
										(*plugins)[x]->objectname);

				autoload.push_back((*plugins)[x]->objectname);
			}
		}

		kpinterface->prefs.SetOptVec("plugin_autoload", autoload, 1);

		globalreg->panel_interface->KillPanel(this);

		return;
	} else if (in_button == pluglist) {
		int listkey = pluglist->GetSelected();

		if (listkey >= 0 && listkey < (int) plugins->size()) {
			vector<string> listdata = pluglist->GetSelectedData();

			if (listdata[1] == "yes") {
				listdata[1] = "no";
				if (listdata[2] != "yes")
					listdata[2] = "no";
			} else {
				listdata[1] = "yes";
				if (listdata[2] != "yes")
					listdata[2] = "Pending";
			}

			pluglist->ReplaceRow(listkey, listdata);
		}
	}
}

int NetDetailsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_NetDetails_Panel *) aux)->ButtonAction(component);
	return 1;
}

int NetDetailsMenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_NetDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

int NetDetailsGraphEvent(TIMEEVENT_PARMS) {
	return ((Kis_NetDetails_Panel *) parm)->GraphTimer();
}

Kis_NetDetails_Panel::Kis_NetDetails_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	grapheventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &NetDetailsGraphEvent, (void *) this);

	menu = new Kis_Menu(globalreg, this);

	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetDetailsMenuCB, this);

	mn_network = menu->AddMenu("Network", 0);
	mi_nextnet = menu->AddMenuItem("Next network", mn_network, 'n');
	mi_prevnet = menu->AddMenuItem("Prev network", mn_network, 'p');
	menu->AddMenuItem("-", mn_network, 0);
	mi_close = menu->AddMenuItem("Close window", mn_network, 'w');

	mn_view = menu->AddMenu("View", 0);
	mi_net = menu->AddMenuItem("Network Details", mn_view, 'n');
	mi_clients = menu->AddMenuItem("Clients", mn_view, 'c');
	menu->AddMenuItem("-", mn_view, 0);
	mi_graphsig = menu->AddMenuItem("Signal Level", mn_view, 's');
	mi_graphpacket = menu->AddMenuItem("Packet Rate", mn_view, 'p');
	mi_graphretry = menu->AddMenuItem("Retry Rate", mn_view, 'r');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	// Details scroll list doesn't get the current one highlighted and
	// doesn't draw titles, also lock to fit inside the window
	netdetails = new Kis_Scrollable_Table(globalreg, this);
	netdetails->SetHighlightSelected(0);
	netdetails->SetLockScrollTop(1);
	netdetails->SetDrawTitles(0);
	AddComponentVec(netdetails, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								 KIS_PANEL_COMP_TAB));

	// We need to populate the titles even if we don't use them so that
	// the row handler knows how to draw them
	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 12;
	t.title = "field";
	t.alignment = 2;
	titles.push_back(t);
	t.width = 0;
	t.title = "value";
	t.alignment = 0;
	titles.push_back(t);

	netdetails->AddTitles(titles);

	active_component = netdetails;
	netdetails->Show();
	netdetails->Activate(1);

	siggraph = new Kis_IntGraph(globalreg, this);
	siggraph->SetName("DETAIL_SIG");
	siggraph->SetPreferredSize(0, 8);
	siggraph->SetScale(-110, -40);
	siggraph->SetInterpolation(1);
	siggraph->SetMode(0);
	siggraph->Show();
	siggraph->AddExtDataVec("Signal", 4, "graph_detail_sig", "yellow,yellow", 
		 					  ' ', ' ', 1, &sigpoints);
	AddComponentVec(siggraph, KIS_PANEL_COMP_EVT);

	packetgraph = new Kis_IntGraph(globalreg, this);
	packetgraph->SetName("DETAIL_PPS");
	packetgraph->SetPreferredSize(0, 8);
	packetgraph->SetScale(0, 0);
	packetgraph->SetInterpolation(1);
	packetgraph->SetMode(0);
	packetgraph->Show();
	packetgraph->AddExtDataVec("Packet Rate", 4, "graph_detail_pps", "green,green", 
							  ' ', ' ', 1, &packetpps);
	AddComponentVec(packetgraph, KIS_PANEL_COMP_EVT);

	retrygraph = new Kis_IntGraph(globalreg, this);
	retrygraph->SetName("DETAIL_RETRY_PPS");
	retrygraph->SetPreferredSize(0, 8);
	retrygraph->SetScale(0, 0);
	retrygraph->SetInterpolation(1);
	retrygraph->SetMode(0);
	retrygraph->Show();
	retrygraph->AddExtDataVec("Retry Rate", 4, "graph_detail_retrypps", "red,red", 
							  ' ', ' ', 1, &retrypps);
	AddComponentVec(retrygraph, KIS_PANEL_COMP_EVT);

	ClearGraphVectors();

	/*
	closebutton = new Kis_Button(globalreg, this);
	closebutton->SetText("Close");
	closebutton->Show();
	closebutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetDetailsButtonCB, this);

	nextbutton = new Kis_Button(globalreg, this);
	nextbutton->SetText("Next");
	nextbutton->Show();
	nextbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetDetailsButtonCB, this);

	prevbutton = new Kis_Button(globalreg, this);
	prevbutton->SetText("Prev");
	prevbutton->Show();
	prevbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetDetailsButtonCB, this);

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(1);
	bbox->SetCenter(1);
	bbox->Show();

	bbox->Pack_End(closebutton, 0, 0);
	bbox->Pack_End(prevbutton, 0, 0);
	bbox->Pack_End(nextbutton, 0, 0);
	*/

	SetTitle("");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	vbox->Pack_End(siggraph, 0, 0);
	vbox->Pack_End(packetgraph, 0, 0);
	vbox->Pack_End(retrygraph, 0, 0);

	vbox->Pack_End(netdetails, 1, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	/*
	vbox->Pack_End(bbox, 0, 0);

	AddComponentVec(closebutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								  KIS_PANEL_COMP_EVT));
	AddComponentVec(prevbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								  KIS_PANEL_COMP_EVT));
	AddComponentVec(nextbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_TAB |
								  KIS_PANEL_COMP_EVT));
	*/

	tab_pos = 0;

	last_dirty = 0;
	last_mac = mac_addr(0);
	dng = NULL;

	vector<string> td;
	td.push_back("");
	td.push_back("No network selected / Empty network selected");
	netdetails->AddRow(0, td);

	UpdateViewMenu(-1);
}

Kis_NetDetails_Panel::~Kis_NetDetails_Panel() {
	if (grapheventid >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(grapheventid);
}

void Kis_NetDetails_Panel::ClearGraphVectors() {
	lastpackets = 0;
	sigpoints.clear();
	packetpps.clear();
	retrypps.clear();
	for (unsigned int x = 0; x < 120; x++) {
		sigpoints.push_back(-256);
		packetpps.push_back(0);
		retrypps.push_back(0);
	}
}

void Kis_NetDetails_Panel::UpdateGraphVectors(int signal, int pps, int retry) {
	sigpoints.push_back(signal);
	if (sigpoints.size() > 120)
		sigpoints.erase(sigpoints.begin(), sigpoints.begin() + sigpoints.size() - 120);

	if (lastpackets == 0)
		lastpackets = pps;
	packetpps.push_back(pps - lastpackets);
	lastpackets = pps;
	if (packetpps.size() > 120)
		packetpps.erase(packetpps.begin(), packetpps.begin() + packetpps.size() - 120);

	retrypps.push_back(retry);
	if (retrypps.size() > 120)
		retrypps.erase(retrypps.begin(), retrypps.begin() + retrypps.size() - 120);
}

void Kis_NetDetails_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	menu->SetPosition(1, 0, 0, 0);

	// All we have to do is position the main box now
	vbox->SetPosition(1, 1, in_x - 1, in_y - 2);
}

int Kis_NetDetails_Panel::AppendNetworkInfo(int k, Kis_Display_NetGroup *tng,
											Netracker::tracked_network *net) {
	vector<string> td;
	ostringstream osstr;

	td.push_back("");
	td.push_back("");

	td[0] = "Name:";
	td[1] = tng->GetName(net);
	netdetails->AddRow(k++, td);

	td[0] = "# Networks:";
	osstr.str("");
	osstr << tng->FetchNetworkVec()->size();
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	// Use the display metanet if we haven't been given one
	if (net == NULL)
		net = dng->FetchNetwork();

	// Catch nulls just incase
	if (net == NULL)
		return k;

	td[0] = "BSSID:";
	td[1] = net->bssid.Mac2String();
	netdetails->AddRow(k++, td);

	td[0] = "First Seen:";
	osstr.str("");
	osstr << setw(14) << left << 
		(string(ctime((const time_t *) &(net->first_time)) + 4).substr(0, 15));
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Last Seen:";
	osstr.str("");
	osstr << setw(14) << left << 
		(string(ctime((const time_t *) &(net->last_time)) + 4).substr(0, 15));
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Type:";
	if (net->type == network_ap)
		td[1] = "Access Point (Managed/Infrastructure)";
	else if (net->type == network_probe)
		td[1] = "Probe (Client)";
	else if (net->type == network_turbocell)
		td[1] = "Turbocell";
	else if (net->type == network_data)
		td[1] = "Data Only (No management)";
	else if (net->type == network_mixed)
		td[1] = "Mixed (Multiple network types in group)";
	else
		td[1] = "Unknown";
	netdetails->AddRow(k++, td);

	td[0] = "Channel:";
	osstr.str("");
	if (net->channel != 0)
		osstr << net->channel;
	else
		osstr << "No channel identifying information seen";
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	for (map<unsigned int, unsigned int>::const_iterator fmi = 
		 net->freq_mhz_map.begin(); fmi != net->freq_mhz_map.end(); ++fmi) {
		float perc = ((float) fmi->second / 
					  (float) (net->llc_packets + net->data_packets)) * 100;

		int ch = FreqToChan(fmi->first);
		ostringstream chtxt;
		if (ch != 0)
			chtxt << ch;
		else
			chtxt << "Unk";


		td[0] = "Frequency:";
		osstr.str("");
		osstr << fmi->first << " (" << chtxt.str() << ") - " << 
			fmi->second << " packets, " <<
			setprecision(2) << perc << "%";
		td[1] = osstr.str();
		netdetails->AddRow(k++, td);
	}

	if (net->lastssid != NULL) {
		td[0] = "Last ssid:";
		td[1] = net->lastssid->ssid;
		netdetails->AddRow(k++, td);

		td[0] = "Encryption:";
		td[1] = "";
		if (net->lastssid->cryptset == 0)
			td[1] = "None (Open)";
		if (net->lastssid->cryptset == crypt_wep)
			td[1] = "WEP (Privacy bit set)";
		if (net->lastssid->cryptset & crypt_layer3)
			td[1] += " Layer3";
		if (net->lastssid->cryptset & crypt_wep40)
			td[1] += " WEP40";
		if (net->lastssid->cryptset & crypt_wep104)
			td[1] += " WEP104";
		if (net->lastssid->cryptset & crypt_wpa)
			td[1] += " WPA";
		if (net->lastssid->cryptset & crypt_tkip)
			td[1] += " TKIP";
		if (net->lastssid->cryptset & crypt_psk)
			td[1] += " PSK";
		if (net->lastssid->cryptset & crypt_aes_ocb)
			td[1] += " AES-OCB";
		if (net->lastssid->cryptset & crypt_aes_ccm)
			td[1] += " AES-CCM";
		if (net->lastssid->cryptset & crypt_leap)
			td[1] += " LEAP";
		if (net->lastssid->cryptset & crypt_ttls)
			td[1] += " TTLS";
		if (net->lastssid->cryptset & crypt_tls)
			td[1] += " TLS";
		if (net->lastssid->cryptset & crypt_peap)
			td[1] += " PEAP";
		if (net->lastssid->cryptset & crypt_isakmp)
			td[1] += " ISA-KMP";
		if (net->lastssid->cryptset & crypt_pptp)
			td[1] += " PPTP";
		if (net->lastssid->cryptset & crypt_fortress)
			td[1] += " Fortress";
		if (net->lastssid->cryptset & crypt_keyguard)
			td[1] += " Keyguard";
		netdetails->AddRow(k++, td);

		td[0] = "Beacon %:";
		if (net->lastssid->beacons > net->lastssid->beaconrate)
			net->lastssid->beacons = net->lastssid->beaconrate;
		osstr.str("");
		osstr << setw(4) << left << 
			(int) (((double) net->lastssid->beacons /
					(double) net->lastssid->beaconrate) * 100);
		td[1] = osstr.str();
		netdetails->AddRow(k++, td);

	} else {
		td[0] = "Encryption:";
		td[1] = "No info available";
		netdetails->AddRow(k++, td);
	}

	if (net->snrdata.last_signal_dbm == -256 || net->snrdata.last_signal_dbm == 0) {
		if (net->snrdata.last_signal_rssi == 0) {
			td[0] = "Signal:";
			td[1] = "No signal data available";
			netdetails->AddRow(k++, td);
		} else {
			td[0] = "Sig RSSI:";
			osstr.str("");
			osstr << net->snrdata.last_signal_rssi << " (max " <<
				net->snrdata.max_signal_rssi << ")";
			td[1] = osstr.str();
			netdetails->AddRow(k++, td);

			td[0] = "Noise RSSI:";
			osstr.str("");
			osstr << net->snrdata.last_noise_rssi << " (max " <<
				net->snrdata.max_noise_rssi << ")";
			td[1] = osstr.str();
			netdetails->AddRow(k++, td);
		}
	} else {
		td[0] = "Sig dBm";
		osstr.str("");
		osstr << net->snrdata.last_signal_dbm << " (max " <<
			net->snrdata.max_signal_dbm << ")";
		td[1] = osstr.str();
		netdetails->AddRow(k++, td);

		td[0] = "Noise dBm";
		osstr.str("");
		osstr << net->snrdata.last_noise_dbm << " (max " <<
			net->snrdata.max_noise_dbm << ")";
		td[1] = osstr.str();
		netdetails->AddRow(k++, td);
	}

	td[0] = "Packets:";
	osstr.str("");
	osstr << net->llc_packets + net->data_packets;
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Data Pkts:";
	osstr.str("");
	osstr << net->data_packets;
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Mgmt Pkts:";
	osstr.str("");
	osstr << net->llc_packets;
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Crypt Pkts:";
	osstr.str("");
	osstr << net->crypt_packets;
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Fragments:";
	osstr.str("");
	osstr << net->fragments << "/sec";
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Retries:";
	osstr.str("");
	osstr << net->retries << "/sec";
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	td[0] = "Bytes:";
	osstr.str("");
	if (net->datasize < 1024) 
		osstr << net->datasize << "B";
	else if (net->datasize < (1024 * 1024)) 
		osstr << (int) (net->datasize / 1024) << "K";
	else 
		osstr << (int) (net->datasize / 1024 / 1024) << "M";
	td[1] = osstr.str();
	netdetails->AddRow(k++, td);

	if (net->cdp_dev_id.length() > 0) {
		td[0] = "CDP Device:";
		td[1] = net->cdp_dev_id;
		netdetails->AddRow(k++, td);

		td[0] = "CDP Port:";
		td[1] = net->cdp_port_id;
		netdetails->AddRow(k++, td);
	}

	return k;
}

int Kis_NetDetails_Panel::GraphTimer() {
	Kis_Display_NetGroup *tng, *ldng;
	Netracker::tracked_network *meta, *tmeta;
	int update = 0;

	if (kpinterface == NULL)
		return 1;

	ldng = dng;

	tng = kpinterface->FetchMainPanel()->FetchSelectedNetgroup();
	if (tng != NULL) {
		if (ldng == NULL) {
			ldng = tng;
			update = 1;
		} else {
			meta = ldng->FetchNetwork();
			tmeta = tng->FetchNetwork();

			if (meta == NULL && tmeta != NULL) {
				ldng = tng;
				update = 1;
			} else if (tmeta != NULL && last_mac != tmeta->bssid) {
				ClearGraphVectors();
				return 1;
			} else if (meta != NULL && last_dirty < meta->last_time) {
				update = 1;
			}
		}
	} else if (ldng != NULL) {
		ClearGraphVectors();
	}

	if (update && ldng != NULL) {
		meta = ldng->FetchNetwork();

		UpdateGraphVectors(meta->snrdata.last_signal_dbm == -256 ? 
						   meta->snrdata.last_signal_rssi : 
						   meta->snrdata.last_signal_dbm, 
						   meta->llc_packets + meta->data_packets,
						   meta->retries);
	}

	return 1;
}

void Kis_NetDetails_Panel::DrawPanel() {
	Kis_Display_NetGroup *tng;
	Netracker::tracked_network *meta, *tmeta;
	int update = 0;
	vector<string> td;

	int k = 0;

	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	// Figure out if we've changed
	tng = kpinterface->FetchMainPanel()->FetchSelectedNetgroup();
	if (tng != NULL) {
		if (dng == NULL) {
			dng = tng;
			update = 1;
		} else {
			meta = dng->FetchNetwork();
			tmeta = tng->FetchNetwork();

			if (meta == NULL && tmeta != NULL) {
				// We didn't have a valid metagroup before - we get the new one
				dng = tng;
				update = 1;
			} else if (tmeta != NULL && last_mac != tmeta->bssid) {
				// We weren't the same network before - we get the new one, clear the
				// graph vectors
				dng = tng;
				ClearGraphVectors();
				update = 1;
			} else if (meta != NULL && last_dirty < meta->last_time) {
				// The network has changed time - just update
				update = 1;
			}
		}
	} else if (dng != NULL) {
		// We've lost a selected network entirely, drop to null and update, clear the
		// graph vectors
		dng = NULL;
		ClearGraphVectors();
		update = 1;
	}

	if (update) {
		netdetails->Clear();

		if (dng != NULL)
			meta = dng->FetchNetwork();
		else
			meta = NULL;

		k = 0;
		td.push_back("");
		td.push_back("");

		if (dng != NULL) {
			td[0] = "";
			td[1] = "Group";
			netdetails->AddRow(k++, td);

			k = AppendNetworkInfo(k, tng, NULL);
		} else {
			td[0] = "";
			td[1] = "No network selected / Empty group selected";
			netdetails->AddRow(0, td);
		}
	}

	DrawComponentVec();

	wmove(win, 0, 0);
}

void Kis_NetDetails_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == closebutton) {
		globalreg->panel_interface->KillPanel(this);
	} else if (in_button == nextbutton) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_DOWN);
		dng = NULL;
	} else if (in_button == prevbutton) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_UP);
		dng = NULL;
	}
}

void Kis_NetDetails_Panel::MenuAction(int opt) {
	// Menu processed an event, do something with it
	if (opt == mi_close) {
		globalreg->panel_interface->KillPanel(this);
		return;
	} else if (opt == mi_nextnet) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_DOWN);
		dng = NULL;
		return;
	} else if (opt == mi_prevnet) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_UP);
		dng = NULL;
		return;
	} else if (opt == mi_net || opt == mi_clients ||
			   opt == mi_graphsig || opt == mi_graphpacket ||
			   opt == mi_graphretry) {
		UpdateViewMenu(opt);
	}
}

void Kis_NetDetails_Panel::UpdateViewMenu(int mi) {
	string opt;

	if (mi == mi_net) {
		opt = kpinterface->prefs.FetchOpt("DETAILS_SHOWNET");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("DETAILS_SHOWNET", "false", 1);
			menu->SetMenuItemChecked(mi_net, 0);
			netdetails->Hide();
		} else {
			kpinterface->prefs.SetOpt("DETAILS_SHOWNET", "true", 1);
			menu->SetMenuItemChecked(mi_net, 1);
			netdetails->Show();
		}
	} else if (mi == mi_graphsig) {
		opt = kpinterface->prefs.FetchOpt("DETAILS_SHOWGRAPHSIG");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("DETAILS_SHOWGRAPHSIG", "false", 1);
			menu->SetMenuItemChecked(mi_graphsig, 0);
			siggraph->Hide();
		} else {
			kpinterface->prefs.SetOpt("DETAILS_SHOWGRAPHSIG", "true", 1);
			menu->SetMenuItemChecked(mi_graphsig, 1);
			siggraph->Show();
		}
	} else if (mi == mi_graphpacket) {
		opt = kpinterface->prefs.FetchOpt("DETAILS_SHOWGRAPHPACKET");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("DETAILS_SHOWGRAPHPACKET", "false", 1);
			menu->SetMenuItemChecked(mi_graphpacket, 0);
			packetgraph->Hide();
		} else {
			kpinterface->prefs.SetOpt("DETAILS_SHOWGRAPHPACKET", "true", 1);
			menu->SetMenuItemChecked(mi_graphpacket, 1);
			packetgraph->Show();
		}
	} else if (mi == mi_graphretry) {
		opt = kpinterface->prefs.FetchOpt("DETAILS_SHOWGRAPHRETRY");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("DETAILS_SHOWGRAPHRETRY", "false", 1);
			menu->SetMenuItemChecked(mi_graphretry, 0);
			retrygraph->Hide();
		} else {
			kpinterface->prefs.SetOpt("DETAILS_SHOWGRAPHRETRY", "true", 1);
			menu->SetMenuItemChecked(mi_graphretry, 1);
			retrygraph->Show();
		}
	} else if (mi == -1) {
		opt = kpinterface->prefs.FetchOpt("DETAILS_SHOWNET");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_net, 1);
			netdetails->Show();
		} else {
			menu->SetMenuItemChecked(mi_net, 0);
			netdetails->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("DETAILS_SHOWGRAPHSIG");
		if (opt == "true") {
			menu->SetMenuItemChecked(mi_graphsig, 1);
			siggraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphsig, 0);
			siggraph->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("DETAILS_SHOWGRAPHPACKET");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_graphpacket, 1);
			packetgraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphpacket, 0);
			packetgraph->Hide();
		}

		opt = kpinterface->prefs.FetchOpt("DETAILS_SHOWGRAPHRETRY");
		if (opt == "true") {
			menu->SetMenuItemChecked(mi_graphretry, 1);
			retrygraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphretry, 0);
			retrygraph->Hide();
		}
	}
}

int ChanDetailsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ChanDetails_Panel *) aux)->ButtonAction(component);
	return 1;
}

int ChanDetailsMenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ChanDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

int ChanDetailsGraphEvent(TIMEEVENT_PARMS) {
	((Kis_ChanDetails_Panel *) parm)->GraphTimer();

	return 1;
}

void ChanDetailsCliConfigured(CLICONF_CB_PARMS) {
	((Kis_ChanDetails_Panel *) auxptr)->NetClientConfigured(kcli, recon);
}

void ChanDetailsCliAdd(KPI_ADDCLI_CB_PARMS) {
	((Kis_ChanDetails_Panel *) auxptr)->NetClientAdd(netcli, add);
}

void ChanDetailsProtoCHANNEL(CLIPROTO_CB_PARMS) {
	((Kis_ChanDetails_Panel *) auxptr)->Proto_CHANNEL(globalreg, proto_string,
													  proto_parsed, srccli, auxptr);
}

Kis_ChanDetails_Panel::Kis_ChanDetails_Panel(GlobalRegistry *in_globalreg,
											 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	grapheventid =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &ChanDetailsGraphEvent, (void *) this);

	menu = new Kis_Menu(globalreg, this);

	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ChanDetailsMenuCB, this);

	mn_channels = menu->AddMenu("Channels", 0);
	mi_close = menu->AddMenuItem("Close window", mn_channels, 'w');

	mn_view = menu->AddMenu("View", 0);
	mi_chansummary = menu->AddMenuItem("Channel Summary", mn_view, 'c');
	menu->AddMenuItem("-", mn_view, 0);
	mi_signal = menu->AddMenuItem("Signal Level", mn_view, 's');
	mi_packets = menu->AddMenuItem("Packet Rate", mn_view, 'p');
	mi_traffic = menu->AddMenuItem("Data", mn_view, 'd');
	mi_networks = menu->AddMenuItem("Networks", mn_view, 'n');

	menu->Show();

	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	// Channel summary list gets titles but doesn't get the current one highlighted
	// and locks to fit inside the window
	chansummary = new Kis_Scrollable_Table(globalreg, this);
	chansummary->SetHighlightSelected(0);
	chansummary->SetLockScrollTop(1);
	chansummary->SetDrawTitles(1);
	AddComponentVec(chansummary, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								  KIS_PANEL_COMP_TAB));

	// Populate the titles
	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;

	t.width = 4;
	t.title = "Chan";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 7;
	t.title = "Packets";
	t.alignment = 2;
	titles.push_back(t);

	t.width = 3;
	t.title = "P/S";
	t.alignment = 2;
	titles.push_back(t);

	t.width = 5;
	t.title = "Data";
	t.alignment = 2;
	titles.push_back(t);

	t.width = 4;
	t.title = "Dt/s";
	t.alignment = 2;
	titles.push_back(t);

	t.width = 4;
	t.title = "Netw";
	t.alignment = 2;
	titles.push_back(t);

	t.width = 4;
	t.title = "ActN";
	t.alignment = 2;
	titles.push_back(t);

	t.width = 6;
	t.title = "Time";
	t.alignment = 2;
	titles.push_back(t);

	chansummary->AddTitles(titles);

	active_component = chansummary;
	chansummary->Show();
	chansummary->Activate(1);

	siggraph = new Kis_IntGraph(globalreg, this);
	siggraph->SetName("CHANNEL_SIG");
	siggraph->SetPreferredSize(0, 12);
	siggraph->SetScale(-110, -20);
	siggraph->SetInterpolation(0);
	siggraph->SetMode(0);
	siggraph->Show();
	siggraph->AddExtDataVec("Signal", 3, "channel_sig", "yellow,yellow",
							' ', ' ', 1, &sigvec);
	siggraph->AddExtDataVec("Noise", 4, "channel_noise", "green,green",
							' ', ' ', 1, &noisevec);
	// AddComponentVec(siggraph, KIS_PANEL_COMP_DRAW);

	packetgraph = new Kis_IntGraph(globalreg, this);
	packetgraph->SetName("CHANNEL_PPS");
	packetgraph->SetPreferredSize(0, 12);
	packetgraph->SetInterpolation(0);
	packetgraph->SetMode(0);
	packetgraph->Show();
	packetgraph->AddExtDataVec("Packet Rate", 4, "channel_pps", "green,green",
							   ' ', ' ', 1, &packvec);
	// AddComponentVec(packetgraph, KIS_PANEL_COMP_DRAW);

	bytegraph = new Kis_IntGraph(globalreg, this);
	bytegraph->SetName("CHANNEL_BPS");
	bytegraph->SetPreferredSize(0, 12);
	bytegraph->SetInterpolation(0);
	bytegraph->SetMode(0);
	bytegraph->Show();
	bytegraph->AddExtDataVec("Traffic", 4, "channel_bytes", "green,green",
							 ' ', ' ', 1, &bytevec);
	// AddComponentVec(bytegraph, KIS_PANEL_COMP_DRAW);

	netgraph = new Kis_IntGraph(globalreg, this);
	netgraph->SetName("CHANNEL_NETS");
	netgraph->SetPreferredSize(0, 12);
	netgraph->SetInterpolation(0);
	netgraph->SetMode(0);
	netgraph->Show();
	netgraph->AddExtDataVec("Networks", 3, "channel_nets", "yellow,yellow",
							' ', ' ', 1, &netvec);
	netgraph->AddExtDataVec("Active", 4, "channel_actnets", "green,green",
							' ', ' ', 1, &anetvec);
	// AddComponentVec(netgraph, KIS_PANEL_COMP_DRAW);

	SetTitle("");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	vbox->Pack_End(siggraph, 0, 0);
	vbox->Pack_End(packetgraph, 0, 0);
	vbox->Pack_End(bytegraph, 0, 0);
	vbox->Pack_End(netgraph, 0, 0);
	vbox->Pack_End(chansummary, 0, 0);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	tab_pos = 0;

	UpdateViewMenu(-1);
	GraphTimer();

	addref = kpinterface->Add_NetCli_AddCli_CB(ChanDetailsCliAdd, (void *) this);	
}

Kis_ChanDetails_Panel::~Kis_ChanDetails_Panel() {
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(ChanDetailsCliConfigured);
	kpinterface->Remove_AllNetcli_ProtoHandler("CHANNEL", ChanDetailsProtoCHANNEL, this);
	globalreg->timetracker->RemoveTimer(grapheventid);
}

void Kis_ChanDetails_Panel::NetClientConfigured(KisNetClient *in_cli, int in_recon) {
	if (in_recon)
		return;

	if (in_cli->RegisterProtoHandler("CHANNEL", KCLI_CHANDETAILS_CHANNEL_FIELDS,
									 ChanDetailsProtoCHANNEL, this) < 0) {
		_MSG("Could not register CHANNEL protocol with remote server, connection "
			 "will be terminated", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
}

void Kis_ChanDetails_Panel::NetClientAdd(KisNetClient *in_cli, int add) {
	if (add == 0)
		return;

	in_cli->AddConfCallback(ChanDetailsCliConfigured, 1, this);
}

void Kis_ChanDetails_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	menu->SetPosition(1, 0, 0, 0);

	vbox->SetPosition(1, 1, in_x - 1, in_y - 2);
}

int Kis_ChanDetails_Panel::GraphTimer() {
	// Translates the channel map we get from the server into int vectors for 
	// the graphs, also populates the channel labels with the channel #s at
	// the appropriate positions.
	//
	// Also rewrites the channel summary table w/ the new data
	//
	// All in all this is a really expensive timer, but we only do it inside
	// the channel display window and its in the UI, so screw it

	// Update the vectors
	sigvec.clear();
	noisevec.clear();
	packvec.clear();
	bytevec.clear();
	netvec.clear();
	anetvec.clear();
	graph_label_vec.clear();
	chansummary->Clear();

	unsigned int chpos = 0;
	unsigned int tpos = 0;

	for (map<uint32_t, chan_sig_info *>::iterator x = channel_map.begin();
		 x != channel_map.end(); ++x) {
		if (x->second->sig_rssi != 0) {
			sigvec.push_back(x->second->sig_rssi);
			noisevec.push_back(x->second->noise_rssi);
		} else if (x->second->sig_dbm != 0) {
			sigvec.push_back(x->second->sig_dbm);
			if (x->second->noise_dbm == 0)
				noisevec.push_back(-256);
			else
				noisevec.push_back(x->second->noise_dbm);
		} else {
			sigvec.push_back(-256);
			noisevec.push_back(-256);
		}

		packvec.push_back(x->second->packets_delta);
		bytevec.push_back(x->second->bytes_delta);
		netvec.push_back(x->second->networks);
		anetvec.push_back(x->second->networks_active);

		Kis_IntGraph::graph_label lab;
		lab.position = chpos++;
		lab.label = IntToString(x->first);
		graph_label_vec.push_back(lab);

		// Populate the channel info table
		vector<string> td;
		td.push_back(IntToString(x->first));
		td.push_back(IntToString(x->second->packets));
		td.push_back(IntToString(x->second->packets_delta));

		if (x->second->bytes_seen < 1024) {
			td.push_back(IntToString(x->second->bytes_seen) + "B");
		} else if (x->second->bytes_seen < (1024 * 1024)) {
			td.push_back(IntToString(x->second->bytes_seen / 1024) + "K");
		} else {
			td.push_back(IntToString(x->second->bytes_seen / 1024 / 1024) + "M");
		}
		if (x->second->bytes_delta < 1024) {
			td.push_back(IntToString(x->second->bytes_delta) + "B");
		} else if (x->second->bytes_delta < (1024 * 1024)) {
			td.push_back(IntToString(x->second->bytes_delta / 1024) + "K");
		} else {
			td.push_back(IntToString(x->second->bytes_delta / 1024 / 1024) + "M");
		}

		td.push_back(IntToString(x->second->networks));
		td.push_back(IntToString(x->second->networks_active));

		td.push_back(NtoString<float>((float) x->second->channel_time_on / 
									  1000000).Str() + "s");

		chansummary->AddRow(tpos++, td);
	}

	siggraph->SetXLabels(graph_label_vec, "Signal");
	packetgraph->SetXLabels(graph_label_vec, "Packet Rate");
	bytegraph->SetXLabels(graph_label_vec, "Traffic");
	netgraph->SetXLabels(graph_label_vec, "Networks");

	return 1;
}

void Kis_ChanDetails_Panel::DrawPanel() {
	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	DrawComponentVec();

	wmove(win, 0, 0);
}

void Kis_ChanDetails_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	return;
}

void Kis_ChanDetails_Panel::MenuAction(int opt) {
	if (opt == mi_close) {
		globalreg->panel_interface->KillPanel(this);
		return;
	} else {
		UpdateViewMenu(opt);
	}
}

void Kis_ChanDetails_Panel::UpdateViewMenu(int mi) {
	string opt;

	if (mi == mi_chansummary) {
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWSUM");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWSUM", "false", 1);
			menu->SetMenuItemChecked(mi_chansummary, 0);
			chansummary->Hide();
		} else {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWSUM", "true", 1);
			menu->SetMenuItemChecked(mi_chansummary, 1);
			chansummary->Show();
		}
	} else if (mi == mi_signal) {
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWSIG");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWSIG", "false", 1);
			menu->SetMenuItemChecked(mi_signal, 0);
			siggraph->Hide();
		} else {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWSIG", "true", 1);
			menu->SetMenuItemChecked(mi_signal, 1);
			siggraph->Show();
		}
	} else if (mi == mi_packets) {
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWPACK");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWPACK", "false", 1);
			menu->SetMenuItemChecked(mi_packets, 0);
			packetgraph->Hide();
		} else {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWPACK", "true", 1);
			menu->SetMenuItemChecked(mi_packets, 1);
			packetgraph->Show();
		}
	} else if (mi == mi_traffic) {
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWTRAF");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWTRAF", "false", 1);
			menu->SetMenuItemChecked(mi_traffic, 0);
			bytegraph->Hide();
		} else {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWTRAF", "true", 1);
			menu->SetMenuItemChecked(mi_traffic, 1);
			bytegraph->Show();
		}
	} else if (mi == mi_networks) {
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWNET");
		if (opt == "" || opt == "true") {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWNET", "false", 1);
			menu->SetMenuItemChecked(mi_networks, 0);
			netgraph->Hide();
		} else {
			kpinterface->prefs.SetOpt("CHANDETAILS_SHOWNET", "true", 1);
			menu->SetMenuItemChecked(mi_networks, 1);
			netgraph->Show();
		}
	} else if (mi == -1) {
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWSUM");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_chansummary, 1);
			chansummary->Show();
		} else {
			menu->SetMenuItemChecked(mi_chansummary, 0);
			chansummary->Hide();
		}
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWSIG");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_signal, 1);
			siggraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_signal, 0);
			siggraph->Hide();
		}
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWPACK");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_packets, 1);
			packetgraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_packets, 0);
			packetgraph->Hide();
		}
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWTRAF");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_traffic, 1);
			bytegraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_traffic, 0);
			bytegraph->Hide();
		}
		opt = kpinterface->prefs.FetchOpt("CHANDETAILS_SHOWNET");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_networks, 1);
			netgraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_networks, 0);
			netgraph->Hide();
		}
	}
}

void Kis_ChanDetails_Panel::Proto_CHANNEL(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < KCLI_CHANDETAILS_CHANNEL_NUMFIELDS)
		return;

	int fnum = 0;

	chan_sig_info *ci;

	int tint;
	long int tlong;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}

	if (channel_map.find(tint) != channel_map.end()) {
		ci = channel_map[tint];
	} else {
		ci = new chan_sig_info;
		ci->channel = tint;
		channel_map[tint] = ci;
	}

	ci->last_updated = time(0);

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		return;
	if (tint != 0)
		ci->channel_time_on = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	ci->packets = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	if (tint != 0)
		ci->packets_delta = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%ld", &tlong) != 1)
		return;
	ci->usec_used = tlong;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%ld", &tlong) != 1)
		return;
	ci->bytes_seen = tlong;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%ld", &tlong) != 1)
		return;
	if (tlong != 0)
		ci->bytes_delta = tlong;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	ci->networks = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	ci->networks_active = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	ci->sig_dbm = tint;
	
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	ci->sig_rssi = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	ci->noise_dbm = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	ci->noise_rssi = tint;
}

int ChanconfButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Chanconf_Panel *) aux)->ButtonAction(component);
	return 1;
}


Kis_Chanconf_Panel::Kis_Chanconf_Panel(GlobalRegistry *in_globalreg, 
									   KisPanelInterface *in_intf):
	Kis_Panel(in_globalreg, in_intf) {

	cardlist = new Kis_Scrollable_Table(globalreg, this);
	cardlist->SetHighlightSelected(1);
	cardlist->SetLockScrollTop(1);
	cardlist->SetDrawTitles(1);
	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 16;
	t.title = "Name";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 4;
	t.title = "Chan";
	t.alignment = 2;
	titles.push_back(t);
	cardlist->AddTitles(titles);
	vector<string> td;
	td.push_back("No sources found");
	td.push_back("---");
	cardlist->AddRow(0, td);
	cardlist->Show();
	AddComponentVec(cardlist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));

	lockrad = new Kis_Radiobutton(globalreg, this);
	lockrad->SetText("Lock");
	lockrad->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ChanconfButtonCB, this);
	lockrad->Show();
	lockrad->SetChecked(1);
	AddComponentVec(lockrad, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));

	hoprad = new Kis_Radiobutton(globalreg, this);
	hoprad->SetText("Hop");
	hoprad->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ChanconfButtonCB, this);
	hoprad->Show();
	AddComponentVec(hoprad, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							 KIS_PANEL_COMP_TAB));

	dwellrad = new Kis_Radiobutton(globalreg, this);
	dwellrad->SetText("Dwell");
	dwellrad->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ChanconfButtonCB, this);
	dwellrad->Show();
	AddComponentVec(dwellrad, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));

	lockrad->LinkRadiobutton(hoprad);
	lockrad->LinkRadiobutton(dwellrad);

	dwellrad->LinkRadiobutton(hoprad);
	dwellrad->LinkRadiobutton(lockrad);

	hoprad->LinkRadiobutton(dwellrad);
	hoprad->LinkRadiobutton(lockrad);

	inpchannel = new Kis_Single_Input(globalreg, this);
	inpchannel->SetLabel("Chan/Freq", LABEL_POS_LEFT);
	inpchannel->SetTextLen(4);
	inpchannel->SetCharFilter(FILTER_NUM);

	inpchannel->Show();
	AddComponentVec(inpchannel, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								 KIS_PANEL_COMP_TAB));

	inprate = new Kis_Single_Input(globalreg, this);
	inprate->SetLabel("Rate", LABEL_POS_LEFT);
	inprate->SetTextLen(4);
	inprate->SetCharFilter(FILTER_NUM);
	inprate->Hide();
	AddComponentVec(inprate, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));

	/*
	if (kpinterface->FetchMainPanel()->FetchDisplayNetlist()->FetchSelectedNetgroup() != NULL)
		inpchannel->SetText(IntToString(kpinterface->FetchMainPanel()->FetchDisplayNetlist()->FetchSelectedNetgroup()->FetchNetwork()->channel), -1, -1);
	else
		inpchannel->SetText("6", -1, -1);
	*/

	okbutton = new Kis_Button(globalreg, this);
	okbutton->SetText("Change");
	okbutton->Show();
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	
	cancelbutton = new Kis_Button(globalreg, this);
	cancelbutton->SetText("Cancel");
	cancelbutton->Show();
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));

	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ChanconfButtonCB, this);
	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, ChanconfButtonCB, this);

	SetTitle("Configure Channel");

	cbox = new Kis_Panel_Packbox(globalreg, this);
	cbox->SetPackH();
	cbox->SetHomogenous(1);
	cbox->SetSpacing(1);
	cbox->SetCenter(1);
	AddComponentVec(cbox, KIS_PANEL_COMP_DRAW);
	cbox->Pack_End(lockrad, 0, 0);
	cbox->Pack_End(hoprad, 0, 0);
	cbox->Pack_End(dwellrad, 0, 0);
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

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	vbox->Pack_End(cardlist, 1, 0);
	vbox->Pack_End(cbox, 0, 0);
	vbox->Pack_End(inpchannel, 0, 0);
	vbox->Pack_End(inprate, 0, 0);
	vbox->Pack_End(bbox, 0, 0);
	
	vbox->Show();

	tab_pos = 0;
	cardlist->Activate(1);

	last_selected = 0;
	radio_changed = 0;
	last_radio = lockrad;
}

Kis_Chanconf_Panel::~Kis_Chanconf_Panel() {

}

void Kis_Chanconf_Panel::DrawPanel() {
	map<uuid, KisPanelInterface::knc_card *> *cardmap =
		kpinterface->FetchNetCardMap();

	vector<string> td;

	for (map<uuid, KisPanelInterface::knc_card *>::iterator x = cardmap->begin();
		 x != cardmap->end(); ++x) {
		int sel = cardlist->DelRow(0);

		td.clear();

		td.push_back(x->second->name);
		if (x->second->hopping)
			td.push_back("Hop");
		else
			td.push_back(IntToString(x->second->channel));

		cardlist->ReplaceRow(x->second->uuid_hash, td);

		if (sel) {
			cardlist->SetSelected(x->second->uuid_hash);
		}
	}

	if (cardlist->GetSelected() != last_selected || radio_changed != 0) {
		KisPanelInterface::knc_card *card = NULL;
		for (map<uuid, KisPanelInterface::knc_card *>::iterator x = cardmap->begin();
			 x != cardmap->end(); ++x) {
			if (x->second->uuid_hash == (unsigned int) cardlist->GetSelected()) {
				card = x->second;
				break;
			}
		}

		// This should never happen but lets be safe
		if (card == NULL) {
			Kis_Panel::DrawPanel();
			return;
		}

		// Set up the window for new cards OR set up the window based on the
		// new radiobutton selection
		if (last_selected != cardlist->GetSelected()) {
			if (card->hopping == 0 && card->dwell == 0) {
				lockrad->SetChecked(1);
				last_radio = lockrad;

				inpchannel->SetLabel("Chan/Freq", LABEL_POS_LEFT);
				inpchannel->SetTextLen(4);
				inpchannel->SetCharFilter(FILTER_NUM);
				inpchannel->SetText(IntToString(card->channel), -1, -1);
				inpchannel->Show();

				inprate->Hide();
			} else if (card->dwell != 0) {
				dwellrad->SetChecked(1);
				last_radio = dwellrad;

				inpchannel->SetLabel("Channels", LABEL_POS_LEFT);
				inpchannel->SetTextLen(256);
				inpchannel->SetCharFilter(string(FILTER_NUM) + ",:");
				inpchannel->SetText(card->channellist, -1, -1);
				inpchannel->Show();

				inprate->SetLabel("Dwell", LABEL_POS_LEFT);
				inprate->SetTextLen(3);
				inprate->SetCharFilter(FILTER_NUM);
				inprate->SetText(IntToString(card->hopvelocity), -1, -1);
				inprate->Show();

			} else if (card->hopping) {
				hoprad->SetChecked(1);
				last_radio = hoprad;

				inpchannel->SetLabel("Channels", LABEL_POS_LEFT);
				inpchannel->SetTextLen(256);
				inpchannel->SetCharFilter(string(FILTER_NUM) + ",:");
				inpchannel->SetText(card->channellist, -1, -1);
				inpchannel->Show();

				inprate->SetLabel("Rate", LABEL_POS_LEFT);
				inprate->SetTextLen(3);
				inprate->SetCharFilter(FILTER_NUM);
				inprate->SetText(IntToString(card->hopvelocity), -1, -1);
				inprate->Show();
			}
		} else {
			if (last_radio == lockrad) {
				inpchannel->SetLabel("Chan/Freq", LABEL_POS_LEFT);
				inpchannel->SetTextLen(4);
				inpchannel->SetCharFilter(FILTER_NUM);
				inpchannel->SetText(IntToString(card->channel), -1, -1);
				inpchannel->Show();

				// attack of the api doom, set the selected network channel as the
				// default lock channel if we're not already locked
				if (card->hopping == 0 && card->dwell == 0) {
					inpchannel->SetText(IntToString(card->channel), -1, -1);
				} else {
					if (kpinterface->FetchMainPanel()->FetchDisplayNetlist()->FetchSelectedNetgroup() != NULL)
						inpchannel->SetText(IntToString(kpinterface->FetchMainPanel()->FetchDisplayNetlist()->FetchSelectedNetgroup()->FetchNetwork()->channel), -1, -1);
					else
						inpchannel->SetText("6", -1, -1);
				}

				inprate->Hide();
			} else if (last_radio == dwellrad) {
				inpchannel->SetLabel("Channels", LABEL_POS_LEFT);
				inpchannel->SetTextLen(256);
				inpchannel->SetCharFilter(string(FILTER_NUM) + ",:");
				inpchannel->SetText(card->channellist, -1, -1);
				inpchannel->Show();

				inprate->SetLabel("Dwell", LABEL_POS_LEFT);
				inprate->SetTextLen(3);
				inprate->SetCharFilter(FILTER_NUM);
				inprate->SetText(IntToString(card->hopvelocity), -1, -1);
				inprate->Show();

			} else if (last_radio == hoprad) {
				inpchannel->SetLabel("Channels", LABEL_POS_LEFT);
				inpchannel->SetTextLen(256);
				inpchannel->SetCharFilter(string(FILTER_NUM) + ",:");
				inpchannel->SetText(card->channellist, -1, -1);
				inpchannel->Show();

				inprate->SetLabel("Rate", LABEL_POS_LEFT);
				inprate->SetTextLen(3);
				inprate->SetCharFilter(FILTER_NUM);
				inprate->SetText(IntToString(card->hopvelocity), -1, -1);
				inprate->Show();
			}

		}

		last_selected = cardlist->GetSelected();
		radio_changed = 0;
	}

	Kis_Panel::DrawPanel();
}

void Kis_Chanconf_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		uint32_t cardid = cardlist->GetSelected();
		map<uuid, KisPanelInterface::knc_card *> *cardmap =
			kpinterface->FetchNetCardMap();

		if (cardmap->size() == 0) {
			kpinterface->RaiseAlert("No cards",
					"No cards found in the list from the \n"
					"server, something is wrong.\n");
			kpinterface->KillPanel(this);
			return;
		}

		if (cardid == 0) {
			kpinterface->RaiseAlert("No card", "No card selected\n");
			return;
		}

		if (kpinterface->FetchFirstNetclient() == NULL) {
			kpinterface->RaiseAlert("No server",
					"Not connected to a server, you \n"
					"shouldn't have been able to get to\n"
					"this point\n");
			kpinterface->KillPanel(this);
			return;
		}

		KisPanelInterface::knc_card *card = NULL;

		for (map<uuid, KisPanelInterface::knc_card *>::iterator x = cardmap->begin();
			 x != cardmap->end(); ++x) {
			if (x->second->uuid_hash == cardid) {
				card = x->second;
				break;
			}
		}

		if (card == NULL) {
			kpinterface->RaiseAlert("No card",
					"No card matched the selected item\n"
					"this shouldn't happen.\n");
			kpinterface->KillPanel(this);
			return;
		}

		if (last_radio == lockrad) {
			if (inpchannel->GetText() == "") {
				kpinterface->RaiseAlert("No channel",
					"No channel given\n");
				return;
			}

			kpinterface->FetchFirstNetclient()->InjectCommand("HOPSOURCE " + 
				card->carduuid.UUID2String() + " LOCK " + 
				inpchannel->GetText());
			kpinterface->KillPanel(this);
			return;
		} else if (last_radio == hoprad || last_radio == dwellrad) {
			if (inpchannel->GetText() == "") {
				kpinterface->RaiseAlert("No channels",
										"No channels given\n");
				return;
			}

			if (inprate->GetText() == "") {
				kpinterface->RaiseAlert("No rate",
										"No hop rate given\n");
				return;
			}

			if (inpchannel->GetText() != card->channellist) 
				kpinterface->FetchFirstNetclient()->InjectCommand("CHANSOURCE " +
					card->carduuid.UUID2String() + " " + inpchannel->GetText());

			kpinterface->FetchFirstNetclient()->InjectCommand("HOPSOURCE " + 
				card->carduuid.UUID2String() + string(" ") + 
				string(last_radio == hoprad ? "HOP" : "DWELL") +
				string(" ") + inprate->GetText());

			kpinterface->KillPanel(this);
			return;
		}
	} else if (in_button == cancelbutton) {
		globalreg->panel_interface->KillPanel(this);
		return;
	} else if (in_button == lockrad && last_radio != lockrad) {
		last_radio = lockrad;
		radio_changed = 1;
	} else if (in_button == hoprad && last_radio != hoprad) {
		last_radio = hoprad;
		radio_changed = 1;
	} else if (in_button == dwellrad && last_radio != dwellrad) {
		last_radio = dwellrad;
		radio_changed = 1;
	}
}

static const char *gpsinfo_fields[] = {
	"fix", "lat", "lon", "alt", "spd", "satinfo", NULL
};

void GpsProtoGPS(CLIPROTO_CB_PARMS) {
	((Kis_Gps_Panel *) auxptr)->Proto_GPS(globalreg, proto_string,
										  proto_parsed, srccli, auxptr);
}

void GpsCliConfigured(CLICONF_CB_PARMS) {
	if (recon)
		return;

	string agg_gps_fields;

	TokenNullJoin(&agg_gps_fields, gpsinfo_fields);

	if (kcli->RegisterProtoHandler("GPS", agg_gps_fields, GpsProtoGPS, auxptr) < 0) {
		_MSG("Could not register GPS protocol with remote server, connection "
			 "will be terminated", MSGFLAG_ERROR);
		kcli->KillConnection();
	}
}

void GpsCliAdd(KPI_ADDCLI_CB_PARMS) {
	if (add == 0)
		return;

	netcli->AddConfCallback(GpsCliConfigured, 1, auxptr);
}

int GpsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_Gps_Panel *) aux)->ButtonAction(component);
	return 1;
}

Kis_Gps_Panel::Kis_Gps_Panel(GlobalRegistry *in_globalreg, 
									   KisPanelInterface *in_intf):
	Kis_Panel(in_globalreg, in_intf) {

	okbutton = new Kis_Button(globalreg, this);
	okbutton->SetText("OK");
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, GpsButtonCB, this);
	okbutton->Show();
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	okbutton->Activate(0);

	SetTitle("GPS Info");

	gpssiggraph = new Kis_IntGraph(globalreg, this);
	gpssiggraph->SetName("GPS_SIG");
	gpssiggraph->SetPreferredSize(0, 12);
	gpssiggraph->SetInterpolation(0);
	gpssiggraph->SetMode(0);
	gpssiggraph->SetDrawScale(0);
	gpssiggraph->SetDrawLayers(0);
	gpssiggraph->AddExtDataVec("PRN SNR", 3, "gps_prn", "green,green",
							   ' ', ' ', 1, &sat_info_vec);
	gpssiggraph->SetXLabels(sat_label_vec, "PRN SNR");
	gpssiggraph->Show();

	gpslocinfo = new Kis_Free_Text(globalreg, this);
	gpslocinfo->Show();

	gpsmoveinfo = new Kis_Free_Text(globalreg, this);
	gpsmoveinfo->Show();

	gpssatinfo = new Kis_Free_Text(globalreg, this);
	gpssatinfo->Show();

	/*
	tbox = new Kis_Panel_Packbox(globalreg, this);
	tbox->SetPackV();
	tbox->SetHomogenous(0);
	tbox->SetSpacing(0);
	tbox->SetCenter(0);
	tbox->Pack_End(gpslocinfo, 0, 0);
	tbox->Pack_End(gpsmoveinfo, 0, 0);
	tbox->Pack_End(gpssatinfo, 0, 0);
	tbox->Pack_End(gpssiggraph, 0, 0);
	tbox->Show();

	gpspolgraph = new Kis_PolarGraph(globalreg, this);
	gpspolgraph->SetPreferredSize(12, 12);
	gpspolgraph->Show();

	hbox = new Kis_Panel_Packbox(globalreg, this);
	hbox->SetPackH();
	hbox->SetHomogenous(1);
	hbox->SetSpacing(1);
	hbox->Pack_End(gpspolgraph, 0, 0);
	hbox->Pack_End(gpssiggraph, 0, 0);
	hbox->Show();
	*/

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	vbox->Pack_End(gpslocinfo, 0, 0);
	vbox->Pack_End(gpsmoveinfo, 0, 0);
	vbox->Pack_End(gpssatinfo, 0, 0);
	vbox->Pack_End(gpssiggraph, 1, 0);
	vbox->Pack_End(okbutton, 0, 0);
	
	vbox->Show();

	active_component = okbutton;
	tab_pos = 0;

	addref = 
		kpinterface->Add_NetCli_AddCli_CB(GpsCliAdd, (void *) this);

	agg_gps_num = TokenNullJoin(&agg_gps_fields, gpsinfo_fields);
}

Kis_Gps_Panel::~Kis_Gps_Panel() {
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(GpsCliConfigured);
	kpinterface->Remove_AllNetcli_ProtoHandler("GPS", GpsProtoGPS, this);
}

void Kis_Gps_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == okbutton) {
		kpinterface->KillPanel(this);
		return;
	}
}

#define DEG_2_RAD 0.0174532925199432957692369076848861271
void Kis_Gps_Panel::Proto_GPS(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) agg_gps_num)
		return;

	int fnum = 0, fix;
	float lat, lon, alt, spd;

	string gpstext;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &fix) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &lat) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &lon) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &alt) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &spd) != 1)
		return;

	int eng = StrLower(kpinterface->prefs.FetchOpt("GPSUNIT")) != "metric";

	if (eng) {
		// Convert speed to feet/sec
		spd /= 3.2808;
		// Convert alt to feet
		alt /= 3.2808;
	}

	if (fix < 2) {
		gpslocinfo->SetText("No position (GPS does not have signal)");
		gpsmoveinfo->SetText("");
	} else {
		gpstext = string("Lat ") + 
			NtoString<float>(lat).Str() + string(" Lon ") + 
			NtoString<float>(lon).Str();
		gpslocinfo->SetText(gpstext);

		if (eng) {
			if (spd > 2500)
				gpstext = "Spd: " + NtoString<float>(spd / 5280, 2).Str() + " mph ";
			else
				gpstext = "Spd: " + NtoString<float>(spd, 2).Str() + " fph ";

			if (alt > 2500)
				gpstext += "Alt: " + NtoString<float>(alt / 5280, 2).Str() + " m ";
			else
				gpstext += "Alt: " + NtoString<float>(alt, 2).Str() + " ft ";
		} else {
			if (spd > 1000)
				gpstext = "Spd: " + NtoString<float>(spd / 1000, 2).Str() + "Km/hr ";
			else
				gpstext = "Spd: " + NtoString<float>(spd, 2).Str() + "m/hr ";

			if (alt > 1000)
				gpstext += "Alt: " + NtoString<float>(alt / 1000, 2).Str() + "Km ";
			else
				gpstext += "Alt: " + NtoString<float>(alt, 2).Str() + "m ";
		} 

		gpsmoveinfo->SetText(gpstext);
	}

	vector<string> satblocks = StrTokenize((*proto_parsed)[fnum++].word, ",");

	sat_info_vec.clear();
	sat_label_vec.clear();
	// gpspolgraph->ClearPoints();
	
	for (unsigned int x = 0; x < satblocks.size(); x++) {
		int prn, azimuth, elevation, snr;

		if (sscanf(satblocks[x].c_str(), "%d:%d:%d:%d", &prn, &elevation,
				   &azimuth, &snr) != 4)
			continue;

		sat_info_vec.push_back(snr);

		Kis_IntGraph::graph_label lab;
		lab.position = x;
		lab.label = IntToString(prn);
		sat_label_vec.push_back(lab);

		/*
		Kis_PolarGraph::graph_point gp;
		gp.colorpref = "GPS_WEAKSNR";
		gp.colordefault = "red,black";
		gp.name = IntToString(prn);

		gp.r = ((90.0 - (double) elevation) / 90.0);
		gp.theta = azimuth * DEG_2_RAD;

		// fprintf(stderr, "debug - added %d %f %f\n", prn, gp.theta, gp.r);

		gpspolgraph->AddPoint(x, gp);
		*/

	}

	gpssatinfo->SetText(IntToString(sat_info_vec.size()) + " satellites, " +
						IntToString(fix) + string("d fix"));
	gpssiggraph->SetXLabels(sat_label_vec, "PRN SNR");

}

#endif

