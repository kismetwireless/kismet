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
#include "kis_panel_details.h"
#include "kis_panel_preferences.h"

#include "soundcontrol.h"

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

void KisMainPanel_BATTERY(CLIPROTO_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->Proto_BATTERY(globalreg, proto_string,
											   proto_parsed, srccli, auxptr);
}

void KisMainPanel_ALERT(CLIPROTO_CB_PARMS) {
	((Kis_Main_Panel *) auxptr)->Proto_ALERT(globalreg, proto_string,
											 proto_parsed, srccli, auxptr);
}

const char *gps_fields[] = {
	"connected", "fix", "lat", "lon", "alt", "spd", "heading", NULL
};

Kis_Main_Panel::Kis_Main_Panel(GlobalRegistry *in_globalreg, 
							   KisPanelInterface *in_intf) : 
	Kis_Panel(in_globalreg, in_intf) {

	globalreg->InsertGlobal("KISUI_MAIN_PANEL", this);

	menu = new Kis_Menu(globalreg, this);
	globalreg->InsertGlobal("KISUI_MAIN_MENU", menu);

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
	mi_audioprefs = menu->AddMenuItem("Audio...", mn_preferences, 'A');
	mi_colorprefs = menu->AddMenuItem("Colors...", mn_preferences, 'C');
	// mi_clicolprefs = menu->AddMenuItem("Client Columns...", mn_preferences, 'c');
	// mi_cliextraprefs = menu->AddMenuItem("Client Extras...", mn_preferences, 'E');
	mi_gpsprefs = menu->AddMenuItem("GPS...", mn_preferences, 'G');
	mi_infoprefs = menu->AddMenuItem("Info Pane...", mn_preferences, 'I');
	// mi_netcolprefs = menu->AddMenuItem("Network Columns...", mn_preferences, 'n');
	// mi_netextraprefs = menu->AddMenuItem("Network Extras...", mn_preferences, 'e');
	mi_serverprefs = menu->AddMenuItem("Servers...", mn_preferences, 'S');
	mi_startprefs = menu->AddMenuItem("Startup & Shutdown...", mn_preferences, 's');
	mi_warnprefs = menu->AddMenuItem("Warnings...", mn_preferences, 'W');

	menu->AddMenuItem("-", mn_file, 0);

	mi_quit = menu->AddMenuItem("Quit", mn_file, 'Q');

	menu->EnableMenuItem(mi_connect);
	menu->DisableMenuItem(mi_disconnect);
	connect_enable = 1;

	mn_sort = menu->AddMenu("Sort", 0);

	mn_view = menu->AddMenu("View", 0);

	// Make an invisible menu placeholder
	mi_lastview = mi_viewplaceholder = menu->AddMenuItem("placeholder", mn_view, 0);
	menu->SetMenuItemVis(mi_viewplaceholder, 0);

	/*
	mi_viewnetworks =  menu->AddMenuItem("Display as Networks", mn_view, 0);
	mi_viewdevices = menu->AddMenuItem("Display as Devices", mn_view, 0);
	*/
	mn_filter = menu->AddSubMenuItem("Filter", mn_view, 'F');
	menu->AddMenuItem("-", mn_view, 0);

	/*
	menu->SetMenuItemCheckSymbol(mi_viewnetworks, '*');
	menu->SetMenuItemCheckSymbol(mi_viewdevices, '*');
	*/

	mi_showdevice = menu->AddMenuItem("Device List", mn_view, 'n');
	mi_showgps = menu->AddMenuItem("GPS Data", mn_view, 'g');
	mi_showbattery = menu->AddMenuItem("Battery", mn_view, 'b');
	mi_showsummary = menu->AddMenuItem("General Info", mn_view, 'S');
	mi_showstatus = menu->AddMenuItem("Status", mn_view, 's');
	mi_showpps = menu->AddMenuItem("Packet Graph", mn_view, 'p');
	mi_showsources = menu->AddMenuItem("Source Info", mn_view, 'C');

	mn_windows = menu->AddMenu("Windows", 0);
	mi_netdetails = menu->AddMenuItem("Device Details...", mn_windows, 'd');
	mi_addnote = menu->AddMenuItem("Network Note...", mn_windows, 'N');
	mi_chandetails = menu->AddMenuItem("Channel Details...", mn_windows, 'c');
	mi_gps = menu->AddMenuItem("GPS Details...", mn_windows, 'g');
	mi_alerts = menu->AddMenuItem("Alerts...", mn_windows, 'a');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	mn_view_appended = 0;

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

	devicelist = new Kis_Devicelist(globalreg, this);
	devicelist->SetName("KIS_MAIN_DEVICELIST");
	devicelist->Show();

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

	batteryinfo = new Kis_Free_Text(globalreg, this);
	batteryinfo->SetName("KIS_MAIN_BATTERY");
	batteryinfo->SetAlignment(1);
	batteryinfo->Show();
	linebox->Pack_End(batteryinfo, 0, 0);

	// Pack our boxes together
	hbox->Pack_End(netbox, 1, 0);
	hbox->Pack_End(optbox, 0, 0);

	//netbox->Pack_End(netlist, 1, 0);
	netbox->Pack_End(devicelist, 1, 0);
	netbox->Pack_End(linebox, 0, 0);
	netbox->Pack_End(packetrate, 0, 0);
	netbox->Pack_End(statustext, 0, 0);

	vbox->Pack_End(hbox, 1, 0);

	// AddComponentVec(netlist, KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT);
	AddComponentVec(devicelist, KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	if (kpinterface->prefs->FetchOpt("LOADEDFROMFILE") != "1") {
		_MSG("Failed to load preferences file, will use defaults", MSGFLAG_INFO);
	}

	// Initialize base colors
	InitColorPref("panel_text_color", "white,black");
	InitColorPref("panel_textdis_color", "white,black");

	AddColorPref("panel_text_color", "Text");
	AddColorPref("panel_textdis_color", "Text-Inactive");
	AddColorPref("panel_border_color", "Window Border");
	AddColorPref("menu_text_color", "Menu Text");
	AddColorPref("menu_disable_color", "Menu Disabled");
	AddColorPref("menu_border_color", "Menu Border");
	AddColorPref("netlist_header_color", "Netlist Header");
	AddColorPref("netlist_normal_color", "Netlist Unencrypted");
	AddColorPref("netlist_wep_color", "Netlist WEP");
	AddColorPref("netlist_crypt_color", "Netlist Encrypted");
	AddColorPref("netlist_group_color", "Netlist Group");
	AddColorPref("netlist_decrypt_color", "Netlist Decrypted");
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

	// SetActiveComponent(netlist);
	SetActiveComponent(devicelist);
}

Kis_Main_Panel::~Kis_Main_Panel() {
	globalreg->messagebus->RemoveClient(statuscli);
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(KisMainPanel_Configured);
	kpinterface->Remove_All_Netcli_ProtoHandler("INFO",
												KisMainPanel_INFO, this);
	kpinterface->Remove_All_Netcli_ProtoHandler("GPS",
												KisMainPanel_GPS, this);
	kpinterface->Remove_All_Netcli_ProtoHandler("BATTERY",
												KisMainPanel_BATTERY, this);
	kpinterface->Remove_All_Netcli_ProtoHandler("ALERT",
												KisMainPanel_ALERT, this);
}

void kmp_prompt_startserver(KIS_PROMPT_CB_PARMS) {
	if (ok) {
		Kis_Spawn_Panel *sp = new Kis_Spawn_Panel(globalreg, globalreg->panel_interface);

		// if (globalreg->panel_interface->prefs->FetchOpt("STARTUP_CONSOLE") == "true" ||
		// 	globalreg->panel_interface->prefs->FetchOpt("STARTUP_CONSOLE") == "") 
		if (globalreg->panel_interface->prefs->FetchOptBoolean("STARTUP_CONSOLE", 1))
			sp->SpawnConsole(1);
		else
			sp->SpawnConsole(0);

		globalreg->panel_interface->QueueModalPanel(sp);
	}
}

void kmp_prompt_asroot(KIS_PROMPT_CB_PARMS) {
	if (check) {
		globalreg->panel_interface->prefs->SetOpt("STARTUP_WARNROOT", "false", 1);
	}
}

void kmp_prompt_greycolor(KIS_PROMPT_CB_PARMS) {
	if (ok) 
		globalreg->panel_interface->prefs->SetOpt("panel_textdis_color", 
												  "grey,black", time(0));

	globalreg->panel_interface->prefs->SetOpt("STARTUP_COLOR", "true", time(0));
}

void Kis_Main_Panel::Startup() {
	int initclient = 0;

	// Save preferences to detect errors
	kpinterface->SavePreferences();

	// Load audio prefs and set up defaults
	LoadAudioPrefs();

	if (kpinterface->prefs->FetchOpt("DEFAULT_HOST") == "") {
		kpinterface->prefs->SetOpt("DEFAULT_HOST", "localhost", 1);
		kpinterface->prefs->SetOpt("DEFAULT_PORT", "2501", 1);
		kpinterface->prefs->SetOpt("AUTOCONNECT", "true", 1);
	}

	// if (kpinterface->prefs->FetchOpt("autoconnect") == "true" &&
	if (kpinterface->prefs->FetchOptBoolean("autoconnect", 0) &&
		kpinterface->prefs->FetchOpt("default_host") != "" &&
		kpinterface->prefs->FetchOpt("default_port") != "") {

		string constr = string("tcp://") +
			kpinterface->prefs->FetchOpt("default_host") + ":" +
			kpinterface->prefs->FetchOpt("default_port");

		_MSG("Auto-connecting to " + constr, MSGFLAG_INFO);

		initclient = kpinterface->AddNetClient(constr, 1);
	}

	if (kpinterface->prefs->FetchOpt("STARTUP_COLOR") == "") {
		vector<string> t;

		Kis_Prompt_Panel *kpp =
			new Kis_Prompt_Panel(globalreg, kpinterface);
		
		kpp->InitColorPref("grey_color", "grey,black");
		kpp->InitColorPref("white_color", "white,black");

		t.push_back("\004Cwhite_color;Some terminals don't display some colors "
					"(notably, dark grey)");
		t.push_back("correctly.  The next line of text should read 'Dark grey text': ");
		t.push_back("\004Cgrey_color;Dark grey text");
		t.push_back("\004Cwhite_color;Is it visible?  If you answer 'No', dark grey ");
		t.push_back("will not be used in the default color scheme.  Remember, you ");
		t.push_back("can always change colors to your taste by going to ");
		t.push_back("Kismet->Preferences->Colors.");
		t.push_back("");

		kpp->SetTitle("Terminal colors");
		kpp->SetCallback(kmp_prompt_greycolor, this);
		kpp->SetDisplayText(t);
		kpp->SetButtonText("Yes", "No");
		kpinterface->QueueModalPanel(kpp);
	}

	// if ((getuid() == 0 || geteuid() == 0) &&
	// 	(kpinterface->prefs->FetchOpt("STARTUP_WARNROOT") == "" ||
	// 	 kpinterface->prefs->FetchOpt("STARTUP_WARNROOT") == "true")) {
	if ((getuid() == 0 || geteuid() == 0) &&
		kpinterface->prefs->FetchOptBoolean("STARTUP_WARNROOT", 1)) {
		vector<string> t;
		t.push_back("Kismet is running as root");
		t.push_back("Kismet was started as root.  This isn't the recommended");
		t.push_back("way to start Kismet as it can be dangerous -- the risk");
		t.push_back("to your system from any programming errors is increased.");
		t.push_back("See the README section 'SUID INSTALLATION & SECURITY' for");
		t.push_back("more information.");

		Kis_Prompt_Panel *kpp =
			new Kis_Prompt_Panel(globalreg, kpinterface);
		kpp->SetTitle("Kismet running as root");
		kpp->SetDisplayText(t);
		kpp->SetCheckText("Do not show this warning in the future");
		kpp->SetChecked(0);
		kpp->SetButtonText("OK", "");
		kpp->SetCallback(kmp_prompt_asroot, this);
		kpinterface->QueueModalPanel(kpp);
	}

	// If we're supposed to prompt for the server and we haven't successfully
	// auto-connected to the default...
	// if ((kpinterface->prefs->FetchOpt("STARTUP_PROMPTSERVER") == "" ||
	// 	 kpinterface->prefs->FetchOpt("STARTUP_PROMPTSERVER") == "true") &&
	//	initclient <= 0) {
	if (kpinterface->prefs->FetchOptBoolean("STARTUP_PROMPTSERVER", 1) &&
		initclient <= 0) {
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
		kpp->SetButtonText("Yes", "No");
		kpp->SetDefaultButton(1);
		kpinterface->QueueModalPanel(kpp);
	// } else if ((kpinterface->prefs->FetchOpt("STARTUP_SERVER") == "true" ||
	// 			kpinterface->prefs->FetchOpt("STARTUP_SERVER") == "") &&
	// 		   initclient <= 0) {
	} else if (kpinterface->prefs->FetchOptBoolean("STARTUP_SERVER", 1) &&
			   initclient <= 0) {
		// fprintf(stderr, "debug - kmp_prompt_startserver\n");
		kmp_prompt_startserver(globalreg, 1, -1, this);
	}
}

void Kis_Main_Panel::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	// Reset the GPS text
	gpsinfo->SetText("No GPS info (GPS not connected)");
	
	if (in_cli->RegisterProtoHandler("INFO", "packets,llcpackets,rate,networks",
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

	if (in_cli->RegisterProtoHandler("BATTERY", "percentage,charging,ac,remaining",
									 KisMainPanel_BATTERY, this) < 0) {
		_MSG("Could not register BATTERY protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}

	if (in_cli->RegisterProtoHandler("ALERT", "header",
									 KisMainPanel_ALERT, this) < 0) {
		_MSG("Could not register ALERT protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
}

void Kis_Main_Panel::NetClientAdd(KisNetClient *in_cli, int add) {
	if (add == 0)
		return;

	in_cli->AddConfCallback(KisMainPanel_Configured, 1, this);
}

void Kis_Main_Panel::LoadAudioPrefs() {
	// Set up the sound and speech options and fill in all the prefs so they're
	// in the file in the future
	if (kpinterface->prefs->FetchOpt("SOUNDBIN") == "")
		kpinterface->prefs->SetOpt("SOUNDBIN", "play", 1);
	globalreg->soundctl->SetPlayer(kpinterface->prefs->FetchOpt("SOUNDBIN"));

	if (kpinterface->prefs->FetchOpt("SPEECHBIN") == "")
		kpinterface->prefs->SetOpt("SPEECHBIN", "flite", 1);
	if (kpinterface->prefs->FetchOpt("SPEECHTYPE") == "")
		kpinterface->prefs->SetOpt("SPEECHTYPE", "raw", 1);
	globalreg->soundctl->SetSpeaker(kpinterface->prefs->FetchOpt("SPEECHBIN"),
								  kpinterface->prefs->FetchOpt("SPEECHTYPE"));

	if (kpinterface->prefs->FetchOpt("SPEECHENCODING") == "")
		kpinterface->prefs->SetOpt("SPEECHENCODING", "spell", 1);
	globalreg->soundctl->SetSpeechEncode(kpinterface->prefs->FetchOpt("SPEECHENCODING"));
	

	if (kpinterface->prefs->FetchOpt("SOUNDENABLE") == "") {
		// TODO - call "do you want to enable sound" prompt
		kpinterface->prefs->SetOpt("SOUNDENABLE", "false", 1);
	}
	// globalreg->soundctl->SetSoundEnable(StrLower(kpinterface->prefs->FetchOpt("SOUNDENABLE")) == "true");
	globalreg->soundctl->SetSoundEnable(kpinterface->prefs->FetchOptBoolean("SOUNDENABLE", 0));

	if (kpinterface->prefs->FetchOpt("SPEECHENABLE") == "") {
		// TOO - call "do you want to enable speech" prompt
		kpinterface->prefs->SetOpt("SPEECHENABLE", "false", 1);
	}
	// globalreg->soundctl->SetSpeechEnable(StrLower(kpinterface->prefs->FetchOpt("SPEECHENABLE")) == "true");
	globalreg->soundctl->SetSpeechEnable(kpinterface->prefs->FetchOptBoolean("SPEECHENABLE", 0));

	snd_new = snd_packet = snd_gpslock = snd_gpslost = snd_alert = -1;

	if (kpinterface->prefs->FetchOpt("SOUNDPREFIX") == "") 
		kpinterface->prefs->SetOpt("SOUNDPREFIX", 
								   string(DATA_LOC) + "/sounds/kismet/", 1);
	sound_prefix = kpinterface->prefs->FetchOpt("SOUNDPREFIX");

	vector<string> sndpref = kpinterface->prefs->FetchOptVec("SOUND");
	vector<string> sndparse;
	string snd;
	int val;

	for (unsigned s = 0; s < sndpref.size(); s++) {
		sndparse = StrTokenize(sndpref[s], ",");
		if (sndparse.size() != 2)
			continue;

		snd = StrLower(sndparse[0]);
		// val = (StrLower(sndparse[1]) == "true");
		val = StringToBool(sndparse[1], 0);

		if (snd == "newnet")
			snd_new = val;
		else if (snd == "packet")
			snd_packet = val;
		else if (snd == "gpslock")
			snd_gpslock = val;
		else if (snd == "gpslost")
			snd_gpslost = val;
		else if (snd == "alert")
			snd_alert = val;
	}

	if (snd_new < 0) {
		snd_new = 1;
		sndpref.push_back("newnet,true");
	}

	if (snd_packet < 0) {
		snd_packet = 1;
		sndpref.push_back("packet,true");
	}

	if (snd_gpslock < 0) {
		snd_gpslock = 1;
		sndpref.push_back("gpslock,true");
	}

	if (snd_gpslost < 0) {
		snd_gpslost = 1;
		sndpref.push_back("gpslost,true");
	}

	if (snd_alert == 0) {
		snd_alert = 1;
		sndpref.push_back("alert,true");
	}

	kpinterface->prefs->SetOptVec("sound", sndpref, time(0));

	sndpref = kpinterface->prefs->FetchOptVec("speech");
	for (unsigned int x = 0; x < sndpref.size(); x++) {
		sndparse = QuoteStrTokenize(sndpref[x], ",");

		if (sndparse.size() != 2)
			continue;

		snd = StrLower(sndparse[0]);

		if (snd == "new") 
			spk_new = sndparse[1];
		else if (snd == "alert")
			spk_alert = sndparse[1];
		else if (snd == "gpslost")
			spk_gpslost = sndparse[1];
		else if (snd == "gpslock")
			spk_gpslock = sndparse[1];
	}

	if (spk_new == "") {
		spk_new = "New network detected s.s.i.d. %1 channel %2";
		sndpref.push_back("new,\"" + spk_new + "\"");
	}

	if (spk_alert == "") {
		spk_alert = "Alert %1";
		sndpref.push_back("alert,\"" + spk_alert + "\"");
	}

	if (spk_gpslost == "") {
		spk_gpslost = "G.P.S. signal lost";
		sndpref.push_back("gpslost,\"" + spk_gpslost + "\"");
	}

	if (spk_gpslock == "") {
		spk_gpslock = "G.P.S. signal O.K.";
		sndpref.push_back("gpslock,\"" + spk_gpslock + "\"");
	}

	kpinterface->prefs->SetOptVec("SPEECH", sndpref, 1);

}

void Kis_Main_Panel::SpeakString(string type, vector<string> text) {
	string base;

	if (type == "new")
		base = spk_new;
	else if (type == "alert")
		base = spk_alert;
	else if (type == "gpslost")
		base = spk_gpslost;
	else if (type == "gpslock")
		base = spk_gpslock;
	else
		return;

	for (unsigned int x = 0; x < text.size(); x++) {
		string k = "%" + IntToString(x + 1);
		if (base.find(k) != string::npos)
			base.replace(base.find(k), k.length(), text[x]);
	}

	globalreg->soundctl->SayText(base);
}

void Kis_Main_Panel::Proto_INFO(CLIPROTO_CB_PARMS) {
	// "packets,llcpackets,rate,networks",
	
	if (proto_parsed->size() < 4)
		return;

	int pkts, datapkts, networks;

	if (sscanf((*proto_parsed)[0].word.c_str(), "%d", &pkts) != 1) 
		return;

	if (sscanf((*proto_parsed)[1].word.c_str(), "%d", &datapkts) != 1) 
		return;

	// Parse out of order, networks are a higher sound priority than packets
	if (sscanf((*proto_parsed)[3].word.c_str(), "%d", &networks) != 1)
		return;

	// Use the sound pref tracker as the # of new networks counter
	if (networks != 0 && snd_new != 0 && networks != snd_new) {
		snd_new = networks;
		globalreg->soundctl->PlaySound(sound_prefix + string("/") + "new.wav");
	}

	if ((*proto_parsed)[2].word != "0" && snd_packet)
		globalreg->soundctl->PlaySound(sound_prefix + string("/") + "packet.wav");

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

	int fnum = 0, connected, fix;
	float lat, lon, alt, spd;

	string gpstext;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &connected) != 1)
		return;

	if (connected <= 0) {
		gpsinfo->SetText("No GPS data (GPS not connected)");
		return;
	}

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

	// Use the gpslock/lost prefs to determine if we play the sound or if we
	// already have played this state
	if (fix < 2 && snd_gpslost != 0 && snd_gpslost < 2) {
		snd_gpslost = 2;

		if (snd_gpslock)
			snd_gpslock = 1;

		globalreg->soundctl->PlaySound(sound_prefix + string("/") + "gpslost.wav");
	}

	if (fix >= 2 && snd_gpslock != 0 && snd_gpslock < 2) {
		snd_gpslock = 2;
		
		if (snd_gpslost)
			snd_gpslost = 1;

		globalreg->soundctl->PlaySound(sound_prefix + string("/") + "gpslock.wav");
	}

	int eng = StrLower(kpinterface->prefs->FetchOpt("GPSUNIT")) != "metric";

	gpstext = string("GPS ") + 
		NtoString<float>(lat, 6).Str() + string(" ") + 
		NtoString<float>(lon, 6).Str() + string(" ");

	// Convert to m/hr
	spd *= 3600;

	if (eng) {
		// Convert speed to feet/hr
		spd *= 3.2808;
		// Convert alt to feet
		alt *= 3.2808;
	}

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

void Kis_Main_Panel::Proto_BATTERY(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < 4)
		return;

	// Bat-comment!
	string battxt;

	int charging = 0, percentage = 0, ac = 0, remaining = 0;

	if (sscanf((*proto_parsed)[0].word.c_str(), "%d", &percentage) == 0)
		return;

	if (sscanf((*proto_parsed)[1].word.c_str(), "%d", &charging) == 0)
		return;

	if (sscanf((*proto_parsed)[2].word.c_str(), "%d", &ac) == 0)
		return;

	if (sscanf((*proto_parsed)[3].word.c_str(), "%d", &remaining) == 0)
		return;

	battxt = "Pwr: ";

	if (ac) {
		battxt += "AC";
		if (charging == 1)
			battxt += " (Charging)";
	} else {
		battxt += "Battery " + IntToString(percentage) + "%";
	}

	if (remaining > 0 && ac == 0) {
		remaining /= 60;

		battxt += " " + IntToString(remaining / 60) + "h " + 
			NtoString<int>(remaining % 60, 2, 0).Str() + "m";
	}

	batteryinfo->SetText(battxt);

}

void Kis_Main_Panel::Proto_ALERT(CLIPROTO_CB_PARMS) {
	if (snd_alert)
		globalreg->soundctl->PlaySound(sound_prefix + string("/") + "alert.wav");
}

void Kis_Main_Panel::Position(int in_sy, int in_sx, int in_y, int in_x) {
	Kis_Panel::Position(in_sy, in_sx, in_y, in_x);

	menu->SetPosition(1, 0, 0, 0);

	// All we have to do is position the main box now
	vbox->SetPosition(1, 1, in_x - 1, in_y - 2);
}

void Kis_Main_Panel::DrawPanel() {
	// Set up the source list
	vector<string> sourceinfotxt;
	map<uuid, KisPanelInterface::knc_card *> *cardmap =
		kpinterface->FetchNetCardMap();

	for (map<uuid, KisPanelInterface::knc_card *>::iterator x = cardmap->begin();
		 x != cardmap->end(); ++x) {
		sourceinfotxt.push_back("\004u" + x->second->name + "\004U");
		if (x->second->dwell)
			sourceinfotxt.push_back("Dwell");
		else if (x->second->hopping)
			sourceinfotxt.push_back("Hop");
		else
			sourceinfotxt.push_back(IntToString(x->second->channel));
	}

	sourceinfo->SetText(sourceinfotxt);

	Kis_Panel::DrawPanel();
}

int Kis_Main_Panel::MouseEvent(MEVENT *mevent) {
	int con = kpinterface->FetchNetConnected();

	if (con == 0 && connect_enable == 0) {
		menu->EnableMenuItem(mi_connect);
		menu->DisableMenuItem(mi_disconnect);
		connect_enable = 1;
	} else if (con && connect_enable) {
		menu->EnableMenuItem(mi_disconnect);
		menu->DisableMenuItem(mi_connect);
		connect_enable = 0;
	}

	if (kpinterface->FetchServerFramework() == NULL ||
		(kpinterface->FetchServerFramework() != NULL &&
		 kpinterface->FetchServerFramework()->Valid() == 0)) {
		menu->EnableMenuItem(mi_startserver);
	} else {
		menu->DisableMenuItem(mi_startserver);
	}

	return Kis_Panel::MouseEvent(mevent);
}

int Kis_Main_Panel::KeyPress(int in_key) {
	int con = kpinterface->FetchNetConnected();

	if (con == 0 && connect_enable == 0) {
		menu->EnableMenuItem(mi_connect);
		menu->DisableMenuItem(mi_disconnect);
		connect_enable = 1;
	} else if (con && connect_enable) {
		menu->EnableMenuItem(mi_disconnect);
		menu->DisableMenuItem(mi_connect);
		connect_enable = 0;
	}

	return Kis_Panel::KeyPress(in_key);
}

void Kis_Main_Panel::AddViewSeparator() {
	if (mn_view_appended)
		return;

	mn_view_appended = 1;
	menu->AddMenuItem("-", mn_view, 0);
}

// Dump text to stderr
void kmp_textcli_stderr(TEXTCLI_PARMS) {
	fprintf(stderr, "[SERVER] %s\n", text.c_str());
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
extern void CatchShutdown(int);
void kmp_prompt_killserver(KIS_PROMPT_CB_PARMS) {
	// Kis_Main_Panel *kmp = (Kis_Main_Panel *) auxptr;
	TextCliFrame *cf = globalreg->panel_interface->FetchServerFramework();
	PopenClient *po = globalreg->panel_interface->FetchServerPopen();
	KisNetClient *knc = globalreg->panel_interface->FetchNetClient();

	endwin();

	if (ok && cf != NULL && po != NULL) {
		// Kill and spin down cleanly
		cf->RegisterCallback(kmp_textcli_stderr, NULL);
		cf->RegisterFailCB(kmp_spawnserver_fail, NULL);
		po->SoftKillConnection();
	} else if (ok && knc != NULL) {
		// Send a kill command if we're killing and we're not running it locally
		knc->InjectCommand("SHUTDOWN");
	} else if (po != NULL) {
		// Detatch
		po->DetatchConnection();
	}

	if (knc != NULL)
		knc->Shutdown();

	// Spindown
	CatchShutdown(0);
}

void Kis_Main_Panel::MenuAction(int opt) {
	int con = kpinterface->FetchNetConnected();

	// Menu processed an event, do something with it
	if (opt == mi_quit) {
		if (con == 0 &&
			(kpinterface->FetchServerFramework() == NULL ||
			 (kpinterface->FetchServerFramework() != NULL &&
			  kpinterface->FetchServerFramework()->Valid() == 0))) {
			kmp_prompt_killserver(globalreg, 1, -1, NULL);
		}

		// if ((kpinterface->prefs->FetchOpt("STOP_PROMPTSERVER") == "true" ||
		// 	 kpinterface->prefs->FetchOpt("STOP_PROMPTSERVER") == "") &&
		// 	(kpinterface->prefs->FetchOpt("STOP_SERVER") == "true" ||
		// 	 kpinterface->prefs->FetchOpt("STOP_SERVER") == "")) {
		if (kpinterface->prefs->FetchOptBoolean("STOP_PROMPTSERVER", 1) &&
			kpinterface->prefs->FetchOptBoolean("STOP_SERVER", 1)) {

			vector<string> t;
			t.push_back("Stop Kismet server before quitting?");
			t.push_back("This will stop capture & shut down any other");
			t.push_back("clients that might be connected to this server");

			if (globalreg->panel_interface->FetchServerFramework() != NULL) {
				t.push_back("Not stopping the server will leave it running in");
				t.push_back("the background.");
			}

			Kis_Prompt_Panel *kpp = 
				new Kis_Prompt_Panel(globalreg, kpinterface);
			kpp->SetTitle("Stop Kismet Server");
			kpp->SetDisplayText(t);
			if (globalreg->panel_interface->FetchServerFramework() == NULL) {
				kpp->SetButtonText("Kill", "Leave");
			} else {
				kpp->SetButtonText("Kill", "Background");
			}
			kpp->SetCallback(kmp_prompt_killserver, this);
			kpp->SetDefaultButton(1);
			kpinterface->QueueModalPanel(kpp);
			return;
		// } else if (kpinterface->prefs->FetchOpt("STOP_SERVER") == "true" ||
		// 		   kpinterface->prefs->FetchOpt("STOP_SERVER") == "") {
		} else if (kpinterface->prefs->FetchOptBoolean("STOP_SERVER", 1)) {
			// if we're stopping the server without prompt, just call the
			// prompt handler and tell it OK
			kmp_prompt_killserver(globalreg, 1, -1, NULL);
		} else {
			// Otherwise we're not prompting and we're not just stopping,
			// so exit and don't stop
			kmp_prompt_killserver(globalreg, 0, -1, NULL);
		}

		return;
	} else if (opt == mi_connect) {
		Kis_Connect_Panel *cp = new Kis_Connect_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(cp);
	} else if (opt == mi_startserver) {
		Kis_Spawn_Panel *sp = new Kis_Spawn_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(sp);
	} else if (opt == mi_serverconsole) {
		Kis_Console_Panel *cp = new Kis_Console_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(cp);
	} else if (opt == mi_disconnect) {
		if (con) {
			kpinterface->RemoveNetClient();
		}
	} else if (opt == mi_addnote) {
		Kis_AddDevNote_Panel *dp = new Kis_AddDevNote_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(dp);
	} else if (opt == mi_chandetails) {
		Kis_ChanDetails_Panel *dp = new Kis_ChanDetails_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(dp);
	} else if (opt == mi_gps) {
		Kis_Gps_Panel *gp = new Kis_Gps_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(gp);
	} else if (opt == mi_alerts) {
		Kis_AlertDetails_Panel *ap = new Kis_AlertDetails_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(ap);
	} else if (opt == mi_showsummary ||
			   opt == mi_showstatus ||
			   opt == mi_showpps ||
			   opt == mi_showgps ||
			   opt == mi_showbattery ||
			   opt == mi_showsources ||
			   opt == mi_showdevice) {
		UpdateViewMenu(opt);
	} else if (opt == mi_addcard) {
		Kis_AddCard_Panel *acp = new Kis_AddCard_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(acp);
	} else if (opt == mi_conf) {
		Kis_Chanconf_Panel *cp = new Kis_Chanconf_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(cp);
	} else if (opt == mi_addplugin) {
		Kis_Plugin_Picker *pp = new Kis_Plugin_Picker(globalreg, kpinterface);
		kpinterface->AddPanel(pp);
	} else if (opt == mi_colorprefs) {
		SpawnColorPrefs();
	} else if (opt == mi_startprefs) {
		Kis_StartupPref_Panel *sp = new Kis_StartupPref_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(sp);
	} else if (opt == mi_serverprefs) {
		SpawnServerPrefs();
	} else if (opt == mi_infoprefs) {
		SpawnInfoPrefs();
	} else if (opt == mi_gpsprefs) {
		Kis_GpsPref_Panel *pp = new Kis_GpsPref_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(pp);
	} else if (opt == mi_audioprefs) {
		Kis_AudioPref_Panel *pp = new Kis_AudioPref_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(pp);
	} else if (opt == mi_warnprefs) {
		Kis_WarnPref_Panel *pp = new Kis_WarnPref_Panel(globalreg, kpinterface);
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

	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnInfoPrefs() {
	Kis_ColumnPref_Panel *cpp = new Kis_ColumnPref_Panel(globalreg, kpinterface);

	for (unsigned int x = 0; info_bits_details[x][0] != NULL; x++) {
		cpp->AddColumn(info_bits_details[x][0],
					   info_bits_details[x][1]);
	}

	cpp->ColumnPref("netinfo_items", "Info Pane");
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::SpawnServerPrefs() {
	Kis_AutoConPref_Panel *cpp = new Kis_AutoConPref_Panel(globalreg, kpinterface);
	kpinterface->AddPanel(cpp);
}

void Kis_Main_Panel::UpdateViewMenu(int mi) {
	string opt;

	// this gets called pretty rarely so we can resolve the devicelist
	// directly here

#if 0
	if (mi == mi_viewnetworks && !menu->GetMenuItemChecked(mi_viewnetworks)) {
		kpinterface->prefs->SetOpt("MAIN_VIEWSTYLE", "network", 1);
		menu->SetMenuItemChecked(mi_viewnetworks, 1);
		menu->SetMenuItemChecked(mi_viewdevices, 0);

		Kis_Devicelist *devlist = 
			(Kis_Devicelist *) globalreg->FetchGlobal("MAIN_DEVICELIST");
		if (devlist != NULL)
			devlist->SetViewMode(KDL_DISPLAY_NETWORKS);

	} else if (mi == mi_viewdevices && !menu->GetMenuItemChecked(mi_viewdevices)) {
		kpinterface->prefs->SetOpt("MAIN_VIEWSTYLE", "device", 1);
		menu->SetMenuItemChecked(mi_viewnetworks, 0);
		menu->SetMenuItemChecked(mi_viewdevices, 1);

		Kis_Devicelist *devlist = 
			(Kis_Devicelist *) globalreg->FetchGlobal("MAIN_DEVICELIST");
		if (devlist != NULL)
			devlist->SetViewMode(KDL_DISPLAY_DEVICES);
#endif
	if (mi == mi_showsummary) {
		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWSUMMARY");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			kpinterface->prefs->SetOpt("MAIN_SHOWSUMMARY", "false", 1);
			menu->SetMenuItemChecked(mi_showsummary, 0);
			optbox->Hide();
		} else {
			kpinterface->prefs->SetOpt("MAIN_SHOWSUMMARY", "true", 1);
			menu->SetMenuItemChecked(mi_showsummary, 1);
			optbox->Show();
		}
	} else if (mi == mi_showstatus) {
		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWSTATUS");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			kpinterface->prefs->SetOpt("MAIN_SHOWSTATUS", "false", 1);
			menu->SetMenuItemChecked(mi_showstatus, 0);
			statustext->Hide();
		} else {
			kpinterface->prefs->SetOpt("MAIN_SHOWSTATUS", "true", 1);
			menu->SetMenuItemChecked(mi_showstatus, 1);
			statustext->Show();
		}
	} else if (mi == mi_showgps) {
		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWGPS");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			kpinterface->prefs->SetOpt("MAIN_SHOWGPS", "false", 1);
			menu->SetMenuItemChecked(mi_showgps, 0);
			gpsinfo->Hide();
		} else {
			kpinterface->prefs->SetOpt("MAIN_SHOWGPS", "true", 1);
			menu->SetMenuItemChecked(mi_showgps, 1);
			gpsinfo->Show();
		}
	} else if (mi == mi_showbattery) {
		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWBAT");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			kpinterface->prefs->SetOpt("MAIN_SHOWBAT", "false", 1);
			menu->SetMenuItemChecked(mi_showbattery, 0);
			batteryinfo->Hide();
		} else {
			kpinterface->prefs->SetOpt("MAIN_SHOWBAT", "true", 1);
			menu->SetMenuItemChecked(mi_showbattery, 1);
			batteryinfo->Show();
		}
	} else if (mi == mi_showpps) {
		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWPPS");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			kpinterface->prefs->SetOpt("MAIN_SHOWPPS", "false", 1);
			menu->SetMenuItemChecked(mi_showpps, 0);
			packetrate->Hide();
		} else {
			kpinterface->prefs->SetOpt("MAIN_SHOWPPS", "true", 1);
			menu->SetMenuItemChecked(mi_showpps, 1);
			packetrate->Show();
		}
	} else if (mi == mi_showsources) {
		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWSOURCE");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			kpinterface->prefs->SetOpt("MAIN_SHOWSOURCE", "false", 1);
			menu->SetMenuItemChecked(mi_showsources, 0);
			sourceinfo->Hide();
		} else {
			kpinterface->prefs->SetOpt("MAIN_SHOWSOURCE", "true", 1);
			menu->SetMenuItemChecked(mi_showsources, 1);
			sourceinfo->Show();
		}
	}

	if (mi == -1) {
#if 0
		opt = StrLower(kpinterface->prefs->FetchOpt("MAIN_VIEWSTYLE"));
		if (opt == "network") {
			menu->SetMenuItemChecked(mi_viewnetworks, 1);
			menu->SetMenuItemChecked(mi_viewdevices, 0);
		} else if (opt == "device") {
			menu->SetMenuItemChecked(mi_viewnetworks, 0);
			menu->SetMenuItemChecked(mi_viewdevices, 1);
		} else {
			menu->SetMenuItemChecked(mi_viewnetworks, 1);
			menu->SetMenuItemChecked(mi_viewdevices, 0);
		}
#endif

		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWSUMMARY");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			menu->SetMenuItemChecked(mi_showsummary, 1);
			optbox->Show();
		} else {
			menu->SetMenuItemChecked(mi_showsummary, 0);
			optbox->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWSTATUS");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			menu->SetMenuItemChecked(mi_showstatus, 1);
			statustext->Show();
		} else {
			menu->SetMenuItemChecked(mi_showstatus, 0);
			statustext->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWPPS");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			menu->SetMenuItemChecked(mi_showpps, 1);
			packetrate->Show();
		} else {
			menu->SetMenuItemChecked(mi_showpps, 0);
			packetrate->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWGPS");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			menu->SetMenuItemChecked(mi_showgps, 1);
			gpsinfo->Show();
		} else {
			menu->SetMenuItemChecked(mi_showgps, 0);
			gpsinfo->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWBAT");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			menu->SetMenuItemChecked(mi_showbattery, 1);
			batteryinfo->Show();
		} else {
			menu->SetMenuItemChecked(mi_showbattery, 0);
			batteryinfo->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWSOURCE");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			menu->SetMenuItemChecked(mi_showsources, 1);
			sourceinfo->Show();
		} else {
			menu->SetMenuItemChecked(mi_showsources, 0);
			sourceinfo->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("MAIN_SHOWDEVLIST");
		// if (opt == "" || opt == "true") {
		if (StringToBool(opt, 1)) {
			menu->SetMenuItemChecked(mi_showdevice, 1);
			devicelist->Show();
		} else {
			menu->SetMenuItemChecked(mi_showdevice, 0);
			devicelist->Hide();
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

	SetTitle("Connect to Server");

	hostname->SetLabel("Host", LABEL_POS_LEFT);
	hostname->SetTextLen(120);
	hostname->SetCharFilter(FILTER_ALPHANUMSYM);
	hostname->SetText(kpinterface->prefs->FetchOpt("default_host"), -1, -1);

	hostport->SetLabel("Port", LABEL_POS_LEFT);
	hostport->SetTextLen(5);
	hostport->SetCharFilter(FILTER_NUM);
	hostport->SetText(kpinterface->prefs->FetchOpt("default_port"), -1, -1);

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

	SetActiveComponent(hostname);

	Position(WIN_CENTER(8, 40));
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
	check = new Kis_Checkbox(globalreg, this);

	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, PromptButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, PromptButtonCB, this);

	okbutton->SetText("OK");
	cancelbutton->SetText("Cancel");

	ftext->Show();
	okbutton->Show();
	cancelbutton->Show();
	check->Hide();

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
	vbox->Pack_End(check, 0, 0);
	vbox->Pack_End(bbox, 0, 0);

	AddComponentVec(ftext, (KIS_PANEL_COMP_DRAW));
	AddComponentVec(check, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
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
		SetActiveComponent(okbutton);
	} else {
		SetActiveComponent(cancelbutton);
	}
}

void Kis_Prompt_Panel::SetButtonText(string in_oktext, string in_notext) {
	if (in_oktext == "") {
		okbutton->Hide();
		cancelbutton->Show();
		SetActiveComponent(cancelbutton);
	} else if (in_notext == "") {
		cancelbutton->Hide();
		okbutton->Show();
		SetActiveComponent(okbutton);
	}

	cancelbutton->SetText(in_notext);
	okbutton->SetText(in_oktext);
}

void Kis_Prompt_Panel::SetCheckText(string in_text) {
	int rp = 0;

	if (in_text == "" && check->GetVisible() != 0) {
		check->Hide();
		rp = -1;
	} else if (in_text != "" && check->GetVisible() == 0) {
		check->Show();
		rp = 1;
	}

	check->SetText(in_text);
	if (rp)
		Position(WIN_CENTER(sizey + rp, sizex));
}

void Kis_Prompt_Panel::SetChecked(int in_check) {
	check->SetChecked(in_check);
}

void Kis_Prompt_Panel::SetCallback(ksp_prompt_cb in_callback, void *in_auxptr) {
	auxptr = in_auxptr;
	callback = in_callback;
}

void Kis_Prompt_Panel::SetDisplayText(vector<string> in_text) {
	ftext->SetText(in_text);

	unsigned int maxlen = 0;
	for (unsigned int x = 0; x < in_text.size(); x++) 
		if (in_text[x].length() > maxlen)
			maxlen = in_text[x].length();

	Position(WIN_CENTER(in_text.size() + 3 + check->GetVisible(), maxlen + 4));
}

Kis_Prompt_Panel::~Kis_Prompt_Panel() {
	delete bbox;
}

void Kis_Prompt_Panel::ButtonAction(Kis_Panel_Component *component) {
	if (component == okbutton) {
		if (callback != NULL)
			(*callback)(globalreg, 1, check->GetChecked(), auxptr);

		kpinterface->KillPanel(this);
	} else if (component == cancelbutton) {
		if (callback != NULL)
			(*callback)(globalreg, 0, check->GetChecked(), auxptr);

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

	int log = 1;
	string logtitle, argpassed;

	// Wish we could use getopt here but can't figure out a way */
	for (int x = 1; x < globalreg->argc; x++) {
		string vs = string(globalreg->argv[x]);

		if (vs == "-n" || vs == "--no-logging") {
			log = 0;
		} else if (vs == "-t" && x <= (globalreg->argc - 1)) {
			logtitle = string(globalreg->argv[x+1]);
			x++;
		} else {
			argpassed += vs + " ";
		}
	}

	spawn_console = 0;

	// if (kpinterface->prefs->FetchOpt("STARTUP_CONSOLE") == "true" ||
	// 	kpinterface->prefs->FetchOpt("STARTUP_CONSOLE") == "")
	if (kpinterface->prefs->FetchOptBoolean("STARTUP_CONSOLE", 1)) 
		spawn_console = 1;

	options = new Kis_Single_Input(globalreg, this);
	logname = new Kis_Single_Input(globalreg, this);
	cancelbutton = new Kis_Button(globalreg, this);
	okbutton = new Kis_Button(globalreg, this);
	logging_check = new Kis_Checkbox(globalreg, this);
	console_check = new Kis_Checkbox(globalreg, this);

	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpawnButtonCB, this);
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpawnButtonCB, this);
	logging_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpawnButtonCB, this);
	console_check->SetCallback(COMPONENT_CBTYPE_ACTIVATED, SpawnButtonCB, this);

	SetTitle("Start Kismet Server");

	options->SetLabel("Startup Options", LABEL_POS_LEFT);
	options->SetTextLen(120);
	options->SetCharFilter(FILTER_ALPHANUMSYM);

	if (globalreg->argc <= 1) {
		options->SetText(kpinterface->prefs->FetchOpt("default_server_options"), -1, -1);
	} else {
		options->SetText(argpassed, -1, -1);
	}

	logging_check->SetText("Logging");
	logging_check->SetChecked(log);

	logname->SetLabel("Log Title", LABEL_POS_LEFT);
	logname->SetTextLen(64);
	logname->SetCharFilter(FILTER_ALPHA FILTER_NUM);

	if (logtitle == "")
		logname->SetText("Kismet", -1, -1);
	else
		logname->SetText(logtitle, -1, -1);

	console_check->SetText("Show Console");
	console_check->SetChecked(spawn_console);

	okbutton->SetText("Start");
	cancelbutton->SetText("Cancel");

	options->Show();
	okbutton->Show();
	cancelbutton->Show();
	logging_check->Show();
	logname->Show();
	console_check->Show();

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
	vbox->Pack_End(logging_check, 0, 0);
	vbox->Pack_End(logname, 0, 0);
	vbox->Pack_End(console_check, 0, 0);
	vbox->Pack_End(bbox, 1, 0);

	AddComponentVec(options, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(logging_check, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(logname, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(console_check, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(okbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT));

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	main_component = vbox;

	SetActiveComponent(okbutton);

	Position(WIN_CENTER(11, 40));
}

Kis_Spawn_Panel::~Kis_Spawn_Panel() {
	delete bbox;
}

void Kis_Spawn_Panel::ButtonAction(Kis_Panel_Component *component) {
	if (component == okbutton) {
		string opt = options->GetText();
		
		if (logging_check->GetChecked()) {
			opt += " -t " + logname->GetText();
		} else {
			opt += " -n";
		}

		kpinterface->SpawnServer(opt);
		kpinterface->KillPanel(this);

		if (console_check->GetChecked()) {
			Kis_Console_Panel *cp = new Kis_Console_Panel(globalreg, kpinterface);
			kpinterface->AddPanel(cp);
		}
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

	SetTitle("Kismet Server Console");

	// Import the existing console
	constext->SetFollowTail(1);
	constext->SetMaxText(250);
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

	SetActiveComponent(constext);

	main_component = vbox;

	Position(WIN_CENTER(LINES, COLS));
}

Kis_Console_Panel::~Kis_Console_Panel() {
	if (kpinterface->FetchServerFramework() != NULL)  {
		kpinterface->FetchServerFramework()->RemoveCallback(textcb);
	}
}

void Kis_Console_Panel::ButtonAction(Kis_Panel_Component *component) {
	if (component == okbutton) {
		kpinterface->KillPanel(this);
	}

	if (component == killbutton) {
		kpinterface->KillServer();
	}
}

void Kis_Console_Panel::AddConsoleText(string in_text) {
	constext->AppendText(in_text);
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

	SetTitle("Add Source");

	srciface->SetLabel("Intf", LABEL_POS_LEFT);
	srciface->SetTextLen(128);
	srciface->SetCharFilter(FILTER_ALPHANUMSYM);
	srciface->Show();
	
	srcname->SetLabel("Name", LABEL_POS_LEFT);
	srcname->SetTextLen(32);
	srcname->SetCharFilter(FILTER_ALPHANUMSYM);
	srcname->Show();

	srcopts->SetLabel("Opts", LABEL_POS_LEFT);
	srcopts->SetTextLen(128);
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

	target_cli = kpinterface->FetchNetClient();

	SetActiveComponent(srciface);

	main_component = vbox;

	Position(WIN_CENTER(10, 40));
}

Kis_AddCard_Panel::~Kis_AddCard_Panel() {
}

void Kis_AddCard_Panel::DrawPanel() {
	if (kpinterface->FetchNetConnected() == 0) {
		kpinterface->RaiseAlert("Not connected", 
								"Not connected to a Kismet server, sources can\n"
								"only be added once a connection has been made.");
		kpinterface->KillPanel(this);
		return;
	}

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

void kpp_proto_PLUGIN_complete(CLICMD_CB_PARMS) {
	((Kis_Plugin_Picker *) auxptr)->Proto_PLUGIN_complete();
}

void kpp_proto_PLUGIN(CLIPROTO_CB_PARMS) {
	((Kis_Plugin_Picker *) auxptr)->Proto_PLUGIN(globalreg, proto_string,
												 proto_parsed, srccli, auxptr);
}

void kpp_netclinetconfigured(CLICONF_CB_PARMS) {
	// Register the plugin handler with an ENABLE complete to notify us when we've
	// finished getting our list of initial plugins
	if (kcli->RegisterProtoHandler("PLUGIN", "name,version,description",
								   kpp_proto_PLUGIN, auxptr, 
								   kpp_proto_PLUGIN_complete) < 0) {
		_MSG("Could not register PLUGIN protocol with remote server, "
			 "connection will be terminated.", MSGFLAG_ERROR);
		kcli->KillConnection();
	}
}

void kpp_netcliadd(KPI_ADDCLI_CB_PARMS) {
	if (add) 
		netcli->AddConfCallback(kpp_netclinetconfigured, 1, auxptr);
}

Kis_Plugin_Picker::Kis_Plugin_Picker(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	pluglist = new Kis_Scrollable_Table(globalreg, this);

	srv_plugin_info = 0;

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 40;
	t.title = "Client Plugin";
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
	pluglist->SetPreferredSize(0, 10);
	AddComponentVec(pluglist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));


	vector<string> ht;

	helptext = new Kis_Free_Text(globalreg, this);
	helptext->Show();
	ht.push_back("For more information about Kismet UI plugins see the README");
	ht.push_back("Select a plugin and press enter to toggle loaded/unloaded");
	ht.push_back("Kismet UI Plugins:");
	helptext->SetText(ht);
	AddComponentVec(helptext, (KIS_PANEL_COMP_DRAW));

	ht.clear();
	shelptext = new Kis_Free_Text(globalreg, this);
	shelptext->Show();
	ht.push_back("");
	ht.push_back("Server plugins cannot currently be loaded/unloaded from the UI");
	ht.push_back("Kismet Server Plugins:");
	shelptext->SetText(ht);
	AddComponentVec(shelptext, (KIS_PANEL_COMP_DRAW));

	spluglist = new Kis_Scrollable_Table(globalreg, this);

	titles.clear();

	t.width = 20;
	t.title = "Server Plugin";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 9;
	t.title = "Version";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 0;
	t.title = "Description";
	t.alignment = 0;
	titles.push_back(t);

	spluglist->AddTitles(titles);
	spluglist->Show();
	AddComponentVec(spluglist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	spluglist->SetPreferredSize(0, 4);

	okbutton = new Kis_Button(globalreg, this);
	okbutton->SetText("Close");
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, PluginPickerButtonCB, this);
	okbutton->Show();
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));


	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->SetCenter(0);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	vbox->Pack_End(helptext, 0, 0);
	vbox->Pack_End(pluglist, 1, 0);

	vbox->Pack_End(shelptext, 0, 0);
	vbox->Pack_End(spluglist, 1, 0);
	vbox->Pack_End(okbutton, 0, 0);

	vbox->Show();

	plugins = kpinterface->FetchPluginVec();

	vector<string> td;

	if (kpinterface->FetchNetClient() == NULL) {
		td.push_back("");
		td.push_back("");
		td.push_back("No server connection");
		spluglist->ReplaceRow(0, td);
	} else {
		td.push_back("");
		td.push_back("");
		td.push_back("Loading list of Server plugins...");
		spluglist->ReplaceRow(0, td);
	}

	for (unsigned int x = 0; x < plugins->size(); x++) {
		vector<string> prefs = kpinterface->prefs->FetchOptVec("plugin_autoload");
		string en = "";

		td.clear();

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

	SetActiveComponent(pluglist);

	main_component = vbox;

	SetTitle("");

	net_plugin_ref = 
		kpinterface->Add_NetCli_AddCli_CB(kpp_netcliadd, (void *) this);

	Position(WIN_CENTER(20, 70));
}

Kis_Plugin_Picker::~Kis_Plugin_Picker() {
	kpinterface->Remove_Netcli_AddCli_CB(net_plugin_ref);
	kpinterface->Remove_All_Netcli_Conf_CB(kpp_netclinetconfigured);
	kpinterface->Remove_All_Netcli_ProtoHandler("PLUGIN", kpp_proto_PLUGIN, this);
	kpinterface->Remove_All_Netcli_Cmd_CB(kpp_proto_PLUGIN_complete, this);
}

void Kis_Plugin_Picker::Proto_PLUGIN(CLIPROTO_CB_PARMS) {
	// Bad kluge; plugin only sends on enable, but this is a bad assumption to
	// make.  We'll make it anyway.
	if (proto_parsed->size() < 3)
		return;

	vector<string> td;

	td.push_back((*proto_parsed)[0].word);
	td.push_back((*proto_parsed)[1].word);
	td.push_back((*proto_parsed)[2].word);

	spluglist->ReplaceRow(srv_plugin_info++, td);
}

void Kis_Plugin_Picker::Proto_PLUGIN_complete() {
	// Kick "no plugins" text on the server plugin table if we don't have
	// any, we only et here once ENABLE is done sending our initial *PLUGIN list
	if (srv_plugin_info == 0) {
		vector<string> td;
		td.push_back("");
		td.push_back("");
		td.push_back("No plugins loaded");
	}
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

		kpinterface->prefs->SetOptVec("plugin_autoload", autoload, 1);

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

	SetActiveComponent(cardlist);

	last_selected = 0;
	radio_changed = 0;
	last_radio = lockrad;

	main_component = vbox;

	Position(WIN_CENTER(14, 50));
}

Kis_Chanconf_Panel::~Kis_Chanconf_Panel() {

}

void Kis_Chanconf_Panel::DrawPanel() {
	if (kpinterface->FetchNetConnected() == 0) {
		kpinterface->RaiseAlert("Not connected", 
								"Not connected to a Kismet server, channels can\n"
								"only be configured once a connection has been made.");
		kpinterface->KillPanel(this);
		return;
	}

	map<uuid, KisPanelInterface::knc_card *> *cardmap =
		kpinterface->FetchNetCardMap();

	vector<string> td;

	for (map<uuid, KisPanelInterface::knc_card *>::iterator x = cardmap->begin();
		 x != cardmap->end(); ++x) {
		// Did we have a "no cards" row?
		int sel = cardlist->DelRow(0);

		td.clear();

		td.push_back(x->second->name);
		if (x->second->hopping)
			td.push_back("Hop");
		else
			td.push_back(IntToString(x->second->channel));

		cardlist->ReplaceRow(x->second->uuid_hash, td);

		// If we had a no cards row, we need to select the first row we add
		if (sel == 1) {
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
				inpchannel->SetCharFilter(string(FILTER_NUM) + "range-,:");
				inpchannel->SetText(card->channellist, -1, -1);
				inpchannel->Show();

				inprate->SetLabel("Dwell", LABEL_POS_LEFT);
				inprate->SetTextLen(3);
				inprate->SetCharFilter(FILTER_NUM);
				inprate->SetText(IntToString(card->dwell), -1, -1);
				inprate->Show();

			} else if (card->hopping) {
				hoprad->SetChecked(1);
				last_radio = hoprad;

				inpchannel->SetLabel("Channels", LABEL_POS_LEFT);
				inpchannel->SetTextLen(256);
				inpchannel->SetCharFilter(string(FILTER_NUM) + "range-,:");
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
					// TODO get channel of selected device
					inpchannel->SetText("6", -1, -1);

					/*
					if (kpinterface->FetchMainPanel()->FetchDisplayNetlist()->FetchSelectedNetgroup() != NULL)
						inpchannel->SetText(IntToString(kpinterface->FetchMainPanel()->FetchDisplayNetlist()->FetchSelectedNetgroup()->FetchNetwork()->channel), -1, -1);
					else
						inpchannel->SetText("6", -1, -1);
						*/
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
				inprate->SetText(IntToString(card->dwell), -1, -1);
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

		if (kpinterface->FetchNetConnected() == 0) {
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

			kpinterface->FetchNetClient()->InjectCommand("HOPSOURCE " + 
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
				kpinterface->FetchNetClient()->InjectCommand("CHANSOURCE " +
					card->carduuid.UUID2String() + " " + inpchannel->GetText());

			kpinterface->FetchNetClient()->InjectCommand("HOPSOURCE " + 
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
	"connected", "fix", "lat", "lon", "alt", "spd", "satinfo", NULL
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
	gpslocinfo->SetText("No GPS data (GPS not connected)");
	gpslocinfo->Show();

	gpsmoveinfo = new Kis_Free_Text(globalreg, this);
	gpsmoveinfo->Show();

	gpssatinfo = new Kis_Free_Text(globalreg, this);
	gpssatinfo->Show();

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

	SetActiveComponent(okbutton);

	addref = 
		kpinterface->Add_NetCli_AddCli_CB(GpsCliAdd, (void *) this);

	agg_gps_num = TokenNullJoin(&agg_gps_fields, gpsinfo_fields);

	main_component = vbox;

	Position(WIN_CENTER(20, 60));
}

Kis_Gps_Panel::~Kis_Gps_Panel() {
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(GpsCliConfigured);
	kpinterface->Remove_All_Netcli_ProtoHandler("GPS", GpsProtoGPS, this);
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

	int fnum = 0, fix, connected;
	float lat, lon, alt, spd;

	string gpstext;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &connected) != 1)
		return;

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

	int eng = StrLower(kpinterface->prefs->FetchOpt("GPSUNIT")) != "metric";

	// Convert speed to m/hr
	spd *= 3600;

	if (eng) {
		// Convert speed to feet/hr
		spd *= 3.2808;
		// Convert alt to feet
		alt *= 3.2808;
	}

	if (connected == 0) {
		gpslocinfo->SetText("No GPS data (GPS not connected)");
		gpsmoveinfo->SetText("");
		return;
	}

	if (fix < 2) {
		gpslocinfo->SetText("No position (GPS does not have signal)");
		gpsmoveinfo->SetText("");
	} else {
		gpstext = string("Lat ") + 
			NtoString<float>(lat, 6).Str() + string(" Lon ") + 
			NtoString<float>(lon, 6).Str();
		gpslocinfo->SetText(gpstext);

		if (eng) {
			// Reset gpstext for locinfo
			if (spd > 2500)
				gpstext = "Spd: " + NtoString<float>(spd / 5280, 2).Str() + " mph ";
			else
				gpstext = "Spd: " + NtoString<float>(spd, 2).Str() + " fph ";

			if (alt > 2500)
				gpstext += "Alt: " + NtoString<float>(alt / 5280, 2).Str() + " m ";
			else
				gpstext += "Alt: " + NtoString<float>(alt, 2).Str() + " ft ";
		} else {
			// Reset gpstext for locinfo
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

	gpssatinfo->SetText(IntToString(sat_info_vec.size()) + " satellites" +
						(fix >= 2 ? string(", ") + IntToString(fix) + string("d fix") : 
						", No position"));
	gpssiggraph->SetXLabels(sat_label_vec, "PRN SNR");
}

int AddDevNoteCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_AddDevNote_Panel *) aux)->Action(component, status);
	return 1;
}

Kis_AddDevNote_Panel::Kis_AddDevNote_Panel(GlobalRegistry *in_globalreg, 
										   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	notetxt = new Kis_Single_Input(globalreg, this);
	notetxt->SetLabel("Note", LABEL_POS_LEFT);
	notetxt->SetCharFilter(FILTER_ALPHANUMSYM);
	notetxt->SetTextLen(256);
	AddComponentVec(notetxt, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));
	notetxt->Show();

	permanent = new Kis_Checkbox(globalreg, this);
	permanent->SetLabel("Remember note when restarting Kismet");
	permanent->SetChecked(1);
	AddComponentVec(permanent, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								KIS_PANEL_COMP_TAB));
	permanent->Show();

	okbutton = new Kis_Button(globalreg, this);
	okbutton->SetLabel("Add Note");
	okbutton->Show();
	okbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AddDevNoteCB, this);
	AddComponentVec(okbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							   KIS_PANEL_COMP_TAB));
	okbutton->Show();

	cancelbutton = new Kis_Button(globalreg, this);
	cancelbutton->SetLabel("Cancel");
	cancelbutton->Show();
	cancelbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AddDevNoteCB, this);
	AddComponentVec(cancelbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								   KIS_PANEL_COMP_TAB));

	delbutton = new Kis_Button(globalreg, this);
	delbutton->SetLabel("Delete Note");
	delbutton->Show();
	delbutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AddDevNoteCB, this);
	AddComponentVec(delbutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								KIS_PANEL_COMP_TAB));

	bbox = new Kis_Panel_Packbox(globalreg, this);
	bbox->SetPackH();
	bbox->SetHomogenous(1);
	bbox->SetSpacing(0);
	bbox->SetCenter(1);
	bbox->Show();
	AddComponentVec(bbox, KIS_PANEL_COMP_DRAW);

	bbox->Pack_End(delbutton, 0, 0);
	bbox->Pack_End(cancelbutton, 0, 0);
	bbox->Pack_End(okbutton, 0, 0);

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(1);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);
	vbox->Show();

	vbox->Pack_End(notetxt, 0, 0);
	vbox->Pack_End(permanent, 0, 0);
	vbox->Pack_End(bbox, 0, 0);

	main_component = vbox;
	SetActiveComponent(notetxt);

	Position(WIN_CENTER(7, 60));
}

Kis_AddDevNote_Panel::~Kis_AddDevNote_Panel() {

}

void Kis_AddDevNote_Panel::DrawPanel() {
	// TODO - Fix
#if 0
	if (dng == NULL) {
		if ((dng = kpinterface->FetchMainPanel()->FetchSelectedNetgroup()) == NULL) {
			kpinterface->RaiseAlert("No network",
									"Cannot add a note, no network was selected.\n"
									"Set the Sort type to anything besides Auto-Fit\n"
									"and highlight a network, then add a note.\n");
			kpinterface->KillPanel(this);
			return;
		}

		Netracker::tracked_network *meta = dng->FetchNetwork();

		if (meta == NULL) {
			kpinterface->RaiseAlert("No network",
									"Cannot add a note, no network was selected.\n"
									"Set the Sort type to anything besides Auto-Fit\n"
									"and highlight a network, then add a note.\n");
			kpinterface->KillPanel(this);
			return;
		}

		string oldnote = "";
		for (map<string, string>::const_iterator si = meta->arb_tag_map.begin();
			 si != meta->arb_tag_map.end(); ++si) {
			if (si->first == "User Note") {
				oldnote = si->second;
				break;
			}
		}

		bssid = meta->bssid;

		notetxt->SetText(oldnote, -1, -1);
	}

#endif

	Kis_Panel::DrawPanel();
}

void Kis_AddDevNote_Panel::Action(Kis_Panel_Component *in_button, int in_state) {
	if (in_button == cancelbutton) {
		kpinterface->KillPanel(this);
	} else if (in_button == delbutton) {
		if (kpinterface->FetchNetClient() == NULL) {
			kpinterface->RaiseAlert("No connection",
									"No longer connected to a Kismet server, cannot\n"
									"remove a note from a network.\n");
			kpinterface->KillPanel(this);
			return;
		}

		kpinterface->FetchNetClient()->InjectCommand("DELNETTAG " +
							bssid.Mac2String() + " \001User Note\001");

		kpinterface->KillPanel(this);

	} else if (in_button == okbutton) {
		if (kpinterface->FetchNetClient() == NULL) {
			kpinterface->RaiseAlert("No connection",
									"No longer connected to a Kismet server, cannot\n"
									"add a note to a network.\n");
			kpinterface->KillPanel(this);
			return;
		}

		string perm = "0";
		if (permanent->GetChecked())
			perm = "1";

		kpinterface->FetchNetClient()->InjectCommand("ADDDEVTAG " +
							bssid.Mac2String() + " " + 
							IntToString(bssid.GetPhy()) + " " + 
							perm + " \001User Note\001 " +
							"\001" + notetxt->GetText() + "\001");

		kpinterface->KillPanel(this);
		return;
	}
}


#endif

