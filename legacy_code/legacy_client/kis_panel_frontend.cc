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

#include <sys/stat.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <dirent.h>

#include "util.h"
#include "messagebus.h"
#include "kis_panel_widgets.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"
#include "version.h"

#define KPI_SOURCE_FIELDS	"uuid,interface,type,username,channel,packets,hop," \
	"velocity,dwell,hop_time_sec,hop_time_usec,channellist,error,warning"

#define KPI_ALERT_FIELDS	"sec,usec,header,bssid,source,dest,other,channel,text"

// STATUS protocol parser that injects right into the messagebus
void KisPanelClient_STATUS(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < 2) {
		return;
	}

	int flags;
	string text;

	text = (*proto_parsed)[0].word;

	if (sscanf((*proto_parsed)[1].word.c_str(), "%d", &flags) != 1) {
		return;
	}

	_MSG(text, flags);
}

void KisPanelClient_SOURCE(CLIPROTO_CB_PARMS) {
	// Pass it off to the clinet frame
	((KisPanelInterface *) auxptr)->proto_SOURCE(globalreg, proto_string,
												 proto_parsed, srccli, auxptr);
}

void KisPanelClient_ALERT(CLIPROTO_CB_PARMS) {
	((KisPanelInterface *) auxptr)->proto_ALERT(globalreg, proto_string,
												proto_parsed, srccli, auxptr);
}

void KisPanelClient_INFO(CLIPROTO_CB_PARMS) {
	((KisPanelInterface *) auxptr)->proto_INFO(globalreg, proto_string,
											   proto_parsed, srccli, auxptr);
}

void kpi_prompt_sourcewarnings(KIS_PROMPT_CB_PARMS) {
	if (check) 
		globalreg->panel_interface->prefs->SetOpt("WARN_SOURCEWARN", "false", 1);
}

void KisPanelInterface::proto_SOURCE(CLIPROTO_CB_PARMS) {
	// "uuid,interface,type,username,channel,packets,hop," 
	//	"velocity,dwell,hop_time_sec,hop_time_usec,channellist,
	//	error,warning"

	if (proto_parsed->size() < 14) {
		return;
	}

	int fnum = 0;
	int tint;

	knc_card *source = NULL;

	uuid inuuid = uuid((*proto_parsed)[fnum++].word);

	if (inuuid.error)
		return;

	if (netcard_map.find(inuuid) == netcard_map.end()) {
		source = new knc_card;
		source->carduuid = inuuid;
		source->uuid_hash = Adler32Checksum(inuuid.UUID2String().c_str(),
											inuuid.UUID2String().length());
		netcard_map[inuuid] = source;
	} else {
		source = netcard_map.find(inuuid)->second;
	}

	source->last_update = time(0);

	source->interface = ((*proto_parsed)[fnum++].word);
	source->type = ((*proto_parsed)[fnum++].word);
	source->name = ((*proto_parsed)[fnum++].word);
	
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	source->channel = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	source->packets = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	source->hopping = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	source->hopvelocity = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	source->dwell = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	source->hop_tm.tv_sec = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	source->hop_tm.tv_usec = tint;

	source->channellist = (*proto_parsed)[fnum++].word;

	source->error = (*proto_parsed)[fnum++].word == "1";

	string warning = (*proto_parsed)[fnum++].word;
	
	if (warning != "" && warning != source->warning && 
		prefs->FetchOpt("WARN_SOURCEWARN") != "false") {

		vector<string> t;

		t = StrTokenize(InLineWrap(warning, 0, 50), "\n");
		Kis_Prompt_Panel *kpp =
			new Kis_Prompt_Panel(globalreg, this);

		kpp->SetTitle("Sources Warning");
		kpp->SetDisplayText(t);
		kpp->SetCheckText("Do not show source warnings in the future");
		kpp->SetChecked(0);
		kpp->SetDefaultButton(1);
		kpp->SetButtonText("OK", "");
		kpp->SetCallback(kpi_prompt_sourcewarnings, this);
		QueueModalPanel(kpp);
	}

	source->warning = warning;

}

void KisPanelInterface::proto_ALERT(CLIPROTO_CB_PARMS) {
	// sec, usec, header, bssid, source, dest, other, channel, text
	
	if (proto_parsed->size() < 9) {
		return;
	}

	int fnum = 0;
	int tint;
	unsigned int tuint;
	mac_addr tmac;

	knc_alert *alert = new knc_alert;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) {
		delete alert;
		return;
	}
	alert->tv.tv_sec = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) {
		delete alert;
		return;
	}
	alert->tv.tv_usec = tuint;

	alert->alertname = MungeToPrintable((*proto_parsed)[fnum++].word);

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		delete alert;
		return;
	}
	alert->bssid = tmac;

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		delete alert;
		return;
	}
	alert->source = tmac;

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		delete alert;
		return;
	}
	alert->dest = tmac;

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		delete alert;
		return;
	}
	alert->other = tmac;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		delete alert;
		return;
	}
	alert->channel = tint;

	alert->text = (*proto_parsed)[fnum++].word;

	alert_vec.push_back(alert);
}

void kpi_prompt_addsource(KIS_PROMPT_CB_PARMS) {
	if (ok && globalreg->panel_interface->FetchNetClient() != NULL) {
		Kis_AddCard_Panel *acp = 
			new Kis_AddCard_Panel(globalreg, globalreg->panel_interface);
		globalreg->panel_interface->AddPanel(acp);
	}
}

void kpi_prompt_warnallerr(KIS_PROMPT_CB_PARMS) {
	if (check)
		globalreg->panel_interface->prefs->SetOpt("WARN_ALLERRSOURCE", "false", 1);

	((KisPanelInterface *) auxptr)->ResetWarnAllClear();
}

void KisPanelInterface::proto_INFO(CLIPROTO_CB_PARMS) {
	// Numsources,numerrorsources

	if (proto_parsed->size() < 1) {
		return;
	}

	int fnum = 0;
	int ns = 0, ne = 0;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &ns) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &ne) != 1)
		return;

	if (ns != 0 && ne >= ns)
		warned_all_errors_consec++;
	else
		warned_all_errors_consec = 0;

	// If we've found all our defined sources, make sure they're not all in
	// an error state
	if (ns != 0 && time(0) - warned_all_errors > 60 && 
		warned_cleared && ne >= ns && warned_all_errors_consec > 20 && 
		prefs->FetchOpt("WARN_ALLERRSOURCE") != "false") {

		warned_all_errors = time(0);
		warned_all_errors_consec = 0;

		vector<string> t;

		t.push_back("All packet sources are in error state.");
		t.push_back("Kismet will not be able to capture any data");
		t.push_back("until a packet source is out of error mode.");
		t.push_back("In most cases Kismet will continue to try to");
		t.push_back("re-enable errored packet sources.");

		Kis_Prompt_Panel *kpp =
			new Kis_Prompt_Panel(globalreg, this);
		kpp->SetTitle("Sources Failed");
		kpp->SetDisplayText(t);
		kpp->SetCheckText("Do not show this warning in the future");
		kpp->SetChecked(0);
		kpp->SetDefaultButton(1);
		kpp->SetButtonText("OK", "");
		QueueModalPanel(kpp);
	}

	// If we have no sources and we haven't warned the user about that, do so
	if (ns == 0 && warned_no_sources == 0) {
		warned_no_sources = 1;

		vector<string> t;

		t.push_back("Kismet started with no packet sources defined.");
		t.push_back("No sources were defined or all defined sources");
		t.push_back("encountered unrecoverable errors.");
		t.push_back("Kismet will not be able to capture any data until");
		t.push_back("a capture interface is added.  Add a source now?");

		Kis_Prompt_Panel *kpp =
			new Kis_Prompt_Panel(globalreg, this);
		kpp->SetTitle("No sources");
		kpp->SetDisplayText(t);
		kpp->SetCallback(kpi_prompt_addsource, this);
		kpp->SetButtonText("Yes", "No");
		kpp->SetDefaultButton(1);
		QueueModalPanel(kpp);
	}

}

void KisPanelClient_Configured(CLICONF_CB_PARMS) {
	((KisPanelInterface *) auxptr)->NetClientConfigure(kcli, recon);
}

KisPanelInterface::KisPanelInterface() {
	fprintf(stderr, "FATAL OOPS: KisPanelInterface not called with globalreg\n");
	exit(-1);
}

KisPanelInterface::KisPanelInterface(GlobalRegistry *in_globalreg) :
	PanelInterface(in_globalreg) {
	globalreg = in_globalreg;

	globalreg->InsertGlobal("KIS_PANEL_INTERFACE", this);

	network_client = NULL;

	prefs = new ConfigFile(globalreg);

	shutdown_mode = 0;

	// Load the preferences file
	LoadPreferences();

	// Update the plugin dirs if we didn't get them
	if (prefs->FetchOptVec("PLUGINDIR").size() == 0) {
		vector<string> pdv;
		pdv.push_back("%h/.kismet/client_plugins/");
		pdv.push_back(string(LIB_LOC) + "/kismet_client/");
		prefs->SetOptVec("PLUGINDIR", pdv, 1);
	}

	// Initialize the plugin data record.  The first panel to get added
	// to us is the main panel.
	plugdata.kpinterface = this;
	plugdata.mainpanel = NULL;
	plugdata.globalreg = globalreg;

	// Fill the plugin paths if they haven't been found
	ScanPlugins();

	addcb_ref = 0;

	mainp = NULL;

	server_framework = NULL;
	server_popen = NULL;
	server_text_cb = -1;

	warned_no_sources = 0;
	warned_all_errors = warned_all_errors_consec = 0;
	warned_cleared = 1;

	endwin();
}

KisPanelInterface::~KisPanelInterface() {
	Shutdown();

	globalreg->InsertGlobal("KIS_PANEL_INTERFACE", NULL);

	delete network_client;
}

void KisPanelInterface::Shutdown() {
	SavePreferences();

	Remove_All_Netcli_Conf_CB(KisPanelClient_Configured);

	Remove_All_Netcli_ProtoHandler("STATUS", KisPanelClient_STATUS, this);
	Remove_All_Netcli_ProtoHandler("SOURCE", KisPanelClient_SOURCE, this);
	Remove_All_Netcli_ProtoHandler("INFO", KisPanelClient_INFO, this);
	Remove_All_Netcli_ProtoHandler("ALERT", KisPanelClient_ALERT, this);

	// Destroy panels in this destructor, if they get destroyed in the
	// parent destructor sadness happens
	for (unsigned int x = 0; x < live_panels.size(); x++)
		KillPanel(live_panels[x]);

	// we don't kill the clients since we might still be issuing shutdown
	// commands

	// we don't kill the server if it exists, but we do kill the callback
	// referencing ourselves
	if (server_framework != NULL)
		server_framework->RemoveCallback(server_text_cb);

	shutdown_mode = 1;
}

int KisPanelInterface::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
	if (shutdown_mode)
		return in_max_fd;

	return PanelInterface::MergeSet(in_max_fd, out_rset, out_wset);
}

int KisPanelInterface::Poll(fd_set& in_rset, fd_set& in_wset) {
	if (shutdown_mode)
		return 0;

	return PanelInterface::Poll(in_rset, in_wset);
}

void KisPanelInterface::AddPanel(Kis_Panel *in_panel) {
	in_panel->ShowPanel();

	PanelInterface::AddPanel(in_panel);

	if (plugdata.mainpanel == NULL)
		plugdata.mainpanel = (Kis_Main_Panel *) in_panel;

	if (mainp == NULL)
		mainp = (Kis_Main_Panel *) in_panel;
}

void KisPanelInterface::KillPanel(Kis_Panel *in_panel) {
	// Kill the panel (this will delete it so be careful)
	PanelInterface::KillPanel(in_panel);

	// If it's a modal panel, remove it from the modal vec list.  We only ever display
	// the head of the modal vec list, so this check is sane.  We're also only doing
	// a pointer compare, so it being destroyed above is also sane
	if (modal_vec.size() > 0 && modal_vec[0] == in_panel) {
		modal_vec.erase(modal_vec.begin());

		// If we have another modal alert queued, put it up
		if (modal_vec.size() > 0)
			AddPanel(modal_vec[0]);
	}

}

int KisPanelInterface::LoadPreferences() {
	if (prefs->ParseConfig(prefs->ExpandLogPath("%h/.kismet/kismet_ui.conf",
												"", "", 0, 1).c_str()) >= 0) {
		prefs->SetOpt("LOADEDFROMFILE", "1", 0);
	} 

	SavePreferences();

	return 1;
}

int KisPanelInterface::SavePreferences() {
	// Try to make the dir
	int ret;

	string dir = prefs->ExpandLogPath("%h/.kismet", "", "", 0, 1);

	ret = mkdir(dir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR);

	if (ret < 0 && errno != EEXIST) {
		string err = string(strerror(errno));
		_MSG("Failed to create dir " + dir + ": " + err,
			 MSGFLAG_ERROR);

		RaiseAlert("Could not save prefs",
					"Could not save preferences file, failed to create\n"
					"directory " + dir + ":\n"
					"  " + err + "\n"
					"Kismet will continue to run, however changes to\n"
					"preferences will not be saved.\n");

		return -1;
	}

	ret = prefs->SaveConfig(prefs->ExpandLogPath("%h/.kismet/kismet_ui.conf",
											   "", "", 0, 1).c_str());

	if (ret < 0)
		RaiseAlert("Could not save prefs",
				   "Could not save the preferences file, check error\n"
				   "messages.  Kismet will continue to run, however\n"
				   "preference changes will not be preserved.\n");

	return ret;
}

int KisPanelInterface::AddNetClient(string in_host, int in_reconnect) {
	if (network_client != NULL)
		delete network_client;

	KisNetClient *netcl = new KisNetClient(globalreg);

	network_client = netcl;

	netcl->AddConfCallback(KisPanelClient_Configured, 1, this);

	for (unsigned int x = 0; x < addclicb_vec.size(); x++)
		(*(addclicb_vec[x]->cb))(globalreg, netcl, 1, 
								 addclicb_vec[x]->auxptr);

	return netcl->Connect(in_host, in_reconnect);
}

void KisPanelInterface::RemoveNetClient() {
	if (network_client != NULL) {
		for (unsigned int c = 0; c < addclicb_vec.size(); c++)
			(*(addclicb_vec[c]->cb))(globalreg, network_client, 0, 
									 addclicb_vec[c]->auxptr);
		delete network_client;
		network_client = NULL;
	}

	return;
}

void KisPanelInterface::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	// Reset the card list.  This assumes we only ever have one client, which
	// is the case despite the stubs for multi-client.  Sorry.  We do this here
	// so we don't get deltas before the reconnect event in configure.  
	for (map<uuid, KisPanelInterface::knc_card *>::iterator x = netcard_map.begin();
		 x != netcard_map.end(); ++x) {
		delete x->second;
	}
	netcard_map.clear();

	warned_no_sources = 0;
	warned_all_errors = warned_all_errors_consec = 0;
	warned_cleared = 1;

	_MSG("Got configure event for client", MSGFLAG_INFO);

	if (in_cli->RegisterProtoHandler("STATUS", "text,flags",
									 KisPanelClient_STATUS, this) < 0) {
		_MSG("Could not register STATUS protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}

	if (in_cli->RegisterProtoHandler("SOURCE", KPI_SOURCE_FIELDS,
									 KisPanelClient_SOURCE, this) < 0) {
		_MSG("Could not register SOURCE protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}

	if (in_cli->RegisterProtoHandler("INFO", "numsources,numerrorsources",
									 KisPanelClient_INFO, this) < 0) {
		_MSG("Could not register INFO protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}

	if (in_cli->RegisterProtoHandler("ALERT", KPI_ALERT_FIELDS,
									 KisPanelClient_ALERT, this) < 0) {
		_MSG("Could not register ALERT protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
}

int KisPanelInterface::Remove_All_Netcli_ProtoHandler(string in_proto,
													 CliProto_Callback in_cb,
													 void *in_aux) {
	if (network_client != NULL)
		network_client->RemoveProtoHandler(in_proto, in_cb, in_aux);

	return 0;
}

void KisPanelInterface::Remove_All_Netcli_Cmd_CB(CliCmd_Callback in_cb, void *in_aux) {
	if (network_client != NULL)
		network_client->RemoveAllCmdCallbacks(in_cb, in_aux);

	return;
}

void KisPanelInterface::RaiseAlert(string in_title, string in_text) {
	vector<string> t = StrTokenize(in_text, "\n");

	Kis_Prompt_Panel *kpp =
		new Kis_Prompt_Panel(globalreg, this);
	kpp->SetTitle(in_title);
	kpp->SetDisplayText(t);
	kpp->SetButtonText("OK", "");

	if (modal_vec.size() != 0)
		modal_vec.push_back(kpp);
	else
		AddPanel(kpp);
}

void KisPanelInterface::QueueModalPanel(Kis_Panel *in_panel) {
	if (modal_vec.size() > 0) {
		modal_vec.push_back(in_panel);
	} else {
		modal_vec.push_back(in_panel);
		AddPanel(in_panel);
	}
}

map<uuid, KisPanelInterface::knc_card *> *KisPanelInterface::FetchNetCardMap() {
	return &netcard_map;
}

int KisPanelInterface::Add_NetCli_AddCli_CB(KPI_AddCli_Callback in_cb,
											void *in_auxptr) {
	addcli_cb_rec *cbr = new addcli_cb_rec;

	cbr->refnum = addcb_ref;
	cbr->cb = in_cb;
	cbr->auxptr = in_auxptr;

	addcb_ref++;

	addclicb_vec.push_back(cbr);

	// Call it immediately if we're already connected
	if (network_client != NULL) {
		(*(in_cb))(globalreg, network_client, 1, in_auxptr);
	}

	return cbr->refnum;
}

void KisPanelInterface::Remove_Netcli_AddCli_CB(int in_cbref) {
	for (unsigned int x = 0; x < addclicb_vec.size(); x++) {
		if (addclicb_vec[x]->refnum == in_cbref) {
			delete addclicb_vec[x];
			addclicb_vec.erase(addclicb_vec.begin() + x);
			return;
		}
	}
}

void KisPanelInterface::Remove_All_Netcli_Conf_CB(CliConf_Callback in_cb) {
	if (network_client != NULL) {
		network_client->RemoveConfCallback(in_cb);
	}
}

string global_plugin_load;
void PluginClientSignalHandler(int sig) {
	fprintf(stderr, "\n\n"
			"FATAL: Kismet (UI) crashed while loading a plugin...\n"
			"Plugin loading: %s\n\n"
			"This is either a bug in the plugin, or the plugin needs to be recompiled\n"
			"to match the version of Kismet you are using (especially if you are using\n"
			"development versions of Kismet or have recently upgraded.)\n\n"
			"Remove the plugin from the plugins directory to keep it from loading,\n"
			"or manually edit ~/.kismet/kismet_ui.conf and remove the plugin_autoload\n"
			"line to stop Kismet from trying to start it.\n\n",
			global_plugin_load.c_str());
	exit(1);
}

void KisPanelInterface::LoadPlugin(string in_fname, string in_objname) {
	void *dlfile;
	panel_plugin_hook plughook;
#ifdef SYS_CYGWIN
	_sig_func_ptr old_segv = SIG_DFL;
#else
	sig_t old_segv = SIG_DFL;
#endif

	old_segv = signal(SIGSEGV, PluginClientSignalHandler);

	global_plugin_load = in_fname;

	if ((dlfile = dlopen(in_fname.c_str(), RTLD_LAZY)) == NULL) {
		_MSG("Failed to open plugin '" + in_fname + "': " +
			 dlerror(), MSGFLAG_ERROR);
		signal(SIGSEGV, old_segv);
		return;
	}

	// Resolve the version function
	panel_plugin_revisioncall vsym = NULL;	
	if ((vsym = (panel_plugin_revisioncall) dlsym(dlfile, 
											"kis_revision_info")) == NULL) {
		string msg = "Failed to find a Kismet version record in plugin '" + in_fname + 
			 "'.  This plugin has not been "
			 "updated to use the new version API.  Please download the "
			 "latest version, or contact the plugin authors.  Kismet will "
			 "still load this plugin, but BE WARNED, there is no way "
			 "to know if it was compiled for this version of Kismet, and "
			 "crashes may occur.";
		RaiseAlert("Plugin Loading Error", InLineWrap(msg, 0, 50));
	} else {
		// Make a struct of whatever PREV we use, it will tell us what
		// it supports in response.
		panel_plugin_revision *prev = new panel_plugin_revision;
		prev->version_api_revision = KIS_PANEL_PLUGIN_VREVISION;

		(*vsym)(prev);

		if (prev->version_api_revision >= 1) {
			if (prev->major != string(VERSION_MAJOR) ||
				prev->minor != string(VERSION_MINOR) ||
				prev->tiny != string(VERSION_TINY)) {
				string msg = 
					"Failed to load plugin '" + in_fname + 
					"': This plugin was compiled for a different version of "
					"Kismet; Please recompile and reinstall it, or remove "
					"it entirely.";
				_MSG(msg, MSGFLAG_ERROR);

				RaiseAlert("Loading Plugin Failed", InLineWrap(msg, 0, 50));

		    dlclose(dlfile);
				signal(SIGSEGV, old_segv);
				return;
			}
		}

		delete(prev);
	}

	if ((plughook = (panel_plugin_hook) dlsym(dlfile, "panel_plugin_init")) == NULL) {
		_MSG("Failed to find 'panel_plugin_init' function in plugin '" + in_fname + 
			 "': " + strerror(errno), MSGFLAG_ERROR);
		dlclose(dlfile);
		signal(SIGSEGV, old_segv);
		return;
	}

	int ret;
	ret = (*(plughook))(globalreg, &plugdata);

	if (ret < 0) {
		_MSG("Failed to initialize plugin '" + in_fname + "'", MSGFLAG_ERROR);
		dlclose(dlfile);
		signal(SIGSEGV, old_segv);
		return;
	}

	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		if (plugin_vec[x]->filename == in_fname && 
			plugin_vec[x]->objectname == in_objname) {
			plugin_vec[x]->dlfileptr = dlfile;
			break;
		}
	}

	signal(SIGSEGV, old_segv);
}

void KisPanelInterface::ScanPlugins() {
	vector<string> plugdirs = prefs->FetchOptVec("PLUGINDIR");

	for (unsigned int x = 0; x < plugdirs.size(); x++) {
		DIR *plugdir;
		struct dirent *plugfile;
		string expanddir = prefs->ExpandLogPath(plugdirs[x], "", "", 0, 1);

		if ((plugdir = opendir(expanddir.c_str())) == NULL) {
			continue;
		}

		while ((plugfile = readdir(plugdir)) != NULL) {
			int loaded = 0;

			if (plugfile->d_name[0] == '.')
				continue;

			string fname = plugfile->d_name;

			if (fname.find(".so") == fname.length() - 3) {
				for (unsigned int y = 0; y < plugin_vec.size(); y++) {
					if (plugin_vec[y]->filename == expanddir + fname) {
						loaded = 1;
						break;
					}
				}

				if (loaded)
					continue;

				panel_plugin_meta *pm = new panel_plugin_meta;
				pm->filename = expanddir + fname;
				pm->objectname = fname;
				pm->dlfileptr = (void *) 0x0;
				plugin_vec.push_back(pm);
			}
		}

		closedir(plugdir);
	}
}

void KisPanelInterface::LoadPlugins() {
	// Scan for plugins to auto load
	vector<string> plugprefs = prefs->FetchOptVec("plugin_autoload");
	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		for (unsigned int y = 0; y < plugprefs.size(); y++) {
			if (plugin_vec[x]->objectname == plugprefs[y] &&
				plugin_vec[x]->dlfileptr == 0x0) {
				_MSG("Auto-loading plugin '" + plugprefs[y] + "'", MSGFLAG_INFO);
				LoadPlugin(plugin_vec[x]->filename, plugin_vec[x]->objectname);
				break;
			}
		}
	}
}

// keep the last 50 lines of server console for when the window is first opened
void kpi_textcli_consolevec(TEXTCLI_PARMS) {
	vector<string> *console = 
		((KisPanelInterface *) auxptr)->FetchServerConsole();
	console->push_back(text);
	if (console->size() > 100) 
		console->erase(console->begin(), console->begin() + console->size() - 100);
}

void KisPanelInterface::SpawnServer(string in_parm) {
	server_parm = in_parm;
	SpawnServer();
}

void kpi_serverpopen_fail(CLIFRAME_FAIL_CB_PARMS) {
	((KisPanelInterface *) auxptr)->RaiseAlert("Kismet Server Failed",
		InLineWrap("Locally started Kismet server exited unexpectedly "
		"with error " + IntToString(in_errno) + ".  Something "
		"has gone wrong.  Check the Kismet server console for "
		"more information and errors.", 0, 50));
}

void KisPanelInterface::SpawnServer() {
	string servercmd = string(BIN_LOC) + "/kismet_server " + server_parm;

	if (server_framework == NULL) {
		server_framework = new TextCliFrame(globalreg);
		server_popen = new PopenClient(globalreg);

		server_framework->RegisterNetworkClient(server_popen);
		server_framework->RegisterFailCB(kpi_serverpopen_fail, this);
		server_popen->RegisterClientFramework(server_framework);

		server_text_cb = 
			server_framework->RegisterCallback(kpi_textcli_consolevec, this);

		if (server_popen->Connect(servercmd.c_str(), 'r', NULL, NULL) < 0) {
			_MSG("Failed to launch kismet_server", MSGFLAG_ERROR);
			delete server_popen;
			delete server_framework;
			server_popen = NULL;
			server_framework = NULL;
		}
	}
}

void KisPanelInterface::KillServer() {
	if (server_framework != NULL) {
		server_popen->SoftKillConnection();
		server_framework->RemoveCallback(server_text_cb);
	}
}

#endif

