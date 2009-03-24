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

#define KPI_SOURCE_FIELDS	"uuid,interface,type,username,channel,packets,hop," \
	"velocity,dwell,hop_time_sec,hop_time_usec,channellist,error"

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

void KisPanelClient_INFO(CLIPROTO_CB_PARMS) {
	((KisPanelInterface *) auxptr)->proto_INFO(globalreg, proto_string,
											   proto_parsed, srccli, auxptr);
}

void KisPanelInterface::proto_SOURCE(CLIPROTO_CB_PARMS) {
	// "uuid,interface,type,username,channel,packets,hop," 
	//	"velocity,dwell,hop_time_sec,hop_time_usec,channellist"

	if (proto_parsed->size() < 12) {
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

	if (source->error)
		num_source_errors++;
}

void kpi_prompt_addsource(KIS_PROMPT_CB_PARMS) {
	if (ok && globalreg->panel_interface->FetchNetClient() != NULL) {
		Kis_AddCard_Panel *acp = 
			new Kis_AddCard_Panel(globalreg, globalreg->panel_interface);
		globalreg->panel_interface->AddPanel(acp);
	}
}

void KisPanelInterface::proto_INFO(CLIPROTO_CB_PARMS) {
	// Numsources

	if (proto_parsed->size() < 1) {
		return;
	}

	int fnum = 0;
	int tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;

	// If we've found all our defined sources, make sure they're not all in
	// an error state
	if (tint != 0 && warned_all_errors == 0 && num_source_errors == tint) {
		warned_all_errors = 1;

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
		kpp->SetDefaultButton(1);
		kpp->SetButtonText("OK", "");
		AddPanel(kpp);
	}

	num_source_errors = 0;

	// If we have no sources and we haven't warned the user about that, do so
	if (tint == 0 && warned_no_sources == 0) {
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
		AddPanel(kpp);
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

	shutdown_mode = 0;

	// Load the preferences file
	LoadPreferences();

	// Update the plugin dirs if we didn't get them
	if (prefs.FetchOptVec("PLUGINDIR").size() == 0) {
		vector<string> pdv;
		pdv.push_back("%h/.kismet/client_plugins/");
		pdv.push_back(string(LIB_LOC) + "/kismet_client/");
		prefs.SetOptVec("PLUGINDIR", pdv, 1);
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

	endwin();
}

KisPanelInterface::~KisPanelInterface() {
	Shutdown();

	delete network_client;
}

void KisPanelInterface::Shutdown() {
	SavePreferences();

	Remove_All_Netcli_Conf_CB(KisPanelClient_Configured);

	Remove_AllNetcli_ProtoHandler("STATUS", KisPanelClient_STATUS, this);
	Remove_AllNetcli_ProtoHandler("SOURCE", KisPanelClient_SOURCE, this);
	Remove_AllNetcli_ProtoHandler("INFO", KisPanelClient_SOURCE, this);

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

unsigned int KisPanelInterface::MergeSet(unsigned int in_max_fd, fd_set *out_rset, 
										 fd_set *out_wset) {
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
	PanelInterface::AddPanel(in_panel);

	if (plugdata.mainpanel == NULL)
		plugdata.mainpanel = (Kis_Main_Panel *) in_panel;

	if (mainp == NULL)
		mainp = (Kis_Main_Panel *) in_panel;
}

int KisPanelInterface::LoadPreferences() {
	if (prefs.ParseConfig(prefs.ExpandLogPath("%h/.kismet/kismet_ui.conf",
											  "", "", 0, 1).c_str())) 
		prefs.SetOpt("LOADEDFROMFILE", "1", 0);

	return 1;
}

int KisPanelInterface::SavePreferences() {
	// Try to make the dir
	int ret;

	string dir = prefs.ExpandLogPath("%h/.kismet", "", "", 0, 1);

	ret = mkdir(dir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR);

	if (ret < 0 && errno != EEXIST) {
		_MSG("Failed to create dir " + dir + ": " + string(strerror(errno)),
			 MSGFLAG_ERROR);
	}

	ret = prefs.SaveConfig(prefs.ExpandLogPath("%h/.kismet/kismet_ui.conf",
											   "", "", 0, 1).c_str());

	return ret;
}

int KisPanelInterface::AddNetClient(string in_host, int in_reconnect) {
	KisNetClient *netcl = new KisNetClient(globalreg);

	netcl->AddConfCallback(KisPanelClient_Configured, 1, this);

	for (unsigned int x = 0; x < addclicb_vec.size(); x++)
		(*(addclicb_vec[x]->cb))(globalreg, netcl, 1, 
								 addclicb_vec[x]->auxptr);

	if (netcl->Connect(in_host, in_reconnect) < 0)
		return -1;

	if (network_client != NULL)
		delete network_client;

	network_client = netcl;

	return 1;
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
	warned_all_errors = 0;

	if (in_recon)
		return;

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

	if (in_cli->RegisterProtoHandler("INFO", "numsources",
									 KisPanelClient_INFO, this) < 0) {
		_MSG("Could not register INFO protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
}

int KisPanelInterface::Remove_AllNetcli_ProtoHandler(string in_proto,
													 CliProto_Callback in_cb,
													 void *in_aux) {
	if (network_client != NULL)
		network_client->RemoveProtoHandler(in_proto, in_cb, in_aux);

	return 0;
}

void KisPanelInterface::RaiseAlert(string in_title, string in_text) {
	vector<string> t = StrTokenize(in_text, "\n");

	Kis_Prompt_Panel *kpp =
		new Kis_Prompt_Panel(globalreg, this);
	kpp->SetTitle(in_title);
	kpp->SetDisplayText(t);
	kpp->SetButtonText("OK", "");
	AddPanel(kpp);
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

void KisPanelInterface::LoadPlugin(string in_fname, string in_objname) {
	void *dlfile;
	panel_plugin_hook plughook;

	if ((dlfile = dlopen(in_fname.c_str(), RTLD_LAZY)) == NULL) {
		_MSG("Failed to open plugin '" + in_fname + "': " +
			 dlerror(), MSGFLAG_ERROR);
		return;
	}

	if ((plughook = (panel_plugin_hook) dlsym(dlfile, "panel_plugin_init")) == NULL) {
		_MSG("Failed to find 'panel_plugin_init' function in plugin '" + in_fname + 
			 "': " + strerror(errno), MSGFLAG_ERROR);
		dlclose(dlfile);
		return;
	}

	int ret;
	ret = (*(plughook))(globalreg, &plugdata);

	if (ret < 0) {
		_MSG("Failed to initialize plugin '" + in_fname + "'", MSGFLAG_ERROR);
		dlclose(dlfile);
		return;
	}

	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		if (plugin_vec[x]->filename == in_fname && 
			plugin_vec[x]->objectname == in_objname) {
			plugin_vec[x]->dlfileptr = dlfile;
			break;
		}
	}
}

void KisPanelInterface::ScanPlugins() {
	vector<string> plugdirs = prefs.FetchOptVec("PLUGINDIR");

	for (unsigned int x = 0; x < plugdirs.size(); x++) {
		DIR *plugdir;
		struct dirent *plugfile;
		string expanddir = ConfigFile::ExpandLogPath(plugdirs[x], "", "", 0, 1);

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

// Catch plugin failures so we can alert the user
string global_plugin_load;
void PluginSignalHandler(int sig) {
	fprintf(stderr, "\n\n"
			"FATAL: Kismet_Client crashed while loading a plugin...\n"
			"Plugin loading: %s\n\n"
			"This is either a bug in the plugin, or the plugin needs to be recompiled\n"
			"to match the version of Kismet you are using (especially if you are using\n"
			"development versions of Kismet or have recently upgraded.\n\n"
			"If the plugin is automatically loaded, edit ~/.kismet/kismet_ui.conf and\n"
			"remove the plugin_autoload line.\n\n", global_plugin_load.c_str());
	exit(1);
}

void KisPanelInterface::LoadPlugins() {
	// Scan for plugins to auto load
	vector<string> plugprefs = prefs.FetchOptVec("plugin_autoload");
	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		for (unsigned int y = 0; y < plugprefs.size(); y++) {
			if (plugin_vec[x]->objectname == plugprefs[y] &&
				plugin_vec[x]->dlfileptr == 0x0) {
				global_plugin_load = plugin_vec[x]->objectname;
				signal(SIGSEGV, PluginSignalHandler);
				_MSG("Auto-loading plugin '" + plugprefs[y] + "'", MSGFLAG_INFO);
				LoadPlugin(plugin_vec[x]->filename, plugin_vec[x]->objectname);
				signal(SIGSEGV, SIG_DFL);
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
	if (console->size() > 50) 
		console->erase(console->begin(), console->begin() + console->size() - 50);
}

void KisPanelInterface::SpawnServer(string in_parm) {
	server_parm = in_parm;
	SpawnServer();
}

void KisPanelInterface::SpawnServer() {
	string servercmd = string(BIN_LOC) + "/kismet_server " + server_parm;

	if (server_framework == NULL) {
		server_framework = new TextCliFrame(globalreg);
		server_popen = new PopenClient(globalreg);

		server_framework->RegisterNetworkClient(server_popen);
		server_popen->RegisterClientFramework(server_framework);

		server_text_cb = 
			server_framework->RegisterCallback(kpi_textcli_consolevec, this);

		if (server_popen->Connect(servercmd.c_str(), 'r') < 0) {
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

