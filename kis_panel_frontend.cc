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
	"velocity,dwell,hop_time_sec,hop_time_usec,channellist"

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

void KisPanelInterface::proto_SOURCE(CLIPROTO_CB_PARMS) {
	// "uuid,interface,type,username,channel,packets,hop," 
	//	"velocity,dwell,hop_time_sec,hop_time_usec,channellist"

	if (proto_parsed->size() < 12) {
		fprintf(stderr, "invalid size %d\n", proto_parsed->size());
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
}

KisPanelInterface::~KisPanelInterface() {
	SavePreferences();

	Remove_AllNetcli_ProtoHandler("STATUS", KisPanelClient_STATUS, this);
	Remove_AllNetcli_ProtoHandler("SOURCE", KisPanelClient_SOURCE, this);

	// Destroy panels in this destructor, if they get destroyed in the
	// parent destructor sadness happens
	for (unsigned int x = 0; x < live_panels.size(); x++)
		delete live_panels[x];
	live_panels.clear();

	for (unsigned int x = 0; x < netclient_vec.size(); x++)
		delete netclient_vec[x];
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

	netclient_vec.push_back(netcl);

	return 1;
}

vector<KisNetClient *> KisPanelInterface::FetchNetClientVec() {
	return netclient_vec;
}

vector<KisNetClient *> *KisPanelInterface::FetchNetClientVecPtr() {
	return &netclient_vec;
}

int KisPanelInterface::RemoveNetClient(KisNetClient *in_cli) {
	for (unsigned int x = 0; x < netclient_vec.size(); x++) {
		if (netclient_vec[x] == in_cli) {
			for (unsigned int c = 0; c < addclicb_vec.size(); c++)
				(*(addclicb_vec[c]->cb))(globalreg, in_cli, 0, 
										 addclicb_vec[c]->auxptr);
			delete netclient_vec[x];
			netclient_vec.erase(netclient_vec.begin() + x);
			return 1;
		}
	}

	return 0;
}

void KisPanelInterface::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	// Reset the card list.  This assumes we only ever have one client, which
	// is the case despite the stubs for multi-client.  Sorry.  -d
	
	for (map<uuid, KisPanelInterface::knc_card *>::iterator x = netcard_map.begin();
		 x != netcard_map.end(); ++x) {
		delete(x->second);
	}
	netcard_map.clear();

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
}

int KisPanelInterface::Remove_AllNetcli_ProtoHandler(string in_proto,
													 CliProto_Callback in_cb,
													 void *in_aux) {
	for (unsigned int x = 0; x < netclient_vec.size(); ++x) {
		netclient_vec[x]->RemoveProtoHandler(in_proto, in_cb, in_aux);
	}

	return 0;
}

void KisPanelInterface::RaiseAlert(string in_title, string in_text) {
	Kis_ModalAlert_Panel *ma = new Kis_ModalAlert_Panel(globalreg, this);

	ma->Position((LINES / 2) - 5, (COLS / 2) - 20, 10, 40);

	ma->ConfigureAlert(in_title, in_text);
	
	globalreg->panel_interface->AddPanel(ma);

}

void KisPanelInterface::RaiseServerPicker(string in_title, kpi_sl_cb_hook in_hook,
										  void *in_aux) {
	Kis_ServerList_Picker *slp = new Kis_ServerList_Picker(globalreg, this);

	slp->Position((LINES / 2) - 5, (COLS / 2) - 17, 10, 34);

	slp->ConfigurePicker(in_title, in_hook, in_aux);

	globalreg->panel_interface->AddPanel(slp);
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

	// Call it for all the existing clients, since if we're adding a function
	// to take action when a client gets added, we probably want to be able
	// to take action on all the existing.  We can add a parm to control
	// this sometime if this ever turns out to be not the case, but I don't
	// think it will.
	for (unsigned int x = 0; x < netclient_vec.size(); ++x) {
		(*(in_cb))(globalreg, netclient_vec[x], 1, in_auxptr);
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

#endif

