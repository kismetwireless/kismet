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

#include "util.h"
#include "messagebus.h"
#include "kis_panel_widgets.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"

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

void KisPanelClient_CARD(CLIPROTO_CB_PARMS) {
	// Pass it off to the clinet frame
	((KisPanelInterface *) auxptr)->NetClientCARD(globalreg, proto_string,
												  proto_parsed, srccli, auxptr);
}

void KisPanelInterface::NetClientCARD(CLIPROTO_CB_PARMS) {
	// interface		0
	// type				1
	// username			2
	// channel			3
	// uuid				4
	// packets			5
	// hopping			6
	// MAX				7
	
	if (proto_parsed->size() < 7) {
		return;
	}

	// Grab the UUID first, see if we need to build a record or if we're
	// filling in an existing one
	uuid carduuid = uuid((*proto_parsed)[4].word);
	if (carduuid.error) {
		_MSG("Invalid UUID in CARD protocol, skipping line", MSGFLAG_ERROR);
		return;
	}

	KisPanelInterface::knc_card *card = NULL;
	int prevknown = 0;
	map<uuid, KisPanelInterface::knc_card *>::iterator itr;

	if ((itr = netcard_map.find(carduuid)) != netcard_map.end()) {
		card = itr->second;
		prevknown = 1;
	} else {
		card = new KisPanelInterface::knc_card;
	}

	// If we didn't know about it, get the name, type, etc.  Otherwise
	// we can ignore it because we should never change this
	if (prevknown == 0) {
		card->carduuid = carduuid;
		card->uuid_hash = Adler32Checksum(carduuid.UUID2String().c_str(),
										  carduuid.UUID2String().length());
		card->interface = MungeToPrintable((*proto_parsed)[0].word);
		card->type = MungeToPrintable((*proto_parsed)[1].word);
		card->username = MungeToPrintable((*proto_parsed)[2].word);
	}

	// Parse the current channel and number of packets for all of them
	int tchannel;
	int tpackets;
	int thopping;

	if (sscanf((*proto_parsed)[3].word.c_str(), "%d", &tchannel) != 1) {
		_MSG("Invalid channel in CARD protocol, skipping line.", MSGFLAG_ERROR);
		if (prevknown == 0)
			delete card;
		return;
	}

	if (sscanf((*proto_parsed)[5].word.c_str(), "%d", &tpackets) != 1) {
		_MSG("Invalid packet count in CARD protocol, skipping line.", MSGFLAG_ERROR);
		if (prevknown == 0)
			delete card;
		return;
	}

	if (sscanf((*proto_parsed)[6].word.c_str(), "%d", &thopping) != 1) {
		_MSG("Invalid hop state in CARD protocol, skipping line.", MSGFLAG_ERROR);
		if (prevknown == 0)
			delete card;
		return;
	}

	// We're good, lets fill it in
	card->channel = tchannel;
	card->packets = tpackets;
	card->hopping = thopping;

	// Fill in the last time we saw something here
	card->last_update = time(0);

	if (prevknown == 0) 
		netcard_map[carduuid] = card;

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

	addcb_ref = 0;

	mainp = NULL;
}

KisPanelInterface::~KisPanelInterface() {
	SavePreferences();

	Remove_AllNetcli_ProtoHandler("STATUS", KisPanelClient_STATUS, this);
	Remove_AllNetcli_ProtoHandler("CARD", KisPanelClient_CARD, this);

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
	if (in_recon)
		return;

	_MSG("Got configure event for client", MSGFLAG_INFO);

	if (in_cli->RegisterProtoHandler("STATUS", "text,flags",
									 KisPanelClient_STATUS, this) < 0) {
		_MSG("Could not register STATUS protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
	if (in_cli->RegisterProtoHandler("CARD", 
									 "interface,type,username,channel,"
									 "uuid,packets,hopping",
									 KisPanelClient_CARD, this) < 0) {
		_MSG("Could not register CARD protocol with remote server, connection "
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

	panel_plugin_meta *pm = new panel_plugin_meta;
	pm->filename = in_fname;
	pm->objectname = in_objname;
	pm->dlfileptr = dlfile;
	plugin_vec.push_back(pm);
}

#endif

