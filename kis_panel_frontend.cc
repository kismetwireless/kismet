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

}

KisPanelInterface::~KisPanelInterface() {
	for (unsigned int x = 0; x < netclient_vec.size(); x++)
		delete netclient_vec[x];
}

int KisPanelInterface::AddNetClient(string in_host, int in_reconnect) {
	KisNetClient *netcl = new KisNetClient(globalreg);

	netcl->AddConfCallback(KisPanelClient_Configured, 1, this);

	if (netcl->Connect(in_host, in_reconnect) < 0)
		return -1;

	netclient_vec.push_back(netcl);

	return 1;
}

vector<KisNetClient *> KisPanelInterface::FetchNetClientVec() {
	return netclient_vec;
}

int KisPanelInterface::RemoveNetClient(KisNetClient *in_cli) {
	for (unsigned int x = 0; x < netclient_vec.size(); x++) {
		if (netclient_vec[x] == in_cli) {
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
}

void KisPanelInterface::RaiseAlert(string in_title, string in_text) {
	Kis_ModalAlert_Panel *ma = new Kis_ModalAlert_Panel(globalreg, this);

	ma->Position((LINES / 2) - 5, (COLS / 2) - 20, 10, 40);

	ma->ConfigureAlert(in_title, in_text);
	
	globalreg->panel_interface->AddPanel(ma);

}

#endif

