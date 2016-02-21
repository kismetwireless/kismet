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

#include "kis_panel_info.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"

#include "soundcontrol.h"

#include "phy_80211.h"

const char *time_fields[] = { "timesec", NULL };

const char *info_fields[] = { "networks", "packets", "rate", "filtered", NULL };

const char *info_bits_details[][2] = {
	{ "elapsed", "Elapsed time" },
	{ "numnets", "Number of networks" },
	{ "numpkts", "Number of packets" },
	{ "pktrate", "Packet rate" },
	{ "numfilter", "Number of filtered packets" },
	{ "sources", "Packet sources" },
	{ NULL, NULL}
};

// Callbacks
void KisInfobits_Configured(CLICONF_CB_PARMS) {
	((Kis_Info_Bits *) auxptr)->NetClientConfigure(kcli, recon);
}

void KisInfobits_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Kis_Info_Bits *) auxptr)->NetClientAdd(netcli, add);
}

void KisInfobits_INFO(CLIPROTO_CB_PARMS) {
	((Kis_Info_Bits *) auxptr)->Proto_INFO(globalreg, proto_string,
										   proto_parsed, srccli, auxptr);
}

void KisInfobits_TIME(CLIPROTO_CB_PARMS) {
	((Kis_Info_Bits *) auxptr)->Proto_TIME(globalreg, proto_string, 
										   proto_parsed, srccli, auxptr);
}

Kis_Info_Bits::Kis_Info_Bits(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Packbox(in_globalreg, in_panel) {
	kpinterface = in_panel->FetchPanelInterface();

	num_networks = num_packets = packet_rate = filtered_packets = 0;

	addref = kpinterface->Add_NetCli_AddCli_CB(KisInfobits_AddCli, (void *) this);

	// Set up our inherited vbox attributes
	SetPackV();
	SetHomogenous(0);
	SetSpacing(1);

	info_color_normal = -1;
	parent_panel->InitColorPref("info_normal_color", "white,black");

	title = new Kis_Free_Text(globalreg, parent_panel);
	title->SetColorPrefs("info_normal_color", "info_normal_color");
	title->SetText("\004uKismet\004U");
	title->SetAlignment(1);
	title->Show();
	Pack_End(title, 0, 0);

	asm_time_num = TokenNullJoin(&asm_time_fields, time_fields);
	asm_info_num = TokenNullJoin(&asm_info_fields, info_fields);

	UpdatePrefs();
}

Kis_Info_Bits::~Kis_Info_Bits() {
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(KisInfobits_Configured);
	kpinterface->Remove_All_Netcli_ProtoHandler("TIME", KisInfobits_TIME, this);
	kpinterface->Remove_All_Netcli_ProtoHandler("INFO", KisInfobits_INFO, this);
}

int Kis_Info_Bits::UpdatePrefs() {
	string ibits;

	if ((ibits = kpinterface->prefs->FetchOpt("NETINFO_ITEMS")) == "") {
		ibits = "elapsed,numnets,numpkts,pktrate,numfilter";
		kpinterface->prefs->SetOpt("NETINFO_ITEMS", ibits, 1);
	}

	if (kpinterface->prefs->FetchOptDirty("NETINFO_ITEMS") == 0) {
		return 0;
	}

	kpinterface->prefs->SetOptDirty("NETINFO_ITEMS", 0);

	infovec.clear();

	// Unpack the vbox and remove the widgets
	for (map<int, Kis_Free_Text *>::iterator x = infowidgets.begin();
		 x != infowidgets.end(); ++x) {
		Pack_Remove(x->second);
		delete(x->second);
	}
	infowidgets.clear();

	vector<string> toks = StrTokenize(ibits, ",");
	string t;

	int optnum;
	Kis_Free_Text *ft;

	for (unsigned int x = 0; x < toks.size(); x++) {
		t = StrLower(toks[x]);

		if (t == "elapsed") {
			optnum = info_elapsed;
			infovec.push_back(info_elapsed);
		} else if (t == "numnets") {
			optnum = info_numnets;
		} else if (t == "numpkts") {
			optnum = info_numpkts;
		} else if (t == "pktrate") {
			optnum = info_pktrate;
		} else if (t == "numfilter") {
			optnum = info_filtered;
		} else {
			_MSG("Unknown info panel item '" + t + "', skipping.",
				 MSGFLAG_INFO);
			continue;
		}

		infovec.push_back(optnum);
		ft = new Kis_Free_Text(globalreg, parent_panel);
		ft->SetColorPrefs("info_normal_color", "info_normal_color");
		ft->Show();
		ft->SetAlignment(1);
		Pack_End(ft, 0, 0);
		infowidgets[optnum] = ft;
	}

	return 1;
}

void Kis_Info_Bits::DrawComponent() {
	UpdatePrefs();

	if (kpinterface->FetchNetClient() == NULL ||
		(kpinterface->FetchNetClient() != NULL &&
		 kpinterface->FetchNetClient()->Valid() <= 0)) {
		vector<string> titletext = title->GetText();
		if (titletext.size() == 1) {
			titletext.push_back("\004rNot\004R");
			titletext.push_back("\004rConnected\004R");
			title->SetText(titletext);
		}
	}

	Kis_Panel_Packbox::DrawComponent();
}

void Kis_Info_Bits::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	first_time = in_cli->FetchServerStarttime();
	
	title->SetText("\004u" + in_cli->FetchServerName() + "\004U");

	if (in_cli->RegisterProtoHandler("TIME", asm_time_fields,
									 KisInfobits_TIME, this) < 0) {
		_MSG("Could not register TIME protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}

	if (in_cli->RegisterProtoHandler("INFO", asm_info_fields,
									 KisInfobits_INFO, this) < 0) {
		_MSG("Could not register INFO protocol with remote server, connection "
			 "will be terminated.", MSGFLAG_ERROR);
		in_cli->KillConnection();
	}
}

void Kis_Info_Bits::NetClientAdd(KisNetClient *in_cli, int add) {
	if (add == 0)
		return;

	in_cli->AddConfCallback(KisInfobits_Configured, 1, this);
}

void Kis_Info_Bits::Proto_TIME(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) asm_time_num) {
		return;
	}

	unsigned int ttime;
	if (sscanf((*proto_parsed)[0].word.c_str(), "%u", &ttime) != 1) {
		return;
	}

	last_time = ttime;

	if (infowidgets.find(info_elapsed) != infowidgets.end()) {
		vector<string> it;
		char t[20];
		time_t el = last_time - first_time;

		it.push_back("\004bElapsed\004B");
		snprintf(t, 20, "%02d:%02d.%02d", 
				 (int) (el / 60) / 60,
				 (int) (el / 60) % 60,
				 (int) (el % 60));
		it.push_back(t);

		infowidgets[info_elapsed]->SetText(it);
	}
}

void Kis_Info_Bits::Proto_INFO(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) asm_info_num) {
		return;
	}

	int tint;
	int fnum = 0;

	vector<string> it(2);
	char n[20];

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}
	num_networks = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}
	num_packets = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}
	packet_rate = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) {
		return;
	}
	filtered_packets = tint;

	if (infowidgets.find(info_numnets) != infowidgets.end()) {
		it[0] = "\004bNetworks\004B";
		snprintf(n, 20, "%d", num_networks);
		it[1] = n;
		infowidgets[info_numnets]->SetText(it);
	}

	if (infowidgets.find(info_numpkts) != infowidgets.end()) {
		it[0] = "\004bPackets\004B";
		snprintf(n, 20, "%d", num_packets);
		it[1] = n;
		infowidgets[info_numpkts]->SetText(it);
	}

	if (infowidgets.find(info_pktrate) != infowidgets.end()) {
		it[0] = "\004bPkt/Sec\004B";
		snprintf(n, 20, "%d", packet_rate);
		it[1] = n;
		infowidgets[info_pktrate]->SetText(it);
	}

	if (infowidgets.find(info_filtered) != infowidgets.end()) {
		it[0] = "\004bFiltered\004B";
		snprintf(n, 20, "%d", filtered_packets);
		it[1] = n;
		infowidgets[info_filtered]->SetText(it);
	}
}

#endif // panel

