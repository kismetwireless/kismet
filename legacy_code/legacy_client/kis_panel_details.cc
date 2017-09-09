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
#include "kis_panel_details.h"

int ChanDetailsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ChanDetails_Panel *) aux)->ButtonAction(component);
	return 1;
}

int ChanDetailsMenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ChanDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

int ChanDetailsGraphEvent(TIMEEVENT_PARMS) {
	((Kis_ChanDetails_Panel *) auxptr)->GraphTimer();

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

	chansummary->Show();

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

	SetActiveComponent(chansummary);

	UpdateViewMenu(-1);
	GraphTimer();

	addref = kpinterface->Add_NetCli_AddCli_CB(ChanDetailsCliAdd, (void *) this);	

	main_component = vbox;

	Position(WIN_CENTER(LINES, COLS));
}

Kis_ChanDetails_Panel::~Kis_ChanDetails_Panel() {
	kpinterface->Remove_Netcli_AddCli_CB(addref);
	kpinterface->Remove_All_Netcli_Conf_CB(ChanDetailsCliConfigured);
	kpinterface->Remove_All_Netcli_ProtoHandler("CHANNEL", 
												ChanDetailsProtoCHANNEL, this);
	globalreg->timetracker->RemoveTimer(grapheventid);
}

void Kis_ChanDetails_Panel::NetClientConfigured(KisNetClient *in_cli, int in_recon) {
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
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWSUM");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWSUM", "false", 1);
			menu->SetMenuItemChecked(mi_chansummary, 0);
			chansummary->Hide();
		} else {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWSUM", "true", 1);
			menu->SetMenuItemChecked(mi_chansummary, 1);
			chansummary->Show();
		}
	} else if (mi == mi_signal) {
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWSIG");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWSIG", "false", 1);
			menu->SetMenuItemChecked(mi_signal, 0);
			siggraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWSIG", "true", 1);
			menu->SetMenuItemChecked(mi_signal, 1);
			siggraph->Show();
		}
	} else if (mi == mi_packets) {
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWPACK");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWPACK", "false", 1);
			menu->SetMenuItemChecked(mi_packets, 0);
			packetgraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWPACK", "true", 1);
			menu->SetMenuItemChecked(mi_packets, 1);
			packetgraph->Show();
		}
	} else if (mi == mi_traffic) {
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWTRAF");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWTRAF", "false", 1);
			menu->SetMenuItemChecked(mi_traffic, 0);
			bytegraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWTRAF", "true", 1);
			menu->SetMenuItemChecked(mi_traffic, 1);
			bytegraph->Show();
		}
	} else if (mi == mi_networks) {
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWNET");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWNET", "false", 1);
			menu->SetMenuItemChecked(mi_networks, 0);
			netgraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("CHANDETAILS_SHOWNET", "true", 1);
			menu->SetMenuItemChecked(mi_networks, 1);
			netgraph->Show();
		}
	} else if (mi == -1) {
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWSUM");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_chansummary, 1);
			chansummary->Show();
		} else {
			menu->SetMenuItemChecked(mi_chansummary, 0);
			chansummary->Hide();
		}
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWSIG");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_signal, 1);
			siggraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_signal, 0);
			siggraph->Hide();
		}
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWPACK");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_packets, 1);
			packetgraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_packets, 0);
			packetgraph->Hide();
		}
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWTRAF");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_traffic, 1);
			bytegraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_traffic, 0);
			bytegraph->Hide();
		}
		opt = kpinterface->prefs->FetchOpt("CHANDETAILS_SHOWNET");
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

int AlertDetailsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_AlertDetails_Panel *) aux)->ButtonAction(component);
	return 1;
}

int AlertDetailsMenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_AlertDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

class KisAlert_Sort_Time {
public:
	inline bool operator()(KisPanelInterface::knc_alert *x, 
						   KisPanelInterface::knc_alert *y) const {
		if (x->tv.tv_sec < y->tv.tv_sec ||
			(x->tv.tv_sec == y->tv.tv_sec && x->tv.tv_usec < y->tv.tv_usec))
			return 1;

		return 0;
	}
};

class KisAlert_Sort_TimeInv {
public:
	inline bool operator()(KisPanelInterface::knc_alert *x, 
						   KisPanelInterface::knc_alert *y) const {
		if (x->tv.tv_sec < y->tv.tv_sec ||
			(x->tv.tv_sec == y->tv.tv_sec && x->tv.tv_usec < y->tv.tv_usec))
			return 0;

		return 1;
	}
};

class KisAlert_Sort_Type {
public:
	inline bool operator()(KisPanelInterface::knc_alert *x, 
						   KisPanelInterface::knc_alert *y) const {
		return x->alertname < y->alertname;
	}
};

class KisAlert_Sort_Bssid {
public:
	inline bool operator()(KisPanelInterface::knc_alert *x, 
						   KisPanelInterface::knc_alert *y) const {
		return x->bssid < y->bssid;
	}
};

Kis_AlertDetails_Panel::Kis_AlertDetails_Panel(GlobalRegistry *in_globalreg, 
											   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	last_alert = NULL;
	last_selected = NULL;
	last_sort = 0;

	menu = new Kis_Menu(globalreg, this);

	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, AlertDetailsMenuCB, this);

	mn_alert = menu->AddMenu("Alert", 0);
	mi_close = menu->AddMenuItem("Close window", mn_alert, 'w');

	mn_sort = menu->AddMenu("Sort", 0);
	mi_latest = menu->AddMenuItem("Latest", mn_sort, 'l');
	mi_time = menu->AddMenuItem("Time", mn_sort, 't');
	mi_type = menu->AddMenuItem("Type", mn_sort, 'T');
	mi_bssid = menu->AddMenuItem("BSSID", mn_sort, 'b');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	alertlist = new Kis_Scrollable_Table(globalreg, this);
	alertlist->SetHighlightSelected(1);
	alertlist->SetLockScrollTop(1);
	alertlist->SetDrawTitles(0);
	AddComponentVec(alertlist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								KIS_PANEL_COMP_TAB));

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 8;
	t.title = "time";
	t.alignment = 2;
	titles.push_back(t);
	t.width = 10;
	t.title = "header";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 0;
	t.title = "text";
	t.alignment = 0;
	titles.push_back(t);

	alertlist->AddTitles(titles);
	alertlist->Show();

	alertdetails = new Kis_Scrollable_Table(globalreg, this);
	alertdetails->SetHighlightSelected(0);
	alertdetails->SetLockScrollTop(1);
	alertdetails->SetDrawTitles(0);
	alertdetails->SetPreferredSize(0, 6);
	AddComponentVec(alertdetails, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								KIS_PANEL_COMP_TAB));

	titles.clear();

	t.width = 12;
	t.title = "field";
	t.alignment = 2;
	titles.push_back(t);
	t.width = 0;
	t.title = "text";
	t.alignment = 0;
	titles.push_back(t);

	alertdetails->AddTitles(titles);
	alertdetails->SetPreferredSize(0, 6);
	alertdetails->Show();

	SetTitle("");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	vbox->Pack_End(alertlist, 1, 0);
	vbox->Pack_End(alertdetails, 0, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	main_component = vbox;

	SetActiveComponent(alertlist);

	UpdateSortPrefs(1);
	UpdateSortMenu(-1);

	Position(WIN_CENTER(LINES, COLS));
}

Kis_AlertDetails_Panel::~Kis_AlertDetails_Panel() {

}

void Kis_AlertDetails_Panel::DrawPanel() {
	vector<KisPanelInterface::knc_alert *> *raw_alerts = kpinterface->FetchAlertVec();
	int k = 0;
	vector<string> td;

	td.push_back("");
	td.push_back("");
	td.push_back("");

	// No custom drawing if we have no alerts
	if (raw_alerts->size() == 0) {
		sorted_alerts.clear();
		alertdetails->Clear();
		alertlist->Clear();
		td[0] = "";
		td[1] = "";
		td[2] = "No alerts";
		alertlist->ReplaceRow(k++, td);
		Kis_Panel::DrawPanel();
		return;
	}

	// If we've changed the list
	if ((*raw_alerts)[raw_alerts->size() - 1] != last_alert) {
		sorted_alerts = *raw_alerts;

		switch (sort_mode) {
			case alertsort_time:
				stable_sort(sorted_alerts.begin(), sorted_alerts.end(), 
							KisAlert_Sort_Time());
				break;
			case alertsort_latest:
				stable_sort(sorted_alerts.begin(), sorted_alerts.end(), 
							KisAlert_Sort_TimeInv());
				break;
			case alertsort_type:
				stable_sort(sorted_alerts.begin(), sorted_alerts.end(), 
							KisAlert_Sort_Type());
				break;
			case alertsort_bssid:
				stable_sort(sorted_alerts.begin(), sorted_alerts.end(), 
							KisAlert_Sort_Bssid());
				break;
		}

		for (unsigned int x = 0; x < sorted_alerts.size(); x++) {
			td[0] = 
			string(ctime((const time_t *) &(sorted_alerts[x]->tv.tv_sec))).substr(11, 8);
			td[1] = sorted_alerts[x]->alertname;
			td[2] = sorted_alerts[x]->text;
			alertlist->ReplaceRow(k++, td);
		}
	}

	td.clear();
	td.push_back("");
	td.push_back("");
	k = 0;

	// Update the details for the selected alert if we've changed
	if (alertlist->GetSelected() >= 0 && 
		alertlist->GetSelected() < (int) sorted_alerts.size()) {
		if (sorted_alerts[alertlist->GetSelected()] != last_selected) {
			last_selected = sorted_alerts[alertlist->GetSelected()];
			alertdetails->Clear();

			td[0] = "Time:";
			td[1] = string(ctime((const time_t *) 
								 &(last_selected->tv.tv_sec))).substr(4, 15);
			alertdetails->ReplaceRow(k++, td);

			td[0] = "Alert:";
			td[1] = last_selected->alertname;
			alertdetails->ReplaceRow(k++, td);

			td[0] = "BSSID:";
			td[1] = last_selected->bssid.Mac2String();
			alertdetails->ReplaceRow(k++, td);

			td[0] = "Source:";
			td[1] = last_selected->source.Mac2String();
			alertdetails->ReplaceRow(k++, td);

			td[0] = "Dest:";
			td[1] = last_selected->dest.Mac2String();
			alertdetails->ReplaceRow(k++, td);

			td[0] = "Channel:";
			td[1] = IntToString(last_selected->channel);
			alertdetails->ReplaceRow(k++, td);

			td[0] = "Text:";
			td[1] = last_selected->text;
			alertdetails->ReplaceRow(k++, td);
		}
	} else {
		alertdetails->Clear();
		td[0] = "";
		td[1] = "No alert selected";
		alertdetails->ReplaceRow(k++, td);
	}

	Kis_Panel::DrawPanel();
}

void Kis_AlertDetails_Panel::ButtonAction(Kis_Panel_Component *in_button) {

}

void Kis_AlertDetails_Panel::MenuAction(int opt) {
	// Menu processed an event, do something with it
	if (opt == mi_close) {
		globalreg->panel_interface->KillPanel(this);
		return;
	} else if (opt == mi_time) {
		kpinterface->prefs->SetOpt("ALERTLIST_SORT", "time", time(0));
	} else if (opt == mi_latest) {
		kpinterface->prefs->SetOpt("ALERTLIST_SORT", "latest", time(0));
	} else if (opt == mi_type) {
		kpinterface->prefs->SetOpt("ALERTLIST_SORT", "type", time(0));
	} else if (opt == mi_bssid) {
		kpinterface->prefs->SetOpt("ALERTLIST_SORT", "bssid", time(0));
	}
	
	if (opt == mi_time || opt == mi_latest || opt == mi_type ||
			   opt == mi_bssid) {
		UpdateSortPrefs(0);
		UpdateSortMenu(opt);
	}
}

void Kis_AlertDetails_Panel::UpdateSortMenu(int mi) {
	menu->SetMenuItemChecked(mi_time, sort_mode == alertsort_time);
	menu->SetMenuItemChecked(mi_latest, sort_mode == alertsort_latest);
	menu->SetMenuItemChecked(mi_type, sort_mode == alertsort_type);
	menu->SetMenuItemChecked(mi_bssid, sort_mode == alertsort_bssid);
}

int Kis_AlertDetails_Panel::UpdateSortPrefs(int always) {
	string sort;

	if ((sort = kpinterface->prefs->FetchOpt("ALERTLIST_SORT")) == "") {
		sort = "latest";
		kpinterface->prefs->SetOpt("ALERTLIST_SORT", sort, time(0));
	}

	if (kpinterface->prefs->FetchOptDirty("ALERTLIST_SORT") < last_sort && always == 0)
		return 0;

	last_sort = kpinterface->prefs->FetchOptDirty("ALERTLIST_SORT");

	sort = StrLower(sort);

	if (sort == "latest")
		sort_mode = alertsort_latest;
	else if (sort == "time")
		sort_mode = alertsort_time;
	else if (sort == "type")
		sort_mode = alertsort_type;
	else if (sort == "bssid")
		sort_mode = alertsort_bssid;
	else
		sort_mode = alertsort_latest;

	return 1;
}

#endif
