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

#include <config.h>

#include <stdio.h>

#include <string>
#include <sstream>

#include <globalregistry.h>
#include <kis_panel_plugin.h>
#include <kis_panel_frontend.h>
#include <kis_panel_windows.h>
#include <kis_panel_network.h>
#include <kis_panel_widgets.h>
#include <version.h>

#define KCLI_SPECTRUM_CHANNEL_FIELDS	"devname,amp_offset_mdbm,amp_res_mdbm," \
	"start_khz,res_hz,samples" 

#define RSSI_CONVERT(O,R,D)	(int) ((D) * ((double) (R) / 1000.0f) + \
								   ((double) (O) / 1000.0f))

void showspectrum_menu_callback(MENUITEM_CB_PARMS);

struct spec_data {
	int mi_showspectrum;

	Kis_IntGraph *spectrum;
	vector<int> pack_cur, pack_avg, pack_peak;
	vector<Kis_IntGraph::graph_label> graph_label_vec;

	vector<vector<int> > avg_seed;

	int addref;

	string device;
};

void SpecCliAdd(KPI_ADDCLI_CB_PARMS);

extern "C" {

int panel_plugin_init(GlobalRegistry *globalreg, KisPanelPluginData *pdata) {
	_MSG("Loading Kismet Spectools plugin", MSGFLAG_INFO);

	spec_data *adata;
	adata = new spec_data;

	pdata->pluginaux = (void *) adata;

	Kis_Menu *menu = pdata->kpinterface->FetchMainPanel()->FetchMenu();

	int mn_view = menu->FindMenu("View");

	pdata->kpinterface->FetchMainPanel()->AddViewSeparator();
	adata->mi_showspectrum = menu->AddMenuItem("Spectrum", mn_view, 0);
	menu->SetMenuItemCallback(adata->mi_showspectrum, showspectrum_menu_callback,
							  pdata);

	adata->spectrum = new Kis_IntGraph(globalreg, pdata->mainpanel);
	adata->spectrum->SetName("SPECTRUM");
	adata->spectrum->SetPreferredSize(0, 12);
	adata->spectrum->SetScale(-120, -50);
	adata->spectrum->SetInterpolation(1);
	adata->spectrum->SetMode(0);

	adata->spectrum->AddExtDataVec("Current", 5, "spectrum_cur", "yellow,yellow",
								   '#', '\0', 1, &(adata->pack_cur));
	adata->spectrum->AddExtDataVec("Average", 4, "spectrum_avg", "green,green",
								   ' ', ' ', 1, &(adata->pack_avg));
	adata->spectrum->AddExtDataVec("Peak", 3, "spectrum_peak", "blue,blue",
								   ' ', ' ', 1, &(adata->pack_peak));

	pdata->mainpanel->AddComponentVec(adata->spectrum, KIS_PANEL_COMP_DRAW);

	string opt = pdata->kpinterface->prefs->FetchOpt("MAIN_SHOWSPECTRUM");
	if (opt == "true" || opt == "") {
		adata->spectrum->Show();
		pdata->mainpanel->SetPluginMenuItemChecked(adata->mi_showspectrum, 1);
	} else {
		adata->spectrum->Hide();
		pdata->mainpanel->SetPluginMenuItemChecked(adata->mi_showspectrum, 0);
	}

	pdata->mainpanel->FetchNetBox()->Pack_After_Named("KIS_MAIN_NETLIST", 
													  adata->spectrum, 1, 0);

	adata->addref =
		pdata->kpinterface->Add_NetCli_AddCli_CB(SpecCliAdd, (void *) pdata);

	return 1;
}

void kis_revision_info(panel_plugin_revision *prev) {
	if (prev->version_api_revision >= 1) {
		prev->version_api_revision = 1;
		prev->major = string(VERSION_MAJOR);
		prev->minor = string(VERSION_MINOR);
		prev->tiny = string(VERSION_TINY);
	}
}

}

void SpecDetailsProtoSPECTRUM(CLIPROTO_CB_PARMS) {
	KisPanelPluginData *pdata = (KisPanelPluginData *) auxptr;
	spec_data *adata = (spec_data *) pdata->pluginaux;

	// "devname,amp_offset_mdbm,amp_res_mdbm,start_khz,res_hz,samples" 
	
	if (proto_parsed->size() < 6)
		return;

	int fnum = 0;

	int amp_offset = 0, amp_res = 0, start_khz = 0, res_hz = 0;

	// Only process the first one we saw
	if (adata->device != "" && adata->device != (*proto_parsed)[fnum].word)
		return;

	adata->device = (*proto_parsed)[fnum++].word;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &amp_offset) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &amp_res) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &start_khz) != 1)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &res_hz) != 1)
		return;

	vector<string> rssis = StrTokenize((*proto_parsed)[fnum++].word, ":");

	adata->pack_cur.clear();
	adata->pack_avg.clear();
	adata->pack_peak.clear();

	for (unsigned int x = 0; x < rssis.size(); x++) {
		int tint;
		int dbm;

		if (sscanf(rssis[x].c_str(), "%d", &tint) != 1)
			return;

		dbm = RSSI_CONVERT(amp_offset, amp_res, tint);

		adata->pack_cur.push_back(dbm);
	}

	adata->avg_seed.push_back(adata->pack_cur);
	if (adata->avg_seed.size() > 50)
		adata->avg_seed.erase(adata->avg_seed.begin());

	for (unsigned int x = 0; x < adata->avg_seed.size(); x++) {
		for (unsigned int y = 0; y < adata->avg_seed[x].size(); y++) {
			// Add it to the totals
			if (y >= adata->pack_avg.size())
				adata->pack_avg.push_back(adata->avg_seed[x][y]);
			else
				adata->pack_avg[y] += adata->avg_seed[x][y];

			// Compare it to the peak
			if (y >= adata->pack_peak.size())
				adata->pack_peak.push_back(adata->avg_seed[x][y]);
			else if (adata->pack_peak[y] < adata->avg_seed[x][y])
				adata->pack_peak[y] = adata->avg_seed[x][y];
		}
	}

	for (unsigned int x = 0; x < adata->pack_avg.size(); x++) {
		adata->pack_avg[x] = (int) ((float) adata->pack_avg[x] / 
									 adata->avg_seed.size());
	}
}

void SpecCliConfigured(CLICONF_CB_PARMS) {
	KisPanelPluginData *pdata = (KisPanelPluginData *) auxptr;
	spec_data *adata = (spec_data *) pdata->pluginaux;

	if (recon)
		return;

	if (kcli->RegisterProtoHandler("SPECTRUM", KCLI_SPECTRUM_CHANNEL_FIELDS,
								   SpecDetailsProtoSPECTRUM, pdata) < 0) {
		_MSG("Could not register SPECTRUM protocol with remote server", MSGFLAG_ERROR);
	}
}

void SpecCliAdd(KPI_ADDCLI_CB_PARMS) {
	KisPanelPluginData *pdata = (KisPanelPluginData *) auxptr;
	spec_data *adata = (spec_data *) pdata->pluginaux;

	if (add == 0)
		return;

	netcli->AddConfCallback(SpecCliConfigured, 1, pdata);
}

void showspectrum_menu_callback(MENUITEM_CB_PARMS) {
	KisPanelPluginData *pdata = (KisPanelPluginData *) auxptr;
	spec_data *adata = (spec_data *) pdata->pluginaux;

	string opt = pdata->kpinterface->prefs->FetchOpt("MAIN_SHOWSPECTRUM");
	if (opt == "" || opt == "true") {
		pdata->kpinterface->prefs->SetOpt("MAIN_SHOWSPECTRUM", "false", 1);
		pdata->mainpanel->SetPluginMenuItemChecked(adata->mi_showspectrum, 0);
		adata->spectrum->Hide();
	} else {
		pdata->kpinterface->prefs->SetOpt("MAIN_SHOWSPECTRUM", "true", 1);
		pdata->mainpanel->SetPluginMenuItemChecked(adata->mi_showspectrum, 1);
		adata->spectrum->Show();
	}
}

