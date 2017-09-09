
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

#ifndef __KIS_PANEL_DETAILS_H__
#define __KIS_PANEL_DETAILS_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "globalregistry.h"
#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"

#include "kis_panel_plugin.h"

class KisPanelInterface;

#define KCLI_CHANDETAILS_CHANNEL_FIELDS		"channel,time_on,packets,packetsdelta," \
	"usecused,bytes,bytesdelta,networks,activenetworks,maxsignal_dbm,maxsignal_rssi," \
	"maxnoise_dbm,maxnoise_rssi"
#define KCLI_CHANDETAILS_CHANNEL_NUMFIELDS	13

class Kis_ChanDetails_Panel : public Kis_Panel {
public:
	Kis_ChanDetails_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_ChanDetails_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_ChanDetails_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_ChanDetails_Panel();

	virtual void DrawPanel();
	virtual void ButtonAction(Kis_Panel_Component *in_button);
	virtual void MenuAction(int opt);

	virtual int GraphTimer();

	void NetClientConfigured(KisNetClient *in_cli, int in_recon);
	void NetClientAdd(KisNetClient *in_cli, int add);
	void Proto_CHANNEL(CLIPROTO_CB_PARMS);

	struct chan_sig_info {
		chan_sig_info() {
			last_updated = 0;
			channel = 0;
			channel_time_on = 0;
			packets = 0;
			packets_delta = 0;
			usec_used = 0;
			bytes_seen = 0;
			bytes_delta = 0;
			sig_dbm = 0;
			sig_rssi = 0;
			noise_dbm = 0;
			noise_rssi = 0;
			networks = 0;
			networks_active = 0;
		}

		time_t last_updated;

		int channel;
		int channel_time_on;
		int packets;
		int packets_delta;
		long int usec_used;
		long int bytes_seen;
		long int bytes_delta;

		int sig_dbm;
		int sig_rssi;
		int noise_dbm;
		int noise_rssi;

		int networks;
		int networks_active;
	};

protected:
	virtual void UpdateViewMenu(int mi);
	
	Kis_Panel_Packbox *vbox;
	Kis_Scrollable_Table *chansummary;

	Kis_IntGraph *siggraph, *packetgraph, *bytegraph, *netgraph;

	// Graph data pools
	vector<int> sigvec, noisevec, packvec, bytevec, netvec, anetvec;
	vector<Kis_IntGraph::graph_label> graph_label_vec;

	// Channel records
	map<uint32_t, chan_sig_info *> channel_map;

	time_t last_dirty;

	int mn_channels, mi_lock, mi_hop, mi_close;
	int mn_view, mi_chansummary, mi_signal, mi_packets, mi_traffic, mi_networks;

	int grapheventid;
	int addref;
};

enum alertsort_opts {
	alertsort_time, alertsort_latest, alertsort_type, alertsort_bssid
};

class Kis_AlertDetails_Panel : public Kis_Panel {
public:
	Kis_AlertDetails_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_AlertDetails_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_AlertDetails_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Kis_AlertDetails_Panel();

	virtual void DrawPanel();
	virtual void ButtonAction(Kis_Panel_Component *in_button);
	virtual void MenuAction(int opt);

protected:
	virtual void UpdateSortMenu(int mi);
	virtual int UpdateSortPrefs(int always);

	Kis_Panel_Packbox *vbox;
	Kis_Scrollable_Table *alertlist, *alertdetails;

	time_t last_sort;
	alertsort_opts sort_mode;

	int mn_alert, mi_close;
	int mn_sort, mi_time, mi_latest, mi_type, mi_bssid;

	vector<KisPanelInterface::knc_alert *> sorted_alerts;

	KisPanelInterface::knc_alert *last_alert, *last_selected;
};

#endif

#endif
