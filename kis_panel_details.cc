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

int NetDetailsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_NetDetails_Panel *) aux)->ButtonAction(component);
	return 1;
}

int NetDetailsMenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_NetDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

int NetDetailsGraphEvent(TIMEEVENT_PARMS) {
	return ((Kis_NetDetails_Panel *) parm)->GraphTimer();
}

Kis_NetDetails_Panel::Kis_NetDetails_Panel(GlobalRegistry *in_globalreg, 
									 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	grapheventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &NetDetailsGraphEvent, (void *) this);

	menu = new Kis_Menu(globalreg, this);

	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, NetDetailsMenuCB, this);

	mn_network = menu->AddMenu("Network", 0);
	mi_addnote = menu->AddMenuItem("Network Note...", mn_network, 'N');
	menu->AddMenuItem("-", mn_network, 0);
	mi_nextnet = menu->AddMenuItem("Next network", mn_network, 'n');
	mi_prevnet = menu->AddMenuItem("Prev network", mn_network, 'p');
	menu->AddMenuItem("-", mn_network, 0);
	mi_close = menu->AddMenuItem("Close window", mn_network, 'w');

	mn_view = menu->AddMenu("View", 0);
	mi_net = menu->AddMenuItem("Network Details", mn_view, 'n');
	mi_clients = menu->AddMenuItem("Clients", mn_view, 'c');
	menu->AddMenuItem("-", mn_view, 0);
	mi_graphsig = menu->AddMenuItem("Signal Level", mn_view, 's');
	mi_graphpacket = menu->AddMenuItem("Packet Rate", mn_view, 'p');
	mi_graphretry = menu->AddMenuItem("Retry Rate", mn_view, 'r');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	netdetailt = new Kis_Free_Text(globalreg, this);
	AddComponentVec(netdetailt, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								 KIS_PANEL_COMP_TAB));

#if 0
	// Details scroll list doesn't get the current one highlighted and
	// doesn't draw titles, also lock to fit inside the window
	netdetails = new Kis_Scrollable_Table(globalreg, this);
	netdetails->SetHighlightSelected(0);
	netdetails->SetLockScrollTop(1);
	netdetails->SetDrawTitles(0);
	AddComponentVec(netdetails, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								 KIS_PANEL_COMP_TAB));

	// We need to populate the titles even if we don't use them so that
	// the row handler knows how to draw them
	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 15;
	t.title = "field";
	t.alignment = 2;
	titles.push_back(t);
	t.width = 0;
	t.title = "value";
	t.alignment = 0;
	titles.push_back(t);

	netdetails->AddTitles(titles);

	netdetails->Show();
#endif

	siggraph = new Kis_IntGraph(globalreg, this);
	siggraph->SetName("DETAIL_SIG");
	siggraph->SetPreferredSize(0, 8);
	siggraph->SetScale(-110, -40);
	siggraph->SetInterpolation(1);
	siggraph->SetMode(0);
	siggraph->Show();
	siggraph->AddExtDataVec("Signal", 4, "graph_detail_sig", "yellow,yellow", 
		 					  ' ', ' ', 1, &sigpoints);
	AddComponentVec(siggraph, KIS_PANEL_COMP_EVT);

	packetgraph = new Kis_IntGraph(globalreg, this);
	packetgraph->SetName("DETAIL_PPS");
	packetgraph->SetPreferredSize(0, 8);
	packetgraph->SetScale(0, 0);
	packetgraph->SetInterpolation(1);
	packetgraph->SetMode(0);
	packetgraph->Show();
	packetgraph->AddExtDataVec("Packet Rate", 4, "graph_detail_pps", "green,green", 
							  ' ', ' ', 1, &packetpps);
	AddComponentVec(packetgraph, KIS_PANEL_COMP_EVT);

	retrygraph = new Kis_IntGraph(globalreg, this);
	retrygraph->SetName("DETAIL_RETRY_PPS");
	retrygraph->SetPreferredSize(0, 8);
	retrygraph->SetScale(0, 0);
	retrygraph->SetInterpolation(1);
	retrygraph->SetMode(0);
	retrygraph->Show();
	retrygraph->AddExtDataVec("Retry Rate", 4, "graph_detail_retrypps", "red,red", 
							  ' ', ' ', 1, &retrypps);
	AddComponentVec(retrygraph, KIS_PANEL_COMP_EVT);

	ClearGraphVectors();

	SetTitle("");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	vbox->Pack_End(siggraph, 0, 0);
	vbox->Pack_End(packetgraph, 0, 0);
	vbox->Pack_End(retrygraph, 0, 0);

	vbox->Pack_End(netdetailt, 1, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	last_dirty = 0;
	last_mac = mac_addr(0);
	dng = NULL;

	vector<string> td;
	td.push_back("");
	td.push_back("No network selected / Empty network selected");
	td.push_back("Change sort order to anything other than \"Auto Fit\"");
	td.push_back("and highlight a network.");

	netdetailt->SetText(td);

	UpdateViewMenu(-1);

	SetActiveComponent(netdetailt);

	main_component = vbox;

	Position(WIN_CENTER(LINES, COLS));
}

Kis_NetDetails_Panel::~Kis_NetDetails_Panel() {
	if (grapheventid >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(grapheventid);
}

void Kis_NetDetails_Panel::ClearGraphVectors() {
	lastpackets = 0;
	sigpoints.clear();
	packetpps.clear();
	retrypps.clear();
	for (unsigned int x = 0; x < 120; x++) {
		sigpoints.push_back(-256);
		packetpps.push_back(0);
		retrypps.push_back(0);
	}
}

void Kis_NetDetails_Panel::UpdateGraphVectors(int signal, int pps, int retry) {
	sigpoints.push_back(signal);
	if (sigpoints.size() > 120)
		sigpoints.erase(sigpoints.begin(), sigpoints.begin() + sigpoints.size() - 120);

	if (lastpackets == 0)
		lastpackets = pps;
	packetpps.push_back(pps - lastpackets);
	lastpackets = pps;
	if (packetpps.size() > 120)
		packetpps.erase(packetpps.begin(), packetpps.begin() + packetpps.size() - 120);

	retrypps.push_back(retry);
	if (retrypps.size() > 120)
		retrypps.erase(retrypps.begin(), retrypps.begin() + retrypps.size() - 120);
}

string crypt_to_str(uint64_t cryptset) {
	ostringstream osstr;

	if (cryptset == 0)
		osstr << "None (Open)";
	if (cryptset == crypt_wep)
		osstr << "WEP (Privacy bit set)";
	if (cryptset & crypt_layer3)
		osstr << " Layer3";
	if (cryptset & crypt_wpa_migmode)
		osstr << " WPA Migration Mode";
	if (cryptset & crypt_wep40)
		osstr << " WEP (40bit)";
	if (cryptset & crypt_wep104)
		osstr << " WEP (104bit)";
	if (cryptset & crypt_wpa)
		osstr << " WPA";
	if (cryptset & crypt_tkip)
		osstr << " TKIP";
	if (cryptset & crypt_psk)
		osstr << " PSK";
	if (cryptset & crypt_aes_ocb)
		osstr << " AES-ECB";
	if (cryptset & crypt_aes_ccm)
		osstr << " AES-CCM";
	if (cryptset & crypt_leap)
		osstr << " LEAP";
	if (cryptset & crypt_ttls)
		osstr << " TTLS";
	if (cryptset & crypt_tls)
		osstr << " TLS";
	if (cryptset & crypt_peap)
		osstr << " PEAP";
	if (cryptset & crypt_isakmp)
		osstr << " ISA-KMP";
	if (cryptset & crypt_pptp)
		osstr << " PPTP";
	if (cryptset & crypt_fortress)
		osstr << " Fortress";
	if (cryptset & crypt_keyguard)
		osstr << " Keyguard";
	if (cryptset & crypt_unknown_nonwep)
		osstr << " WPA/ExtIV data";

	return osstr.str();
}

int Kis_NetDetails_Panel::AppendSSIDInfo(vector<string> *td, 
										 Netracker::tracked_network *net,
										 Netracker::adv_ssid_data *ssid) {
	ostringstream osstr;

	if (ssid != NULL) {
		osstr.str("");
		osstr << ssid->ssid;

		if (ssid->type == ssid_beacon) {
			if (ssid->ssid != "")
				osstr << " ";

			if (ssid->ssid_cloaked) 
				osstr << "(Cloaked)";
		} else if (ssid->type == ssid_probereq && ssid->ssid == "") {
			osstr << "(Broadcast request)";
		}

		td->push_back(AlignString("SSID: ", ' ', 2, 16) + osstr.str());

		// Look for probable matches
		if (ssid->ssid_cloaked && ssid->ssid == "" && ssid->type == ssid_beacon) {
			ssid_type t = ssid_file;

			for (map<uint32_t, Netracker::adv_ssid_data *>::iterator asi =
				 net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
				if (asi->second->type == ssid_proberesp && t == ssid_file) {
					td->push_back(AlignString("Probable Decloak: ", ' ', 2, 18) + 
								  asi->second->ssid);
					break;
				} else if (asi->second->type == ssid_file) {
					td->push_back(AlignString("Cached: ", ' ', 2, 18) + 
								  asi->second->ssid);
				}
			}
		}

		td->push_back(AlignString("Length: ", ' ', 2, 18) + 
					  IntToString(ssid->ssid.length()));

		osstr.str("");
		if (ssid->type == ssid_beacon)
			osstr << "Beacon (advertising AP)";
		else if (ssid->type == ssid_probereq)
			osstr << "Request (searching client)";
		else if (ssid->type == ssid_proberesp)
			osstr << "Response (responding AP)";
		else if (ssid->type == ssid_file)
			osstr << "Previously cached SSID";
		else
			osstr << "Unknown";
		td->push_back(AlignString("Type: ", ' ', 2, 18) + osstr.str());

		if (ssid->dot11d_vec.size() > 0) {
			td->push_back(AlignString("802.11d Country: ", ' ', 2, 18) + 
						  ssid->dot11d_country);

			for (unsigned int z = 0; z < ssid->dot11d_vec.size(); z++) {
				td->push_back(AlignString("", ' ', 2, 18) + 
							  string("Channel ") + 
							  IntToString(ssid->dot11d_vec[z].startchan) +
							  string("-") +
							  IntToString(ssid->dot11d_vec[z].startchan +
										  ssid->dot11d_vec[z].numchan - 1) +
							  string(" ") +
							  IntToString(ssid->dot11d_vec[z].txpower) + 
							  string("dBm"));
			}
		}

		osstr.str(crypt_to_str(ssid->cryptset));
		td->push_back(AlignString("Encryption: ", ' ', 2, 18) + osstr.str());

		if (net->type == network_ap) {
			if (ssid->beacons > ssid->beaconrate)
				ssid->beacons = ssid->beaconrate;

			int brate = (int) (((double) ssid->beacons /
								(double) ssid->beaconrate) * 100);

			if (brate > 0) {
				td->push_back(AlignString("Beacon %: ", ' ', 2, 18) + 
							  IntToString(brate));
			}
		}
	}

	return 1;
}

int Kis_NetDetails_Panel::AppendNetworkInfo(vector<string> *td,
											Kis_Display_NetGroup *tng,
											Netracker::tracked_network *net) {
	vector<Netracker::tracked_network *> *netvec = NULL;
	ostringstream osstr;

	if (tng != NULL)
		netvec = tng->FetchNetworkVec();

	td->push_back(AlignString("Name: ", ' ', 2, 16) + tng->GetName(net));

	if (net == NULL && netvec != NULL && netvec->size() > 1) {
		td->push_back(AlignString("# Networks: ", ' ', 2, 16) + 
					 IntToString(netvec->size()));
	}

	// Use the display metanet if we haven't been given one
	if (net == NULL && dng != NULL)
		net = dng->FetchNetwork();

	// Catch nulls just incase
	if (net == NULL)
		return 0;

	td->push_back(AlignString("BSSID: ", ' ', 2, 16) + net->bssid.Mac2String());

	td->push_back(AlignString("Manuf: ", ' ', 2, 16) + net->manuf);

	osstr.str("");
	osstr << setw(14) << left << 
		(string(ctime((const time_t *) &(net->first_time)) + 4).substr(0, 15));
	td->push_back(AlignString("First Seen: ", ' ', 2, 16) + osstr.str());

	osstr.str("");
	osstr << setw(14) << left << 
		(string(ctime((const time_t *) &(net->last_time)) + 4).substr(0, 15));
	td->push_back(AlignString("Last Seen: ", ' ', 2, 16) + osstr.str());

	osstr.str("");
	if (net->type == network_ap)
		osstr << "Access Point (Managed/Infrastructure)";
	else if (net->type == network_probe)
		osstr << "Probe (Client)";
	else if (net->type == network_turbocell)
		osstr << "Turbocell";
	else if (net->type == network_data)
		osstr << "Data Only (No management)";
	else if (net->type == network_mixed)
		osstr << "Mixed (Multiple network types in group)";
	else
		osstr << "Unknown";
	td->push_back(AlignString("Type: ", ' ', 2, 16) + osstr.str());

	osstr.str("");
	if (net->channel != 0)
		osstr << net->channel;
	else
		osstr << "No channel identifying information seen";
	td->push_back(AlignString("Channel: ", ' ', 2, 16) + osstr.str());

	for (map<unsigned int, unsigned int>::const_iterator fmi = 
		 net->freq_mhz_map.begin(); fmi != net->freq_mhz_map.end(); ++fmi) {
		float perc = ((float) fmi->second / 
					  (float) (net->llc_packets + net->data_packets)) * 100;

		int ch = FreqToChan(fmi->first);
		ostringstream chtxt;
		if (ch != 0)
			chtxt << ch;
		else
			chtxt << "Unk";

		osstr.str("");
		osstr << fmi->first << " (" << chtxt.str() << ") - " << 
			fmi->second << " packets, " << 
			NtoString<float>(perc, 2).Str() << "%";
		td->push_back(AlignString(fmi == net->freq_mhz_map.begin() ? 
								  "Frequency: " : "", ' ', 2, 16) + osstr.str());
	}

	if (netvec == NULL || (netvec != NULL && netvec->size() == 1)) {
		if (net->ssid_map.size() > 1) {
			if (net->lastssid != NULL) {
				if (net->lastssid->ssid != "") {
					td->push_back(AlignString("Latest SSID: ", ' ', 2, 16) + 
								  tng->GetName(net));
				}
			} else {
				td->push_back(AlignString("", ' ', 2, 16) + "No SSID data seen");
			}
		}

		if (net->ssid_map.size() > 0) {
			td->push_back("");
			for (map<uint32_t, Netracker::adv_ssid_data *>::iterator s = 
				 net->ssid_map.begin(); s != net->ssid_map.end(); ++s) {
				AppendSSIDInfo(td, net, s->second);
				td->push_back("");
			}
		}
	}

	if (net->snrdata.last_signal_dbm == -256 || net->snrdata.last_signal_dbm == 0) {
		if (net->snrdata.last_signal_rssi == 0) {
			td->push_back(AlignString("Signal: ", ' ', 2, 16) + 
						  "No signal data available");
		} else {
			osstr.str("");
			osstr << net->snrdata.last_signal_rssi << " RSSI (max " <<
				net->snrdata.max_signal_rssi << " RSSI)";
			td->push_back(AlignString("Signal: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			osstr << net->snrdata.last_noise_rssi << " RSSI (max " <<
				net->snrdata.max_noise_rssi << " RSSI)";
			td->push_back(AlignString("Noise: ", ' ', 2, 16) + osstr.str());
		}
	} else {
		osstr.str("");
		osstr << net->snrdata.last_signal_dbm << "dBm (max " <<
			net->snrdata.max_signal_dbm << "dBm)";
		td->push_back(AlignString("Signal: ", ' ', 2, 16) + osstr.str());

		osstr.str("");
		osstr << net->snrdata.last_noise_dbm << "dBm (max " <<
			net->snrdata.max_noise_dbm << "dBm)";
		td->push_back(AlignString("Noise: ", ' ', 2, 16) + osstr.str());
	}

	if (net->data_cryptset != 0) {
		osstr.str(crypt_to_str(net->data_cryptset));
		td->push_back(AlignString("Data Crypt: ", ' ', 2, 16) + osstr.str());
		td->push_back(AlignString(" ", ' ', 2, 16) + "( Data encryption seen "
					  "by BSSID )");
	}

	td->push_back(AlignString("Packets: ", ' ', 2, 16) + 
				  IntToString(net->llc_packets + net->data_packets));

	td->push_back(AlignString("Data Packets: ", ' ', 2, 16) + 
				  IntToString(net->data_packets));

	td->push_back(AlignString("Mgmt Packets: ", ' ', 2, 16) + 
				  IntToString(net->llc_packets));

	td->push_back(AlignString("Crypt Packets: ", ' ', 2, 16) + 
				  IntToString(net->crypt_packets));

	td->push_back(AlignString("Fragments: ", ' ', 2, 16) + 
				  IntToString(net->fragments) + "/sec");

	td->push_back(AlignString("Retries: ", ' ', 2, 16) + 
				  IntToString(net->retries) + "/sec");

	osstr.str("");
	if (net->datasize < 1024) 
		osstr << net->datasize << "B";
	else if (net->datasize < (1024 * 1024)) 
		osstr << (int) (net->datasize / 1024) << "K";
	else 
		osstr << (int) (net->datasize / 1024 / 1024) << "M";
	td->push_back(AlignString("Data Size: ", ' ', 2, 16) + osstr.str());

	if (net->guess_ipdata.ip_type >= ipdata_factoryguess &&
		net->guess_ipdata.ip_type <= ipdata_group) {
		td->push_back("");

		osstr.str("");

		switch (net->guess_ipdata.ip_type) {
			case ipdata_group:
				osstr << "Aggregated";
				break;
			case ipdata_udptcp:
				osstr << "UDP/TCP";
				break;
			case ipdata_arp:
				osstr << "ARP";
				break;
			case ipdata_dhcp:
				osstr << "DHCP";
				break;
			default:
				osstr << "Unknown";
				break;
		}

		td->push_back(AlignString("IP Type: ", ' ', 2, 16) + osstr.str());

		td->push_back(AlignString("IP Address: ", ' ', 2, 16) + 
					 string(inet_ntoa(net->guess_ipdata.ip_addr_block)));
		if (net->guess_ipdata.ip_netmask.s_addr != 0) 
			td->push_back(AlignString("IP Netmask: ", ' ', 2, 16) +
						 string(inet_ntoa(net->guess_ipdata.ip_netmask)));
		if (net->guess_ipdata.ip_gateway.s_addr != 0) 
			td->push_back(AlignString("IP Gateway: ", ' ', 2, 16) +
						 string(inet_ntoa(net->guess_ipdata.ip_gateway)));

		td->push_back("");
	}

	map<uuid, KisPanelInterface::knc_card *> *cardmap =
		kpinterface->FetchNetCardMap();
	map<uuid, KisPanelInterface::knc_card *>::iterator kci;

	for (map<uuid, Netracker::source_data *>::iterator sdi = net->source_map.begin();
		 sdi != net->source_map.end(); ++sdi) {
		if ((kci = cardmap->find(sdi->second->source_uuid)) == cardmap->end()) {
			td->push_back(AlignString("Seen By: ", ' ', 2, 16) + "(Unknown Source) " + 
						  sdi->second->source_uuid.UUID2String());
		} else {
			td->push_back(AlignString("Seen By: ", ' ', 2, 16) +
						  kci->second->name + " (" + kci->second->interface + ") " +
						  sdi->second->source_uuid.UUID2String());
		}
		osstr.str("");
		osstr << setw(14) << left << 
		(string(ctime((const time_t *) &(sdi->second->last_seen)) + 4).substr(0, 15));
		td->push_back(AlignString("", ' ', 2, 16) + osstr.str());
	}

	if (net->cdp_dev_id.length() > 0) {
		td->push_back(AlignString("CDP Device: ", ' ', 2, 16) + net->cdp_dev_id);
		td->push_back(AlignString("CDP Port: ", ' ', 2, 16) + net->cdp_port_id);
	}

	for (map<string, string>::const_iterator ai = net->arb_tag_map.begin();
		 ai != net->arb_tag_map.end(); ++ai) {
		if (ai->first == "" || ai->second == "")
			continue;
		td->push_back(AlignString(ai->first + ": ", ' ', 2, 16) + ai->second);
	}

	if (netvec == NULL)
		return 1;

	if (netvec->size() == 1)
		return 1;

	for (unsigned int x = 0; x < netvec->size(); x++) {
		td->push_back("");
		AppendNetworkInfo(td, NULL, (*netvec)[x]);
	}

	return 1;
}

int Kis_NetDetails_Panel::GraphTimer() {
	Kis_Display_NetGroup *tng, *ldng;
	Netracker::tracked_network *meta, *tmeta;
	int update = 0;

	if (kpinterface == NULL)
		return 1;

	ldng = dng;

	tng = kpinterface->FetchMainPanel()->FetchSelectedNetgroup();
	if (tng != NULL) {
		if (ldng == NULL) {
			ldng = tng;
			update = 1;
		} else {
			meta = ldng->FetchNetwork();
			tmeta = tng->FetchNetwork();

			if (meta == NULL && tmeta != NULL) {
				ldng = tng;
				update = 1;
			} else if (tmeta != NULL && last_mac != tmeta->bssid) {
				ClearGraphVectors();
				return 1;
			} else if (meta != NULL && last_dirty < meta->last_time) {
				update = 1;
			}
		}
	} else if (ldng != NULL) {
		ClearGraphVectors();
	}

	if (update && ldng != NULL) {
		meta = ldng->FetchNetwork();

		UpdateGraphVectors(meta->snrdata.last_signal_dbm == -256 ? 
						   meta->snrdata.last_signal_rssi : 
						   meta->snrdata.last_signal_dbm, 
						   meta->llc_packets + meta->data_packets,
						   meta->retries);
	}

	return 1;
}

void Kis_NetDetails_Panel::DrawPanel() {
	Kis_Display_NetGroup *tng;
	Netracker::tracked_network *meta, *tmeta;
	int update = 0;
	vector<string> td;

	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	// Figure out if we've changed
	tng = kpinterface->FetchMainPanel()->FetchSelectedNetgroup();
	if (tng != NULL) {
		if (dng == NULL) {
			dng = tng;
			update = 1;
		} else {
			meta = dng->FetchNetwork();
			tmeta = tng->FetchNetwork();

			if (meta == NULL && tmeta != NULL) {
				// We didn't have a valid metagroup before - we get the new one
				dng = tng;
				update = 1;
			} else if (tmeta != NULL && last_mac != tmeta->bssid) {
				// We weren't the same network before - we get the new one, clear the
				// graph vectors
				dng = tng;
				ClearGraphVectors();
				update = 1;
			} else if (meta != NULL && last_dirty < meta->last_time) {
				// The network has changed time - just update
				update = 1;
			}
		}
	} else if (dng != NULL) {
		// We've lost a selected network entirely, drop to null and update, clear the
		// graph vectors
		dng = NULL;
		ClearGraphVectors();
		update = 1;
	}

	if (dng == NULL) {
		if ((dng = kpinterface->FetchMainPanel()->FetchSelectedNetgroup()) == NULL) {
			kpinterface->RaiseAlert("No network",
									"Cannot view details, no network was selected.\n"
									"Set the Sort type to anything besides Auto-Fit\n"
									"and highlight a network, then view details.\n");
			kpinterface->KillPanel(this);
			return;
		}

		Netracker::tracked_network *meta = dng->FetchNetwork();

		if (meta == NULL) {
			kpinterface->RaiseAlert("No network",
									"Cannot view details, no network was selected.\n"
									"Set the Sort type to anything besides Auto-Fit\n"
									"and highlight a network, then view details.\n");
			kpinterface->KillPanel(this);
			return;
		}
	}

	if (update) {
		if (dng != NULL)
			meta = dng->FetchNetwork();
		else
			meta = NULL;

		td.clear();

		if (dng != NULL) {
			AppendNetworkInfo(&td, tng, NULL);
		} else {
			td.push_back("No network selected");
			td.push_back("Change sort order to anything other than \"Auto Fit\"");
			td.push_back("and highlight a network.");
		}
	}

	netdetailt->SetText(td);

	DrawComponentVec();

	wmove(win, 0, 0);
}

void Kis_NetDetails_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == closebutton) {
		globalreg->panel_interface->KillPanel(this);
	} else if (in_button == nextbutton) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_DOWN);
		dng = NULL;
	} else if (in_button == prevbutton) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_UP);
		dng = NULL;
	}
}

void Kis_NetDetails_Panel::MenuAction(int opt) {
	// Menu processed an event, do something with it
	if (opt == mi_close) {
		globalreg->panel_interface->KillPanel(this);
		return;
	} else if (opt == mi_addnote) {
		Kis_AddNetNote_Panel *np = new Kis_AddNetNote_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(np);
	} else if (opt == mi_nextnet) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_DOWN);
		dng = NULL;
		return;
	} else if (opt == mi_prevnet) {
		kpinterface->FetchMainPanel()->FetchDisplayNetlist()->KeyPress(KEY_UP);
		dng = NULL;
		return;
	} else if (opt == mi_clients) {
		Kis_Clientlist_Panel *cl = new Kis_Clientlist_Panel(globalreg, kpinterface);
		kpinterface->AddPanel(cl);
	} else if (opt == mi_net || opt == mi_graphsig || opt == mi_graphpacket ||
			   opt == mi_graphretry) {
		UpdateViewMenu(opt);
	}
}

void Kis_NetDetails_Panel::UpdateViewMenu(int mi) {
	string opt;

	if (mi == mi_net) {
		opt = kpinterface->prefs->FetchOpt("DETAILS_SHOWNET");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("DETAILS_SHOWNET", "false", 1);
			menu->SetMenuItemChecked(mi_net, 0);
			netdetailt->Hide();
		} else {
			kpinterface->prefs->SetOpt("DETAILS_SHOWNET", "true", 1);
			menu->SetMenuItemChecked(mi_net, 1);
			netdetailt->Show();
		}
	} else if (mi == mi_graphsig) {
		opt = kpinterface->prefs->FetchOpt("DETAILS_SHOWGRAPHSIG");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHSIG", "false", 1);
			menu->SetMenuItemChecked(mi_graphsig, 0);
			siggraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHSIG", "true", 1);
			menu->SetMenuItemChecked(mi_graphsig, 1);
			siggraph->Show();
		}
	} else if (mi == mi_graphpacket) {
		opt = kpinterface->prefs->FetchOpt("DETAILS_SHOWGRAPHPACKET");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHPACKET", "false", 1);
			menu->SetMenuItemChecked(mi_graphpacket, 0);
			packetgraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHPACKET", "true", 1);
			menu->SetMenuItemChecked(mi_graphpacket, 1);
			packetgraph->Show();
		}
	} else if (mi == mi_graphretry) {
		opt = kpinterface->prefs->FetchOpt("DETAILS_SHOWGRAPHRETRY");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHRETRY", "false", 1);
			menu->SetMenuItemChecked(mi_graphretry, 0);
			retrygraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("DETAILS_SHOWGRAPHRETRY", "true", 1);
			menu->SetMenuItemChecked(mi_graphretry, 1);
			retrygraph->Show();
		}
	} else if (mi == -1) {
		opt = kpinterface->prefs->FetchOpt("DETAILS_SHOWNET");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_net, 1);
			netdetailt->Show();
		} else {
			menu->SetMenuItemChecked(mi_net, 0);
			netdetailt->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("DETAILS_SHOWGRAPHSIG");
		if (opt == "true") {
			menu->SetMenuItemChecked(mi_graphsig, 1);
			siggraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphsig, 0);
			siggraph->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("DETAILS_SHOWGRAPHPACKET");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_graphpacket, 1);
			packetgraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphpacket, 0);
			packetgraph->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("DETAILS_SHOWGRAPHRETRY");
		if (opt == "true") {
			menu->SetMenuItemChecked(mi_graphretry, 1);
			retrygraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphretry, 0);
			retrygraph->Hide();
		}
	}
}

int ChanDetailsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ChanDetails_Panel *) aux)->ButtonAction(component);
	return 1;
}

int ChanDetailsMenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ChanDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

int ChanDetailsGraphEvent(TIMEEVENT_PARMS) {
	((Kis_ChanDetails_Panel *) parm)->GraphTimer();

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

int CliDetailsButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ClientDetails_Panel *) aux)->ButtonAction(component);
	return 1;
}

int CliDetailsMenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_ClientDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

int CliDetailsGraphEvent(TIMEEVENT_PARMS) {
	return ((Kis_ClientDetails_Panel *) parm)->GraphTimer();
}

Kis_ClientDetails_Panel::Kis_ClientDetails_Panel(GlobalRegistry *in_globalreg, 
												 KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	grapheventid =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &CliDetailsGraphEvent, (void *) this);

	menu = new Kis_Menu(globalreg, this);

	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, CliDetailsMenuCB, this);

	mn_client = menu->AddMenu("Client", 0);
	mi_addnote = menu->AddMenuItem("Client Note...", mn_client, 'N');
	menu->AddMenuItem("-", mn_client, 0);
	mi_nextcli = menu->AddMenuItem("Next client", mn_client, 'n');
	mi_prevcli = menu->AddMenuItem("Prev client", mn_client, 'p');
	menu->AddMenuItem("-", mn_client, 0);
	mi_close = menu->AddMenuItem("Close window", mn_client, 'w');

	mn_view = menu->AddMenu("View", 0);
	mi_cli = menu->AddMenuItem("Client Details", mn_view, 'c');
	menu->AddMenuItem("-", mn_view, 0);
	mi_graphsig = menu->AddMenuItem("Signal Level", mn_view, 's');
	mi_graphpacket = menu->AddMenuItem("Packet Rate", mn_view, 'p');
	mi_graphretry = menu->AddMenuItem("Retry Rate", mn_view, 'r');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	clientdetailt = new Kis_Free_Text(globalreg, this);
	AddComponentVec(clientdetailt, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									KIS_PANEL_COMP_TAB));
	clientdetailt->Show();

	siggraph = new Kis_IntGraph(globalreg, this);
	siggraph->SetName("DETAIL_SIG");
	siggraph->SetPreferredSize(0, 8);
	siggraph->SetScale(-110, -40);
	siggraph->SetInterpolation(1);
	siggraph->SetMode(0);
	siggraph->Show();
	siggraph->AddExtDataVec("Signal", 4, "graph_detail_sig", "yellow,yellow", 
		 					  ' ', ' ', 1, &sigpoints);
	AddComponentVec(siggraph, KIS_PANEL_COMP_EVT);

	packetgraph = new Kis_IntGraph(globalreg, this);
	packetgraph->SetName("DETAIL_PPS");
	packetgraph->SetPreferredSize(0, 8);
	packetgraph->SetScale(0, 0);
	packetgraph->SetInterpolation(1);
	packetgraph->SetMode(0);
	packetgraph->Show();
	packetgraph->AddExtDataVec("Packet Rate", 4, "graph_detail_pps", "green,green", 
							  ' ', ' ', 1, &packetpps);
	AddComponentVec(packetgraph, KIS_PANEL_COMP_EVT);

	retrygraph = new Kis_IntGraph(globalreg, this);
	retrygraph->SetName("DETAIL_RETRY_PPS");
	retrygraph->SetPreferredSize(0, 8);
	retrygraph->SetScale(0, 0);
	retrygraph->SetInterpolation(1);
	retrygraph->SetMode(0);
	retrygraph->Show();
	retrygraph->AddExtDataVec("Retry Rate", 4, "graph_detail_retrypps", "red,red", 
							  ' ', ' ', 1, &retrypps);
	AddComponentVec(retrygraph, KIS_PANEL_COMP_EVT);

	ClearGraphVectors();

	SetTitle("");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	vbox->Pack_End(siggraph, 0, 0);
	vbox->Pack_End(packetgraph, 0, 0);
	vbox->Pack_End(retrygraph, 0, 0);

	vbox->Pack_End(clientdetailt, 1, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	last_dirty = 0;
	last_mac = mac_addr(0);
	dng = NULL;
	dcli = NULL;

	vector<string> td;
	td.push_back("No client selected");
	td.push_back("Change client list sort order to something other than ");
	td.push_back("\"Autofit\" and select a client.");
	clientdetailt->SetText(td);

	main_component = vbox;

	SetActiveComponent(clientdetailt);

	clientlist = NULL;

	UpdateViewMenu(-1);

	Position(WIN_CENTER(LINES, COLS));
}

Kis_ClientDetails_Panel::~Kis_ClientDetails_Panel() {
	if (grapheventid >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(grapheventid);
}

void Kis_ClientDetails_Panel::ClearGraphVectors() {
	lastpackets = 0;
	sigpoints.clear();
	packetpps.clear();
	retrypps.clear();
	for (unsigned int x = 0; x < 120; x++) {
		sigpoints.push_back(-256);
		packetpps.push_back(0);
		retrypps.push_back(0);
	}
}

void Kis_ClientDetails_Panel::UpdateGraphVectors(int signal, int pps, int retry) {
	sigpoints.push_back(signal);
	if (sigpoints.size() > 120)
		sigpoints.erase(sigpoints.begin(), sigpoints.begin() + sigpoints.size() - 120);

	if (lastpackets == 0)
		lastpackets = pps;
	packetpps.push_back(pps - lastpackets);
	lastpackets = pps;
	if (packetpps.size() > 120)
		packetpps.erase(packetpps.begin(), packetpps.begin() + packetpps.size() - 120);

	retrypps.push_back(retry);
	if (retrypps.size() > 120)
		retrypps.erase(retrypps.begin(), retrypps.begin() + retrypps.size() - 120);
}

int Kis_ClientDetails_Panel::GraphTimer() {
	Netracker::tracked_client *ldcli;

	if (clientlist == NULL)
		return 1;

	if (kpinterface == NULL)
		return 1;

	ldcli = clientlist->FetchSelectedClient();
	if (ldcli != NULL) {
		if (ldcli != dcli) 
			ClearGraphVectors();
	} else {
		ClearGraphVectors();
		return 1;
	}

	UpdateGraphVectors(ldcli->snrdata.last_signal_dbm == -256 ?
					   ldcli->snrdata.last_signal_rssi :
					   ldcli->snrdata.last_signal_dbm,
					   ldcli->llc_packets + ldcli->data_packets,
					   ldcli->retries);

	return 1;
}

void Kis_ClientDetails_Panel::DrawPanel() {
	Netracker::tracked_client *tcli = NULL;
	int update = 0;
	vector<string> td;
	ostringstream osstr;

	ColorFromPref(text_color, "panel_text_color");
	ColorFromPref(border_color, "panel_border_color");

	wbkgdset(win, text_color);
	werase(win);

	DrawTitleBorder();

	if (clientlist != NULL) {
		tcli = clientlist->FetchSelectedClient();
		if (tcli == NULL) {
			dcli = tcli;
			update = 1;
			ClearGraphVectors();
		} else if (tcli != dcli) {
			dcli = tcli;
			update = 1;
			ClearGraphVectors();
		} else { 
			if (dcli->last_time != last_dirty)
				update = 1;
		}
	} else if (dcli != NULL) {
		dcli = NULL;
		update = 1;
		ClearGraphVectors();
	}

	if (update) {
		if (dcli != NULL) {
			td.push_back(AlignString("MAC Address: ", ' ', 2, 16) + 
						  dcli->mac.Mac2String());

			td.push_back(AlignString("Manuf: ", ' ', 2, 16) + dcli->manuf);

			td.push_back(AlignString("Network: ", ' ', 2, 16) + 
						  dcli->bssid.Mac2String());

			if (dcli->netptr != NULL) {
				if (dcli->netptr->lastssid != NULL &&
					dcli->netptr->lastssid->ssid != "") {
					td.push_back(AlignString("Net SSID: ", ' ', 2, 16) + 
								  dcli->netptr->lastssid->ssid);
				}

				td.push_back(AlignString("Net Manuf: ", ' ', 2, 16) + 
							  dcli->netptr->manuf);
			}

			osstr.str("");
			if (dcli->type == client_unknown)
				osstr << "Unknown";
			else if (dcli->type == client_fromds) 
				osstr << "Wired (traffic from AP only)";
			else if (dcli->type == client_tods)
				osstr << "Wireless (traffic from wireless only)";
			else if (dcli->type == client_interds)
				osstr << "Inter-AP traffic (WDS)";
			else if (dcli->type == client_established)
				osstr << "Wireless (traffic to and from AP)";
			else if (dcli->type == client_adhoc)
				osstr << "Wireless Ad-Hoc";
			td.push_back(AlignString("Type: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			osstr << setw(14) << left <<
				(string(ctime((const time_t *) &(dcli->first_time)) + 4).substr(0, 15));
			td.push_back(AlignString("First Seen: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			osstr << setw(14) << left <<
				(string(ctime((const time_t *) &(dcli->last_time)) + 4).substr(0, 15));
			td.push_back(AlignString("Last Seen: ", ' ', 2, 16) + osstr.str());

			if (dcli->ssid_map.size() > 0) {
				td.push_back("");
				for (map<uint32_t, Netracker::adv_ssid_data *>::iterator si =
					 dcli->ssid_map.begin(); si != dcli->ssid_map.end(); ++si) {

					osstr.str("");
					if (si->second->ssid == "") 
						osstr << "(Broadcast request) ";
					else
						osstr << si->second->ssid << " ";

					td.push_back(AlignString("Probed Network: ", ' ', 2, 16) + 
								 osstr.str());

					osstr.str(crypt_to_str(si->second->cryptset));
					td.push_back(AlignString("Encryption: ", ' ', 2, 18) + osstr.str());

					osstr.str("");
					osstr << setw(14) << left << 
						(string(ctime((const time_t *) 
									  &(si->second->last_time)) + 4).substr(0, 15));
					td.push_back(AlignString("Last Probed: ", ' ', 2, 18) + osstr.str());

					td.push_back("");
				}
			}

			td.push_back(AlignString("Decrypted: ", ' ', 2, 16) + 
						  (dcli->decrypted ? "Yes" : "No"));

			for (map<unsigned int, unsigned int>::const_iterator fmi = 
				 dcli->freq_mhz_map.begin(); fmi != dcli->freq_mhz_map.end(); ++fmi) {
				float perc = ((float) fmi->second / 
							  (float) (dcli->llc_packets + dcli->data_packets)) * 100;

				int ch = FreqToChan(fmi->first);
				ostringstream chtxt;
				if (ch != 0)
					chtxt << ch;
				else
					chtxt << "Unk";

				osstr.str("");
				osstr << fmi->first << " (" << chtxt.str() << ") - " << 
					fmi->second << " packets, " << 
					NtoString<float>(perc, 2).Str() << "%";
				td.push_back(AlignString(fmi == dcli->freq_mhz_map.begin() ? 
										  "Frequency: " : "", ' ', 2, 16) + osstr.str());
			}

			if (dcli->snrdata.last_signal_dbm == -256 || 
				dcli->snrdata.last_signal_dbm == 0) {
				if (dcli->snrdata.last_signal_rssi == 0) {
					td.push_back(AlignString("Signal: ", ' ', 2, 16) + 
								  "No signal data available");
				} else {
					osstr.str("");
					osstr << dcli->snrdata.last_signal_rssi << " RSSI (max " <<
						dcli->snrdata.max_signal_rssi << " RSSI)";
					td.push_back(AlignString("Signal: ", ' ', 2, 16) + osstr.str());

					osstr.str("");
					osstr << dcli->snrdata.last_noise_rssi << " RSSI (max " <<
						dcli->snrdata.max_noise_rssi << " RSSI)";
					td.push_back(AlignString("Noise: ", ' ', 2, 16) + osstr.str());
				}
			} else {
				osstr.str("");
				osstr << dcli->snrdata.last_signal_dbm << "dBm (max " <<
					dcli->snrdata.max_signal_dbm << "dBm)";
				td.push_back(AlignString("Signal: ", ' ', 2, 16) + osstr.str());

				osstr.str("");
				osstr << dcli->snrdata.last_noise_dbm << "dBm (max " <<
					dcli->snrdata.max_noise_dbm << "dBm)";
				td.push_back(AlignString("Noise: ", ' ', 2, 16) + osstr.str());
			}

			if (dcli->data_cryptset != 0) {
				osstr.str(crypt_to_str(dcli->data_cryptset));
				td.push_back(AlignString("Data Crypt: ", ' ', 2, 16) + 
							 osstr.str());
				td.push_back(AlignString(" ", ' ', 2, 16) + "( Data encryption "
							 "seen by client )");
			}

			osstr.str("");
			osstr << dcli->llc_packets + dcli->data_packets;
			td.push_back(AlignString("Packets: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			osstr << dcli->data_packets;
			td.push_back(AlignString("Data Packets: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			osstr << dcli->llc_packets;
			td.push_back(AlignString("Mgmt Packets: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			osstr << dcli->crypt_packets;
			td.push_back(AlignString("Crypt Packets: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			osstr << dcli->fragments << "/sec";
			td.push_back(AlignString("Fragments: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			osstr << dcli->retries << "/sec";
			td.push_back(AlignString("Retries: ", ' ', 2, 16) + osstr.str());

			osstr.str("");
			if (dcli->datasize < 1024) 
				osstr << dcli->datasize << "B";
			else if (dcli->datasize < (1024 * 1024)) 
				osstr << (int) (dcli->datasize / 1024) << "K";
			else 
				osstr << (int) (dcli->datasize / 1024 / 1024) << "M";
			td.push_back(AlignString("Data Size: ", ' ', 2, 16) + osstr.str());

			map<uuid, KisPanelInterface::knc_card *> *cardmap =
				kpinterface->FetchNetCardMap();
			map<uuid, KisPanelInterface::knc_card *>::iterator kci;

			for (map<uuid, Netracker::source_data *>::iterator sdi = 
				 dcli->source_map.begin();
				 sdi != dcli->source_map.end(); ++sdi) {
				if ((kci = cardmap->find(sdi->second->source_uuid)) == cardmap->end()) {
					td.push_back(AlignString("Seen By: ", ' ', 2, 16) + 
								  "(Unknown Source) " + 
								  sdi->second->source_uuid.UUID2String());
				} else {
					td.push_back(AlignString("Seen By: ", ' ', 2, 16) +
								  kci->second->name + " (" + kci->second->interface + 
								  ") " +
								  sdi->second->source_uuid.UUID2String());
				}
				osstr.str("");
				osstr << setw(14) << left << 
					(string(ctime((const time_t *) 
								  &(sdi->second->last_seen)) + 4).substr(0, 15));
				td.push_back(AlignString("", ' ', 2, 16) + osstr.str());
			}

			if (dcli->cdp_dev_id.length() > 0) {
				td.push_back(AlignString("CDP Device: ", ' ', 2, 16) + 
							  dcli->cdp_dev_id);
				td.push_back(AlignString("CDP Port: ", ' ', 2, 16) + 
							  dcli->cdp_port_id);
			}

			if (dcli->dhcp_host.length() > 0) {
				td.push_back(AlignString("DHCP Name: ", ' ', 2, 16) + 
							  dcli->dhcp_host);
			}

			if (dcli->dhcp_vendor.length() > 0) {
				td.push_back(AlignString("DHCP OS: ", ' ', 2, 16) + 
							  dcli->dhcp_vendor);
			}

			if (dcli->guess_ipdata.ip_type > ipdata_factoryguess &&
				dcli->guess_ipdata.ip_type < ipdata_group) {
				td.push_back("");

				osstr.str("");

				switch (dcli->guess_ipdata.ip_type) {
					case ipdata_udptcp:
						osstr << "UDP/TCP";
						break;
					case ipdata_arp:
						osstr << "ARP";
						break;
					case ipdata_dhcp:
						osstr << "DHCP";
						break;
					default:
						osstr << "Unknown";
						break;
				}

				td.push_back(AlignString("IP Type: ", ' ', 2, 16) + osstr.str());

				td.push_back(AlignString("IP Address: ", ' ', 2, 16) + 
							 string(inet_ntoa(dcli->guess_ipdata.ip_addr_block)));
				if (dcli->guess_ipdata.ip_netmask.s_addr != 0) 
					td.push_back(AlignString("IP Netmask: ", ' ', 2, 16) +
								 string(inet_ntoa(dcli->guess_ipdata.ip_netmask)));
				if (dcli->guess_ipdata.ip_gateway.s_addr != 0) 
					td.push_back(AlignString("IP Gateway: ", ' ', 2, 16) +
								 string(inet_ntoa(dcli->guess_ipdata.ip_gateway)));

				td.push_back("");
			}

			for (map<string, string>::const_iterator ai = dcli->arb_tag_map.begin();
				 ai != dcli->arb_tag_map.end(); ++ai) {
				if (ai->first == "" || ai->second == "")
					continue;
				td.push_back(AlignString(ai->first + ": ", ' ', 2, 16) + ai->second);
			}
		}
	}

	clientdetailt->SetText(td);

	DrawComponentVec();
	wmove(win, 0, 0);
}

void Kis_ClientDetails_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	return;
}

void Kis_ClientDetails_Panel::MenuAction(int opt) {
	if (opt == mi_close) {
		globalreg->panel_interface->KillPanel(this);
		return;
	} else if (opt == mi_addnote) {
		Kis_AddCliNote_Panel *np = new Kis_AddCliNote_Panel(globalreg, kpinterface);
		np->SetClient(dcli);
		kpinterface->AddPanel(np);
		return;
	} else if (opt == mi_nextcli && clientlist != NULL) {
		clientlist->KeyPress(KEY_DOWN);
		dcli = NULL;
		return;
	} else if (opt == mi_prevcli && clientlist != NULL) {
		clientlist->KeyPress(KEY_UP);
		dcli = NULL;
		return;
	} else if (opt == mi_cli || opt == mi_graphsig ||
			   opt == mi_graphpacket || opt == mi_graphretry) {
		UpdateViewMenu(opt);
		return;
	}
}

void Kis_ClientDetails_Panel::UpdateViewMenu(int mi) {
	string opt;

	if (mi == mi_cli) {
		opt = kpinterface->prefs->FetchOpt("CLIDETAILS_SHOWCLI");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CLIDETAILS_SHOWCLI", "false", 1);
			menu->SetMenuItemChecked(mi_cli, 0);
			clientdetailt->Hide();
		} else {
			kpinterface->prefs->SetOpt("CLIDETAILS_SHOWCLI", "true", 1);
			menu->SetMenuItemChecked(mi_cli, 1);
			clientdetailt->Show();
		}
	} else if (mi == mi_graphsig) {
		opt = kpinterface->prefs->FetchOpt("CLIDETAILS_SHOWGRAPHSIG");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CLIDETAILS_SHOWGRAPHSIG", "false", 1);
			menu->SetMenuItemChecked(mi_graphsig, 0);
			siggraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("CLIDETAILS_SHOWGRAPHSIG", "true", 1);
			menu->SetMenuItemChecked(mi_graphsig, 1);
			siggraph->Show();
		}
	} else if (mi == mi_graphpacket) {
		opt = kpinterface->prefs->FetchOpt("CLIDETAILS_SHOWGRAPHPACKET");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CLIDETAILS_SHOWGRAPHPACKET", "false", 1);
			menu->SetMenuItemChecked(mi_graphpacket, 0);
			packetgraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("CLIDETAILS_SHOWGRAPHPACKET", "true", 1);
			menu->SetMenuItemChecked(mi_graphpacket, 1);
			packetgraph->Show();
		}
	} else if (mi == mi_graphretry) {
		opt = kpinterface->prefs->FetchOpt("CLIDETAILS_SHOWGRAPHRETRY");
		if (opt == "" || opt == "true") {
			kpinterface->prefs->SetOpt("CLIDETAILS_SHOWGRAPHRETRY", "false", 1);
			menu->SetMenuItemChecked(mi_graphretry, 0);
			retrygraph->Hide();
		} else {
			kpinterface->prefs->SetOpt("CLIDETAILS_SHOWGRAPHRETRY", "true", 1);
			menu->SetMenuItemChecked(mi_graphretry, 1);
			retrygraph->Show();
		}
	} else if (mi == -1) {
		opt = kpinterface->prefs->FetchOpt("CLIDETAILS_SHOWCLI");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_cli, 1);
			clientdetailt->Show();
		} else {
			menu->SetMenuItemChecked(mi_cli, 0);
			clientdetailt->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("CLIDETAILS_SHOWGRAPHSIG");
		if (opt == "true") {
			menu->SetMenuItemChecked(mi_graphsig, 1);
			siggraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphsig, 0);
			siggraph->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("CLIDETAILS_SHOWGRAPHPACKET");
		if (opt == "" || opt == "true") {
			menu->SetMenuItemChecked(mi_graphpacket, 1);
			packetgraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphpacket, 0);
			packetgraph->Hide();
		}

		opt = kpinterface->prefs->FetchOpt("CLIDETAILS_SHOWGRAPHRETRY");
		if (opt == "true") {
			menu->SetMenuItemChecked(mi_graphretry, 1);
			retrygraph->Show();
		} else {
			menu->SetMenuItemChecked(mi_graphretry, 0);
			retrygraph->Hide();
		}
	}
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

int RegDetailsMenuCB(COMPONENT_CALLBACK_PARMS) {
	((Kis_RegDetails_Panel *) aux)->MenuAction(status);
	return 1;
}

Kis_RegDetails_Panel::Kis_RegDetails_Panel(GlobalRegistry *in_globalreg, 
											   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	menu = new Kis_Menu(globalreg, this);

	menu->SetCallback(COMPONENT_CBTYPE_ACTIVATED, RegDetailsMenuCB, this);

	mn_regd = menu->AddMenu("Reg", 0);
	mi_close = menu->AddMenuItem("Close window", mn_regd, 'w');

	menu->Show();
	AddComponentVec(menu, KIS_PANEL_COMP_EVT);

	reglist = new Kis_Scrollable_Table(globalreg, this);
	reglist->SetHighlightSelected(1);
	reglist->SetLockScrollTop(1);
	reglist->SetDrawTitles(1);
	AddComponentVec(reglist, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
							  KIS_PANEL_COMP_TAB));

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;
	t.width = 8;
	t.title = "Cty";
	t.alignment = 0;
	titles.push_back(t);
	t.width = 4;
	t.title = "#Net";
	t.alignment = 3;
	titles.push_back(t);
	t.width = 0;
	t.title = "Channels";
	t.alignment = 0;
	titles.push_back(t);

	netlist = new Kis_Netlist(globalreg, this);
	netlist->Show();
	netlist->SetPreferredSize(0, 10);
	AddComponentVec(netlist, KIS_PANEL_COMP_TAB | KIS_PANEL_COMP_EVT);

	text = new Kis_Free_Text(globalreg, this);
	text->Show();

	SetTitle("");

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);
	vbox->Show();

	vbox->Pack_End(reglist, 1, 0);
	vbox->Pack_End(netlist, 0, 0);
	vbox->Pack_End(text, 0, 0);

	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	main_component = vbox;

	SetActiveComponent(reglist);

	main_netlist = kpinterface->FetchMainPanel()->FetchDisplayNetlist();

	Position(WIN_CENTER(LINES, COLS));
}

Kis_RegDetails_Panel::~Kis_RegDetails_Panel() {
	delete netlist;
}

void Kis_RegDetails_Panel::DrawPanel() {
	// Kind of ugly but it's a specialty panel
	if (main_netlist == NULL)
		return;

	// vector<Kis_Display_NetGroup *> *display_vctor = main_netlist->FetchDisplayVector();
}

void Kis_RegDetails_Panel::MenuAction(int opt) {
	if (opt == mi_close) {
		globalreg->panel_interface->KillPanel(this);
		return;
	}
}

#endif
