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

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "packetchain.h"
#include "kis_netframe.h"
#include "timetracker.h"
#include "filtercore.h"
#include "gpscore.h"
#include "packet.h"
#include "uuid.h"
#include "alertracker.h"
#include "configfile.h"

#include "devicetracker.h"
#include "phy_80211.h"

int phydot11_packethook_wep(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->PacketWepDecryptor(in_pack);
}

int phydot11_packethook_dot11(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->PacketDot11dissector(in_pack);
}

int phydot11_packethook_dot11data(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->PacketDot11dataDissector(in_pack);
}

int phydot11_packethook_dot11classify(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->ClassifierDot11(in_pack);
}

int phydot11_packethook_dot11string(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->PacketDot11stringDissector(in_pack);
}

int phydot11_packethook_dot11tracker(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->TrackerDot11(in_pack);
}

Kis_80211_Phy::Kis_80211_Phy(GlobalRegistry *in_globalreg, 
		Devicetracker *in_tracker, int in_phyid) : 
	Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid) {

	globalreg->InsertGlobal("PHY_80211_TRACKER", this);

	phyname = "IEEE802.11";

	// Packet classifier - makes basic records plus dot11 data
	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11classify, this,
											CHAINPOS_CLASSIFIER, -100);

	globalreg->packetchain->RegisterHandler(&phydot11_packethook_wep, this,
											CHAINPOS_DECRYPT, -100);
	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11, this,
											CHAINPOS_LLCDISSECT, -100);
	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11data, this,
											CHAINPOS_DATADISSECT, -100);
	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11string, this,
											CHAINPOS_DATADISSECT, -99);

	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11tracker, this,
											CHAINPOS_TRACKER, 100);

	// dot11 device comp
	dev_comp_net = devicetracker->RegisterDeviceComponent("DOT11_NET");
	dev_comp_client = devicetracker->RegisterDeviceComponent("DOT11_CLIENT");

	// If we haven't registered packet components yet, do so.  We have to
	// co-exist with the old tracker core for some time
	pack_comp_80211 = _PCM(PACK_COMP_80211) =
		globalreg->packetchain->RegisterPacketComponent("PHY80211");

	pack_comp_basicdata = 
		globalreg->packetchain->RegisterPacketComponent("BASICDATA");

	pack_comp_mangleframe = 
		globalreg->packetchain->RegisterPacketComponent("MANGLEDATA");

	pack_comp_checksum =
		globalreg->packetchain->RegisterPacketComponent("CHECKSUM");

	pack_comp_linkframe = 
		globalreg->packetchain->RegisterPacketComponent("LINKFRAME");

	pack_comp_decap =
		globalreg->packetchain->RegisterPacketComponent("DECAP");

	pack_comp_common = 
		globalreg->packetchain->RegisterPacketComponent("COMMON");

	// Register the dissector alerts
	alert_netstumbler_ref = 
		globalreg->alertracker->ActivateConfiguredAlert("NETSTUMBLER");
	alert_nullproberesp_ref =
		globalreg->alertracker->ActivateConfiguredAlert("NULLPROBERESP");
	alert_lucenttest_ref =
		globalreg->alertracker->ActivateConfiguredAlert("LUCENTTEST");
	alert_msfbcomssid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("MSFBCOMSSID");
	alert_msfdlinkrate_ref =
		globalreg->alertracker->ActivateConfiguredAlert("MSFDLINKRATE");
	alert_msfnetgearbeacon_ref =
		globalreg->alertracker->ActivateConfiguredAlert("MSFNETGEARBEACON");
	alert_longssid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("LONGSSID");
	alert_disconinvalid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DISCONCODEINVALID");
	alert_deauthinvalid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DEAUTHCODEINVALID");
	alert_dhcpclient_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPCLIENTID");

	// Do we process the whole data packet?
    if (globalreg->kismet_config->FetchOptBoolean("hidedata", 0) ||
		globalreg->kismet_config->FetchOptBoolean("dontbeevil", 0)) {
		_MSG("hidedata= set in Kismet config.  Kismet will ignore the contents "
			 "of data packets entirely", MSGFLAG_INFO);
		dissect_data = 0;
	} else {
		dissect_data = 1;
	}

	dissect_strings = 0;
	dissect_all_strings = 0;

	// Load the wep keys from the config file
	if (LoadWepkeys() < 0) {
		globalreg->fatal_condition = 1;
		return;
	}

    if (globalreg->kismet_config->FetchOptBoolean("allowkeytransmit", 0)) {
        _MSG("Allowing Kismet clients to view WEP keys", MSGFLAG_INFO);
        client_wepkey_allowed = 1;
    } else {
		client_wepkey_allowed = 0;
	}

	// Build the wep identity
	for (unsigned int wi = 0; wi < 256; wi++)
		wep_identity[wi] = wi;

	string_filter = new FilterCore(globalreg);
	vector<string> filterlines = 
		globalreg->kismet_config->FetchOptVec("filter_string");
	for (unsigned int fl = 0; fl < filterlines.size(); fl++) {
		if (string_filter->AddFilterLine(filterlines[fl]) < 0) {
			_MSG("Failed to add filter_string config line from the Kismet config "
				 "file.", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}
	}
	
	// _MSG("Registered 80211 PHY as id " + IntToString(in_phyid), MSGFLAG_INFO);
}

Kis_80211_Phy::~Kis_80211_Phy() {
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_wep, CHAINPOS_DECRYPT);
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11, 
										  CHAINPOS_LLCDISSECT);
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11data, 
										  CHAINPOS_DATADISSECT);
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11string,
										  CHAINPOS_DATADISSECT);
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11classify,
										  CHAINPOS_CLASSIFIER);

	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11tracker, 
										  CHAINPOS_TRACKER);

}

int Kis_80211_Phy::LoadWepkeys() {
    // Convert the WEP mappings to our real map
    vector<string> raw_wepmap_vec;
    raw_wepmap_vec = globalreg->kismet_config->FetchOptVec("wepkey");
    for (size_t rwvi = 0; rwvi < raw_wepmap_vec.size(); rwvi++) {
        string wepline = raw_wepmap_vec[rwvi];

        size_t rwsplit = wepline.find(",");
        if (rwsplit == string::npos) {
            _MSG("Malformed 'wepkey' option in the config file", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
        }

        mac_addr bssid_mac = wepline.substr(0, rwsplit).c_str();

        if (bssid_mac.error == 1) {
            _MSG("Malformed 'wepkey' option in the config file", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
        }

        string rawkey = wepline.substr(rwsplit + 1, wepline.length() - (rwsplit + 1));

        unsigned char key[WEPKEY_MAX];
        int len = Hex2UChar((unsigned char *) rawkey.c_str(), key);

        if (len != 5 && len != 13 && len != 16) {
			_MSG("Invalid key '" + rawkey + "' length " + IntToString(len) + 
				 " in a wepkey= config file entry", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
        }

        dot11_wep_key *keyinfo = new dot11_wep_key;
        keyinfo->bssid = bssid_mac;
        keyinfo->fragile = 0;
        keyinfo->decrypted = 0;
        keyinfo->failed = 0;
        keyinfo->len = len;
        memcpy(keyinfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        wepkeys.insert(bssid_mac, keyinfo);

		_MSG("Using key '" + rawkey + "' for BSSID " + bssid_mac.Mac2String(),
			 MSGFLAG_INFO);
    }

	return 1;
}

int Kis_80211_Phy::TimerKick() {
	return 1;
}

dot11_ssid *Kis_80211_Phy::BuildSSID(uint32_t ssid_csum, 
									 dot11_packinfo *packinfo,
									 kis_packet *in_pack) {
	dot11_ssid *adssid;
	kis_tracked_device *dev = NULL;
	dot11_network *net = NULL;

	adssid = new dot11_ssid;
	adssid->checksum = ssid_csum;
	adssid->mac = packinfo->bssid_mac;
	adssid->ssid = string(packinfo->ssid);
	if (packinfo->ssid_len == 0 || packinfo->ssid_blank) {
		adssid->ssid_cloaked = 1;
	}

	adssid->beacon_info = string(packinfo->beacon_info);
	adssid->cryptset = packinfo->cryptset;
	adssid->first_time = globalreg->timestamp.tv_sec;
	adssid->maxrate = packinfo->maxrate;
	adssid->beaconrate = Ieee80211Interval2NSecs(packinfo->beacon_interval);
	adssid->packets = 0;

	// If it's a probe response record it in the SSID cache, we only record
	// one per BSSID for now and only if we have a cloaked SSID on this record.
	// While we're at it, also figure out if we're responding for SSIDs we've never
	// been advertising (in a non-cloaked way), that's probably not a good
	// thing.
	if (packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_resp &&
		(packinfo->ssid_len || packinfo->ssid_blank == 0)) {

		dev = devicetracker->FetchDevice(packinfo->bssid_mac);

		if (dev != NULL) {
			net = (dot11_network *) dev->fetch(dev_comp_net);

			if (net != NULL) {
				for (map<uint32_t, dot11_ssid *>::iterator asi = 
					 net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {

					// Catch beacon, cloaked situation
					if (asi->second->type == dot11_ssid_beacon &&
						asi->second->ssid_cloaked) {
						// Remember the revealed SSID
						ssid_conf->SetOpt(packinfo->bssid_mac.Mac2String(), 
										  packinfo->ssid, 
										  globalreg->timestamp.tv_sec);
					}

				}
			}
		}
	}

	if (packinfo->type == packet_management &&
		(packinfo->subtype == packet_sub_probe_resp || 
		 packinfo->subtype == packet_sub_beacon)) {

		// Run it through the AP spoof protection system
		for (unsigned int x = 0; x < apspoof_vec.size(); x++) {
			// Shortcut to checking the mac address first, if it's one we 
			// have then we don't have to do the expensive operation of pcre or
			// string matching
			if (apspoof_vec[x]->allow_mac_map.find(packinfo->source_mac) !=
				apspoof_vec[x]->allow_mac_map.end()) {
				continue;
			}

			int match = 0, matched = 0;
			string match_type;

#ifdef HAVE_LIBPCRE
			if (apspoof_vec[x]->ssid_re != NULL) {
				int ovector[128];

				match = (pcre_exec(apspoof_vec[x]->ssid_re, apspoof_vec[x]->ssid_study,
								   packinfo->ssid.c_str(), packinfo->ssid.length(),
								   0, 0, ovector, 128) >= 0);

				match_type = "regular expression";
				matched = 1;
			}
#endif

			if (matched == 0) {
				match = (apspoof_vec[x]->ssid == packinfo->ssid);
				match_type = "SSID";
				matched = 1;
			}

			if (match && globalreg->alertracker->PotentialAlert(alert_adhoc_ref)) {
				string ntype = 
					packinfo->subtype == packet_sub_beacon ? string("advertising") :
					string("responding for");

				string al = "Unauthorized device (" + 
					packinfo->source_mac.Mac2String() + string(") ") + ntype + 
					" for SSID '" + packinfo->ssid + "', matching APSPOOF "
					"rule " + apspoof_vec[x]->name + string(" with ") + match_type + 
					string(" which may indicate spoofing or impersonation.");

				globalreg->alertracker->RaiseAlert(alert_ssidmatch_ref, in_pack, 
												   packinfo->bssid_mac, 
												   packinfo->source_mac, 
												   packinfo->dest_mac, 
												   packinfo->other_mac, 
												   packinfo->channel, al);
				break;
			}
		}
	}

	return adssid;
}

int Kis_80211_Phy::ClassifierDot11(kis_packet *in_pack) {
	// Get the 802.11 info
	dot11_packinfo *dot11info = 
		(dot11_packinfo *) in_pack->fetch(pack_comp_80211);

	if (dot11info == NULL)
		return 0;

	kis_common_info *ci = new kis_common_info;

	ci->phyid = phyid;

	if (dot11info->type == packet_management)
		ci->type = packet_basic_mgmt;
	else if (dot11info->type == packet_phy)
		ci->type = packet_basic_phy;
	else if (dot11info->type == packet_data)
		ci->type = packet_basic_data;
	else if (dot11info->type == packet_noise || dot11info->corrupt ||
			 in_pack->error || dot11info->type == packet_unknown ||
			 dot11info->subtype == packet_sub_unknown)
		ci->error = 1;

	ci->datasize = dot11info->datasize;

	// We track devices/nets/clients by source mac
	ci->device = dot11info->source_mac;
	ci->device.SetPhy(phyid);
	ci->source = ci->device;

	in_pack->insert(pack_comp_common, ci);

	return 1;
}

void Kis_80211_Phy::SetStringExtract(int in_extr) {
	if (in_extr == 0 && dissect_strings == 2) {
		_MSG("SetStringExtract(): String dissection cannot be disabled because "
			 "it is required by another active component.", MSGFLAG_ERROR);
		return;
	}

	// If we're setting the extract here, we have to turn it on for all BSSIDs
	dissect_strings = in_extr;
	dissect_all_strings = in_extr;
}

void Kis_80211_Phy::AddWepKey(mac_addr bssid, uint8_t *key, unsigned int len, 
							  int temp) {
	if (len > WEPKEY_MAX)
		return;

    dot11_wep_key *winfo = new dot11_wep_key;

	winfo->decrypted = 0;
	winfo->failed = 0;
    winfo->bssid = bssid;
	winfo->fragile = temp;
    winfo->len = len;

    memcpy(winfo->key, key, len);

    // Replace exiting ones
	if (wepkeys.find(winfo->bssid) != wepkeys.end()) {
		delete wepkeys[winfo->bssid];
		wepkeys[winfo->bssid] = winfo;
		return;
	}

	wepkeys.insert(winfo->bssid, winfo);
}

void Kis_80211_Phy::BlitDevices(int in_fd, vector<kis_tracked_device *> *devlist) {
	
}

int Kis_80211_Phy::TrackerDot11(kis_packet *in_pack) {
	dot11_network *net = NULL;
	dot11_client *cli = NULL;

	// We can't do anything w/ it from the packet layer
	if (in_pack->error || in_pack->filtered)
		return 0;

	// Fetch what we already know about the packet.  
	dot11_packinfo *dot11info =
		(dot11_packinfo *) in_pack->fetch(pack_comp_80211);

	// Got nothing to do
	if (dot11info == NULL)
		return 0;

	kis_common_info *commoninfo =
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	if (commoninfo == NULL)
		return 0;

	kis_data_packinfo *datainfo =
		(kis_data_packinfo *) in_pack->fetch(pack_comp_basicdata);

	// We can't do anything useful
	if (dot11info->corrupt || dot11info->type == packet_noise ||
		dot11info->type == packet_unknown || 
		dot11info->subtype == packet_sub_unknown)
		return 0;

	// Phy-only packets dont' carry anything we can do something smart
	// with at the moment though in the future we might want to
	if (dot11info->type == packet_phy)
		return 0;

	// Do we have a net record?
	kis_tracked_device *dev = devicetracker->FetchDevice(commoninfo->device);

	// buh?  something hinky is going on
	if (dev == NULL) {
		fprintf(stderr, "debug - phydot11 got to tracking stage with no devtracker->dev?\n");
		return 0;
	}

	// Types of phydot11 devices:
	// Client   - A client device, which may be wired or wireless.  Stored under
	// 			  dev_comp_client.  May also represent the direct-from-ap 
	// 			  communications an AP/router combo device, where the AP is its
	// 			  own client.
	//
	// AP		- A device which operates as an AP in some fashion, ie the BSSID
	// 			  target of a packet.  Packet counts reflect all traffic on the
	// 			  BSSID from all clients and traffic from the BSSID itself, so
	// 			  are effectively a double-count of some packets.  Don't add them.
	
	// Actions:
	// - Identify AP
	//   - Create device_tracker ap device if missing
	//   - Create dev_comp_net component on apdev if missing
	// - Learn BSSID, increment AP records
	// - Identify client
	//   - Create device_tracker client device if missing
	//   - Create dev_comp_client on clidev if missing
	// - Increment client counts
	
	// Things we no longer have to worry about because they're handled by
	// the devicetracker layer:
	//  - l1 signal info tracking
	//  - GPS tracking
	//  - Capture source tracking
	//  - Tagging
	//

	// Find or create a device record for the ap device
	kis_tracked_device *apdev =
		devicetracker->MapToDevice(dot11info->bssid_mac, in_pack);

	net = (dot11_network *) apdev->fetch(dev_comp_net);

	if (net == NULL) {
		net = new dot11_network();

		if (dot11info->type == packet_management &&
			dot11info->subtype == packet_sub_probe_req) {
			net->type = dot11_network_probe;
		} else if (dot11info->distrib == distrib_adhoc) {
			net->type = dot11_network_adhoc;
		} else if (dot11info->type == packet_data) {
			net->type = dot11_network_data;
		} else {
			net->type = dot11_network_ap;
		}

		apdev->insert(dev_comp_net, net);
	}

	if (dot11info->distrib == distrib_adhoc && net->type == dot11_network_ap) {
		string al = "Network BSSID " + dot11info->bssid_mac.Mac2String() + 
			" previously advertised as AP network, now advertising as "
			"Ad-Hoc which may indicate AP spoofing/impersonation";

		globalreg->alertracker->RaiseAlert(alert_adhoc_ref, in_pack,
										   dot11info->bssid_mac,
										   dot11info->source_mac,
										   dot11info->dest_mac,
										   dot11info->other_mac,
										   dot11info->channel, al);

	} else if (dot11info->type == packet_management && dot11info->ess &&
		net->type == dot11_network_data) {
		// Turn data-only networks into ap networks if we see management
		// frames
		net->type = dot11_network_ap;
	} else if (dot11info->distrib == distrib_adhoc) {
		// Haven't seen network as managed, now seeing it as adhoc 
		net->type = dot11_network_adhoc;
	}

	net->bss_timestamp = dot11info->timestamp;

	if (dot11info->type == packet_management &&
		(dot11info->subtype == packet_sub_deauthentication ||
		 dot11info->subtype == packet_sub_disassociation))
		net->client_disconnects++;

	net->last_sequence = dot11info->sequence_number;

	// If we've figured out we have data...
	if (datainfo != NULL) {
		if (datainfo->cdp_dev_id != "") {
			if (dot11info->bssid_mac == dot11info->source_mac) {
				net->cdp_dev_id = datainfo->cdp_dev_id;
			}

			cli->cdp_dev_id = datainfo->cdp_dev_id;
		}

		if (datainfo->cdp_port_id != "") {
			if (dot11info->bssid_mac == dot11info->source_mac) {
				net->cdp_port_id = datainfo->cdp_port_id;
			}

			cli->cdp_port_id = datainfo->cdp_port_id;
		}
	}

	// Find the tracked client device
	kis_tracked_device *clidev =
		devicetracker->MapToDevice(dot11info->source_mac, in_pack);

	cli = (dot11_client *) apdev->fetch(dev_comp_client);

	if (cli == NULL) {
		cli = new dot11_client();

		if (dot11info->distrib == distrib_from ||
			(dot11info->type == packet_management &&
			 (dot11info->subtype == packet_sub_beacon ||
			  dot11info->subtype == packet_sub_probe_resp))) {
			cli->type = dot11_client_fromds;
		} else if (dot11info->distrib == distrib_to ||
				   (dot11info->type == packet_management &&
					dot11info->subtype == packet_sub_probe_req)) {
			cli->type = dot11_client_tods;
		} else if (dot11info->distrib == distrib_inter) {
			cli->type = dot11_client_interds;
		} else if (dot11info->distrib == distrib_adhoc) {
			cli->type = dot11_client_adhoc;
		} else {
			cli->type = dot11_client_unknown;
		}

		clidev->insert(dev_comp_client, cli);
	}

	// Interdistrib and adhoc get attached to both tx and rx, for 
	// crypt and data
	if (dot11info->distrib == distrib_from || 
		dot11info->distrib == distrib_adhoc ||
		dot11info->distrib == distrib_inter) {

		net->tx_cryptset |= dot11info->cryptset;
		cli->tx_cryptset |= dot11info->cryptset;

		net->tx_datasize += dot11info->datasize;
		cli->tx_datasize += dot11info->datasize;
	}
	
	if (dot11info->distrib == distrib_to ||
		dot11info->distrib == distrib_adhoc ||
		dot11info->distrib == distrib_inter) {

		net->rx_cryptset |= dot11info->cryptset;
		cli->rx_cryptset |= dot11info->cryptset;

		net->rx_datasize += dot11info->datasize;
		cli->rx_datasize += dot11info->datasize;
	}

	if (dot11info->decrypted) {
		net->decrypted = 1;
		cli->decrypted = 1;
	}

	// fragments, retries, ssid, bssid
	cli->last_bssid = dot11info->bssid_mac;

	cli->fragments += dot11info->fragmented;
	cli->retries += dot11info->retry;

	net->new_packets++;
	cli->new_packets++;

	// We don't have to maintain a dirty vec because the devicetracker does
	// does that for us; anything that managed to be a device here is going
	// to have flagged dirty in the devicetracker
	cli->dirty = 1;
	net->dirty = 1;

	return 1;
}

void Kis_80211_Phy::ExportLogRecord(kis_tracked_device *in_device, string in_logtype, 
								FILE *in_logfile, int in_lineindent) {
	return;
}

