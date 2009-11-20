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
#include <string>
#include <errno.h>
#include <time.h>

#include <pthread.h>

#include <sstream>
#include <iomanip>

#include <util.h>
#include <messagebus.h>
#include <packet.h>
#include <packetchain.h>
#include <packetsource.h>
#include <packetsourcetracker.h>
#include <timetracker.h>
#include <configfile.h>
#include <plugintracker.h>
#include <globalregistry.h>
#include <netracker.h>
#include <packetdissectors.h>
#include <alertracker.h>
#include <version.h>

GlobalRegistry *globalreg = NULL;

mac_addr fios_macs[] = {
	mac_addr("00:18:01:00:00:00/FF:FF:FF:00:00:00"),
	mac_addr("00:1F:90:00:00:00/FF:FF:FF:00:00:00"),
	mac_addr("00:0F:B3:00:00:00/FF:FF:FF:00:00:00"),
	mac_addr("00:15:05:00:00:00/FF:FF:FF:00:00:00"),
	mac_addr("00:1B:03:00:00:00/FF:FF:FF:00:00:00"), 
	mac_addr("00:1E:A7:00:00:00/FF:FF:FF:00:00:00"),
	mac_addr("00:20:E0:00:00:00/FF:FF:FF:00:00:00"),
	mac_addr("00:24:7B:00:00:00/FF:FF:FF:00:00:00"),
	mac_addr("00:26:62:00:00:00/FF:FF:FF:00:00:00"),
	mac_addr("00:26:B8:00:00:00/FF:FF:FF:00:00:00")
};
#define num_fios_macs		10

struct kisautowep_net {
	mac_addr bssid;

	unsigned int ssid_valid;
	unsigned int key_confirmed;
	unsigned int key_failed;

	unsigned char key[5];

	Netracker::tracked_network *net;
};

struct kisautowep_state {
	map<mac_addr, kisautowep_net *> netmap;
	int alert_ref;
	unsigned char wep_identity[256];
};

kisautowep_state *state;

kisautowep_net *kisautowep_new() {
	kisautowep_net *net = new kisautowep_net;

	net->ssid_valid = 0;
	net->key_confirmed = 0;
	net->key_failed = 0;
	net->net = NULL;

	return net;
}

// Sort all the lowest-effort stuff to the top of the pile, exclude
// packets based on wrong phy, wrong OUI, missing tracking data, before
// doing local map searches
int kisautowep_packet_hook(CHAINCALL_PARMS) {
	kisautowep_state *kstate = (kisautowep_state *) auxdata;
	kisautowep_net *anet = NULL;
	char keystr[11];

	// printf("debug - autoweb packet hook\n");

	// Pull the dot11 decode
	kis_ieee80211_packinfo *packinfo = (kis_ieee80211_packinfo *)
		in_pack->fetch(_PCM(PACK_COMP_80211));

	if (packinfo == NULL) {
		return 0;
	}

	// Not an 802.11 frame type we known how to track, we'll just skip
	// it, too
	if (packinfo->corrupt || packinfo->type == packet_noise ||
		packinfo->type == packet_unknown || 
		packinfo->subtype == packet_sub_unknown) {
		return 0;
	}

	// We have to have a network record
	Netracker::tracked_network *net;
	kis_netracker_netinfo *netpackinfo =
		(kis_netracker_netinfo *) in_pack->fetch(_PCM(PACK_COMP_TRACKERNET));

	// No network?  Can't handle this either.
	if (netpackinfo == NULL) {
		return 0;
	}

	// We can only make new networks on beacons
	if (packinfo->type != packet_management ||
		packinfo->subtype != packet_sub_beacon)
		return 0;

	net = netpackinfo->netref;

	// Has to have exactly 1 ssid, since no default ap is going to be doing
	// anything clever
	if (net->ssid_map.size() < 1)
		return 0;

	// If we already know about it, we only care about data frames
	map<mac_addr, kisautowep_net *>::iterator nmi;
	if ((nmi = kstate->netmap.find(net->bssid)) != kstate->netmap.end()) {
		return 0;
	}

	int bssid_possible = 0;

	// is it a fios AP?
	for (unsigned int x = 0; x < num_fios_macs; x++) {
		if (net->bssid == fios_macs[x]) {
			bssid_possible = 1;
			break;
		}
	}

	// Dump out if we're not the right OUI
	if (bssid_possible == 0)
		return 0;

	// Get the SSID in the stupidest way possible (we know it's only 1...)
	Netracker::adv_ssid_data *ssid =
		((net->ssid_map.begin())++)->second;

	// We need to make a net
	anet = kisautowep_new();

	anet->bssid = net->bssid;
	anet->net = net;

	// Remember it
	kstate->netmap[net->bssid] = anet;

	// Has to be AP
	if (ssid->type != ssid_beacon)
		return 0;

	// Has to be WEP
	if (ssid->cryptset != crypt_wep)
		return 0;

	// Has to be 5 characters
	if (ssid->ssid.length() != 5) {
		return 0;
	}

	// Has to be 0-9 A-Z
	for (unsigned int x = 0; x < ssid->ssid.length(); x++) {
		if ((ssid->ssid[x] < '0' || ssid->ssid[x] > '9') &&
			(ssid->ssid[x] < 'A' || ssid->ssid[x] > 'Z')) {
			return 0;
		}
	}

	// Plausible ssid
	anet->ssid_valid = 1;

	// Calculate the base36 value
	unsigned long int base36 = 0;

	for (unsigned int x = 0; x < ssid->ssid.length(); x++) {
		if (ssid->ssid[x] >= '0' && ssid->ssid[x] <= '9') {
			base36 += (ssid->ssid[x] - '0') * pow(36, x);
		} else if (ssid->ssid[x] >= 'A' && ssid->ssid[x] <= 'Z') {
			base36 += (ssid->ssid[x] - 'A' + 10) * pow(36, x);
		}
	}

	// First 2 bits, bytes 1 and 2 of the BSSID
	anet->key[0] = net->bssid[1];
	anet->key[1] = net->bssid[2];

	for (unsigned int x = 0; x < 3; x++) {
		// TODO - this probably doesn't work on little endian?
		anet->key[4 - x] = (base36 >> (x * 8)) & 0xFF;
	}

	snprintf(keystr, 11, "%02X%02X%02X%02X%02X",
			 anet->key[0], anet->key[1],
			 anet->key[2], anet->key[3],
			 anet->key[4]);

	string al = "Auto-WEP guessed default WEP key " + string(keystr) + " for network '" +
		 MungeToPrintable(ssid->ssid) + "' BSSID " + net->bssid.Mac2String();

	_MSG(al, MSGFLAG_INFO);

	globalreg->netracker->SetNetworkTag(net->bssid, "WEP-AUTO-LIKELY",
										string(keystr), 0);

	return 0;
}

// Handle data frames before classification
int kisautowep_data_hook(CHAINCALL_PARMS) {
	kisautowep_state *kstate = (kisautowep_state *) auxdata;
	kisautowep_net *anet = NULL;
	char keystr[11];

	// Pull the dot11 decode
	kis_ieee80211_packinfo *packinfo = (kis_ieee80211_packinfo *)
		in_pack->fetch(_PCM(PACK_COMP_80211));

	if (packinfo == NULL) {
		return 0;
	}

	// Not an 802.11 frame type we known how to track, we'll just skip
	// it, too
	if (packinfo->corrupt || packinfo->type == packet_noise ||
		packinfo->type == packet_unknown || 
		packinfo->subtype == packet_sub_unknown) {
		return 0;
	}

	// We don't care about anything but data if we've already seen the network
	if (packinfo->type != packet_data || packinfo->decrypted) {
		return 0;
	}

	map<mac_addr, kisautowep_net *>::iterator nmi;

	// Don't do anything if we don't know what this is
	if ((nmi = kstate->netmap.find(packinfo->bssid_mac)) == kstate->netmap.end()) 
		return 0;

	// Get the SSID in the stupidest way possible (we know it's only 1...)
	Netracker::adv_ssid_data *ssid =
		((nmi->second->net->ssid_map.begin())++)->second;

	// If we've confirmed everything, we're done
	if (nmi->second->key_confirmed)  {
		return 0;
	}

	// If we're not a valid network, don't try
	if (nmi->second->ssid_valid == 0) {
		return 0;
	}

	// If we've tried too much, we give up
	if (nmi->second->key_failed > 5) {
		return 0;
	}

	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_80211FRAME));

	if (chunk == NULL) {
		if ((chunk = 
			 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME))) == NULL) {
			return 0;
		}
	}

	if (chunk == NULL) {
		return 0;
	}

	kis_datachunk *decrypted;

	snprintf(keystr, 11, "%02X%02X%02X%02X%02X",
			 nmi->second->key[0], nmi->second->key[1],
			 nmi->second->key[2], nmi->second->key[3],
			 nmi->second->key[4]);

	decrypted = 
		KisBuiltinDissector::DecryptWEP(packinfo, chunk,
										nmi->second->key, 5,
										kstate->wep_identity);

	// If we couldn't decrypt, we failed
	if (decrypted == NULL) {
		// Brute force the other keys, but only a few times!  Otherwise we're
		// doing 10x decrypts on every packet.  We only try the other keys the
		// first N data packets we see.  This is incase the wired mac used
		// to derive the key is an actiontec OUI but not the same OUI
		// as the wireless
		if (nmi->second->key_failed < 5) {
			unsigned char modkey[5];

			memcpy(modkey, nmi->second->key, 5);

			for (unsigned int x = 0; x < num_fios_macs; x++) {
				modkey[0] = fios_macs[x][1];
				modkey[1] = fios_macs[x][2];

				decrypted = 
					KisBuiltinDissector::DecryptWEP(packinfo, chunk,
													modkey, 5,
													kstate->wep_identity);

				if (decrypted != NULL) {
					memcpy(nmi->second->key, modkey, 5);

					snprintf(keystr, 11, "%02X%02X%02X%02X%02X",
							 nmi->second->key[0], nmi->second->key[1],
							 nmi->second->key[2], nmi->second->key[3],
							 nmi->second->key[4]);

					_MSG("Auto-WEP found alternate WEP key " + string(keystr) + 
						 " for network '" + MungeToPrintable(ssid->ssid) + 
						 "' BSSID " + nmi->second->bssid.Mac2String(), MSGFLAG_INFO);

					nmi->second->key_failed = 0;

					globalreg->netracker->ClearNetworkTag(nmi->second->bssid, 
														  "WEP-AUTO-FAIL");

					goto autowep_key_ok;
				}
			}
		}

		// First-time-fail ops, set the fail attribute for the key, 
		// remove the likely attribute
		if (nmi->second->key_failed == 0) {
			_MSG("Auto-WEP failed to confirm WEP keys for network '" + 
				 MungeToPrintable(ssid->ssid) + "' BSSID " + 
				 nmi->second->bssid.Mac2String() + " network may not be using "
				 "default WEP", MSGFLAG_INFO);

			globalreg->netracker->ClearNetworkTag(nmi->second->bssid, "WEP-AUTO-LIKELY");

			globalreg->netracker->SetNetworkTag(nmi->second->bssid, "WEP-AUTO-FAIL",
												"Not using default WEP key", 0);
		}

		// Increment fail count
		nmi->second->key_failed++;

		return 0;
	}

	// I know.  Shut up.
autowep_key_ok:

	// printf("debug - %s got to key ok\n", nmi->second->bssid.Mac2String().c_str());

	// Otherwise free what we just decrypted
	free(decrypted);

	nmi->second->key_confirmed = 1;

	string al = "Auto-WEP confirmed default WEP key " + string(keystr) + 
		" for network '" + MungeToPrintable(ssid->ssid) + "' BSSID " + 
		nmi->second->bssid.Mac2String();

	_MSG(al, MSGFLAG_INFO);

	// Raise the alert
	globalreg->alertracker->RaiseAlert(kstate->alert_ref, NULL,
									   nmi->second->bssid,
									   nmi->second->bssid,
									   nmi->second->bssid,
									   nmi->second->bssid,
									   nmi->second->net->channel, al);

	globalreg->netracker->ClearNetworkTag(nmi->second->bssid, "WEP-AUTO-LIKELY");
	globalreg->netracker->ClearNetworkTag(nmi->second->bssid, "WEP-AUTO-FAIL");

	globalreg->netracker->SetNetworkTag(nmi->second->bssid, "WEP-AUTO",
										string(keystr), 1);

	globalreg->builtindissector->AddWepKey(nmi->second->bssid, nmi->second->key, 5, 1);

	return 0;
}

int kisautowep_unregister(GlobalRegistry *in_globalreg) {
	globalreg->packetchain->RemoveHandler(&kisautowep_packet_hook, CHAINPOS_CLASSIFIER);
	globalreg->packetchain->RemoveHandler(&kisautowep_data_hook, CHAINPOS_CLASSIFIER);
	return 0;
}

int kisautowep_register(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	state = new kisautowep_state;

	// Hook after we've classified the network for detecting autowep networks,
	// since we need the SSID to be associated
	globalreg->packetchain->RegisterHandler(&kisautowep_packet_hook, state,
											CHAINPOS_CLASSIFIER, 100);
	// Register data handler late after the existing LLC handlers so we get all
	// their state, but before the crypt handlers
	globalreg->packetchain->RegisterHandler(&kisautowep_data_hook, state,
											CHAINPOS_LLCDISSECT, 100);

	state->alert_ref =
		globalreg->alertracker->RegisterAlert("AUTOWEP", sat_minute, 20,
											  sat_second, 5);

	for (unsigned int wi = 0; wi < 256; wi++)
		state->wep_identity[wi] = wi;

	return 1;
}

extern "C" {
	int kis_plugin_info(plugin_usrdata *data) {
		data->pl_name = "AUTOWEP";
		data->pl_version = string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
			string(VERSION_TINY);
		data->pl_description = "AutoWEP Plugin";
		data->pl_unloadable = 0; // We can't be unloaded because we defined a source
		data->plugin_register = kisautowep_register;
		data->plugin_unregister = kisautowep_unregister;

		return 1;
	}

	void kis_revision_info(plugin_revision *prev) {
		if (prev->version_api_revision >= 1) {
			prev->version_api_revision = 1;
			prev->major = string(VERSION_MAJOR);
			prev->minor = string(VERSION_MINOR);
			prev->tiny = string(VERSION_TINY);
		}
	}
}

