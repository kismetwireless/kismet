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
#include <devicetracker.h>
#include <alertracker.h>
#include <version.h>
#include <phy_80211.h>

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

	int channel;

	unsigned int ssid_valid;
	unsigned int key_confirmed;
	unsigned int key_failed;

	unsigned char key[5];

	string ssid;

	kis_tracked_device *dev;
};

struct kisautowep_state {
	map<mac_addr, kisautowep_net *> netmap;
	int alert_ref;
	unsigned char wep_identity[256];

	Kis_80211_Phy *phy80211;
	Devicetracker *devicetracker;

	int dev_comp_dot11;
	int pack_comp_80211, pack_comp_device, pack_comp_decap;
};

kisautowep_state *state;

kisautowep_net *kisautowep_new() {
	kisautowep_net *net = new kisautowep_net;

	net->ssid_valid = 0;
	net->key_confirmed = 0;
	net->key_failed = 0;
	net->dev = NULL;

	return net;
}

// Sort all the lowest-effort stuff to the top of the pile, exclude
// packets based on wrong phy, wrong OUI, missing tracking data, before
// doing local map searches
int kisautowep_packet_hook(CHAINCALL_PARMS) {
	kisautowep_state *kstate = (kisautowep_state *) auxdata;
	kisautowep_net *anet = NULL;
	char keystr[11];

	if (in_pack->error || in_pack->filtered)
		return 0;

	// Pull the dot11 decode
	dot11_packinfo *packinfo = 
		(dot11_packinfo *) in_pack->fetch(state->pack_comp_80211);

	if (packinfo == NULL) 
		return 0;

	if (packinfo->corrupt || packinfo->type == packet_noise ||
		packinfo->type == packet_unknown || 
		packinfo->subtype == packet_sub_unknown) {
		return 0;
	}

	// If we already know about it, we only care about data frames, don't 
	// process new beacons
	map<mac_addr, kisautowep_net *>::iterator nmi;
	if ((nmi = kstate->netmap.find(packinfo->bssid_mac)) != kstate->netmap.end() &&
		packinfo->type == packet_management)
		return 0;

	// We have to be able to correlate this to a dot11 network, so we need
	// to extract the device and then the dot11 component
	kis_tracked_device_info *dev = NULL;
	dot11_device *dot11dev = NULL;

	dev =
		(kis_tracked_device_info *) in_pack->fetch(state->pack_comp_device);

	if (dev == NULL)
		return 0;


	dot11dev = 
		(dot11_device *) dev->devref->fetch(state->dev_comp_dot11);

	if (dot11dev == NULL)
		return 0;

	// Has to have exactly one beaconing ssid, no default AP is going to be doing
	// multi-ssid stuff
	if (dot11dev->ssid_map.size() < 1)
		return 0;

	// We only start autowepping on beacon packets, we'll look at data
	// for an existing network but that's it
	if (packinfo->type == packet_management && 
		packinfo->subtype == packet_sub_beacon) {

		int n_beacons = 0;
		dot11_ssid *ssid = NULL;
		for (map<uint32_t, dot11_ssid *>::iterator i = dot11dev->ssid_map.begin();
			 i != dot11dev->ssid_map.end(); ++i) {
			if (i->second->type == dot11_ssid_beacon) {
				n_beacons++;
				ssid = i->second;
			}
		}

		if (n_beacons != 1)
			return 0;

		int bssid_possible = 0;

		// is it a fios AP?
		for (unsigned int x = 0; x < num_fios_macs; x++) {
			if (packinfo->bssid_mac == fios_macs[x]) {
				bssid_possible = 1;
				break;
			}
		}

		// Dump out if we're not the right OUI
		if (bssid_possible == 0)
			return 0;

		// Use the SSID from the beacon from in the packet

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

		// We need to make a net
		anet = kisautowep_new();

		anet->bssid = packinfo->bssid_mac;
		anet->dev = dev->devref;

		// Remember it
		kstate->netmap[packinfo->bssid_mac] = anet;

		// Plausible ssid
		anet->ssid_valid = 1;

		anet->channel = ssid->channel;

		anet->ssid = packinfo->ssid;

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
		anet->key[0] = packinfo->bssid_mac[1];
		anet->key[1] = packinfo->bssid_mac[2];

		for (unsigned int x = 0; x < 3; x++) {
			// TODO - this probably doesn't work on little endian?
			anet->key[4 - x] = (base36 >> (x * 8)) & 0xFF;
		}

		snprintf(keystr, 11, "%02X%02X%02X%02X%02X",
				 anet->key[0], anet->key[1],
				 anet->key[2], anet->key[3],
				 anet->key[4]);

		string al = "Auto-WEP guessing WEP key for IEEE802.11 network '" + 
			ssid->ssid + "' BSSID " + packinfo->bssid_mac.Mac2String() + 
			" waiting for data packet to confirm.";

		_MSG(al, MSGFLAG_INFO);

		state->devicetracker->SetDeviceTag(dev->devref->key, "WEP-AUTO-LIKELY",
										   "Network appears to be a default "
										   "AP with a known WEP key", 0);
	} else if (packinfo->type == packet_data) {
		// If we're a data packet and we don't have a network record, bail
		if (nmi == kstate->netmap.end())
			return 0;

		if (packinfo->decrypted)
			return 0;

		if (nmi->second->key_confirmed)
			return 0;

		if (nmi->second->ssid_valid == 0)
			return 0;

		// If we've tried too much, we give up
		if (nmi->second->key_failed > 15)
			return 0;

		// printf("debug - autowep data from %s to %s bssid %s\n", packinfo->source_mac.Mac2String().c_str(), packinfo->dest_mac.Mac2String().c_str(), packinfo->bssid_mac.Mac2String().c_str());

		// Get the data frame
		kis_datachunk *chunk = 
			(kis_datachunk *) in_pack->fetch(state->pack_comp_decap);

		if (chunk == NULL) {
			// printf("debug - autowep - no chunk, going for linkframe\n");
			if ((chunk = 
				 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME))) == NULL) {
				return 0;
			}
		}

		kis_datachunk *decrypted;

		snprintf(keystr, 11, "%02X%02X%02X%02X%02X",
				 nmi->second->key[0], nmi->second->key[1],
				 nmi->second->key[2], nmi->second->key[3],
				 nmi->second->key[4]);

		decrypted = 
			Kis_80211_Phy::DecryptWEP(packinfo, chunk,
									  nmi->second->key, 5,
									  kstate->wep_identity);

		// If we couldn't decrypt, we failed
		if (decrypted == NULL) {
			// Brute force the other keys, but only a few times!  Otherwise we're
			// doing 10x decrypts on every packet.  We only try the other keys the
			// first N data packets we see.  This is incase the wired mac used
			// to derive the key is an actiontec OUI but not the same OUI
			// as the wireless
			unsigned char modkey[5];

			memcpy(modkey, nmi->second->key, 5);

			for (unsigned int x = 0; x < num_fios_macs; x++) {
				modkey[0] = fios_macs[x][1];
				modkey[1] = fios_macs[x][2];

				decrypted = 
					Kis_80211_Phy::DecryptWEP(packinfo, chunk, modkey, 5,
											  kstate->wep_identity);

				// printf("debug - %02X%02X%02X%02X%02X - decrypt %p\n", modkey[0], modkey[1], modkey[2], modkey[3], modkey[4], decrypted);
				if (decrypted != NULL) {
					memcpy(nmi->second->key, modkey, 5);

					snprintf(keystr, 11, "%02X%02X%02X%02X%02X",
							 modkey[0], modkey[1], modkey[2], 
							 modkey[3], modkey[4]);

					_MSG("Auto-WEP confirmed default  WEP key " + string(keystr) + 
						 " for network '" + nmi->second->ssid + "' BSSID " + 
						 nmi->second->bssid.Mac2String(), MSGFLAG_INFO);

					nmi->second->key_failed = 0;

					state->devicetracker->ClearDeviceTag(nmi->second->bssid, 
														 "WEP-AUTO-FAIL");

					goto autowep_key_ok;
				}
			}

			// First-time-fail ops, set the fail attribute for the key, 
			// remove the likely attribute
			if (nmi->second->key_failed == 5) {
				_MSG("Auto-WEP failed to confirm WEP keys for network '" + 
					 nmi->second->ssid + "' BSSID " + 
					 nmi->second->bssid.Mac2String() + " network may not be using "
					 "default WEP", MSGFLAG_INFO);

				state->devicetracker->ClearDeviceTag(nmi->second->bssid, 
													  "WEP-AUTO-LIKELY");

				state->devicetracker->SetDeviceTag(nmi->second->bssid, "WEP-AUTO-FAIL",
													"Not using default WEP key", 0);
			}

			// Increment fail count
			nmi->second->key_failed++;

			return 0;
		}

		// I know.  Shut up.
autowep_key_ok:
		// Otherwise free what we just decrypted
		free(decrypted);

		nmi->second->key_confirmed = 1;

		string al = "Auto-WEP confirmed default WEP key " + string(keystr) + 
			" for network '" + nmi->second->ssid + "' BSSID " + 
			nmi->second->bssid.Mac2String();

		_MSG(al, MSGFLAG_INFO);

		// Raise the alert
		globalreg->alertracker->RaiseAlert(kstate->alert_ref, NULL,
										   nmi->second->bssid,
										   nmi->second->bssid,
										   nmi->second->bssid,
										   nmi->second->bssid,
										   nmi->second->channel, al);

		state->devicetracker->ClearDeviceTag(nmi->second->bssid, 
											 "WEP-AUTO-LIKELY");
		state->devicetracker->ClearDeviceTag(nmi->second->bssid, 
											 "WEP-AUTO-FAIL");

		state->devicetracker->SetDeviceTag(nmi->second->bssid, "WEP-AUTO",
										   string(keystr), 1);

		state->phy80211->AddWepKey(nmi->second->bssid, nmi->second->key, 5, 1);

		return 0;
	}

	return 0;
}

int kisautowep_unregister(GlobalRegistry *in_globalreg) {
	globalreg->packetchain->RemoveHandler(&kisautowep_packet_hook, CHAINPOS_CLASSIFIER);
	return 0;
}

int kisautowep_register(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	if (globalreg->kismet_instance != KISMET_INSTANCE_SERVER) {
		_MSG("Not registering autowep, not running on a kismet server instance.",
			 MSGFLAG_INFO);
		return 1;
	}

	state = new kisautowep_state;

	state->phy80211 = 
		(Kis_80211_Phy *) globalreg->FetchGlobal("PHY_80211");

	if (state->phy80211 == NULL) {
		_MSG("Missing PHY_80211 dot11 packet handler, something is wrong.  "
			 "Trying to use this plugin on an older Kismet?",
			 MSGFLAG_ERROR);
		delete state;
		return -1;
	}

	state->devicetracker = 
		(Devicetracker *) globalreg->FetchGlobal("DEVICE_TRACKER");

	if (state->devicetracker == NULL) {
		_MSG("Missing phy-neutral devicetracker, something is wrong.  "
			 "Trying to use this plugin on an older Kismet?",
			 MSGFLAG_ERROR);
		delete state;
		return -1;
	}

	// Hook after we've classified the network for detecting autowep networks,
	// since we need the SSID to be associated
	globalreg->packetchain->RegisterHandler(&kisautowep_packet_hook, state,
											CHAINPOS_TRACKER, 100);

	state->alert_ref =
		globalreg->alertracker->RegisterAlert("AUTOWEP", sat_minute, 20,
											  sat_second, 5,
											  state->phy80211->FetchPhyId());

	state->dev_comp_dot11 = 
		state->devicetracker->RegisterDeviceComponent("DOT11_DEVICE");

	state->pack_comp_80211 = 
		globalreg->packetchain->RegisterPacketComponent("PHY80211");

	state->pack_comp_device =
		globalreg->packetchain->RegisterPacketComponent("DEVICE");

	state->pack_comp_decap =
		globalreg->packetchain->RegisterPacketComponent("DECAP");

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

