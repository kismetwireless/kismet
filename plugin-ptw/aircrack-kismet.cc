/*
    This file is part of Kismet

	This file was derived directly from aircrack-ng, and most of the other files in 
	this directory come, almost unmodified, from that project.

	For more information about aircrack-ng, visit:
	http://aircrack-ng.org

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

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL. *  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so. *  If you
    do not wish to do so, delete this exception statement from your
    version. *  If you delete this exception statement from all source
    files in the program, then also delete it here.
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
#include <alertracker.h>
#include <version.h>
#include <phy_80211.h>

#include "aircrack-crypto.h"
#include "aircrack-ptw2-lib.h"

GlobalRegistry *globalreg = NULL;

struct kisptw_net {
	mac_addr bssid;

	PTW2_attackstate *ptw_clean;
	PTW2_attackstate *ptw_vague;

	int last_crack_ivs, last_crack_vivs;

	int num_ptw_ivs, num_ptw_vivs;
	int ptw_solved;
	int ptw_attempt;

	// Dupes for our thread
	pthread_t crackthread;
	// Use a mutex for trylock to tell if we're done, if we can lock it,
	// we're done
	pthread_mutex_t crackdone;
	int threaded;
	PTW2_attackstate *ptw_clean_t;
	PTW2_attackstate *ptw_vague_t;
	int num_ptw_ivs_t, num_ptw_vivs_t;

	time_t last_packet;

	int len;
	uint8_t wepkey[64];
};

struct kisptw_state {
	map<mac_addr, kisptw_net *> netmap;
	int timer_ref;
	int alert_ref;

	int dev_comp_dot11;
	int pack_comp_80211, pack_comp_decap, pack_comp_device;

	Kis_80211_Phy *phy80211;
	Devicetracker *devicetracker;
};

kisptw_state *state = NULL;

void *kisptw_crack(void *arg) {
	kisptw_net *pnet = (kisptw_net *) arg;
	int i, j;
	int numpackets = 0;

	/* Clear the thread sigmask so we don't catch sigterm weirdly */
	sigset_t sset;
	sigfillset(&sset);
	pthread_sigmask(SIG_BLOCK, &sset, NULL);

	int (* all)[256];
	int PTW_DEFAULTBF[PTW2_KEYHSBYTES] = 
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	all = (int (*)[256]) alloca(256 * 32 * sizeof(int));

	for (i = 0; i < 32; i++) {
		for (j = 0; j < 256; j++) {
			all[i][j] = 1;
		}
	}

	if (pnet->num_ptw_ivs_t > 99) {
		if (PTW2_computeKey(pnet->ptw_clean_t, pnet->wepkey, 5, 1000, 
						   PTW_DEFAULTBF, all, 1) == 1)
			pnet->len = 5;
		else if (PTW2_computeKey(pnet->ptw_clean_t, pnet->wepkey, 13, (2000000), 
								PTW_DEFAULTBF, all, 1) == 1)
			pnet->len = 13;
		else if (PTW2_computeKey(pnet->ptw_clean_t, pnet->wepkey, 5, (100000),
								PTW_DEFAULTBF, all, 1) == 1)
			pnet->len = 5;
	} 
	
	if (pnet->len == 0 && pnet->num_ptw_vivs_t != 0) {
		PTW_DEFAULTBF[10] = PTW_DEFAULTBF[11] = 1;

		if (PTW2_computeKey(pnet->ptw_vague_t, pnet->wepkey, 5, 1000, 
						   PTW_DEFAULTBF, all, 1) == 1)
			pnet->len = 5;
		else if (PTW2_computeKey(pnet->ptw_vague_t, pnet->wepkey, 13, (2000000), 
								PTW_DEFAULTBF, all, 1) == 1)
			pnet->len = 13;
		else if (PTW2_computeKey(pnet->ptw_vague_t, pnet->wepkey, 5, (200000),
								PTW_DEFAULTBF, all, 1) == 1)
			pnet->len = 5;
	}

	if (pnet->len) {
		pnet->ptw_solved = 1;
	} else {
		pnet->ptw_attempt = 2;
	}

	pthread_mutex_unlock(&(pnet->crackdone));
	pthread_exit((void *) 0);
}

int kisptw_event_timer(TIMEEVENT_PARMS) {
	kisptw_state *kst = (kisptw_state *) auxptr;

	for (map<mac_addr, kisptw_net *>::iterator x = kst->netmap.begin();
		  x != kst->netmap.end(); ++x) {

		if (globalreg->netracker->GetNetworkTag(x->second->bssid, "WEP-AUTO") != "") {
			_MSG("Kismet-PTW stopping cracking attempts on the WEP key for " +
				 x->second->bssid.Mac2String() + ": WEP key found via Auto-WEP",
				 MSGFLAG_INFO);
			x->second->ptw_solved = 1;

			if (x->second->ptw_clean != NULL) {
				PTW2_freeattackstate(x->second->ptw_clean);
				x->second->ptw_clean = NULL;
			}

			if (x->second->ptw_clean_t != NULL) {
				PTW2_freeattackstate(x->second->ptw_clean_t);
				x->second->ptw_clean_t = NULL;
			}

			if (x->second->ptw_vague != NULL) {
				PTW2_freeattackstate(x->second->ptw_vague);
				x->second->ptw_vague = NULL;
			}

			if (x->second->ptw_vague_t != NULL) {
				PTW2_freeattackstate(x->second->ptw_vague_t);
				x->second->ptw_vague_t = NULL;
			}

			return 0;
		}

		if (x->second->ptw_attempt == 2) {
			_MSG("Failed to crack WEP key on " + x->second->bssid.Mac2String() + ": "
				 "Not enough data collected yet", MSGFLAG_INFO);
			x->second->ptw_attempt = 0;
		}

		// If we solved this network, we keep the record but free the rest
		if (x->second->ptw_solved && x->second->ptw_solved < 2) {
			if (x->second->ptw_clean != NULL) {
				PTW2_freeattackstate(x->second->ptw_clean);
				x->second->ptw_clean = NULL;
			}

			if (x->second->ptw_clean_t != NULL) {
				PTW2_freeattackstate(x->second->ptw_clean_t);
				x->second->ptw_clean_t = NULL;
			}

			if (x->second->ptw_vague != NULL) {
				PTW2_freeattackstate(x->second->ptw_vague);
				x->second->ptw_vague = NULL;
			}

			if (x->second->ptw_vague_t != NULL) {
				PTW2_freeattackstate(x->second->ptw_vague_t);
				x->second->ptw_vague_t = NULL;
			}

			ostringstream osstr;

			for (int k = 0; k < x->second->len; k++) {
				osstr << hex << setfill('0') << setw(2) << (int) x->second->wepkey[k];
			}

			globalreg->netracker->SetNetworkTag(x->second->bssid, "WEP-PTW",
												osstr.str(), 1);

			string al = "Cracked WEP key on " + x->second->bssid.Mac2String() + ": " +
				 osstr.str();

			globalreg->alertracker->RaiseAlert(state->alert_ref, NULL,
											   x->second->bssid,
											   x->second->bssid,
											   x->second->bssid,
											   x->second->bssid,
											   0, al);

			Kis_80211_Phy *dot11phy = 
				(Kis_80211_Phy *) globalreg->FetchGlobal("PHY_80211_TRACKER");

			dot11phy->AddWepKey(x->second->bssid, x->second->wepkey,
								x->second->len, 1);

			_MSG("Cleaned up WEP data on " + x->second->bssid.Mac2String(), 
				 MSGFLAG_INFO);
			x->second->ptw_solved = 2;
		}

		if (x->second->threaded) {
			void *ret;

#if 0
			if (pthread_tryjoin_np(x->second->crackthread, &ret) == 0) {
				x->second->threaded = 0;
			}
#endif
			if (pthread_mutex_trylock(&(x->second->crackdone)) == 0) {
				x->second->threaded = 0;
				pthread_mutex_unlock(&(x->second->crackdone));
			}
		}

		// Reset the vague packet buffer if it gets out of hand
		if (x->second->num_ptw_vivs > 200000 && x->second->ptw_vague) {
			x->second->num_ptw_vivs = 0;
			PTW2_freeattackstate(x->second->ptw_vague);
		}

		if (time(0) - x->second->last_packet > 1800 &&
			x->second->last_packet != 0 && x->second->threaded == 0) {
			_MSG("No packets from " + x->second->bssid.Mac2String() + " for 30 "
				 "minutes, removing PTW WEP cracking data", MSGFLAG_INFO);
			if (x->second->ptw_clean != NULL) {
				PTW2_freeattackstate(x->second->ptw_clean);
				x->second->ptw_clean = NULL;
			}

			if (x->second->ptw_clean_t != NULL) {
				PTW2_freeattackstate(x->second->ptw_clean_t);
				x->second->ptw_clean_t = NULL;
			}

			if (x->second->ptw_vague != NULL) {
				PTW2_freeattackstate(x->second->ptw_vague);
				x->second->ptw_vague = NULL;
			}

			if (x->second->ptw_vague_t != NULL) {
				PTW2_freeattackstate(x->second->ptw_vague_t);
				x->second->ptw_vague_t = NULL;
			}

			x->second->last_packet = 0;
		}

		if (x->second->ptw_solved == 0 && 
			(x->second->num_ptw_ivs > x->second->last_crack_ivs + 1000 ||
			 x->second->num_ptw_vivs > x->second->last_crack_vivs + 5000) &&
			x->second->threaded == 0) {

			if (x->second->ptw_clean_t)
				PTW2_freeattackstate(x->second->ptw_clean_t);
			if (x->second->ptw_vague_t)
				PTW2_freeattackstate(x->second->ptw_vague_t);

			x->second->ptw_clean_t = NULL;
			x->second->ptw_vague_t = NULL;

			x->second->ptw_clean_t = PTW2_copyattackstate(x->second->ptw_clean);
			if (x->second->ptw_clean_t == NULL) {
				_MSG("Not enough free memory to copy PTW state", MSGFLAG_ERROR);
				return 0;
			}

			x->second->ptw_vague_t = PTW2_copyattackstate(x->second->ptw_vague);
			if (x->second->ptw_vague_t == NULL) {
				_MSG("Not enough free memory to copy PTW state", MSGFLAG_ERROR);
				PTW2_freeattackstate(x->second->ptw_clean_t);
				return 0;
			}

			x->second->last_crack_ivs = 
				x->second->num_ptw_ivs_t = x->second->num_ptw_ivs;
			x->second->last_crack_vivs = 
				x->second->num_ptw_vivs_t = x->second->num_ptw_vivs;

			x->second->threaded = 1;
			x->second->ptw_attempt = 1;

			_MSG("Trying to crack WEP key on " + x->second->bssid.Mac2String() + ": " +
				 IntToString(x->second->num_ptw_vivs_t + x->second->num_ptw_ivs_t) + 
				 " IVs", MSGFLAG_INFO);

			// Only use trylock, this is bad but we should never get here if we've
			// got a running thread, but I don't want us to block if something gets funny
			pthread_mutex_trylock(&(x->second->crackdone));
			pthread_create(&(x->second->crackthread), NULL, kisptw_crack, x->second);
		}
	}

	return 1;
}

int kisptw_datachain_hook(CHAINCALL_PARMS) {
	kisptw_state *kptw = (kisptw_state *) auxdata;
	kisptw_net *pnet = NULL;

	// Fetch the info from the packet chain data
	dot11_packinfo *packinfo = (dot11_packinfo *) 
		in_pack->fetch(_PCM(PACK_COMP_80211));

	// No 802.11 info, we don't handle it.
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

	kis_data_packinfo *datainfo = (kis_data_packinfo *)
		in_pack->fetch(_PCM(PACK_COMP_BASICDATA));

	// No data info?  We can't handle it
	if (datainfo == NULL) {
		return 0;
	}

	// Make sure we got a network
	Netracker::tracked_network *net;
	kis_netracker_netinfo *netpackinfo =
		(kis_netracker_netinfo *) in_pack->fetch(_PCM(PACK_COMP_TRACKERNET));

	// No network?  Can't handle this either.
	if (netpackinfo == NULL) {
		return 0;
	}

	net = netpackinfo->netref;

	// Make sure we got a client, too
	Netracker::tracked_client *cli;
	kis_netracker_cliinfo *clipackinfo =
		(kis_netracker_cliinfo *) in_pack->fetch(_PCM(PACK_COMP_TRACKERCLIENT));

	// No network?  Can't handle this either.
	if (clipackinfo == NULL) {
		return 0;
	}

	cli = clipackinfo->cliref;

	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_MANGLEFRAME));

	if (chunk == NULL) {
		if ((chunk = 
			 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_80211FRAME))) == NULL) {
			if ((chunk = (kis_datachunk *) 
				 in_pack->fetch(_PCM(PACK_COMP_LINKFRAME))) == NULL) {
				return 0;
			}
		}
	}

	// Handle WEP + PTW
	// printf("debug - cryptset %lx modified %lx\n", packinfo->cryptset, packinfo->cryptset & crypt_protectmask);
	if ((packinfo->cryptset & crypt_protectmask) == crypt_wep &&
		chunk != NULL && packinfo->header_offset < chunk->length &&
		chunk->length - packinfo->header_offset > 7) {

		if (chunk->data[packinfo->header_offset + 3] & 0x20) {
			return 0;
		}

		if (kptw->netmap.find(net->bssid) == kptw->netmap.end()) {
			pnet = new kisptw_net;
			pnet->ptw_clean = pnet->ptw_vague = NULL;
			pnet->ptw_clean_t = pnet->ptw_vague_t = NULL;
			pnet->num_ptw_ivs = pnet->num_ptw_vivs = 0;
			pnet->num_ptw_ivs_t = pnet->num_ptw_vivs_t = 0;
			pnet->last_crack_vivs = pnet->last_crack_ivs = 0;
			pnet->ptw_solved = 0;
			pnet->ptw_attempt = 0;
			pnet->threaded = 0;
			pnet->bssid = net->bssid;
			pnet->last_packet = time(0);
			memset(pnet->wepkey, 0, sizeof(pnet->wepkey));
			pnet->len = 0;
			pthread_mutex_init(&(pnet->crackdone), NULL);
			kptw->netmap.insert(make_pair(net->bssid, pnet));

			if (globalreg->netracker->GetNetworkTag(net->bssid, "WEP-AUTO") != "") {
				_MSG("Not collecting WEP PTW data on " + pnet->bssid.Mac2String() + 
					 " as it looks like an Auto-WEP network", MSGFLAG_INFO);
				pnet->ptw_solved = 1;
			} else {
				_MSG("Collecting WEP PTW data on " + pnet->bssid.Mac2String(), 
					 MSGFLAG_INFO);
			}
		} else {
			pnet = kptw->netmap.find(net->bssid)->second;
		}

		if (pnet->ptw_solved)
			return 1;

		int clearsize, i, j, k;
		int weight[16];
		unsigned char clear[2048];
		unsigned char clear2[2048];

		memset(weight, 0, sizeof(weight));
		memset(clear, 0, sizeof(clear));
		memset(clear2, 0, sizeof(clear2));

		k = known_clear(clear, &clearsize, clear2, 
						chunk->data + packinfo->header_offset, 
						chunk->length - packinfo->header_offset - 8);

		if (clearsize >= 16) {
			for (j = 0; j < k; j++) {
				for (i = 0; i < clearsize && 
					 4 + i + packinfo->header_offset < chunk->length; i++) {

					clear[i+(PTW2_KSBYTES*j)] ^= 
						chunk->data[4 + i + packinfo->header_offset];
				}
			}

			if (pnet->ptw_clean == NULL) {
				pnet->ptw_clean = PTW2_newattackstate();
				if (pnet->ptw_clean == NULL) {
					_MSG("Failed to allocate memory for PTW attack state",
						 MSGFLAG_ERROR);
					return 1;
				}
			}

			if (pnet->ptw_vague == NULL) {
				pnet->ptw_vague = PTW2_newattackstate();
				if (pnet->ptw_vague == NULL) {
					_MSG("Failed to allocate memory for PTW attack state",
						 MSGFLAG_ERROR);
					return 1;
				}
			}

			int added = 0;
			if (k == 1) {
				if (PTW2_addsession(pnet->ptw_clean, 
								   chunk->data + packinfo->header_offset,
								   clear, clear2, k)) {
					pnet->num_ptw_ivs++;
					added = 1;
				}
			} else {
				if (PTW2_addsession(pnet->ptw_vague, 
								   chunk->data + packinfo->header_offset,
								   clear, clear2, k)) {
					pnet->num_ptw_vivs++;
					added = 1;
				}
			}

			if (added) {
				pnet->last_packet = time(0);
				globalreg->netracker->SetNetworkTag(pnet->bssid, "WEP-PTW-IV",
													IntToString(pnet->num_ptw_ivs), 0);
				globalreg->netracker->SetNetworkTag(pnet->bssid, "WEP-PTW-UNK",
													IntToString(pnet->num_ptw_vivs), 0);
			}
		}
	}

	return 0;
}

int kisptw_unregister(GlobalRegistry *in_globalreg) {
	int warned = 0;
	void *ret;

	if (state == NULL)
		return 0;

	globalreg->packetchain->RemoveHandler(&kisptw_datachain_hook, CHAINPOS_CLASSIFIER);
	globalreg->timetracker->RemoveTimer(state->timer_ref);

	// Cancel the thread and wait for it to shut down
	for (map<mac_addr, kisptw_net *>::iterator x = state->netmap.begin();
		  x != state->netmap.end(); ++x) {

		if (x->second->threaded == 0)
			continue;

		warned++;

		pthread_cancel(x->second->crackthread);
	}

	if (warned) {
		_MSG("Aircrack-PTW: Canceling & waiting for " + IntToString(warned) + 
			 " pending PTW-crack threads to finish", MSGFLAG_INFO);

		for (map<mac_addr, kisptw_net *>::iterator x = state->netmap.begin();
			 x != state->netmap.end(); ++x) {

			if (x->second->threaded == 0)
				continue;

			pthread_join(x->second->crackthread, &ret);
		}
	}

	return 0;
}

int kisptw_register(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	if (globalreg->kismet_instance != KISMET_INSTANCE_SERVER) {
		_MSG("Not initializing PTW plugin, not running on a server",
			 MSGFLAG_INFO);
		return 1;
	}

	state = new kisptw_state;

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

	globalreg->packetchain->RegisterHandler(&kisptw_datachain_hook, state,
											CHAINPOS_CLASSIFIER, 100);

	state->timer_ref =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5, NULL, 1,
											  &kisptw_event_timer, state);

	state->alert_ref =
		globalreg->alertracker->RegisterAlert("WEPCRACK", sat_minute, 20,
											  sat_second, 5,
											  state->phy80211->FetchPhyId());

	return 1;
}

extern "C" {
	int kis_plugin_info(plugin_usrdata *data) {
		data->pl_name = "AIRCRACK-PTW";
		data->pl_version = string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
			string(VERSION_TINY);
		data->pl_description = "Aircrack PTW Plugin";
		data->pl_unloadable = 0; // We can't be unloaded because we defined a source
		data->plugin_register = kisptw_register;
		data->plugin_unregister = kisptw_unregister;

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

