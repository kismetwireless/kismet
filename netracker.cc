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

#include "globalregistry.h"
#include "packetchain.h"
#include "netracker.h"
#include "packet.h"

// These are both just dropthroughs into the class itself
int kis_80211_netracker_hook(CHAINCALL_PARMS) {
	Netracker *auxptr = (Netracker *) auxdata;
	return auxptr->netracker_chain_handler(in_pack);
}

int kis_80211_datatracker_hook(CHAINCALL_PARMS) {
	Netracker *auxptr = (Netracker *) auxdata;
	return auxptr->datatracker_chain_handler(in_pack);
}

Netracker::Netracker() {
	fprintf(stderr, "Netracker() called with no global registry\n");
}

Netracker::Netracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	// Sanity
	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "Netracker() Sanity failed, globalreg->packetchain is NULL, "
				"can't continue\n");
		exit(1);
	}

	// Register the packet hooks with the chain
	globalreg->packetchain->RegisterHandler(&kis_80211_netracker_hook, this,
											CHAINPOS_CLASSIFIER, -100);
	globalreg->packetchain->RegisterHandler(&kis_80211_datatracker_hook, this,
											CHAINPOS_CLASSIFIER, -99);

	// TODO:
	// Register network export components
	// Read tracker files
	
}

int Netracker::netracker_chain_handler(kis_packet *in_pack) {
	tracked_network *net = NULL;

	// Fetch the info from the packet chain data
	kis_ieee80211_packinfo *packinfo = 
		(kis_ieee80211_packinfo *) in_pack->fetch(globalreg->pcr_80211_ref);
	kis_gps_packinfo *gpsinfo = 
		(kis_gps_packinfo *) in_pack->fetch(globalreg->pcr_gps_ref);
	kis_layer1_packinfo *l1info = 
		(kis_layer1_packinfo *) in_pack->fetch(globalreg->pcr_l1_ref);

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

	// Look to see if we already track this bssid and grab it if we do
	track_iter triter = tracked_map.find(packinfo->bssid_mac);
	if (triter != tracked_map.end())
		net = triter->second;

	// Try to map probe reqs into the network they really belong in, if we
	// track probes, and we don't already have a network for them
	if (globalreg->track_probenets && 
		net == NULL &&
		packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_req) {
		if (probe_assoc_map.find(packinfo->bssid_mac) != probe_assoc_map.end()) {
			net = probe_assoc_map[packinfo->bssid_mac];
		}
	} 

	// TODO: Adhoc and inter-ds matching needs to go here once its redone

	// Spawn a new network record
	if (net == NULL) {
		// Constructor will make our network record clear
		net = new Netracker::tracked_network;

		// Cached IP data
		if (bssid_ip_map.find(packinfo->bssid_mac) != bssid_ip_map.end()) {
			net->guess_ipdata = bssid_ip_map[packinfo->bssid_mac];
		}

		// Copy management network info in
		if (packinfo->type == packet_management &&
			packinfo->subtype == packet_sub_beacon) {

			// Find cached SSID if we don't have one
			if (packinfo->ssid_len == 0) {
				if (bssid_cloak_map.find(packinfo->bssid_mac) != 
					bssid_cloak_map.end()) {
					net->ssid = bssid_cloak_map[packinfo->bssid_mac];
					net->ssid_uncloaked = 1;
				}
				net->ssid_cloaked = 1;
			} else {
				net->ssid = string(packinfo->ssid);
				net->ssid_cloaked = 0;
			}
		}

		net->bssid = packinfo->bssid_mac;

		if (packinfo->type == packet_management && 
			packinfo->subtype == packet_sub_probe_req) {
			net->type = network_probe;
		} else if (packinfo->distrib == distrib_adhoc) {
			net->type = network_adhoc;
		} else {
			net->type = network_ap;
		}

		net->first_time = time(0);
		net->bss_timestamp = packinfo->timestamp;

		// Learn it
		tracked_map[net->bssid] = net;

		// Everything else needs to change with new frames so we fill it in
		// outside of the new network code, obviously
	}

	// Extract info from the GPS component, if we have one
	if (gpsinfo != NULL) {
		net->gpsdata.gps_valid = 1;

		if (gpsinfo->lat < net->gpsdata.min_lat)
			net->gpsdata.min_lat = gpsinfo->lat;
		if (gpsinfo->lon < net->gpsdata.min_lon)
			net->gpsdata.min_lon = gpsinfo->lon;
		if (gpsinfo->alt < net->gpsdata.min_alt)
			net->gpsdata.min_alt = gpsinfo->alt;
		if (gpsinfo->spd < net->gpsdata.min_spd)
			net->gpsdata.min_spd = gpsinfo->spd;

		if (gpsinfo->lat > net->gpsdata.max_lat)
			net->gpsdata.max_lat = gpsinfo->lat;
		if (gpsinfo->lon > net->gpsdata.max_lon)
			net->gpsdata.max_lon = gpsinfo->lon;
		if (gpsinfo->alt > net->gpsdata.max_alt)
			net->gpsdata.max_alt = gpsinfo->alt;
		if (gpsinfo->spd > net->gpsdata.max_spd)
			net->gpsdata.max_spd = gpsinfo->spd;

		net->gpsdata.aggregate_lat += gpsinfo->lat;
		net->gpsdata.aggregate_lon += gpsinfo->lon;
		net->gpsdata.aggregate_alt += gpsinfo->alt;
		net->gpsdata.aggregate_points++;

	}

	// L1 signal info, if our capture source was able to inject any into
	// the packet.
	if (l1info != NULL) {
		net->snrdata.last_quality = l1info->quality;
		net->snrdata.last_signal = l1info->signal;
		net->snrdata.last_noise = l1info->noise;

		if (l1info->quality > net->snrdata.max_quality) {
			net->snrdata.max_quality = l1info->quality;
		}

		if (l1info->noise > net->snrdata.max_noise) {
			net->snrdata.max_noise = l1info->noise;
		}

		if (l1info->signal > net->snrdata.max_signal) {
			net->snrdata.max_signal = l1info->signal;

			if (gpsinfo != NULL) {
				net->snrdata.peak_lat = gpsinfo->lat;
				net->snrdata.peak_lon = gpsinfo->lon;
				net->snrdata.peak_alt = gpsinfo->alt;
			}
		}

		if (l1info->datarate < net->snrdata.maxseenrate)
			net->snrdata.maxseenrate = l1info->datarate;

		// Push in the bits for the carrier and encoding
		net->carrier_set |= (1 << (int) l1info->carrier);
		net->encoding_set |= (1 << (int) l1info->encoding);
	}

	// Extract info from beacon frames, they're the only ones we trust to
	// give us good info...
	if (packinfo->type == packet_management && 
		packinfo->subtype == packet_sub_beacon) {
		net->beacon_info = string(packinfo->beacon_info);

		if (packinfo->ssid_len != 0) {
			net->ssid = string(packinfo->ssid);
		}

		if (net->maxrate < packinfo->maxrate)
			net->maxrate = packinfo->maxrate;

		if (packinfo->wep)
			net->encryption |= crypt_wep;

		net->channel = packinfo->channel;

		net->beaconrate = packinfo->beacon_interval;
	}

	// Catch probe responses
	if (net->ssid_cloaked != 0 && net->ssid_uncloaked == 0 &&
		packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_resp &&
		packinfo->ssid_len != 0) {

	}

	if (packinfo->type == packet_management ||
		packinfo->type == packet_phy) {
		net->llc_packets++;
	} else if (packinfo->type == packet_data) {
		net->data_packets++;

		if (packinfo->encrypted)
			net->crypt_packets++;
	}
	// TODO:  FMSWEAK packets

}


