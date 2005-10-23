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
#include <sstream>

#include "globalregistry.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "netracker.h"
#include "packet.h"
#include "gpsdclient.h"
#include "alertracker.h"

// TCP server hooks
char *NETWORK_fields_text[] = {
    "bssid", "type", "ssid", "beaconinfo",
    "llcpackets", "datapackets", "cryptpackets",
    "weakpackets", "channel", "wep", "firsttime",
    "lasttime", "atype", "rangeip", "netmaskip",
	"gatewayip", "gpsfixed",
    "minlat", "minlon", "minalt", "minspd",
    "maxlat", "maxlon", "maxalt", "maxspd",
    "octets", "cloaked", "beaconrate", "maxrate",
    "manufkey", "manufscore",
    "quality", "signal", "noise",
    "bestquality", "bestsignal", "bestnoise",
    "bestlat", "bestlon", "bestalt",
    "agglat", "agglon", "aggalt", "aggpoints",
    "datasize",
    "turbocellnid", "turbocellmode", "turbocellsat",
    "carrierset", "maxseenrate", "encodingset",
    "decrypted", "dupeivpackets", "bsstimestamp",
	"cdpdevice", "cdpport", "fragments", "retries",
	"newpackets",
    NULL
};

char *REMOVE_fields_text[] = {
    "bssid",
    NULL
};

char *CLIENT_fields_text[] = {
    "bssid", "mac", "type", "firsttime", "lasttime",
    "manufkey", "manufscore",
    "llcpackets", "datapackets", "cryptpackets", "weakpackets",
    "gpsfixed",
    "minlat", "minlon", "minalt", "minspd",
    "maxlat", "maxlon", "maxalt", "maxspd",
    "agglat", "agglon", "aggalt", "aggpoints",
    "maxrate",
    "quality", "signal", "noise",
    "bestquality", "bestsignal", "bestnoise",
    "bestlat", "bestlon", "bestalt",
    "atype", "ip", "gatewayip", "datasize", "maxseenrate", "encodingset",
	"carrierset", "decrypted", "wep", "channel",
	"fragments", "retries", "newpackets",
    NULL
};

char *INFO_fields_text[] = {
	"networks", "packets", "crypt", "weak",
	"noise", "dropped", "rate", "signal",
	"filtered", "clients",
	NULL
};

mac_addr bcast_mac = mac_addr("FF:FF:FF:FF:FF:FF");

// Network records.  data = NETWORK_data
int Protocol_NETWORK(PROTO_PARMS) {
	Netracker::tracked_network *net = (Netracker::tracked_network *) data;
	ostringstream osstr;
	string scratch;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= NETWORK_maxfield) {
            out_string = "Unknown field requested.";
            return -1;
		}

		osstr.str("");

		// Shortcut test the cache once and print/bail immediately
		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		// Fill in the cached element
		switch(fnum) {
			case NETWORK_bssid:
				scratch = net->bssid.Mac2String();
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case NETWORK_type:
				osstr << net->type;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_ssid:
				if (net->ssid.length() == 0 || 
					(net->ssid_cloaked && net->ssid_uncloaked == 0))
					scratch = "\001 \001";
				else
					scratch = "\001" + net->ssid + "\001";
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case NETWORK_beaconinfo:
				if (net->beacon_info.length() == 0)
					scratch = "\001 \001";
				else
					scratch = "\001" + net->beacon_info + "\001";
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case NETWORK_llcpackets:
				osstr << net->llc_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_datapackets:
				osstr << net->data_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_cryptpackets:
				osstr << net->crypt_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_weakpackets:
				osstr << net->fmsweak_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_channel:
				osstr << net->channel;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_wep:
				osstr << net->cryptset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_firsttime:
				osstr << (int) net->first_time;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_lasttime:
				osstr << (int) net->last_time;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_atype:
				osstr << (int) net->guess_ipdata.ip_type;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_rangeip:
				scratch = inet_ntoa(net->guess_ipdata.ip_addr_block);
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case NETWORK_netmaskip:
				scratch = inet_ntoa(net->guess_ipdata.ip_netmask);
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case NETWORK_gatewayip:
				scratch = inet_ntoa(net->guess_ipdata.ip_gateway);
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case NETWORK_gpsfixed:
				osstr << net->gpsdata.gps_valid;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_minlat:
				osstr << net->gpsdata.min_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_minlon:
				osstr << net->gpsdata.min_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_minalt:
				osstr << net->gpsdata.min_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_minspd:
				osstr << net->gpsdata.min_spd;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_maxlat:
				osstr << net->gpsdata.max_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_maxlon:
				osstr << net->gpsdata.max_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_maxalt:
				osstr << net->gpsdata.max_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_maxspd:
				osstr << net->gpsdata.max_spd;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_octets:
				// Deprecated
				out_string += "0";
				cache->Cache(fnum, "0");
				break;
			case NETWORK_cloaked:
				if (net->ssid_cloaked) {
					out_string += "1";
					cache->Cache(fnum, "1");
				} else {
					out_string += "0";
					cache->Cache(fnum, "0");
				}
				break;
			case NETWORK_beaconrate:
				osstr << net->beaconrate;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_maxrate:
				osstr << net->maxrate;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_manufkey:
			case NETWORK_manufscore:
				// Deprecated/broken
				// FIXME manfkey
				out_string += "0";
				cache->Cache(fnum, "0");
				break;
			case NETWORK_quality:
			case NETWORK_bestquality:
				// Deprecated
				out_string += "0";
				cache->Cache(fnum, "0");
				break;
			case NETWORK_signal:
				osstr << net->snrdata.last_signal;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_noise:
				osstr << net->snrdata.last_noise;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_bestsignal:
				osstr << net->snrdata.max_signal;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_bestnoise:
				osstr << net->snrdata.max_noise;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_bestlat:
				osstr << net->snrdata.peak_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_bestlon:
				osstr << net->snrdata.peak_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_bestalt:
				osstr << net->snrdata.peak_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_agglat:
				osstr << net->gpsdata.aggregate_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_agglon:
				osstr << net->gpsdata.aggregate_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_aggalt:
				osstr << net->gpsdata.aggregate_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_aggpoints:
				osstr << net->gpsdata.aggregate_points;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_datasize:
				osstr << net->datasize;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_tcnid:
				// FIXME turbocell
				out_string += "0";
				cache->Cache(fnum, "0");
				break;
			case NETWORK_tcmode:
			case NETWORK_tsat:
				// FIXME turbocell
				out_string += "0";
				cache->Cache(fnum, "0");
				break;
			case NETWORK_carrierset:
				osstr << net->snrdata.carrierset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_maxseenrate:
				osstr << net->snrdata.maxseenrate;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_encodingset:
				osstr << net->snrdata.encodingset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_decrypted:
				osstr << net->decrypted;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_dupeiv:
				osstr << net->dupeiv_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_bsstimestamp:
				osstr << net->bss_timestamp;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_cdpdevice:
				if (net->cdp_dev_id.length() == 0)
					scratch = "\001 \001";
				else
					scratch = "\001" + net->cdp_dev_id + "\001";
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case NETWORK_cdpport:
				if (net->cdp_port_id.length() == 0)
					scratch = "\001 \001";
				else
					scratch = "\001" + net->cdp_port_id + "\001";
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case NETWORK_fragments:
				osstr << net->fragments;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_retries:
				osstr << net->retries;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case NETWORK_newpackets:
				osstr << net->new_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
		}

		// print the newly filled in cache
		out_string += " ";
    }

    return 1;
}

// client records.  data = CLIENT_data
int Protocol_CLIENT(PROTO_PARMS) {
	Netracker::tracked_client *cli = (Netracker::tracked_client *) data;
	ostringstream osstr;
	string scratch;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= CLIENT_maxfield) {
            out_string = "Unknown field requested.";
            return -1;
		}

		osstr.str("");

		// Shortcut test the cache once and print/bail immediately
		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		// Fill in the cached element
		switch(fnum) {
			case CLIENT_bssid:
				scratch = cli->bssid.Mac2String();
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case CLIENT_mac:
				scratch = cli->mac.Mac2String();
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case CLIENT_type:
				osstr << (int) cli->type;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_firsttime:
				osstr << (int) cli->first_time;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_lasttime:
				osstr << (int) cli->last_time;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_manufkey:
			case CLIENT_manufscore:
				// Deprecated/broken
				// FIXME manfkey
				out_string += osstr.str();
				cache->Cache(fnum, "0");
				break;
			case CLIENT_llcpackets:
				osstr << cli->llc_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_datapackets:
				osstr << cli->data_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_cryptpackets:
				osstr << cli->crypt_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_weakpackets:
				osstr << cli->fmsweak_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_gpsfixed:
				osstr << cli->gpsdata.gps_valid;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_minlat:
				osstr << cli->gpsdata.min_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_minlon:
				osstr << cli->gpsdata.min_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_minalt:
				osstr << cli->gpsdata.min_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_minspd:
				osstr << cli->gpsdata.min_spd;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxlat:
				osstr << cli->gpsdata.max_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxlon:
				osstr << cli->gpsdata.max_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxalt:
				osstr << cli->gpsdata.max_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxspd:
				osstr << cli->gpsdata.max_spd;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxrate:
				osstr << cli->maxrate;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_quality:
			case CLIENT_bestquality:
				// Deprecated
				out_string += "0";
				cache->Cache(fnum, "0");
				break;
			case CLIENT_signal:
				osstr << cli->snrdata.last_signal;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_noise:
				osstr << cli->snrdata.last_noise;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_bestsignal:
				osstr << cli->snrdata.max_signal;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_bestnoise:
				osstr << cli->snrdata.max_noise;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_bestlat:
				osstr << cli->snrdata.peak_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_bestlon:
				osstr << cli->snrdata.peak_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_bestalt:
				osstr << cli->snrdata.peak_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_agglat:
				osstr << cli->gpsdata.aggregate_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_agglon:
				osstr << cli->gpsdata.aggregate_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_aggalt:
				osstr << cli->gpsdata.aggregate_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_aggpoints:
				osstr << cli->gpsdata.aggregate_points;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_atype:
				osstr << (int) cli->guess_ipdata.ip_type;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_ip:
				scratch = inet_ntoa(cli->guess_ipdata.ip_addr_block);
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case CLIENT_gatewayip:
				scratch = inet_ntoa(cli->guess_ipdata.ip_gateway);
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case CLIENT_datasize:
				osstr << (int) cli->datasize;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxseenrate:
				osstr << cli->snrdata.maxseenrate;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_encodingset:
				osstr << cli->snrdata.encodingset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_decrypted:
				osstr << cli->decrypted;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_wep:
				osstr << cli->cryptset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_channel:
				osstr << cli->channel;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_fragments:
				osstr << cli->fragments;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_retries:
				osstr << cli->retries;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_newpackets:
				osstr << cli->new_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
		}

		// print the newly filled in cache
		out_string += " ";
    }

    return 1;
}

int Protocol_REMOVE(PROTO_PARMS) {
    string *str = (string *) data;
    out_string += *str;
    return 1;
}

void Protocol_NETWORK_enable(PROTO_ENABLE_PARMS) {
	// Bad touch, bad touch!
	for (Netracker::track_iter x = globalreg->netracker->tracked_map.begin(); 
		 x != globalreg->netracker->tracked_map.end(); ++x) {
        if (x->second->type == network_remove) 
            continue;

		// Send with a local cache that just gets thrown away, its only to 1
		// client so we can't efficiently cache
		kis_protocol_cache cache;
		if (globalreg->kisnetserver->SendToClient(in_fd, _NPM(PROTO_REF_NETWORK),
												  (void *) x->second, &cache) < 0)
			break;
	}
}

void Protocol_CLIENT_enable(PROTO_ENABLE_PARMS) {
	for (Netracker::client_iter x = globalreg->netracker->client_map.begin(); 
		 x != globalreg->netracker->client_map.end(); ++x) {
        if (x->second->type == client_remove) 
            continue;

		kis_protocol_cache cache;
		if (globalreg->kisnetserver->SendToClient(in_fd, _NPM(PROTO_REF_CLIENT),
												  (void *) x->second, &cache) < 0)
			break;
	}
}

int Netracker_Clicmd_ADDFILTER(CLIENT_PARMS) {
	if (parsedcmdline->size() != 1) {
		snprintf(errstr, 1024, "Illegal addfilter request");
		return -1;
	}

	Netracker *netr = (Netracker *) auxptr;

	if (netr->AddFilter((*parsedcmdline)[0].word) < 0) {
		snprintf(errstr, 1024, "Failed to insert filter string");
		return -1;
	}

	_MSG("Added network filter '" + (*parsedcmdline)[0].word + "'",
		 MSGFLAG_INFO);

	return 1;
}

int Protocol_INFO(PROTO_PARMS) {
	ostringstream osstr;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= INFO_maxfield) {
            out_string = "Unknown field requested.";
            return -1;
		}

		osstr.str("");

		// Shortcut test the cache once and print/bail immediately
		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		// Fill in the cached element
		switch(fnum) {
			case INFO_networks:
				osstr << globalreg->netracker->FetchNumNetworks();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_clients:
				osstr << globalreg->netracker->FetchNumClients();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_packets:
				osstr << globalreg->netracker->FetchNumPackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_cryptpackets:
				osstr << globalreg->netracker->FetchNumCryptpackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_weakpackets:
				osstr << globalreg->netracker->FetchNumFMSpackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_noisepackets:
				osstr << globalreg->netracker->FetchNumErrorpackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_droppedpackets:
				osstr << (globalreg->netracker->FetchNumErrorpackets() +
						  globalreg->netracker->FetchNumFiltered());
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_packetrate:
				osstr << globalreg->netracker->FetchPacketRate();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_filteredpackets:
				osstr << globalreg->netracker->FetchNumFiltered();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_signal_dep:
				cache->Cache(fnum, "0 0 0");
				cache->Cache(fnum, osstr.str());
				break;
		}

		// print the newly filled in cache
		out_string += cache->GetCache(fnum) + " ";
    }

    return 1;
}

// These are both just dropthroughs into the class itself
int kis_80211_netracker_hook(CHAINCALL_PARMS) {
	Netracker *auxptr = (Netracker *) auxdata;
	return auxptr->netracker_chain_handler(in_pack);
}

int kis_80211_datatracker_hook(CHAINCALL_PARMS) {
	Netracker *auxptr = (Netracker *) auxdata;

	return auxptr->datatracker_chain_handler(in_pack);
}

int NetrackerUpdateTimer(TIMEEVENT_PARMS) {
	Netracker *ntr = (Netracker *) parm;

	return ntr->TimerKick();
}

Netracker::Netracker() {
	fprintf(stderr, "FATAL OOPS: Netracker() called with no global registry\n");
}

Netracker::Netracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;
	track_filter = NULL;

	// Sanity
	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS:  Netracker called while packetchain is NULL\n");
		exit(1);
	}

	if (globalreg->kisnetserver == NULL) {
		fprintf(stderr, "FATAL OOPS:  Netracker called while netserver is NULL\n");
		exit(1);
	}
	
	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Netracker called while kist_config is NULL\n");
		exit(1);
	}

	if (globalreg->alertracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Netracker called while alertracker is NULL\n");
		exit(1);
	}

	if (globalreg->timetracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Netracker called while timetracker is NULL\n");
		exit(1);
	}

	// Register packet components to tie into our tracker
	_PCM(PACK_COMP_TRACKERNET) =
		globalreg->packetchain->RegisterPacketComponent("netracker_network");
	_PCM(PACK_COMP_TRACKERCLIENT) =
		globalreg->packetchain->RegisterPacketComponent("netracker_client");

	// Register the packet hooks with the chain
	globalreg->packetchain->RegisterHandler(&kis_80211_netracker_hook, this,
											CHAINPOS_CLASSIFIER, -100);
	globalreg->packetchain->RegisterHandler(&kis_80211_datatracker_hook, this,
											CHAINPOS_CLASSIFIER, -99);

	if (globalreg->kismet_config->FetchOpt("track_probenets") == "true") {
		_MSG("Probe network tracking enabled by config file", MSGFLAG_INFO);
		track_probenets = 1;
	} else {
		_MSG("Probe network tracking disabled by config file", MSGFLAG_INFO);
		track_probenets = 0;
	}
	
	string config_path;
	if ((config_path = globalreg->kismet_config->FetchOpt("configdir")) != "") {
		if ((ssid_cache_path = globalreg->kismet_config->FetchOpt("ssidmap")) != "") {
			ssid_cache_path = 
				globalreg->kismet_config->ExpandLogPath(config_path + ssid_cache_path,
														"", "", 0, 1);
			ReadSSIDCache();
		} else {
			ssid_cache_track = 0;
		}

		if ((ip_cache_path = globalreg->kismet_config->FetchOpt("ipmap")) != "") {
			ip_cache_path = 
				globalreg->kismet_config->ExpandLogPath(config_path + ip_cache_path,
														"", "", 0, 1);
			ReadIPCache();
		} else {
			ssid_cache_track = 0;
		}

	} else {
		ssid_cache_track = 0;
		ssid_cache_track = 0;
	}

	// Parse the filtering for the tracker
	track_filter = new FilterCore(globalreg);
	vector<string> filterlines = 
		globalreg->kismet_config->FetchOptVec("filter_tracker");
	for (unsigned int fl = 0; fl < filterlines.size(); fl++) {
		if (track_filter->AddFilterLine(filterlines[fl]) < 0) {
			_MSG("Failed to add filter_tracker config line from the Kismet config "
				 "file.", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}
	}

	// Register network protocols with the tcp server
	_NPM(PROTO_REF_NETWORK) =
		globalreg->kisnetserver->RegisterProtocol("NETWORK", 0, 1, 
												  NETWORK_fields_text, 
												  &Protocol_NETWORK, 
												  &Protocol_NETWORK_enable, this);
	_NPM(PROTO_REF_CLIENT) =
		globalreg->kisnetserver->RegisterProtocol("CLIENT", 0, 1,
												  CLIENT_fields_text, 
												  &Protocol_CLIENT, 
												  &Protocol_CLIENT_enable, this);
	_NPM(PROTO_REF_REMOVE) =
		globalreg->kisnetserver->RegisterProtocol("REMOVE", 0, 1,
												  REMOVE_fields_text, 
												  &Protocol_REMOVE, NULL, this);
	_NPM(PROTO_REF_INFO) =
		globalreg->kisnetserver->RegisterProtocol("INFO", 0, 1,
												  INFO_fields_text, 
												  &Protocol_INFO, NULL, this);

	// Add the client command
	addfiltercmd_ref =
		globalreg->kisnetserver->RegisterClientCommand("ADDTRACKERFILTER",
													   &Netracker_Clicmd_ADDFILTER,
													   this);

	// See if we have some alerts to raise
	alert_chan_ref = 
		globalreg->alertracker->ActivateConfiguredAlert("CHANCHANGE");
	alert_dhcpcon_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPCONFLICT");
	alert_bcastdcon_ref =
		globalreg->alertracker->ActivateConfiguredAlert("BCASTDISCON");
	alert_airjackssid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("AIRJACKSSID");
	alert_wepflap_ref =
		globalreg->alertracker->ActivateConfiguredAlert("CRYPTODROP");

	// Register timer kick
	netrackereventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &NetrackerUpdateTimer, (void *) this);

	num_packets = num_datapackets = num_cryptpackets = num_fmsweakpackets =
		num_errorpackets = num_filterpackets = num_packetdelta = 0;
}

Netracker::~Netracker() {
	// FIXME:  More cleanup here
	if (netrackereventid >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(netrackereventid);

	if (track_filter != NULL)
		delete track_filter;
}

int Netracker::AddFilter(string in_filter) {
	return track_filter->AddFilterLine(in_filter);
}

int Netracker::TimerKick() {
	// Push new networks and reset their rate counters
	for (unsigned int x = 0; x < dirty_net_vec.size(); x++) {
		tracked_network *net = dirty_net_vec[x];

		if (net->type == network_remove)
			continue;

		globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_NETWORK),
										   (void *) net);

		net->new_packets = 0;
		net->dirty = 0;
	}

	for (unsigned int x = 0; x < dirty_cli_vec.size(); x++) {
		tracked_client *cli = dirty_cli_vec[x];

		if (cli->type == client_remove)
			continue;

		globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_CLIENT),
										   (void *) cli);

		cli->new_packets = 0;
		cli->dirty = 0;
	}

	// Empty the vectors
	dirty_net_vec.clear();
	dirty_cli_vec.clear();
	
	// Send the info frame to everyone
	globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_INFO), NULL);

	num_packetdelta = 0;

	return 1;
}

void Netracker::MoveClientNetwork(Netracker::tracked_client *cli, 
								  Netracker::tracked_network *net) {
	// Just to be safe
	if (cli->netptr == NULL)
		return;

	// If the client or network are dirty, we need to flush the current dirty
	// vector out to the client
	if (cli->dirty || net->dirty)
		TimerKick();

	pair<ap_client_itr, ap_client_itr> apclis = 
		ap_client_map.equal_range(cli->netptr->bssid);

	for (ap_client_itr i = apclis.first; i != apclis.second; ++i) {
		if (i->second == cli) {
			ap_client_map.erase(i);
			break;
		}
	}

	// Remove it from one
	cli->netptr->llc_packets -= cli->llc_packets;
	cli->netptr->data_packets -= cli->data_packets;
	cli->netptr->crypt_packets -= cli->crypt_packets;
	cli->netptr->fmsweak_packets -= cli->fmsweak_packets;
	cli->netptr->fragments -= cli->fragments;
	cli->netptr->retries -= cli->retries;

	if (cli->netptr->dirty == 0) {
		cli->netptr->dirty = 1;
		// Push the old network onto the vec
		dirty_net_vec.push_back(cli->netptr);
	}

	// Add it to the other
	cli->netptr = net;
	net->llc_packets += cli->llc_packets;
	net->data_packets += cli->data_packets;
	net->crypt_packets += cli->crypt_packets;
	net->fmsweak_packets += cli->fmsweak_packets;
	net->fragments += cli->fragments;
	net->retries += cli->retries;

	cli->bssid = net->bssid;

	if (cli->dirty == 0) {
		cli->dirty = 1;
		dirty_cli_vec.push_back(cli);
	}

	if (net->dirty == 0) {
		net->dirty = 1;
		dirty_net_vec.push_back(net);
	}

	ap_client_map.insert(make_pair(net->bssid, cli));

	// FIXME:  Add recalculating the crypt_set and other goodies
}

int Netracker::netracker_chain_handler(kis_packet *in_pack) {
	tracked_network *net = NULL;
	tracked_client *cli = NULL;
	int newnetwork = 0;
	int newclient = 0;
	char status[STATUS_MAX];

	// Fetch the info from the packet chain data
	kis_ieee80211_packinfo *packinfo = (kis_ieee80211_packinfo *) 
		in_pack->fetch(_PCM(PACK_COMP_80211));
	kis_gps_packinfo *gpsinfo = (kis_gps_packinfo *) 
		in_pack->fetch(_PCM(PACK_COMP_GPS));
	kis_layer1_packinfo *l1info = (kis_layer1_packinfo *) 
		in_pack->fetch(_PCM(PACK_COMP_RADIODATA));

	// No 802.11 info, we don't handle it.
	if (packinfo == NULL) {
		return 0;
	}

	num_packets++;
	num_packetdelta++;

	// Compare against the filter and return w/out making a network record or
	// anything if we're due to be excluded anyhow.  This also keeps datatracker
	// handlers from processing since they won't find a network reference
	if (track_filter->RunFilter(packinfo->bssid_mac, packinfo->source_mac,
								packinfo->dest_mac)) {
		num_filterpackets++;
		return 0;
	}

	// Not an 802.11 frame type we known how to track, we'll just skip
	// it, too
	if (packinfo->corrupt || packinfo->type == packet_noise ||
		packinfo->type == packet_unknown || 
		packinfo->subtype == packet_sub_unknown) {
		num_errorpackets++;
		return 0;
	}

	// Look to see if we already track this bssid and grab it if we do
	track_iter triter = tracked_map.find(packinfo->bssid_mac);
	if (triter != tracked_map.end()) {
		net = triter->second;
	}

	// Try to map probe reqs into the network they really belong in, if we
	// track probes, and we don't already have a network for them
	if (track_probenets && 
		net == NULL &&
		packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_req) {

		if (probe_assoc_map.find(packinfo->bssid_mac) != probe_assoc_map.end()) {
			net = probe_assoc_map[packinfo->bssid_mac];
		}
	} 

	// Spawn a new network record
	if (net == NULL) {
		// Constructor will make our network record clear
		net = new Netracker::tracked_network;

		// Cached IP data
		if (bssid_ip_map.find(packinfo->bssid_mac) != bssid_ip_map.end()) {
			net->guess_ipdata = bssid_ip_map[packinfo->bssid_mac];
		}

		net->bssid = packinfo->bssid_mac;

		if (packinfo->type == packet_management && 
			packinfo->subtype == packet_sub_probe_req) {
			net->type = network_probe;
		} else if (packinfo->distrib == distrib_adhoc) {
			net->type = network_adhoc;
		} else if (packinfo->type == packet_data) {
			net->type = network_data;
		} else {
			net->type = network_ap;
		}

		// FIXME:  Add turbocell

		net->first_time = globalreg->timestamp.tv_sec;
		net->bss_timestamp = packinfo->timestamp;

		// Learn it
		tracked_map[net->bssid] = net;

		newnetwork = 1;
		// Everything else needs to change with new frames so we fill it in
		// outside of the new network code, obviously
	} else {
		// Update network types for existing networks
		if (packinfo->distrib == distrib_adhoc) {
			// Adhoc gets the network mode flopped
			net->type = network_adhoc;
		} else if (packinfo->type == packet_management && packinfo->ess &&
				   net->type == network_data) {
			// Management frames from an AP on a data-only network turn it into
			// an AP network
			net->type = network_ap;
		}
	}

	// Handle client tracking and creation
	client_iter clitr;
	if ((clitr = client_map.find(packinfo->source_mac)) == client_map.end()) {
		cli = new tracked_client;

		cli->first_time = globalreg->timestamp.tv_sec;

		cli->mac = packinfo->source_mac;
		cli->bssid = net->bssid;

		// Set the distribution type
		if (packinfo->distrib == distrib_from)
			cli->type = client_fromds;
		else if (packinfo->distrib == distrib_to)
			cli->type = client_tods;
		else if (packinfo->distrib == distrib_inter)
			cli->type = client_interds;
		else if (packinfo->distrib == distrib_adhoc)
			cli->type = client_adhoc;
		else
			cli->type = client_unknown;

		// Pointer to us
		cli->netptr = net;

		// Log it in the multimap
		ap_client_map.insert(make_pair(net->bssid, cli));

		newclient = 1;
	} else {
		cli = clitr->second;

		// Update and move the client to this network if it isn't.
		if (cli->netptr != net) {
			MoveClientNetwork(cli, net);
		}

		// Process the type to indicate established clients
		if ((packinfo->distrib == distrib_to && cli->type == client_fromds) ||
			(packinfo->distrib == distrib_from && cli->type == client_tods))
			cli->type = client_established;
		else if (packinfo->distrib == distrib_inter)
			cli->type = client_interds;
		else if (packinfo->distrib == distrib_adhoc)
			cli->type = client_adhoc;
	}

	// Link it to the packet for future chain elements
	kis_netracker_netinfo *netpackinfo = new kis_netracker_netinfo;
	netpackinfo->netref = net;
	in_pack->insert(_PCM(PACK_COMP_TRACKERNET), netpackinfo);

	kis_netracker_cliinfo *clipackinfo = new kis_netracker_cliinfo;
	clipackinfo->cliref = cli;
	in_pack->insert(_PCM(PACK_COMP_TRACKERCLIENT), clipackinfo);

	// Update the time
	net->last_time = globalreg->timestamp.tv_sec;

	// Dirty the network
	if (net->dirty == 0) {
		net->dirty = 1;
		dirty_net_vec.push_back(net);
	}

	// Extract info from the GPS component, if we have one
	if (gpsinfo != NULL && gpsinfo->gps_fix >= 2) {
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

		cli->gpsdata.gps_valid = 1;

		if (gpsinfo->lat < cli->gpsdata.min_lat)
			cli->gpsdata.min_lat = gpsinfo->lat;
		if (gpsinfo->lon < cli->gpsdata.min_lon)
			cli->gpsdata.min_lon = gpsinfo->lon;
		if (gpsinfo->alt < cli->gpsdata.min_alt)
			cli->gpsdata.min_alt = gpsinfo->alt;
		if (gpsinfo->spd < cli->gpsdata.min_spd)
			cli->gpsdata.min_spd = gpsinfo->spd;

		if (gpsinfo->lat > cli->gpsdata.max_lat)
			cli->gpsdata.max_lat = gpsinfo->lat;
		if (gpsinfo->lon > cli->gpsdata.max_lon)
			cli->gpsdata.max_lon = gpsinfo->lon;
		if (gpsinfo->alt > cli->gpsdata.max_alt)
			cli->gpsdata.max_alt = gpsinfo->alt;
		if (gpsinfo->spd > cli->gpsdata.max_spd)
			cli->gpsdata.max_spd = gpsinfo->spd;

		cli->gpsdata.aggregate_lat += gpsinfo->lat;
		cli->gpsdata.aggregate_lon += gpsinfo->lon;
		cli->gpsdata.aggregate_alt += gpsinfo->alt;
		cli->gpsdata.aggregate_points++;
	}

	// L1 signal info, if our capture source was able to inject any into
	// the packet.
	if (l1info != NULL) {
		net->snrdata.last_signal = l1info->signal;
		net->snrdata.last_noise = l1info->noise;

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
		net->snrdata.carrierset |= (1 << (int) l1info->carrier);
		net->snrdata.encodingset |= (1 << (int) l1info->encoding);

		cli->snrdata.last_signal = l1info->signal;
		cli->snrdata.last_noise = l1info->noise;

		if (l1info->noise > cli->snrdata.max_noise) {
			cli->snrdata.max_noise = l1info->noise;
		}

		if (l1info->signal > cli->snrdata.max_signal) {
			cli->snrdata.max_signal = l1info->signal;

			if (gpsinfo != NULL) {
				cli->snrdata.peak_lat = gpsinfo->lat;
				cli->snrdata.peak_lon = gpsinfo->lon;
				cli->snrdata.peak_alt = gpsinfo->alt;
			}
		}

		if (l1info->datarate < cli->snrdata.maxseenrate)
			cli->snrdata.maxseenrate = l1info->datarate;

		// Push in the bits for the carrier and encoding
		cli->snrdata.carrierset |= (1 << (int) l1info->carrier);
		cli->snrdata.encodingset |= (1 << (int) l1info->encoding);
	}

	// Extract info from probe request frames if its a probe network
	if (packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_req) {
		
		if (net->type == network_probe) {
			// Learn the SSID they're probing for
			net->ssid = packinfo->ssid;

			// Calc the checksum and see if its in our map
			uint32_t csum = 
				Adler32Checksum(packinfo->ssid.c_str(), packinfo->ssid.length());
			map<uint32_t, string>::iterator psmi = cli->probe_ssid_map.find(csum);
			if (psmi == cli->probe_ssid_map.end())
				cli->probe_ssid_map[csum] = packinfo->ssid;

		}

		if (cli->maxrate < packinfo->maxrate)
			cli->maxrate = packinfo->maxrate;

	}

	// Extract info from beacon frames, they're the only ones we trust to
	// give us good info...
	if (packinfo->type == packet_management && 
		packinfo->subtype == packet_sub_beacon) {
		
		net->beacon_info = string(packinfo->beacon_info);

		// Find cached SSID if we don't have one
		if (packinfo->ssid_len == 0 || packinfo->ssid_blank) {
			net->ssid_cloaked = 1;
			if (net->ssid_uncloaked == 0 &&
				bssid_cloak_map.find(packinfo->bssid_mac) != bssid_cloak_map.end()) {
				net->ssid = bssid_cloak_map[packinfo->bssid_mac];
				net->ssid_uncloaked = 1;
			}
		} else if (packinfo->ssid_len != 0 && packinfo->ssid_blank == 0) {
			net->ssid = packinfo->ssid;

			if (net->ssid_cloaked && net->ssid_uncloaked == 0) {
				_MSG("Decloaked network " + packinfo->bssid_mac.Mac2String() + 
					 " SSID '" + packinfo->ssid + "'", MSGFLAG_INFO);
				net->ssid_uncloaked = 1;
			} else {
				net->ssid_cloaked = 0;
			}

			// Check our map of known bssids for this AP and add this to it
			uint32_t csum = 
				Adler32Checksum(packinfo->ssid.c_str(), packinfo->ssid.length());
			map<uint32_t, string>::iterator nbmi = net->beacon_ssid_map.find(csum);
			if (nbmi == net->beacon_ssid_map.end())
				net->beacon_ssid_map[csum] = packinfo->ssid;
		}

		if (alert_airjackssid_ref >= 0 && packinfo->ssid == "AirJack" &&
			globalreg->alertracker->PotentialAlert(alert_airjackssid_ref)) {
			ostringstream outs;

			outs << "Network BSSID " << net->bssid.Mac2String() << " broadcasting "
				"SSID 'AirJack' which implies an attempt to disrupt networks";

			globalreg->alertracker->RaiseAlert(alert_airjackssid_ref, in_pack, 
											   packinfo->bssid_mac, 
											   packinfo->source_mac, 
											   packinfo->dest_mac, 
											   packinfo->other_mac, 
											   packinfo->channel, outs.str());

		}

		if (net->maxrate < packinfo->maxrate)
			net->maxrate = packinfo->maxrate;

		if (packinfo->cryptset) {
			num_cryptpackets++;
		} else {
			if (net->cryptset && alert_wepflap_ref &&
				globalreg->alertracker->PotentialAlert(alert_wepflap_ref)) {
				ostringstream outs;

				outs << "Network BSSID " << net->bssid.Mac2String() << " stopped "
					"advertising encryption";

				globalreg->alertracker->RaiseAlert(alert_wepflap_ref, in_pack,
												   packinfo->bssid_mac,
												   packinfo->source_mac,
												   packinfo->dest_mac,
												   packinfo->other_mac,
												   packinfo->channel,
												   outs.str());
			}
		}

		net->cryptset = packinfo->cryptset;
		cli->cryptset = packinfo->cryptset;

		// Fire off an alert if the channel changes
		if (alert_chan_ref >= 0 && newnetwork == 0 && net->channel != 0 &&
			packinfo->channel != 0 && net->channel != packinfo->channel &&
			globalreg->alertracker->PotentialAlert(alert_chan_ref)) {
			ostringstream outs;

			outs << "Network BSSID " << net->bssid.Mac2String() << " changed "
				"channel from " << net->channel << " to " << packinfo->channel;

			globalreg->alertracker->RaiseAlert(alert_chan_ref, in_pack, 
											   packinfo->bssid_mac, 
											   packinfo->source_mac, 
											   packinfo->dest_mac, 
											   packinfo->other_mac, 
											   packinfo->channel, outs.str());
		}

		net->channel = packinfo->channel;
		cli->channel = packinfo->channel;

		net->beaconrate = packinfo->beacon_interval;
	}

	// Catch probe responses and decloak if they're nonblank
	if (packinfo->ssid_len != 0 && packinfo->ssid_blank == 0 &&
		net->ssid_cloaked != 0 && net->ssid_uncloaked == 0 &&
		packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_resp) {

		net->ssid_uncloaked = 1;
		net->ssid = packinfo->ssid;

		// Update the cloak map
		bssid_cloak_map[net->bssid] = packinfo->ssid;

		_MSG("Decloaked network " + packinfo->bssid_mac.Mac2String() + 
			 " SSID '" + packinfo->ssid + "'", MSGFLAG_INFO);
	}

	// Fire an alert on a disconnect/deauth broadcast
	if (alert_bcastdcon_ref >= 0 && packinfo->type == packet_management &&
		(packinfo->subtype == packet_sub_disassociation ||
		 packinfo->subtype == packet_sub_deauthentication) &&
		packinfo->dest_mac == bcast_mac &&
		globalreg->alertracker->PotentialAlert(alert_bcastdcon_ref)) {
		ostringstream outs;

		outs << "Network BSSID " << net->bssid.Mac2String() << " broadcast "
			"deauthenticate/disassociation of all clients, possible DoS";

		globalreg->alertracker->RaiseAlert(alert_bcastdcon_ref, in_pack, 
										   packinfo->bssid_mac, 
										   packinfo->source_mac, 
										   packinfo->dest_mac, 
										   packinfo->other_mac, 
										   packinfo->channel, outs.str());
	}

	if (packinfo->type == packet_management ||
		packinfo->type == packet_phy) {
		net->llc_packets++;
		cli->llc_packets++;
	} else if (packinfo->type == packet_data) {
		net->data_packets++;
		cli->data_packets++;

		if (packinfo->encrypted) {
			net->crypt_packets++;
			cli->crypt_packets++;
		}

		// TODO - Add FMSweak handling
	}

	// Increment per-unit rates
	net->new_packets++;
	cli->new_packets++;

	// Handle data sizes
	net->datasize += packinfo->datasize;
	cli->datasize += packinfo->datasize;

	// Handle fragment and retry values
	if (packinfo->fragmented) {
		net->fragments++;
		cli->fragments++;
	} 
	if (packinfo->retry) {
		net->retries++;
		cli->retries++;
	}

	if (newnetwork) {
		string nettype;

		if (net->type == network_ap) {
			nettype = "managed";
		} else if (net->type == network_adhoc) {
			nettype = "ad-hoc";
		} else if (net->type == network_probe) {
			nettype = "probe";
		} else if (net->type == network_turbocell) {
			nettype = "turbocell";
		} else if (net->type == network_data) {
			nettype = "data";
		}

		snprintf(status, STATUS_MAX, "Detected new %s network \"%s\", BSSID %s, "
				 "encryption %s, channel %d, %2.2f mbit",
				 nettype.c_str(),
				 (net->ssid.length() == 0) ? 
				 "<no ssid>" : net->ssid.c_str(), 
				 net->bssid.Mac2String().c_str(),
				 net->cryptset ? "yes" : "no",
				 net->channel, net->maxrate);
		_MSG(status, MSGFLAG_INFO);
		globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_NETWORK), 
										   (void *) net);
	}

	if (newclient) {
		// do we want to whine in the info field?
		globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_CLIENT),
										   (void *) cli);
	}

	if (net->dirty == 0) {
		net->dirty = 1;
		dirty_net_vec.push_back(net);
	}
	if (cli->dirty == 0) {
		cli->dirty = 1;
		dirty_cli_vec.push_back(cli);
	}

	// TODO/FIXME:  
	//  Manuf matching
	//  IV set handling
	//	"Smart" vs. "Purely accurate" adhoc handling

	return 1;
}

int Netracker::datatracker_chain_handler(kis_packet *in_pack) {
	// Fetch the info from the packet chain data
	kis_ieee80211_packinfo *packinfo = (kis_ieee80211_packinfo *) 
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
	tracked_network *net;
	kis_netracker_netinfo *netpackinfo =
		(kis_netracker_netinfo *) in_pack->fetch(_PCM(PACK_COMP_TRACKERNET));

	// No network?  Can't handle this either.
	if (netpackinfo == NULL) {
		return 0;
	}

	net = netpackinfo->netref;

	// Make sure we got a client, too
	tracked_client *cli;
	kis_netracker_cliinfo *clipackinfo =
		(kis_netracker_cliinfo *) in_pack->fetch(_PCM(PACK_COMP_TRACKERCLIENT));

	// No network?  Can't handle this either.
	if (clipackinfo == NULL) {
		return 0;
	}

	num_datapackets++;

	cli = clipackinfo->cliref;

	// Apply the network-level stuff
	if (packinfo->source_mac == net->bssid) {
		// Things that come from the MAC of the AP carry special weight.  
		// CDP gets copied over so that we can figure out where this AP is
		// (maybe)
		net->cdp_dev_id = datainfo->cdp_dev_id;
		net->cdp_port_id = datainfo->cdp_port_id;
		cli->cdp_dev_id = datainfo->cdp_dev_id;
		cli->cdp_port_id = datainfo->cdp_port_id;
	} 

	// Start comparing IP stuff and move it into the network.  We don't
	// trust IPs coming from the the AP itself UNLESS they're DHCP-Offers because
	// an AP in router mode tends to replicate in internet addresses and confuse
	// things all over the place.
	int ipdata_dirty = 0;

	if ((packinfo->source_mac == net->bssid && datainfo->proto == proto_dhcp_offer) ||
		packinfo->source_mac != net->bssid) {
		if (datainfo->proto  == proto_dhcp_offer) {
			// DHCP Offers are about the most complete and authoritative IP info we
			// can get, so we just overwrite our network knowledge with it.

			// First, check and see if we're going to make noise about this being
			// a conflicting DHCP offer...  since DHCP is the "best" type of address,
			// if we've seen an offer before, it will be this address.
			in_addr ip_calced_range;
			ip_calced_range.s_addr = 
				(datainfo->ip_dest_addr.s_addr & datainfo->ip_netmask_addr.s_addr);

			if (alert_dhcpcon_ref >= 0 && net->guess_ipdata.ip_type == ipdata_dhcp &&
				ip_calced_range.s_addr != net->guess_ipdata.ip_addr_block.s_addr &&
				globalreg->alertracker->PotentialAlert(alert_dhcpcon_ref)) {
				ostringstream outs;

				outs << "Network BSSID " << net->bssid.Mac2String() << " got "
					"conflicting DHCP offer from " <<
					packinfo->source_mac.Mac2String() << " of " <<
					string(inet_ntoa(net->guess_ipdata.ip_addr_block)) <<
					" previously " << string(inet_ntoa(ip_calced_range));

				globalreg->alertracker->RaiseAlert(alert_dhcpcon_ref, in_pack, 
												   packinfo->bssid_mac, 
												   packinfo->source_mac, 
												   packinfo->dest_mac, 
												   packinfo->other_mac, 
												   packinfo->channel, outs.str());
			}
		
			// Copy it into our network IP data
			net->guess_ipdata.ip_type = ipdata_dhcp;
			// IP range goes straight in masked w/ offered netmask
			net->guess_ipdata.ip_addr_block.s_addr = ip_calced_range.s_addr;
			net->guess_ipdata.ip_netmask.s_addr = datainfo->ip_netmask_addr.s_addr;
			net->guess_ipdata.ip_gateway.s_addr = datainfo->ip_gateway_addr.s_addr;
			if (net->dirty == 0) {
				net->dirty = 1;
				dirty_net_vec.push_back(net);
			}

			// Copy it into our client ip data too
			cli->guess_ipdata.ip_type = ipdata_dhcp;
			cli->guess_ipdata.ip_addr_block.s_addr = ip_calced_range.s_addr;
			cli->guess_ipdata.ip_netmask.s_addr = datainfo->ip_netmask_addr.s_addr;
			cli->guess_ipdata.ip_gateway.s_addr = datainfo->ip_gateway_addr.s_addr;
			if (cli->dirty == 0) {
				cli->dirty = 1;
				dirty_cli_vec.push_back(cli);
			}

			ipdata_dirty = 1;
		} else if (datainfo->proto == proto_arp) {
			// Second most trusted:  ARP.  ARP only occurs within the IP subnet,
			// which should be tied to the physical broadcast domain, which should
			// be a good gauge of our network range
			if (cli->guess_ipdata.ip_type <= ipdata_arp) {
				cli->guess_ipdata.ip_type = ipdata_arp;
				cli->guess_ipdata.ip_addr_block.s_addr = 
					datainfo->ip_source_addr.s_addr;
				if (cli->dirty == 0) {
					cli->dirty = 1;
					dirty_cli_vec.push_back(cli);
				}
				ipdata_dirty = 1;
			}
		} else if (datainfo->proto == proto_udp || datainfo->proto == proto_tcp) {
			// Third most trusted: TCP and UDP... update the client
			if (cli->guess_ipdata.ip_type <= ipdata_udptcp) {
				cli->guess_ipdata.ip_type = ipdata_udptcp;

				if (packinfo->distrib == distrib_from) {
					// Coming from the distribution to a client, we probably care
					// about the destination since it's inside our network
					cli->guess_ipdata.ip_addr_block.s_addr = 
						datainfo->ip_dest_addr.s_addr;
				} else {
					// Coming from a client, we're more likely to care about the
					// source.  Let this drop into a generic else since we
					// might as well use the source addr for anything else.  Other
					// distrib types don't give us enough of a clue so source is
					// as good as anything
					cli->guess_ipdata.ip_addr_block.s_addr = 
						datainfo->ip_source_addr.s_addr;
				}

				// Zero the rest of the stuff
				cli->guess_ipdata.ip_netmask.s_addr = 0;
				cli->guess_ipdata.ip_gateway.s_addr = 0;

				if (cli->dirty == 0) {
					cli->dirty = 1;
					dirty_cli_vec.push_back(cli);
				}
				ipdata_dirty = 1;
			}
		}

		// Recalculate the network IP characteristics
		if (ipdata_dirty && net->guess_ipdata.ip_type != ipdata_dhcp) {
			pair<ap_client_itr, ap_client_itr> apclis = 
				ap_client_map.equal_range(net->bssid);

			// Track combined addresses for both types so we can pick the
			// best one
			in_addr combo_tcpudp;
			in_addr combo_arp;
			in_addr combo_nil; // This is dumb
			combo_tcpudp.s_addr = ~0;
			combo_arp.s_addr = ~0;
			combo_nil.s_addr = ~0;

			for (ap_client_itr i = apclis.first; i != apclis.second; ++i) {
				// Short out on DHCP, thats the best news we get, even though
				// we should never get here thanks to the special handling of
				// dhcp in the base ip catcher above
				tracked_client *acli = i->second;
				if (acli->guess_ipdata.ip_type == ipdata_dhcp) {
					net->guess_ipdata = cli->guess_ipdata;
					break;
				} else if (acli->guess_ipdata.ip_type == ipdata_arp) {
					combo_arp.s_addr &=
						acli->guess_ipdata.ip_addr_block.s_addr;
				} else if (acli->guess_ipdata.ip_type == ipdata_udptcp) {
					// Compare the tcpudp addresses
					combo_tcpudp.s_addr &=
						acli->guess_ipdata.ip_addr_block.s_addr;
				}
			}

			// Find the "best" address.  If the arp stuff came out to 0
			// we had no arp or it ANDed out to useless, we need to drop
			// to the tcp field
			if (net->guess_ipdata.ip_type != ipdata_dhcp) {
				if (net->guess_ipdata.ip_type <= ipdata_arp &&
					combo_arp.s_addr != combo_nil.s_addr && combo_arp.s_addr !=
					net->guess_ipdata.ip_addr_block.s_addr) {

					net->guess_ipdata.ip_type = ipdata_arp;
					net->guess_ipdata.ip_addr_block.s_addr =
						combo_arp.s_addr;

					_MSG("Found IP range " + string(inet_ntoa(combo_arp)) +
						 " via ARP for network " + net->bssid.Mac2String() + 
						 " SSID '" + (net->ssid.length() == 0 ? "<no ssid>" : 
									  net->ssid) + "'",
						 MSGFLAG_INFO);

				} else if (net->guess_ipdata.ip_type <= ipdata_udptcp &&
						   combo_tcpudp.s_addr != combo_nil.s_addr && 
						   combo_tcpudp.s_addr != 
						   net->guess_ipdata.ip_addr_block.s_addr) {
					net->guess_ipdata.ip_type = ipdata_udptcp;
					net->guess_ipdata.ip_addr_block.s_addr =
						combo_tcpudp.s_addr;

					_MSG("Found IP range " + string(inet_ntoa(combo_tcpudp)) +
						 " via TCP/UDP for network " + net->bssid.Mac2String() + 
						 " SSID '" + (net->ssid.length() == 0 ? "<no ssid>" : 
									  net->ssid) + "'",
						 MSGFLAG_INFO);
				}

				net->guess_ipdata.ip_netmask.s_addr = 0;
				net->guess_ipdata.ip_gateway.s_addr = 0;

				// FIXME:  Add netmask calculation
				// FIXME:  Add gateway detection
			}
		} // ipdata dirty
	} // ip considered

	return 1;
}

int Netracker::ReadSSIDCache() {
	FILE *ssidf;
	char errstr[1024];
	int ver;

	if ((ssidf = fopen(ssid_cache_path.c_str(), "r")) == NULL) {
		snprintf(errstr, 1024, "Netracker failed to read SSID cache file '%s':  %s",
				 ssid_cache_path.c_str(), strerror(errno));
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return -1;
	}

	// Hijack the error string as a convenient buffer
	fgets(errstr, 1024, ssidf);
	if (sscanf(errstr, "SSIDCACHE_VERSION: %d\n", &ver) != 1) {
		globalreg->messagebus->InjectMessage("Netracker failed to read SSID cache "
											 "file version, cache file will be "
											 "replaced", MSGFLAG_ERROR);
		fclose(ssidf);
		return 0;
	}

	if (ver != NETRACKER_SSIDCACHE_VERSION) {
		snprintf(errstr, 1024, "Netracker got different SSID Cache version, cache "
				 "file will be replaced.  (Got %d expected %d)", ver,
				 NETRACKER_SSIDCACHE_VERSION);
		fclose(ssidf);
		return 0;
	}

	do {
		char macstr[19];
		char ssid[65];
		mac_addr mac;

		// Keep hijacking the error buffer
		fgets(errstr, 1024, ssidf);

		if (sscanf(errstr, "%18s \001%64[^\001]\001\n", macstr, ssid) != 2) {
			globalreg->messagebus->InjectMessage("Netracker got invalid line in "
												 "SSID cache file, skipping",
												 MSGFLAG_INFO);
			continue;
		}

		mac = macstr;
		if (mac.error) {
			globalreg->messagebus->InjectMessage("Netracker got invalid MAC address "
												 "in SSID cache file, skipping",
												 MSGFLAG_INFO);
			continue;
		}

		bssid_cloak_map[mac] = string(ssid);
	} while (!feof(ssidf));

	fclose(ssidf);

	return 1;
}

int Netracker::WriteSSIDCache() {
	FILE *ssidf;
	char errstr[1024];

	if ((ssidf = fopen(ssid_cache_path.c_str(), "w")) == NULL) {
		snprintf(errstr, 1024, "Netracker failed to open SSID cache file '%s':  %s",
				 ssid_cache_path.c_str(), strerror(errno));
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
	}

	fprintf(ssidf, "SSIDCACHE_VERSION: %d\n", NETRACKER_SSIDCACHE_VERSION);

	// Write out everything in the cache map (this must be updated as new networks
	// are found/uncloaked)
	for (ssidcache_iter x = bssid_cloak_map.begin(); 
		 x != bssid_cloak_map.end(); ++x) {
		fprintf(ssidf, "%s \001%64s\001\n", x->first.Mac2String().c_str(),
				x->second.c_str());
	}

	fclose(ssidf);

	return 1;
}

int Netracker::ReadIPCache() {
	FILE *ipf;
	char errstr[1024];
	int ver;

	if ((ipf = fopen(ip_cache_path.c_str(), "r")) == NULL) {
		snprintf(errstr, 1024, "Netracker failed to read IP cache file '%s':  %s",
				 ip_cache_path.c_str(), strerror(errno));
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return -1;
	}

	// Hijack the error string as a convenient buffer
	fgets(errstr, 1024, ipf);
	if (sscanf(errstr, "IPCACHE_VERSION: %d\n", &ver) != 1) {
		globalreg->messagebus->InjectMessage("Netracker failed to read IP cache "
											 "file version, cache file will be "
											 "replaced", MSGFLAG_ERROR);
		fclose(ipf);
		return 0;
	}

	if (ver != NETRACKER_IPCACHE_VERSION) {
		snprintf(errstr, 1024, "Netracker got different IP Cache version, cache "
				 "file will be replaced.  (Got %d expected %d)", ver,
				 NETRACKER_IPCACHE_VERSION);
		fclose(ipf);
		return 0;
	}

	do {
		char macstr[19];
		ip_data ipd;
		mac_addr mac;
		int ipaddr, netmask, gateway;

		// Keep hijacking the error buffer
		fgets(errstr, 1024, ipf);

		if (sscanf(errstr, "%18s %d %d %d\n", macstr, &ipaddr, 
				   &netmask, &gateway) != 4) {
			globalreg->messagebus->InjectMessage("Netracker got invalid line in "
												 "IP cache file, skipping",
												 MSGFLAG_INFO);
			continue;
		}

		mac = macstr;
		if (mac.error) {
			globalreg->messagebus->InjectMessage("Netracker got invalid MAC address "
												 "in IP cache file, skipping",
												 MSGFLAG_INFO);
			continue;
		}

		ipd.ip_addr_block.s_addr = ipaddr;
		ipd.ip_netmask.s_addr = netmask;
		ipd.ip_gateway.s_addr = gateway;

		bssid_ip_map[mac] = ipd;
	} while (!feof(ipf));

	fclose(ipf);

	return 1;
}

int Netracker::WriteIPCache() {
	FILE *ipf;
	char errstr[1024];

	if ((ipf = fopen(ip_cache_path.c_str(), "w")) == NULL) {
		snprintf(errstr, 1024, "Netracker failed to open IP cache file '%s':  %s",
				 ip_cache_path.c_str(), strerror(errno));
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
	}

	fprintf(ipf, "IPCACHE_VERSION: %d\n", NETRACKER_IPCACHE_VERSION);

	// If we're cached and don't exist in the real map, write it out
	// If we're in the real map, write that out instead
	for (ipcache_iter x = bssid_ip_map.begin(); x != bssid_ip_map.end(); ++x) {
		track_iter triter;
		ip_data ipd;
		
		if ((triter = tracked_map.find(x->first)) != tracked_map.end())
			ipd = triter->second->guess_ipdata;
		else
			ipd = x->second;

		fprintf(ipf, "%s %d %d %d\n", x->first.Mac2String().c_str(),
				x->second.ip_addr_block, x->second.ip_netmask,
				x->second.ip_gateway);
	}

	fclose(ipf);

	return 1;
}

int Netracker::FetchNumNetworks() {
	return tracked_map.size();
}

int Netracker::FetchNumClients() {
	return client_map.size();
}

int Netracker::FetchNumPackets() {
	return num_packets;
}

int Netracker::FetchNumDatapackets() {
	return num_datapackets;
}

int Netracker::FetchNumCryptpackets() {
	return num_cryptpackets;
}

int Netracker::FetchNumFMSpackets() {
	return num_fmsweakpackets;
}

int Netracker::FetchNumErrorpackets() {
	return num_errorpackets;
}

int Netracker::FetchNumFiltered() {
	return num_filterpackets;
}

int Netracker::FetchPacketRate() {
	return num_packetdelta;
}

const map<mac_addr, Netracker::tracked_network *> Netracker::FetchTrackedNets() {
	return tracked_map;
}

const map<mac_addr, Netracker::tracked_network *> Netracker::FetchProbeNets() {
	return probe_assoc_map;
}

const map<mac_addr, Netracker::tracked_client *> Netracker::FetchTrackedClients() {
	return client_map;
}

const multimap<mac_addr, Netracker::tracked_client *> Netracker::FetchAssocClients() {
	return ap_client_map;
}

