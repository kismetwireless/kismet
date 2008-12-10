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
const char *BSSID_fields_text[] = {
    "bssid", "type",
    "llcpackets", "datapackets", "cryptpackets",
    "channel", "firsttime", "lasttime", "atype", 
	"rangeip", "netmaskip",
	"gatewayip", "gpsfixed",
    "minlat", "minlon", "minalt", "minspd",
    "maxlat", "maxlon", "maxalt", "maxspd",
    "signal_dbm", "noise_dbm",
	"minsignal_dbm", "minnoise_dbm",
	"maxsignal_dbm", "maxnoise_dbm",
    "signal_rssi", "noise_rssi",
	"minsignal_rssi", "minnoise_rssi",
	"maxsignal_rssi", "maxnoise_rssi",
	"bestlat", "bestlon", "bestalt",
    "agglat", "agglon", "aggalt", "aggpoints",
    "datasize",
    "turbocellnid", "turbocellmode", "turbocellsat",
    "carrierset", "maxseenrate", "encodingset",
    "decrypted", "dupeivpackets", "bsstimestamp",
	"cdpdevice", "cdpport", "fragments", "retries",
	"newpackets", "freqmhz",
    NULL
};

const char *SSID_fields_text[] = {
	"mac", "checksum", "type", "ssid",
	"beaconinfo", "cryptset", "cloaked",
	"firsttime", "lasttime", "maxrate",
	"beaconrate", "packets", "beacons",
	NULL
};

const char *REMOVE_fields_text[] = {
    "bssid",
    NULL
};

const char *CLIENT_fields_text[] = {
    "mac", "type", "firsttime", "lasttime",
    "manufkey", "manufscore",
    "llcpackets", "datapackets", "cryptpackets", 
    "gpsfixed",
    "minlat", "minlon", "minalt", "minspd",
    "maxlat", "maxlon", "maxalt", "maxspd",
    "agglat", "agglon", "aggalt", "aggpoints",
    "maxrate",
    "signal_dbm", "noise_dbm",
	"minsignal_dbm", "minnoise_dbm",
	"maxsignal_dbm", "maxnoise_dbm",
    "signal_rssi", "noise_rssi",
	"minsignal_rssi", "minnoise_rssi",
	"maxsignal_rssi", "maxnoise_rssi",
    "bestlat", "bestlon", "bestalt",
    "atype", "ip", "gatewayip", "datasize", "maxseenrate", "encodingset",
	"carrierset", "decrypted", "channel",
	"fragments", "retries", "newpackets", "freqmhz",
    NULL
};

const char *INFO_fields_text[] = {
	"networks", "packets", "crypt", "noise", "dropped", "rate", "filtered", "clients",
	"llcpackets", "datapackets",
	NULL
};

mac_addr bcast_mac = mac_addr("FF:FF:FF:FF:FF:FF");

int Protocol_BSSID(PROTO_PARMS) {
	Netracker::tracked_network *net = (Netracker::tracked_network *) data;
	ostringstream osstr;
	string scratch;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= BSSID_maxfield) {
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
			case BSSID_bssid:
				scratch = net->bssid.Mac2String();
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case BSSID_type:
				osstr << net->type;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_llcpackets:
				osstr << net->llc_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_datapackets:
				osstr << net->data_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_cryptpackets:
				osstr << net->crypt_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_channel:
				osstr << net->channel;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_freqmhz:
				/* Annoying packed field */
				for (map<unsigned int, unsigned int>::const_iterator fmi = net->freq_mhz_map.begin(); fmi != net->freq_mhz_map.end(); ++fmi) {
					osstr << fmi->first << ":" << fmi->second << "*";
				}
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_firsttime:
				osstr << (int) net->first_time;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_lasttime:
				osstr << (int) net->last_time;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_atype:
				osstr << (int) net->guess_ipdata.ip_type;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_rangeip:
				scratch = inet_ntoa(net->guess_ipdata.ip_addr_block);
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case BSSID_netmaskip:
				scratch = inet_ntoa(net->guess_ipdata.ip_netmask);
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case BSSID_gatewayip:
				scratch = inet_ntoa(net->guess_ipdata.ip_gateway);
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case BSSID_gpsfixed:
				osstr << net->gpsdata.gps_valid;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_minlat:
				osstr << net->gpsdata.min_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_minlon:
				osstr << net->gpsdata.min_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_minalt:
				osstr << net->gpsdata.min_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_minspd:
				osstr << net->gpsdata.min_spd;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxlat:
				osstr << net->gpsdata.max_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxlon:
				osstr << net->gpsdata.max_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxalt:
				osstr << net->gpsdata.max_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxspd:
				osstr << net->gpsdata.max_spd;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_signal_dbm:
				osstr << net->snrdata.last_signal_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_minsignal_dbm:
				osstr << net->snrdata.min_signal_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxsignal_dbm:
				osstr << net->snrdata.max_signal_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_noise_dbm:
				osstr << net->snrdata.last_noise_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_minnoise_dbm:
				osstr << net->snrdata.min_noise_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxnoise_dbm:
				osstr << net->snrdata.max_noise_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_signal_rssi:
				osstr << net->snrdata.last_signal_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_minsignal_rssi:
				osstr << net->snrdata.min_signal_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxsignal_rssi:
				osstr << net->snrdata.max_signal_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_noise_rssi:
				osstr << net->snrdata.last_noise_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_minnoise_rssi:
				osstr << net->snrdata.min_noise_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxnoise_rssi:
				osstr << net->snrdata.max_noise_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_bestlat:
				osstr << net->snrdata.peak_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_bestlon:
				osstr << net->snrdata.peak_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_bestalt:
				osstr << net->snrdata.peak_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_agglat:
				osstr << net->gpsdata.aggregate_lat;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_agglon:
				osstr << net->gpsdata.aggregate_lon;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_aggalt:
				osstr << net->gpsdata.aggregate_alt;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_aggpoints:
				osstr << net->gpsdata.aggregate_points;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_datasize:
				osstr << net->datasize;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_tcnid:
				// FIXME turbocell
				out_string += "0";
				cache->Cache(fnum, "0");
				break;
			case BSSID_tcmode:
			case BSSID_tsat:
				// FIXME turbocell
				out_string += "0";
				cache->Cache(fnum, "0");
				break;
			case BSSID_carrierset:
				osstr << net->snrdata.carrierset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_maxseenrate:
				osstr << net->snrdata.maxseenrate;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_encodingset:
				osstr << net->snrdata.encodingset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_decrypted:
				osstr << net->decrypted;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_dupeiv:
				osstr << net->dupeiv_packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_bsstimestamp:
				osstr << net->bss_timestamp;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_cdpdevice:
				if (net->cdp_dev_id.length() == 0)
					scratch = "\001 \001";
				else
					scratch = "\001" + net->cdp_dev_id + "\001";
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case BSSID_cdpport:
				if (net->cdp_port_id.length() == 0)
					scratch = "\001 \001";
				else
					scratch = "\001" + net->cdp_port_id + "\001";
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case BSSID_fragments:
				osstr << net->fragments;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_retries:
				osstr << net->retries;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case BSSID_newpackets:
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

int Protocol_SSID(PROTO_PARMS) {
	Netracker::adv_ssid_data *ssid = (Netracker::adv_ssid_data *) data;
	ostringstream osstr;
	string scratch;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= SSID_maxfield) {
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
			case SSID_mac:
				scratch = ssid->mac.Mac2String();
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case SSID_checksum:
				osstr << ssid->checksum;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_type:
				osstr << ssid->type;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_ssid:
				if (ssid->ssid_cloaked) {
					osstr << "\001\001";
				} else {
					osstr << "\001" << ssid->ssid << "\001";
				}
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_beaconinfo:
				if (ssid->beacon_info.length() == 0) 
					osstr << "\001 \001";
				else
					osstr << "\001" << ssid->beacon_info << "\001";
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_cryptset:
				osstr << ssid->cryptset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_cloaked:
				osstr << ssid->ssid_cloaked;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_firsttime:
				osstr << ssid->first_time;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_lasttime:
				osstr << ssid->last_time;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_maxrate:
				osstr << ssid->maxrate;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_beaconrate:
				osstr << ssid->beaconrate;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_packets:
				osstr << ssid->packets;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case SSID_beacons:
				osstr << ssid->beacons;
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
			case CLIENT_signal_dbm:
				osstr << cli->snrdata.last_signal_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_minsignal_dbm:
				osstr << cli->snrdata.min_signal_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxsignal_dbm:
				osstr << cli->snrdata.max_signal_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_noise_dbm:
				osstr << cli->snrdata.last_noise_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_minnoise_dbm:
				osstr << cli->snrdata.min_noise_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxnoise_dbm:
				osstr << cli->snrdata.max_noise_dbm;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_signal_rssi:
				osstr << cli->snrdata.last_signal_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_minsignal_rssi:
				osstr << cli->snrdata.min_signal_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxsignal_rssi:
				osstr << cli->snrdata.max_signal_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_noise_rssi:
				osstr << cli->snrdata.last_noise_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_minnoise_rssi:
				osstr << cli->snrdata.min_noise_rssi;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_maxnoise_rssi:
				osstr << cli->snrdata.max_noise_rssi;
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
			case CLIENT_channel:
				osstr << cli->channel;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_freqmhz:
				/* Annoying packed field */
				for (map<unsigned int, unsigned int>::const_iterator fmi = cli->freq_mhz_map.begin(); fmi != cli->freq_mhz_map.end(); ++fmi) {
					osstr << fmi->first << ":" << fmi->second << "*";
				}
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

void Protocol_BSSID_enable(PROTO_ENABLE_PARMS) {
	// Push new networks and reset their rate counters
	for (Netracker::track_iter x = globalreg->netracker->tracked_map.begin(); 
		 x != globalreg->netracker->tracked_map.end(); ++x) {
		Netracker::tracked_network *net = x->second;

		int filtered = 0;

		if (net->type == network_remove)
			continue;

		// Filter on bssid
		if (globalreg->netracker->netcli_filter->RunFilter(net->bssid, 
														   mac_addr(0), mac_addr(0)))
			continue;

		// Do the ADVSSID push inside the BSSID timer kick, because we want 
		// to still allow filtering on the SSID...
		// TODO:  Add filter state caching
		map<uint32_t, Netracker::adv_ssid_data *>::iterator asi;
		for (asi = net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
			if (globalreg->netracker->netcli_filter->RunPcreFilter(asi->second->ssid)) {
				filtered = 1;
				break;
			}
		}

		if (filtered)
			continue;

		kis_protocol_cache cache;
		if (globalreg->kisnetserver->SendToClient(in_fd, _NPM(PROTO_REF_BSSID),
												  (void *) net, &cache) < 0)
			break;

	}
}

void Protocol_SSID_enable(PROTO_ENABLE_PARMS) {
	// Push new networks and reset their rate counters
	for (Netracker::track_iter x = globalreg->netracker->tracked_map.begin(); 
		 x != globalreg->netracker->tracked_map.end(); ++x) {
		Netracker::tracked_network *net = x->second;

		int filtered = 0;

		if (net->type == network_remove)
			continue;

		// Filter on bssid
		if (globalreg->netracker->netcli_filter->RunFilter(net->bssid, mac_addr(0), 
														   mac_addr(0)))
			continue;

		// Do the ADVSSID push inside the BSSID timer kick, because we want 
		// to still allow filtering on the SSID...
		// TODO:  Add filter state caching
		map<uint32_t, Netracker::adv_ssid_data *>::iterator asi;
		for (asi = net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
			if (globalreg->netracker->netcli_filter->RunPcreFilter(asi->second->ssid)) {
				filtered = 1;
				break;
			}
		}

		if (filtered)
			continue;

		for (asi = net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
			kis_protocol_cache cache;
			if (globalreg->kisnetserver->SendToClient(in_fd, _NPM(PROTO_REF_SSID),
													  (void *) asi->second, 
													  &cache) < 0)
				break;
		}
	}
}

void Protocol_CLIENT_enable(PROTO_ENABLE_PARMS) {
	// Push new networks and reset their rate counters
	for (Netracker::track_iter x = globalreg->netracker->tracked_map.begin(); 
		 x != globalreg->netracker->tracked_map.end(); ++x) {
		Netracker::tracked_network *net = x->second;

		int filtered = 0;

		if (net->type == network_remove)
			continue;

		// Filter on bssid
		if (globalreg->netracker->netcli_filter->RunFilter(net->bssid, 
														   mac_addr(0), mac_addr(0)))
			continue;

		// Do the ADVSSID push inside the BSSID timer kick, because we want 
		// to still allow filtering on the SSID...
		// TODO:  Add filter state caching
		map<uint32_t, Netracker::adv_ssid_data *>::iterator asi;
		for (asi = net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
			if (globalreg->netracker->netcli_filter->RunPcreFilter(asi->second->ssid)) {
				filtered = 1;
				break;
			}
		}

		if (filtered)
			continue;

		for (Netracker::client_iter c = net->client_map.begin();
			 c != net->client_map.end(); ++c) {
			if (c->second->type == client_remove) 
				continue;

			kis_protocol_cache cache;
			if (globalreg->kisnetserver->SendToClient(in_fd, _NPM(PROTO_REF_CLIENT),
													  (void *) c->second, &cache) < 0)
				break;
		}
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

int Netracker_Clicmd_ADDNETCLIFILTER(CLIENT_PARMS) {
	if (parsedcmdline->size() != 1) {
		snprintf(errstr, 1024, "Illegal addnetclifilter request");
		return -1;
	}

	Netracker *netr = (Netracker *) auxptr;

	if (netr->AddNetcliFilter((*parsedcmdline)[0].word) < 0) {
		snprintf(errstr, 1024, "Failed to insert filter string");
		return -1;
	}

	_MSG("Added network client filter '" + (*parsedcmdline)[0].word + "'",
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
			case INFO_llcpackets:
				osstr << globalreg->netracker->FetchNumLLCpackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_datapackets:
				osstr << globalreg->netracker->FetchNumDatapackets();
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
	netcli_filter = NULL;

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

	// Parse the filter for the network client
	netcli_filter = new FilterCore(globalreg);
	vector<string> netclifilterlines = 
		globalreg->kismet_config->FetchOptVec("filter_netclient");
	for (unsigned int fl = 0; fl < netclifilterlines.size(); fl++) {
		if (netcli_filter->AddFilterLine(netclifilterlines[fl]) < 0) {
			_MSG("Failed to add filter_tracker config line from the Kismet config "
				 "file.", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}
	}

	// Register network protocols with the tcp server
	_NPM(PROTO_REF_BSSID) =
		globalreg->kisnetserver->RegisterProtocol("BSSID", 0, 1, 
												  BSSID_fields_text, 
												  &Protocol_BSSID, 
												  &Protocol_BSSID_enable, this);
	_NPM(PROTO_REF_SSID) =
		globalreg->kisnetserver->RegisterProtocol("SSID", 0, 1, 
												  SSID_fields_text, 
												  &Protocol_SSID, 
												  &Protocol_SSID_enable, this);
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
	addnetclifiltercmd_ref =
		globalreg->kisnetserver->RegisterClientCommand("ADDNETCLIFILTER",
													   &Netracker_Clicmd_ADDNETCLIFILTER,
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

	num_packets = num_datapackets = num_cryptpackets = num_errorpackets = 
		num_filterpackets = num_packetdelta = num_llcpackets = 0;
}

Netracker::~Netracker() {
	// FIXME:  More cleanup here
	if (netrackereventid >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(netrackereventid);

	if (track_filter != NULL)
		delete track_filter;
	if (netcli_filter != NULL)
		delete netcli_filter;

}

int Netracker::AddFilter(string in_filter) {
	return track_filter->AddFilterLine(in_filter);
}

int Netracker::AddNetcliFilter(string in_filter) {
	return netcli_filter->AddFilterLine(in_filter);
}

int Netracker::TimerKick() {
	// Push new networks and reset their rate counters
	for (unsigned int x = 0; x < dirty_net_vec.size(); x++) {
		tracked_network *net = dirty_net_vec[x];
		int filtered = 0;

		if (net->type == network_remove)
			continue;

		// Filter on bssid
		if (netcli_filter->RunFilter(net->bssid, mac_addr(0), mac_addr(0)))
			continue;

		// Do the ADVSSID push inside the BSSID timer kick, because we want 
		// to still allow filtering on the SSID...
		// TODO:  Add filter state caching
		map<uint32_t, Netracker::adv_ssid_data *>::iterator asi;
		for (asi = net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
			if (netcli_filter->RunPcreFilter(asi->second->ssid)) {
				filtered = 1;
				break;
			}
		}

		if (filtered)
			continue;

		/*
		if (netcli_filter->RunFilter(net->bssid, mac_addr(0), mac_addr(0)) ||
			netcli_filter->RunPcreFilter(net->ssid))
			continue;
			*/

		globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_BSSID),
										   (void *) net);

		for (asi = net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
			if (asi->second->dirty == 0)
				continue;

			globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_SSID),
											   (void *) asi->second);

			/* Reset dirty and beacon counters */
			asi->second->dirty = 0;
			asi->second->beacons = 0;
		}


		/* Reset the frag, retry, and packet counters */
		net->fragments = 0;
		net->retries = 0;
		net->new_packets = 0;
		net->dirty = 0;
	}

	for (unsigned int x = 0; x < dirty_cli_vec.size(); x++) {
		tracked_client *cli = dirty_cli_vec[x];
		int filtered = 0;

		if (cli->type == client_remove)
			continue;

		if (netcli_filter->RunFilter(cli->netptr->bssid, mac_addr(0), mac_addr(0)))
			continue;

		map<uint32_t, Netracker::adv_ssid_data *>::iterator asi;
		for (asi = cli->netptr->ssid_map.begin(); 
			 asi != cli->netptr->ssid_map.end(); ++asi) {
			if (netcli_filter->RunPcreFilter(asi->second->ssid)) {
				filtered = 1;
				break;
			}
		}

		if (filtered)
			continue;

		globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_CLIENT),
										   (void *) cli);

		for (asi = cli->ssid_map.begin(); asi != cli->ssid_map.end(); ++asi) {
			if (asi->second->dirty == 0)
				continue;

			globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_SSID),
											   (void *) asi->second);

			asi->second->dirty = 0;
		}

		// Reset the frag, retry, and packet counts
		cli->fragments = 0;
		cli->retries = 0;
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

	// Handle client creation inside this network - we already made a net
	// so even if it's client-only data traffic we have a valid net ptr

	client_iter clitr;
	if ((clitr = net->client_map.find(packinfo->source_mac)) == net->client_map.end()) {
		// Make a new client and fill it in

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

		// Pointer to parent net, just in case
		cli->netptr = net;

		// Log it in the simple map
		net->client_map[cli->mac] = cli;

		newclient = 1;
	} else {
		cli = clitr->second;

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
	cli->last_time = globalreg->timestamp.tv_sec;

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

	// Make an info pair and add it to our signaling layer
	if (l1info != NULL) {
		Packinfo_Sig_Combo sc(l1info, gpsinfo);
		net->snrdata += sc;
		cli->snrdata += sc;
	}

	// Add to the LLC count
	if (packinfo->type == packet_management || packinfo->type == packet_phy)
		num_llcpackets++;

	// Add to the frequency tracking, inefficient search but it's a small set
	if (l1info != NULL) {
		if (net->freq_mhz_map.find(l1info->freq_mhz) != net->freq_mhz_map.end())
			net->freq_mhz_map[l1info->freq_mhz]++;
		else
			net->freq_mhz_map[l1info->freq_mhz] = 1;
	}

	// Extract info from probe request frames if its a probe network
	if (packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_req) {
		
		// Build the SSID block checksum
		ostringstream ssid_st;

		// Combine some fields into a string
		ssid_st << packinfo->ssid << packinfo->ssid_len;

		packinfo->ssid_csum = Adler32Checksum(ssid_st.str().c_str(), 
									ssid_st.str().length());
		map<uint32_t, Netracker::adv_ssid_data *>::iterator ssidi =
			net->ssid_map.find(packinfo->ssid_csum);

		Netracker::adv_ssid_data *adssid;

		if (ssidi == net->ssid_map.end()) {
			adssid = BuildAdvSSID(packinfo->ssid_csum, packinfo);
			adssid->type = ssid_probereq;
			cli->ssid_map[packinfo->ssid_csum] = adssid;
		} else {
			adssid = ssidi->second;
		}

		// Alert on crypto change
		if (adssid->cryptset != packinfo->cryptset && adssid->cryptset != 0 &&
			globalreg->alertracker->PotentialAlert(alert_wepflap_ref)) {
			ostringstream outs;

			outs << "Network BSSID " << net->bssid.Mac2String() << " changed advertised "
				"SSID '" + packinfo->ssid + "' encryption ";

			if (packinfo->cryptset == 0)
				outs << "to no encryption when it was previous advertised, an "
					"impersonation attack may be underway";
			else if (packinfo->cryptset < adssid->cryptset)
				outs << "to a weaker encryption set than previously advertised, which "
					"may indicate an attack";
			else
				outs << "a different encryption set than previous advertised";

			globalreg->alertracker->RaiseAlert(alert_wepflap_ref, in_pack, 
											   packinfo->bssid_mac, 
											   packinfo->source_mac, 
											   packinfo->dest_mac, 
											   packinfo->other_mac, 
											   packinfo->channel, outs.str());
		}

		adssid->cryptset = packinfo->cryptset;

		adssid->last_time = globalreg->timestamp.tv_sec;
		adssid->packets++;

		adssid->maxrate = packinfo->maxrate;

		adssid->dirty = 1;
	}

	// Extract info from beacon frames, they're the only ones we trust to
	// give us good info...
	if (packinfo->type == packet_management && 
		packinfo->subtype == packet_sub_beacon) {

		// Build the SSID block checksum
		ostringstream ssid_st;

		// Combine some fields into a string
		ssid_st << packinfo->ssid << packinfo->ssid_len << packinfo->cryptset;

		packinfo->ssid_csum = 
			Adler32Checksum(ssid_st.str().c_str(), ssid_st.str().length());

		map<uint32_t, Netracker::adv_ssid_data *>::iterator ssidi =
			net->ssid_map.find(packinfo->ssid_csum);

		Netracker::adv_ssid_data *adssid;

		if (ssidi == net->ssid_map.end()) {
			adssid = BuildAdvSSID(packinfo->ssid_csum, packinfo);
			adssid->type = ssid_beacon;
			net->ssid_map[packinfo->ssid_csum] = adssid;
		} else {
			adssid = ssidi->second;
		}

		adssid->last_time = globalreg->timestamp.tv_sec;
		adssid->packets++;

		adssid->beacons++;

		adssid->dirty = 1;

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

		if (packinfo->cryptset == 0) {
			if (adssid->cryptset && alert_wepflap_ref &&
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

		if (packinfo->channel != 0) {
			// Inherit the channel from the beacon
			net->channel = packinfo->channel;
			cli->channel = packinfo->channel;
		} else if (l1info != NULL) {
			// Otherwise inherit it from the radio layer.  Arguably this could 
			// lie for 2.4ghz stuff, but a 2.4ghz beacon should always have
			// the channel in it.  5ghz (and presumably 4.x ghz) networks don't
			// carry the beacon
			net->channel = FreqToChan(l1info->freq_mhz);
			cli->channel = net->channel;
		}

		if (l1info != NULL) {
			if (cli->freq_mhz_map.find(l1info->freq_mhz) != cli->freq_mhz_map.end())
				cli->freq_mhz_map[l1info->freq_mhz]++;
			else
				cli->freq_mhz_map[l1info->freq_mhz] = 1;
		}
	}

	// Catch probe responses, handle adding probe resp SSIDs

	if (packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_resp) {

		// Build the SSID block checksum
		ostringstream ssid_st;

		// Combine some fields into a string
		ssid_st << packinfo->ssid << packinfo->ssid_len;

		packinfo->ssid_csum = 
			Adler32Checksum(ssid_st.str().c_str(), ssid_st.str().length());

		map<uint32_t, Netracker::adv_ssid_data *>::iterator ssidi =
			net->ssid_map.find(packinfo->ssid_csum);

		Netracker::adv_ssid_data *adssid;

		if (ssidi == net->ssid_map.end()) {
			adssid = BuildAdvSSID(packinfo->ssid_csum, packinfo);
			adssid->type = ssid_proberesp;
			net->ssid_map[packinfo->ssid_csum] = adssid;
		} else {
			adssid = ssidi->second;
		}

		// Alert on crypto change
		if (adssid->cryptset != packinfo->cryptset && adssid->cryptset != 0 &&
			globalreg->alertracker->PotentialAlert(alert_wepflap_ref)) {
			ostringstream outs;

			outs << "Network BSSID " << net->bssid.Mac2String() << " responding to "
				"SSID '" + packinfo->ssid + "' with ";

			if (packinfo->cryptset == 0)
				outs << "no encryption when it was previously advertised as "
					"encrypted, an impersonation attack may be underway";
			else if (packinfo->cryptset < adssid->cryptset)
				outs << "a weaker encryption set than previously advertised, "
					"which may indicate an attack";
			else
				outs << "a different encryption set";

			globalreg->alertracker->RaiseAlert(alert_wepflap_ref, in_pack, 
											   packinfo->bssid_mac, 
											   packinfo->source_mac, 
											   packinfo->dest_mac, 
											   packinfo->other_mac, 
											   packinfo->channel, outs.str());
		}

		adssid->cryptset = packinfo->cryptset;

		adssid->last_time = globalreg->timestamp.tv_sec;
		adssid->packets++;
		adssid->dirty = 1;
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
		num_datapackets++;
		net->data_packets++;
		cli->data_packets++;

		if (packinfo->encrypted) {
			net->crypt_packets++;
			cli->crypt_packets++;
		}
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

	int net_filtered = 0;
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

		// Use the packinfo field here to spew out info about the network,
		// since we don't want to have to find the advssid data related
		string ssid;
		if (packinfo->ssid_len == 0) {
			if (net->type == network_probe) {
				ssid = "<Any>";
			} else if (net->type == network_data) {
				ssid = "<Unknown>";
			} else {
				ssid = "<Hidden SSID>";
			}
		} else {
			ssid = packinfo->ssid;
		}

		snprintf(status, STATUS_MAX, "Detected new %s network \"%s\", BSSID %s, "
				 "encryption %s, channel %d, %2.2f mbit",
				 nettype.c_str(),
				 ssid.c_str(),
				 net->bssid.Mac2String().c_str(),
				 packinfo->cryptset ? "yes" : "no",
				 net->channel, packinfo->maxrate);
		_MSG(status, MSGFLAG_INFO);

		// Check filtering and send BSSID
		int filtered = 0;

		map<uint32_t, Netracker::adv_ssid_data *>::iterator asi;
		for (asi = net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
			if (netcli_filter->RunPcreFilter(asi->second->ssid)) {
				filtered = 1;
				break;
			}
		}

		net_filtered = filtered;

		// Send the BSSID and all SSIDs: If it's a new BSSID, by default,
		// all SSIDs are new
		if (filtered == 0) {
			globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_BSSID), 
											   (void *) net);

			for (asi = net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {
				globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_SSID),
												   (void *) asi->second);
			}
		}
	}

	// Don't send clients for filtered nets
	if (newclient && net_filtered == 0) {
		// Send the BSSID and all SSIDs: If it's a new BSSID, by default,
		// all SSIDs are new
		map<uint32_t, Netracker::adv_ssid_data *>::iterator asi;
		for (asi = cli->ssid_map.begin(); asi != cli->ssid_map.end(); ++asi) {
			globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_SSID),
											   (void *) asi->second);
		}
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
				ip_calced_range.s_addr != 0 &&
				net->guess_ipdata.ip_addr_block.s_addr != 0 &&
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
			// Track combined addresses for both types so we can pick the
			// best one
			in_addr combo_tcpudp;
			in_addr combo_arp;
			in_addr combo_nil; // This is dumb
			combo_tcpudp.s_addr = ~0;
			combo_arp.s_addr = ~0;
			combo_nil.s_addr = ~0;

			for (client_iter i = net->client_map.begin(); i != net->client_map.end();
				 ++i) {
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
						 " via ARP for network " + net->bssid.Mac2String(),
						 MSGFLAG_INFO);

				} else if (net->guess_ipdata.ip_type <= ipdata_udptcp &&
						   combo_tcpudp.s_addr != combo_nil.s_addr && 
						   combo_tcpudp.s_addr != 
						   net->guess_ipdata.ip_addr_block.s_addr) {
					net->guess_ipdata.ip_type = ipdata_udptcp;
					net->guess_ipdata.ip_addr_block.s_addr =
						combo_tcpudp.s_addr;

					_MSG("Found IP range " + string(inet_ntoa(combo_tcpudp)) +
						 " via TCP/UDP for network " + net->bssid.Mac2String(),
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
				(int) x->second.ip_addr_block.s_addr, 
				(int) x->second.ip_netmask.s_addr,
				(int) x->second.ip_gateway.s_addr);
	}

	fclose(ipf);

	return 1;
}

int Netracker::FetchNumNetworks() {
	return tracked_map.size();
}

int Netracker::FetchNumClients() {
	return client_mini_map.size();
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

int Netracker::FetchNumErrorpackets() {
	return num_errorpackets;
}

int Netracker::FetchNumLLCpackets() {
	return num_llcpackets;
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

Netracker::adv_ssid_data *Netracker::BuildAdvSSID(uint32_t ssid_csum, 
												  kis_ieee80211_packinfo *packinfo) {
	Netracker::adv_ssid_data *adssid;

	adssid = new Netracker::adv_ssid_data;
	adssid->checksum = ssid_csum;
	adssid->mac = packinfo->bssid_mac;
	adssid->ssid = string(packinfo->ssid);
	if (packinfo->ssid_len == 0 || packinfo->ssid_blank)
		adssid->ssid_cloaked = 1;
	adssid->beacon_info = string(packinfo->beacon_info);
	adssid->cryptset = packinfo->cryptset;
	adssid->first_time = globalreg->timestamp.tv_sec;
	adssid->maxrate = packinfo->maxrate;
	adssid->beaconrate = Ieee80211Interval2NSecs(packinfo->beacon_interval);
	adssid->packets = 0;

	return adssid;
}

