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
#include "manuf.h"
#include "packetsource.h"

// TCP server hooks
const char *BSSID_fields_text[] = {
    "bssid", "type",
    "llcpackets", "datapackets", "cryptpackets",
    "manuf", "channel", "firsttime", "lasttime", "atype", 
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
	"newpackets", "freqmhz", "datacryptset",
    NULL
};

const char *SSID_fields_text[] = {
	"mac", "checksum", "type", "ssid",
	"beaconinfo", "cryptset", "cloaked",
	"firsttime", "lasttime", "maxrate",
	"beaconrate", "packets", "beacons",
	"dot11d", 
	NULL
};

const char *BSSIDSRC_fields_text[] = {
	"bssid", "uuid", "lasttime", "numpackets", 
    "signal_dbm", "noise_dbm",
	"minsignal_dbm", "minnoise_dbm",
	"maxsignal_dbm", "maxnoise_dbm",
    "signal_rssi", "noise_rssi",
	"minsignal_rssi", "minnoise_rssi",
	"maxsignal_rssi", "maxnoise_rssi",
	NULL
};

const char *CLISRC_fields_text[] = {
	"bssid", "mac", "uuid", "lasttime", "numpackets",
    "signal_dbm", "noise_dbm",
	"minsignal_dbm", "minnoise_dbm",
	"maxsignal_dbm", "maxnoise_dbm",
    "signal_rssi", "noise_rssi",
	"minsignal_rssi", "minnoise_rssi",
	"maxsignal_rssi", "maxnoise_rssi",
	NULL
};

const char *NETTAG_fields_text[] = {
	"bssid", "tag", "value",
	NULL
};

const char *CLITAG_fields_text[] = {
	"bssid", "mac", "tag", "value",
	NULL
};

const char *REMOVE_fields_text[] = {
    "bssid",
    NULL
};

const char *CLIENT_fields_text[] = {
    "bssid", "mac", "type", "firsttime", "lasttime",
    "manuf", "llcpackets", "datapackets", "cryptpackets", 
    "gpsfixed",
    "minlat", "minlon", "minalt", "minspd",
    "maxlat", "maxlon", "maxalt", "maxspd",
    "agglat", "agglon", "aggalt", "aggpoints",
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
	"cdpdevice", "cdpport", "dot11d", "dhcphost", "dhcpvendor",
	"datacryptset", 
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
			case BSSID_manuf:
				out_string += "\001" + net->manuf + "\001";
				cache->Cache(fnum, "\001" + net->manuf + "\001");
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
			case BSSID_datacryptset:
				osstr << net->data_cryptset;
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
				osstr << "\001" << ssid->ssid << "\001";
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
			case SSID_dot11d:
				// Complex packed field (suck, I know):
				// \001 COUNTRYCODE:start-num-dbm:start-num-dbm:.. \001
				osstr << "\001" + ssid->dot11d_country << ":";
				for (unsigned int z = 0; z < ssid->dot11d_vec.size(); z++) {
					osstr << ssid->dot11d_vec[z].startchan << "-" <<
						ssid->dot11d_vec[z].numchan << "-" <<
						ssid->dot11d_vec[z].txpower << ":";
				}
				osstr << "\001";
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
			case CLIENT_manuf:
				out_string += "\001" + cli->manuf + "\001";
				cache->Cache(fnum, "\001" + cli->manuf + "\001");
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
			case CLIENT_carrierset:
				osstr << cli->snrdata.carrierset;
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
			case CLIENT_cdpdevice:
				if (cli->cdp_dev_id.length() == 0)
					scratch = "\001 \001";
				else
					scratch = "\001" + cli->cdp_dev_id + "\001";
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case CLIENT_cdpport:
				if (cli->cdp_port_id.length() == 0)
					scratch = "\001 \001";
				else
					scratch = "\001" + cli->cdp_port_id + "\001";
				out_string += scratch;
				cache->Cache(fnum, scratch);
				break;
			case CLIENT_dot11d:
				osstr << "\001" << cli->dot11d_country << ":";
				for (unsigned int z = 0; z < cli->dot11d_vec.size(); z++) {
					osstr << cli->dot11d_vec[z].startchan << "-" <<
						cli->dot11d_vec[z].numchan << "-" <<
						cli->dot11d_vec[z].txpower << ":";
					osstr << "\001";
					out_string += osstr.str();
					cache->Cache(fnum, osstr.str());
				}
				break;
			case CLIENT_dhcphost:
				osstr << "\001" << cli->dhcp_host << "\001";
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_dhcpvendor:
				osstr << "\001" << cli->dhcp_vendor << "\001";
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
			case CLIENT_datacryptset:
				osstr << cli->data_cryptset;
				out_string += osstr.str();
				cache->Cache(fnum, osstr.str());
				break;
		}

		// print the newly filled in cache
		out_string += " ";
    }

    return 1;
}

int Protocol_BSSIDSRC(PROTO_PARMS) {
	Netracker::source_data *sd = (Netracker::source_data *) data;
	ostringstream osstr;
	string scratch;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= BSSIDSRC_maxfield) {
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
			case BSSIDSRC_bssid:
				scratch = sd->bssid.Mac2String().c_str();
				break;
			case BSSIDSRC_uuid:
				scratch = sd->source_uuid.UUID2String().c_str();
				break;
			case BSSIDSRC_lasttime:
				scratch = IntToString(sd->last_seen);
				break;
			case BSSIDSRC_numpackets:
				scratch = IntToString(sd->num_packets);
				break;
			case BSSIDSRC_signal_dbm:
				scratch = IntToString(sd->snrdata.last_signal_dbm);
				break;
			case BSSIDSRC_minsignal_dbm:
				scratch = IntToString(sd->snrdata.min_signal_dbm);
				break;
			case BSSIDSRC_maxsignal_dbm:
				scratch = IntToString(sd->snrdata.max_signal_dbm);
				break;
			case BSSIDSRC_noise_dbm:
				scratch = IntToString(sd->snrdata.last_noise_dbm);
				break;
			case BSSIDSRC_minnoise_dbm:
				scratch = IntToString(sd->snrdata.min_noise_dbm);
				break;
			case BSSIDSRC_maxnoise_dbm:
				scratch = IntToString(sd->snrdata.max_noise_dbm);
				break;
			case BSSIDSRC_signal_rssi:
				scratch = IntToString(sd->snrdata.last_signal_rssi);
				break;
			case BSSIDSRC_minsignal_rssi:
				scratch = IntToString(sd->snrdata.min_signal_rssi);
				break;
			case BSSIDSRC_maxsignal_rssi:
				scratch = IntToString(sd->snrdata.max_signal_rssi);
				break;
			case BSSIDSRC_noise_rssi:
				scratch = IntToString(sd->snrdata.last_noise_rssi);
				break;
			case BSSIDSRC_minnoise_rssi:
				scratch = IntToString(sd->snrdata.min_noise_rssi);
				break;
			case BSSIDSRC_maxnoise_rssi:
				scratch = IntToString(sd->snrdata.max_noise_rssi);
				break;
		}

		out_string += scratch;
		cache->Cache(fnum, scratch);

		// print the newly filled in cache
		out_string += " ";
    }

    return 1;
}

// Reuse the same struct for net and client tags
struct nettag_struct {
	mac_addr bssid;
	mac_addr mac;
	map<string, string>::const_iterator mi;
};

int Protocol_NETTAG(PROTO_PARMS) {
	nettag_struct *s = (nettag_struct *) data;

	string scratch;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= NETTAG_maxfield) {
            out_string = "Unknown field requested.";
            return -1;
		}

		// Shortcut test the cache once and print/bail immediately
		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		// Fill in the cached element
		switch (fnum) {
			case NETTAG_bssid:
				scratch = s->bssid.Mac2String().c_str();
				break;
			case NETTAG_tag:
				scratch = "\001" + s->mi->first + "\001";
				break;
			case NETTAG_value:
				scratch = "\001" + s->mi->second + "\001";
				break;
		}

		out_string += scratch;
		cache->Cache(fnum, scratch);

		out_string += " ";
    }

    return 1;
}

void Protocol_NETTAG_enable(PROTO_ENABLE_PARMS) {
	// Push new networks and reset their rate counters
	for (Netracker::track_iter x = globalreg->netracker->tracked_map.begin(); 
		 x != globalreg->netracker->tracked_map.end(); ++x) {
		Netracker::tracked_network *net = x->second;

		if (net->type == network_remove)
			continue;

		for (map<string, string>::const_iterator ai = net->arb_tag_map.begin();
			 ai != net->arb_tag_map.end(); ++ai) {
			nettag_struct s;

			s.bssid = net->bssid;
			s.mi = ai;

			kis_protocol_cache cache;
			if (globalreg->kisnetserver->SendToClient(in_fd, 
											globalreg->netracker->proto_ref_nettag,
							  				(void *) &s, &cache) < 0)
				break;
		}
	}
}

int Protocol_CLITAG(PROTO_PARMS) {
	nettag_struct *s = (nettag_struct *) data;

	string scratch;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= CLITAG_maxfield) {
            out_string = "Unknown field requested.";
            return -1;
		}

		// Shortcut test the cache once and print/bail immediately
		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		// Fill in the cached element
		switch(fnum) {
			case CLITAG_bssid:
				scratch = s->bssid.Mac2String().c_str();
				break;
			case CLITAG_mac:
				scratch = s->mac.Mac2String().c_str();
				break;
			case CLITAG_tag:
				scratch = "\001" + s->mi->first + "\001";
				break;
			case CLITAG_value:
				scratch = "\001" + s->mi->second + "\001";
				break;
		}

		out_string += scratch;
		cache->Cache(fnum, scratch);

		out_string += " ";
    }

    return 1;
}

void Protocol_CLITAG_enable(PROTO_ENABLE_PARMS) {
	// Push new networks and reset their rate counters
	for (Netracker::track_iter x = globalreg->netracker->tracked_map.begin(); 
		 x != globalreg->netracker->tracked_map.end(); ++x) {

		if (x->second->type == network_remove)
			continue;

		for (Netracker::client_iter c = x->second->client_map.begin();
			 c != x->second->client_map.end(); ++c) {

			for (map<string, string>::const_iterator ai = c->second->arb_tag_map.begin();
				 ai != c->second->arb_tag_map.end(); ++ai) {
				nettag_struct s;

				s.bssid = x->second->bssid;
				s.mac = c->second->mac;
				s.mi = ai;

				kis_protocol_cache cache;
				if (globalreg->kisnetserver->SendToClient(in_fd, 
											  globalreg->netracker->proto_ref_clitag,
											  (void *) &s, &cache) < 0)
					break;
			}
		}
	}
}

int Protocol_CLISRC(PROTO_PARMS) {
	Netracker::source_data *sd = (Netracker::source_data *) data;
	ostringstream osstr;
	string scratch;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= CLISRC_maxfield) {
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
			case CLISRC_bssid:
				scratch = sd->bssid.Mac2String().c_str();
				break;
			case CLISRC_mac:
				scratch = sd->mac.Mac2String().c_str();
				break;
			case CLISRC_uuid:
				scratch = sd->source_uuid.UUID2String().c_str();
				break;
			case CLISRC_lasttime:
				scratch = IntToString(sd->last_seen);
				break;
			case CLISRC_numpackets:
				scratch = IntToString(sd->num_packets);
				break;
			case CLISRC_signal_dbm:
				scratch = IntToString(sd->snrdata.last_signal_dbm);
				break;
			case CLISRC_minsignal_dbm:
				scratch = IntToString(sd->snrdata.min_signal_dbm);
				break;
			case CLISRC_maxsignal_dbm:
				scratch = IntToString(sd->snrdata.max_signal_dbm);
				break;
			case CLISRC_noise_dbm:
				scratch = IntToString(sd->snrdata.last_noise_dbm);
				break;
			case CLISRC_minnoise_dbm:
				scratch = IntToString(sd->snrdata.min_noise_dbm);
				break;
			case CLISRC_maxnoise_dbm:
				scratch = IntToString(sd->snrdata.max_noise_dbm);
				break;
			case CLISRC_signal_rssi:
				scratch = IntToString(sd->snrdata.last_signal_rssi);
				break;
			case CLISRC_minsignal_rssi:
				scratch = IntToString(sd->snrdata.min_signal_rssi);
				break;
			case CLISRC_maxsignal_rssi:
				scratch = IntToString(sd->snrdata.max_signal_rssi);
				break;
			case CLISRC_noise_rssi:
				scratch = IntToString(sd->snrdata.last_noise_rssi);
				break;
			case CLISRC_minnoise_rssi:
				scratch = IntToString(sd->snrdata.min_noise_rssi);
				break;
			case CLISRC_maxnoise_rssi:
				scratch = IntToString(sd->snrdata.max_noise_rssi);
				break;
		}

		out_string += scratch;
		cache->Cache(fnum, scratch);

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

int Netracker_Clicmd_ADDNETTAG(CLIENT_PARMS) {
	int persist = 0;

	if (parsedcmdline->size() < 4) {
		snprintf(errstr, 1024, "Illegal ADDNETTAG request, expected BSSID "
				 "PERSIST TAG VALUES");
		return -1;
	}

	mac_addr net = mac_addr((*parsedcmdline)[0].word.c_str());

	if (net.error) {
		snprintf(errstr, 1024, "Illegal ADDNETTAG request, expected BSSID "
				 "PERSIST TAG VALUES");
		return -1;
	}

	if ((*parsedcmdline)[1].word != "0")
		persist = 1;

	string content;
	for (unsigned int x = 3; x < parsedcmdline->size(); x++) {
		content += (*parsedcmdline)[x].word;
		if (x < parsedcmdline->size() - 1)
			content += " ";
	}

	((Netracker *) auxptr)->SetNetworkTag(net, (*parsedcmdline)[2].word, content,
										  persist);

	return 1;
}

int Netracker_Clicmd_DELNETTAG(CLIENT_PARMS) {
	if (parsedcmdline->size() < 2) {
		snprintf(errstr, 1024, "Illegal DELNETTAG request, expected BSSID TAG");
		return -1;
	}

	mac_addr net = mac_addr((*parsedcmdline)[0].word.c_str());

	if (net.error) {
		snprintf(errstr, 1024, "Illegal DELNETTAG request, expected BSSID TAG");
		return -1;
	}

	((Netracker *) auxptr)->ClearNetworkTag(net, (*parsedcmdline)[1].word);

	return 1;
}

int Netracker_Clicmd_ADDCLITAG(CLIENT_PARMS) {
	int persist = 0;

	if (parsedcmdline->size() < 5) {
		snprintf(errstr, 1024, "Illegal ADDCLITAG request, expected BSSID MAC PERSIST "
				 "TAG VALUES");
		return -1;
	}

	mac_addr net = mac_addr((*parsedcmdline)[0].word.c_str());

	if (net.error) {
		snprintf(errstr, 1024, "Illegal ADDCLITAG request, expected BSSID MAC PERSIST "
				 "TAG VALUES");
		return -1;
	}

	mac_addr cli = mac_addr((*parsedcmdline)[1].word.c_str());

	if (cli.error) {
		snprintf(errstr, 1024, "Illegal ADDCLITAG request, expected BSSID MAC PERSIST "
				 "TAG VALUES");
		return -1;
	}

	if ((*parsedcmdline)[2].word != "0")
		persist = 1;

	string content;
	for (unsigned int x = 4; x < parsedcmdline->size(); x++) {
		content += (*parsedcmdline)[x].word;
		if (x < parsedcmdline->size() - 1)
			content += " ";
	}

	((Netracker *) auxptr)->SetClientTag(net, cli, (*parsedcmdline)[3].word, content,
										 persist);

	return 1;
}

int Netracker_Clicmd_DELCLITAG(CLIENT_PARMS) {
	if (parsedcmdline->size() < 3) {
		snprintf(errstr, 1024, "Illegal DELCLITAG request, expected BSSID MAC TAG");
		return -1;
	}

	mac_addr net = mac_addr((*parsedcmdline)[0].word.c_str());

	if (net.error) {
		snprintf(errstr, 1024, "Illegal DELCLITAG request, expected BSSID MAC TAG");
		return -1;
	}

	mac_addr cli = mac_addr((*parsedcmdline)[1].word.c_str());

	if (cli.error) {
		snprintf(errstr, 1024, "Illegal DELCLITAG request, expected BSSID MAC TAG");
		return -1;
	}

	((Netracker *) auxptr)->ClearClientTag(net, cli, (*parsedcmdline)[2].word);

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
	((Netracker *) auxptr)->TimerKick();
	return 1;
}

Netracker::Netracker() {
	fprintf(stderr, "FATAL OOPS: Netracker() called with no global registry\n");
}

void Netracker::Usage(char *name) {
	printf(" *** Kismet Net Tracking Options ***\n");
	printf("     --filter-tracker         Tracker filtering\n");
}

Netracker::Netracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;
	track_filter = NULL;
	netcli_filter = NULL;
	vector<string> filterlines;

	int ftc = globalreg->getopt_long_num++;

	static struct option netracker_long_options[] = {
		{ "filter-tracker", required_argument, 0, ftc },
		{ 0, 0, 0, 0 }
	};
	int option_idx = 0;

	optind = 0;

	while (1) {
		int r = getopt_long(globalreg->argc, globalreg->argv,
							"-",
							netracker_long_options, &option_idx);
		if (r < 0) break;

		if (r == ftc)
			filterlines.push_back(string(optarg));
	}

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

	track_probenets = 1;

	// Parse the filtering for the tracker
	track_filter = new FilterCore(globalreg);

	if (filterlines.size() != 0) {
		_MSG("Net tracker filters specified on command line, not loading filters "
			 "from the Kismet config file", MSGFLAG_INFO);
	} else {
		filterlines = 
			globalreg->kismet_config->FetchOptVec("filter_tracker");
	}

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

	// Parse the SSID alert data
	vector<string> spoof_vec = globalreg->kismet_config->FetchOptVec("apspoof");
	for (unsigned int x = 0; x < spoof_vec.size(); x++) {
		string name;
		size_t pos = spoof_vec[x].find(":");
		vector<opt_pair> opts;
		ssid_alert_data *ssid_alert = NULL;
#ifdef HAVE_LIBPCRE
		const char *error = NULL, *study_err = NULL;
		int err_offt;
		pcre *re = NULL;
		pcre_extra *study = NULL;
#endif

		
		if (pos == string::npos || pos >= spoof_vec[x].length() - 1) {
			_MSG("Malformed apspoof= config line in Kismet config file, expected "
				 "apspoof=name:options, got '" + spoof_vec[x] + "'", MSGFLAG_ERROR);
			continue;
		}

		name = spoof_vec[x].substr(0, pos);

		if (StringToOpts(spoof_vec[x].substr(pos + 1, spoof_vec[x].length()),
						 ",", &opts) < 0 || opts.size() == 0) {
			_MSG("Malformed apspoof= alert config line in Kismet config file, expected "
				 "apspoof=name:options, got '" + spoof_vec[x] + "'", MSGFLAG_ERROR);
			continue;
		}

		if (FetchOpt("validmacs", &opts) == "" ||
			(FetchOpt("ssidregex", &opts) == "" && FetchOpt("ssid", &opts) == "")) {
			_MSG("Malformed apspoof= alert config line expects 'validmacs' option "
				 "and 'ssid' or 'ssidregex' options", MSGFLAG_ERROR);
			continue;
		}

		if (FetchOpt("ssidregex", &opts) != "") {
#ifndef HAVE_LIBPCRE
			_MSG("Kismet was not compiled with PCRE, cannot use 'ssidregex' option "
				 "in an apspoof filter", MSGFLAG_ERROR);
			continue;
#else
			if ((re = pcre_compile(FetchOpt("ssidregex", &opts).c_str(), 0, &error,
								   &err_offt, NULL)) == NULL) {
				_MSG("Couldn't parse APSPOOF filter line, invalid PCRE regex "  
					 "'" + FetchOpt("ssidregex", &opts) + 
					 "', regex failure: " + string(error) + " at " +
					 IntToString(err_offt), MSGFLAG_ERROR);
				continue;
			}

			if ((study = pcre_study(re, 0, &study_err)) == NULL && study_err != NULL) {
				_MSG("Couldn't parse APSPOOF filter line '" + 
					 FetchOpt("ssidregex", &opts) +
					 "', optimization failure: " + string(study_err), MSGFLAG_ERROR);
				free(re);
				continue;
			}
#endif
		}

		ssid_alert = new ssid_alert_data;

		ssid_alert->name = name;

		if (FetchOpt("ssid", &opts) != "") {
#ifdef HAVE_LIBPCRE
			if (re != NULL) {
				_MSG("Duplicate 'ssid' and 'ssidregex' options in APSPOOF "
					 "filter line, the 'ssidregex' filter will be used.",
					 MSGFLAG_ERROR);
			}
#endif
		}

#ifdef HAVE_LIBPCRE
		if (re != NULL) {
			ssid_alert->ssid_re = re;
			ssid_alert->ssid_study = study;
			ssid_alert->filter = FetchOpt("ssidregex", &opts);
		} 
#endif
		ssid_alert->ssid = FetchOpt("ssid", &opts);

		vector<string> macvec = StrTokenize(FetchOpt("validmacs", &opts), ",");
	
		int mac_error = 0;
		for (unsigned int m = 0; m < macvec.size(); m++) {
			mac_addr ma = mac_addr(macvec[m].c_str());

			if (ma.error) {
				_MSG("Invalid MAC address '" + macvec[m] + "' in 'validmacs' option "
					 "in APSPOOF filter line, ignoring line", MSGFLAG_ERROR);
				mac_error = 1;
				break;
			}

			ssid_alert->allow_mac_map.insert(ma, 1);
		}

		if (mac_error) {
#ifdef HAVE_LIBPCRE
			if (re)
				pcre_free(re);
			if (study)
				pcre_free(study);
#endif
			delete ssid_alert;
			continue;
		}

		apspoof_vec.push_back(ssid_alert);
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
	proto_ref_bssidsrc =
		globalreg->kisnetserver->RegisterProtocol("BSSIDSRC", 0, 1,
												  BSSIDSRC_fields_text, 
												  &Protocol_BSSIDSRC, 
												  NULL, this);
	proto_ref_clisrc =
		globalreg->kisnetserver->RegisterProtocol("CLISRC", 0, 1,
												  CLISRC_fields_text, 
												  &Protocol_CLISRC, 
												  NULL, this);

	proto_ref_nettag =
		globalreg->kisnetserver->RegisterProtocol("NETTAG", 0, 1,
												  NETTAG_fields_text, 
												  &Protocol_NETTAG, 
												  &Protocol_NETTAG_enable, this);
	proto_ref_clitag =
		globalreg->kisnetserver->RegisterProtocol("CLITAG", 0, 1,
												  CLITAG_fields_text, 
												  &Protocol_CLITAG, 
												  &Protocol_CLITAG_enable, this);

	_NPM(PROTO_REF_REMOVE) =
		globalreg->kisnetserver->RegisterProtocol("REMOVE", 0, 1,
												  REMOVE_fields_text, 
												  &Protocol_REMOVE, NULL, this);

	// Add the client command
	addfiltercmd_ref =
		globalreg->kisnetserver->RegisterClientCommand("ADDTRACKERFILTER",
													   &Netracker_Clicmd_ADDFILTER,
													   this);
	addnetclifiltercmd_ref =
		globalreg->kisnetserver->RegisterClientCommand("ADDNETCLIFILTER",
													   &Netracker_Clicmd_ADDNETCLIFILTER,
													   this);

	addnettagcmd_ref =
		globalreg->kisnetserver->RegisterClientCommand("ADDNETTAG",
													   &Netracker_Clicmd_ADDNETTAG,
													   this);

	delnettagcmd_ref =
		globalreg->kisnetserver->RegisterClientCommand("DELNETTAG",
													   &Netracker_Clicmd_DELNETTAG,
													   this);
	addclitagcmd_ref =
		globalreg->kisnetserver->RegisterClientCommand("ADDCLITAG",
													   &Netracker_Clicmd_ADDCLITAG,
													   this);

	delclitagcmd_ref =
		globalreg->kisnetserver->RegisterClientCommand("DELCLITAG",
													   &Netracker_Clicmd_DELCLITAG,
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
	alert_dhcpname_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPNAMECHANGE");
	alert_dhcpos_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPOSCHANGE");
	alert_adhoc_ref =
		globalreg->alertracker->ActivateConfiguredAlert("ADHOCCONFLICT");
	alert_ssidmatch_ref =
		globalreg->alertracker->ActivateConfiguredAlert("APSPOOF");

	// Register timer kick
	netrackereventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &NetrackerUpdateTimer, (void *) this);

	num_packets = num_datapackets = num_cryptpackets = num_errorpackets = 
		num_filterpackets = num_packetdelta = num_llcpackets = 0;

	// Build the config file
	conf_save = globalreg->timestamp.tv_sec;
	ssid_conf = (ConfigFile *) globalreg->FetchGlobal("SSID_CONF_FILE");

	tag_conf = new ConfigFile(globalreg);
	tag_conf->ParseConfig(tag_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") + "/" + "tag.conf", "", "", 0, 1).c_str());
}

Netracker::~Netracker() {
	SaveSSID();
	SaveTags();

	// FIXME:  More cleanup here
	if (netrackereventid >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(netrackereventid);

	if (track_filter != NULL)
		delete track_filter;
	if (netcli_filter != NULL)
		delete netcli_filter;

	for (map<mac_addr, Netracker::tracked_network *>::iterator n = tracked_map.begin();
		 n != tracked_map.end(); ++n) {
		for (map<uint32_t, Netracker::adv_ssid_data *>::iterator s =
			 n->second->ssid_map.begin(); s != n->second->ssid_map.end(); ++s) {
			delete s->second;
		}

		for (map<uuid, source_data *>::iterator sd = 
			 n->second->source_map.begin(); sd != n->second->source_map.end();
			 ++sd) {
			delete sd->second;
		}

		for (map<mac_addr, Netracker::tracked_client *>::iterator c = 
			 n->second->client_map.begin(); c != n->second->client_map.end(); ++c) {

			for (map<uint32_t, Netracker::adv_ssid_data *>::iterator s =
				 c->second->ssid_map.begin(); s != c->second->ssid_map.end(); ++s) {
				delete s->second;
			}

			for (map<uuid, source_data *>::iterator sd = 
				 c->second->source_map.begin(); sd != c->second->source_map.end();
				 ++sd) {
				delete sd->second;
			}

			delete c->second;
		}

		delete n->second;
	}
}

void Netracker::SaveSSID() {
	int ret;

	string dir = 
		ssid_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir"),
								 "", "", 0, 1);

	ret = mkdir(dir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR);

	if (ret < 0 && errno != EEXIST) {
		string err = string(strerror(errno));
		_MSG("Failed to create Kismet settings directory " + dir + ": " + err,
			 MSGFLAG_ERROR);
	}

	ret = ssid_conf->SaveConfig(ssid_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") + "/" + "ssid_map.conf", "", "", 0, 1).c_str());

	if (ret < 0)
		_MSG("Could not save SSID map cache, check previous error messages (probably "
			 "no permission to write to the Kismet config directory: " + dir,
			 MSGFLAG_ERROR);
}

void Netracker::SaveTags() {
	int ret;

	string dir = 
		tag_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir"),
								"", "", 0, 1);

	ret = mkdir(dir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR);

	if (ret < 0 && errno != EEXIST) {
		string err = string(strerror(errno));
		_MSG("Failed to create Kismet settings directory " + dir + ": " + err,
			 MSGFLAG_ERROR);
	}

	ret = tag_conf->SaveConfig(tag_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") + "/" + "tag.conf", "", "", 0, 1).c_str());

	if (ret < 0)
		_MSG("Could not save tags, check previous error messages (probably "
			 "no permission to write to the Kismet config directory: " + dir,
			 MSGFLAG_ERROR);
}

int Netracker::AddFilter(string in_filter) {
	return track_filter->AddFilterLine(in_filter);
}

int Netracker::AddNetcliFilter(string in_filter) {
	return netcli_filter->AddFilterLine(in_filter);
}

void Netracker::SetNetworkTag(mac_addr in_net, string in_tag, string in_data, int
							  in_persistent) {
	tracked_network *net;
	track_iter ti;

	if ((ti = tracked_map.find(in_net)) == tracked_map.end())
		return;

	net = ti->second;

	net->arb_tag_map[in_tag] = in_data;

	if (in_persistent) {
		vector<string> tfl = tag_conf->FetchOptVec(in_net.Mac2String());
	
		vector<smart_word_token> tflp;
		int repl = 0;
		for (unsigned int x = 0; x < tfl.size(); x++) {
			tflp = NetStrTokenize(tfl[x], ",");

			if (tflp.size() != 2)
				continue;

			if (tflp[0].word == in_tag) {
				repl = 1;
				tfl[x] = "\001" + in_tag + "\001,\001" + in_data + "\001";
				break;
			}
		}

		if (repl == 0) 
			tfl.push_back("\001" + in_tag + "\001,\001" + in_data + "\001");

		tag_conf->SetOptVec(in_net.Mac2String(), tfl, globalreg->timestamp.tv_sec);
	}

	if (net->dirty == 0) {
		dirty_net_vec.push_back(net);
		net->dirty = 1;
	}

}

void Netracker::ClearNetworkTag(mac_addr in_net, string in_tag) {
	track_iter ti;
	map<string, string>::iterator si;

	if ((ti = tracked_map.find(in_net)) == tracked_map.end())
		return;

	if ((si = ti->second->arb_tag_map.find(in_tag)) != ti->second->arb_tag_map.end()) {
		// Set the content to "" so the client gets an update
		// ti->second->arb_tag_map.erase(si);
		si->second = "";

		if (ti->second->dirty == 0) {
			dirty_net_vec.push_back(ti->second);
			ti->second->dirty = 1;
		}

		vector<string> tfl = tag_conf->FetchOptVec(in_net.Mac2String());
		vector<smart_word_token> tflp;
		for (unsigned int x = 0; x < tfl.size(); x++) {
			tflp = NetStrTokenize(tfl[x], ",");

			if (tflp.size() != 2)
				continue;

			if (tflp[0].word == in_tag) {
				tfl.erase(tfl.begin() + x);
				tag_conf->SetOptVec(in_net.Mac2String(), tfl, 
									globalreg->timestamp.tv_sec);
				break;
			}
		}
	}
}

string Netracker::GetNetworkTag(mac_addr in_net, string in_tag) {
	track_iter ti;
	map<string, string>::iterator si;

	if ((ti = tracked_map.find(in_net)) == tracked_map.end())
		return "";

	if ((si = ti->second->arb_tag_map.find(in_tag)) != ti->second->arb_tag_map.end()) {
		return si->second;
	}

	return "";
}

void Netracker::SetClientTag(mac_addr in_net, mac_addr in_cli, string in_tag, 
							 string in_data, int in_persistent) {
	tracked_network *net;
	tracked_client *cli;
	track_iter ti;
	client_iter ci;

	if ((ti = tracked_map.find(in_net)) == tracked_map.end())
		return;

	net = ti->second;

	if ((ci = net->client_map.find(in_cli)) == net->client_map.end())
		return;

	cli = ci->second;

	cli->arb_tag_map[in_tag] = in_data;

	if (in_persistent) {
		vector<string> tfl = 
			tag_conf->FetchOptVec(in_net.Mac2String() + ":" + in_cli.Mac2String());
	
		vector<smart_word_token> tflp;
		int repl = 0;
		for (unsigned int x = 0; x < tfl.size(); x++) {
			tflp = NetStrTokenize(tfl[x], ",");

			if (tflp.size() != 2)
				continue;

			if (tflp[0].word == in_tag) {
				repl = 1;
				tfl[x] = "\001" + in_tag + "\001,\001" + in_data + "\001";
				break;
			}
		}

		if (repl == 0) 
			tfl.push_back("\001" + in_tag + "\001,\001" + in_data + "\001");

		tag_conf->SetOptVec(in_net.Mac2String() + ":" + in_cli.Mac2String(),
							tfl, globalreg->timestamp.tv_sec);
	}

	if (cli->dirty == 0) {
		dirty_cli_vec.push_back(cli);
		cli->dirty = 1;
	}
}

void Netracker::ClearClientTag(mac_addr in_net, mac_addr in_cli, string in_tag) {
	track_iter ti;
	client_iter ci;
	map<string, string>::iterator si;

	if ((ti = tracked_map.find(in_net)) == tracked_map.end())
		return;

	if ((ci = ti->second->client_map.find(in_cli)) == ti->second->client_map.end())
		return;

	if ((si = ci->second->arb_tag_map.find(in_tag)) != ci->second->arb_tag_map.end()) {
		// Set the content to "" so the client gets an update
		// ti->second->arb_tag_map.erase(si);
		si->second = "";

		if (ci->second->dirty == 0) {
			dirty_cli_vec.push_back(ci->second);
			ci->second->dirty = 1;

			vector<string> tfl = 
				tag_conf->FetchOptVec(in_net.Mac2String() + ":" + in_cli.Mac2String());
	
			vector<smart_word_token> tflp;
			for (unsigned int x = 0; x < tfl.size(); x++) {
				tflp = NetStrTokenize(tfl[x], ",");

				if (tflp.size() != 2)
					continue;

				if (tflp[0].word == in_tag) {
					tfl.erase(tfl.begin() + x);
					tag_conf->SetOptVec(in_net.Mac2String() + ":" + in_cli.Mac2String(),
										tfl, globalreg->timestamp.tv_sec);
				}
			}

		}
	}
}

string Netracker::GetClientTag(mac_addr in_net, mac_addr in_cli, string in_tag) {
	track_iter ti;
	client_iter ci;
	map<string, string>::iterator si;

	if ((ti = tracked_map.find(in_net)) == tracked_map.end())
		return "";

	if ((ci = ti->second->client_map.find(in_cli)) == ti->second->client_map.end())
		return "";

	if ((si = ci->second->arb_tag_map.find(in_tag)) != ci->second->arb_tag_map.end()) {
		return si->second;
	}

	return "";
}

int Netracker::TimerKick() {
	// Save SSID config file regularly
	if (globalreg->timestamp.tv_sec - conf_save > 120) {
		conf_save = globalreg->timestamp.tv_sec;
		SaveSSID();
		SaveTags();
	}

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

		for (map<uuid, source_data *>::iterator sdi = net->source_map.begin();
			 sdi != net->source_map.end(); ++sdi) {
			globalreg->kisnetserver->SendToAll(proto_ref_bssidsrc,
											   (void *) sdi->second);
		}

		for (map<string, string>::const_iterator ai = net->arb_tag_map.begin();
			 ai != net->arb_tag_map.end(); ++ai) {
			nettag_struct s;

			s.bssid = net->bssid;
			s.mi = ai;

			globalreg->kisnetserver->SendToAll(proto_ref_nettag, (void *) &s);
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

		for (map<uuid, source_data *>::iterator sdi = cli->source_map.begin();
			 sdi != cli->source_map.end(); ++sdi) {
			globalreg->kisnetserver->SendToAll(proto_ref_clisrc,
											   (void *) sdi->second);
		}

		for (asi = cli->ssid_map.begin(); asi != cli->ssid_map.end(); ++asi) {
			if (asi->second->dirty == 0)
				continue;

			globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_SSID),
											   (void *) asi->second);

			asi->second->dirty = 0;
		}

		for (map<string, string>::const_iterator ai = cli->arb_tag_map.begin();
			 ai != cli->arb_tag_map.end(); ++ai) {
			nettag_struct s;

			s.bssid = cli->bssid;
			s.mac = cli->mac;
			s.mi = ai;

			globalreg->kisnetserver->SendToAll(proto_ref_clitag, (void *) &s);
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
	
	num_packetdelta = 0;

	return 1;
}

int Netracker::netracker_chain_handler(kis_packet *in_pack) {
	tracked_network *net = NULL;
	tracked_client *cli = NULL;
	int newnetwork = 0;
	int newclient = 0;
	char status[STATUS_MAX];

	Packinfo_Sig_Combo *sc = NULL;

	// Fetch the info from the packet chain data
	dot11_packinfo *packinfo = (dot11_packinfo *) 
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

	// Not an 802.11 frame type we known how to track, we'll just skip
	// it, too
	if (packinfo->corrupt || packinfo->type == packet_noise ||
		in_pack->error || packinfo->type == packet_unknown || 
		packinfo->subtype == packet_sub_unknown) {
		num_errorpackets++;
		return 0;
	}

	// Phy packets have no BSSID information so there's nothing else
	// we can do
	if (packinfo->type == packet_phy) {
		num_llcpackets++;
		return 1;
	}

	// Compare against the filter and return w/out making a network record or
	// anything if we're due to be excluded anyhow.  This also keeps datatracker
	// handlers from processing since they won't find a network reference
	if (track_filter->RunFilter(packinfo->bssid_mac, packinfo->source_mac,
								packinfo->dest_mac)) {
		num_filterpackets++;
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

		// Load persistent tags
		vector<string> tfl = tag_conf->FetchOptVec(net->bssid.Mac2String());
	
		vector<smart_word_token> tflp;
		for (unsigned int x = 0; x < tfl.size(); x++) {
			tflp = NetStrTokenize(tfl[x], ",");

			if (tflp.size() != 2)
				continue;

			net->arb_tag_map[tflp[0].word] = tflp[1].word;
		}

		if (globalreg->manufdb != NULL)
			net->manuf = globalreg->manufdb->LookupOUI(net->bssid);

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
		if (packinfo->distrib == distrib_adhoc && net->type == network_ap) {
#if 0
			if (globalreg->alertracker->PotentialAlert(alert_adhoc_ref)) {

				string al = "Network BSSID " + net->bssid.Mac2String() + 
					" advertised as AP network, now advertising as Ad-Hoc IBSS, "
					"which may indicate AP spoofing/impersonation";

				globalreg->alertracker->RaiseAlert(alert_adhoc_ref, in_pack, 
												   packinfo->bssid_mac, 
												   packinfo->source_mac, 
												   packinfo->dest_mac, 
												   packinfo->other_mac, 
												   packinfo->channel, al);

			}
#endif
		} else if (packinfo->type == packet_management && packinfo->ess &&
				   net->type == network_data) {
			// Management frames from an AP on a data-only network turn it into
			// an AP network
			net->type = network_ap;
		} else if (packinfo->distrib == distrib_adhoc) {
			net->type = network_adhoc;
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

		// Load persistent tags
		vector<string> tfl = 
			tag_conf->FetchOptVec(cli->bssid.Mac2String() + ":" + 
								  cli->bssid.Mac2String());
	
		vector<smart_word_token> tflp;
		for (unsigned int x = 0; x < tfl.size(); x++) {
			tflp = NetStrTokenize(tfl[x], ",");

			if (tflp.size() != 2)
				continue;

			net->arb_tag_map[tflp[0].word] = tflp[1].word;
		}

		if (globalreg->manufdb != NULL)
			cli->manuf = globalreg->manufdb->LookupOUI(cli->mac);

		// Set the distribution type
		if (packinfo->distrib == distrib_from || 
			(packinfo->type == packet_management && 
			 packinfo->subtype == packet_sub_beacon))
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

	if (gpsinfo != NULL) {
		net->gpsdata += gpsinfo;
		cli->gpsdata += gpsinfo;
	}

	// Make an info pair and add it to our signaling layer
	if (l1info != NULL) {
		sc = new Packinfo_Sig_Combo(l1info, gpsinfo);
		net->snrdata += *sc;
		cli->snrdata += *sc;
	}

	// Add the source to the network record of who has seen us and when
	kis_ref_capsource *capsource = (kis_ref_capsource *)
		in_pack->fetch(_PCM(PACK_COMP_KISCAPSRC));
	if (capsource != NULL && capsource->ref_source != NULL) {
		map<uuid, source_data *>::iterator sdi;

		if ((sdi = net->source_map.find(capsource->ref_source->FetchUUID())) !=
			net->source_map.end()) {
			sdi->second->last_seen = globalreg->timestamp.tv_sec;
			sdi->second->num_packets++;
			if (sc != NULL)
				sdi->second->snrdata += *sc;
		} else {
			source_data *sd = new source_data;
			sd->source_uuid = capsource->ref_source->FetchUUID();
			sd->last_seen = globalreg->timestamp.tv_sec;
			sd->num_packets = 1;
			sd->bssid = net->bssid;
			if (sc != NULL)
				sd->snrdata += *sc;
			net->source_map[sd->source_uuid] = sd;
		}

		if ((sdi = cli->source_map.find(capsource->ref_source->FetchUUID())) !=
			cli->source_map.end()) {
			sdi->second->last_seen = globalreg->timestamp.tv_sec;
			sdi->second->num_packets++;
			if (sc != NULL)
				sdi->second->snrdata += *sc;
		} else {
			source_data *sd = new source_data;
			sd->source_uuid = capsource->ref_source->FetchUUID();
			sd->last_seen = globalreg->timestamp.tv_sec;
			sd->num_packets = 1;
			sd->bssid = net->bssid;
			sd->mac = cli->mac;
			if (sc != NULL)
				sd->snrdata += *sc;
			cli->source_map[sd->source_uuid] = sd;
		}
	}

	if (sc != NULL) {
		delete sc;
		sc = NULL;
	}

	// Add to the LLC count
	if (packinfo->type == packet_management) {
		num_llcpackets++;
	}

	// Add to the frequency tracking, inefficient search but it's a small set
	if (l1info != NULL) {
		if (net->freq_mhz_map.find(l1info->freq_mhz) != net->freq_mhz_map.end())
			net->freq_mhz_map[l1info->freq_mhz]++;
		else
			net->freq_mhz_map[l1info->freq_mhz] = 1;

		if (cli->freq_mhz_map.find(l1info->freq_mhz) != 
			cli->freq_mhz_map.end())
			cli->freq_mhz_map[l1info->freq_mhz]++;
		else
			cli->freq_mhz_map[l1info->freq_mhz] = 1;
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
			adssid = BuildAdvSSID(packinfo->ssid_csum, packinfo, in_pack);
			adssid->type = ssid_probereq;
			cli->ssid_map[packinfo->ssid_csum] = adssid;

			// Don't change established SSID crypt records from a probe
			adssid->cryptset = packinfo->cryptset;
		} else {
			adssid = ssidi->second;
		}

		adssid->last_time = globalreg->timestamp.tv_sec;
		adssid->packets++;

		adssid->maxrate = packinfo->maxrate;

		adssid->dirty = 1;
	}

	// Extract info from beacon frames, they're the only ones we trust to
	// give us good info...
	if (packinfo->type == packet_management && 
		packinfo->subtype == packet_sub_beacon) {

		// If we're a new network, look up cached and add us to the ssid map
		if (newnetwork) {
			string cached; 
			
			if ((cached = ssid_conf->FetchOpt(packinfo->bssid_mac.Mac2String())) != "") {
				// If we have some indication of the length thanks to nulled-out 
				// bytes, don't import a cache with a different length, otherwise
				// import the cache and flag that we're from a file
				if ((packinfo->ssid_len != 0 && 
					 packinfo->ssid_len == (int) cached.length()) ||
					packinfo->ssid_len == 0) {

					adv_ssid_data *cd = new adv_ssid_data;

					cd->type = ssid_file;
					cd->ssid = cached;
					net->ssid_map[0] = cd;
				}
			}
		}

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
			adssid = BuildAdvSSID(packinfo->ssid_csum, packinfo, in_pack);
			adssid->type = ssid_beacon;
			net->ssid_map[packinfo->ssid_csum] = adssid;
		} else {
			adssid = ssidi->second;
		}

		adssid->last_time = globalreg->timestamp.tv_sec;
		adssid->packets++;

		adssid->beacons++;

		adssid->dirty = 1;

#if 0
		if (alert_airjackssid_ref >= 0 && packinfo->ssid == "AirJack" &&
			globalreg->alertracker->PotentialAlert(alert_airjackssid_ref)) {
			ostringstream outs;

			outs << "Network BSSID " << net->bssid.Mac2String() << 
				" broadcasting SSID 'AirJack' which implies an attempt "
				"to disrupt networks";

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

				outs << "Network BSSID " << net->bssid.Mac2String() << 
					" stopped advertising encryption";

				globalreg->alertracker->RaiseAlert(alert_wepflap_ref, in_pack,
												   packinfo->bssid_mac,
												   packinfo->source_mac,
												   packinfo->dest_mac,
												   packinfo->other_mac,
												   packinfo->channel,
												   outs.str());
			}
		}
#endif

		// Copy the crypto data
		adssid->cryptset = packinfo->cryptset;

		// Fire off an alert if the channel changes
#if 0
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
#endif

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

		// Copy the dot11d data
		adssid->dot11d_country = packinfo->dot11d_country;
		adssid->dot11d_vec = packinfo->dot11d_vec;
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
			adssid = BuildAdvSSID(packinfo->ssid_csum, packinfo, in_pack);
			adssid->type = ssid_proberesp;
			net->ssid_map[packinfo->ssid_csum] = adssid;
		} else {
			adssid = ssidi->second;
		}

		// Alert on crypto change
		if (packinfo->cryptset == 0 && adssid->cryptset != 0 &&
			globalreg->alertracker->PotentialAlert(alert_wepflap_ref)) {
			ostringstream outs;

			outs << "Network BSSID " << net->bssid.Mac2String() << 
				" responding to SSID '" + packinfo->ssid + "' with "
				"no encryption when it was previously advertised as "
				"encrypted, an impersonation attack may be underway";

			globalreg->alertracker->RaiseAlert(alert_wepflap_ref, in_pack, 
											   packinfo->bssid_mac, 
											   packinfo->source_mac, 
											   packinfo->dest_mac, 
											   packinfo->other_mac, 
											   packinfo->channel, outs.str());
		}

		adssid->cryptset |= packinfo->cryptset;

		adssid->last_time = globalreg->timestamp.tv_sec;
		adssid->packets++;
		adssid->dirty = 1;
	}

#if 0
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
#endif

	if (packinfo->type == packet_management ||
		packinfo->type == packet_phy) {
		net->llc_packets++;
		cli->llc_packets++;
	} else if (packinfo->type == packet_data) {
		num_datapackets++;

		net->data_packets++;
		cli->data_packets++;

		if (packinfo->cryptset) {
			num_cryptpackets++;

			net->crypt_packets++;
			cli->crypt_packets++;
		}

		// Handle data sizes
		net->datasize += packinfo->datasize;
		cli->datasize += packinfo->datasize;
	}

	// Increment per-unit rates
	net->new_packets++;
	cli->new_packets++;

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

		/*
		snprintf(status, STATUS_MAX, "Detected new %s network \"%s\", BSSID %s, "
				 "encryption %s, channel %d, %2.2f mbit",
				 nettype.c_str(),
				 ssid.c_str(),
				 net->bssid.Mac2String().c_str(),
				 packinfo->cryptset ? "yes" : "no",
				 net->channel, packinfo->maxrate);
		_MSG(status, MSGFLAG_INFO);
		*/

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
	//	"Smart" vs. "Purely accurate" adhoc handling

	return 1;
}

int Netracker::datatracker_chain_handler(kis_packet *in_pack) {
	// Fetch the info from the packet chain data
	dot11_packinfo *packinfo = (dot11_packinfo *) 
		in_pack->fetch(_PCM(PACK_COMP_80211));

	// No 802.11 info, we don't handle it.
	if (packinfo == NULL) {
		return 0;
	}

	// Not an 802.11 frame type we known how to track, we'll just skip
	// it, too
	if (packinfo->corrupt || packinfo->type != packet_data) { 
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

	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_MANGLEFRAME));

	if (chunk == NULL) {
		if ((chunk = 
			 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_DECAP))) == NULL) {
			if ((chunk = (kis_datachunk *) 
				 in_pack->fetch(_PCM(PACK_COMP_LINKFRAME))) == NULL) {
				return 0;
			}
		}
	}

	// Track decryption
	if (packinfo->decrypted) {
		net->decrypted++;
		// printf("debug - decrypted packet, net %s %d\n", net->bssid.Mac2String().c_str(), net->decrypted);
	}

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

	// Apply the data layer crypt info
	net->data_cryptset |= packinfo->cryptset;
	cli->data_cryptset |= packinfo->cryptset;

	// Apply the DHCP discovery on the client
	if (datainfo->proto  == proto_dhcp_discover) {
#if 0
		if (cli->dhcp_host != datainfo->discover_host &&
			cli->dhcp_host != "" && 
			globalreg->alertracker->PotentialAlert(alert_dhcpname_ref)) {

			string al = "Network BSSID " + net->bssid.Mac2String() + " client " +
				cli->mac.Mac2String() + " changed advertised hostname in DHCP " +
				"from '" + cli->dhcp_host + "' to '" + datainfo->discover_host + "' " +
				"which may indicate client spoofing/impersonation";

			globalreg->alertracker->RaiseAlert(alert_dhcpname_ref, in_pack, 
											   packinfo->bssid_mac, 
											   packinfo->source_mac, 
											   packinfo->dest_mac, 
											   packinfo->other_mac, 
											   packinfo->channel, al);
		}

		if (cli->dhcp_vendor != datainfo->discover_vendor &&
			cli->dhcp_vendor != "" && 
			globalreg->alertracker->PotentialAlert(alert_dhcpos_ref)) {

			string al = "Network BSSID " + net->bssid.Mac2String() + " client " +
				cli->mac.Mac2String() + " changed advertised vendor in DHCP " +
				"from '" + cli->dhcp_vendor + "' to '" + datainfo->discover_vendor + 
				"' which may indicate client spoofing/impersonation";

			globalreg->alertracker->RaiseAlert(alert_dhcpos_ref, in_pack, 
											   packinfo->bssid_mac, 
											   packinfo->source_mac, 
											   packinfo->dest_mac, 
											   packinfo->other_mac, 
											   packinfo->channel, al);
		}
#endif

		cli->dhcp_host = datainfo->discover_host;
		cli->dhcp_vendor = datainfo->discover_vendor;
	}

	// Start comparing IP stuff and move it into the network.  We don't
	// trust IPs coming from the the AP itself UNLESS they're DHCP-Offers because
	// an AP in router mode tends to replicate in internet addresses and confuse
	// things all over the place.
	int ipdata_dirty = 0;

	if ((packinfo->source_mac == net->bssid && 
		 datainfo->proto == proto_dhcp_offer) ||
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

			if (alert_dhcpcon_ref >= 0 && 
				net->guess_ipdata.ip_type == ipdata_dhcp &&
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
			net->guess_ipdata.ip_netmask.s_addr = 
				datainfo->ip_netmask_addr.s_addr;
			net->guess_ipdata.ip_gateway.s_addr = 
				datainfo->ip_gateway_addr.s_addr;

			if (net->dirty == 0) {
				net->dirty = 1;
				dirty_net_vec.push_back(net);
			}

			// Copy it into our client ip data too
			cli->guess_ipdata.ip_type = ipdata_dhcp;
			cli->guess_ipdata.ip_addr_block.s_addr = ip_calced_range.s_addr;
			cli->guess_ipdata.ip_netmask.s_addr = 
				datainfo->ip_netmask_addr.s_addr;
			cli->guess_ipdata.ip_gateway.s_addr = 
				datainfo->ip_gateway_addr.s_addr;
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

		// Recalculate the network IP characteristics if it's not DHCP
		if (ipdata_dirty && net->guess_ipdata.ip_type != ipdata_dhcp) {
			in_addr min_addr, max_addr, mask_addr;
			uint32_t maskbits = ~0 & ~(1 << 0);

			min_addr.s_addr = ~0;
			max_addr.s_addr = 0;
			mask_addr.s_addr = 0;

			for (client_iter i = net->client_map.begin(); i != net->client_map.end();
				 ++i) {

				uint32_t ha;

				// Immediately inherit DHCP data masked by the netmask
				if (i->second->guess_ipdata.ip_type == ipdata_dhcp) {
					net->guess_ipdata = i->second->guess_ipdata;
					net->guess_ipdata.ip_addr_block.s_addr &=
						net->guess_ipdata.ip_netmask.s_addr;

					_MSG("Found IP range " + 
						 string(inet_ntoa(net->guess_ipdata.ip_addr_block)) + "/" + 
						 string(inet_ntoa(net->guess_ipdata.ip_netmask)) + 
						 " via DHCP for network " + net->bssid.Mac2String(),
						 MSGFLAG_INFO);

					goto end_ip_decode;
					break;
				}

				// fprintf(stderr, "debug - client ip %s\n", inet_ntoa(i->second->guess_ipdata.ip_addr_block));

				ha = ntohl(i->second->guess_ipdata.ip_addr_block.s_addr);

				if (ha == 0)
					continue;

				if (ha < min_addr.s_addr)
					min_addr.s_addr = ha;
				if (ha > max_addr.s_addr)
					max_addr.s_addr = ha;
			}

			min_addr.s_addr = htonl(min_addr.s_addr);
			max_addr.s_addr = htonl(max_addr.s_addr);

			for (int x = 1; x < 31; x++) {
				mask_addr.s_addr = htonl(maskbits);

				if ((mask_addr.s_addr & min_addr.s_addr) ==
					(mask_addr.s_addr & max_addr.s_addr)) {
					break;
				}

				maskbits &= ~(1 << x);
			}

			in_addr combo;

			combo.s_addr = (min_addr.s_addr & mask_addr.s_addr);

			// fprintf(stderr, "debug - %s min %s max %s mask %s new %s old %s\n", net->bssid.Mac2String().c_str(), strdup(inet_ntoa(min_addr)), strdup(inet_ntoa(max_addr)), strdup(inet_ntoa(mask_addr)), strdup(inet_ntoa(combo)), strdup(inet_ntoa(net->guess_ipdata.ip_addr_block))); 

			if ((min_addr.s_addr & mask_addr.s_addr) != 
				net->guess_ipdata.ip_addr_block.s_addr) {

				net->guess_ipdata.ip_addr_block.s_addr = 
					(min_addr.s_addr & mask_addr.s_addr);
				net->guess_ipdata.ip_netmask = mask_addr;
				net->guess_ipdata.ip_gateway.s_addr = 0;

				if (net->guess_ipdata.ip_type != ipdata_group) {
					net->guess_ipdata.ip_type = ipdata_group;

					_MSG("Found IP range " + 
						 string(inet_ntoa(net->guess_ipdata.ip_addr_block)) + "/" + 
						 string(inet_ntoa(net->guess_ipdata.ip_netmask)) + 
						 " for network " + net->bssid.Mac2String(), MSGFLAG_INFO);
				}

			}

		} // ipdata dirty
	} // ip considered

end_ip_decode:

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
												  dot11_packinfo *packinfo,
												  kis_packet *in_pack) {
	Netracker::adv_ssid_data *adssid;
	Netracker::tracked_network *net = NULL;

	adssid = new Netracker::adv_ssid_data;
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

		if (tracked_map.find(packinfo->bssid_mac) != tracked_map.end()) {
			net = tracked_map[packinfo->bssid_mac];

			for (map<uint32_t, Netracker::adv_ssid_data *>::iterator asi = 
				 net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {

				// Catch beacon, cloaked situation
				if (asi->second->type == ssid_beacon &&
					asi->second->ssid_cloaked) {
					// Remember the revealed SSID
					ssid_conf->SetOpt(packinfo->bssid_mac.Mac2String(), 
									  packinfo->ssid, 
									  globalreg->timestamp.tv_sec);
				}

			}
		}
	}

	if (packinfo->type == packet_management &&
		(packinfo->subtype == packet_sub_probe_resp || 
		 packinfo->subtype == packet_sub_beacon)) {

#if 0
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
#endif
	}

	return adssid;
}

// vim: ts=4:sw=4
