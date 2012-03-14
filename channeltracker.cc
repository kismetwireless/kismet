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

#include <string>
#include <sstream>

#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "packetsource.h"
#include "configfile.h"
#include "channeltracker.h"
#include "packetsourcetracker.h"

enum CHANNEL_fields {
	CHANNEL_channel, CHANNEL_time_on, CHANNEL_packets, CHANNEL_packets_delta,
	CHANNEL_usec_used, CHANNEL_bytes, CHANNEL_bytes_delta, CHANNEL_networks,
	CHANNEL_maxsignal_dbm, CHANNEL_maxsignal_rssi, CHANNEL_maxnoise_dbm,
	CHANNEL_maxnoise_rssi, CHANNEL_activenetworks,
	CHANNEL_maxfield
};

const char *CHANNEL_fields_text[] = {
	"channel", "time_on", "packets", "packetsdelta",
	"usecused", "bytes", "bytesdelta", "networks",
	"maxsignal_dbm", "maxsignal_rssi", "maxnoise_dbm",
	"maxnoise_rssi", "activenetworks",
	NULL
};

int ct_chan_hook(CHAINCALL_PARMS) {
	((Channeltracker *) auxdata)->ChainHandler(in_pack);
	return 1;
}

int ct_channeltimer(TIMEEVENT_PARMS) {
	((Channeltracker *) auxptr)->ChanTimer();
	return 1;
}

void Protocol_CHANNEL_enable(PROTO_ENABLE_PARMS) {
	return;
}

int Protocol_CHANNEL(PROTO_PARMS) {
	Channeltracker::channel_record *chrec = (Channeltracker::channel_record *) data;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];
		if (fnum >= CHANNEL_maxfield) {
			out_string += "Unknown field requested";
			return -1;
		}

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		switch (fnum) {
			case CHANNEL_channel:
				cache->Cache(fnum, IntToString(chrec->channel));
				break;

			case CHANNEL_time_on:
				cache->Cache(fnum, IntToString(chrec->channel_time_on));
				break;

			case CHANNEL_packets:
				cache->Cache(fnum, IntToString(chrec->packets));
				break;

			case CHANNEL_packets_delta:
				cache->Cache(fnum, IntToString(chrec->packets_delta));
				break;

			case CHANNEL_usec_used:
				cache->Cache(fnum, LongIntToString(chrec->usec_used));
				break;

			case CHANNEL_bytes:
				cache->Cache(fnum, LongIntToString(chrec->bytes_seen));
				break;

			case CHANNEL_bytes_delta:
				cache->Cache(fnum, LongIntToString(chrec->bytes_delta));
				break;

			case CHANNEL_networks:
				cache->Cache(fnum, IntToString(chrec->seen_networks.size()));
				break;

			case CHANNEL_maxsignal_dbm:
				cache->Cache(fnum, IntToString(chrec->max_signal_dbm));
				break;

			case CHANNEL_maxsignal_rssi:
				cache->Cache(fnum, IntToString(chrec->max_signal_rssi));
				break;

			case CHANNEL_maxnoise_dbm:
				cache->Cache(fnum, IntToString(chrec->max_noise_dbm));
				break;

			case CHANNEL_maxnoise_rssi:
				cache->Cache(fnum, IntToString(chrec->max_noise_rssi));
				break;

			case CHANNEL_activenetworks:
				cache->Cache(fnum, IntToString(chrec->delta_networks.size()));
				break;
		}

		out_string += cache->GetCache(fnum) + " ";
	}

	return 1;
}

Channeltracker::Channeltracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	if (globalreg->timetracker == NULL) {
		fprintf(stderr, "FATAL OOPS: Channeltracker called before timetracker\n");
		exit(1);
	}

	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS:  Channeltracker called before packetchain\n");
		exit(1);
	}

	globalreg->packetchain->RegisterHandler(&ct_chan_hook, this, CHAINPOS_LOGGING, 0);

	chan_timer_id =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 2, NULL, 1,
											  &ct_channeltimer, this);

	chan_proto_id =
		globalreg->kisnetserver->RegisterProtocol("CHANNEL", 0, 1,
												  CHANNEL_fields_text,
												  &Protocol_CHANNEL,
												  &Protocol_CHANNEL_enable,
												  this);
}

Channeltracker::~Channeltracker() {
	globalreg->timetracker->RemoveTimer(chan_timer_id);
	globalreg->packetchain->RemoveHandler(&ct_chan_hook, CHAINPOS_LOGGING);
	globalreg->kisnetserver->RemoveProtocol(chan_proto_id);
}

void Channeltracker::ChanTimer() {
	map<uint32_t, int> *tick_map = globalreg->sourcetracker->FetchChannelTickMap();

	// If we have more than 50 channels (arbitrary number) in the tick map, we're
	// probably processing a huge range, which means we won't include the tick
	// map - we'll only use the map of channels we've seen packets on.
	for (map<uint32_t, int>::iterator x = tick_map->begin(); 
		 x != tick_map->end() && tick_map->size() < 50; ++x) {
		if (x->first == 0)
			continue;
		
		if (channel_map.find(x->first) == channel_map.end()) {
			channel_record *crec = new channel_record;
			channel_map[FreqToChan(x->first)] = crec;
			crec->channel = FreqToChan(x->first);
		}
	}

	for (map<uint32_t, channel_record *>::iterator x = channel_map.begin();
		 x != channel_map.end(); ++x) {

		if (tick_map->find(x->first) != tick_map->end()) {
			x->second->channel_time_on = (*tick_map)[x->first] * 
				(1000000 / SERVER_TIMESLICES_SEC);
		} else {
			x->second->channel_time_on = 0;
		}

		globalreg->kisnetserver->SendToAll(chan_proto_id, (void *) x->second);

		// Reset the deltas
		x->second->packets_delta = 0;
		x->second->bytes_delta = 0;
		x->second->usec_used = 0;
		x->second->delta_networks.clear();
		x->second->sent_reset = 1;
	}
}

void Channeltracker::ChainHandler(kis_packet *in_pack) {
	dot11_packinfo *packinfo =
		(dot11_packinfo *) in_pack->fetch(_PCM(PACK_COMP_80211));
	kis_layer1_packinfo *radioinfo =
		(kis_layer1_packinfo *) in_pack->fetch(_PCM(PACK_COMP_RADIODATA));

	channel_record *crec = NULL;

	if (radioinfo == NULL)
		return;

	if (radioinfo->freq_mhz == 0)
		return;

	int channel = FreqToChan(radioinfo->freq_mhz);

	if (channel_map.find(channel) != channel_map.end()) {
		crec = channel_map[channel];
	} else {
		crec = new channel_record;
		channel_map[channel] = crec;
		crec->channel = channel;
	}

	if (packinfo != NULL) {
		crec->bytes_seen += packinfo->datasize;
		crec->bytes_delta += packinfo->datasize;

		if (crec->seen_networks.find(packinfo->bssid_mac) == crec->seen_networks.end()) {
			crec->seen_networks.insert(packinfo->bssid_mac, 1);
			crec->delta_networks.insert(packinfo->bssid_mac, 1);
		} else if (crec->delta_networks.find(packinfo->bssid_mac) ==
				   crec->delta_networks.end()) {
			crec->delta_networks.insert(packinfo->bssid_mac, 1);
		}

		// Todo - fill in time handling
	}

	if ((radioinfo->signal_dbm > crec->max_signal_dbm &&
		 radioinfo->signal_dbm != 0) || crec->sent_reset) 
		crec->max_signal_dbm = radioinfo->signal_dbm;
	
	if (radioinfo->signal_rssi > crec->max_signal_rssi || crec->sent_reset) 
		crec->max_signal_rssi = radioinfo->signal_rssi;

	if ((radioinfo->noise_dbm > crec->max_noise_dbm  &&
		 radioinfo->noise_dbm != 0) || crec->sent_reset) 
		crec->max_noise_dbm = radioinfo->noise_dbm;

	if (radioinfo->noise_rssi > crec->max_noise_rssi || crec->sent_reset) 
		crec->max_noise_rssi = radioinfo->noise_rssi;

	crec->packets++;
	crec->packets_delta++;

	crec->sent_reset = 0;
}

