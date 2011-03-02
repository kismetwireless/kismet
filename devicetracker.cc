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
#include "util.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "devicetracker.h"
#include "packet.h"
#include "gpsdclient.h"
#include "alertracker.h"
#include "manuf.h"
#include "packetsource.h"

enum KISDEV_COMMON_FIELDS {
	KISDEV_phytype, KISDEV_macaddr, KISDEV_firsttime, KISDEV_lasttime,
	KISDEV_packets, KISDEV_llcpackets, KISDEV_errorpackets,
	KISDEV_datapackets, KISDEV_cryptpackets,
	KISDEV_datasize, KISDEV_newpackets, KISDEV_channel, KISDEV_frequency,
	KISDEV_freqmhz,
	
	KISDEV_gpsfixed,
    KISDEV_minlat, KISDEV_minlon, KISDEV_minalt, KISDEV_minspd,
    KISDEV_maxlat, KISDEV_maxlon, KISDEV_maxalt, KISDEV_maxspd,
    KISDEV_signaldbm, KISDEV_noisedbm, 
	KISDEV_minsignaldbm, KISDEV_minnoisedbm, KISDEV_maxsignaldbm, KISDEV_maxnoisedbm,
    KISDEV_signalrssi, KISDEV_noiserssi, KISDEV_minsignalrssi, KISDEV_minnoiserssi,
    KISDEV_maxsignalrssi, KISDEV_maxnoiserssi,
    KISDEV_bestlat, KISDEV_bestlon, KISDEV_bestalt,
    KISDEV_agglat, KISDEV_agglon, KISDEV_aggalt, KISDEV_aggpoints,

	KISDEV_maxfield
};

const char *KISDEV_common_text[] = {
	"phytype", "macaddr", "firsttime", "lasttime",
	"packets", "llcpackets", "errorpackets",
	"datapackets", "cryptpackets",
	"datasize", "newpackets", "channel", "frequency",
	"freqmhz",

	"gpsfixed",
	"minlat", "minlon", "minalt", "minspd",
	"maxlat", "maxlon", "maxalt", "maxspd",
	"signaldbm", "noisedbm", "minsignaldbm", "minnoisedbm",
	"signalrssi", "noiserssi", "minsignalrssi", "minnoiserssi",
	"maxsignalrssi", "maxnoiserssi",
	"bestlat", "bestlon", "bestalt",
	"agglat", "agglon", "aggalt", "aggpoints",

	NULL
};

enum DEVTAG_FIELDS {
	DEVTAG_macaddr, DEVTAG_tag, DEVTAG_value
};

const char *DEVTAG_fields_text[] = {
	"macaddr", "tag", "value"
};

int Protocol_KISDEV_COMMON(PROTO_PARMS) {
	kis_device_common *com = (kis_device_common *) data;
	kis_tracked_device *dev = com->device;
	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];

		if (fnum > KISDEV_maxfield) {
			out_string = "\001Unknown field\001";
			return -1;
		}

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		scratch = "";

		switch (fnum) {
			case KISDEV_phytype:
				scratch = IntToString(com->phy_type);
				break;
			case KISDEV_macaddr:
				scratch = dev->key.Mac2String();
				break;
			case KISDEV_firsttime:
				scratch = IntToString(com->first_time);
				break;
			case KISDEV_lasttime:
				scratch = IntToString(com->last_time);
				break;
			case KISDEV_packets:
				scratch = IntToString(com->packets);
				break;
			case KISDEV_llcpackets:
				scratch = IntToString(com->llc_packets);
				break;
			case KISDEV_errorpackets:
				scratch = IntToString(com->error_packets);
				break;
			case KISDEV_datapackets:
				scratch = IntToString(com->data_packets);
				break;
			case KISDEV_cryptpackets:
				scratch = IntToString(com->crypt_packets);
				break;
			case KISDEV_datasize:
				scratch = LongIntToString(com->datasize);
				break;
			case KISDEV_newpackets:
				scratch = IntToString(com->new_packets);
				break;
			case KISDEV_channel:
				scratch = IntToString(com->channel);
				break;
			case KISDEV_frequency:
				scratch = IntToString(com->frequency);
				break;
			case KISDEV_freqmhz:
				for (map<unsigned int, unsigned int>::const_iterator fmi = com->freq_mhz_map.begin();
					 fmi != com->freq_mhz_map.end(); ++fmi) {
					scratch += IntToString(fmi->first) + ":" + IntToString(fmi->second) + "*";
				}
				break;
			case KISDEV_gpsfixed:
				scratch = IntToString(com->gpsdata.gps_valid);
				break;
			case KISDEV_minlat:
				scratch = FloatToString(com->gpsdata.min_lat);
				break;
			case KISDEV_minlon:
				scratch = FloatToString(com->gpsdata.min_lon);
				break;
			case KISDEV_minalt:
				scratch = FloatToString(com->gpsdata.min_alt);
				break;
			case KISDEV_minspd:
				scratch = FloatToString(com->gpsdata.min_spd);
				break;
			case KISDEV_maxlat:
				scratch = FloatToString(com->gpsdata.max_lat);
				break;
			case KISDEV_maxlon:
				scratch = FloatToString(com->gpsdata.max_lon);
				break;
			case KISDEV_maxalt:
				scratch = FloatToString(com->gpsdata.max_alt);
				break;
			case KISDEV_maxspd:
				scratch = FloatToString(com->gpsdata.max_spd);
				break;
			case KISDEV_signaldbm:
				scratch = IntToString(com->snrdata.last_signal_dbm);
				break;
			case KISDEV_noisedbm:
				scratch = IntToString(com->snrdata.last_noise_dbm);
				break;
			case KISDEV_minsignaldbm:
				scratch = IntToString(com->snrdata.min_signal_dbm);
				break;
			case KISDEV_maxsignaldbm:
				scratch = IntToString(com->snrdata.max_signal_dbm);
				break;
			case KISDEV_minnoisedbm:
				scratch = IntToString(com->snrdata.min_noise_dbm);
				break;
			case KISDEV_maxnoisedbm:
				scratch = IntToString(com->snrdata.max_noise_dbm);
				break;
			case KISDEV_signalrssi:
				scratch = IntToString(com->snrdata.last_signal_rssi);
				break;
			case KISDEV_noiserssi:
				scratch = IntToString(com->snrdata.last_noise_rssi);
				break;
			case KISDEV_minsignalrssi:
				scratch = IntToString(com->snrdata.min_signal_rssi);
				break;
			case KISDEV_maxsignalrssi:
				scratch = IntToString(com->snrdata.max_signal_rssi);
				break;
			case KISDEV_minnoiserssi:
				scratch = IntToString(com->snrdata.min_noise_rssi);
				break;
			case KISDEV_maxnoiserssi:
				scratch = IntToString(com->snrdata.max_noise_rssi);
				break;
			case KISDEV_bestlat:
				scratch = IntToString(com->snrdata.peak_lat);
				break;
			case KISDEV_bestlon:
				scratch = IntToString(com->snrdata.peak_lon);
				break;
			case KISDEV_bestalt:
				scratch = IntToString(com->snrdata.peak_alt);
				break;
			case KISDEV_agglat:
				scratch = LongIntToString(com->gpsdata.aggregate_lat);
				break;
			case KISDEV_agglon:
				scratch = LongIntToString(com->gpsdata.aggregate_lon);
				break;
			case KISDEV_aggalt:
				scratch = LongIntToString(com->gpsdata.aggregate_alt);
				break;
			case KISDEV_aggpoints:
				scratch = LongIntToString(com->gpsdata.aggregate_points);
				break;
		}
		
		cache->Cache(fnum, scratch);
		out_string += scratch + " ";
	}

	return 1;
}
	

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	next_componentid = 0;
	num_packets = num_errorpackets = num_filterpackets = num_packetdelta = 0;

	timerid = 0;

	proto_ref_trackdevice = RegisterDeviceComponent("COMMON");

	conf_save = 0;

	next_phy_id = 0;
}

Devicetracker::~Devicetracker() {

}

int Devicetracker::FetchNumDevices(int in_phy) {
	int r = 0;

	if (in_phy == KIS_PHY_ANY)
		return tracked_map.size();

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (tracked_vec[x]->phy_type == in_phy)
			r++;
	}

	return r;
}

int Devicetracker::FetchNumPackets(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return num_packets;

	map<int, int>::iterator i = phy_packets.find(in_phy);
	if (i != phy_packets.end())
		return i->second;

	return 0;
}

int Devicetracker::FetchNumDatapackets(int in_phy) {
	int r = 0;

	kis_device_common *common;

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (tracked_vec[x]->phy_type == in_phy || in_phy == KIS_PHY_ANY) {
			if ((common = 
				 (kis_device_common *) tracked_vec[x]->fetch(devinfo_common)) != NULL)
				r += common->data_packets;
		}
	}

	return 0;
}

int Devicetracker::FetchNumCryptpackets(int in_phy) {
	int r = 0;

	kis_device_common *common;

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (tracked_vec[x]->phy_type == in_phy || in_phy == KIS_PHY_ANY) {
			if ((common = 
				 (kis_device_common *) tracked_vec[x]->fetch(devinfo_common)) != NULL)
				r += common->crypt_packets;
		}
	}

	return 0;
}

int Devicetracker::FetchNumErrorpackets(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return num_errorpackets;

	map<int, int>::iterator i = phy_errorpackets.find(in_phy);
	if (i != phy_errorpackets.end())
		return i->second;

	return 0;
}

int Devicetracker::FetchNumFilterpackets(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return num_filterpackets;

	map<int, int>::iterator i = phy_filterpackets.find(in_phy);
	if (i != phy_errorpackets.end())
		return i->second;

	return 0;
}

int Devicetracker::FetchPacketRate(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return num_packetdelta;

	map<int, int>::iterator i = phy_packetdelta.find(in_phy);
	if (i != phy_packetdelta.end())
		return i->second;

	return 0;
}

int Devicetracker::RegisterDeviceComponent(string in_component) {
	if (component_str_map.find(StrLower(in_component)) != component_str_map.end()) {
		return component_str_map[StrLower(in_component)];
	}

	int num = next_componentid++;

	component_str_map[StrLower(in_component)] = num;
	component_id_map[num] = StrLower(in_component);

	return num;
}

int Devicetracker::RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler) {
	int num = next_phy_id++;

	Kis_Phy_Handler *strongphy = 
		in_weak_handler->CreatePhyHandler(globalreg, this, num);

	phy_handler_map[num] = strongphy;

	return num;
}

