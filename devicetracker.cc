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
#include <pthread.h>

#include "globalregistry.h"
#include "util.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "devicetracker.h"
#include "packet.h"
#include "gpswrapper.h"
#include "alertracker.h"
#include "manuf.h"
#include "packetsourcetracker.h"
#include "packetsource.h"
#include "dumpfile_devicetracker.h"
#include "entrytracker.h"

#include <msgpack.hpp>

enum KISDEV_COMMON_FIELDS {
	KISDEV_phytype, KISDEV_macaddr, KISDEV_name, KISDEV_typestring, 
	KISDEV_basictype, KISDEV_cryptstring, KISDEV_basiccrypt,
	KISDEV_firsttime, KISDEV_lasttime,
	KISDEV_packets, KISDEV_llcpackets, KISDEV_errorpackets,
	KISDEV_datapackets, KISDEV_cryptpackets, KISDEV_filterpackets,
	KISDEV_datasize, KISDEV_newpackets, KISDEV_channel, KISDEV_frequency,
	KISDEV_freqmhz, KISDEV_manuf,
	
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
	"phytype", "macaddr", "name", "typestring", 
	"basictype", "cryptstring", "basiccrypt",
	"firsttime", "lasttime",
	"packets", "llcpackets", "errorpackets",
	"datapackets", "cryptpackets", "filterpackets",
	"datasize", "newpackets", "channel", "frequency",
	"freqmhz", "manuf",

	"gpsfixed",
	"minlat", "minlon", "minalt", "minspd",
	"maxlat", "maxlon", "maxalt", "maxspd",
	"signaldbm", "noisedbm", "minsignaldbm", "minnoisedbm",
	"maxsignaldbm", "maxnoisedbm",
	"signalrssi", "noiserssi", "minsignalrssi", "minnoiserssi",
	"maxsignalrssi", "maxnoiserssi",
	"bestlat", "bestlon", "bestalt",
	"agglat", "agglon", "aggalt", "aggpoints",

	NULL
};

int Protocol_KISDEV_COMMON(PROTO_PARMS) {
	kis_tracked_device_base *dev = (kis_tracked_device_base *) data;
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
				scratch = UIntToString(dev->get_phytype());
				break;
			case KISDEV_macaddr:
                scratch = dev->get_mac().Mac2String();
				break;
			case KISDEV_name:
				scratch = "\001" + dev->get_name() + "\001";
				break;
			case KISDEV_typestring:
				scratch = "\001" + dev->get_type_string() + "\001";
				break;
			case KISDEV_basictype:
				scratch = IntToString(dev->get_basic_type_set());
				break;
			case KISDEV_cryptstring:
				scratch = "\001" + dev->get_crypt_string() + "\001";
				break;
			case KISDEV_basiccrypt:
				scratch = IntToString(dev->get_basic_crypt_set());
				break;
			case KISDEV_firsttime:
				scratch = UIntToString(dev->get_first_time());
				break;
			case KISDEV_lasttime:
				scratch = UIntToString(dev->get_last_time());
				break;
			case KISDEV_packets:
				scratch = UIntToString(dev->get_packets());
				break;
			case KISDEV_llcpackets:
				scratch = UIntToString(dev->get_llc_packets());
				break;
			case KISDEV_errorpackets:
				scratch = UIntToString(dev->get_error_packets());
				break;
			case KISDEV_datapackets:
				scratch = UIntToString(dev->get_data_packets());
				break;
			case KISDEV_cryptpackets:
				scratch = UIntToString(dev->get_crypt_packets());
				break;
			case KISDEV_filterpackets:
				scratch = UIntToString(dev->get_filter_packets());
				break;
			case KISDEV_datasize:
				scratch = ULongToString(dev->get_datasize_tx() + dev->get_datasize_rx());
				break;
			case KISDEV_newpackets:
				scratch = UIntToString(dev->get_new_packets());
				break;
			case KISDEV_channel:
				scratch = IntToString(dev->get_channel());
				break;
			case KISDEV_frequency:
				scratch = UIntToString(dev->get_frequency());
				break;
			case KISDEV_freqmhz:
				for (map<int, TrackerElement *>::const_iterator fmi = 
					 dev->get_freq_mhz_map()->begin();
					 fmi != dev->get_freq_mhz_map()->end(); ++fmi) {
					scratch += IntToString(fmi->first) + ":" + 
                        UIntToString(GetTrackerValue<uint64_t>(fmi->second)) + "*";
				}
				break;
			case KISDEV_manuf:
				scratch = "\001" + dev->get_manuf() + "\001";
				break;
			case KISDEV_gpsfixed:
                scratch = UIntToString(dev->get_location()->get_valid());
				break;
			case KISDEV_minlat:
                scratch = FloatToString(dev->get_location()->get_min_loc()->get_lat());
				break;
			case KISDEV_minlon:
                scratch = FloatToString(dev->get_location()->get_min_loc()->get_lon());
				break;
			case KISDEV_minalt:
                scratch = FloatToString(dev->get_location()->get_min_loc()->get_alt());
				break;
			case KISDEV_minspd:
                scratch = FloatToString(dev->get_location()->get_min_loc()->get_speed());
				break;
			case KISDEV_maxlat:
                scratch = FloatToString(dev->get_location()->get_max_loc()->get_lat());
				break;
			case KISDEV_maxlon:
                scratch = FloatToString(dev->get_location()->get_max_loc()->get_lon());
				break;
			case KISDEV_maxalt:
                scratch = FloatToString(dev->get_location()->get_max_loc()->get_alt());
				break;
			case KISDEV_maxspd:
                scratch = FloatToString(dev->get_location()->get_max_loc()->get_speed());
				break;
			case KISDEV_signaldbm:
                scratch = IntToString(dev->get_signal_data()->get_last_signal_dbm());
				break;
			case KISDEV_noisedbm:
                scratch = IntToString(dev->get_signal_data()->get_last_noise_dbm());
				break;
			case KISDEV_minsignaldbm:
                scratch = IntToString(dev->get_signal_data()->get_min_signal_dbm());
				break;
			case KISDEV_maxsignaldbm:
                scratch = IntToString(dev->get_signal_data()->get_max_signal_dbm());
				break;
			case KISDEV_minnoisedbm:
                scratch = IntToString(dev->get_signal_data()->get_min_noise_dbm());
				break;
			case KISDEV_maxnoisedbm:
                scratch = IntToString(dev->get_signal_data()->get_max_noise_dbm());
				break;
			case KISDEV_signalrssi:
                scratch = IntToString(dev->get_signal_data()->get_last_signal_rssi());
				break;
			case KISDEV_noiserssi:
                scratch = IntToString(dev->get_signal_data()->get_last_noise_rssi());
				break;
			case KISDEV_minsignalrssi:
                scratch = IntToString(dev->get_signal_data()->get_min_signal_rssi());
				break;
			case KISDEV_maxsignalrssi:
                scratch = IntToString(dev->get_signal_data()->get_max_signal_rssi());
				break;
			case KISDEV_minnoiserssi:
                scratch = IntToString(dev->get_signal_data()->get_min_noise_rssi());
				break;
			case KISDEV_maxnoiserssi:
                scratch = IntToString(dev->get_signal_data()->get_max_noise_rssi());
				break;
			case KISDEV_bestlat:
                scratch = FloatToString(dev->get_signal_data()->get_peak_loc()->get_lat());
				break;
			case KISDEV_bestlon:
                scratch = FloatToString(dev->get_signal_data()->get_peak_loc()->get_lon());
				break;
			case KISDEV_bestalt:
                scratch = FloatToString(dev->get_signal_data()->get_peak_loc()->get_alt());
				break;
			case KISDEV_agglat:
                scratch = LongIntToString(dev->get_location()->get_agg_lat());
				break;
			case KISDEV_agglon:
                scratch = LongIntToString(dev->get_location()->get_agg_lon());
				break;
			case KISDEV_aggalt:
                scratch = LongIntToString(dev->get_location()->get_agg_alt());
				break;
			case KISDEV_aggpoints:
                scratch = LongIntToString(dev->get_location()->get_num_agg());
				break;
		}
		
		cache->Cache(fnum, scratch);
		out_string += scratch + " ";
	}

	return 1;
}

void Protocol_KISDEV_COMMON_enable(PROTO_ENABLE_PARMS) {
	((Devicetracker *) data)->BlitDevices(in_fd);
}

enum DEVICEDONE_FIELDS {
	DEVICEDONE_phytype, DEVICEDONE_macaddr,
	DEVICEDONE_maxfield
};

const char *DEVICEDONE_text[] = {
	"phytype", "macaddr",
	NULL
};

int Protocol_DEVICEDONE(PROTO_PARMS) {
	kis_tracked_device_base *dev = (kis_tracked_device_base *) data;
	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];

		if (fnum > DEVICEDONE_maxfield) {
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
				scratch = IntToString(dev->get_phytype());
				break;
			case DEVICEDONE_macaddr:
				scratch = dev->get_macaddr().Mac2String();
				break;
		}
		
		cache->Cache(fnum, scratch);
		out_string += scratch + " ";
	}

	return 1;
}

enum DEVTAG_FIELDS {
	DEVTAG_phytype, DEVTAG_macaddr, DEVTAG_tag, DEVTAG_value,

	DEVTAG_maxfield
};

const char *DEVTAG_fields_text[] = {
	"phytype", "macaddr", "tag", "value",
	NULL
};

class devtag_tx {
public:
	string tag;
	kis_tag_data *data;
	mac_addr macaddr;
	int phyid;
};

int Protocol_KISDEV_DEVTAG(PROTO_PARMS) {
	devtag_tx *s = (devtag_tx *) data;
	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];
		
		if (fnum > DEVTAG_maxfield) {
			out_string = "\001Unknown field\001";
			return -1;
		}

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		scratch = "";

		switch (fnum) {
			case DEVTAG_phytype:
				scratch = IntToString(s->phyid);
				break;

			case DEVTAG_macaddr:
				scratch = s->macaddr.Mac2String();
				break;

			case DEVTAG_tag:
				scratch = "\001" + s->tag + "\001";
				break;

			case DEVTAG_value:
				scratch = "\001" + s->data->value + "\001";
				break;
		}
		
		cache->Cache(fnum, scratch);
		out_string += scratch + " ";
	}

	return 1;
	
}

void Protocol_DEVTAG_enable(PROTO_ENABLE_PARMS) {

}

enum PHYMAP_FIELDS {
	PHYMAP_phyid, PHYMAP_phyname, PHYMAP_packets, PHYMAP_datapackets, 
	PHYMAP_errorpackets, PHYMAP_filterpackets, PHYMAP_packetrate,

	PHYMAP_maxfield
};

const char *KISDEV_phymap_text[] = {
	"phyid", "phyname", "packets", "datapackets", "errorpackets", 
	"filterpackets", "packetrate",
	NULL
};

// String info shoved into the protocol handler by the string collector
class kis_proto_phymap_info {
public:
	int phyid;
	string phyname;
	int packets, datapackets, errorpackets, filterpackets, packetrate;
};

int Protocol_KISDEV_PHYMAP(PROTO_PARMS) {
	kis_proto_phymap_info *info = (kis_proto_phymap_info *) data;
	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];

		if (fnum > PHYMAP_maxfield) {
			out_string = "\001Unknown field\001";
			return -1;
		}

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		scratch = "";

		switch (fnum) {
			case PHYMAP_phyid:
				scratch = IntToString(info->phyid);
				break;
			case PHYMAP_phyname:
				scratch = "\001" + info->phyname + "\001";
				break;
			case PHYMAP_packets:
				scratch = IntToString(info->packets);
				break;
			case PHYMAP_datapackets:
				scratch = IntToString(info->datapackets);
				break;
			case PHYMAP_errorpackets:
				scratch = IntToString(info->errorpackets);
				break;
			case PHYMAP_filterpackets:
				scratch = IntToString(info->filterpackets);
				break;
			case PHYMAP_packetrate:
				scratch = IntToString(info->packetrate);
				break;
		}
		
		cache->Cache(fnum, scratch);
		out_string += scratch + " ";
	}

	return 1;
}

void Protocol_KISDEV_PHYMAP_enable(PROTO_ENABLE_PARMS) {
	((Devicetracker *) data)->BlitPhy(in_fd);
}

// Replaces the *INFO sentence
enum TRACKINFO_FIELDS {
	TRACKINFO_devices, TRACKINFO_packets, TRACKINFO_datapackets,
	TRACKINFO_cryptpackets, TRACKINFO_errorpackets, TRACKINFO_filterpackets,
	TRACKINFO_packetrate,

	TRACKINFO_maxfield
};

const char *TRACKINFO_fields_text[] = {
	"devices", "packets", "datapackets",
	"cryptpackets", "errorpackets", "filterpackets",
	"packetrate",
	NULL
};

int Protocol_KISDEV_TRACKINFO(PROTO_PARMS) {
	Devicetracker *tracker = (Devicetracker *) data;
	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];

		if (fnum > TRACKINFO_maxfield) {
			out_string = "\001Unknown field\001";
			return -1;
		}

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		scratch = "";

		switch (fnum) {
			case TRACKINFO_devices:
				scratch = IntToString(tracker->FetchNumDevices(KIS_PHY_ANY));
				break;
			case TRACKINFO_packets:
				scratch = IntToString(tracker->FetchNumPackets(KIS_PHY_ANY));
				break;
			case TRACKINFO_datapackets:
				scratch = IntToString(tracker->FetchNumDatapackets(KIS_PHY_ANY));
				break;
			case TRACKINFO_cryptpackets:
				scratch = IntToString(tracker->FetchNumCryptpackets(KIS_PHY_ANY));
				break;
			case TRACKINFO_errorpackets:
				scratch = IntToString(tracker->FetchNumErrorpackets(KIS_PHY_ANY));
				break;
			case TRACKINFO_filterpackets:
				scratch = IntToString(tracker->FetchNumFilterpackets(KIS_PHY_ANY));
				break;
			case TRACKINFO_packetrate:
				scratch = IntToString(tracker->FetchPacketRate(KIS_PHY_ANY));
				break;
		}
		
		cache->Cache(fnum, scratch);
		out_string += scratch + " ";
	}

	return 1;
}

enum STRING_FIELDS {
	STRING_phytype, STRING_macaddr, STRING_source, STRING_dest, STRING_string,
	STRING_maxfield
};

const char *STRINGS_fields_text[] = {
    "phytype", "macaddr", "source", "dest", "string", 
    NULL
};

// String info shoved into the protocol handler by the string collector
class kis_proto_string_info {
public:
	mac_addr device;
	int phy;
	mac_addr source;
	mac_addr dest;
	string stringdata;
};

int Protocol_KISDEV_STRING(PROTO_PARMS) {
	kis_proto_string_info *info = (kis_proto_string_info *) data;

	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];

		if (fnum > STRING_maxfield) {
			out_string = "\001Unknown field\001";
			return -1;
		} 

		switch (fnum) {
			case STRING_macaddr:
				scratch = info->device.Mac2String();
				break;
			case STRING_phytype:
				scratch = IntToString(info->phy);
				break;
			case STRING_source:
				scratch = info->source.Mac2String();
				break;
			case STRING_dest:
				scratch = info->dest.Mac2String();
				break;
			case STRING_string:
				scratch = "\001" + info->stringdata + "\001";
				break;
			default:
				scratch = "\001Unknown string field\001";
				break;
		}

		cache->Cache(fnum, scratch);
		out_string += scratch + " ";
	}

	return 1;
}

int Devicetracker_Timer(TIMEEVENT_PARMS) {
	return ((Devicetracker *) auxptr)->TimerKick();
}

int Devicetracker_packethook_stringcollector(CHAINCALL_PARMS) {
	return ((Devicetracker *) auxdata)->StringCollector(in_pack);
}

int Devicetracker_packethook_commontracker(CHAINCALL_PARMS) {
	return ((Devicetracker *) auxdata)->CommonTracker(in_pack);
}

int Devicetracker_CMD_ADDDEVTAG(CLIENT_PARMS) {
	int persist = 0;
	int pos = 0;

	if (parsedcmdline->size() < 5) {
		snprintf(errstr, 1024, "Illegal ADDDEVTAG request, expected DEVMAC PHYID "
				 "PERSIST TAG VALUE");
		return -1;
	}

	mac_addr dev = mac_addr((*parsedcmdline)[pos++].word.c_str());

	if (dev.error) {
		snprintf(errstr, 1024, "Illegal device in ADDDEVTAG");
		return -1;
	}

	int phyid;
	if (sscanf((*parsedcmdline)[pos++].word.c_str(), "%d", &phyid) != 1) {
		snprintf(errstr, 1024, "Illegal phy id");
		return -1;
	}

	dev.SetPhy(phyid);

	if ((*parsedcmdline)[pos++].word != "0")
		persist = 1;

	string tag = (*parsedcmdline)[pos++].word;

	string content;
	for (unsigned int x = pos; x < parsedcmdline->size(); x++) {
		content += (*parsedcmdline)[x].word;
		if (x < parsedcmdline->size() - 1)
			content += " ";
	}

	int r = ((Devicetracker *) auxptr)->SetDeviceTag(dev, content);

	if (r < 0) {
		snprintf(errstr, 1024, "Failed to set tag");
		return -1;
	}

	return 1;
}

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) {
    pthread_mutex_init(&devicelist_mutex, NULL);

	globalreg = in_globalreg;

	globalreg->InsertGlobal("DEVICE_TRACKER", this);

    kis_tracked_device_base *base_builder = new kis_tracked_device_base(globalreg, 0);

    device_base_id = 
        globalreg->entrytracker->RegisterField("kismet.device.base", base_builder,
                "core device record");

	next_componentid = 0;
	num_packets = num_datapackets = num_errorpackets = 
		num_filterpackets = num_packetdelta = 0;

	conf_save = 0;
	next_phy_id = 0;

    // TODO kill this
    
	// Internally register our common reference first
	devcomp_ref_common = RegisterDeviceComponent("COMMON");

	// Timer kickoff
	timerid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &Devicetracker_Timer, this);

	// Register global packet components used by the device tracker and
	// subsequent parts
	pack_comp_device = _PCM(PACK_COMP_DEVICE) =
		globalreg->packetchain->RegisterPacketComponent("DEVICE");

	pack_comp_common =  _PCM(PACK_COMP_COMMON) =
		globalreg->packetchain->RegisterPacketComponent("COMMON");

	pack_comp_basicdata = _PCM(PACK_COMP_BASICDATA) = 
		globalreg->packetchain->RegisterPacketComponent("BASICDATA");

	_PCM(PACK_COMP_MANGLEFRAME) =
		globalreg->packetchain->RegisterPacketComponent("MANGLEDATA");

	pack_comp_radiodata = 
		globalreg->packetchain->RegisterPacketComponent("RADIODATA");

	pack_comp_gps =
		globalreg->packetchain->RegisterPacketComponent("GPS");

	pack_comp_capsrc = _PCM(PACK_COMP_KISCAPSRC) = 
		globalreg->packetchain->RegisterPacketComponent("KISCAPSRC");

	// Register the network protocols
	proto_ref_phymap =
		globalreg->kisnetserver->RegisterProtocol("PHYMAP", 0, 1,
												  KISDEV_phymap_text,
												  &Protocol_KISDEV_PHYMAP,
												  &Protocol_KISDEV_PHYMAP_enable,
												  this);

	proto_ref_commondevice =
		globalreg->kisnetserver->RegisterProtocol("DEVICE", 0, 1,
												  KISDEV_common_text,
												  &Protocol_KISDEV_COMMON,
												  &Protocol_KISDEV_COMMON_enable,
												  this);

	proto_ref_devicedone =
		globalreg->kisnetserver->RegisterProtocol("DEVICEDONE", 0, 1,
												  DEVICEDONE_text,
												  &Protocol_DEVICEDONE,
												  NULL,
												  this);

	proto_ref_trackinfo =
		globalreg->kisnetserver->RegisterProtocol("TRACKINFO", 0, 1,
												  TRACKINFO_fields_text,
												  &Protocol_KISDEV_TRACKINFO,
												  NULL,
												  this);

	proto_ref_devtag =
		globalreg->kisnetserver->RegisterProtocol("DEVTAG", 0, 1,
												  DEVTAG_fields_text,
												  &Protocol_KISDEV_DEVTAG,
												  NULL,
												  this);

	cmd_adddevtag =
		globalreg->kisnetserver->RegisterClientCommand("ADDDEVTAG", 
													   &Devicetracker_CMD_ADDDEVTAG,
													   this);

	// Common tracker, very early in the tracker chain
	globalreg->packetchain->RegisterHandler(&Devicetracker_packethook_commontracker,
											this, CHAINPOS_TRACKER, -100);

	// Strings
	globalreg->packetchain->RegisterHandler(&Devicetracker_packethook_stringcollector,
											this, CHAINPOS_LOGGING, -100);

	if (_PCM(PACK_COMP_STRINGS) != -1) {
		pack_comp_string = _PCM(PACK_COMP_STRINGS);
	} else {
		pack_comp_string = _PCM(PACK_COMP_STRINGS) =
			globalreg->packetchain->RegisterPacketComponent("string");
	}

	if (_NPM(PROTO_REF_STRING) == -1) {
		proto_ref_string = _NPM(PROTO_REF_STRING);
	} else {
		proto_ref_string = _NPM(PROTO_REF_STRING) = 
			globalreg->kisnetserver->RegisterProtocol("STRING", 0, 0,
													  STRINGS_fields_text,
													  &Protocol_KISDEV_STRING,
													  NULL, this);
	}

	// Create the global kistxt and kisxml logfiles
	new Dumpfile_Devicetracker(globalreg, "kistxt", "text");
	new Dumpfile_Devicetracker(globalreg, "kisxml", "xml");

	// Set up the persistent tag conf file
	// Build the config file
	conf_save = globalreg->timestamp.tv_sec;

	tag_conf = new ConfigFile(globalreg);
	tag_conf->ParseConfig(tag_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") + "/" + "tag.conf", "", "", 0, 1).c_str());


    // Register ourselves with the HTTP server
    globalreg->httpd_server->RegisterHandler(this);
}

Devicetracker::~Devicetracker() {
    globalreg->httpd_server->RemoveHandler(this);

	if (timerid >= 0)
		globalreg->timetracker->RemoveTimer(timerid);

	globalreg->packetchain->RemoveHandler(&Devicetracker_packethook_stringcollector,
										  CHAINPOS_LOGGING);
	globalreg->packetchain->RemoveHandler(&Devicetracker_packethook_commontracker,
										  CHAINPOS_TRACKER);

    // TODO broken for now
    /*
	if (track_filter != NULL)
		delete track_filter;
    */

    pthread_mutex_lock(&devicelist_mutex);
	for (map<int, Kis_Phy_Handler *>::iterator p = phy_handler_map.begin();
		 p != phy_handler_map.end(); ++p) {
		delete p->second;
	}

	for (unsigned int d = 0; d < tracked_vec.size(); d++) {
		delete tracked_vec[d];
	}
    pthread_mutex_unlock(&devicelist_mutex);

    pthread_mutex_destroy(&devicelist_mutex);
}

void Devicetracker::SaveTags() {
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

vector<kis_tracked_device_base *> *Devicetracker::FetchDevices(int in_phy) {
    devicelist_mutex_locker(this);

	if (in_phy == KIS_PHY_ANY)
		return &tracked_vec;

	if (phy_device_vec.find(in_phy) == phy_device_vec.end())
		return NULL;

	return phy_device_vec[in_phy];
}

Kis_Phy_Handler *Devicetracker::FetchPhyHandler(int in_phy) {
	map<int, Kis_Phy_Handler *>::iterator i = phy_handler_map.find(in_phy);

	if (i == phy_handler_map.end())
		return NULL;

	return i->second;
}

int Devicetracker::FetchNumDevices(int in_phy) {
    devicelist_mutex_locker(this);

	int r = 0;

	if (in_phy == KIS_PHY_ANY)
		return tracked_map.size();

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (tracked_vec[x]->get_phytype() == in_phy)
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
	if (in_phy == KIS_PHY_ANY)
		return num_datapackets;

	map<int, int>::iterator i = phy_datapackets.find(in_phy);
	if (i != phy_datapackets.end())
		return i->second;

	return 0;
}

int Devicetracker::FetchNumCryptpackets(int in_phy) {
	int r = 0;

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (tracked_vec[x]->get_phytype() == in_phy || in_phy == KIS_PHY_ANY) {
            r += tracked_vec[x]->get_crypt_packets();
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

string Devicetracker::FetchDeviceComponentName(int in_id) {
	if (component_id_map.find(in_id) == component_id_map.end())
		return "<UNKNOWN>";

	return component_id_map[in_id];
}

int Devicetracker::RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler) {
	int num = next_phy_id++;

	Kis_Phy_Handler *strongphy = 
		in_weak_handler->CreatePhyHandler(globalreg, this, num);

	phy_handler_map[num] = strongphy;

	phy_packets[num] = 0;
	phy_datapackets[num] = 0;
	phy_errorpackets[num] = 0;
	phy_filterpackets[num] = 0;
	phy_packetdelta[num] = 0;
	
	phy_dirty_vec[num] = new vector<kis_tracked_device_base *>;
	phy_device_vec[num] = new vector<kis_tracked_device_base *>;

	_MSG("Registered PHY handler '" + strongphy->FetchPhyName() + "' as ID " +
		 IntToString(num), MSGFLAG_INFO);

	return num;
}

// Send all devices to a client
void Devicetracker::BlitDevices(int in_fd) {
    for (unsigned int x = 0; x < tracked_vec.size(); x++) {
        kis_protocol_cache cache;
        kis_protocol_cache devcache;
        kis_protocol_cache donecache;

        kis_tracked_device_base *dev = tracked_vec[x];

        if (in_fd == -1) {
            globalreg->kisnetserver->SendToAll(proto_ref_commondevice, 
                    (void *) dev);

            /* Remove the arbtagmap for now, it will become a sub-class attachment
               map<string, kis_tag_data *>::iterator ti;

               for (ti = common->arb_tag_map.begin(); 
               ti != common->arb_tag_map.end(); ++ti) {

               if (ti->second == NULL)
               continue;

               devtag_tx dtx;
               dtx.data = ti->second;
               dtx.tag = ti->first;
               dtx.macaddr = common->device->key;
               dtx.phyid = common->device->phy_type;

               globalreg->kisnetserver->SendToAll(proto_ref_devtag, (void *) &dtx);
               }
               */

            globalreg->kisnetserver->SendToAll(proto_ref_devicedone, 
                    (void *) tracked_vec[x]);
        } else {
            globalreg->kisnetserver->SendToClient(in_fd, proto_ref_commondevice,
                    (void *) dev, &cache);

            /*
               map<string, kis_tag_data *>::iterator ti;

               for (ti = common->arb_tag_map.begin(); 
               ti != common->arb_tag_map.end(); ++ti) {
               if (ti->second == NULL)
               continue;

               devtag_tx dtx;
               dtx.data = ti->second;
               dtx.tag = ti->first;
               dtx.macaddr = common->device->key;
               dtx.phyid = common->device->phy_type;

               globalreg->kisnetserver->SendToClient(in_fd, proto_ref_devtag, 
               (void *) &dtx, &devcache);
               }
               */

            globalreg->kisnetserver->SendToClient(in_fd, proto_ref_devicedone,
                    (void *) tracked_vec[x], 
                    &donecache);
        }
    } 
}

void Devicetracker::BlitPhy(int in_fd) {
	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {

		kis_protocol_cache cache;
		kis_proto_phymap_info info;

		info.phyid = x->first;
		info.phyname = x->second->FetchPhyName();

		info.packets = FetchNumPackets(x->first);
		info.datapackets = FetchNumDatapackets(x->first);
		info.errorpackets = FetchNumErrorpackets(x->first);
		info.filterpackets = FetchNumFilterpackets(x->first);
		info.packetrate = FetchPacketRate(x->first);

		if (in_fd == -1)
			globalreg->kisnetserver->SendToAll(proto_ref_phymap, (void *) &info);
		else
			globalreg->kisnetserver->SendToClient(in_fd, proto_ref_phymap,
												  (void *) &info, &cache);
	}
}

namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

EntryTracker *entrytracker;

template<>
    struct pack<mac_addr> {
        template <typename Stream>
            packer<Stream>& operator()(msgpack::packer<Stream>& o, 
                    mac_addr const& v) const {
                o.pack_array(2);
                o.pack(v.longmac);
                o.pack(v.longmask);
                return o;
            }
    };

template<>
    struct pack<TrackerElement *> {
        template <typename Stream>
            packer<Stream>& operator()(msgpack::packer<Stream>& o, 
                    TrackerElement * const& v) const {

                o.pack_array(2);

                o.pack((int) v->get_type());

                TrackerElement::tracked_map *tmap;
                TrackerElement::map_iterator map_iter;

                TrackerElement::tracked_mac_map *tmacmap;
                TrackerElement::mac_map_iterator mac_map_iter;

                switch (v->get_type()) {
                    case TrackerString:
                        o.pack(GetTrackerValue<string>(v));
                        break;
                    case TrackerInt8:
                        o.pack(GetTrackerValue<int8_t>(v));
                        break;
                    case TrackerUInt8:
                        o.pack(GetTrackerValue<uint8_t>(v));
                        break;
                    case TrackerInt16:
                        o.pack(GetTrackerValue<int16_t>(v));
                        break;
                    case TrackerUInt16:
                        o.pack(GetTrackerValue<uint16_t>(v));
                        break;
                    case TrackerInt32:
                        o.pack(GetTrackerValue<int32_t>(v));
                        break;
                    case TrackerUInt32:
                        o.pack(GetTrackerValue<uint32_t>(v));
                        break;
                    case TrackerInt64:
                        o.pack(GetTrackerValue<int64_t>(v));
                        break;
                    case TrackerUInt64:
                        o.pack(GetTrackerValue<uint64_t>(v));
                        break;
                    case TrackerFloat:
                        o.pack(GetTrackerValue<float>(v));
                        break;
                    case TrackerDouble:
                        o.pack(GetTrackerValue<double>(v));
                        break;
                    case TrackerMac:
                        o.pack(GetTrackerValue<mac_addr>(v));
                        break;
                    case TrackerUuid:
                        o.pack(GetTrackerValue<uuid>(v).UUID2String());
                        break;
                    case TrackerVector:
                        o.pack(*(v->get_vector()));
                        break;
                    case TrackerMap:
                        tmap = v->get_map();
                        o.pack_map(tmap->size());
                        for (map_iter = tmap->begin(); map_iter != tmap->end(); 
                                ++map_iter) {
                            o.pack(entrytracker->GetFieldName(map_iter->first));
                            o.pack(map_iter->second);

                        }
                        break;
                    case TrackerIntMap:
                        tmap = v->get_intmap();
                        o.pack_map(tmap->size());
                        for (map_iter = tmap->begin(); map_iter != tmap->end(); 
                                ++map_iter) {
                            o.pack(map_iter->first);
                            o.pack(map_iter->second);

                        }
                        break;
                    case TrackerMacMap:
                        tmacmap = v->get_macmap();
                        o.pack_map(tmacmap->size());
                        for (mac_map_iter = tmacmap->begin(); 
                                mac_map_iter != tmacmap->end();
                                ++mac_map_iter) {
                            o.pack(mac_map_iter->first);
                            o.pack(mac_map_iter->second);
                        }

                    default:
                        break;
                }

                return o;
            }
    };

}
}
}

int Devicetracker::TimerKick() {
	BlitPhy(-1);
	// BlitDevices(-1);

	globalreg->kisnetserver->SendToAll(proto_ref_trackinfo, (void *) this);

	// Reset the packet rates per phy
	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		phy_packetdelta[x->first] = 0;
	}

	// Send all the dirty common data
	for (unsigned int x = 0; x < dirty_device_vec.size(); x++) {
		kis_tracked_device_base *dev = dirty_device_vec[x];

        // Reset packet delta
        dev->set_new_packets(0);

        map<string, kis_tag_data *>::iterator ti;

        // No longer dirty
        dev->set_dirty(false);
    }

	// Send all the phy-specific dirty stuff
	for (map<int, vector<kis_tracked_device_base *> *>::iterator x = phy_dirty_vec.begin();
		 x != phy_dirty_vec.end(); ++x) {
		// phy_handler_map[x->first]->BlitDevices(-1, x->second);
		x->second->clear();
	}

	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin(); 
		 x != phy_handler_map.end(); ++x) {
		x->second->TimerKick();
	}

    // Set the msgpack entry tracker manually for now
    msgpack::adaptor::entrytracker = globalreg->entrytracker;

	for (unsigned int x = 0; x < dirty_device_vec.size(); x++) {
		globalreg->kisnetserver->SendToAll(proto_ref_devicedone, 
										   (void *) dirty_device_vec[x]);

        string fname = "/tmp/kismet/" + dirty_device_vec[x]->get_key().Mac2String();

        printf("debug - attempting to serialize to %s\n", fname.c_str());

        std::stringstream buffer;
        msgpack::pack(buffer, (TrackerElement *) dirty_device_vec[x]);

        FILE *f = fopen(fname.c_str(), "wb");

        fwrite(buffer.str().c_str(), buffer.str().length(), 1, f);
        fflush(f);
        fclose(f);
	}

	dirty_device_vec.clear();

    for (unsigned int x = 0; x < tracked_vec.size(); x++) {
    }

	// Reset the packet rate delta
	num_packetdelta = 0;

	return 1;
}

kis_tracked_device_base *Devicetracker::FetchDevice(mac_addr in_device) {
    devicelist_mutex_locker(this);

	device_itr i = tracked_map.find(in_device);

	if (i != tracked_map.end())
		return i->second;

	return NULL;
}

kis_tracked_device_base *Devicetracker::FetchDevice(mac_addr in_device, 
        unsigned int in_phy) {
	in_device.SetPhy(in_phy);
	return FetchDevice(in_device);
}

int Devicetracker::StringCollector(kis_packet *in_pack) {
	kis_tracked_device_info *devinfo = 
		(kis_tracked_device_info *) in_pack->fetch(_PCM(PACK_COMP_DEVICE));
	kis_common_info *common = 
		(kis_common_info *) in_pack->fetch(pack_comp_common);
	kis_string_info *strings =
		(kis_string_info *) in_pack->fetch(_PCM(PACK_COMP_STRINGS));

	if (devinfo == NULL || strings == NULL || common == NULL)
		return 0;

	kis_proto_string_info si;

	si.device = devinfo->devref->get_key();
	si.phy = devinfo->devref->get_phytype();
	si.source = common->source;
	si.dest = common->dest;

	for (unsigned int x = 0; x < strings->extracted_strings.size(); x++) {
		si.stringdata = strings->extracted_strings[x];
	
		globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_STRING), (void *) &si);
	}

	return 1;
}

int Devicetracker::CommonTracker(kis_packet *in_pack) {
	kis_common_info *pack_common = 
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	kis_ref_capsource *pack_capsrc =
		(kis_ref_capsource *) in_pack->fetch(pack_comp_capsrc);

	num_packets++;
	num_packetdelta++;

	if (in_pack->error && pack_capsrc != NULL)  {
		pack_capsrc->ref_source->AddErrorPacketCount();
		return 0;
	}

	// If we can't figure it out at all (no common layer) just bail
	if (pack_common == NULL)
		return 0;

	if (pack_common->error) {
		if (pack_capsrc != NULL)  {
			pack_capsrc->ref_source->AddErrorPacketCount();
		}

		// If we couldn't get any common data consider it an error
		// and bail
		num_errorpackets++;

		if (phy_handler_map.find(pack_common->phyid) != phy_handler_map.end()) {
			phy_errorpackets[pack_common->phyid]++;
		}

		return 0;
	}

	if (in_pack->filtered) {
		num_filterpackets++;
	}

	// Make sure our PHY is sane
	if (phy_handler_map.find(pack_common->phyid) == phy_handler_map.end()) {
		_MSG("Invalid phy id " + IntToString(pack_common->phyid) + " in packet "
			 "something is wrong.", MSGFLAG_ERROR);
		return 0;
	}

	phy_packets[pack_common->phyid]++;
	phy_packetdelta[pack_common->phyid]++;

	if (in_pack->error || pack_common->error) {
		phy_errorpackets[pack_common->phyid]++;
	}

	if (in_pack->filtered) {
		phy_filterpackets[pack_common->phyid]++;
		num_filterpackets++;
	} else {
		if (pack_common->type == packet_basic_data) {
			num_datapackets++;
			phy_datapackets[pack_common->phyid]++;
		} 
	}

	// If we dont' have a device mac, don't make a record
	if (pack_common->device == 0)
		return 0;

	mac_addr devmac = pack_common->device;

	// If we don't have a usable mac, bail.
	// TODO maybe change this in the future?  It's kind of phy dependent
	if (devmac == globalreg->empty_mac)
		return 0;

	devmac.SetPhy(pack_common->phyid);

	kis_tracked_device_base *device = NULL;

	// Make a new device or fetch an existing one
	device = BuildDevice(devmac, in_pack);

	if (device == NULL)
		return 0;

	// Push our common data into it
	PopulateCommon(device, in_pack);

	return 1;
}

// Find a device, creating the device as needed and populating common data
kis_tracked_device_base *Devicetracker::MapToDevice(mac_addr in_device, 
        kis_packet *in_pack) {

	kis_tracked_device_base *device = NULL;
	kis_common_info *pack_common = 
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	// If we can't figure it out at all (no common layer) just bail
	if (pack_common == NULL)
		return NULL;

	mac_addr devmac = in_device;
	devmac.SetPhy(pack_common->phyid);

	if ((device = FetchDevice(devmac)) == NULL) {
		device = BuildDevice(devmac, in_pack);
		
		if (device == NULL)
			return NULL;

		PopulateCommon(device, in_pack);
	} 

	return device;
}

// Find a device, creating the device as needed and populating common data
kis_tracked_device_base *Devicetracker::BuildDevice(mac_addr in_device, 
        kis_packet *in_pack) {

	kis_common_info *pack_common = 
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	// If we can't figure it out at all (no common layer) just bail
	if (pack_common == NULL)
		return NULL;

	if (in_pack->error || pack_common->error) {
		return NULL;
	}

	// If we dont' have a device mac, don't make a record
	if (pack_common->device == 0)
		return NULL;

	kis_tracked_device_base *device = NULL;

	mac_addr devmac = in_device;
	devmac.SetPhy(pack_common->phyid);

	device = FetchDevice(devmac);

	if (device == NULL) {
		fprintf(stderr, "debug - devicetracker building device for %s\n", devmac.Mac2String().c_str());

		// we don't have this device tracked.  Make one based on the
		// input data (for example, this could be a bssid which has never
		// talked, but which we see a client communicating with)
        device = 
            (kis_tracked_device_base *) globalreg->entrytracker->GetTrackedInstance(device_base_id);

		device->set_key(devmac);

        device->set_macaddr(devmac);

		device->set_phytype(pack_common->phyid);

        // New devices always marked dirty
        device->set_dirty(true);

		// Defer tag loading to when we populate the common record

        printf("debug - inserting device %s into map\n", device->get_key().Mac2String().c_str());

        devicelist_mutex_locker(this);

		tracked_map[device->get_key()] = device;
		tracked_vec.push_back(device);
		phy_device_vec[pack_common->phyid]->push_back(device);

		// mark it dirty
        dirty_device_vec.push_back(device);
        phy_dirty_vec[pack_common->phyid]->push_back(device);
	}

	return device;
}

int Devicetracker::PopulateCommon(kis_tracked_device_base *device, kis_packet *in_pack) {
	kis_common_info *pack_common = 
		(kis_common_info *) in_pack->fetch(pack_comp_common);
	kis_layer1_packinfo *pack_l1info = 
		(kis_layer1_packinfo *) in_pack->fetch(pack_comp_radiodata);
	kis_gps_packinfo *pack_gpsinfo =
		(kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);
	kis_ref_capsource *pack_capsrc =
		(kis_ref_capsource *) in_pack->fetch(pack_comp_capsrc);

    tracker_component_locker((tracker_component *) device);

	// If we can't figure it out at all (no common layer) just bail
	if (pack_common == NULL)
		return 0;

	// We shouldn't have ever been able to get this far w/out having a phy
	// handler since we wouldn't know the phy id
	Kis_Phy_Handler *handler = FetchPhyHandler(pack_common->phyid);
	if (handler == NULL) {
		_MSG("DeviceTracker failed to populate common because we couldn't find "
			 "a matching phy handler", MSGFLAG_ERROR);
		return 0;
	}

	// Mark it dirty
	if (!device->get_dirty()) {
		device->set_dirty(true);
		dirty_device_vec.push_back(device);
		phy_dirty_vec[pack_common->phyid]->push_back(device);
	}

    device->set_first_time(in_pack->ts.tv_sec);

    if (globalreg->manufdb != NULL) 
        device->set_manuf(globalreg->manufdb->LookupOUI(device->get_macaddr()));

    // Set name
    device->set_name(device->get_macaddr().Mac2String());

    /* Persistent tag loading removed, will be handled by serializing network in the future */

    device->inc_packets();
    device->inc_new_packets();

    device->set_last_time(in_pack->ts.tv_sec);

	if (pack_common->error)
        device->inc_error_packets();

	if (pack_common->type == packet_basic_data) {
        // TODO fix directional data
        device->inc_data_packets();
        device->add_datasize_rx(pack_common->datasize);
	} else if (pack_common->type == packet_basic_mgmt ||
			   pack_common->type == packet_basic_phy) {
        device->inc_llc_packets();
	}

	if (pack_l1info != NULL) {
		if (pack_l1info->channel != 0)
            device->set_channel(pack_l1info->channel);
		if (pack_l1info->freq_mhz != 0)
            device->set_frequency(pack_l1info->freq_mhz);

		Packinfo_Sig_Combo *sc = new Packinfo_Sig_Combo(pack_l1info, pack_gpsinfo);
        (*(device->get_signal_data())) += *sc;

		delete(sc);

        device->inc_frequency_count((int) pack_l1info->freq_mhz);
	}

    if (pack_gpsinfo != NULL) {
        device->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->gps_fix);
    }

	// Update seenby records for time, frequency, packets
	if (pack_capsrc != NULL) {
        int f = -1;

        if (pack_l1info != NULL)
            f = pack_l1info->freq_mhz;

        device->inc_seenby_count(pack_capsrc->ref_source, in_pack->ts.tv_sec, f);
	}

    device->add_basic_crypt(pack_common->basic_crypt_set);

	if (pack_common->channel)
        device->set_channel(pack_common->channel);

	kis_tracked_device_info *devinfo = 
		(kis_tracked_device_info *) in_pack->fetch(pack_comp_device);

	if (devinfo == NULL) {
		devinfo = new kis_tracked_device_info;
		devinfo->devref = device;
		in_pack->insert(pack_comp_device, devinfo);
	}

	return 1;
}

void Devicetracker::WriteXML(FILE *in_logfile) {
	Packetsourcetracker *pst = 
		(Packetsourcetracker *) globalreg->FetchGlobal("PACKETSOURCE_TRACKER");

	// Punt and die, better than segv
	if (pst == NULL) {
		_MSG("Devicetracker XML log - packetsourcetracker vanished!", MSGFLAG_ERROR);
		return;
	}

	GpsWrapper *gpsw = 
		(GpsWrapper *) globalreg->FetchGlobal("GPSWRAPPER");

	if (gpsw == NULL) {
		_MSG("Devicetracker XML log - gpswrapper vanished!", MSGFLAG_ERROR);
		return;
	}

	fprintf(in_logfile, "<?xml version=\"1.0\"?>\n");

	fprintf(in_logfile, 
			"<k:run xmlns:k=\"http://www.kismetwireless.net/xml\"\n"
			"xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"\n"
			"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
			"xsi:schemaLocation=\"http://www.kismetwireless.net/xml kismet.xsd\"\n");

	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		fprintf(in_logfile, 
				"\nxmlns:%s=\"http://www.kismetwireless.net/xml/%s\"",
				x->second->FetchPhyXsdNs().c_str(),
				x->second->FetchPhyXsdNs().c_str());
	}
	fprintf(in_logfile, ">\n\n");

	// write the schema into the run element
	fprintf(in_logfile, "<xs:schema\n" 
			"xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"\n"
			"xmlns=\"http://xmlns.myexample.com/version3\"\n"
			"targetNamespace=\"http://www.kismetwireless.net/xml\"\n"
			"xmlns:common=\"http://www.kismetwireless.net/xml/common\"\n"
			"xmlns:device=\"http://www.kismetwireless.net/xml/device\"\n"
			"xmlns:gps=\"http://www.kismetwireless.net/xml/gps\"\n"
			"xmlns:run=\"http://www.kismetwireless.net/xml/run\"\n");

	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		fprintf(in_logfile, "xmlns:%s=\"http://www.kismetwireless.net/xml/%s\"\n",
				x->second->FetchPhyXsdNs().c_str(),
				x->second->FetchPhyXsdNs().c_str());
	}

	fprintf(in_logfile, "elementFormDefault=\"unqualified\"\n"
			"attributeFromDefault=\"unqualified\">\n");

	fprintf(in_logfile, 
			"<xs:import namespace=\"http://www.kismetwireless.net/xml/common\" "
			"schemaLocation=\"http://www.kismetwireless.net/xml/common.xsd\"/>\n"
			"<xs:import namespace=\"http://www.kismetwireless.net/xml/device\" "
			"schemaLocation=\"http://www.kismetwireless.net/xml/device.xsd\"/>\n"
			"<xs:import namespace=\"http://www.kismetwireless.net/xml/gps\" "
			"schemaLocation=\"http://www.kismetwireless.net/xml/gps.xsd\"/>\n"
			"<xs:import namespace=\"http://www.kismetwireless.net/xml/run\" "
			"schemaLocation=\"http://www.kismetwireless.net/xml/run.xsd\"/>\n");

	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		fprintf(in_logfile, 
				"<xs:import namespace=\"http://www.kismetwireless.net/xml/%s\" "
				"schemaLocation=\"%s\"/>\n",
				x->second->FetchPhyXsdNs().c_str(),
				x->second->FetchPhyXsdUrl().c_str());
	}

	fprintf(in_logfile,
			"<xs:element name=\"run\"/>\n"
			"</xs:schema>\n");
	

	fprintf(in_logfile, 
			"<version>%s-%s-%s</version>\n",
			globalreg->version_major.c_str(),
			globalreg->version_minor.c_str(),
			globalreg->version_tiny.c_str());

	fprintf(in_logfile,
			"<server>%s</server>\n",
			SanitizeXML(globalreg->servername).c_str());
	
	fprintf(in_logfile,
			"<logname>%s</logname>\n",
			SanitizeXML(globalreg->logname).c_str());

	fprintf(in_logfile, 
			"<startTime>%.24s</startTime>\n",
			ctime(&(globalreg->start_time)));
	fprintf(in_logfile,
			"<endTime>%.24s</endTime>\n",
			ctime(&(globalreg->timestamp.tv_sec)));

	vector<pst_packetsource *> *pstv = pst->FetchSourceVec();

	fprintf(in_logfile, "<captureSources>\n");
	for (unsigned int x = 0; x < pstv->size(); x++) {
		pst_packetsource *ps = (*pstv)[x];

		if (ps == NULL)
			continue;

		if (ps->strong_source == NULL || ps->proto_source == NULL)
			continue;

		fprintf(in_logfile,
				"<captureSource>\n"
				"<uuid>%s</uuid>\n"
				"<definition>%s</definition>\n"
				"<name>%s</name>\n"
				"<interface>%s</interface>\n"
				"<type>%s</type>\n"
				"<packets>%u</packets>\n"
				"<errorPackets>%u</errorPackets>\n",

				ps->strong_source->FetchUUID().UUID2String().c_str(),
				ps->sourceline.c_str(),
				ps->strong_source->FetchName().c_str(),
				ps->strong_source->FetchInterface().c_str(),
				ps->strong_source->FetchType().c_str(),
				ps->strong_source->FetchNumPackets(),
				ps->strong_source->FetchNumErrorPackets());

		// TODO rewrite this for phy-specific channel handling
		string channels;
		if (ps->channel_ptr != NULL) {
			for (unsigned int c = 0; c < ps->channel_ptr->channel_vec.size(); c++) {
				if (ps->channel_ptr->channel_vec[c].range == 0) {
					channels += IntToString(ps->channel_ptr->channel_vec[c].u.chan_t.channel);
					if (ps->channel_ptr->channel_vec[c].u.chan_t.dwell > 1)
						channels += string(":") +
							IntToString(ps->channel_ptr->channel_vec[c].u.chan_t.dwell);
				} else {
					channels += string("range-") + IntToString(ps->channel_ptr->channel_vec[c].u.range_t.start) + string("-") + IntToString(ps->channel_ptr->channel_vec[c].u.range_t.end) + string("-") + IntToString(ps->channel_ptr->channel_vec[c].u.range_t.width) + string("-") + IntToString(ps->channel_ptr->channel_vec[c].u.range_t.iter);
				}

				if (c != ps->channel_ptr->channel_vec.size() - 1)
					channels += ",";
			}
		} else {
			channels = IntToString(ps->strong_source->FetchChannel());
		}

		fprintf(in_logfile, "<channels>%s</channels>\n", channels.c_str());

		fprintf(in_logfile, "<channelhop>%s</channelhop>\n",
				(ps->channel_dwell || ps->channel_hop) ? "true" : "false");

		fprintf(in_logfile, "</captureSource>\n");
	}
	fprintf(in_logfile, "</captureSources>\n");

	fprintf(in_logfile, "<totalDevices>%u</totalDevices>\n",
			FetchNumDevices(KIS_PHY_ANY));

	fprintf(in_logfile, "<phyTypes>\n");

	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		fprintf(in_logfile, 
				"<phyType>\n"
				"<name>%s</name>\n"
				"<devices>%u</devices>\n"
				"<packets>%u</packets>\n"
				"<packetData>%u</packetData>\n"
				"<packetFiltered>%u</packetFiltered>\n"
				"<packetError>%u</packetError>\n"
				"</phyType>\n",
				SanitizeXML(x->second->FetchPhyName()).c_str(),
				FetchNumDevices(x->first),
				FetchNumPackets(x->first),
				FetchNumDatapackets(x->first),
				FetchNumFilterpackets(x->first),
				FetchNumErrorpackets(x->first));
	}
	fprintf(in_logfile, "</phyTypes>\n");

	fprintf(in_logfile, 
			"<gpsDevices>\n"
			"<gpsDevice>\n"
			"<device>%s</device>\n"
			"<type>%s</type>\n"
			"</gpsDevice>\n"
			"</gpsDevices>\n",
			SanitizeXML(gpsw->FetchDevice()).c_str(),
			SanitizeXML(gpsw->FetchType()).c_str());

	vector<kis_tracked_device_base *> *devlist = FetchDevices(KIS_PHY_ANY);

	if (devlist->size() > 0)
		fprintf(in_logfile, "<devices>\n");

	for (unsigned int x = 0; x < devlist->size(); x++) {
		kis_tracked_device_base *dev = (*devlist)[x];
		Kis_Phy_Handler *phy = FetchPhyHandler(dev->get_phytype());

		if (dev->get_phytype() == KIS_PHY_UNKNOWN || phy == NULL) 
			fprintf(in_logfile, "<device phy=\"unknown\">\n");
		else
			fprintf(in_logfile, 
					"<device xsi:type=\"%s:%sdevice\" phy=\"%s\">\n",
					phy->FetchPhyXsdNs().c_str(), phy->FetchPhyXsdNs().c_str(),
					phy->FetchPhyXsdNs().c_str());

		fprintf(in_logfile, 
				"<deviceMac>%s</deviceMac>\n",
				dev->get_mac().Mac2String().c_str());

		if (dev->get_name() != "")
			fprintf(in_logfile, 
					"<name>%s</name>\n",
					SanitizeXML(dev->get_name()).c_str());

		if (dev->get_type_string() != "")
			fprintf(in_logfile, "<classifiedType>%s</classifiedType>\n",
					SanitizeXML(dev->get_type_string()).c_str());

		fprintf(in_logfile, "<commonTypes>\n");
		if ((dev->get_basic_type_set() & KIS_DEVICE_BASICTYPE_AP))
			fprintf(in_logfile, "<commonType>ap</commonType>\n");
		if ((dev->get_basic_type_set() & KIS_DEVICE_BASICTYPE_CLIENT))
			fprintf(in_logfile, "<commonType>client</commonType>\n");
		if ((dev->get_basic_type_set() & KIS_DEVICE_BASICTYPE_WIRED))
			fprintf(in_logfile, "<commonType>wired</commonType>\n");
		if ((dev->get_basic_type_set() & KIS_DEVICE_BASICTYPE_PEER))
			fprintf(in_logfile, "<commonType>peer</commonType>\n");
		fprintf(in_logfile, "</commonTypes>\n");

		fprintf(in_logfile, "<commonCryptTypes>\n");
		// Empty or only generic encryption known
		if (dev->get_basic_crypt_set() == KIS_DEVICE_BASICCRYPT_NONE)
			fprintf(in_logfile, "<commonCrypt>none</commonCrypt>\n");
		if ((dev->get_basic_crypt_set() == KIS_DEVICE_BASICCRYPT_ENCRYPTED))
			fprintf(in_logfile, "<commonCrypt>encrypted</commonCrypt>\n");
		// Deeper detection of l2/l3
		if ((dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L2))
			fprintf(in_logfile, "<commonCrypt>L2 encrypted</commonCrypt>\n");
		if ((dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L2))
			fprintf(in_logfile, "<commonCrypt>L3 encrypted</commonCrypt>\n");
		fprintf(in_logfile, "</commonCryptTypes>\n");

        time_t t = dev->get_first_time();
		fprintf(in_logfile, 
				"<firstSeen>%.24s</firstSeen>\n",
				ctime(&t));
        t = dev->get_last_time();
		fprintf(in_logfile,
				"<lastSeen>%.24s</lastSeen>\n",
				ctime(&t));

        TrackerElement *seenby_map = dev->get_seenby_map();

        if (seenby_map->size() > 0) 
			fprintf(in_logfile, "<seenBySources>\n");

        for (TrackerElement::map_const_iterator si = seenby_map->begin();
                si != seenby_map->end(); ++si) {
            kis_tracked_seenby_data *sbd = (kis_tracked_seenby_data *) si->second;

            time_t st;

			fprintf(in_logfile, 
					"<seenBySource>\n"
					"<uuid>%s</uuid>\n",
					sbd->get_uuid().UUID2String().c_str());
            
            st = sbd->get_first_time();
			fprintf(in_logfile, "<firstSeen>%.24s</firstSeen>\n",
					ctime(&st));

            st = sbd->get_last_time();
			fprintf(in_logfile, "<lastSeen>%.24s</lastSeen>\n",
					ctime(&st));

			fprintf(in_logfile, "<packets>%lu</packets>\n",
                    sbd->get_num_packets());

            TrackerElement *fe = sbd->get_freq_mhz_map();

            if (fe->size() > 0) {
				fprintf(in_logfile, "<frequencySeen>\n");

                for (TrackerElement::map_const_iterator fi = fe->begin();
                        fi != fe->end(); ++fi) {
					fprintf(in_logfile, "<frequency mhz=\"%u\" packets=\"%lu\"/>\n",
							fi->first, GetTrackerValue<uint64_t>(fi->second));
                }

				fprintf(in_logfile, "</frequencySeen>\n");
			}

			fprintf(in_logfile, "</seenBySource>\n");
		}

        if (seenby_map->size() > 0) 
			fprintf(in_logfile, "</seenBySources>\n");

        kis_tracked_location *location = dev->get_location();
        kis_tracked_signal_data *snrdata = dev->get_signal_data();

        if (location->get_valid()) {
			fprintf(in_logfile, 
					"<gpsAverage>\n"
					"<latitude>%f</latitude>\n"
					"<longitude>%f</longitude>\n"
					"<altitude>%f</altitude>\n"
					"</gpsAverage>\n",
                    location->get_avg_loc()->get_lat(),
                    location->get_avg_loc()->get_lon(),
                    location->get_avg_loc()->get_alt());

			fprintf(in_logfile,
					"<gpsMinimum>\n"
					"<latitude>%f</latitude>\n"
					"<longitude>%f</longitude>\n"
                    "<altitude>%f</altitude>\n",
                    location->get_min_loc()->get_lat(),
                    location->get_min_loc()->get_lon(),
                    location->get_min_loc()->get_alt());
			fprintf(in_logfile, "</gpsMinimum>\n");

			fprintf(in_logfile,
					"<gpsMaximum>\n"
					"<latitude>%f</latitude>\n"
					"<longitude>%f</longitude>\n"
                    "<altitude>%f</altitude>\n",
                    location->get_max_loc()->get_lat(),
                    location->get_max_loc()->get_lon(),
                    location->get_max_loc()->get_alt());
			fprintf(in_logfile, "</gpsMaximum>\n");

            kis_tracked_location_triplet *peak_location = snrdata->get_peak_loc();

            if (peak_location->get_valid()) {
                fprintf(in_logfile,
                        "<gpsPeaksignal>\n"
                        "<latitude>%f</latitude>\n"
                        "<longitude>%f</longitude>\n"
                        "<altitude>%f</altitude>\n",
                        peak_location->get_lat(),
                        peak_location->get_lon(),
                        peak_location->get_alt());
                fprintf(in_logfile, "</gpsPeaksignal>\n");
            }
		}

        if (snrdata->get_last_signal_dbm() != 0) {
			// Smells like DBM signalling
			fprintf(in_logfile, "<signalLevel type=\"dbm\">\n");

			fprintf(in_logfile, "<lastSignal>%d</lastSignal>\n",
					snrdata->get_last_signal_dbm());

            if (snrdata->get_last_noise_dbm() != 0) 
				fprintf(in_logfile, "<lastNoise>%d</lastNoise>\n",
						snrdata->get_last_noise_dbm());

			fprintf(in_logfile, "<minSignal>%d</minSignal>\n",
					snrdata->get_min_signal_dbm());

            if (snrdata->get_min_noise_dbm() != 0) 
				fprintf(in_logfile, "<minNoise>%d</minNoise>\n",
						snrdata->get_min_noise_dbm());

			fprintf(in_logfile, "<maxSignal>%d</maxSignal>\n",
					snrdata->get_max_signal_dbm());

            if (snrdata->get_max_noise_dbm() != 0) 
				fprintf(in_logfile, "<maxNoise>%d</maxNoise>\n",
						snrdata->get_max_noise_dbm());
			
			fprintf(in_logfile, "</signalLevel>\n");
		} else if (snrdata->get_last_signal_rssi() != 0) {
			// Smells like RSSI
			fprintf(in_logfile, "<signalLevel type=\"rssi\">\n");

			fprintf(in_logfile, "<lastSignal>%d</lastSignal>\n",
					snrdata->get_last_signal_rssi());

			if (snrdata->get_last_noise_rssi() != 0)
				fprintf(in_logfile, "<lastNoise>%d</lastNoise>\n",
						snrdata->get_last_noise_rssi());

			fprintf(in_logfile, "<minSignal>%d</minSignal>\n",
					snrdata->get_min_signal_rssi());

			if (snrdata->get_min_noise_rssi() != 0)
				fprintf(in_logfile, "<minNoise>%d</minNoise>\n",
						snrdata->get_min_noise_rssi());

			fprintf(in_logfile, "<maxSignal>%d</maxSignal>\n",
					snrdata->get_max_signal_rssi());

			if (snrdata->get_max_noise_rssi() != 0)
				fprintf(in_logfile, "<maxNoise>%d</maxNoise>\n",
						snrdata->get_max_noise_rssi());
			
			fprintf(in_logfile, "</signalLevel>\n");
		}

		fprintf(in_logfile, 
				"<packets>%lu</packets>\n"
				"<packetLink>%lu</packetLink>\n"
				"<packetData>%lu</packetData>\n"
				"<packetFiltered>%lu</packetFiltered>\n"
				"<packetError>%lu</packetError>\n"
				"<dataBytes>%lu</dataBytes>\n",
                dev->get_packets(), dev->get_llc_packets(), dev->get_data_packets(),
                dev->get_filter_packets(), dev->get_error_packets(), 
                dev->get_datasize_rx() + dev->get_datasize_tx());

		if (dev->get_manuf() != "")
			fprintf(in_logfile, "<manufacturer>%s</manufacturer>\n",
					SanitizeXML(dev->get_manuf()).c_str());

        if (dev->get_tag() != "") {
            fprintf(in_logfile, "<tags><tag name=\"tag\">%s</tag></tags>",
                    SanitizeXML(dev->get_tag()).c_str());
        }

		// Call all the phy handlers for logging
		for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
			 x != phy_handler_map.end(); ++x) {
			x->second->ExportLogRecord(dev, "xml", in_logfile, 0);
		}

		fprintf(in_logfile, "</device>\n");

	}

	if (devlist->size() > 0)
		fprintf(in_logfile, "</devices>\n");

	fprintf(in_logfile, "</k:run>\n");
}

void Devicetracker::WriteTXT(FILE *in_logfile) {
	Packetsourcetracker *pst = 
		(Packetsourcetracker *) globalreg->FetchGlobal("PACKETSOURCE_TRACKER");

	// Punt and die, better than segv
	if (pst == NULL) {
		_MSG("Devicetracker TXT log - packetsourcetracker vanished!", MSGFLAG_ERROR);
		return;
	}

	GpsWrapper *gpsw = 
		(GpsWrapper *) globalreg->FetchGlobal("GPSWRAPPER");

	if (gpsw == NULL) {
		_MSG("Devicetracker TXT log - gpswrapper vanished!", MSGFLAG_ERROR);
		return;
	}

	fprintf(in_logfile, "Version: %s-%s-%s\n",
			globalreg->version_major.c_str(),
			globalreg->version_minor.c_str(),
			globalreg->version_tiny.c_str());
	fprintf(in_logfile, "\n");

	fprintf(in_logfile, "Server: %s\n",
			globalreg->servername.c_str());
	fprintf(in_logfile, "\n");

	fprintf(in_logfile, "Log name: %s\n",
			globalreg->logname.c_str());
	fprintf(in_logfile, "\n");

	fprintf(in_logfile, "Start time: %.24s\n",
			ctime(&(globalreg->start_time)));
	fprintf(in_logfile, "End time: %.24s\n",
			ctime(&(globalreg->timestamp.tv_sec)));
	fprintf(in_logfile, "\n");

	vector<pst_packetsource *> *pstv = pst->FetchSourceVec();

	fprintf(in_logfile, "Capture sources:\n");
	for (unsigned int x = 0; x < pstv->size(); x++) {
		pst_packetsource *ps = (*pstv)[x];

		if (ps == NULL)
			continue;

		if (ps->strong_source == NULL || ps->proto_source == NULL)
			continue;

		fprintf(in_logfile,
				" UUID: %s\n"
				" Definition: %s\n"
				" Name: %s\n"
				" Interface: %s\n"
				" Type: %s\n"
				" Packets: %u\n"
				" Error packets: %u\n",

				ps->strong_source->FetchUUID().UUID2String().c_str(),
				ps->sourceline.c_str(),
				ps->strong_source->FetchName().c_str(),
				ps->strong_source->FetchInterface().c_str(),
				ps->strong_source->FetchType().c_str(),
				ps->strong_source->FetchNumPackets(),
				ps->strong_source->FetchNumErrorPackets());

		// TODO rewrite this for phy-specific channel handling
		string channels;
		if (ps->channel_ptr != NULL) {
			for (unsigned int c = 0; c < ps->channel_ptr->channel_vec.size(); c++) {
				if (ps->channel_ptr->channel_vec[c].range == 0) {
					channels += IntToString(ps->channel_ptr->channel_vec[c].u.chan_t.channel);
					if (ps->channel_ptr->channel_vec[c].u.chan_t.dwell > 1)
						channels += string(":") +
							IntToString(ps->channel_ptr->channel_vec[c].u.chan_t.dwell);
				} else {
					channels += string("range-") + IntToString(ps->channel_ptr->channel_vec[c].u.range_t.start) + string("-") + IntToString(ps->channel_ptr->channel_vec[c].u.range_t.end) + string("-") + IntToString(ps->channel_ptr->channel_vec[c].u.range_t.width) + string("-") + IntToString(ps->channel_ptr->channel_vec[c].u.range_t.iter);
				}

				if (c != ps->channel_ptr->channel_vec.size() - 1)
					channels += ",";
			}
		} else {
			channels = IntToString(ps->strong_source->FetchChannel());
		}

		fprintf(in_logfile, " Channels: %s\n", channels.c_str());

		fprintf(in_logfile, " Channel hopping: %s\n",
				(ps->channel_dwell || ps->channel_hop) ? "true" : "false");

		fprintf(in_logfile, "\n");
	}

	fprintf(in_logfile, "Total devices: %u\n", FetchNumDevices(KIS_PHY_ANY));
	fprintf(in_logfile, "\n");

	fprintf(in_logfile, "Phy types:\n");

	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		fprintf(in_logfile, 
				" Phy name: %s\n"
				" Devices: %u\n"
				" Packets: %u\n"
				" Data packets: %u\n"
				" Filtered packets: %u\n"
				" Error packets: %u\n\n",
				x->second->FetchPhyName().c_str(),
				FetchNumDevices(x->first),
				FetchNumPackets(x->first),
				FetchNumDatapackets(x->first),
				FetchNumFilterpackets(x->first),
				FetchNumErrorpackets(x->first));
	}

	if (gpsw != NULL) {
		fprintf(in_logfile, "GPS device: %s\n",
				gpsw->FetchDevice().c_str());
		fprintf(in_logfile, "GPS type: %s\n",
				gpsw->FetchType().c_str());
	} else {
		fprintf(in_logfile, "GPS device: None\n");
	}
	fprintf(in_logfile, "\n");
	
	vector<kis_tracked_device_base *> *devlist = FetchDevices(KIS_PHY_ANY);

	if (devlist->size() > 0)
		fprintf(in_logfile, "Devices:\n");

	for (unsigned int x = 0; x < devlist->size(); x++) {
		kis_tracked_device_base *dev = (*devlist)[x];
		Kis_Phy_Handler *phy = FetchPhyHandler(dev->get_phytype());

		fprintf(in_logfile, 
				" Device MAC: %s\n",
                dev->get_mac().Mac2String().c_str());

		if (dev->get_phytype() == KIS_PHY_UNKNOWN || phy == NULL) 
			fprintf(in_logfile, " Device phy: Unknown\n");
		else
			fprintf(in_logfile, " Device phy: %s\n",
					phy->FetchPhyName().c_str());

		if (dev->get_name() != "")
			fprintf(in_logfile, 
					" Device name: %s\n",
					dev->get_name().c_str());

		if (dev->get_type_string() != "")
			fprintf(in_logfile, " Device type: %s\n",
					dev->get_type_string().c_str());

		fprintf(in_logfile, " Basic device type:\n");
		if (dev->get_basic_type_set() == KIS_DEVICE_BASICTYPE_DEVICE) 
			fprintf(in_logfile, "  Generic device (No special characteristics detected)\n");
		if ((dev->get_basic_type_set() & KIS_DEVICE_BASICTYPE_AP))
			fprintf(in_logfile, "  AP (Central network controller)\n");
		if ((dev->get_basic_type_set() & KIS_DEVICE_BASICTYPE_CLIENT))
			fprintf(in_logfile, "  Client (Network client)\n");
		if ((dev->get_basic_type_set() & KIS_DEVICE_BASICTYPE_WIRED))
			fprintf(in_logfile, "  Wired (Bridged wired device)\n");
		if ((dev->get_basic_type_set() & KIS_DEVICE_BASICTYPE_PEER))
			fprintf(in_logfile, "  Peer (Ad-hoc or peerless client)\n");
		fprintf(in_logfile, "\n");

		fprintf(in_logfile, " Basic device encryption:\n");

		// Empty or only generic encryption known
		if (dev->get_basic_crypt_set() == KIS_DEVICE_BASICCRYPT_NONE)
			fprintf(in_logfile, "  None (No detected encryption)\n");
		if ((dev->get_basic_crypt_set() == KIS_DEVICE_BASICCRYPT_ENCRYPTED))
			fprintf(in_logfile, "  Encrypted (Some form of encryption in use)\n");
		// Deeper detection of l2/l3
		if ((dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L2))
			fprintf(in_logfile, "  L2 encrypted (Link layer encryption)\n");
		if ((dev->get_basic_crypt_set() & KIS_DEVICE_BASICCRYPT_L2))
			fprintf(in_logfile, "  L3 encrypted (L3+ encryption)\n");
		fprintf(in_logfile, "\n");

        time_t dt;

        dt = dev->get_first_time();
		fprintf(in_logfile, 
				" First seen: %.24s\n",
				ctime(&(dt)));
        dt = dev->get_last_time();
		fprintf(in_logfile,
				" Last seen: %.24s\n",
				ctime(&(dt)));
		fprintf(in_logfile, "\n");

        TrackerElement *seenby_map = dev->get_seenby_map();

		if (seenby_map->size() > 0)
			fprintf(in_logfile, " Seen by capture sources:\n");

        for (TrackerElement::map_const_iterator si = seenby_map->begin();
                si != seenby_map->end(); ++si) {
            kis_tracked_seenby_data *sbd = (kis_tracked_seenby_data *) si->second;

			fprintf(in_logfile, 
					"  UUID: %s>\n",
					sbd->get_uuid().UUID2String().c_str());

            time_t st;

            st = sbd->get_first_time();
			fprintf(in_logfile, "  First seen: %.24s\n",
					ctime(&(st)));

            st = sbd->get_last_time();
			fprintf(in_logfile, "  Last seen: %.24s\n",
					ctime(&(st)));
			fprintf(in_logfile, "  Packets: %lu\n",
                    sbd->get_num_packets());

            TrackerElement *fe = sbd->get_freq_mhz_map();

            if (fe->size() > 0) {
				fprintf(in_logfile, "  Frequencies seen:\n");

                for (TrackerElement::map_const_iterator fi = fe->begin();
                        fi != fe->end(); ++fi) {
					fprintf(in_logfile, "   Frequency (MHz): %u\n"
							"   Packets: %lu\n",
							fi->first, GetTrackerValue<uint64_t>(fi->second));
                }
            }

			fprintf(in_logfile, "\n");
		}

        kis_tracked_location *location = dev->get_location();
        kis_tracked_signal_data *snrdata = dev->get_signal_data();

        if (location->get_valid()) {
			fprintf(in_logfile, 
					"  GPS average latitude: %f\n"
					"  GPS average longitude: %f\n"
					"  GPS average altitude: %f\n"
					"\n",
                    location->get_avg_loc()->get_lat(),
                    location->get_avg_loc()->get_lon(),
                    location->get_avg_loc()->get_alt());

			fprintf(in_logfile,
					"  GPS bounding minimum latitude: %f\n"
					"  GPS bounding minimum longitude: %f\n"
                    "  GPS bounding minimum altitude: %f\n",
                    location->get_min_loc()->get_lat(),
                    location->get_min_loc()->get_lon(),
                    location->get_min_loc()->get_alt());

			fprintf(in_logfile, "\n");

			fprintf(in_logfile,
					"  GPS bounding maximum latitude: %f\n"
					"  GPS bounding maximum longitude: %f\n"
                    "  GPS bounding maximum altitude: %f\n",
                    location->get_max_loc()->get_lat(),
                    location->get_max_loc()->get_lon(),
                    location->get_max_loc()->get_alt());

			fprintf(in_logfile, "\n");

            kis_tracked_location_triplet *peak_location = snrdata->get_peak_loc();

			fprintf(in_logfile,
					"  GPS peak signal latitude: %f\n"
					"  GPS peak signal longitude: %f\n"
                    "  GPS peak signal altitude: %f\n",
                    peak_location->get_lat(),
                    peak_location->get_lon(),
                    peak_location->get_alt());
		}

        if (snrdata->get_last_signal_dbm() != 0) {
			fprintf(in_logfile, " Signal (as dBm)\n");

			fprintf(in_logfile, "  Latest signal: %d\n",
                    snrdata->get_last_signal_dbm());

            fprintf(in_logfile, "  Latest noise: %d\n",
                    snrdata->get_last_noise_dbm());

			fprintf(in_logfile, "  Minimum signal: %d\n",
                    snrdata->get_min_signal_dbm());

            fprintf(in_logfile, "  Minimum noise: %d\n",
                    snrdata->get_min_noise_dbm());

			fprintf(in_logfile, "  Maximum signal: %d\n",
                    snrdata->get_max_signal_dbm());

			fprintf(in_logfile, "  Maximum noise: %d\n",
                    snrdata->get_max_noise_dbm());

			fprintf(in_logfile, "\n");
        }

        if (snrdata->get_last_signal_rssi() != 0) {
			fprintf(in_logfile, " Signal (as RSSI)\n");

			fprintf(in_logfile, "  Latest signal: %d\n",
                    snrdata->get_last_signal_rssi());

            fprintf(in_logfile, "  Latest noise: %d\n",
                    snrdata->get_last_noise_rssi());

			fprintf(in_logfile, "  Minimum signal: %d\n",
                    snrdata->get_min_signal_rssi());

            fprintf(in_logfile, "  Minimum noise: %d\n",
                    snrdata->get_min_noise_rssi());

			fprintf(in_logfile, "  Maximum signal: %d\n",
                    snrdata->get_max_signal_rssi());

			fprintf(in_logfile, "  Maximum noise: %d\n",
                    snrdata->get_max_noise_rssi());

			fprintf(in_logfile, "\n");
        }

		fprintf(in_logfile, 
				" Total packets: %lu\n"
				" Link-type packets: %lu\n"
				" Data packets: %lu\n"
				" Filtered packets: %lu\n"
				" Error packets: %lu\n"
				" Data (in bytes): %lu\n\n",
                dev->get_packets(), dev->get_llc_packets(), dev->get_data_packets(),
                dev->get_filter_packets(), dev->get_error_packets(),
                dev->get_datasize_rx() + dev->get_datasize_tx());

        if (dev->get_manuf() != "") 
			fprintf(in_logfile, " Manufacturer: %s\n\n",
					dev->get_manuf().c_str());

        if (dev->get_tag() != "") {
            fprintf(in_logfile, " Tag: %s\n", 
                    dev->get_tag().c_str());
		}

		// Call all the phy handlers for logging
		for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin();
			 x != phy_handler_map.end(); ++x) {
			x->second->ExportLogRecord(dev, "text", in_logfile, 1);
		}

		fprintf(in_logfile, "\n");

	}

	if (devlist->size() > 0)
		fprintf(in_logfile, "\n");

}

int Devicetracker::LogDevices(string in_logclass, 
							  string in_logtype, FILE *in_logfile) {
	string logclass = StrLower(in_logclass);
	string logtype = StrLower(in_logtype);

	if (logclass == "xml") {
		WriteXML(in_logfile);
		return 1;
	} else if (logclass == "text") {
		WriteTXT(in_logfile);
		return 1;
	}

	return 0;
}

int Devicetracker::SetDeviceTag(mac_addr in_device, string in_data) {

	kis_tracked_device_base *dev = FetchDevice(in_device);
	Kis_Phy_Handler *handler = FetchPhyHandler(in_device.GetPhy());

	if (dev == NULL) {
		return -1;
	}

    if (handler == NULL) {
        return -1;
    }

    dev->set_tag(in_data);

	string tag = handler->FetchPhyName() + in_device.Mac2String();

    tag_conf->SetOpt(tag, in_data, globalreg->timestamp.tv_sec);

	if (!dev->get_dirty()) {
        dev->set_dirty(true);
		dirty_device_vec.push_back(dev);
	}

	return 0;
}

int Devicetracker::ClearDeviceTag(mac_addr in_device) {
	kis_tracked_device_base *dev = FetchDevice(in_device);
	Kis_Phy_Handler *handler = FetchPhyHandler(in_device.GetPhy());

	if (handler == NULL)
		return -1;

	if (dev == NULL)
		return -1;

    dev->set_tag("");

    string tag = handler->FetchPhyName() + in_device.Mac2String();

    tag_conf->SetOpt(tag, "", globalreg->timestamp.tv_sec);

	if (!dev->get_dirty()) {
        dev->set_dirty(true);
		dirty_device_vec.push_back(dev);
	}

	return 0;
}

string Devicetracker::FetchDeviceTag(mac_addr in_device) {
	kis_tracked_device_base *dev = FetchDevice(in_device);

	if (dev == NULL)
		return "";

    return dev->get_tag();
}

// HTTP interfaces
bool Devicetracker::VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0) {
        return false;
    }

    if (strcmp(path, "/devices/msgpack/all_devices") == 0)
        return true;

    vector<string> tokenurl = StrTokenize(path, "/");

    if (tokenurl.size() < 4)
        return false;

    if (tokenurl[1] == "devices") {
        if (tokenurl[2] == "msgpack") {
            devicelist_mutex_locker(this);
            
            if (tracked_map.find(mac_addr(tokenurl[3])) != tracked_map.end()) {
                return true;
            } else {
                fprintf(stderr, "debug - couldn't find entry for mac %s / %s\n", tokenurl[3].c_str(), mac_addr(tokenurl[3]).Mac2String().c_str());
                return false;
            }
        }
    }


    return false;
}

void Devicetracker::CreateStreamResponse(struct MHD_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(url, "/devices/msgpack/all_devices") == 0) {
        devicelist_mutex_locker(this);

        vector<string> macvec;
        for (unsigned int x = 0; x < tracked_vec.size(); x++) {
            macvec.push_back(tracked_vec[x]->get_macaddr().MacPhy2String());
            // stream << tracked_vec[x]->get_macaddr().MacPhy2String() << "\n";
        }
        
        msgpack::pack(stream, macvec);
    }

    vector<string> tokenurl = StrTokenize(url, "/");

    if (tokenurl.size() < 4)
        return;

    if (tokenurl[1] == "devices") {
        if (tokenurl[2] == "msgpack") {
            devicelist_mutex_locker(this);
           
            map<mac_addr, kis_tracked_device_base *>::iterator itr;

            if ((itr = tracked_map.find(mac_addr(tokenurl[3]))) != tracked_map.end()) {

                msgpack::pack(stream, (TrackerElement *) itr->second);

                return;
            } else {
                return;
            }
        }
    }

}


