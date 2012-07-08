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
#include "gpswrapper.h"
#include "alertracker.h"
#include "manuf.h"
#include "packetsourcetracker.h"
#include "packetsource.h"
#include "dumpfile_devicetracker.h"

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
				scratch = IntToString(dev->phy_type);
				break;
			case KISDEV_macaddr:
				scratch = dev->key.Mac2String();
				break;
			case KISDEV_name:
				scratch = "\001" + com->name + "\001";
				break;
			case KISDEV_typestring:
				scratch = "\001" + com->type_string + "\001";
				break;
			case KISDEV_basictype:
				scratch = IntToString(com->basic_type_set);
				break;
			case KISDEV_cryptstring:
				scratch = "\001" + com->crypt_string + "\001";
				break;
			case KISDEV_basiccrypt:
				scratch = IntToString(com->basic_crypt_set);
				break;
			case KISDEV_firsttime:
				scratch = UIntToString(com->first_time);
				break;
			case KISDEV_lasttime:
				scratch = UIntToString(com->last_time);
				break;
			case KISDEV_packets:
				scratch = UIntToString(com->packets);
				break;
			case KISDEV_llcpackets:
				scratch = UIntToString(com->llc_packets);
				break;
			case KISDEV_errorpackets:
				scratch = UIntToString(com->error_packets);
				break;
			case KISDEV_datapackets:
				scratch = UIntToString(com->data_packets);
				break;
			case KISDEV_cryptpackets:
				scratch = UIntToString(com->crypt_packets);
				break;
			case KISDEV_filterpackets:
				scratch = UIntToString(com->filter_packets);
				break;
			case KISDEV_datasize:
				scratch = ULongToString(com->datasize);
				break;
			case KISDEV_newpackets:
				scratch = UIntToString(com->new_packets);
				break;
			case KISDEV_channel:
				scratch = IntToString(com->channel);
				break;
			case KISDEV_frequency:
				scratch = UIntToString(com->frequency);
				break;
			case KISDEV_freqmhz:
				for (map<unsigned int, unsigned int>::const_iterator fmi = 
					 com->freq_mhz_map.begin();
					 fmi != com->freq_mhz_map.end(); ++fmi) {
					scratch += IntToString(fmi->first) + ":" + IntToString(fmi->second) + "*";
				}
				break;
			case KISDEV_manuf:
				scratch = "\001" + com->manuf + "\001";
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
	kis_tracked_device *dev = (kis_tracked_device *) data;
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
				scratch = IntToString(dev->phy_type);
				break;
			case DEVICEDONE_macaddr:
				scratch = dev->key.Mac2String();
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

	int r = ((Devicetracker *) auxptr)->SetDeviceTag(dev, tag, content, persist);

	if (r < 0) {
		snprintf(errstr, 1024, "Failed to set tag");
		return -1;
	}

	return 1;
}

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	globalreg->InsertGlobal("DEVICE_TRACKER", this);

	next_componentid = 0;
	num_packets = num_datapackets = num_errorpackets = 
		num_filterpackets = num_packetdelta = 0;

	conf_save = 0;
	next_phy_id = 0;

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
	
}

Devicetracker::~Devicetracker() {
	if (timerid >= 0)
		globalreg->timetracker->RemoveTimer(timerid);

	globalreg->packetchain->RemoveHandler(&Devicetracker_packethook_stringcollector,
										  CHAINPOS_LOGGING);
	globalreg->packetchain->RemoveHandler(&Devicetracker_packethook_commontracker,
										  CHAINPOS_TRACKER);

	if (track_filter != NULL)
		delete track_filter;

	for (map<int, Kis_Phy_Handler *>::iterator p = phy_handler_map.begin();
		 p != phy_handler_map.end(); ++p) {
		delete p->second;
	}

	for (unsigned int d = 0; d < tracked_vec.size(); d++) {
		delete tracked_vec[d];
	}
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

vector<kis_tracked_device *> *Devicetracker::FetchDevices(int in_phy) {
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
	if (in_phy == KIS_PHY_ANY)
		return num_datapackets;

	map<int, int>::iterator i = phy_datapackets.find(in_phy);
	if (i != phy_datapackets.end())
		return i->second;

	return 0;
}

int Devicetracker::FetchNumCryptpackets(int in_phy) {
	int r = 0;

	kis_device_common *common;

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (tracked_vec[x]->phy_type == in_phy || in_phy == KIS_PHY_ANY) {
			if ((common = 
				 (kis_device_common *) tracked_vec[x]->fetch(devcomp_ref_common)) != NULL)
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
	
	phy_dirty_vec[num] = new vector<kis_tracked_device *>;
	phy_device_vec[num] = new vector<kis_tracked_device *>;

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

		// If it has a common field
		kis_device_common *common;

		if ((common = 
			 (kis_device_common *) tracked_vec[x]->fetch(devcomp_ref_common)) != NULL) {

			if (in_fd == -1) {
				globalreg->kisnetserver->SendToAll(proto_ref_commondevice, 
												   (void *) common);

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

				globalreg->kisnetserver->SendToAll(proto_ref_devicedone, 
												   (void *) tracked_vec[x]);
			} else {
				globalreg->kisnetserver->SendToClient(in_fd, proto_ref_commondevice,
													  (void *) common, &cache);

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

				globalreg->kisnetserver->SendToClient(in_fd, proto_ref_devicedone,
													  (void *) tracked_vec[x], 
													  &donecache);
			}
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
		kis_tracked_device *dev = dirty_device_vec[x];

		// If it has a common field
		kis_device_common *common;

		if ((common = 
			 (kis_device_common *) dev->fetch(devcomp_ref_common)) != NULL) {
			globalreg->kisnetserver->SendToAll(proto_ref_commondevice, 
											   (void *) common);

			// Reset packet delta
			common->new_packets = 0;

			map<string, kis_tag_data *>::iterator ti;

			for (ti = common->arb_tag_map.begin(); 
				 ti != common->arb_tag_map.end(); ++ti) {
				if (ti->second == NULL)
					continue;

				if (ti->second->dirty == false)
					continue;

				devtag_tx dtx;
				dtx.data = ti->second;
				dtx.tag = ti->first;
				dtx.macaddr = common->device->key;
				dtx.phyid = common->device->phy_type;

				globalreg->kisnetserver->SendToAll(proto_ref_devtag, 
												   (void *) &dtx);

				if (ti->second->value == "") {
					delete ti->second;
					ti->second = NULL;
				} else {
					ti->second->dirty = false;
				}
			}

		}

		// No longer dirty
		dev->dirty = 0;
	}

	// Send all the phy-specific dirty stuff
	for (map<int, vector<kis_tracked_device *> *>::iterator x = phy_dirty_vec.begin();
		 x != phy_dirty_vec.end(); ++x) {
		phy_handler_map[x->first]->BlitDevices(-1, x->second);
		x->second->clear();
	}

	for (map<int, Kis_Phy_Handler *>::iterator x = phy_handler_map.begin(); 
		 x != phy_handler_map.end(); ++x) {
		x->second->TimerKick();
	}

	for (unsigned int x = 0; x < dirty_device_vec.size(); x++) {
		globalreg->kisnetserver->SendToAll(proto_ref_devicedone, 
										   (void *) dirty_device_vec[x]);
	}

	dirty_device_vec.clear();

	// Reset the packet rate delta
	num_packetdelta = 0;

	return 1;
}

kis_tracked_device *Devicetracker::FetchDevice(mac_addr in_device) {
	device_itr i = tracked_map.find(in_device);

	if (i != tracked_map.end())
		return i->second;

	return NULL;
}

kis_tracked_device *Devicetracker::FetchDevice(mac_addr in_device, 
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

	si.device = devinfo->devref->key;
	si.phy = devinfo->devref->phy_type;
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

	kis_tracked_device *device = NULL;

	// Make a new device or fetch an existing one
	device = BuildDevice(devmac, in_pack);

	if (device == NULL)
		return 0;

	// Push our common data into it
	PopulateCommon(device, in_pack);

	return 1;
}

// Find a device, creating the device as needed and populating common data
kis_tracked_device *Devicetracker::MapToDevice(mac_addr in_device, 
											   kis_packet *in_pack) {
	kis_tracked_device *device = NULL;
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
kis_tracked_device *Devicetracker::BuildDevice(mac_addr in_device, 
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

	kis_tracked_device *device = NULL;

	mac_addr devmac = in_device;
	devmac.SetPhy(pack_common->phyid);

	device = FetchDevice(devmac);

	if (device == NULL) {
		// fprintf(stderr, "debug - devicetracker building device for %s\n", devmac.Mac2String().c_str());

		// we don't have this device tracked.  Make one based on the
		// input data (for example, this could be a bssid which has never
		// talked, but which we see a client communicating with)
		device = new kis_tracked_device(globalreg);

		device->key = devmac;

		device->phy_type = pack_common->phyid;

		// Defer tag loading to when we populate the common record

		tracked_map[device->key] = device;
		tracked_vec.push_back(device);
		phy_device_vec[pack_common->phyid]->push_back(device);

		// mark it dirty
		if (device->dirty == 0) {
			device->dirty = 1;
			dirty_device_vec.push_back(device);
			phy_dirty_vec[pack_common->phyid]->push_back(device);
		}
	}

	return device;
}

int Devicetracker::PopulateCommon(kis_tracked_device *device, kis_packet *in_pack) {
	kis_common_info *pack_common = 
		(kis_common_info *) in_pack->fetch(pack_comp_common);
	kis_data_packinfo *pack_data = 
		(kis_data_packinfo *) in_pack->fetch(pack_comp_basicdata);
	kis_layer1_packinfo *pack_l1info = 
		(kis_layer1_packinfo *) in_pack->fetch(pack_comp_radiodata);
	kis_gps_packinfo *pack_gpsinfo =
		(kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);
	kis_ref_capsource *pack_capsrc =
		(kis_ref_capsource *) in_pack->fetch(pack_comp_capsrc);

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
	if (device->dirty == 0) {
		device->dirty = 1;
		dirty_device_vec.push_back(device);
		phy_dirty_vec[pack_common->phyid]->push_back(device);
	}

	// Make a common record
	kis_device_common *common = NULL;
	common = (kis_device_common *) device->fetch(devcomp_ref_common);

	if (common == NULL) {
		common = new kis_device_common;
		common->device = device;
		device->insert(devcomp_ref_common, common);

		common->first_time = in_pack->ts.tv_sec;

		if (globalreg->manufdb != NULL) 
			common->manuf = globalreg->manufdb->LookupOUI(device->key);

		// Set name
		common->name = device->key.Mac2String();

		// Load persistent tags
		string tag = handler->FetchPhyName() + device->key.Mac2String();

		vector<string> tfl = tag_conf->FetchOptVec(tag);

		vector<smart_word_token> tflp;
		for (unsigned int x = 0; x < tfl.size(); x++) {
			tflp = NetStrTokenize(tfl[x], ",");

			if (tflp.size() != 2)
				continue;

			kis_tag_data *d = new kis_tag_data;;
			d->dirty = true;
			d->value = tflp[1].word;

			map<string, kis_tag_data *>::iterator ti =
				common->arb_tag_map.find(tflp[0].word);

			if (ti != common->arb_tag_map.end()) {
				if (ti->second != NULL)
					delete ti->second;
			}

			common->arb_tag_map[tflp[0].word] = d;
		}

	}

	common->packets++;

	common->last_time = in_pack->ts.tv_sec;
	common->new_packets++;

	if (pack_common->error)
		common->error_packets++;

	if (pack_common->type == packet_basic_data) {
		common->data_packets++;
		common->datasize += pack_common->datasize;
	} else if (pack_common->type == packet_basic_mgmt ||
			   pack_common->type == packet_basic_phy) {
		common->llc_packets++;
	}

	if (pack_l1info != NULL) {
		if (pack_l1info->channel != 0)
			common->channel = pack_l1info->channel;
		if (pack_l1info->freq_mhz != 0)
			common->frequency = pack_l1info->freq_mhz;

		Packinfo_Sig_Combo *sc = new Packinfo_Sig_Combo(pack_l1info, pack_gpsinfo);
		common->snrdata += *sc;
		delete(sc);

		if (common->freq_mhz_map.find(pack_l1info->freq_mhz) != 
			common->freq_mhz_map.end())
			common->freq_mhz_map[pack_l1info->freq_mhz]++;
		else
			common->freq_mhz_map[pack_l1info->freq_mhz] = 1;
	}

	common->gpsdata += pack_gpsinfo;

	// Update seenby records for time, frequency, packets
	if (pack_capsrc != NULL) {
		kis_seenby_data *seenby = NULL;

		map<uuid, kis_seenby_data *>::iterator si =
			common->seenby_map.find(pack_capsrc->ref_source->FetchUUID());

		if (si == common->seenby_map.end()) {
			seenby = new kis_seenby_data;
			seenby->first_time = in_pack->ts.tv_sec;
			seenby->num_packets = 0;
			common->seenby_map[pack_capsrc->ref_source->FetchUUID()] = seenby;
		} else {
			seenby = si->second;
		}

		seenby->last_time = in_pack->ts.tv_sec;
		seenby->num_packets++;

		if (pack_l1info != NULL) {
			if (seenby->freq_mhz_map.find(pack_l1info->freq_mhz) != 
				seenby->freq_mhz_map.end())
				seenby->freq_mhz_map[pack_l1info->freq_mhz]++;
			else
				seenby->freq_mhz_map[pack_l1info->freq_mhz] = 1;
		}
	}

	common->basic_crypt_set |= pack_common->basic_crypt_set;

	if (pack_common->channel)
		common->channel = pack_common->channel;

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

	vector<kis_tracked_device *> *devlist = FetchDevices(KIS_PHY_ANY);

	if (devlist->size() > 0)
		fprintf(in_logfile, "<devices>\n");

	for (unsigned int x = 0; x < devlist->size(); x++) {
		kis_tracked_device *dev = (*devlist)[x];
		kis_device_common *com = (kis_device_common *) dev->fetch(devcomp_ref_common);
		Kis_Phy_Handler *phy = FetchPhyHandler(dev->phy_type);

		if (com == NULL)
			continue;

		if (dev->phy_type == KIS_PHY_UNKNOWN || phy == NULL) 
			fprintf(in_logfile, "<device phy=\"unknown\">\n");
		else
			fprintf(in_logfile, 
					"<device xsi:type=\"%s:%sdevice\" phy=\"%s\">\n",
					phy->FetchPhyXsdNs().c_str(), phy->FetchPhyXsdNs().c_str(),
					phy->FetchPhyXsdNs().c_str());

		fprintf(in_logfile, 
				"<deviceMac>%s</deviceMac>\n",
				dev->key.Mac2String().c_str());

		if (com->name != "")
			fprintf(in_logfile, 
					"<name>%s</name>\n",
					SanitizeXML(com->name).c_str());

		if (com->type_string != "")
			fprintf(in_logfile, "<classifiedType>%s</classifiedType>\n",
					SanitizeXML(com->type_string).c_str());

		fprintf(in_logfile, "<commonTypes>\n");
		if ((com->basic_type_set & KIS_DEVICE_BASICTYPE_AP))
			fprintf(in_logfile, "<commonType>ap</commonType>\n");
		if ((com->basic_type_set & KIS_DEVICE_BASICTYPE_CLIENT))
			fprintf(in_logfile, "<commonType>client</commonType>\n");
		if ((com->basic_type_set & KIS_DEVICE_BASICTYPE_WIRED))
			fprintf(in_logfile, "<commonType>wired</commonType>\n");
		if ((com->basic_type_set & KIS_DEVICE_BASICTYPE_PEER))
			fprintf(in_logfile, "<commonType>peer</commonType>\n");
		fprintf(in_logfile, "</commonTypes>\n");

		fprintf(in_logfile, "<commonCryptTypes>\n");
		// Empty or only generic encryption known
		if (com->basic_crypt_set == KIS_DEVICE_BASICCRYPT_NONE)
			fprintf(in_logfile, "<commonCrypt>none</commonCrypt>\n");
		if ((com->basic_crypt_set == KIS_DEVICE_BASICCRYPT_ENCRYPTED))
			fprintf(in_logfile, "<commonCrypt>encrypted</commonCrypt>\n");
		// Deeper detection of l2/l3
		if ((com->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L2))
			fprintf(in_logfile, "<commonCrypt>L2 encrypted</commonCrypt>\n");
		if ((com->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L2))
			fprintf(in_logfile, "<commonCrypt>L3 encrypted</commonCrypt>\n");
		fprintf(in_logfile, "</commonCryptTypes>\n");

		fprintf(in_logfile, 
				"<firstSeen>%.24s</firstSeen>\n",
				ctime(&(com->first_time)));
		fprintf(in_logfile,
				"<lastSeen>%.24s</lastSeen>\n",
				ctime(&(com->last_time)));

		if (com->seenby_map.size() > 0)
			fprintf(in_logfile, "<seenBySources>\n");

		for (map<uuid, kis_seenby_data *>::iterator si = com->seenby_map.begin();
			 si != com->seenby_map.end(); ++si) {
			fprintf(in_logfile, 
					"<seenBySource>\n"
					"<uuid>%s</uuid>\n",
					si->first.UUID2String().c_str());
			fprintf(in_logfile, "<firstSeen>%.24s</firstSeen>\n",
					ctime(&(si->second->first_time)));
			fprintf(in_logfile, "<lastSeen>%.24s</lastSeen>\n",
					ctime(&(si->second->last_time)));
			fprintf(in_logfile, "<packets>%u</packets>\n",
					si->second->num_packets);

			if (si->second->freq_mhz_map.size() > 0) {
				fprintf(in_logfile, "<frequencySeen>\n");
				for (map<unsigned int, unsigned int>::iterator fi = 
					 si->second->freq_mhz_map.begin(); fi !=
					 si->second->freq_mhz_map.end(); ++fi) {

					fprintf(in_logfile, "<frequency mhz=\"%u\" packets=\"%u\"/>\n",
							fi->first, fi->second);

				}
				fprintf(in_logfile, "</frequencySeen>\n");
			}

			fprintf(in_logfile, "</seenBySource>\n");
		}

		if (com->seenby_map.size() > 0)
			fprintf(in_logfile, "</seenBySources>\n");

		if (com->gpsdata.gps_valid) {
			fprintf(in_logfile, 
					"<gpsAverage>\n"
					"<latitude>%f</latitude>\n"
					"<longitude>%f</longitude>\n"
					"<altitude>%f</altitude>\n"
					"</gpsAverage>\n",
					com->gpsdata.aggregate_lat,
					com->gpsdata.aggregate_lon,
					com->gpsdata.aggregate_alt);

			fprintf(in_logfile,
					"<gpsMinimum>\n"
					"<latitude>%f</latitude>\n"
					"<longitude>%f</longitude>\n",
					com->gpsdata.min_lat,
					com->gpsdata.min_lon);
			if (com->gpsdata.min_alt != KIS_GPS_ALT_BOGUS_MIN)
				fprintf(in_logfile, "<altitude>%f</altitude>\n",
						com->gpsdata.min_alt);
			fprintf(in_logfile, "</gpsMinimum>\n");

			fprintf(in_logfile,
					"<gpsMaximum>\n"
					"<latitude>%f</latitude>\n"
					"<longitude>%f</longitude>\n",
					com->gpsdata.max_lat,
					com->gpsdata.max_lon);
			if (com->gpsdata.max_alt != KIS_GPS_ALT_BOGUS_MAX)
				fprintf(in_logfile, "<altitude>%f</altitude>\n",
						com->gpsdata.max_alt);
			fprintf(in_logfile, "</gpsMaximum>\n");

			fprintf(in_logfile,
					"<gpsPeaksignal>\n"
					"<latitude>%f</latitude>\n"
					"<longitude>%f</longitude>\n",
					com->snrdata.peak_lat,
					com->snrdata.peak_lon);
			if (com->snrdata.peak_alt != KIS_GPS_ALT_BOGUS_MIN)
				fprintf(in_logfile, "<altitude>%f</altitude>\n",
						com->snrdata.peak_alt);
			fprintf(in_logfile, "</gpsPeaksignal>\n");
		}

		if (com->snrdata.last_signal_dbm != KIS_SIGNAL_DBM_BOGUS_MIN) {
			// Smells like DBM signalling
			fprintf(in_logfile, "<signalLevel type=\"dbm\">\n");

			fprintf(in_logfile, "<lastSignal>%d</lastSignal>\n",
					com->snrdata.last_signal_dbm);

			if (com->snrdata.last_noise_dbm != KIS_SIGNAL_DBM_BOGUS_MIN)
				fprintf(in_logfile, "<lastNoise>%d</lastNoise>\n",
						com->snrdata.last_noise_dbm);

			fprintf(in_logfile, "<minSignal>%d</minSignal>\n",
					com->snrdata.min_signal_dbm);

			if (com->snrdata.min_noise_dbm != KIS_SIGNAL_DBM_BOGUS_MIN)
				fprintf(in_logfile, "<minNoise>%d</minNoise>\n",
						com->snrdata.min_noise_dbm);

			fprintf(in_logfile, "<maxSignal>%d</maxSignal>\n",
					com->snrdata.max_signal_dbm);

			if (com->snrdata.max_noise_dbm != KIS_SIGNAL_DBM_BOGUS_MAX)
				fprintf(in_logfile, "<maxNoise>%d</maxNoise>\n",
						com->snrdata.max_noise_dbm);
			
			fprintf(in_logfile, "</signalLevel>\n");
		} else if (com->snrdata.last_signal_rssi != KIS_SIGNAL_RSSI_BOGUS_MIN) {
			// Smells like RSSI
			fprintf(in_logfile, "<signalLevel type=\"rssi\">\n");

			fprintf(in_logfile, "<lastSignal>%d</lastSignal>\n",
					com->snrdata.last_signal_rssi);

			if (com->snrdata.last_noise_rssi != KIS_SIGNAL_RSSI_BOGUS_MIN)
				fprintf(in_logfile, "<lastNoise>%d</lastNoise>\n",
						com->snrdata.last_noise_rssi);

			fprintf(in_logfile, "<minSignal>%d</minSignal>\n",
					com->snrdata.min_signal_rssi);

			if (com->snrdata.min_noise_rssi != KIS_SIGNAL_RSSI_BOGUS_MIN)
				fprintf(in_logfile, "<minNoise>%d</minNoise>\n",
						com->snrdata.min_noise_rssi);

			fprintf(in_logfile, "<maxSignal>%d</maxSignal>\n",
					com->snrdata.max_signal_rssi);

			if (com->snrdata.max_noise_rssi != KIS_SIGNAL_RSSI_BOGUS_MAX)
				fprintf(in_logfile, "<maxNoise>%d</maxNoise>\n",
						com->snrdata.max_noise_rssi);
			
			fprintf(in_logfile, "</signalLevel>\n");
		}

		fprintf(in_logfile, 
				"<packets>%u</packets>\n"
				"<packetLink>%u</packetLink>\n"
				"<packetData>%u</packetData>\n"
				"<packetFiltered>%u</packetFiltered>\n"
				"<packetError>%u</packetError>\n"
				"<dataBytes>%lu</dataBytes>\n",
				com->packets, com->llc_packets, com->data_packets,
				com->filter_packets, com->error_packets, com->datasize);

		if (com->manuf != "")
			fprintf(in_logfile, "<manufacturer>%s</manufacturer>\n",
					SanitizeXML(com->manuf).c_str());

		if (com->arb_tag_map.size() > 0)
			fprintf(in_logfile, "<tags>");

		for (map<string, kis_tag_data *>::iterator ti = com->arb_tag_map.begin();
			 ti != com->arb_tag_map.end(); ++ti) {
			if (ti->second != NULL && ti->second->value != "")
				fprintf(in_logfile, "<tag name=\"%s\">%s</tag>\n",
						SanitizeXML(ti->first).c_str(),
						SanitizeXML(ti->second->value).c_str());
		}

		if (com->arb_tag_map.size() > 0)
			fprintf(in_logfile, "</tags>");

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
	
	vector<kis_tracked_device *> *devlist = FetchDevices(KIS_PHY_ANY);

	if (devlist->size() > 0)
		fprintf(in_logfile, "Devices:\n");

	for (unsigned int x = 0; x < devlist->size(); x++) {
		kis_tracked_device *dev = (*devlist)[x];
		kis_device_common *com = (kis_device_common *) dev->fetch(devcomp_ref_common);
		Kis_Phy_Handler *phy = FetchPhyHandler(dev->phy_type);

		if (com == NULL)
			continue;

		fprintf(in_logfile, 
				" Device MAC: %s\n",
				dev->key.Mac2String().c_str());

		if (dev->phy_type == KIS_PHY_UNKNOWN || phy == NULL) 
			fprintf(in_logfile, " Device phy: Unknown\n");
		else
			fprintf(in_logfile, " Device phy: %s\n",
					phy->FetchPhyName().c_str());

		if (com->name != "")
			fprintf(in_logfile, 
					" Device name: %s\n",
					com->name.c_str());

		if (com->type_string != "")
			fprintf(in_logfile, " Device type: %s\n",
					com->type_string.c_str());

		fprintf(in_logfile, " Basic device type:\n");
		if (com->basic_type_set == KIS_DEVICE_BASICTYPE_DEVICE) 
			fprintf(in_logfile, "  Generic device (No special characteristics detected)\n");
		if ((com->basic_type_set & KIS_DEVICE_BASICTYPE_AP))
			fprintf(in_logfile, "  AP (Central network controller)\n");
		if ((com->basic_type_set & KIS_DEVICE_BASICTYPE_CLIENT))
			fprintf(in_logfile, "  Client (Network client)\n");
		if ((com->basic_type_set & KIS_DEVICE_BASICTYPE_WIRED))
			fprintf(in_logfile, "  Wired (Bridged wired device)\n");
		if ((com->basic_type_set & KIS_DEVICE_BASICTYPE_PEER))
			fprintf(in_logfile, "  Peer (Ad-hoc or peerless client)\n");
		fprintf(in_logfile, "\n");

		fprintf(in_logfile, " Basic device encryption:\n");

		// Empty or only generic encryption known
		if (com->basic_crypt_set == KIS_DEVICE_BASICCRYPT_NONE)
			fprintf(in_logfile, "  None (No detected encryption)\n");
		if ((com->basic_crypt_set == KIS_DEVICE_BASICCRYPT_ENCRYPTED))
			fprintf(in_logfile, "  Encrypted (Some form of encryption in use)\n");
		// Deeper detection of l2/l3
		if ((com->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L2))
			fprintf(in_logfile, "  L2 encrypted (Link layer encryption)\n");
		if ((com->basic_crypt_set & KIS_DEVICE_BASICCRYPT_L2))
			fprintf(in_logfile, "  L3 encrypted (L3+ encryption)\n");
		fprintf(in_logfile, "\n");

		fprintf(in_logfile, 
				" First seen: %.24s\n",
				ctime(&(com->first_time)));
		fprintf(in_logfile,
				" Last seen: %.24s\n",
				ctime(&(com->last_time)));
		fprintf(in_logfile, "\n");

		if (com->seenby_map.size() > 0)
			fprintf(in_logfile, " Seen by capture sources:\n");

		for (map<uuid, kis_seenby_data *>::iterator si = com->seenby_map.begin();
			 si != com->seenby_map.end(); ++si) {
			fprintf(in_logfile, 
					"  UUID: %s>\n",
					si->first.UUID2String().c_str());
			fprintf(in_logfile, "  First seen: %.24s\n",
					ctime(&(si->second->first_time)));
			fprintf(in_logfile, "  Last seen: %.24s\n",
					ctime(&(si->second->last_time)));
			fprintf(in_logfile, "  Packets: %u\n",
					si->second->num_packets);

			if (si->second->freq_mhz_map.size() > 0) {
				fprintf(in_logfile, "  Frequencies seen:\n");
				for (map<unsigned int, unsigned int>::iterator fi = 
					 si->second->freq_mhz_map.begin(); fi !=
					 si->second->freq_mhz_map.end(); ++fi) {

					fprintf(in_logfile, "   Frequency (MHz): %u\n"
							"   Packets: %u\n",
							fi->first, fi->second);
				}
			}

			fprintf(in_logfile, "\n");
		}

		if (com->gpsdata.gps_valid) {
			fprintf(in_logfile, 
					"  GPS average latitude: %f\n"
					"  GPS average longitude: %f\n"
					"  GPS average altitude: %f\n"
					"\n",
					com->gpsdata.aggregate_lat,
					com->gpsdata.aggregate_lon,
					com->gpsdata.aggregate_alt);

			fprintf(in_logfile,
					"  GPS bounding minimum latitude: %f\n"
					"  GPS bounding minimum longitude: %f\n",
					com->gpsdata.min_lat,
					com->gpsdata.min_lon);

			if (com->gpsdata.min_alt != KIS_GPS_ALT_BOGUS_MIN)
				fprintf(in_logfile, "  GPS bounding minimum altitude: %f\n",
						com->gpsdata.min_alt);

			fprintf(in_logfile, "\n");

			fprintf(in_logfile,
					"  GPS bounding maximum latitude: %f\n"
					"  GPS bounding maximum longitude: %f\n",
					com->gpsdata.max_lat,
					com->gpsdata.max_lon);
			if (com->gpsdata.max_alt != KIS_GPS_ALT_BOGUS_MAX)
				fprintf(in_logfile, "  GPS bounding maximum altitude: %f\n",
						com->gpsdata.max_alt);
			fprintf(in_logfile, "\n");

			fprintf(in_logfile,
					"  GPS peak signal latitude: %f\n"
					"  GPS peak signal longitude: %f\n",
					com->snrdata.peak_lat,
					com->snrdata.peak_lon);
			if (com->snrdata.peak_alt != KIS_GPS_ALT_BOGUS_MIN)
				fprintf(in_logfile, "  GPS peak signal altitude: %f\n",
						com->snrdata.peak_alt);
			fprintf(in_logfile, "\n");
		}

		if (com->snrdata.last_signal_dbm != KIS_SIGNAL_DBM_BOGUS_MIN) {
			fprintf(in_logfile, " Signal (in dBm)\n");

			fprintf(in_logfile, "  Latest signal: %d\n",
					com->snrdata.last_signal_dbm);

			if (com->snrdata.last_noise_dbm != KIS_SIGNAL_DBM_BOGUS_MIN)
				fprintf(in_logfile, "  Latest noise: %d\n",
						com->snrdata.last_noise_dbm);

			fprintf(in_logfile, "  Minimum signal: %d\n",
					com->snrdata.min_signal_dbm);

			if (com->snrdata.min_noise_dbm != KIS_SIGNAL_DBM_BOGUS_MIN)
				fprintf(in_logfile, "  Minimum noise: %d\n",
						com->snrdata.min_noise_dbm);

			fprintf(in_logfile, "  Maximum signal: %d\n",
					com->snrdata.max_signal_dbm);

			if (com->snrdata.max_noise_dbm != KIS_SIGNAL_DBM_BOGUS_MAX)
				fprintf(in_logfile, "  Maximum noise: %d\n",
						com->snrdata.max_noise_dbm);
			
			fprintf(in_logfile, "\n");
		} else if (com->snrdata.last_signal_rssi != KIS_SIGNAL_RSSI_BOGUS_MIN) {
			// Smells like RSSI
			fprintf(in_logfile, " Signal (as RSSI)\n");

			fprintf(in_logfile, "  Latest signal: %d\n",
					com->snrdata.last_signal_rssi);

			if (com->snrdata.last_noise_rssi != KIS_SIGNAL_RSSI_BOGUS_MIN)
				fprintf(in_logfile, "  Latest noise: %d\n",
						com->snrdata.last_noise_rssi);

			fprintf(in_logfile, "  Minimum signal: %d\n",
					com->snrdata.min_signal_rssi);

			if (com->snrdata.min_noise_rssi != KIS_SIGNAL_RSSI_BOGUS_MIN)
				fprintf(in_logfile, "  Minimum noise: %d\n",
						com->snrdata.min_noise_rssi);

			fprintf(in_logfile, "  Maximum signal: %d\n",
					com->snrdata.max_signal_rssi);

			if (com->snrdata.max_noise_rssi != KIS_SIGNAL_RSSI_BOGUS_MAX)
				fprintf(in_logfile, "  Maximum noise: %d\n",
						com->snrdata.max_noise_rssi);
			
			fprintf(in_logfile, "\n");
		}

		fprintf(in_logfile, 
				" Total packets: %u\n"
				" Link-type packets: %u\n"
				" Data packets: %u\n"
				" Filtered packets: %u\n"
				" Error packets: %u\n"
				" Data (in bytes): %lu\n\n",
				com->packets, com->llc_packets, com->data_packets,
				com->filter_packets, com->error_packets, com->datasize);

		if (com->manuf != "")
			fprintf(in_logfile, " Manufacturer: %s\n\n",
					com->manuf.c_str());

		if (com->arb_tag_map.size() > 0)
			fprintf(in_logfile, " Tagged data:\n");

		for (map<string, kis_tag_data *>::iterator ti = com->arb_tag_map.begin();
			 ti != com->arb_tag_map.end(); ++ti) {
			if (ti->second != NULL && ti->second->value != "")
				fprintf(in_logfile, "  %s: %s\n",
						ti->first.c_str(),
						ti->second->value.c_str());
		}
		if (com->arb_tag_map.size() > 0)
			fprintf(in_logfile, "\n");

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

int Devicetracker::SetDeviceTag(mac_addr in_device, string in_tag, string in_data,
								int in_persistent) {
	kis_tracked_device *dev = FetchDevice(in_device);
	kis_device_common *com = NULL;
	Kis_Phy_Handler *handler = FetchPhyHandler(in_device.GetPhy());

	if (handler == NULL) {
		return -1;
	}

	if (dev == NULL) {
		return -1;
	}

	if ((com = (kis_device_common *) dev->fetch(devcomp_ref_common)) == NULL) {
		return -1;
	}

	kis_tag_data *d = new kis_tag_data;;
	d->dirty = true;
	d->value = in_data;

	map<string, kis_tag_data *>::iterator ti =
		com->arb_tag_map.find(in_tag);

	if (ti != com->arb_tag_map.end()) {
		if (ti->second != NULL)
			delete ti->second;
	}

	com->arb_tag_map[in_tag] = d;

	string tag = handler->FetchPhyName() + in_device.Mac2String();

	if (in_persistent) {
		vector<string> tfl = tag_conf->FetchOptVec(tag);

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

		tag_conf->SetOptVec(tag, tfl, globalreg->timestamp.tv_sec);

		tag_conf->SaveConfig(tag_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") + "/" + "tag.conf", "", "", 0, 1).c_str());

	}

	if (dev->dirty == 0) {
		dev->dirty = 1;
		dirty_device_vec.push_back(dev);
	}

	return 0;
}

int Devicetracker::ClearDeviceTag(mac_addr in_device, string in_tag) {
	kis_tracked_device *dev = FetchDevice(in_device);
	kis_device_common *com = NULL;
	Kis_Phy_Handler *handler = FetchPhyHandler(in_device.GetPhy());

	if (handler == NULL)
		return -1;

	if (dev == NULL)
		return -1;

	if ((com = (kis_device_common *) dev->fetch(devcomp_ref_common)) == NULL)
		return -1;

	map<string, kis_tag_data *>::iterator si;

	if ((si = com->arb_tag_map.find(in_tag)) != com->arb_tag_map.end()) {
		// Set the content to "" so the client gets an update
		si->second->value = "";
		si->second->dirty = true;

		if (dev->dirty == 0) {
			dev->dirty = 1;
			dirty_device_vec.push_back(dev);
		}

		string tag = handler->FetchPhyName() + in_device.Mac2String();

		vector<string> tfl = tag_conf->FetchOptVec(tag);
		vector<smart_word_token> tflp;

		for (unsigned int x = 0; x < tfl.size(); x++) {
			tflp = NetStrTokenize(tfl[x], ",");

			if (tflp.size() != 2)
				continue;

			if (tflp[0].word == in_tag) {
				tfl.erase(tfl.begin() + x);
				tag_conf->SetOptVec(tag, tfl, globalreg->timestamp.tv_sec);
				break;
			}
		}
	}

	return 0;
}

string Devicetracker::FetchDeviceTag(mac_addr in_device, string in_tag) {
	kis_tracked_device *dev = FetchDevice(in_device);
	kis_device_common *com = NULL;

	if (dev == NULL)
		return "";

	if ((com = (kis_device_common *) dev->fetch(devcomp_ref_common)) == NULL)
		return "";

	map<string, kis_tag_data *>::iterator si;

	if ((si = com->arb_tag_map.find(in_tag)) != com->arb_tag_map.end()) {
		if (si->second == NULL)
			return "";

		return si->second->value;
	}

	return "";
}

