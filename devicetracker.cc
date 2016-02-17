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
#include "devicetracker_component.h"
#include "msgpack_adapter.h"

int Devicetracker_packethook_stringcollector(CHAINCALL_PARMS) {
	return ((Devicetracker *) auxdata)->StringCollector(in_pack);
}

int Devicetracker_packethook_commontracker(CHAINCALL_PARMS) {
	return ((Devicetracker *) auxdata)->CommonTracker(in_pack);
}

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) {
    pthread_mutex_init(&devicelist_mutex, NULL);

	globalreg = in_globalreg;

	globalreg->InsertGlobal("DEVICE_TRACKER", this);

    device_base_id = 
        globalreg->entrytracker->RegisterField("kismet.device.base", TrackerMac,
                "core device record");

    phy_base_id =
        globalreg->entrytracker->RegisterField("kismet.phy.list", TrackerVector,
                "list of phys");

    phy_entry_id =
        globalreg->entrytracker->RegisterField("kismet.phy.entry", TrackerMac,
                "phy entry");

    device_summary_base_id =
        globalreg->entrytracker->RegisterField("kismet.device.list", TrackerVector,
                "list of devices");
    device_summary_entry_id =
        globalreg->entrytracker->RegisterField("kismet.device.summary", TrackerMac,
                "device summary");

	next_componentid = 0;
	num_packets = num_datapackets = num_errorpackets = 
		num_filterpackets = num_packetdelta = 0;

	conf_save = 0;
	next_phy_id = 0;

    timerid =
        globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, this); 

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

	// Create the global kistxt and kisxml logfiles
	new Dumpfile_Devicetracker(globalreg, "kistxt", "text");
	new Dumpfile_Devicetracker(globalreg, "kisxml", "xml");

	// Set up the persistent tag conf file
	// Build the config file
	conf_save = globalreg->timestamp.tv_sec;

	tag_conf = new ConfigFile(globalreg);
	tag_conf->ParseConfig(
            tag_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") + 
                "/" + "tag.conf", "", "", 0, 1).c_str());


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

string Devicetracker::FetchPhyName(int in_phy) {
    if (in_phy == KIS_PHY_ANY) {
        return "ANY";
    }

    Kis_Phy_Handler *phyh = FetchPhyHandler(in_phy);

    if (phyh == NULL) {
        return "UNKNOWN";
    }

    return phyh->FetchPhyName();
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

int Devicetracker::timetracker_event(int event_id __attribute__((unused))) {
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
	for (map<int, vector<kis_tracked_device_base *> *>::iterator x = 
            phy_dirty_vec.begin();
		 x != phy_dirty_vec.end(); ++x) {
		x->second->clear();
	}

	for (unsigned int x = 0; x < dirty_device_vec.size(); x++) {
#if 0
        string fname = "/tmp/kismet/" + dirty_device_vec[x]->get_key().Mac2String();

        printf("debug - attempting to serialize to %s\n", fname.c_str());

        std::stringstream buffer;
        MsgpackAdapter::Pack(globalreg, buffer, 
                (TrackerElement *) dirty_device_vec[x]);

        FILE *f = fopen(fname.c_str(), "wb");

        fwrite(buffer.str().c_str(), buffer.str().length(), 1, f);
        fflush(f);
        fclose(f);
#endif
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

    // TODO aggregate to local string buffer instead for querying
#if 0
	kis_proto_string_info si;

	si.device = devinfo->devref->get_key();
	si.phy = devinfo->devref->get_phytype();
	si.source = common->source;
	si.dest = common->dest;

	for (unsigned int x = 0; x < strings->extracted_strings.size(); x++) {
		si.stringdata = strings->extracted_strings[x];
	
		globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_STRING), (void *) &si);
	}
#endif

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
        device = new kis_tracked_device_base(globalreg, device_base_id);

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

    // Simple fixed URLS
    
    if (strcmp(path, "/devices/msgpack/all_devices") == 0)
        return true;

    if (strcmp(path, "/phy/msgpack/all_phys") == 0)
        return true;

    // Split URL and process
    vector<string> tokenurl = StrTokenize(path, "/");
    if (tokenurl.size() < 2)
        return false;

    if (tokenurl[1] == "devices") {
        if (tokenurl.size() < 4)
            return false;
        if (tokenurl[2] == "msgpack") {
            devicelist_mutex_locker(this);
            
            if (tracked_map.find(mac_addr(tokenurl[3])) != tracked_map.end()) {
                return true;
            } else {
                return false;
            }
        }
    }

    return false;
}

void Devicetracker::httpd_msgpack_all_phys(std::stringstream &stream) {
    TrackerElement *phyvec =
        globalreg->entrytracker->GetTrackedInstance(phy_base_id);

    kis_tracked_phy *anyphy = new kis_tracked_phy(globalreg, phy_base_id);
    anyphy->set_from_phy(this, KIS_PHY_ANY);
    phyvec->add_vector(anyphy);

    map<int, Kis_Phy_Handler *>::iterator mi;
    for (mi = phy_handler_map.begin(); mi != phy_handler_map.end(); ++mi) {
        kis_tracked_phy *p = new kis_tracked_phy(globalreg, phy_base_id);
        p->set_from_phy(this, mi->first);
        phyvec->add_vector(p);
    }

    MsgpackAdapter::Pack(globalreg, stream, phyvec);

    delete(phyvec);
}

void Devicetracker::httpd_msgpack_device_summary(std::stringstream &stream) {
    devicelist_mutex_locker(this);

    TrackerElement *devvec =
        globalreg->entrytracker->GetTrackedInstance(device_summary_base_id);

    for (unsigned int x = 0; x < tracked_vec.size(); x++) {
        kis_tracked_device_summary *summary =
            new kis_tracked_device_summary(globalreg, device_summary_entry_id,
                    tracked_vec[x]);
        devvec->add_vector(summary);
    }

    MsgpackAdapter::Pack(globalreg, stream, devvec);

    delete(devvec);
}

void Devicetracker::CreateStreamResponse(struct MHD_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(path, "/devices/msgpack/all_devices") == 0) {
        httpd_msgpack_device_summary(stream);
        return;
    }

    if (strcmp(path, "/phy/msgpack/all_phys") == 0) {
        httpd_msgpack_all_phys(stream);
        return;
    }

    vector<string> tokenurl = StrTokenize(path, "/");

    if (tokenurl.size() < 2)
        return;

    if (tokenurl[1] == "devices") {
        if (tokenurl.size() < 4)
            return;
        if (tokenurl[2] == "msgpack") {
            devicelist_mutex_locker(this);
           
            map<mac_addr, kis_tracked_device_base *>::iterator itr;

            if ((itr = tracked_map.find(mac_addr(tokenurl[3]))) != tracked_map.end()) {

                MsgpackAdapter::Pack(globalreg, stream, (TrackerElement *) itr->second);

                return;
            } else {
                return;
            }
        }
    }

}


