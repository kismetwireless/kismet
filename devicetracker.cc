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

#include <memory>

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>

#ifdef HAVE_GNU_PARALLEL
#include <parallel/algorithm>
#endif

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
#include "gps_manager.h"
#include "alertracker.h"
#include "manuf.h"
#include "packetsourcetracker.h"
#include "packetsource.h"
#include "dumpfile_devicetracker.h"
#include "entrytracker.h"
#include "devicetracker_component.h"
#include "msgpack_adapter.h"
#include "xmlserialize_adapter.h"
#include "json_adapter.h"
#include "structured.h"
#include "kismet_json.h"
#include "base64.h"

// Use parallel sorts if we can for threading boost
#ifdef HAVE_GNU_PARALLEL
#define kismet__sort __gnu_parallel::sort
#else
#define kismet__sort std::sort
#endif

int Devicetracker_packethook_commontracker(CHAINCALL_PARMS) {
	return ((Devicetracker *) auxdata)->CommonTracker(in_pack);
}

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_Stream_Handler(in_globalreg) {

    // Initialize as recursive to allow multiple locks in a single thread
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&devicelist_mutex, &mutexattr);

	globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    device_base_id =
        entrytracker->RegisterField("kismet.device.base", TrackerMac,
                "core device record");
    device_list_base_id =
        entrytracker->RegisterField("kismet.device.list",
                TrackerVector, "list of devices");

    phy_base_id =
        entrytracker->RegisterField("kismet.phy.list", TrackerVector,
                "list of phys");

    phy_entry_id =
        entrytracker->RegisterField("kismet.phy.entry", TrackerMac,
                "phy entry");

    device_summary_base_id =
        entrytracker->RegisterField("kismet.device.summary_list",
                TrackerVector, "summary list of devices");

    device_update_required_id =
        entrytracker->RegisterField("kismet.devicelist.refresh",
                TrackerUInt8, "device list refresh recommended");
    device_update_timestamp_id =
        entrytracker->RegisterField("kismet.devicelist.timestamp",
                TrackerInt64, "device list timestamp");

    // These need unique IDs to be put in the map for serialization.
    // They also need unique field names, we can rename them with setlocalname
    dt_length_id =
        entrytracker->RegisterField("kismet.datatables.recordsTotal", TrackerUInt64, 
                "datatable records total");
    dt_filter_id =
        entrytracker->RegisterField("kismet.datatables.recordsFiltered", TrackerUInt64,
                "datatable records filtered");
    dt_draw_id =
        entrytracker->RegisterField("kismet.datatables.draw", TrackerUInt64,
                "Datatable records draw ID");

    packets_rrd.reset(new kis_tracked_rrd<>(globalreg, 0));
    packets_rrd_id =
        globalreg->entrytracker->RegisterField("kismet.device.packets_rrd",
                packets_rrd, "RRD of total packets seen");

	num_packets = num_datapackets = num_errorpackets =
		num_filterpackets = 0;

	conf_save = 0;
	next_phy_id = 0;

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

	// Create the global kistxt and kisxml logfiles
	// new Dumpfile_Devicetracker(globalreg, "kistxt", "text");
	// new Dumpfile_Devicetracker(globalreg, "kisxml", "xml");

	// Set up the persistent tag conf file
	// Build the config file
	conf_save = globalreg->timestamp.tv_sec;

	tag_conf = new ConfigFile(globalreg);
	tag_conf->ParseConfig(
            tag_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") +
                "/" + "tag.conf", "", "", 0, 1).c_str());

    // Set up the device timeout
    device_idle_expiration =
        globalreg->kismet_config->FetchOptInt("tracker_device_timeout", 0);

    if (device_idle_expiration != 0) {
        stringstream ss;
        ss << "Removing tracked devices which have been inactive for more than " <<
            device_idle_expiration << " seconds.";
        _MSG(ss.str(), MSGFLAG_INFO);

		// Schedule device idle reaping every minute
        device_idle_timer =
            globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 60, NULL,
                1, this);
    } else {
        device_idle_timer = -1;
    }

	max_num_devices =
		globalreg->kismet_config->FetchOptUInt("tracker_max_devices", 0);

	if (max_num_devices > 0) {
		stringstream ss;
		ss << "Limiting maximum number of devices to " << max_num_devices <<
			" older devices will be removed from tracking when this limit is reached.";
		_MSG(ss.str(), MSGFLAG_INFO);

		// Schedule max device reaping every 5 seconds
		max_devices_timer =
			globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5, NULL,
				1, this);
	} else {
		max_devices_timer = -1;
	}

    full_refresh_time = globalreg->timestamp.tv_sec;
}

Devicetracker::~Devicetracker() {
    pthread_mutex_lock(&devicelist_mutex);

    globalreg->devicetracker = NULL;
    globalreg->RemoveGlobal("DEVICE_TRACKER");

	globalreg->packetchain->RemoveHandler(&Devicetracker_packethook_commontracker,
										  CHAINPOS_TRACKER);

    globalreg->timetracker->RemoveTimer(device_idle_timer);
	globalreg->timetracker->RemoveTimer(max_devices_timer);

    // TODO broken for now
    /*
	if (track_filter != NULL)
		delete track_filter;
    */

    for (map<int, Kis_Phy_Handler *>::iterator p = phy_handler_map.begin();
            p != phy_handler_map.end(); ++p) {
        delete p->second;
    }

    tracked_vec.clear();

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

Kis_Phy_Handler *Devicetracker::FetchPhyHandler(int in_phy) {
	map<int, Kis_Phy_Handler *>::iterator i = phy_handler_map.find(in_phy);

	if (i == phy_handler_map.end())
		return NULL;

	return i->second;
}

Kis_Phy_Handler *Devicetracker::FetchPhyHandler(uint64_t in_key) {
    return FetchPhyHandler(DevicetrackerKey::GetPhy(in_key));
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
    local_locker lock(&devicelist_mutex);

	int r = 0;

	if (in_phy == KIS_PHY_ANY)
		return tracked_map.size();

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (DevicetrackerKey::GetPhy(tracked_vec[x]->get_key()) == in_phy)
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
        int phytype = DevicetrackerKey::GetPhy(tracked_vec[x]->get_key());
		if (phytype == in_phy || in_phy == KIS_PHY_ANY) {
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

int Devicetracker::RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler) {
	int num = next_phy_id++;

	Kis_Phy_Handler *strongphy =
		in_weak_handler->CreatePhyHandler(globalreg, this, num);

	phy_handler_map[num] = strongphy;

	phy_packets[num] = 0;
	phy_datapackets[num] = 0;
	phy_errorpackets[num] = 0;
	phy_filterpackets[num] = 0;

	_MSG("Registered PHY handler '" + strongphy->FetchPhyName() + "' as ID " +
		 IntToString(num), MSGFLAG_INFO);

	return num;
}

void Devicetracker::UpdateFullRefresh() {
    full_refresh_time = globalreg->timestamp.tv_sec;
}

shared_ptr<kis_tracked_device_base> Devicetracker::FetchDevice(uint64_t in_key) {
    local_locker lock(&devicelist_mutex);

	device_itr i = tracked_map.find(in_key);

	if (i != tracked_map.end())
		return i->second;

	return NULL;
}

shared_ptr<kis_tracked_device_base> Devicetracker::FetchDevice(mac_addr in_device,
        unsigned int in_phy) {
	return FetchDevice(DevicetrackerKey::MakeKey(in_device, in_phy));
}

int Devicetracker::CommonTracker(kis_packet *in_pack) {
    local_locker lock(&devicelist_mutex);

	kis_common_info *pack_common =
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	kis_ref_capsource *pack_capsrc =
		(kis_ref_capsource *) in_pack->fetch(pack_comp_capsrc);

    packets_rrd->add_sample(1, globalreg->timestamp.tv_sec);

	num_packets++;

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

    // This is all moved to phys doing smart things
#if 0
	// If we dont' have a device mac, don't make a record
	if (pack_common->device == 0)
		return 0;

	mac_addr devmac = pack_common->device;

	// If we don't have a usable mac, bail.
	// TODO maybe change this in the future?  It's kind of phy dependent
	if (devmac == globalreg->empty_mac)
		return 0;

	kis_tracked_device_base *device = NULL;

	// Make a new device or fetch an existing one
	device = BuildDevice(devmac, in_pack);

	if (device == NULL)
		return 0;

	// Push our common data into it
	PopulateCommon(device, in_pack);
#endif
	return 1;
}

// This function handles populating the base common info about a device.
// Specific info should be populated by the phy handler.
shared_ptr<kis_tracked_device_base> Devicetracker::UpdateCommonDevice(mac_addr in_mac,
        int in_phy, kis_packet *in_pack, unsigned int in_flags) {

    local_locker lock(&devicelist_mutex);

    stringstream sstr;

	kis_layer1_packinfo *pack_l1info =
		(kis_layer1_packinfo *) in_pack->fetch(pack_comp_radiodata);
	kis_gps_packinfo *pack_gpsinfo =
		(kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);
	kis_ref_capsource *pack_capsrc =
		(kis_ref_capsource *) in_pack->fetch(pack_comp_capsrc);
	kis_common_info *pack_common =
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	shared_ptr<kis_tracked_device_base> device = NULL;
    Kis_Phy_Handler *phy = NULL;
    uint64_t key = 0;

    if ((phy = FetchPhyHandler(in_phy)) == NULL) {
        sstr << "Got packet for phy id " << in_phy << " but no handler " <<
            "found for this phy.";
        _MSG(sstr.str(), MSGFLAG_ERROR);
    }

    key = DevicetrackerKey::MakeKey(in_mac, in_phy);

	if ((device = FetchDevice(key)) == NULL) {
        device.reset(new kis_tracked_device_base(globalreg, device_base_id));

        device->set_key(key);
        device->set_macaddr(in_mac);
        device->set_phyname(phy->FetchPhyName());

        tracked_map[device->get_key()] = device;
        tracked_vec.push_back(device);

        device->set_first_time(in_pack->ts.tv_sec);

        if (globalreg->manufdb != NULL)
            device->set_manuf(globalreg->manufdb->LookupOUI(device->get_macaddr()));
    }

    device->set_last_time(in_pack->ts.tv_sec);

    if (in_flags & UCD_UPDATE_PACKETS) {
        device->inc_packets();

        device->get_packets_rrd()->add_sample(1, globalreg->timestamp.tv_sec);

        if (pack_common != NULL) {
            if (pack_common->error)
                device->inc_error_packets();

            if (pack_common->type == packet_basic_data) {
                // TODO fix directional data
                device->inc_data_packets();
                device->inc_datasize(pack_common->datasize);
                device->get_data_rrd()->add_sample(pack_common->datasize,
                        globalreg->timestamp.tv_sec);

                if (pack_common->datasize <= 250)
                    device->get_packet_rrd_bin_250()->add_sample(1, 
                            globalreg->timestamp.tv_sec);
                else if (pack_common->datasize <= 500)
                    device->get_packet_rrd_bin_500()->add_sample(1, 
                            globalreg->timestamp.tv_sec);
                else if (pack_common->datasize <= 1000)
                    device->get_packet_rrd_bin_1000()->add_sample(1, 
                            globalreg->timestamp.tv_sec);
                else if (pack_common->datasize <= 1500)
                    device->get_packet_rrd_bin_1500()->add_sample(1, 
                            globalreg->timestamp.tv_sec);
                else 
                    device->get_packet_rrd_bin_jumbo()->add_sample(1, 
                            globalreg->timestamp.tv_sec);

            } else if (pack_common->type == packet_basic_mgmt ||
                    pack_common->type == packet_basic_phy) {
                device->inc_llc_packets();
            }

        }
    }

	if ((in_flags & UCD_UPDATE_FREQUENCIES)) {
        if (pack_l1info != NULL) {
            if (!(pack_l1info->channel == "0"))
                device->set_channel(pack_l1info->channel);
            if (pack_l1info->freq_khz != 0)
                device->set_frequency(pack_l1info->freq_khz);

            Packinfo_Sig_Combo *sc = new Packinfo_Sig_Combo(pack_l1info, pack_gpsinfo);
            (*(device->get_signal_data())) += *sc;

            delete(sc);

            device->inc_frequency_count((int) pack_l1info->freq_khz);
        } else {
            if (!(pack_common->channel == "0"))
                device->set_channel(pack_common->channel);
            if (pack_common->freq_khz != 0)
                device->set_frequency(pack_common->freq_khz);
            
            device->inc_frequency_count((int) pack_common->freq_khz);
        }
	}

	if ((in_flags & UCD_UPDATE_FREQUENCIES) && pack_common != NULL) {
        if (!(pack_common->channel == "0"))
            device->set_channel(pack_common->channel);
    }

    if ((in_flags & UCD_UPDATE_LOCATION) && pack_gpsinfo != NULL) {
        device->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix);
    }

	// Update seenby records for time, frequency, packets
	if ((in_flags & UCD_UPDATE_SEENBY) && pack_capsrc != NULL) {
        double f = -1;

        if (pack_l1info != NULL)
            f = pack_l1info->freq_khz;

        device->inc_seenby_count(pack_capsrc->ref_source, in_pack->ts.tv_sec, f);
	}

    return device;
}

int Devicetracker::PopulateCommon(shared_ptr<kis_tracked_device_base> device, 
        kis_packet *in_pack) {

    local_locker lock(&devicelist_mutex);

	kis_common_info *pack_common =
		(kis_common_info *) in_pack->fetch(pack_comp_common);
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

    // device->set_first_time(in_pack->ts.tv_sec);

    if (globalreg->manufdb != NULL)
        device->set_manuf(globalreg->manufdb->LookupOUI(device->get_macaddr()));

    // Set name
    device->set_devicename(device->get_macaddr().Mac2String());

    /* Persistent tag loading removed, will be handled by serializing network in the future */

    device->inc_packets();

    device->get_packets_rrd()->add_sample(1, globalreg->timestamp.tv_sec);

    device->set_last_time(in_pack->ts.tv_sec);

	if (pack_common->error)
        device->inc_error_packets();

	if (pack_common->type == packet_basic_data) {
        // TODO fix directional data
        device->inc_data_packets();
        device->inc_datasize(pack_common->datasize);
        device->get_data_rrd()->add_sample(pack_common->datasize,
                globalreg->timestamp.tv_sec);

        if (pack_common->datasize <= 250) {
            device->get_packet_rrd_bin_250()->add_sample(1, globalreg->timestamp.tv_sec);
        } else if (pack_common->datasize <= 500) {
            device->get_packet_rrd_bin_500()->add_sample(1, globalreg->timestamp.tv_sec);
        } else if (pack_common->datasize <= 1000) {
            device->get_packet_rrd_bin_1000()->add_sample(1, globalreg->timestamp.tv_sec);
        } else if (pack_common->datasize <= 1500) {
            device->get_packet_rrd_bin_1500()->add_sample(1, globalreg->timestamp.tv_sec);
        } else if (pack_common->datasize > 1500 ) {
            device->get_packet_rrd_bin_jumbo()->add_sample(1, globalreg->timestamp.tv_sec);
        }

	} else if (pack_common->type == packet_basic_mgmt ||
			   pack_common->type == packet_basic_phy) {
        device->inc_llc_packets();
	}

	if (pack_l1info != NULL) {
		if (!(pack_l1info->channel == "0"))
            device->set_channel(pack_l1info->channel);
		if (pack_l1info->freq_khz != 0)
            device->set_frequency(pack_l1info->freq_khz);

		Packinfo_Sig_Combo *sc = new Packinfo_Sig_Combo(pack_l1info, pack_gpsinfo);
        (*(device->get_signal_data())) += *sc;

		delete(sc);

        device->inc_frequency_count((int) pack_l1info->freq_khz);
	}

    if (pack_gpsinfo != NULL) {
        device->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix);
    }

	// Update seenby records for time, frequency, packets
	if (pack_capsrc != NULL) {
        int f = -1;

        if (pack_l1info != NULL)
            f = pack_l1info->freq_khz;

        device->inc_seenby_count(pack_capsrc->ref_source, in_pack->ts.tv_sec, f);
	}

    device->add_basic_crypt(pack_common->basic_crypt_set);

	if (!(pack_common->channel == "0"))
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
	shared_ptr<Packetsourcetracker> pst =
		static_pointer_cast<Packetsourcetracker>(globalreg->FetchGlobal("PACKETSOURCE_TRACKER"));

	// Punt and die, better than segv
	if (pst == NULL) {
		_MSG("Devicetracker XML log - packetsourcetracker vanished!", MSGFLAG_ERROR);
		return;
	}

#if 0
	GpsWrapper *gpsw =
		(GpsWrapper *) globalreg->FetchGlobal("GPSWRAPPER");

	if (gpsw == NULL) {
		_MSG("Devicetracker XML log - gpswrapper vanished!", MSGFLAG_ERROR);
		return;
	}
#endif

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

#if 0
	fprintf(in_logfile,
			"<gpsDevices>\n"
			"<gpsDevice>\n"
			"<device>%s</device>\n"
			"<type>%s</type>\n"
			"</gpsDevice>\n"
			"</gpsDevices>\n",
			SanitizeXML(gpsw->FetchDevice()).c_str(),
			SanitizeXML(gpsw->FetchType()).c_str());
#endif

	vector<kis_tracked_device_base *> *devlist = NULL;// = FetchDevices(KIS_PHY_ANY);

	if (devlist->size() > 0)
		fprintf(in_logfile, "<devices>\n");

	for (unsigned int x = 0; x < devlist->size(); x++) {
		kis_tracked_device_base *dev = (*devlist)[x];
		Kis_Phy_Handler *phy = FetchPhyHandler(dev->get_key());

		if (phy == NULL)
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

        SharedTrackerElement seenby_map = dev->get_seenby_map();

        if (seenby_map->size() > 0)
			fprintf(in_logfile, "<seenBySources>\n");

        for (TrackerElement::map_const_iterator si = seenby_map->begin();
                si != seenby_map->end(); ++si) {
            shared_ptr<kis_tracked_seenby_data> sbd = 
                static_pointer_cast<kis_tracked_seenby_data>(si->second);

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

#if 0
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
#endif

			fprintf(in_logfile, "</seenBySource>\n");
		}

        if (seenby_map->size() > 0)
			fprintf(in_logfile, "</seenBySources>\n");

        shared_ptr<kis_tracked_location> location = dev->get_location();
        shared_ptr<kis_tracked_signal_data> snrdata = dev->get_signal_data();

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

            shared_ptr<kis_tracked_location_triplet> peak_location = snrdata->get_peak_loc();

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
                dev->get_datasize());

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
	shared_ptr<Packetsourcetracker> pst =
        static_pointer_cast<Packetsourcetracker>(globalreg->FetchGlobal("PACKETSOURCE_TRACKER"));

	// Punt and die, better than segv
	if (pst == NULL) {
		_MSG("Devicetracker TXT log - packetsourcetracker vanished!", MSGFLAG_ERROR);
		return;
	}

#if 0
	GpsWrapper *gpsw =
		(GpsWrapper *) globalreg->FetchGlobal("GPSWRAPPER");

	if (gpsw == NULL) {
		_MSG("Devicetracker TXT log - gpswrapper vanished!", MSGFLAG_ERROR);
		return;
	}
#endif

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

#if 0
	if (gpsw != NULL) {
		fprintf(in_logfile, "GPS device: %s\n",
				gpsw->FetchDevice().c_str());
		fprintf(in_logfile, "GPS type: %s\n",
				gpsw->FetchType().c_str());
	} else {
		fprintf(in_logfile, "GPS device: None\n");
	}
	fprintf(in_logfile, "\n");
#endif

	vector<kis_tracked_device_base *> *devlist = NULL; // = FetchDevices(KIS_PHY_ANY);

	if (devlist->size() > 0)
		fprintf(in_logfile, "Devices:\n");

	for (unsigned int x = 0; x < devlist->size(); x++) {
		kis_tracked_device_base *dev = (*devlist)[x];
		Kis_Phy_Handler *phy = FetchPhyHandler(dev->get_key());

		fprintf(in_logfile,
				" Device MAC: %s\n",
                dev->get_mac().Mac2String().c_str());

		if (phy == NULL)
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

        SharedTrackerElement seenby_map = dev->get_seenby_map();

		if (seenby_map->size() > 0)
			fprintf(in_logfile, " Seen by capture sources:\n");

        for (TrackerElement::map_const_iterator si = seenby_map->begin();
                si != seenby_map->end(); ++si) {
            shared_ptr<kis_tracked_seenby_data> sbd = 
                static_pointer_cast<kis_tracked_seenby_data>(si->second);

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

#if 0
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
#endif

			fprintf(in_logfile, "\n");
		}

        shared_ptr<kis_tracked_location> location = dev->get_location();
        shared_ptr<kis_tracked_signal_data> snrdata = dev->get_signal_data();

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

            shared_ptr<kis_tracked_location_triplet> peak_location = snrdata->get_peak_loc();

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
                dev->get_datasize());

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

#if 0
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
	// Kis_Phy_Handler *handler = FetchPhyHandler(in_device.GetPhy());

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
#endif

// HTTP interfaces
bool Devicetracker::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        // Simple fixed URLS

        string stripped = Httpd_StripSuffix(path);
        bool can_serialize = Httpd_CanSerialize(path);

        if (stripped == "/devices/all_devices" && can_serialize)
            return true;

        if (stripped == "/devices/all_devices_dt" && can_serialize)
            return true;

        if (strcmp(path, "/devices/all_devices.xml") == 0)
            return true;

        if (stripped == "/phy/all_phys" && can_serialize)
            return true;

        if (stripped == "/phy/all_phys_dt" && can_serialize)
            return true;

        // Split URL and process
        vector<string> tokenurl = StrTokenize(path, "/");
        if (tokenurl.size() < 2)
            return false;

        if (tokenurl[1] == "devices") {
            if (tokenurl.size() < 3)
                return false;

            // Do a by-key lookup and return the device or the device path
            if (tokenurl[2] == "by-key") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                local_locker lock(&devicelist_mutex);

                uint64_t key = 0;
                std::stringstream ss(tokenurl[3]);
                ss >> key;

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                map<uint64_t, shared_ptr<kis_tracked_device_base> >::iterator tmi =
                    tracked_map.find(key);
                if (tmi != tracked_map.end()) {
                    // Try to find the exact field
                    if (tokenurl.size() > 5) {
                        vector<string>::const_iterator first = tokenurl.begin() + 5;
                        vector<string>::const_iterator last = tokenurl.end();
                        vector<string> fpath(first, last);

                        if (tmi->second->get_child_path(fpath) == NULL) {
                            return false;
                        }
                    }

                    return true;
                } else {
                    return false;
                }
            } else if (tokenurl[2] == "by-mac") {
                if (tokenurl.size() < 5)
                    return false;

                local_locker lock(&devicelist_mutex);

                if (!Httpd_CanSerialize(tokenurl[4]))
                    return false;

                mac_addr mac = mac_addr(tokenurl[3]);

                if (mac.error) {
                    return false;
                }

                // Try to find the actual mac
                vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
                for (vi = tracked_vec.begin(); vi != tracked_vec.end(); ++vi) {
                    if ((*vi)->get_macaddr() == mac) {
                        return true;
                    }
                }

                return false;
            } else if (tokenurl[2] == "last-time") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                long lastts;
                if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1) {
                    return false;
                }

                return Httpd_CanSerialize(tokenurl[4]);
            }
        }
    } else if (strcmp(method, "POST") == 0) {
        // Split URL and process
        vector<string> tokenurl = StrTokenize(path, "/");
        if (tokenurl.size() < 2)
            return false;

        if (tokenurl[1] == "devices") {
            if (tokenurl.size() < 4)
                return false;

            if (tokenurl[2] == "summary") {
                return Httpd_CanSerialize(tokenurl[3]);
            }

            if (tokenurl[2] == "last-time") {
                if (tokenurl.size() < 5) {
                    return false;
                }

                long lastts;
                if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1) {
                    return false;
                }

                return Httpd_CanSerialize(tokenurl[4]);
            }
        }
    }

    return false;
}

void Devicetracker::httpd_all_phys(string path, std::stringstream &stream,
        string in_wrapper_key) {

    SharedTrackerElement phyvec =
        globalreg->entrytracker->GetTrackedInstance(phy_base_id);

    SharedTrackerElement wrapper = NULL;

    if (in_wrapper_key != "") {
        wrapper.reset(new TrackerElement(TrackerMap));
        wrapper->add_map(phyvec);
        phyvec->set_local_name(in_wrapper_key);
    } else {
        wrapper = phyvec;
    }

    shared_ptr<kis_tracked_phy> anyphy(new kis_tracked_phy(globalreg, phy_base_id));
    anyphy->set_from_phy(this, KIS_PHY_ANY);
    phyvec->add_vector(anyphy);

    map<int, Kis_Phy_Handler *>::iterator mi;
    for (mi = phy_handler_map.begin(); mi != phy_handler_map.end(); ++mi) {
        shared_ptr<kis_tracked_phy> p(new kis_tracked_phy(globalreg, phy_base_id));
        p->set_from_phy(this, mi->first);
        phyvec->add_vector(p);
    }

    Httpd_Serialize(path, stream, wrapper);
}

void Devicetracker::httpd_device_summary(string url, std::stringstream &stream, 
        shared_ptr<TrackerElementVector> subvec, 
        vector<TrackerElementSummary> summary_vec,
        string in_wrapper_key) {

    local_locker lock(&devicelist_mutex);

    SharedTrackerElement devvec =
        globalreg->entrytracker->GetTrackedInstance(device_summary_base_id);

    TrackerElementSerializer::rename_map rename_map;

    // Wrap the dev vec in a dictionary and change its name
    SharedTrackerElement wrapper = NULL;

    if (in_wrapper_key != "") {
        wrapper.reset(new TrackerElement(TrackerMap));
        wrapper->add_map(devvec);
        devvec->set_local_name(in_wrapper_key);
    } else {
        wrapper = devvec;
    }

    if (subvec == NULL) {
        for (unsigned int x = 0; x < tracked_vec.size(); x++) {
            if (summary_vec.size() == 0) {
                devvec->add_vector(tracked_vec[x]);
            } else {
                SharedTrackerElement simple;

                SummarizeTrackerElement(entrytracker, tracked_vec[x], 
                        summary_vec, simple, rename_map);

                devvec->add_vector(simple);
            }
        }
    } else {
        for (TrackerElementVector::const_iterator x = subvec->begin();
                x != subvec->end(); ++x) {
            if (summary_vec.size() == 0) {
                devvec->add_vector(*x);
            } else {
                SharedTrackerElement simple;

                SummarizeTrackerElement(entrytracker, *x, 
                        summary_vec, simple, rename_map);

                devvec->add_vector(simple);
            }
        }
    }

    Httpd_Serialize(url, stream, wrapper, &rename_map);
}

void Devicetracker::httpd_xml_device_summary(std::stringstream &stream) {
    local_locker lock(&devicelist_mutex);

    SharedTrackerElement devvec =
        globalreg->entrytracker->GetTrackedInstance(device_summary_base_id);

    for (unsigned int x = 0; x < tracked_vec.size(); x++) {
        devvec->add_vector(tracked_vec[x]);
    }

    XmlserializeAdapter *xml = new XmlserializeAdapter(globalreg);

    xml->RegisterField("kismet.device.list", "SummaryDevices");
    xml->RegisterFieldNamespace("kismet.device.list",
            "k",
            "http://www.kismetwireless.net/xml/summary",
            "http://www.kismetwireless.net/xml/summary.xsd");
    xml->RegisterFieldSchema("kismet.device.list",
            "common",
            "http://www.kismetwireless.net/xml/common",
            "http://www.kismetwireless.net/xml/common.xsd");
    xml->RegisterFieldSchema("kismet.device.list",
            "gps",
            "http://www.kismetwireless.net/xml/gps",
            "http://www.kismetwireless.net/xml/gps.xsd");


    xml->RegisterField("kismet.device.summary", "summary");

    xml->RegisterField("kismet.device.base.name", "name");
    xml->RegisterField("kismet.device.base.phyname", "phyname");
    xml->RegisterField("kismet.device.base.signal", "signal");
    xml->RegisterField("kismet.device.base.channel", "channel");
    xml->RegisterField("kismet.device.base.frequency", "frequency");
    xml->RegisterField("kismet.device.base.manuf", "manufacturer");
    xml->RegisterField("kismet.device.base.key", "key");
    xml->RegisterField("kismet.device.base.macaddr", "macaddress");
    xml->RegisterField("kismet.device.base.type", "type");
    xml->RegisterField("kismet.device.base.first_time", "firstseen");
    xml->RegisterField("kismet.device.base.last_time", "lastseen");
    xml->RegisterField("kismet.device.base.packets.total", "packetstotal");

    xml->RegisterField("kismet.common.signal.last_signal_dbm", "lastsignaldbm");
    xml->RegisterField("kismet.common.signal.min_signal_dbm", "minsignaldbm");
    xml->RegisterField("kismet.common.signal.max_signal_dbm", "maxsignaldbm");
    xml->RegisterField("kismet.common.signal.last_noise_dbm", "lastnoisedbm");
    xml->RegisterField("kismet.common.signal.min_noise_dbm", "minnoisedbm");
    xml->RegisterField("kismet.common.signal.max_noise_dbm", "maxnoisedbm");
    xml->RegisterField("kismet.common.signal.last_signal_rssi", "lastsignalrssi");
    xml->RegisterField("kismet.common.signal.min_signal_rssi", "minsignalrssi");
    xml->RegisterField("kismet.common.signal.max_signal_rssi", "maxsignalrssi");
    xml->RegisterField("kismet.common.signal.last_noise_rssi", "lastnoiserssi");
    xml->RegisterField("kismet.common.signal.min_noise_rssi", "minnoiserssi");
    xml->RegisterField("kismet.common.signal.max_noise_rssi", "maxnoiserssi");

    xml->RegisterField("kismet.common.signal.peak_loc", "peaklocation");
    xml->RegisterFieldXsitype("kismet.common.signal.peak_loc", "kismet:location");

    xml->RegisterField("kismet.common.location.lat", "lat");
    xml->RegisterField("kismet.common.location.lon", "lon");
    xml->RegisterField("kismet.common.location.alt", "alt");
    xml->RegisterField("kismet.common.location.speed", "speed");

    stream << "<?xml version=\"1.0\"?>";

    xml->XmlSerialize(devvec, stream);

    delete(xml);
}

void Devicetracker::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        struct MHD_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    string stripped = Httpd_StripSuffix(path);

    if (stripped == "/devices/all_devices") {
        httpd_device_summary(path, stream, NULL, vector<TrackerElementSummary>());
        return;
    }

    if (stripped == "/devices/all_devices_dt") {
        httpd_device_summary(path, stream, NULL, 
                vector<TrackerElementSummary>(), "aaData");
        return;
    }

    // XML is special right now
    if (strcmp(path, "/devices/all_devices.xml") == 0) {
        httpd_xml_device_summary(stream);
        return;
    }

    if (stripped == "/phy/all_phys") {
        httpd_all_phys(path, stream);
    }

    if (stripped == "/phy/all_phys_dt") {
        httpd_all_phys(path, stream, "aaData");
    }

    vector<string> tokenurl = StrTokenize(path, "/");

    if (tokenurl.size() < 2)
        return;

    if (tokenurl[1] == "devices") {
        if (tokenurl.size() < 5)
            return;

        if (tokenurl[2] == "by-key") {
            if (tokenurl.size() < 5) {
                return;
            }

            if (!Httpd_CanSerialize(tokenurl[4]))
                return;

            local_locker lock(&devicelist_mutex);

            uint64_t key = 0;
            std::stringstream ss(tokenurl[3]);

            ss >> key;

            /*
			if (sscanf(tokenurl[3].c_str(), "%lu", &key) != 1) {
				return;
            }
            */

            map<uint64_t, shared_ptr<kis_tracked_device_base> >::iterator tmi =
                tracked_map.find(key);
            if (tmi != tracked_map.end()) {
                // Try to find the exact field
                if (tokenurl.size() > 5) {
                    vector<string>::const_iterator first = tokenurl.begin() + 5;
                    vector<string>::const_iterator last = tokenurl.end();
                    vector<string> fpath(first, last);

                    SharedTrackerElement sub = tmi->second->get_child_path(fpath);

                    if (sub == NULL) {
                        return;
                    } 

                    Httpd_Serialize(tokenurl[4], stream, sub);

                    return;
                }

                Httpd_Serialize(tokenurl[4], stream, tmi->second);

                return;
            } else {
                return;
            }
        } else if (tokenurl[2] == "by-mac") {
            if (tokenurl.size() < 5)
                return;

            if (!Httpd_CanSerialize(tokenurl[4]))
                return;

            local_locker lock(&devicelist_mutex);

            mac_addr mac = mac_addr(tokenurl[3]);

            if (mac.error) {
                return;
            }

            SharedTrackerElement devvec =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

            vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
            for (vi = tracked_vec.begin(); vi != tracked_vec.end(); ++vi) {
                if ((*vi)->get_macaddr() == mac) {
                    devvec->add_vector((*vi));
                }
            }

            Httpd_Serialize(tokenurl[4], stream, devvec);

            return;
        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5)
                return;

            // Is the timestamp an int?
            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1)
                return;

            if (!Httpd_CanSerialize(tokenurl[4]))
                return;

            local_locker lock(&devicelist_mutex);

            SharedTrackerElement wrapper(new TrackerElement(TrackerMap));

            SharedTrackerElement refresh =
                globalreg->entrytracker->GetTrackedInstance(device_update_required_id);

            // If we've changed the list more recently, we have to do a refresh
            if (lastts < full_refresh_time) {
                refresh->set((uint8_t) 1);
            } else {
                refresh->set((uint8_t) 0);
            }

            wrapper->add_map(refresh);

            SharedTrackerElement updatets =
                globalreg->entrytracker->GetTrackedInstance(device_update_timestamp_id);
            updatets->set((int64_t) globalreg->timestamp.tv_sec);

            wrapper->add_map(updatets);

            SharedTrackerElement devvec =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

            wrapper->add_map(devvec);

            vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
            for (vi = tracked_vec.begin(); vi != tracked_vec.end(); ++vi) {
                if ((*vi)->get_last_time() > lastts)
                    devvec->add_vector((*vi));
            }

            Httpd_Serialize(tokenurl[4], stream, wrapper);

            return;
        }

    }
}

int Devicetracker::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    local_locker lock(&devicelist_mutex);

    // Split URL and process
    vector<string> tokenurl = StrTokenize(concls->url, "/");

    // All URLs are at least /devices/summary/x or /devices/last-time/ts/x
    if (tokenurl.size() < 4) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
        return 1;
    }

    // fprintf(stderr, "debug - devicetracker con %p thinks we're complete, populating\n", concls);

    // Common structured API data
    SharedStructured structdata;

    // Summarization vector
    vector<TrackerElementSummary> summary_vec;

    // Wrapper, if any
    string wrapper_name;

    SharedStructured regexdata;

    try {
        // Decode the base64 msgpack and parse it, or parse the json
        if (concls->variable_cache.find("msgpack") != concls->variable_cache.end()) {
            structdata.reset(new StructuredMsgpack(Base64::decode(concls->variable_cache["msgpack"]->str())));
        } else if (concls->variable_cache.find("json") != 
                concls->variable_cache.end()) {
            structdata.reset(new StructuredJson(concls->variable_cache["json"]->str()));
        } else {
            // fprintf(stderr, "debug - missing data\n");
            throw StructuredDataException("Missing data");
        }

        // fprintf(stderr, "debug - parsed structured data\n");

        SharedStructured fields = structdata->getStructuredByKey("fields");
        StructuredData::structured_vec fvec = fields->getStructuredArray();

        for (StructuredData::structured_vec::iterator i = fvec.begin(); 
                i != fvec.end(); ++i) {
            if ((*i)->isString()) {
                // fprintf(stderr, "debug - field: %s\n", (*i)->getString().c_str());
                summary_vec.push_back(TrackerElementSummary((*i)->getString(), 
                        entrytracker));
            } else if ((*i)->isArray()) {
                StructuredData::string_vec mapvec = (*i)->getStringVec();

                if (mapvec.size() != 2) {
                    // fprintf(stderr, "debug - malformed rename pair\n");
                    concls->response_stream << "Invalid request: "
                        "Expected field, rename";
                    concls->httpcode = 400;
                    return 1;
                }

                summary_vec.push_back(TrackerElementSummary(mapvec[0], mapvec[1],
                            entrytracker));
                // fprintf(stderr, "debug - map field: %s:%s\n", mapvec[0].c_str(), mapvec[1].c_str());
            }
        }

        // Get the wrapper, if one exists, default to empty if it doesn't
        wrapper_name = structdata->getKeyAsString("wrapper", "");

        if (structdata->hasKey("regex")) {
            regexdata = structdata->getStructuredByKey("regex");
        }

    } catch(const StructuredDataException e) {
        // fprintf(stderr, "debug - missing data key %s data %s\n", key, data);
        concls->response_stream << "Invalid request: ";
        concls->response_stream << e.what();
        concls->httpcode = 400;
        return 1;
    }

    if (tokenurl[1] == "devices") {
        if (tokenurl[2] == "summary") {
            // Wrapper we insert under
            SharedTrackerElement wrapper = NULL;

            // DT fields
            SharedTrackerElement dt_length_elem = NULL;
            SharedTrackerElement dt_filter_elem = NULL;

            // Rename cache generated during simplification
            TrackerElementSerializer::rename_map rename_map;

            SharedTrackerElement outdevs =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

            unsigned int dt_start = 0;
            unsigned int dt_length = 0;
            unsigned int dt_draw = 0;

            // Search string
            string dt_search;

            // Resolved paths to fields we search
            vector<vector<int> > dt_search_paths;
            
            unsigned int dt_order_col = -1;
            int dt_order_dir = 0;
            vector<int> dt_order_field;

            if (structdata->getKeyAsBool("datatable", false)) {
                // fprintf(stderr, "debug - we think we're doing a server-side datatable\n");
                if (concls->variable_cache.find("start") != 
                        concls->variable_cache.end()) {
                    *(concls->variable_cache["start"]) >> dt_start;
                }

                if (concls->variable_cache.find("length") != 
                        concls->variable_cache.end()) {
                    *(concls->variable_cache["length"]) >> dt_length;
                }

                if (concls->variable_cache.find("draw") != 
                        concls->variable_cache.end()) {
                    *(concls->variable_cache["draw"]) >> dt_draw;
                }

                if (concls->variable_cache.find("search[value]") !=
                            concls->variable_cache.end()) {
                    dt_search = concls->variable_cache["search[value]"]->str();
                }

                // If we're searching, we need to figure out what columns are
                // searchable.  Because of how we have to map names into datatables,
                // we don't get a usable field definition from the dt js plugin,
                // BUT we DO get a usable fieldspec from our fields list that
                // we already processed... so we have to make a slightly funky
                // assumption that columns[x] is equivalent to summary_vec[x],
                // and then we just pull the parsed-int field path in for our
                // searching mechanism
                if (dt_search.length() != 0) {
                    // fprintf(stderr, "debug - searching for '%s'\n", dt_search.c_str());
                    std::stringstream sstr;

                    // We have to act like an array and iterate through the
                    // column fields...  We use the summary vec length as a 
                    // quick cheat
                    for (unsigned int ci = 0; ci < summary_vec.size(); ci++) {
                        sstr.str("");
                        sstr << "columns[" << ci << "][searchable]";
                        map<string, std::unique_ptr<std::stringstream> >::iterator mi;
                        if ((mi = concls->variable_cache.find(sstr.str())) !=
                                concls->variable_cache.end()) {
                            if (mi->second->str() == "true") {
                                // We can blindly trust the offset b/c we're 
                                // iterating from our summary vec size, not the
                                // form data
                                dt_search_paths.push_back(summary_vec[ci].resolved_path);
                            }
                        } else {
                            // If we've run out of columns to look at for some
                            // reason just bail instead of doing more string 
                            // construction
                            break;
                        }
                    }

                }
                
                // We only handle sorting by the first column
                if (concls->variable_cache.find("order[0][column]") !=
                        concls->variable_cache.end()) {
                    *(concls->variable_cache["order[0][column]"]) >> dt_order_col;
                }

                // Don't allow ordering by a column that doesn't make sense
                if (dt_order_col >= summary_vec.size())
                    dt_order_col = -1;

                if (dt_order_col >= 0 &&
                        concls->variable_cache.find("order[0][dir]") !=
                        concls->variable_cache.end()) {
                    string ord = concls->variable_cache["order[0][dir]"]->str();

                    if (ord == "asc")
                        dt_order_dir = 1;

                    dt_order_field = summary_vec[dt_order_col].resolved_path;
                }

                // Force a length if we think we're doing a smart position and
                // something has gone wonky
                if (dt_length == 0)
                    dt_length = 50;

                // DT always has to wrap in an object
                wrapper.reset(new TrackerElement(TrackerMap));

                // wrap in 'data' for DT
                wrapper->add_map(outdevs);
                outdevs->set_local_name("data");

                // Set the DT draw
                SharedTrackerElement 
                    draw_elem(new TrackerElement(TrackerUInt64, dt_draw_id));
                draw_elem->set((uint64_t) dt_draw);
                draw_elem->set_local_name("draw");
                wrapper->add_map(draw_elem);

                // Make the length and filter elements
                dt_length_elem.reset(new TrackerElement(TrackerUInt64, dt_length_id));
                dt_length_elem->set_local_name("recordsTotal");
                dt_length_elem->set((uint64_t) tracked_vec.size());
                wrapper->add_map(dt_length_elem);

                dt_filter_elem.reset(new TrackerElement(TrackerUInt64, dt_filter_id));
                dt_filter_elem->set_local_name("recordsFiltered");
                wrapper->add_map(dt_filter_elem);
            }

            if (regexdata != NULL) {
                // If we're doing a basic regex outside of devicetables
                // shenanigans...
                SharedTrackerElement pcredevs =
                    globalreg->entrytracker->GetTrackedInstance(device_list_base_id);
                TrackerElementVector pcrevec(pcredevs);

                devicetracker_pcre_worker worker(globalreg, regexdata, pcredevs);
                MatchOnDevices(&worker);
                
                // Check DT ranges
                if (dt_start >= pcrevec.size())
                    dt_start = 0;

                if (dt_filter_elem != NULL)
                    dt_filter_elem->set((uint64_t) pcrevec.size());

                // Sort the list by the selected column
                if (dt_order_col >= 0) {
                    kismet__sort(pcrevec.begin(), pcrevec.end(), 
                            [&](SharedTrackerElement a, SharedTrackerElement b) {
                            SharedTrackerElement fa =
                                GetTrackerElementPath(dt_order_field, a);
                            SharedTrackerElement fb =
                                GetTrackerElementPath(dt_order_field, b);

                            if (dt_order_dir == 0)
                                return fa < fb;
                            return fb < fa;
                        });
                }

                // If we filtered, that's our list
                TrackerElementVector::iterator vi;
                // Set the iterator endpoint for our length
                TrackerElementVector::iterator ei;
                if (dt_length == 0 ||
                        dt_length + dt_start >= pcrevec.size())
                    ei = pcrevec.end();
                else
                    ei = pcrevec.begin() + dt_start + dt_length;

                for (vi = pcrevec.begin() + dt_start; vi != ei; ++vi) {
                    SharedTrackerElement simple;

                    SummarizeTrackerElement(entrytracker,
                            (*vi), summary_vec,
                            simple, rename_map);

                    outdevs->add_vector(simple);
                }
            } else if (dt_search_paths.size() != 0) {
                // Otherwise, we're doing a search inside a datatables query,
                // so go through every device and do a search on every element
                // which we have flagged as searchable, and which is a string or
                // mac which we can treat as a string.
                SharedTrackerElement matchdevs =
                    globalreg->entrytracker->GetTrackedInstance(device_list_base_id);
                TrackerElementVector matchvec(matchdevs);

                devicetracker_stringmatch_worker worker(globalreg, dt_search, 
                        dt_search_paths, matchdevs);
                MatchOnDevices(&worker);
                
                if (dt_order_col >= 0) {
                    kismet__sort(matchvec.begin(), matchvec.end(), 
                            [&](SharedTrackerElement a, SharedTrackerElement b) {
                            SharedTrackerElement fa =
                                GetTrackerElementPath(dt_order_field, a);
                            SharedTrackerElement fb =
                                GetTrackerElementPath(dt_order_field, b);

                            if (dt_order_dir == 0)
                                return fa < fb;

                            return fb < fa;
                        });
                }

                // Check DT ranges
                if (dt_start >= matchvec.size())
                    dt_start = 0;

                if (dt_filter_elem != NULL)
                    dt_filter_elem->set((uint64_t) matchvec.size());
                
                // Set the iterator endpoint for our length
                TrackerElementVector::iterator ei;
                if (dt_length == 0 ||
                        dt_length + dt_start >= matchvec.size())
                    ei = matchvec.end();
                else
                    ei = matchvec.begin() + dt_start + dt_length;

                // If we filtered, that's our list
                TrackerElementVector::iterator vi;
                for (vi = matchvec.begin() + dt_start; vi != ei; ++vi) {
                    SharedTrackerElement simple;

                    SummarizeTrackerElement(entrytracker,
                            (*vi), summary_vec,
                            simple, rename_map);

                    outdevs->add_vector(simple);
                }
            } else {
                // Otherwise we use the complete list
                //
                // Check DT ranges
                if (dt_start >= tracked_vec.size())
                    dt_start = 0;

                if (dt_filter_elem != NULL)
                    dt_filter_elem->set((uint64_t) tracked_vec.size());

                if (dt_order_col >= 0) {
                    kismet__sort(tracked_vec.begin(), tracked_vec.end(), 
                            [&](SharedTrackerElement a, SharedTrackerElement b) {
                            SharedTrackerElement fa =
                                GetTrackerElementPath(dt_order_field, a);
                            SharedTrackerElement fb =
                                GetTrackerElementPath(dt_order_field, b);

                            if (dt_order_dir == 0)
                                return fa < fb;

                            return fb < fa;
                        });
                }

                vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
                vector<shared_ptr<kis_tracked_device_base> >::iterator ei;

                // Set the iterator endpoint for our length
                if (dt_length == 0 ||
                        dt_length + dt_start >= tracked_vec.size())
                    ei = tracked_vec.end();
                else
                    ei = tracked_vec.begin() + dt_start + dt_length;

                for (vi = tracked_vec.begin() + dt_start; vi != ei; ++vi) {
                    SharedTrackerElement simple;

                    SummarizeTrackerElement(entrytracker,
                            (*vi), summary_vec,
                            simple, rename_map);

                    outdevs->add_vector(simple);
                }
            }

            // Apply wrapper if we haven't applied it already
            if (wrapper_name != "" && wrapper == NULL) {
                wrapper.reset(new TrackerElement(TrackerMap));
                wrapper->add_map(outdevs);
                outdevs->set_local_name(wrapper_name);
            } else if (wrapper == NULL) {
                wrapper = outdevs;
            }

            Httpd_Serialize(tokenurl[3], concls->response_stream, wrapper, &rename_map);
            return 1;

        } else if (tokenurl[2] == "last-time") {
            if (tokenurl.size() < 5) {
                // fprintf(stderr, "debug - couldn't parse ts\n");
                concls->response_stream << "Invalid request";
                concls->httpcode = 400;
                return 1;
            }

            // Is the timestamp an int?
            long lastts;
            if (sscanf(tokenurl[3].c_str(), "%ld", &lastts) != 1 ||
                    !Httpd_CanSerialize(tokenurl[4])) {
                // fprintf(stderr, "debug - couldn't parse/deserialize\n");
                concls->response_stream << "Invalid request";
                concls->httpcode = 400;
                return 1;
            }

            // We always wrap in a map
            SharedTrackerElement wrapper(new TrackerElement(TrackerMap));

            SharedTrackerElement refresh =
                globalreg->entrytracker->GetTrackedInstance(device_update_required_id);

            // If we've changed the list more recently, we have to do a refresh
            if (lastts < full_refresh_time) {
                refresh->set((uint8_t) 1);
            } else {
                refresh->set((uint8_t) 0);
            }

            wrapper->add_map(refresh);

            SharedTrackerElement updatets =
                globalreg->entrytracker->GetTrackedInstance(device_update_timestamp_id);
            updatets->set((int64_t) globalreg->timestamp.tv_sec);

            wrapper->add_map(updatets);

            // Rename cache generated during simplification
            TrackerElementSerializer::rename_map rename_map;

            // Create the device vector of all devices, and simplify it
            SharedTrackerElement sourcedevs =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);
            TrackerElementVector sourcevec(sourcedevs);

            if (regexdata != NULL) {
                devicetracker_pcre_worker worker(globalreg, regexdata, sourcedevs);
                MatchOnDevices(&worker);
            }

            SharedTrackerElement outdevs =
                globalreg->entrytracker->GetTrackedInstance(device_list_base_id);

            if (regexdata != NULL) {
                // If we filtered, that's our list
                TrackerElementVector::iterator vi;
                for (vi = sourcevec.begin(); vi != sourcevec.end(); ++vi) {
                    shared_ptr<kis_tracked_device_base> vid =
                        static_pointer_cast<kis_tracked_device_base>(*vi);

                    if (vid->get_last_time() > lastts) {
                        SharedTrackerElement simple;

                        SummarizeTrackerElement(entrytracker,
                                (*vi), summary_vec,
                                simple, rename_map);

                        outdevs->add_vector(simple);
                    }
                }
            } else {
                // Otherwise we use the complete list
                vector<shared_ptr<kis_tracked_device_base> >::iterator vi;
                for (vi = tracked_vec.begin(); vi != tracked_vec.end(); ++vi) {
                    if ((*vi)->get_last_time() > lastts) {
                        SharedTrackerElement simple;

                        SummarizeTrackerElement(entrytracker,
                                (*vi), summary_vec,
                                simple, rename_map);

                        outdevs->add_vector(simple);
                    }
                }
            }

            // Put the simplified map in the vector
            wrapper->add_map(outdevs);

            Httpd_Serialize(tokenurl[4], concls->response_stream, wrapper, &rename_map);
            return MHD_YES;
        }
    }

    concls->response_stream << "OK";

    return MHD_YES;
}

void Devicetracker::MatchOnDevices(DevicetrackerFilterWorker *worker) {
    local_locker lock(&devicelist_mutex);

    map<uint64_t, shared_ptr<kis_tracked_device_base> >::iterator tmi;

    for (tmi = tracked_map.begin(); tmi != tracked_map.end(); ++tmi) {
        worker->MatchDevice(this, tmi->second);
    }

    worker->Finalize(this);
}

// Simple std::sort comparison function to order by the least frequently
// seen devices
bool devicetracker_sort_lastseen(shared_ptr<kis_tracked_device_base> a,
	shared_ptr<kis_tracked_device_base> b) {

	return a->get_last_time() < b->get_last_time();
}

int Devicetracker::timetracker_event(int eventid) {
    if (eventid == device_idle_timer) {
        local_locker lock(&devicelist_mutex);

        vector<shared_ptr<kis_tracked_device_base> > target_devs;

        // Find all eligible devices, remove them from the tracked vec
        for (vector<shared_ptr<kis_tracked_device_base> >::iterator i =
                tracked_vec.begin(); i != tracked_vec.end(); /* */ ) {
            if (globalreg->timestamp.tv_sec - (*i)->get_last_time() >
                    device_idle_expiration) {
                target_devs.push_back(*i);
                tracked_vec.erase(i);
            } else {
                ++i;
            }
        }

        if (target_devs.size() > 0)
            UpdateFullRefresh();

        // Remove them from the global index, and then unlink to let the
        // tracked element GC clean them up
        for (vector<shared_ptr<kis_tracked_device_base> >::iterator i =
                target_devs.begin(); i != target_devs.end(); ++i) {
            device_itr mi = tracked_map.find((*i)->get_key());

            if (mi != tracked_map.end())
                tracked_map.erase(mi);

            // fprintf(stderr, "debug - forgetting device %s age %lu expiration %d\n", (*i)->get_macaddr().Mac2String().c_str(), globalreg->timestamp.tv_sec - (*i)->get_last_time(), device_idle_expiration);
        }

    } else if (eventid == max_devices_timer) {
		local_locker lock(&devicelist_mutex);

		// Do nothing if we don't care
		if (max_num_devices <= 0)
			return 1;

		// Do nothing if the number of devices is less than the max
		if (tracked_vec.size() <= max_num_devices)
			return 1;

        // Do an update since we're trimming something
        UpdateFullRefresh();

		// Now things start getting expensive.  Start by sorting the
		// vector of devices - anything else that has to sort the entire list
        // has to sort it themselves
		kismet__sort(tracked_vec.begin(), tracked_vec.end(), 
                devicetracker_sort_lastseen);

		unsigned int drop = tracked_vec.size() - max_num_devices;

		// Figure out how many we don't care about, and remove them from the map
		for (unsigned int d = 0; d < drop; d++) {
			device_itr mi = tracked_map.find(tracked_vec[d]->get_key());

			if (mi != tracked_map.end())
				tracked_map.erase(mi);
		}

		// Clear them out of the vector
		tracked_vec.erase(tracked_vec.begin(), tracked_vec.begin() + drop);
	}

    // Loop
    return 1;
}

void Devicetracker::usage(const char *name __attribute__((unused))) {
    printf("\n");
	printf(" *** Device Tracking Options ***\n");
	printf("     --device-timeout=n       Expire devices after N seconds\n"
          );
}

void Devicetracker::lock_devicelist() {
#ifdef HAVE_PTHREAD_TIMELOCK
        struct timespec t;

        clock_gettime(CLOCK_REALTIME , &t); 
        t.tv_sec += 5; \

        if (pthread_mutex_timedlock(&devicelist_mutex, &t) != 0) {
            throw(std::runtime_error("mutex not available w/in 5 seconds"));
        }
#else
        pthread_mutex_lock(&devicelist_mutex);
#endif
}

void Devicetracker::unlock_devicelist() {
    pthread_mutex_unlock(&devicelist_mutex);
}

devicetracker_stringmatch_worker::devicetracker_stringmatch_worker(GlobalRegistry *in_globalreg,
        string in_query,
        vector<vector<int> > in_paths,
        SharedTrackerElement in_devvec_object) {

    globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    query = in_query;
    fieldpaths = in_paths;

    // Preemptively try to compute a mac address partial search term
    mac_addr::PrepareSearchTerm(query, mac_query_term, mac_query_term_len);

    return_dev_vec = in_devvec_object;
}

devicetracker_stringmatch_worker::~devicetracker_stringmatch_worker() {

}

void devicetracker_stringmatch_worker::MatchDevice(Devicetracker *devicetracker __attribute__((unused)),
        shared_ptr<kis_tracked_device_base> device) {
    vector<vector<int> >::iterator i;

    bool matched = false;

    // Go through the fields
    for (i = fieldpaths.begin(); i != fieldpaths.end(); ++i) {
        // We should never have to search nested vectors so we don't use
        // multipath
        SharedTrackerElement field = GetTrackerElementPath(*i, device);

        if (field->get_type() == TrackerString) {
            // We can only do a straight string match against string fields
            matched = GetTrackerValue<string>(field).find(query) != std::string::npos;
        } else if (field->get_type() == TrackerMac && mac_query_term_len != 0) {
            // If we were able to interpret the query term as a partial
            // mac address, do a mac compare
            matched = 
                GetTrackerValue<mac_addr>(field).PartialSearch(mac_query_term,
                        mac_query_term_len);
        }

        if (matched) {
            return_dev_vec->add_vector(device);
            break;
        }
    }

}

void devicetracker_stringmatch_worker::Finalize(Devicetracker *devicetracker __attribute__((unused))) {

}

#ifdef HAVE_LIBPCRE

devicetracker_pcre_worker::devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
        vector<shared_ptr<devicetracker_pcre_worker::pcre_filter> > in_filter_vec,
        SharedTrackerElement in_devvec_object) {

    globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    filter_vec = in_filter_vec;
    error = false;

    return_dev_vec = in_devvec_object;
}

devicetracker_pcre_worker::devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
        SharedStructured raw_pcre_vec,
        SharedTrackerElement in_devvec_object) {

    globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    error = false;

    return_dev_vec = in_devvec_object;

    // Process a structuredarray of sub-arrays of [target, filter]; throw any 
    // exceptions we encounter

    StructuredData::structured_vec rawvec = raw_pcre_vec->getStructuredArray();
    for (StructuredData::structured_vec::iterator i = rawvec.begin(); 
            i != rawvec.end(); ++i) {
        StructuredData::structured_vec rpair = (*i)->getStructuredArray();

        if (rpair.size() != 2)
            throw StructuredDataException("expected [field, regex] pair");

        string field = rpair[0]->getString();
        string regex = rpair[1]->getString();

        shared_ptr<pcre_filter> filter(new pcre_filter());
        filter->target = field;

        const char *compile_error, *study_error;
        int erroroffset;
        ostringstream errordesc;

        filter->re =
            pcre_compile(regex.c_str(), 0, &compile_error, &erroroffset, NULL);

        if (filter->re == NULL) {
            errordesc << "Could not parse PCRE expression: " << compile_error <<
                " at character " << erroroffset;
            throw std::runtime_error(errordesc.str());
        }

        filter->study = pcre_study(filter->re, 0, &study_error);
        if (filter->study == NULL) {
            errordesc << "Could not parse PCRE expression, study/optimization "
                "failure: " << study_error;
            throw std::runtime_error(errordesc.str());
        }

        filter_vec.push_back(filter);
    }
}

devicetracker_pcre_worker::devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
        string in_target,
        SharedStructured raw_pcre_vec,
        SharedTrackerElement in_devvec_object) {

    globalreg = in_globalreg;

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    error = false;

    return_dev_vec = in_devvec_object;

    // Process a structuredarray of sub-arrays of [target, filter]; throw any 
    // exceptions we encounter

    StructuredData::structured_vec rawvec = raw_pcre_vec->getStructuredArray();
    for (StructuredData::structured_vec::iterator i = rawvec.begin(); 
            i != rawvec.end(); ++i) {

        string regex = (*i)->getString();

        shared_ptr<pcre_filter> filter(new pcre_filter());
        filter->target = in_target; 

        const char *compile_error, *study_error;
        int erroroffset;
        ostringstream errordesc;

        filter->re =
            pcre_compile(regex.c_str(), 0, &compile_error, &erroroffset, NULL);

        if (filter->re == NULL) {
            errordesc << "Could not parse PCRE expression: " << compile_error <<
                " at character " << erroroffset;
            throw std::runtime_error(errordesc.str());
        }

        filter->study = pcre_study(filter->re, 0, &study_error);
        if (filter->study == NULL) {
            errordesc << "Could not parse PCRE expression, study/optimization "
                "failure: " << study_error;
            throw std::runtime_error(errordesc.str());
        }

        filter_vec.push_back(filter);
    }
}

devicetracker_pcre_worker::~devicetracker_pcre_worker() {

}

void devicetracker_pcre_worker::MatchDevice(Devicetracker *devicetracker __attribute__((unused)),
        shared_ptr<kis_tracked_device_base> device) {
    vector<shared_ptr<devicetracker_pcre_worker::pcre_filter> >::iterator i;

    bool matched = false;

    // Go through all the filters until we find one that hits
    for (i = filter_vec.begin(); i != filter_vec.end(); ++i) {

        // Get complex fields - this lets us search nested vectors
        // or strings or whatnot
        vector<SharedTrackerElement> fields = 
            GetTrackerElementMultiPath((*i)->target, device, entrytracker);

        for (vector<SharedTrackerElement>::iterator fi = fields.begin();
                fi != fields.end(); ++fi) {
            // We can only regex strings
            if ((*fi)->get_type() != TrackerString)
                continue;

            int rc;
            int ovector[128];

            rc = pcre_exec((*i)->re, (*i)->study,
                    GetTrackerValue<string>(*fi).c_str(),
                    GetTrackerValue<string>(*fi).length(),
                    0, 0, ovector, 128);

            // Stop matching as soon as we find a hit
            if (rc >= 0) {
                matched = true;
                break;
            }

        }

        if (matched) {
            return_dev_vec->add_vector(device);
        }
    }

}

void devicetracker_pcre_worker::Finalize(Devicetracker *devicetracker __attribute__((unused))) {

}

#endif

