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

#include "kismet_algorithm.h"

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
#include "gpstracker.h"
#include "alertracker.h"
#include "manuf.h"
#include "entrytracker.h"
#include "devicetracker_component.h"
#include "msgpack_adapter.h"
#include "json_adapter.h"
#include "structured.h"
#include "kismet_json.h"
#include "base64.h"
#include "kis_datasource.h"

int Devicetracker_packethook_commontracker(CHAINCALL_PARMS) {
	return ((Devicetracker *) auxdata)->CommonTracker(in_pack);
}

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_Chain_Stream_Handler(in_globalreg),
    KisDatabase(in_globalreg, "devicetracker") {

    // Initialize as recursive to allow multiple locks in a single thread
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&devicelist_mutex, &mutexattr);

	globalreg = in_globalreg;

    // create a vector
    SharedTrackerElement itve(new TrackerElement(TrackerVector));
    immutable_tracked_vec = TrackerElementVector(itve);

    // Create the pcap httpd
    httpd_pcap.reset(new Devicetracker_Httpd_Pcap(globalreg));

    entrytracker =
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    device_base_id =
        entrytracker->RegisterField("kismet.device.base", 
                std::shared_ptr<kis_tracked_device_base>(new kis_tracked_device_base(globalreg, 0)),
                "core device record");
    device_list_base_id =
        entrytracker->RegisterField("kismet.device.list",
                TrackerVector, "list of devices");

    phy_base_id =
        entrytracker->RegisterField("kismet.phy.list", TrackerVector,
                "list of phys");

    phy_entry_id =
        entrytracker->RegisterField("kismet.phy.entry", TrackerMap,
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

	pack_comp_datasrc = 
		globalreg->packetchain->RegisterPacketComponent("KISDATASRC");

	// Common tracker, very early in the tracker chain
	globalreg->packetchain->RegisterHandler(&Devicetracker_packethook_commontracker,
											this, CHAINPOS_TRACKER, -100);

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

    track_history_cloud =
        globalreg->kismet_config->FetchOptBoolean("keep_location_cloud_history", true);

    if (!track_history_cloud) {
        _MSG("Location history cloud tracking disabled.  This may prevent some plugins "
                "from working.  This can be re-enabled by setting "
                "keep_datasource_signal_history=true", MSGFLAG_INFO);
    }

    track_persource_history =
        globalreg->kismet_config->FetchOptBoolean("keep_datasource_signal_history", true);

    if (!track_persource_history) {
        _MSG("Per-source signal history tracking disabled.  This may prevent some plugins "
                "from working.  This can be re-enabled by setting "
                "keep_datasource_signal_history=true", MSGFLAG_INFO);
    }

    // Update the database
    Database_UpgradeDB();
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
    immutable_tracked_vec.clear();
    tracked_mac_multimap.clear();

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

Kis_Phy_Handler *Devicetracker::FetchPhyHandlerByName(string in_name) {
    for (auto i = phy_handler_map.begin(); i != phy_handler_map.end(); ++i) {
        if (i->second->FetchPhyName() == in_name) {
            return i->second;
        }
    }
    return NULL;
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

	if (in_pack->error) {
		// and bail
		num_errorpackets++;
		return 0;
	}

	kis_common_info *pack_common =
		(kis_common_info *) in_pack->fetch(pack_comp_common);

    packets_rrd->add_sample(1, globalreg->timestamp.tv_sec);

	num_packets++;

	// If we can't figure it out at all (no common layer) just bail
	if (pack_common == NULL)
		return 0;

	if (pack_common->error) {
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
	packetchain_comp_datasource *pack_datasrc =
		(packetchain_comp_datasource *) in_pack->fetch(pack_comp_datasrc);
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

        // Device ID is the size of the vector so a new device always gets put
        // in it's numbered slot
        device->set_kis_internal_id(immutable_tracked_vec.size());

        device->set_key(key);
        device->set_macaddr(in_mac);
        device->set_phyname(phy->FetchPhyName());

        tracked_map[device->get_key()] = device;
        tracked_vec.push_back(device);
        immutable_tracked_vec.push_back(device);
        tracked_mac_multimap.emplace(in_mac, device);

        device->set_first_time(in_pack->ts.tv_sec);

        if (globalreg->manufdb != NULL)
            device->set_manuf(globalreg->manufdb->LookupOUI(device->get_macaddr()));
    }

    // Tag the packet with the base device
	kis_tracked_device_info *devinfo =
		(kis_tracked_device_info *) in_pack->fetch(pack_comp_device);

	if (devinfo == NULL) {
		devinfo = new kis_tracked_device_info;
		devinfo->devref = device;
		in_pack->insert(pack_comp_device, devinfo);
	}


    if (device->get_last_time() < in_pack->ts.tv_sec)
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

        // Throttle history cloud to one update per second to prevent floods of
        // data from swamping the cloud
        if (track_history_cloud && pack_gpsinfo->fix >= 2 &&
                in_pack->ts.tv_sec - device->get_location_cloud()->get_last_sample_ts() >= 1) {
            shared_ptr<kis_historic_location> histloc(new kis_historic_location(globalreg, 0));

            histloc->set_lat(pack_gpsinfo->lat);
            histloc->set_lon(pack_gpsinfo->lon);
            histloc->set_alt(pack_gpsinfo->alt);
            histloc->set_speed(pack_gpsinfo->speed);
            histloc->set_heading(pack_gpsinfo->heading);

            histloc->set_time_sec(in_pack->ts.tv_sec);

            if (pack_l1info != NULL) {
                histloc->set_frequency(pack_l1info->freq_khz);
                if (pack_l1info->signal_dbm != 0)
                    histloc->set_signal(pack_l1info->signal_dbm);
                else
                    histloc->set_signal(pack_l1info->signal_rssi);
            }

            device->get_location_cloud()->add_sample(histloc);
        }
    }

	// Update seenby records for time, frequency, packets
	if ((in_flags & UCD_UPDATE_SEENBY) && pack_datasrc != NULL) {
        double f = -1;

        Packinfo_Sig_Combo *sc = NULL;

        if (pack_l1info != NULL)
            f = pack_l1info->freq_khz;

        // Generate a signal record if we're following per-source signal
        if (track_persource_history) {
            sc = new Packinfo_Sig_Combo(pack_l1info, pack_gpsinfo);
        }

        device->inc_seenby_count(pack_datasrc->ref_source, in_pack->ts.tv_sec, f, sc);

        if (sc != NULL)
            delete(sc);
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
    packetchain_comp_datasource *pack_datasrc =
        (packetchain_comp_datasource *) in_pack->fetch(pack_comp_datasrc);

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

    kis_tracked_device_info *devinfo =
        (kis_tracked_device_info *) in_pack->fetch(pack_comp_device);

    if (devinfo == NULL) {
        fprintf(stderr, "debug - populating devinfo\n");
        devinfo = new kis_tracked_device_info;
        devinfo->devref = device;
        in_pack->insert(pack_comp_device, devinfo);
    }


    // device->set_first_time(in_pack->ts.tv_sec);

    if (globalreg->manufdb != NULL)
        device->set_manuf(globalreg->manufdb->LookupOUI(device->get_macaddr()));

    // Set name
    device->set_devicename(device->get_macaddr().Mac2String());

    /* Persistent tag loading removed, will be handled by serializing network in the future */

    device->inc_packets();

    device->get_packets_rrd()->add_sample(1, globalreg->timestamp.tv_sec);

    if (device->get_last_time() < in_pack->ts.tv_sec) 
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

        device->inc_frequency_count((int) pack_l1info->freq_khz);

        if (sc != NULL)
            delete(sc);

    }

    if (pack_gpsinfo != NULL) {
        device->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix);
    }

    // Update seenby records for time, frequency, packets
    if (pack_datasrc != NULL) {
        int f = -1;
        Packinfo_Sig_Combo *sc = NULL;

        if (pack_l1info != NULL)
            f = pack_l1info->freq_khz;

        // Generate a signal record if we're following per-source signal
        if (track_persource_history) {
            sc = new Packinfo_Sig_Combo(pack_l1info, pack_gpsinfo);
        }

        device->inc_seenby_count(pack_datasrc->ref_source, in_pack->ts.tv_sec, f, sc);

        if (sc != NULL)
            delete(sc);
    }

    device->add_basic_crypt(pack_common->basic_crypt_set);

    if (!(pack_common->channel == "0"))
        device->set_channel(pack_common->channel);

    return 1;
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

// Sort based on internal kismet ID
bool devicetracker_sort_internal_id(shared_ptr<kis_tracked_device_base> a,
	shared_ptr<kis_tracked_device_base> b) {

	return a->get_kis_internal_id() < b->get_kis_internal_id();
}

void Devicetracker::MatchOnDevices(DevicetrackerFilterWorker *worker, 
        TrackerElementVector vec, bool batch) {

    // We chunk into blocks of 500 devices and perform the match in 
    // batches; this prevents a single query from running so long that
    // things fall down.  It is slightly less efficient on huge data sets,
    // but the tradeoff is a naive client being able to crash the whole
    // show by doing a query against 20,000 devices in one go.
   
    // Handle non-batched stuff like internal memory management ops
    if (!batch) {
        local_locker lock(&devicelist_mutex);

        kismet__for_each(vec.begin(), vec.end(), 
                [&](SharedTrackerElement val) {
                    shared_ptr<kis_tracked_device_base> v = 
                        static_pointer_cast<kis_tracked_device_base>(val);
                    worker->MatchDevice(this, v);
                });

        worker->Finalize(this);
        return;
    }
    
    size_t dpos = 0;
    size_t chunk_sz = 50;

    while (1) {
        {
            // Limited scope lock
            
            local_locker lock(&devicelist_mutex);

            auto b = vec.begin() + dpos;
            auto e = b + chunk_sz;
            bool last_loop = false;

            if (e > vec.end()) {
                e = vec.end();
                last_loop = true;
            }

            // Parallel f-e
            kismet__for_each(b, e, 
                    [&](SharedTrackerElement val) {
                        if (val == NULL)
                            return;
                        shared_ptr<kis_tracked_device_base> v = 
                            static_pointer_cast<kis_tracked_device_base>(val);

                        worker->MatchDevice(this, v);
                    });

            if (last_loop)
                break;

            dpos += chunk_sz;
        }

        // We're now unlocked, do a tiny sleep to let another thread grab the lock
        // if it needs to
        usleep(1000);

    }

    worker->Finalize(this);
}

void Devicetracker::MatchOnDevices(DevicetrackerFilterWorker *worker, bool batch) {
    MatchOnDevices(worker, immutable_tracked_vec, batch);
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

        time_t ts_now = globalreg->timestamp.tv_sec;
        bool purged = false;

        // Find all eligible devices, remove them from the tracked vec
        tracked_vec.erase(std::remove_if(tracked_vec.begin(), tracked_vec.end(),
                [&](shared_ptr<kis_tracked_device_base> d) {
                    if (ts_now - d->get_last_time() > device_idle_expiration) {
                        // fprintf(stderr, "debug - forgetting device %s age %lu expiration %d\n", d->get_macaddr().Mac2String().c_str(), globalreg->timestamp.tv_sec - d->get_last_time(), device_idle_expiration);
                        
                        device_itr mi = tracked_map.find(d->get_key());
                        if (mi != tracked_map.end())
                            tracked_map.erase(mi);

                        // Forget it from the immutable vec, but keep its 
                        // position; we need to have vecpos = devid
                        auto iti = immutable_tracked_vec.begin() + d->get_kis_internal_id();
                        (*iti).reset();

                        // Erase it from the multimap
                        auto mmp = tracked_mac_multimap.equal_range(d->get_macaddr());

                        for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) {
                            if (mmpi->second->get_key() == d->get_key()) {
                                tracked_mac_multimap.erase(mmpi);
                                break;
                            }
                        }

                        purged = true;

                        return true;
                    }

                    return false;
         
                    }), tracked_vec.end());

        if (purged)
            UpdateFullRefresh();

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
		kismet__stable_sort(tracked_vec.begin(), tracked_vec.end(), 
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

int Devicetracker::Database_UpgradeDB() {

    return 0;
}


