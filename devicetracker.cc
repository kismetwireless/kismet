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
#include "json_adapter.h"
#include "structured.h"
#include "kismet_json.h"
#include "storageloader.h"
#include "base64.h"
#include "kis_datasource.h"
#include "kis_databaselogfile.h"

#include "zstr.hpp"

void kis_tracked_device_base::inc_frequency_count(double frequency) {
    if (frequency <= 0)
        return;

    auto i = freq_khz_map->find(frequency);

    if (i == freq_khz_map->end()) {
        auto e = std::make_shared<TrackerElementDouble>(frequency_val_id, 1);
        freq_khz_map->insert(frequency, e);
    } else {
        *(std::static_pointer_cast<TrackerElementDouble>(i->second)) += 1;
    }
}

void kis_tracked_device_base::inc_seenby_count(KisDatasource *source, 
        time_t tv_sec, int frequency, Packinfo_Sig_Combo *siginfo) {
    std::shared_ptr<kis_tracked_seenby_data> seenby;

    auto seenby_iter = seenby_map->find(source->get_source_key());

    // Make a new seenby record
    if (seenby_iter == seenby_map->end()) {
        seenby = std::make_shared<kis_tracked_seenby_data>(entrytracker, seenby_val_id);

        seenby->set_src_uuid(source->get_source_uuid());
        seenby->set_first_time(tv_sec);
        seenby->set_last_time(tv_sec);
        seenby->set_num_packets(1);

        if (frequency > 0)
            seenby->inc_frequency_count(frequency);

        if (siginfo != NULL)
            (*(seenby->get_signal_data())) += *siginfo;

        seenby_map->insert(source->get_source_key(), seenby);

    } else {
        seenby = std::static_pointer_cast<kis_tracked_seenby_data>(seenby_iter->second);

        seenby->set_last_time(tv_sec);
        seenby->inc_num_packets();

        if (frequency > 0)
            seenby->inc_frequency_count(frequency);

        if (siginfo != NULL)
            (*(seenby->get_signal_data())) += *siginfo;
    }
}

void kis_tracked_device_base::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.device.base.key", "unique device key across phy and server", &key);
    RegisterField("kismet.device.base.macaddr", "mac address", &macaddr);
    RegisterField("kismet.device.base.phyname", "phy name", &phyname);
    RegisterField("kismet.device.base.name", "printable device name", &devicename);
    RegisterField("kismet.device.base.username", "user name", &username);
    RegisterField("kismet.device.base.commonname", 
            "common name alias of custom or device names", &commonname);
    RegisterField("kismet.device.base.type", "printable device type", &type_string);
    RegisterField("kismet.device.base.basic_type_set", "bitset of basic type", &basic_type_set);
    RegisterField("kismet.device.base.crypt", "printable encryption type", &crypt_string);
    RegisterField("kismet.device.base.basic_crypt_set", 
            "bitset of basic encryption", &basic_crypt_set);
    RegisterField("kismet.device.base.first_time", "first time seen time_t", &first_time);
    RegisterField("kismet.device.base.last_time", "last time seen time_t", &last_time);
    RegisterField("kismet.device.base.mod_time", 
            "internal timestamp of last record change", &mod_time);
    RegisterField("kismet.device.base.packets.total", "total packets seen of all types", &packets);
    RegisterField("kismet.device.base.packets.rx", "observed packets sent to device", &rx_packets);
    RegisterField("kismet.device.base.packets.tx", "observed packets from device", &tx_packets);
    RegisterField("kismet.device.base.packets.llc", "observed protocol control packets", &llc_packets);
    RegisterField("kismet.device.base.packets.error", "corrupt/error packets", &error_packets);
    RegisterField("kismet.device.base.packets.data", "data packets", &data_packets);
    RegisterField("kismet.device.base.packets.crypt", "data packets using encryption", &crypt_packets);
    RegisterField("kismet.device.base.packets.filtered", "packets dropped by filter", &filter_packets);
    RegisterField("kismet.device.base.datasize", "transmitted data in bytes", &datasize);
    
    packets_rrd_id =
        RegisterDynamicField("kismet.device.base.packets.rrd", "packet rate rrd", &packets_rrd);
    data_rrd_id =
        RegisterDynamicField("kismet.device.base.datasize.rrd", "packet size rrd", &data_rrd);
    signal_data_id =
        RegisterDynamicField("kismet.device.base.signal", "signal data", &signal_data);

    RegisterField("kismet.device.base.freq_khz_map", "packets seen per frequency (khz)", &freq_khz_map);
    RegisterField("kismet.device.base.channel", "channel (phy specific)", &channel);
    RegisterField("kismet.device.base.frequency", "frequency", &frequency);
    RegisterField("kismet.device.base.manuf", "manufacturer name", &manuf);
    RegisterField("kismet.device.base.num_alerts", "number of alerts on this device", &alert);
    RegisterField("kismet.device.base.tags", "set of arbitrary tags, including user notes", &tag_map);

    tag_entry_id =
        entrytracker->RegisterField("kismet.device.base.tag", 
                TrackerElementFactory<TrackerElementString>(), "arbitrary tag");

    location_id =
        RegisterDynamicField("kismet.device.base.location", "location", &location);
    location_cloud_id =
        RegisterDynamicField("kismet.device.base.location_cloud", 
                "historic location cloud", &location_cloud);

    RegisterField("kismet.device.base.seenby", "sources that have seen this device", &seenby_map);

    // Packet count, not actual frequency, so uint64 not double
    frequency_val_id =
        entrytracker->RegisterField("kismet.device.base.frequency.count",
                TrackerElementFactory<TrackerElementUInt64>(), "frequency packet count");

    seenby_val_id =
        entrytracker->RegisterField("kismet.device.base.seenby.data",
                TrackerElementFactory<kis_tracked_seenby_data>(entrytracker, 0),
                "datasource seen-by data");

    packet_rrd_bin_250_id =
        RegisterDynamicField("kismet.device.base.packet.bin.250", "RRD of packets up to 250 bytes",
                &packet_rrd_bin_250);
    packet_rrd_bin_500_id =
        RegisterDynamicField("kismet.device.base.packet.bin.500", "RRD of packets up to 500 bytes",
                &packet_rrd_bin_500);
    packet_rrd_bin_1000_id =
        RegisterDynamicField("kismet.device.base.packet.bin.1000", "RRD of packets up to 1000 bytes",
                &packet_rrd_bin_1000);
    packet_rrd_bin_1500_id =
        RegisterDynamicField("kismet.device.base.packet.bin.1500", "RRD of packets up to 1500 bytes",
                &packet_rrd_bin_1500);
    packet_rrd_bin_jumbo_id =
        RegisterDynamicField("kismet.device.base.packet.bin.jumbo", "RRD of packets over 1500 bytes",
                &packet_rrd_bin_jumbo);

    RegisterField("kismet.device.base.server_uuid", 
            "UUID of server which saw this device", &server_uuid);
}

void kis_tracked_device_base::reserve_fields(std::shared_ptr<TrackerElementMap> e) {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            // If we're inheriting, it's our responsibility to kick submaps with
            // complex types as well; since they're not themselves complex objects
            for (auto s : *seenby_map) {
                // Build a proper seenby record for each item in the list
                auto sbd = 
                    std::make_shared<kis_tracked_seenby_data>(entrytracker, seenby_val_id, 
                            std::static_pointer_cast<TrackerElementMap>(s.second));
                // And assign it over the same key
                s.second = sbd;
            }
        }
    }

int Devicetracker_packethook_commontracker(CHAINCALL_PARMS) {
	return ((Devicetracker *) auxdata)->CommonTracker(in_pack);
}

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_Chain_Stream_Handler(in_globalreg),
    KisDatabase(in_globalreg, "devicetracker") {

	globalreg = in_globalreg;

    // create a vector
    immutable_tracked_vec = std::make_shared<TrackerElementVector>();

    // Create the pcap httpd
    httpd_pcap.reset(new Devicetracker_Httpd_Pcap(globalreg));

    entrytracker =
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>(globalreg, "ENTRYTRACKER");

    device_base_id =
        entrytracker->RegisterField("kismet.device.base", 
                TrackerElementFactory<kis_tracked_device_base>(entrytracker, 0),
                "core device record");
    device_list_base_id =
        entrytracker->RegisterField("kismet.device.list",
                TrackerElementFactory<TrackerElementVector>(),
                "list of devices");

    phy_base_id =
        entrytracker->RegisterField("kismet.phy.list", 
                TrackerElementFactory<TrackerElementVector>(),
                "list of phys");

    phy_entry_id =
        entrytracker->RegisterField("kismet.phy.entry", 
                TrackerElementFactory<TrackerElementMap>(),
                "phy entry");

    device_summary_base_id =
        entrytracker->RegisterField("kismet.device.summary_list",
                TrackerElementFactory<TrackerElementVector>(),
                "summary list of devices");

    device_update_required_id =
        entrytracker->RegisterField("kismet.devicelist.refresh",
                TrackerElementFactory<TrackerElementUInt8>(),
                "device list refresh recommended");
    device_update_timestamp_id =
        entrytracker->RegisterField("kismet.devicelist.timestamp",
                TrackerElementFactory<TrackerElementUInt64>(),
                "device list timestamp");

    // These need unique IDs to be put in the map for serialization.
    // They also need unique field names, we can rename them with setlocalname
    dt_length_id =
        entrytracker->RegisterField("kismet.datatables.recordsTotal", 
                TrackerElementFactory<TrackerElementUInt64>(),
                "datatable records total");
    dt_filter_id =
        entrytracker->RegisterField("kismet.datatables.recordsFiltered", 
                TrackerElementFactory<TrackerElementUInt64>(),
                "datatable records filtered");
    dt_draw_id =
        entrytracker->RegisterField("kismet.datatables.draw", 
                TrackerElementFactory<TrackerElementUInt64>(),
                "Datatable records draw ID");

	num_packets = num_datapackets = num_errorpackets =
		num_filterpackets = 0;

	next_phy_id = 0;

    std::shared_ptr<Packetchain> packetchain =
        Globalreg::FetchMandatoryGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");

	// Register global packet components used by the device tracker and
	// subsequent parts
	pack_comp_device = _PCM(PACK_COMP_DEVICE) =
		packetchain->RegisterPacketComponent("DEVICE");

	pack_comp_common =  _PCM(PACK_COMP_COMMON) =
		packetchain->RegisterPacketComponent("COMMON");

	pack_comp_basicdata = _PCM(PACK_COMP_BASICDATA) =
		packetchain->RegisterPacketComponent("BASICDATA");

	_PCM(PACK_COMP_MANGLEFRAME) =
		packetchain->RegisterPacketComponent("MANGLEDATA");

	pack_comp_radiodata =
		packetchain->RegisterPacketComponent("RADIODATA");

	pack_comp_gps =
		packetchain->RegisterPacketComponent("GPS");

	pack_comp_datasrc = 
		packetchain->RegisterPacketComponent("KISDATASRC");

	// Common tracker, very early in the tracker chain
	packetchain->RegisterHandler(&Devicetracker_packethook_commontracker,
											this, CHAINPOS_TRACKER, -100);

    std::shared_ptr<Timetracker> timetracker = 
        Globalreg::FetchMandatoryGlobalAs<Timetracker>(globalreg, "TIMETRACKER");

   
    // Always disable persistent storage for now
    persistent_storage = false;
    persistent_mode = MODE_ONSTART;
    persistent_compression = false;
    statestore = NULL;
    persistent_storage_timeout = 0;

#if 0
    if (!globalreg->kismet_config->FetchOptBoolean("persistent_config_present", false)) {
        _MSG("Kismet has recently added persistent device storage; it looks like you "
                "need to update your Kismet configs; install the latest configs with "
                "'make forceconfigs' from the Kismet source directory.",
                MSGFLAG_ERROR);

        std::shared_ptr<Alertracker> alertracker =
            Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
        alertracker->RaiseOneShot("CONFIGERROR", 
                "Kismet has recently added persistent device storage; it looks like "
                "kismet_storage.conf is missing; You should install the latest Kismet "
                "configs with 'make forceconfigs' from the Kismet source directory, or "
                "manually reconcile the new configs.", -1);

        persistent_storage = false;
        persistent_mode = MODE_ONSTART;
        persistent_compression = false;
        statestore = NULL;
        persistent_storage_timeout = 0;
    } else {
        persistent_storage =
            globalreg->kismet_config->FetchOptBoolean("persistent_state", false);

        if (!persistent_storage) {
            _MSG("Persistent storage has been disabled.  Kismet will not remember devices "
                    "between launches.", MSGFLAG_INFO);
            statestore = NULL;
        } else {
            statestore = new DevicetrackerStateStore(globalreg, this);

            unsigned int storerate = 
                globalreg->kismet_config->FetchOptUInt("persistent_storage_rate", 60);

            _MSG("Persistent device storage enabled.  Kismet will remember devices and "
                    "other information between launches.  Kismet will store devices "
                    "every " + UIntToString(storerate) + " seconds and on exit.", 
                    MSGFLAG_INFO);

            devices_storing = false;

            device_storage_timer =
                timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * storerate, NULL, 1,
                        [this](int) -> int {
                            local_locker l(&storing_mutex);

                            if (devices_storing) {
                                _MSG("Attempting to save persistent devices, but devices "
                                        "are still being saved from a previous storage "
                                        "attempt.  It's possible your system is slow, or you "
                                        "have a very large log of devices.  Try increasing "
                                        "the delay in 'persistent_storage_rate' in your "
                                        "kismet_storage.conf file.", MSGFLAG_ERROR);
                                return 1;
                            }

                            devices_storing = true;

                            // Run the device storage in its own thread
                            std::thread t([this] {
                                store_devices(immutable_tracked_vec);

                                {
                                    local_locker l(&storing_mutex);
                                    devices_storing = false;
                                }
                            });

                            // Detatch the thread, we don't care about it
                            t.detach();

                            return 1;
                        });

            std::string pertype = 
                StrLower(globalreg->kismet_config->FetchOpt("persistent_load"));

            if (pertype == "onstart") {
                persistent_mode = MODE_ONSTART;
            } else if (pertype == "ondemand") {
                persistent_mode = MODE_ONDEMAND;
            } else {
                _MSG("Persistent load mode missing from config, assuming 'onstart'",
                        MSGFLAG_ERROR);
                persistent_mode = MODE_ONSTART;
            }

            persistent_compression = 
                globalreg->kismet_config->FetchOptBoolean("persistent_compression", true);

            persistent_storage_timeout =
                globalreg->kismet_config->FetchOptULong("persistent_timeout", 86400);
        }
    }
#endif

    if (globalreg->kismet_config->FetchOptBoolean("kis_log_devices", true)) {
        unsigned int lograte = 
            globalreg->kismet_config->FetchOptUInt("kis_log_device_rate", 30);

        _MSG("Saving devices to the Kismet database log every " + UIntToString(lograte) + 
                " seconds.", MSGFLAG_INFO);

        databaselog_logging = false;

        databaselog_timer =
            timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * lograte, NULL, 1,
                [this](int) -> int {
                    local_locker l(&databaselog_mutex);

                    if (databaselog_logging) {
                        _MSG("Attempting to log devices, but devices are still being "
                                "saved from the last logging attempt.  It's possible your "
                                "system is slow or you have a very large number of devices "
                                "to log.  Try increasing the delay in 'kis_log_storage_rate' "
                                "in kismet_logging.conf", MSGFLAG_ERROR);
                        return 1;
                    }

                    databaselog_logging = true;

                    // Run the device storage in its own thread
                    std::thread t([this] {
                        databaselog_write_devices();

                        {
                            local_locker l(&databaselog_mutex);
                            databaselog_logging = false;
                        }
                    });

                    // Detatch the thread, we don't care about it
                    t.detach();

                    return 1;
                });
    } else {
        databaselog_timer = -1;
    }

    last_devicelist_saved = 0;
    last_database_logged = 0;

    // Preload the vector for speed
    unsigned int preload_sz = 
        globalreg->kismet_config->FetchOptUInt("tracker_device_presize", 1000);

    tracked_vec.reserve(preload_sz);
    immutable_tracked_vec->reserve(preload_sz);

    // Set up the device timeout
    device_idle_expiration =
        globalreg->kismet_config->FetchOptInt("tracker_device_timeout", 0);

    if (device_idle_expiration != 0) {
        device_idle_min_packets =
            globalreg->kismet_config->FetchOptUInt("tracker_device_packets", 0);

        std::stringstream ss;
        ss << "Removing tracked devices which have been inactive for more than " <<
            device_idle_expiration << " seconds";

        if (device_idle_min_packets > 2) 
            ss << " and fewer than " << device_idle_min_packets << " packets";

        _MSG(ss.str(), MSGFLAG_INFO);

		// Schedule device idle reaping every minute
        device_idle_timer =
            timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 60, NULL, 1, this);
    } else {
        device_idle_timer = -1;
    }

	max_num_devices =
		globalreg->kismet_config->FetchOptUInt("tracker_max_devices", 0);

	if (max_num_devices > 0) {
        _MSG_INFO("Limiting maximum number of devices to {}, older devices will be "
                "removed from tracking when this limit is reached.", max_num_devices);

		// Schedule max device reaping every 5 seconds
		max_devices_timer =
			timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5, NULL, 1, this);
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

    // Open and upgrade the DB, default path
    Database_Open("");
    Database_UpgradeDB();
}

Devicetracker::~Devicetracker() {
    local_locker lock(&devicelist_mutex);

    store_all_devices();
    databaselog_write_all_devices();

    if (statestore != NULL) {
        delete(statestore);
        statestore = NULL;
    }

    globalreg->devicetracker = NULL;
    globalreg->RemoveGlobal("DEVICETRACKER");

    std::shared_ptr<Packetchain> packetchain =
        Globalreg::FetchMandatoryGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");
    if (packetchain != NULL) {
        packetchain->RemoveHandler(&Devicetracker_packethook_commontracker,
                CHAINPOS_TRACKER);
    }

    std::shared_ptr<Timetracker> timetracker = 
        Globalreg::FetchGlobalAs<Timetracker>(globalreg, "TIMETRACKER");
    if (timetracker != NULL) {
        timetracker->RemoveTimer(device_idle_timer);
        timetracker->RemoveTimer(max_devices_timer);
        timetracker->RemoveTimer(device_storage_timer);
    }

    // TODO broken for now
    /*
	if (track_filter != NULL)
		delete track_filter;
    */

    for (auto p = phy_handler_map.begin(); p != phy_handler_map.end(); ++p) {
        delete p->second;
    }

    tracked_vec.clear();
    immutable_tracked_vec->clear();
    tracked_mac_multimap.clear();
}

Kis_Phy_Handler *Devicetracker::FetchPhyHandler(int in_phy) {
	std::map<int, Kis_Phy_Handler *>::iterator i = phy_handler_map.find(in_phy);

	if (i == phy_handler_map.end())
		return NULL;

	return i->second;
}

Kis_Phy_Handler *Devicetracker::FetchPhyHandlerByName(std::string in_name) {
    for (auto i = phy_handler_map.begin(); i != phy_handler_map.end(); ++i) {
        if (i->second->FetchPhyName() == in_name) {
            return i->second;
        }
    }
    return NULL;
}

std::string Devicetracker::FetchPhyName(int in_phy) {
    if (in_phy == KIS_PHY_ANY) {
        return "ANY";
    }

    Kis_Phy_Handler *phyh = FetchPhyHandler(in_phy);

    if (phyh == NULL) {
        return "UNKNOWN";
    }

    return phyh->FetchPhyName();
}

int Devicetracker::FetchNumDevices() {
    local_locker lock(&devicelist_mutex);

    return tracked_map.size();
}

int Devicetracker::FetchNumPackets() {
    return num_packets;
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

std::shared_ptr<kis_tracked_device_base> Devicetracker::FetchDevice(device_key in_key) {
    local_locker lock(&devicelist_mutex);

	device_itr i = tracked_map.find(in_key);

	if (i != tracked_map.end())
		return i->second;

	return NULL;
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

	return 1;
}

// This function handles populating the base common info about a device, transforming a 
// kis_common_info record into a full kis_tracked_device_base (or updating an existing
// kis_tracked_device_base record); 
//
// Because a phy can create multiple devices from a single packet (such as WiFi creating
// the access point, source, and destination devices), only the specific common device 
// being passed will be updated.
std::shared_ptr<kis_tracked_device_base> 
    Devicetracker::UpdateCommonDevice(kis_common_info *pack_common, 
            mac_addr in_mac, Kis_Phy_Handler *in_phy, kis_packet *in_pack, 
            unsigned int in_flags, std::string in_basic_type) {

    std::stringstream sstr;

    bool new_device = false;

	kis_layer1_packinfo *pack_l1info =
		(kis_layer1_packinfo *) in_pack->fetch(pack_comp_radiodata);
	kis_gps_packinfo *pack_gpsinfo =
		(kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);
	packetchain_comp_datasource *pack_datasrc =
		(packetchain_comp_datasource *) in_pack->fetch(pack_comp_datasrc);

    std::shared_ptr<kis_tracked_device_base> device = NULL;
    device_key key;

    key = device_key(globalreg->server_uuid_hash, in_phy->FetchPhynameHash(), in_mac);

	if ((device = FetchDevice(key)) == NULL) {
        if (in_flags & UCD_UPDATE_EXISTING_ONLY)
            return NULL;

        device =
            std::make_shared<kis_tracked_device_base>(entrytracker, device_base_id);
        // Device ID is the size of the vector so a new device always gets put
        // in it's numbered slot
        device->set_kis_internal_id(immutable_tracked_vec->size());

        device->set_key(key);
        device->set_macaddr(in_mac);
        device->set_phyname(in_phy->FetchPhyName());

        device->set_server_uuid(globalreg->server_uuid);

        device->set_first_time(in_pack->ts.tv_sec);

        device->set_type_string(in_basic_type);

        if (globalreg->manufdb != NULL)
            device->set_manuf(globalreg->manufdb->LookupOUI(in_mac));

        load_stored_username(device);
        load_stored_tags(device);

        new_device = true;

    }

    // Lock the device itself for updating, now that it's part of the list
    local_locker devlocker(&(device->device_mutex));

    // Tag the packet with the base device
	kis_tracked_device_info *devinfo =
		(kis_tracked_device_info *) in_pack->fetch(pack_comp_device);

	if (devinfo == NULL) {
		devinfo = new kis_tracked_device_info;
		in_pack->insert(pack_comp_device, devinfo);
	}

    devinfo->devrefs[in_mac] = device;

    // Update the mod data
    device->update_modtime();

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
        } else if (pack_common != NULL) {
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

    if (((in_flags & UCD_UPDATE_LOCATION) ||
                ((in_flags & UCD_UPDATE_EMPTY_LOCATION) && !device->has_location_cloud())) &&
            pack_gpsinfo != NULL) {
        device->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix);

        // Throttle history cloud to one update per second to prevent floods of
        // data from swamping the cloud
        if (track_history_cloud && pack_gpsinfo->fix >= 2 &&
                in_pack->ts.tv_sec - device->get_location_cloud()->get_last_sample_ts() >= 1) {
            auto histloc = std::make_shared<kis_historic_location>(entrytracker, 0);

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

    if (pack_common != NULL)
        device->add_basic_crypt(pack_common->basic_crypt_set);

    // Add the new device at the end once we've populated it
    if (new_device) {
        local_locker devlocker(&devicelist_mutex);
        tracked_map[key] = device;
        tracked_vec.push_back(device);
        immutable_tracked_vec->push_back(device);
        tracked_mac_multimap.emplace(in_mac, device);
    }

    return device;
}

// Sort based on internal kismet ID
bool devicetracker_sort_internal_id(std::shared_ptr<kis_tracked_device_base> a,
	std::shared_ptr<kis_tracked_device_base> b) {
	return a->get_kis_internal_id() < b->get_kis_internal_id();
}

void Devicetracker::MatchOnDevices(DevicetrackerFilterWorker *worker, 
        std::shared_ptr<TrackerElementVector> vec, bool batch) {

    kismet__for_each(vec->begin(), vec->end(), [&](SharedTrackerElement val) {
                if (val == NULL)
                    return;

                std::shared_ptr<kis_tracked_device_base> v = 
                    std::static_pointer_cast<kis_tracked_device_base>(val);

                bool m;

                // Lock the device itself inside the worker op
                {
                    local_locker devlocker(&(v->device_mutex));
                    m = worker->MatchDevice(this, v);
                }

                if (m) 
                    worker->MatchedDevice(v);
            });

    worker->Finalize(this);

#if 0
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
                std::shared_ptr<kis_tracked_device_base> v = 
                        std::static_pointer_cast<kis_tracked_device_base>(val);
                    worker->MatchDevice(this, v);
                });

        worker->Finalize(this);
        return;
    }
    
    size_t dpos = 0;
    size_t chunk_sz = 10;

    while (1) {
        local_demand_locker lock(&devicelist_mutex);

        lock.lock();

        auto b = vec.begin() + dpos;
        auto e = b + chunk_sz;
        bool last_loop = false;

        if (e > vec.end()) {
            e = vec.end();
            last_loop = true;
        }

        // Parallel for-each while inside a lock
        
        
        kismet__for_each(b, e, 
                [&](SharedTrackerElement val) {

                if (val == NULL)
                    return;
                std::shared_ptr<kis_tracked_device_base> v = 
                std::static_pointer_cast<kis_tracked_device_base>(val);

                worker->MatchDevice(this, v);
                });

        lock.unlock();

        if (last_loop)
            break;

        dpos += chunk_sz;

        // We're now unlocked, do a tiny sleep to let another thread grab the lock
        // if it needs to
        usleep(1000);

    }

    worker->Finalize(this);
#endif
}

void Devicetracker::MatchOnDevices(DevicetrackerFilterWorker *worker, bool batch) {
    MatchOnDevices(worker, immutable_tracked_vec, batch);
}

// Simple std::sort comparison function to order by the least frequently
// seen devices
bool devicetracker_sort_lastseen(std::shared_ptr<kis_tracked_device_base> a,
	std::shared_ptr<kis_tracked_device_base> b) {

	return a->get_last_time() < b->get_last_time();
}

int Devicetracker::timetracker_event(int eventid) {
    if (eventid == device_idle_timer) {
        local_locker lock(&devicelist_mutex);

        time_t ts_now = globalreg->timestamp.tv_sec;
        bool purged = false;

        // Find all eligible devices, remove them from the tracked vec
        tracked_vec.erase(std::remove_if(tracked_vec.begin(), tracked_vec.end(),
                [&](std::shared_ptr<kis_tracked_device_base> d) {
                    // Lock the device itself
                    local_locker devlocker(&(d->device_mutex));

                    if (ts_now - d->get_last_time() > device_idle_expiration &&
                            (d->get_packets() < device_idle_min_packets || 
                             device_idle_min_packets <= 0)) {
                        device_itr mi = tracked_map.find(d->get_key());

                        if (mi != tracked_map.end())
                            tracked_map.erase(mi);

                        // Erase it from the multimap
                        auto mmp = tracked_mac_multimap.equal_range(d->get_macaddr());

                        for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) {
                            if (mmpi->second->get_key() == d->get_key()) {
                                tracked_mac_multimap.erase(mmpi);
                                break;
                            }
                        }

                        // Forget it from the immutable vec, but keep its 
                        // position; we need to have vecpos = devid
                        auto iti = immutable_tracked_vec->begin() + d->get_kis_internal_id();
                        (*iti).reset();


                        purged = true;

                        // fprintf(stderr, "debug - thinking we're purging %s refcount %d\n", d->get_macaddr().Mac2String().c_str(), d.use_count());


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

        tracked_vec.erase(std::remove_if(tracked_vec.begin() + max_num_devices, tracked_vec.end(),
                [&](std::shared_ptr<kis_tracked_device_base> d) {
                    // Lock the device itself
                    local_locker devlocker(&(d->device_mutex));

                    device_itr mi = tracked_map.find(d->get_key());

                    if (mi != tracked_map.end())
                        tracked_map.erase(mi);

                    // Erase it from the multimap
                    auto mmp = tracked_mac_multimap.equal_range(d->get_macaddr());

                    for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) {
                        if (mmpi->second->get_key() == d->get_key()) {
                            tracked_mac_multimap.erase(mmpi);
                            break;
                        }
                    }

                    // Forget it from the immutable vec, but keep its 
                    // position; we need to have vecpos = devid
                    auto iti = immutable_tracked_vec->begin() + d->get_kis_internal_id();
                    (*iti).reset();

                    return true;
         
                    }), tracked_vec.end());
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
    local_eol_locker lock(&devicelist_mutex);
}

void Devicetracker::unlock_devicelist() {
    local_unlocker unlock(&devicelist_mutex);
}

int Devicetracker::Database_UpgradeDB() {
    local_locker dblock(&ds_mutex);

    unsigned int dbv = Database_GetDBVersion();
    std::string sql;
    int r;
    char *sErrMsg = NULL;

    if (db == NULL)
        return -1;

    if (dbv < 2) {
        // Define a simple table for custom device names, and a similar simple table
        // for notes; we store them outside the device record so that we have an
        // architecture available for saving them without requiring device snapshotting
        //
        // Names and tags are saved in both the custom tables AND the stored device 
        // record; stored devices retain their internal state, only new devices query
        // these tables.
    }

    if (dbv < 3) {
        sql = 
            "DROP TABLE device_storage";

        sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);
    }

    if (dbv < 4) {
        sql = 
            "DROP TABLE device_names";

        sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        sql = 
            "DROP TABLE device_tags";

        sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        sql = 
            "CREATE TABLE device_names ("
            "key TEXT, "
            "name TEXT, "
            "UNIQUE(key) ON CONFLICT REPLACE)";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Devicetracker unable to create device_names table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            sqlite3_close(db);
            db = NULL;
            return -1;
        }

        // Tags are stored as a combination of phy, device, and tag name, and are loaded 
        // into the tag map
        sql = 
            "CREATE TABLE device_tags ("
            "key TEXT, "
            "tag TEXT, "
            "content TEXT, "
            "UNIQUE(key, tag) ON CONFLICT REPLACE)";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Devicetracker unable to create device_tags table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            sqlite3_close(db);
            db = NULL;
            return -1;
        }
    }

    Database_SetDBVersion(4);

    return 0;
}

void Devicetracker::AddDevice(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker lock(&devicelist_mutex);

    if (FetchDevice(device->get_key()) != NULL) {
        _MSG("Devicetracker tried to add device " + device->get_macaddr().Mac2String() + 
                " which already exists", MSGFLAG_ERROR);
        return;
    }

    // Device ID is the size of the vector so a new device always gets put
    // in it's numbered slot
    device->set_kis_internal_id(immutable_tracked_vec->size());

    tracked_map[device->get_key()] = device;
    tracked_vec.push_back(device);
    immutable_tracked_vec->push_back(device);
    tracked_mac_multimap.emplace(device->get_macaddr(), device);
}

int Devicetracker::store_devices() {
    auto devs = std::make_shared<TrackerElementVector>();

    // Find anything that has changed
    for (auto v : *immutable_tracked_vec) {
        if (v == NULL)
            continue;

        auto kdb = std::static_pointer_cast<kis_tracked_device_base>(v);
        if (kdb->get_mod_time() > last_database_logged)
            devs->push_back(v);
    }

    last_devicelist_saved = time(0);

    return store_devices(devs);
}

int Devicetracker::store_all_devices() {
    last_devicelist_saved = time(0);

    return store_devices(immutable_tracked_vec);
}

int Devicetracker::store_devices(std::shared_ptr<TrackerElementVector> devices) {
    if (!persistent_storage)
        return 0;

    if (statestore == NULL)
        return 0;

    int r = statestore->store_devices(devices);

    return r;
}

void Devicetracker::databaselog_write_devices() {
    auto devs = std::make_shared<TrackerElementVector>();

    // Find anything that has changed
    for (auto v : *immutable_tracked_vec) {
        if (v == NULL)
            continue;

        std::shared_ptr<kis_tracked_device_base> kdb =
            std::static_pointer_cast<kis_tracked_device_base>(v);
        if (kdb->get_mod_time() > last_database_logged)
            devs->push_back(v);
    }

    last_database_logged = time(0);

    databaselog_write_devices(devs);
}

void Devicetracker::databaselog_write_all_devices() {
    last_database_logged = time(0);

    databaselog_write_devices(immutable_tracked_vec);
}

void Devicetracker::databaselog_write_devices(std::shared_ptr<TrackerElementVector> vec) {
    auto dbf = Globalreg::FetchGlobalAs<KisDatabaseLogfile>(globalreg, "DATABASELOG");
    
    if (dbf == NULL)
        return;

    // Fire off a database log
    dbf->log_devices(vec);
}

int Devicetracker::load_devices() {
    // Deliberately don't lock the db and device list - adding to the device list should
    // always be safe and handled by the add device locking, and the database should
    // be quiet during startup; we don't want a long load process to break the
    // mutex timers

    if (!persistent_storage || persistent_mode != MODE_ONSTART || statestore == NULL)
        return 0;

    if (!Database_Valid())
        return 0;

    int r;
    
    r = statestore->load_devices();

    if (r < 0)
        return r;

    r = statestore->clear_old_devices();

    return r;
}

// Attempt to load a single device from the database, return NULL if it wasn't found
// or if there was an error
std::shared_ptr<kis_tracked_device_base> Devicetracker::load_device(Kis_Phy_Handler *in_phy,
        mac_addr in_mac) {

    if (!persistent_storage || persistent_mode != MODE_ONDEMAND || statestore == NULL)
        return NULL;

    if (!statestore->Database_Valid())
        return NULL;

    return statestore->load_device(in_phy, in_mac);
}

std::shared_ptr<kis_tracked_device_base> 
Devicetracker::convert_stored_device(mac_addr macaddr,
        const unsigned char *raw_stored_data, unsigned long stored_len) {

    try {
        // Decompress the record if necessary
        std::stringbuf ibuf;

        // Decompression buffer, autodetect compression
        zstr::istreambuf izbuf(&ibuf, 1 << 16, true);

        // Link an istream to the compression buffer
        std::istream istream(&izbuf);

        // Flag exceptions on decompression errors
        istream.exceptions(std::ios_base::badbit);

        // Assign the row string to the strbuf behind the decompression system
        ibuf.sputn((const char *) raw_stored_data, stored_len);
        ibuf.pubsync();

        // Get the decompressed record
        std::string uzbuf(std::istreambuf_iterator<char>(istream), {});

        // Read out the structured json
        SharedStructured sjson(new StructuredJson(uzbuf));

        // Process structured object into a shared element
        SharedTrackerElement e = 
            StorageLoader::storage_to_tracker(entrytracker, sjson);

        if (e->get_type() != TrackerType::TrackerMap) 
            throw StructuredDataException(fmt::format("Expected a TrackerMap from loading the storage "
                    "element, but got {}", e->type_to_typestring(e->get_type())));

        // Adopt it into a device
        auto kdb = std::make_shared<kis_tracked_device_base>(entrytracker, device_base_id, 
                std::static_pointer_cast<TrackerElementMap>(e));

        // Give all the phys a shot at it
        for (auto p : phy_handler_map)
            p.second->LoadPhyStorage(e, kdb);

        // Update the server uuid in case we don't have it
        if (kdb->get_server_uuid().error)
            kdb->set_server_uuid(globalreg->server_uuid);

        // Update the manuf in case we added a manuf db
        if (globalreg->manufdb != NULL)
            kdb->set_manuf(globalreg->manufdb->LookupOUI(kdb->get_macaddr()));

        return kdb;
    } catch (const zstr::Exception& e) {
        _MSG("Unable to decompress stored device data (" + macaddr.Mac2String() + "); the "
                "stored device will be skipped: " + std::string(e.what()), MSGFLAG_ERROR);
        return NULL;
    } catch (const StructuredDataException& e) {
        _MSG("Could not parse stored device data (" + macaddr.Mac2String() + "); the "
                "stored device will be skipped: " + std::string(e.what()), MSGFLAG_ERROR);
        return NULL;
    } catch (const std::runtime_error&e ) {
        _MSG("Could not parse stored device data (" + macaddr.Mac2String() + "); the "
                "stored device will be skipped: " + std::string(e.what()), MSGFLAG_ERROR);
        return NULL;
    } catch (const std::exception& e) {
        _MSG("Unable to load a stored device (" + macaddr.Mac2String() + "); the stored "
                "device will be skipped: " + std::string(e.what()), MSGFLAG_ERROR);
        return NULL;
    }

    return NULL;
}

void Devicetracker::load_stored_username(std::shared_ptr<kis_tracked_device_base> in_dev) {
    // Lock the database; we're doing a single query
    local_locker dblock(&ds_mutex);

    if (!Database_Valid())
        return;

    // Lock the device itself
    local_locker devlocker(&(in_dev->device_mutex));

    std::string sql;
    std::string keystring = in_dev->get_key().as_string();

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    sql = 
        "SELECT name FROM device_names WHERE key = ? ";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database query for stored devicename in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return;
    }

    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, keystring.c_str(), keystring.length(), 0);

    while (1) {
        r = sqlite3_step(stmt);

        if (r == SQLITE_ROW) {
            const unsigned char *rowstr;

            rowstr = (const unsigned char *) sqlite3_column_text(stmt, 0);

            in_dev->set_username(std::string((const char *) rowstr));

        } else if (r == SQLITE_DONE) {
            break;
        } else {
            _MSG("Devicetracker encountered an error loading stored device username: " + 
                    std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            break;
        }
    }

    sqlite3_finalize(stmt);
}

void Devicetracker::load_stored_tags(std::shared_ptr<kis_tracked_device_base> in_dev) {
    // Lock the database; we're doing a single query
    local_locker dblock(&ds_mutex);

    if (!Database_Valid())
        return;

    // Lock the device itself
    local_locker devlocker(&(in_dev->device_mutex));

    std::string sql;
    std::string keystring = in_dev->get_key().as_string();

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    sql = 
        "SELECT tag, content FROM device_tags WHERE key = ?";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database query for stored devicetag in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return;
    }

    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, keystring.c_str(), keystring.length(), 0);

    while (1) {
        r = sqlite3_step(stmt);

        if (r == SQLITE_ROW) {
            const unsigned char *tagstr;
            const unsigned char *contentstr;

            tagstr = (const unsigned char *) sqlite3_column_text(stmt, 0);
            contentstr = (const unsigned char *) sqlite3_column_text(stmt, 1);

            auto tagc = std::make_shared<TrackerElementString>();
            tagc->set(std::string((const char *) contentstr));

            in_dev->get_tag_map()->insert(std::string((const char *) tagstr), tagc);
        } else if (r == SQLITE_DONE) {
            break;
        } else {
            _MSG("Devicetracker encountered an error loading stored device username: " + 
                    std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            break;
        }
    }

    sqlite3_finalize(stmt);
}

void Devicetracker::SetDeviceUserName(std::shared_ptr<kis_tracked_device_base> in_dev,
        std::string in_username) {

    // Lock the device itself
    local_locker devlocker(&(in_dev->device_mutex));

    in_dev->set_username(in_username);

    if (!Database_Valid()) {
        _MSG("Unable to store device name to permanent storage, the database connection "
                "is not available", MSGFLAG_ERROR);
        return;
    }

    std::string sql;

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    std::string keystring = in_dev->get_key().as_string();

    sql = 
        "INSERT INTO device_names "
        "(key, name) "
        "VALUES (?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database insert for device name in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return;
    }
 
    sqlite3_reset(stmt);

    sqlite3_bind_text(stmt, 1, keystring.c_str(), keystring.length(), 0);
    sqlite3_bind_text(stmt, 2, in_username.c_str(), in_username.length(), 0);

    // Only lock the database while we're inserting
    {
        local_locker lock(&ds_mutex);
        sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);

    return;
}

void Devicetracker::SetDeviceTag(std::shared_ptr<kis_tracked_device_base> in_dev,
        std::string in_tag, std::string in_content) {

    // Lock the device itself
    local_locker devlocker(&(in_dev->device_mutex));

    auto e = std::make_shared<TrackerElementString>();
    e->set(in_content);

    auto sm = in_dev->get_tag_map();

    auto t = sm->find(in_tag);
    if (t != sm->end()) {
        t->second = e;
    } else {
        sm->insert(in_tag, e);
    }

    if (!Database_Valid()) {
        _MSG("Unable to store device name to permanent storage, the database connection "
                "is not available", MSGFLAG_ERROR);
        return;
    }

    std::string sql;

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    std::string keystring = in_dev->get_key().as_string();

    sql = 
        "INSERT INTO device_tags "
        "(key, tag, content) "
        "VALUES (?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database insert for device tags in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return;
    }
 
    sqlite3_reset(stmt);

    sqlite3_bind_text(stmt, 1, keystring.c_str(), keystring.length(), 0);
    sqlite3_bind_text(stmt, 2, in_tag.c_str(), in_tag.length(), 0);
    sqlite3_bind_text(stmt, 3, in_content.c_str(), in_content.length(), 0);

    // Only lock the database while we're inserting
    {
        local_locker lock(&ds_mutex);
        sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);

    return;
}

DevicetrackerStateStore::DevicetrackerStateStore(GlobalRegistry *in_globalreg,
        Devicetracker *in_devicetracker) :
    KisDatabase(in_globalreg, "devicestate") {

    devicetracker = in_devicetracker;

    // Open and upgrade the DB, default path
    Database_Open("");
    Database_UpgradeDB();
}

int DevicetrackerStateStore::Database_UpgradeDB() {
    local_locker dblock(&ds_mutex);

    unsigned int dbv = Database_GetDBVersion();
    std::string sql;
    int r;
    char *sErrMsg = NULL;

    if (dbv < 1) {
        // We keep the last seen timestamp for automatic culling of the database of
        // idle device records.
        //
        // We need to split out the phyname and device mac because key is linked to 
        // the phy *number*, which is *variable* based on the order phys are initialized;
        // we need to rekey the phys.
        sql = 
            "CREATE TABLE device_storage ("
            "first_time INT, "
            "last_time INT, "
            "phyname TEXT, "
            "devmac TEXT, "
            "storage BLOB, "
            "UNIQUE(phyname, devmac) ON CONFLICT REPLACE)";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Devicetracker unable to create device_storage table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            sqlite3_close(db);
            db = NULL;
            return -1;
        }

    }

    // Hardcode a table check
    if (dbv == 1) {
        _MSG("Purging device state, as it cannot be ported forward into the new key "
                "architecture, sorry.", MSGFLAG_ERROR);

        sql =
            "DELETE FROM device_storage";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Devicetracker unable to clear device_storage table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            sqlite3_close(db);
            db = NULL;
            return -1;
        }
    }

    Database_SetDBVersion(2);

    return 0;
}

int DevicetrackerStateStore::clear_old_devices() {
    local_locker dblock(&ds_mutex);

    std::string sql;
    std::stringstream sqlss;
    int r;
    char *sErrMsg = NULL;

    if (!Database_Valid())
        return 0;

    if (devicetracker->persistent_storage_timeout == 0)
        return 0;

    sqlss << 
        "DELETE FROM device_storage WHERE (last_time < " <<
        time(0) - devicetracker->persistent_storage_timeout << ")";
    sql = sqlss.str();


    r = sqlite3_exec(db, sql.c_str(), NULL, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to delete timed out devices in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        sqlite3_close(db);
        db = NULL;
        return -1;
    }

    return 1;
}

int DevicetrackerStateStore::clear_all_devices() {
    local_locker dblock(&ds_mutex);

    std::string sql;
    std::stringstream sqlss;
    int r;
    char *sErrMsg = NULL;

    if (!Database_Valid())
        return 0;

    if (devicetracker->persistent_storage_timeout == 0)
        return 0;

    sql = "DELETE FROM device_storage";

    r = sqlite3_exec(db, sql.c_str(), NULL, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to delete timed out devices in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        sqlite3_close(db);
        db = NULL;
        return -1;
    }

    return 1;
}


int DevicetrackerStateStore::load_devices() {
    if (!Database_Valid())
        return 0;

    std::string sql;
    std::string phyname;

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    sql = 
        "SELECT devmac, storage FROM device_storage";

    // If we have a timeout, apply that
    if (devicetracker->persistent_storage_timeout != 0) {
        std::stringstream timess;

        timess << sql << " WHERE (last_time > " <<
            time(0) - devicetracker->persistent_storage_timeout << ")";
        sql = timess.str();
    }


    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database query for stored devices in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return -1;
    }

    _MSG("Loading stored devices.  This may take some time, depending on the speed of "
            "your system and the number of stored devices.", MSGFLAG_INFO);

    unsigned int num_devices = 0;

    sqlite3_reset(stmt);

    while (1) {
        r = sqlite3_step(stmt);

        if (r == SQLITE_ROW) {
            const unsigned char *rowstr;
            unsigned long rowlen;

            mac_addr m;

            rowstr = sqlite3_column_text(stmt, 0);
            m = mac_addr((const char *) rowstr);

            if (m.error) {
                _MSG("Encountered an error loading a stored device, "
                        "unable to process mac address; skipping device.",
                        MSGFLAG_ERROR);
                continue;
            }

            rowstr = (const unsigned char *) sqlite3_column_blob(stmt, 1);
            rowlen = sqlite3_column_bytes(stmt, 1);

            // Adopt it into a device
            std::shared_ptr<kis_tracked_device_base> kdb =
                devicetracker->convert_stored_device(m, rowstr, rowlen);

            if (kdb != NULL) {
                devicetracker->AddDevice(kdb);
                num_devices++;
            }
        } else if (r == SQLITE_DONE) {
            break;
        } else {
            _MSG("Encountered an error loading stored devices: " + 
                    std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            break;
        }
    }

    sqlite3_finalize(stmt);

    return 1;
}

// Attempt to load a single device from the database, return NULL if it wasn't found
// or if there was an error
std::shared_ptr<kis_tracked_device_base> 
DevicetrackerStateStore::load_device(Kis_Phy_Handler *in_phy, mac_addr in_mac) {
    if (!Database_Valid())
        return NULL;

    // Lock the database; we're doing a single query
    local_locker dblock(&ds_mutex);

    std::string sql;
    std::string macstring = in_mac.Mac2String();
    std::string phystring = in_phy->FetchPhyName();

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    sql = 
        "SELECT storage FROM device_storage WHERE phyname = ? AND "
        "devmac = ?";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database query for stored device in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return NULL;
    }

    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, phystring.c_str(), phystring.length(), 0);
    sqlite3_bind_text(stmt, 2, macstring.c_str(), macstring.length(), 0);

    while (1) {
        r = sqlite3_step(stmt);

        if (r == SQLITE_ROW) {
            const unsigned char *rowstr;
            unsigned long rowlen;

            rowstr = (const unsigned char *) sqlite3_column_blob(stmt, 0);
            rowlen = sqlite3_column_bytes(stmt, 0);

            return devicetracker->convert_stored_device(in_mac, rowstr, rowlen);
        } else if (r == SQLITE_DONE) {
            break;
        } else {
            _MSG("Encountered an error loading stored device: " + 
                    std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            break;
        }
    }

    sqlite3_finalize(stmt);

    return NULL;
}

int DevicetrackerStateStore::store_devices(std::shared_ptr<TrackerElementVector> devices) {
    local_locker lock(&ds_mutex);

    if (!Database_Valid()) {
        _MSG("Unable to snapshot device records!  The database connection to " +
                ds_dbfile + " is invalid...", MSGFLAG_ERROR);
        return 0;
    }

    std::string sql;

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    sql = 
        "INSERT INTO device_storage "
        "(first_time, last_time, phyname, devmac, storage) "
        "VALUES (?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database insert for devices in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return -1;
    }

    // Use a function worker to insert it into the db
    devicetracker_function_worker fw(
            [this, &stmt] 
                (Devicetracker *, std::shared_ptr<kis_tracked_device_base> d) -> bool {
                std::shared_ptr<kis_tracked_device_base> kdb =
                    std::static_pointer_cast<kis_tracked_device_base>(d);

                std::string serialstring;
                std::string macstring;
                std::string phystring;

                // Prep the compression buf
                std::stringbuf sbuf;
                zstr::ostreambuf zobuf(&sbuf, 1 << 16, true);
                std::ostream zstream(&zobuf);

                // Standard noncompression buf
                std::ostream sstream(&sbuf);

                std::ostream *serialstream;

                if (devicetracker->persistent_compression)
                serialstream = &zstream;
                else
                    serialstream = &sstream;


                sbuf.str("");
                sqlite3_reset(stmt);

                // Pack a storage formatted blob
                {
                    local_locker lock(&(devicetracker->devicelist_mutex));
                    StorageJsonAdapter::Pack(*serialstream, d, NULL);
                }

                // Sync the buffers
                zobuf.pubsync();
                sbuf.pubsync();

                serialstring = sbuf.str();

                macstring = kdb->get_macaddr().Mac2String();
                phystring = kdb->get_phyname();

                sqlite3_bind_int(stmt, 1, kdb->get_first_time());
                sqlite3_bind_int(stmt, 2, kdb->get_mod_time());
                sqlite3_bind_text(stmt, 3, phystring.c_str(), phystring.length(), 0);
                sqlite3_bind_text(stmt, 4, macstring.c_str(), macstring.length(), 0);
                sqlite3_bind_blob(stmt, 5, serialstring.data(), serialstring.length(), 0);

                sqlite3_step(stmt);

                return false;
            }, NULL);

    // Perform the write as a single transaction
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
    devicetracker->MatchOnDevices(&fw, devices);
    sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);

    sqlite3_finalize(stmt);

    return 1;
}
