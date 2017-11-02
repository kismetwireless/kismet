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
#include "msgpack_adapter.h"
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

    TrackerElement::double_map_iterator i = freq_khz_map->double_find(frequency);

    if (i == freq_khz_map->double_end()) {
        SharedTrackerElement e =
            globalreg->entrytracker->GetTrackedInstance(frequency_val_id);
        e->set((uint64_t) 1);
        freq_khz_map->add_doublemap(frequency, e);
    } else {
        (*(i->second))++;
    }
}

void kis_tracked_device_base::inc_seenby_count(KisDatasource *source, 
        time_t tv_sec, int frequency, Packinfo_Sig_Combo *siginfo) {
    TrackerElement::map_iterator seenby_iter;
    std::shared_ptr<kis_tracked_seenby_data> seenby;

    seenby_iter = seenby_map->find(source->get_source_key());

    // Make a new seenby record
    if (seenby_iter == seenby_map->end()) {
        seenby.reset(new kis_tracked_seenby_data(globalreg, seenby_val_id));

        seenby->set_src_uuid(source->get_source_uuid());
        seenby->set_first_time(tv_sec);
        seenby->set_last_time(tv_sec);
        seenby->set_num_packets(1);

        if (frequency > 0)
            seenby->inc_frequency_count(frequency);

        if (siginfo != NULL)
            (*(seenby->get_signal_data())) += *siginfo;

        seenby_map->add_intmap(source->get_source_key(), seenby);

    } else {
        seenby = static_pointer_cast<kis_tracked_seenby_data>(seenby_iter->second);

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

    RegisterField("kismet.device.base.key", TrackerKey,
            "unique device key across phy and server", &key);

    RegisterField("kismet.device.base.macaddr", TrackerMac,
            "mac address", &macaddr);

    RegisterField("kismet.device.base.phyname", TrackerString,
            "phy name", &phyname);

    RegisterField("kismet.device.base.name", TrackerString,
            "printable device name", &devicename);

    RegisterField("kismet.device.base.username", TrackerString,
            "user name", &username);

    RegisterField("kismet.device.base.type", TrackerString,
            "printable device type", &type_string);

    RegisterField("kismet.device.base.basic_type_set", TrackerUInt64,
            "bitset of basic type", &basic_type_set);

    RegisterField("kismet.device.base.crypt", TrackerString,
            "printable encryption type", &crypt_string);

    RegisterField("kismet.device.base.basic_crypt_set", TrackerUInt64,
            "bitset of basic encryption", &basic_crypt_set);

    RegisterField("kismet.device.base.first_time", TrackerUInt64,
            "first time seen time_t", &first_time);
    RegisterField("kismet.device.base.last_time", TrackerUInt64,
            "last time seen time_t", &last_time);
    RegisterField("kismet.device.base.mod_time", TrackerUInt64,
            "internal timestamp of last record change", &mod_time);

    RegisterField("kismet.device.base.packets.total", TrackerUInt64,
            "total packets seen of all types", &packets);
    RegisterField("kismet.device.base.packets.rx", TrackerUInt64,
            "observed packets sent to device", &rx_packets);
    RegisterField("kismet.device.base.packets.tx", TrackerUInt64,
            "observed packets from device", &tx_packets);
    RegisterField("kismet.device.base.packets.llc", TrackerUInt64,
            "observed protocol control packets", &llc_packets);
    RegisterField("kismet.device.base.packets.error", TrackerUInt64,
            "corrupt/error packets", &error_packets);
    RegisterField("kismet.device.base.packets.data", TrackerUInt64,
            "data packets", &data_packets);
    RegisterField("kismet.device.base.packets.crypt", TrackerUInt64,
            "data packets using encryption", &crypt_packets);
    RegisterField("kismet.device.base.packets.filtered", TrackerUInt64,
            "packets dropped by filter", &filter_packets);

    RegisterField("kismet.device.base.datasize", TrackerUInt64,
            "transmitted data in bytes", &datasize);

    std::shared_ptr<kis_tracked_rrd<> > packets_rrd_builder(new kis_tracked_rrd<>(globalreg, 0));
    packets_rrd_id =
        globalreg->entrytracker->RegisterField("kismet.device.base.packets.rrd",
                packets_rrd_builder, "packet rate rrd");

    std::shared_ptr<kis_tracked_rrd<> > data_rrd_builder(new kis_tracked_rrd<>(globalreg, 0));
    data_rrd_id =
        globalreg->entrytracker->RegisterField("kismet.device.base.datasize.rrd",
                data_rrd_builder, "packet size rrd");

    std::shared_ptr<kis_tracked_signal_data> sig_builder(new kis_tracked_signal_data(globalreg, 0));
    signal_data_id =
        RegisterComplexField("kismet.device.base.signal", sig_builder,
                "signal data");

    RegisterField("kismet.device.base.freq_khz_map", TrackerDoubleMap,
            "packets seen per frequency (khz)", &freq_khz_map);

    RegisterField("kismet.device.base.channel", TrackerString,
            "channel (phy specific)", &channel);
    RegisterField("kismet.device.base.frequency", TrackerDouble,
            "frequency", &frequency);

    RegisterField("kismet.device.base.manuf", TrackerString,
            "manufacturer name", &manuf);

    RegisterField("kismet.device.base.num_alerts", TrackerUInt32,
            "number of alerts on this device", &alert);

    RegisterField("kismet.device.base.tags", TrackerStringMap,
            "set of arbitrary tags, including user notes", &tag_map);
    tag_entry_id =
        RegisterField("kismet.device.base.tag", TrackerString, "arbitrary tag");

    std::shared_ptr<kis_tracked_location> loc_builder(new kis_tracked_location(globalreg, 0));
    location_id =
        RegisterComplexField("kismet.device.base.location", loc_builder,
                "location");

    location_cloud_id =
        RegisterComplexField("kismet.device.base.location_cloud", 
                std::shared_ptr<kis_location_history>(new kis_location_history(globalreg, 0)),
                "historic location cloud");

    RegisterField("kismet.device.base.seenby", TrackerIntMap,
            "sources that have seen this device", &seenby_map);

    // Packet count, not actual frequency, so uint64 not double
    frequency_val_id =
        globalreg->entrytracker->RegisterField("kismet.device.base.frequency.count",
                TrackerUInt64, "frequency packet count");

    std::shared_ptr<kis_tracked_seenby_data> seenby_builder(new kis_tracked_seenby_data(globalreg, 0));
    seenby_val_id =
        RegisterComplexField("kismet.device.base.seenby.data",
                seenby_builder, "seen-by data");

    std::shared_ptr<kis_tracked_minute_rrd<> > bin_rrd_builder(new kis_tracked_minute_rrd<>(globalreg, 0));

    packet_rrd_bin_250_id =
        RegisterComplexField("kismet.device.base.packet.bin.250", bin_rrd_builder, 
                "Packets up to 250 bytes");
    packet_rrd_bin_500_id =
        RegisterComplexField("kismet.device.base.packet.bin.500", bin_rrd_builder, 
                "Packets up to 500 bytes");
    packet_rrd_bin_1000_id =
        RegisterComplexField("kismet.device.base.packet.bin.1000", bin_rrd_builder, 
                "Packets up to 1000 bytes");
    packet_rrd_bin_1500_id =
        RegisterComplexField("kismet.device.base.packet.bin.1500", bin_rrd_builder, 
                "Packets up to 1500 bytes");
    packet_rrd_bin_jumbo_id =
        RegisterComplexField("kismet.device.base.packet.bin.jumbo", bin_rrd_builder, 
                "Jumbo packets over 1500 bytes");
}

void kis_tracked_device_base::reserve_fields(SharedTrackerElement e) {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            signal_data.reset(new kis_tracked_signal_data(globalreg, signal_data_id,
                    e->get_map_value(signal_data_id)));

            location.reset(new kis_tracked_location(globalreg, location_id,
                    e->get_map_value(location_id)));

            location_cloud.reset(new kis_location_history(globalreg, location_cloud_id,
                    e->get_map_value(location_cloud_id)));

            packets_rrd.reset(new kis_tracked_rrd<>(globalreg,
                    packets_rrd_id, e->get_map_value(packets_rrd_id)));

            data_rrd.reset(new kis_tracked_rrd<>(globalreg,
                    data_rrd_id, e->get_map_value(data_rrd_id)));

            packet_rrd_bin_250.reset(new kis_tracked_minute_rrd<>(globalreg,
                    packet_rrd_bin_250_id, e->get_map_value(packet_rrd_bin_250_id)));

            packet_rrd_bin_500.reset(new kis_tracked_minute_rrd<>(globalreg,
                    packet_rrd_bin_500_id, e->get_map_value(packet_rrd_bin_500_id)));

            packet_rrd_bin_1000.reset(new kis_tracked_minute_rrd<>(globalreg,
                    packet_rrd_bin_1000_id, e->get_map_value(packet_rrd_bin_1000_id)));

            packet_rrd_bin_1500.reset(new kis_tracked_minute_rrd<>(globalreg,
                    packet_rrd_bin_1500_id, e->get_map_value(packet_rrd_bin_1500_id)));

            packet_rrd_bin_jumbo.reset(new kis_tracked_minute_rrd<>(globalreg,
                    packet_rrd_bin_jumbo_id, e->get_map_value(packet_rrd_bin_jumbo_id)));

            // If we're inheriting, it's our responsibility to kick submaps with
            // complex types as well; since they're not themselves complex objects
            TrackerElementIntMap seenby(seenby_map);
            for (auto s = seenby.begin(); s != seenby.end(); ++s) {
                // Build a proper seenby record for each item in the list
                std::shared_ptr<kis_tracked_seenby_data> sbd(new kis_tracked_seenby_data(globalreg, seenby_val_id, s->second));
                // And assign it over the same key
                s->second = std::static_pointer_cast<TrackerElement>(sbd);
            }
        } else {
            signal_data.reset(new kis_tracked_signal_data(globalreg, signal_data_id));

            packets_rrd.reset(new kis_tracked_rrd<>(globalreg, packets_rrd_id));
        }

        // add using known fields b/c we might add null
        add_map(signal_data_id, signal_data);
        add_map(location_id, location);
        add_map(location_cloud_id, location_cloud);
        add_map(packets_rrd_id, packets_rrd);
        add_map(data_rrd_id, data_rrd);
        add_map(packet_rrd_bin_250_id, packet_rrd_bin_250);
        add_map(packet_rrd_bin_500_id, packet_rrd_bin_500);
        add_map(packet_rrd_bin_1000_id, packet_rrd_bin_1000);
        add_map(packet_rrd_bin_1500_id, packet_rrd_bin_1500);
        add_map(packet_rrd_bin_jumbo_id, packet_rrd_bin_jumbo);

    }

int Devicetracker_packethook_commontracker(CHAINCALL_PARMS) {
	return ((Devicetracker *) auxdata)->CommonTracker(in_pack);
}

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_Chain_Stream_Handler(in_globalreg),
    KisDatabase(in_globalreg, "devicetracker") {

	globalreg = in_globalreg;

    // create a vector
    SharedTrackerElement itve(new TrackerElement(TrackerVector));
    immutable_tracked_vec = TrackerElementVector(itve);

    // Create the pcap httpd
    httpd_pcap.reset(new Devicetracker_Httpd_Pcap(globalreg));

    entrytracker =
        Globalreg::FetchGlobalAs<EntryTracker>(globalreg, "ENTRY_TRACKER");

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

    if (!globalreg->kismet_config->FetchOptBoolean("persistent_config_present", false)) {
        _MSG("Kismet has recently added persistent device storage; it looks like you "
                "need to update your Kismet configs; install the latest configs with "
                "'make forceconfigs' from the Kismet source directory.",
                MSGFLAG_ERROR);

        shared_ptr<Alertracker> alertracker =
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
        }
    }

    if (globalreg->kismet_config->FetchOptBoolean("kis_log_devices", false)) {
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

    // Set up the device timeout
    device_idle_expiration =
        globalreg->kismet_config->FetchOptInt("tracker_device_timeout", 0);

    if (device_idle_expiration != 0) {
        std::stringstream ss;
        ss << "Removing tracked devices which have been inactive for more than " <<
            device_idle_expiration << " seconds.";
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
        std::stringstream ss;
		ss << "Limiting maximum number of devices to " << max_num_devices <<
			" older devices will be removed from tracking when this limit is reached.";
		_MSG(ss.str(), MSGFLAG_INFO);

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
    local_eol_locker lock(&devicelist_mutex);

    store_all_devices();
    databaselog_write_all_devices();

    if (statestore != NULL) {
        delete(statestore);
        statestore = NULL;
    }

    globalreg->devicetracker = NULL;
    globalreg->RemoveGlobal("DEVICE_TRACKER");

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
    immutable_tracked_vec.clear();
    tracked_mac_multimap.clear();
}

Kis_Phy_Handler *Devicetracker::FetchPhyHandler(int in_phy) {
	map<int, Kis_Phy_Handler *>::iterator i = phy_handler_map.find(in_phy);

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

std::shared_ptr<kis_tracked_device_base> Devicetracker::FetchDevice(TrackedDeviceKey in_key) {
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
std::shared_ptr<kis_tracked_device_base> Devicetracker::UpdateCommonDevice(mac_addr in_mac,
        Kis_Phy_Handler *in_phy, kis_packet *in_pack, unsigned int in_flags) {

    local_locker lock(&devicelist_mutex);

    std::stringstream sstr;

	kis_layer1_packinfo *pack_l1info =
		(kis_layer1_packinfo *) in_pack->fetch(pack_comp_radiodata);
	kis_gps_packinfo *pack_gpsinfo =
		(kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);
	packetchain_comp_datasource *pack_datasrc =
		(packetchain_comp_datasource *) in_pack->fetch(pack_comp_datasrc);
	kis_common_info *pack_common =
		(kis_common_info *) in_pack->fetch(pack_comp_common);

    std::shared_ptr<kis_tracked_device_base> device = NULL;
    TrackedDeviceKey key;

    key = TrackedDeviceKey(globalreg->server_uuid_hash, in_phy->FetchPhynameHash(), in_mac);

	if ((device = FetchDevice(key)) == NULL) {
        device.reset(new kis_tracked_device_base(globalreg, device_base_id));
        // Device ID is the size of the vector so a new device always gets put
        // in it's numbered slot
        device->set_kis_internal_id(immutable_tracked_vec.size());

        device->set_key(key);
        device->set_macaddr(in_mac);
        device->set_phyname(in_phy->FetchPhyName());

        tracked_map[key] = device;
        tracked_vec.push_back(device);
        immutable_tracked_vec.push_back(device);
        tracked_mac_multimap.emplace(in_mac, device);

        device->set_first_time(in_pack->ts.tv_sec);

        if (globalreg->manufdb != NULL)
            device->set_manuf(globalreg->manufdb->LookupOUI(device->get_macaddr()));

        // fprintf(stderr, "debug - new device from key %s server %X phy %X\n", key.as_string().c_str(), globalreg->server_uuid_hash, in_phy->FetchPhynameHash());
    }

    // Tag the packet with the base device
	kis_tracked_device_info *devinfo =
		(kis_tracked_device_info *) in_pack->fetch(pack_comp_device);

	if (devinfo == NULL) {
		devinfo = new kis_tracked_device_info;
		devinfo->devref = device;
		in_pack->insert(pack_comp_device, devinfo);
	}

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
            std::shared_ptr<kis_historic_location> histloc(new kis_historic_location(globalreg, 0));

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

int Devicetracker::PopulateCommon(std::shared_ptr<kis_tracked_device_base> device, 
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

// Sort based on internal kismet ID
bool devicetracker_sort_internal_id(std::shared_ptr<kis_tracked_device_base> a,
	std::shared_ptr<kis_tracked_device_base> b) {

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
        // Limited scope lock

        local_demand_locker lock(&devicelist_mutex);

        auto b = vec.begin() + dpos;
        auto e = b + chunk_sz;
        bool last_loop = false;

        if (e > vec.end()) {
            e = vec.end();
            last_loop = true;
        }

        // Parallel for-each while inside a lock
        
        lock.lock();
        
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
                    if (ts_now - d->get_last_time() > device_idle_expiration) {
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

    if (dbv < 2) {
        // Define a simple table for custom device names, and a similar simple table
        // for notes; we store them outside the device record so that we have an
        // architecture available for saving them without requiring device snapshotting
        //
        // Names and tags are saved in both the custom tables AND the stored device 
        // record; stored devices retain their internal state, only new devices query
        // these tables.
        sql = 
            "CREATE TABLE device_names ("
            "phyname TEXT, "
            "devmac TEXT, "
            "name TEXT, "
            "UNIQUE(phyname, devmac) ON CONFLICT REPLACE)";

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
            "phyname TEXT, "
            "devmac TEXT, "
            "tag TEXT, "
            "content TEXT, "
            "UNIQUE(phyname, devmac, tag) ON CONFLICT REPLACE)";

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

    if (dbv < 3) {
        sql = 
            "DROP TABLE device_storage";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Devicetracker unable to drop old storage table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            sqlite3_close(db);
            db = NULL;
            return -1;
        }
    }

    Database_SetDBVersion(3);

    return 0;
}

void Devicetracker::AddDevice(std::shared_ptr<kis_tracked_device_base> device) {
    if (FetchDevice(device->get_key()) != NULL) {
        _MSG("Devicetracker tried to add device " + device->get_macaddr().Mac2String() + 
                " which already exists", MSGFLAG_ERROR);
        return;
    }

    // Device ID is the size of the vector so a new device always gets put
    // in it's numbered slot
    device->set_kis_internal_id(immutable_tracked_vec.size());

    tracked_map[device->get_key()] = device;
    tracked_vec.push_back(device);
    immutable_tracked_vec.push_back(device);
    tracked_mac_multimap.emplace(device->get_macaddr(), device);
}

int Devicetracker::store_devices() {
    SharedTrackerElement devs(new TrackerElement(TrackerVector));
    TrackerElementVector dv(devs);

    // Find anything that has changed
    for (auto v : immutable_tracked_vec) {
        if (v == NULL)
            continue;

        std::shared_ptr<kis_tracked_device_base> kdb =
            std::static_pointer_cast<kis_tracked_device_base>(v);
        if (kdb->get_mod_time() > last_database_logged)
            dv.push_back(v);
    }

    last_devicelist_saved = time(0);

    return store_devices(devs);
}

int Devicetracker::store_all_devices() {
    last_devicelist_saved = time(0);

    return store_devices(immutable_tracked_vec);
}

int Devicetracker::store_devices(TrackerElementVector devices) {
    if (!persistent_storage)
        return 0;

    if (statestore == NULL)
        return 0;

    int r = statestore->store_devices(devices);

    return r;
}

void Devicetracker::databaselog_write_devices() {
    SharedTrackerElement devs(new TrackerElement(TrackerVector));
    TrackerElementVector dv(devs);

    // Find anything that has changed
    for (auto v : immutable_tracked_vec) {
        if (v == NULL)
            continue;

        std::shared_ptr<kis_tracked_device_base> kdb =
            std::static_pointer_cast<kis_tracked_device_base>(v);
        if (kdb->get_mod_time() > last_database_logged)
            dv.push_back(v);
    }

    last_database_logged = time(0);

    databaselog_write_devices(devs);
}

void Devicetracker::databaselog_write_all_devices() {
    last_database_logged = time(0);

    databaselog_write_devices(immutable_tracked_vec);
}

void Devicetracker::databaselog_write_devices(TrackerElementVector vec) {
    std::shared_ptr<KisDatabaseLogfile> dbf =
        Globalreg::FetchGlobalAs<KisDatabaseLogfile>(globalreg, "DATABASELOG");
    
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

    return statestore->load_devices();
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

        /*
        // Read out the structured json
        SharedStructured sjson(new StructuredJson(uzbuf));
        */

        SharedStructured sstructured(new StructuredMsgpack(uzbuf));

        // Process structured object into a shared element
        SharedTrackerElement e = 
            StorageLoader::storage_to_tracker(entrytracker, sstructured);

        // Adopt it into a device
        std::shared_ptr<kis_tracked_device_base> 
            kdb(new kis_tracked_device_base(globalreg, device_base_id, e));

        // Give all the phys a shot at it
        for (auto p : phy_handler_map)
            p.second->LoadPhyStorage(e, kdb);

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
    } catch (const exception& e) {
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

    std::string sql;
    std::string macstring = in_dev->get_macaddr().Mac2String();
    std::string phystring = in_dev->get_phyname();

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    sql = 
        "SELECT name FROM device_names WHERE phyname = ? AND "
        "devmac = ?";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database query for stored devicename in " +
                ds_dbfile + ":" + string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return;
    }

    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, phystring.c_str(), phystring.length(), 0);
    sqlite3_bind_text(stmt, 2, macstring.c_str(), macstring.length(), 0);

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
                    string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
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

    std::string sql;
    std::string macstring = in_dev->get_macaddr().Mac2String();
    std::string phystring = in_dev->get_phyname();

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    sql = 
        "SELECT tag, content FROM device_names WHERE phyname = ? AND "
        "devmac = ?";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database query for stored devicename in " +
                ds_dbfile + ":" + string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return;
    }

    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, phystring.c_str(), phystring.length(), 0);
    sqlite3_bind_text(stmt, 2, macstring.c_str(), macstring.length(), 0);

    TrackerElementStringMap strmap(in_dev->get_tracker_tag_map());

    while (1) {
        r = sqlite3_step(stmt);

        if (r == SQLITE_ROW) {
            const unsigned char *tagstr;
            const unsigned char *contentstr;

            tagstr = (const unsigned char *) sqlite3_column_text(stmt, 0);
            contentstr = (const unsigned char *) sqlite3_column_text(stmt, 1);

            SharedTrackerElement tagc(new TrackerElement(TrackerString));

            tagc->set(std::string((const char *) contentstr));

            TrackerElementStringMap::pair 
                strpair(std::string((const char *) tagstr), tagc);

            strmap.insert(strpair);

        } else if (r == SQLITE_DONE) {
            break;
        } else {
            _MSG("Devicetracker encountered an error loading stored device username: " + 
                    string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            break;
        }
    }

    sqlite3_finalize(stmt);
}

void Devicetracker::SetDeviceUserName(std::shared_ptr<kis_tracked_device_base> in_dev,
        std::string in_username) {

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

    std::string macstring = in_dev->get_macaddr().Mac2String();
    std::string phystring = in_dev->get_phyname();

    sql = 
        "INSERT INTO device_names "
        "(phyname, devmac, name) "
        "VALUES (?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database insert for device name in " +
                ds_dbfile + ":" + string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return;
    }
 
    sqlite3_reset(stmt);

    sqlite3_bind_text(stmt, 1, phystring.c_str(), phystring.length(), 0);
    sqlite3_bind_text(stmt, 2, macstring.c_str(), macstring.length(), 0);
    sqlite3_bind_text(stmt, 3, in_username.c_str(), in_username.length(), 0);

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

    SharedTrackerElement e(new TrackerElement(TrackerString));
    e->set(std::string(in_content));
    TrackerElementStringMap sm(in_dev->get_tracker_tag_map());

    auto t = sm.find(in_tag);
    if (t != sm.end())
        sm.erase(t);
    sm.insert(TrackerElementStringMap::pair(in_tag, e));

    if (!Database_Valid()) {
        _MSG("Unable to store device name to permanent storage, the database connection "
                "is not available", MSGFLAG_ERROR);
        return;
    }

    std::string sql;

    int r;
    sqlite3_stmt *stmt = NULL;
    const char *pz = NULL;

    std::string macstring = in_dev->get_macaddr().Mac2String();
    std::string phystring = in_dev->get_phyname();

    sql = 
        "INSERT INTO device_tags "
        "(phyname, devmac, tag, content) "
        "VALUES (?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database insert for device tags in " +
                ds_dbfile + ":" + string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return;
    }
 
    sqlite3_reset(stmt);

    sqlite3_bind_text(stmt, 1, phystring.c_str(), phystring.length(), 0);
    sqlite3_bind_text(stmt, 2, macstring.c_str(), macstring.length(), 0);
    sqlite3_bind_text(stmt, 3, in_tag.c_str(), in_tag.length(), 0);
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

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &stmt, &pz);

    if (r != SQLITE_OK) {
        _MSG("Devicetracker unable to prepare database query for stored devices in " +
                ds_dbfile + ":" + string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
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
                    string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
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
                ds_dbfile + ":" + string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
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
                    string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            break;
        }
    }

    sqlite3_finalize(stmt);

    return NULL;
}

int DevicetrackerStateStore::store_devices(TrackerElementVector devices) {
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
                ds_dbfile + ":" + string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        return -1;
    }
 
    // Use a function worker to break up the load and insert it into the
    // database
    devicetracker_function_worker fw(globalreg,
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
                    StorageMsgpackAdapter::Pack(globalreg, *serialstream, d, NULL);
                }

                // Sync the buffers
                zobuf.pubsync();
                sbuf.pubsync();

                serialstring = sbuf.str();

                macstring = kdb->get_macaddr().Mac2String();
                phystring = kdb->get_phyname();

                sqlite3_bind_int(stmt, 1, kdb->get_first_time());
                sqlite3_bind_int(stmt, 2, kdb->get_last_time());
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
