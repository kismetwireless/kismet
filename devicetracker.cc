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

#include "alertracker.h"
#include "base64.h"
#include "configfile.h"
#include "datasourcetracker.h"
#include "devicetracker.h"
#include "devicetracker_component.h"
#include "devicetracker_view.h"
#include "entrytracker.h"
#include "globalregistry.h"
#include "gpstracker.h"
#include "json_adapter.h"
#include "kis_datasource.h"
#include "kis_databaselogfile.h"
#include "manuf.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"
#include "pcapng_stream_futurebuf.h"
#include "util.h"
#include "zstr.hpp"

int Devicetracker_packethook_commontracker(CHAINCALL_PARMS) {
	return ((device_tracker *) auxdata)->common_tracker(in_pack);
}

device_tracker::device_tracker() :
    lifetime_global(),
    kis_database(Globalreg::globalreg, "devicetracker"),
    deferred_startup() {

    view_mutex.set_name("device_tracker::view_mutex");
    devicelist_mutex.set_name("device_tracker::devicelist_mutex");
    range_mutex.set_name("device_tracker::range_mutex");

    next_phy_id = 0;

    // create a vector
    immutable_tracked_vec = std::make_shared<tracker_element_vector>();

    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();

	eventbus =
		Globalreg::fetch_mandatory_global_as<event_bus>();

    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();

    timetracker =
        Globalreg::fetch_mandatory_global_as<time_tracker>();

    streamtracker =
        Globalreg::fetch_mandatory_global_as<stream_tracker>();

    device_base_id =
        entrytracker->register_field("kismet.device.base", 
                tracker_element_factory<kis_tracked_device_base>(),
                "core device record");
    device_list_base_id =
        entrytracker->register_field("kismet.device.list",
                tracker_element_factory<tracker_element_vector>(),
                "list of devices");


    device_summary_base_id =
        entrytracker->register_field("kismet.device.summary_list",
                tracker_element_factory<tracker_element_vector>(),
                "summary list of devices");

    device_update_required_id =
        entrytracker->register_field("kismet.devicelist.refresh",
                tracker_element_factory<tracker_element_uint8>(),
                "device list refresh recommended");
    device_update_timestamp_id =
        entrytracker->register_field("kismet.devicelist.timestamp",
                tracker_element_factory<tracker_element_uint64>(),
                "device list timestamp");

    // These need unique IDs to be put in the map for serialization.
    // They also need unique field names, we can rename them with setlocalname
    dt_length_id =
        entrytracker->register_field("kismet.datatables.recordsTotal", 
                tracker_element_factory<tracker_element_uint64>(),
                "datatable records total");
    dt_filter_id =
        entrytracker->register_field("kismet.datatables.recordsFiltered", 
                tracker_element_factory<tracker_element_uint64>(),
                "datatable records filtered");
    dt_draw_id =
        entrytracker->register_field("kismet.datatables.draw", 
                tracker_element_factory<tracker_element_uint64>(),
                "Datatable records draw ID");

    // Generate the system-wide packet RRD
    packets_rrd = 
        entrytracker->register_and_get_field_as<kis_tracked_rrd<>>("kismet.device.packets_rrd",
            tracker_element_factory<kis_tracked_rrd<>>(), "Packets seen RRD");

	num_packets = num_datapackets = num_errorpackets =
		num_filterpackets = 0;

    std::shared_ptr<packet_chain> packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>(globalreg, "PACKETCHAIN");

	// Register global packet components used by the device tracker and
	// subsequent parts
	pack_comp_device = 
		packetchain->register_packet_component("DEVICE");

	pack_comp_common =  
		packetchain->register_packet_component("COMMON");

	pack_comp_basicdata = 
		packetchain->register_packet_component("BASICDATA");

    pack_comp_mangleframe =
		packetchain->register_packet_component("MANGLEDATA");

	pack_comp_radiodata =
		packetchain->register_packet_component("RADIODATA");

	pack_comp_gps =
		packetchain->register_packet_component("GPS");

	pack_comp_datasrc = 
		packetchain->register_packet_component("KISDATASRC");

	// Common tracker, very early in the tracker chain
	packetchain->register_handler(&Devicetracker_packethook_commontracker,
											this, CHAINPOS_TRACKER, -100);

    // Post any events related to the device generated during tracking mode
    // (like a new device being created) at the very END of tracking, so that
    // the device has as complete a view as possible; if we trigger it at the
    // BEGINNING of the chain, we get only the generic device with none of the
    // phy-specific attachments.
    packetchain_tracking_done_id =
        packetchain->register_handler([this](kis_packet *in_packet) -> int {
            for (const auto& e : in_packet->process_complete_events)
                eventbus->publish(e);
            return 1;
        }, CHAINPOS_TRACKER, 0x7FFF'FFFF);

    if (!globalreg->kismet_config->fetch_opt_bool("track_device_rrds", true)) {
        _MSG("Not tracking historical packet data to save RAM", MSGFLAG_INFO);
        ram_no_rrd = true;
    } else {
        ram_no_rrd = false;
    }

    if (!globalreg->kismet_config->fetch_opt_bool("track_device_seenby_views", true)) {
        _MSG("Not building device seenby views to save RAM", MSGFLAG_INFO);
        map_seenby_views = false;
    } else {
        map_seenby_views = true;
    }

    if (!globalreg->kismet_config->fetch_opt_bool("track_device_phy_views", true)) {
        _MSG("Not building device phy views to save RAM", MSGFLAG_INFO);
        map_phy_views = false;
    } else {
        map_phy_views = true;
    }

    if (globalreg->kismet_config->fetch_opt_bool("kis_log_devices", true)) {
        unsigned int lograte = 
            globalreg->kismet_config->fetch_opt_uint("kis_log_device_rate", 30);

        _MSG("Saving devices to the Kismet database log every " + uint_to_string(lograte) + 
                " seconds.", MSGFLAG_INFO);

        databaselog_logging = false;

        databaselog_timer =
            timetracker->register_timer(std::chrono::seconds(lograte), 1,
                [this](int) -> int {
                    local_locker l(&databaselog_mutex);

                    if (databaselog_logging) {
                        _MSG("Attempting to log devices, but devices are still being "
                                "saved from the last logging attempt.  It's possible your "
                                "system is slow or you have a very large number of devices "
                                "to log.  Try increasing the delay in 'kis_log_device_rate' "
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

                    // Detach the thread, we don't care about it
                    t.detach();

                    return 1;
                });
    } else {
        databaselog_timer = -1;
    }

#if 0
    last_devicelist_saved = 0;
#endif

    last_database_logged = 0;

    // Preload the vector for speed
    unsigned int preload_sz = 
        globalreg->kismet_config->fetch_opt_uint("tracker_device_presize", 1000);

    tracked_vec.reserve(preload_sz);
    immutable_tracked_vec->reserve(preload_sz);

    // Set up the device timeout
    device_idle_expiration =
        globalreg->kismet_config->fetch_opt_int("tracker_device_timeout", 0);

    if (device_idle_expiration != 0) {
        device_idle_min_packets =
            globalreg->kismet_config->fetch_opt_uint("tracker_device_packets", 0);

        std::stringstream ss;
        ss << "Removing tracked devices which have been inactive for more than " <<
            device_idle_expiration << " seconds";

        if (device_idle_min_packets > 2) 
            ss << " and fewer than " << device_idle_min_packets << " packets";

        _MSG(ss.str(), MSGFLAG_INFO);

		// Schedule device idle reaping every minute
        device_idle_timer =
            timetracker->register_timer(std::chrono::seconds(60), 1,
                [this](int eventid) -> int {
                    timetracker_event(eventid);
                    return 1;
                });
    } else {
        device_idle_timer = -1;
    }

	max_num_devices =
		globalreg->kismet_config->fetch_opt_uint("tracker_max_devices", 0);

	if (max_num_devices > 0) {
        _MSG_INFO("Limiting maximum number of devices to {}, older devices will be "
                "removed from tracking when this limit is reached.", max_num_devices);

		// Schedule max device reaping every 5 seconds
		max_devices_timer =
			timetracker->register_timer(SERVER_TIMESLICES_SEC * 5, NULL, 1, 
                [this](int eventid) -> int {
                    timetracker_event(eventid);
                    return 1;
                });
	} else {
		max_devices_timer = -1;
	}

    full_refresh_time = globalreg->timestamp.tv_sec;

    track_history_cloud =
        globalreg->kismet_config->fetch_opt_bool("keep_location_cloud_history", true);

    if (!track_history_cloud) {
        _MSG("Location history cloud tracking disabled.  This may prevent some plugins "
                "from working.  This can be re-enabled by setting "
                "keep_datasource_signal_history=true", MSGFLAG_INFO);
    }

    track_persource_history =
        globalreg->kismet_config->fetch_opt_bool("keep_datasource_signal_history", true);

    if (!track_persource_history) {
        _MSG("Per-source signal history tracking disabled.  This may prevent some plugins "
                "from working.  This can be re-enabled by setting "
                "keep_datasource_signal_history=true", MSGFLAG_INFO);
    }

    // Initialize the view system
    view_vec = std::make_shared<tracker_element_vector>();

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/devices/views/all_views", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(view_vec, &view_mutex));

    httpd->register_route("/devices/multimac/devices", {"POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    return multimac_endp_handler(con);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    lock_device_range(devs);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    unlock_device_range(devs);
                }));

    httpd->register_route("/devices/multikey/devices", {"POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    return multikey_endp_handler(con, false);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    lock_device_range(devs);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    unlock_device_range(devs);
                }));

    httpd->register_route("/devices/multikey/as-object/devices", {"POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    return multikey_endp_handler(con, true);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    lock_device_range(devs);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    unlock_device_range(devs);
                }));

    httpd->register_route("/devices/all_devices", {"GET", "POST"}, httpd->RO_ROLE, {"ekjson", "itjson"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    auto device_ro = std::make_shared<tracker_element_vector>();

                    {
                        local_locker l(&devicelist_mutex, "all_devices ek/itjson copy");
                        device_ro->set(immutable_tracked_vec->begin(), immutable_tracked_vec->end());
                    }

                    return device_ro;
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    lock_device_range(devs);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    unlock_device_range(devs);
                }));

    httpd->register_route("/devices/by-key/:key/device", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    auto key_k = con->uri_params().find(":key");
                    auto devkey = string_to_n<device_key>(key_k->second);

                    if (devkey.get_error())
                        throw std::runtime_error("invalid device key");

                    auto dev = fetch_device(devkey);

                    if (dev == nullptr)
                        throw std::runtime_error("nonexistent device key");

                    return dev;
                }));

    httpd->register_route("/devices/by-mac/:mac/devices", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    auto mac_k = con->uri_params().find(":mac");
                    auto mac = string_to_n<mac_addr>(mac_k->second);

                    if (mac.error())
                        throw std::runtime_error("invalid device MAC");

                    auto devvec = std::make_shared<tracker_element_vector>();

                    local_shared_locker l(&devicelist_mutex, "devices/by-mac/");
                    const auto mmp = tracked_mac_multimap.equal_range(mac);
                    for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi)
                        devvec->push_back(mmpi->second);

                    return devvec;
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    lock_device_range(devs);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    unlock_device_range(devs);
                }));

    httpd->register_route("/devices/last-time/:timestamp/devices", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    auto ts_k = con->uri_params().find(":timestamp");
                    auto lastts = string_to_n<long>(ts_k->second);

                    auto ts_worker = device_tracker_view_function_worker(
                        [lastts](std::shared_ptr<kis_tracked_device_base> d) -> bool {
                            if (d->get_last_time() <= lastts)
                                return false;
                            return true;
                        });

                    return do_readonly_device_work(ts_worker);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    lock_device_range(devs);
                },
                [this](std::shared_ptr<tracker_element> devs) {
                    unlock_device_range(devs);
                }));

    httpd->register_route("/devices/by-key/:key/set_name", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](shared_con con) {
                    auto key_k = con->uri_params().find(":key");
                    auto devkey = string_to_n<device_key>(key_k->second);

                    if (devkey.get_error())
                        throw std::runtime_error("invalid device key");

                    auto dev = fetch_device(devkey);

                    if (dev == nullptr)
                        throw std::runtime_error("no such device");

                    auto name = con->json()["username"].asString();

                    set_device_user_name(dev, name);

                    std::ostream os(&con->response_stream());
                    os << "Device name set\n";
                }));

    httpd->register_route("/devices/by-key/:key/set_tag", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](shared_con con) {
                    auto key_k = con->uri_params().find(":key");
                    auto devkey = string_to_n<device_key>(key_k->second);

                    if (devkey.get_error())
                        throw std::runtime_error("invalid device key");

                    auto dev = fetch_device(devkey);

                    if (dev == nullptr)
                        throw std::runtime_error("no such device");

                    auto tag = con->json()["tagname"].asString();
                    auto content = con->json()["tagvalue"].asString();

                    set_device_tag(dev, tag, content);

                    std::ostream os(&con->response_stream());
                    os << "Device tag set\n";
                }));

    httpd->register_route("/devices/pcap/by-key/:key/packets", {"GET"}, "pcap", {"pcapng"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto key_k = con->uri_params().find(":key");
                    auto devkey = string_to_n<device_key>(key_k->second);

                    if (devkey.get_error())
                        throw std::runtime_error("invalid device key");

                    auto pcapng = std::make_shared<pcapng_stream_packetchain>(con->response_stream(),
                            [this, devkey](kis_packet *packet) -> bool {
                                auto devinfo = packet->fetch<kis_tracked_device_info>(pack_comp_device);

                                if (devinfo == nullptr)
                                    return false;

                                for (const auto& dri : devinfo->devrefs) {
                                    if (dri.second->get_key() == devkey)
                                        return true;
                                }

                                return true;
                            },
                            nullptr,
                            1024*512);
        
                    con->clear_timeout();
                    con->set_target_file(fmt::format("kismet-device-{}.pcapng", devkey));
                    con->set_closure_cb([pcapng]() { pcapng->stop_stream("http connection lost"); });

                    auto sid = 
                        streamtracker->register_streamer(pcapng, fmt::format("kismet-device-{}.pcapng", devkey),
                            "pcapng", "httpd", 
                            fmt::format("pcapng of packets for dev key {}", devkey));

                    pcapng->start_stream();
                    pcapng->block_until_stream_done();

                    streamtracker->remove_streamer(sid);
                }));


    phy_phyentry_id =
        entrytracker->register_field("kismet.phy.phy",
                tracker_element_factory<tracker_element_map>(),
                "Kismet PHY handler");

    phy_phyname_id =
        entrytracker->register_field("kismet.phy.phy_name",
                tracker_element_factory<tracker_element_string>(),
                "Phy name (consistent across executions)");

    phy_phyid_id =
        entrytracker->register_field("kismet.phy.phy_id",
                tracker_element_factory<tracker_element_uint32>(),
                "Phy ID (dynamic runtime index, may change between executions)");

    phy_devices_count_id =
        entrytracker->register_field("kismet.phy.device_count",
                tracker_element_factory<tracker_element_uint64>(),
                "Devices present in phy");

    phy_packets_count_id =
        entrytracker->register_field("kismet.phy.packet_count",
                tracker_element_factory<tracker_element_uint64>(),
                "Packets seen in phy");

    httpd->register_route("/phy/all_phys", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    return all_phys_endp_handler(con);
            }));

    // Open and upgrade the DB, default path
    database_open("");
    database_upgrade_db();

    new_datasource_evt_id = 
        eventbus->register_listener(datasource_tracker::event_new_datasource(),
                [this](std::shared_ptr<eventbus_event> evt) {
                    handle_new_datasource_event(evt);
                });

    new_device_evt_id = 
        eventbus->register_listener(device_tracker::event_new_device(),
                [this](std::shared_ptr<eventbus_event> evt) {
                    handle_new_device_event(evt);
                });

    devicefound_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("devicefound_timeout", 60);
    devicelost_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("devicelost_timeout", 60);

    alert_macdevice_found_ref =
        alertracker->activate_configured_alert("DEVICEFOUND",
                "A target device has been seen", -1);
    alert_macdevice_lost_ref =
        alertracker->activate_configured_alert("DEVICELOST",
                "A target device has timed out", -1);

    auto found_vec = 
        Globalreg::globalreg->kismet_config->fetch_opt_vec("devicefound");
    for (const auto& m : found_vec) {
        auto mac = mac_addr(m);

        if (mac.state.error) {
            _MSG_ERROR("Invalid 'devicefound=' option, expected MAC address "
                    "or MAC address mask");
            continue;
        }

        macdevice_alert_conf_map[mac] = 1;
    }

    auto lost_vec =
        Globalreg::globalreg->kismet_config->fetch_opt_vec("devicelost");
    for (const auto& m : lost_vec) {
        auto mac = mac_addr(m);

        if (mac.state.error) {
            _MSG_ERROR("Invalid 'devicelost=' option, expected MAC address "
                    "or MAC address mask.");
            continue;
        }

        auto k = macdevice_alert_conf_map.find(mac);
        if (k != macdevice_alert_conf_map.end())
            k->second = 3;
        else
            macdevice_alert_conf_map[mac] = 2;
    }

    macdevice_alert_timeout_timer =
        timetracker->register_timer(std::chrono::seconds(30), 1,
                [this](int) -> int {
                    macdevice_timer_event();
                    return 1;
                });

    device_location_signal_threshold =
        Globalreg::globalreg->kismet_config->fetch_opt_as<int>("device_location_signal_threshold", 0);

    // httpd->register_alias("/devices/summary/devices.json", "/devices/views/all/devices.json");
}

void device_tracker::trigger_deferred_startup() {
    // Defer view creation
    all_view =
        std::make_shared<device_tracker_view>("all", 
                "All devices",
                [](std::shared_ptr<kis_tracked_device_base>) -> bool {
                    return true;
                },
                [](std::shared_ptr<kis_tracked_device_base>) -> bool {
                    return true;
                });
    add_view(all_view);

}

device_tracker::~device_tracker() {
    local_locker lock(&devicelist_mutex);

    if (eventbus != nullptr) {
        eventbus->remove_listener(new_datasource_evt_id);
        eventbus->remove_listener(new_device_evt_id);
    }

    globalreg->devicetracker = NULL;
    globalreg->remove_global("DEVICETRACKER");

    std::shared_ptr<packet_chain> packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>(globalreg, "PACKETCHAIN");
    if (packetchain != NULL) {
        packetchain->remove_handler(&Devicetracker_packethook_commontracker,
                CHAINPOS_TRACKER);
        packetchain->remove_handler(packetchain_tracking_done_id, CHAINPOS_TRACKER);
    }

    std::shared_ptr<time_tracker> timetracker = 
        Globalreg::fetch_global_as<time_tracker>(globalreg, "TIMETRACKER");
    if (timetracker != NULL) {
        timetracker->remove_timer(device_idle_timer);
        timetracker->remove_timer(max_devices_timer);
        timetracker->remove_timer(device_storage_timer);
    }

    // TODO broken for now
    /*
	if (track_filter != NULL)
		delete track_filter;
    */

    for (auto p : phy_handler_map)
        delete(p.second);

    tracked_vec.clear();
    immutable_tracked_vec->clear();
    tracked_mac_multimap.clear();
}

void device_tracker::macdevice_timer_event() {
    local_locker lock(&devicelist_mutex);

    time_t now = time(0);

    // Put the ones we still monitor into a new vector and swap
    // at the end
    auto keep_vec = std::vector<std::shared_ptr<kis_tracked_device_base>>{};
    for (const auto& k : macdevice_flagged_vec) {
        if (now - k->get_mod_time() > devicelost_timeout) {
            auto alrt = 
                fmt::format("Monitored device {} ({}) hasn't been seen for {} "
                        "seconds.", k->get_macaddr(), k->get_commonname(),
                        devicelost_timeout);
            alertracker->raise_alert(alert_macdevice_lost_ref,
                    nullptr, k->get_macaddr(), mac_addr{0}, 
                    mac_addr{0}, mac_addr{0}, k->get_channel(), 
                    alrt);
        } else {
            keep_vec.push_back(k);
        }
    }

    macdevice_flagged_vec = keep_vec;
}

kis_phy_handler *device_tracker::fetch_phy_handler(int in_phy) {
	auto i = phy_handler_map.find(in_phy);

	if (i == phy_handler_map.end())
		return NULL;

	return i->second;
}

kis_phy_handler *device_tracker::fetch_phy_handler_by_name(const std::string& in_name) {
    for (const auto& i : phy_handler_map) {
        if (i.second->fetch_phy_name() == in_name) {
            return i.second;
        }
    }
    return NULL;
}

std::string device_tracker::fetch_phy_name(int in_phy) {
    if (in_phy == KIS_PHY_ANY) {
        return "ANY";
    }

    kis_phy_handler *phyh = fetch_phy_handler(in_phy);

    if (phyh == NULL) {
        return "UNKNOWN";
    }

    return phyh->fetch_phy_name();
}

int device_tracker::fetch_num_devices() {
    local_shared_locker lock(&devicelist_mutex);

    return tracked_map.size();
}

int device_tracker::fetch_num_packets() {
    return num_packets;
}


int device_tracker::register_phy_handler(kis_phy_handler *in_weak_handler) {
	int num = next_phy_id++;

	kis_phy_handler *strongphy = in_weak_handler->create_phy_handler(globalreg, num);

	phy_handler_map[num] = strongphy;

	phy_packets[num] = 0;
	phy_datapackets[num] = 0;
	phy_errorpackets[num] = 0;
	phy_filterpackets[num] = 0;

    if (map_phy_views) {
        auto phy_id = strongphy->fetch_phy_id();

        auto k = phy_view_map.find(phy_id);
        if (k == phy_view_map.end()) {
            auto phy_view = 
                std::make_shared<device_tracker_view>(fmt::format("phy-{}", strongphy->fetch_phy_name()),
                        fmt::format("{} devices", strongphy->fetch_phy_name()),
                        std::vector<std::string>{"phy", strongphy->fetch_phy_name()},
                        [phy_id](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                            return dev->get_phyid() == phy_id;
                        },
                        [phy_id](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                            return dev->get_phyid() == phy_id;
                        }
                        );
            phy_view_map[phy_id] = phy_view;
            add_view(phy_view);
        }
    }

    auto evt = eventbus->get_eventbus_event(event_new_phy());
    evt->get_event_content()->insert(event_new_phy(), 
            std::make_shared<tracker_element_string>(strongphy->fetch_phy_name()));
    eventbus->publish(evt);

	_MSG("Registered PHY handler '" + strongphy->fetch_phy_name() + "' as ID " +
		 int_to_string(num), MSGFLAG_INFO);

	return num;
}

void device_tracker::update_full_refresh() {
    full_refresh_time = globalreg->timestamp.tv_sec;
}

std::shared_ptr<kis_tracked_device_base> device_tracker::fetch_device(device_key in_key) {
    local_shared_locker lock(&devicelist_mutex);

	device_itr i = tracked_map.find(in_key);

	if (i != tracked_map.end())
		return i->second;

	return NULL;
}

int device_tracker::common_tracker(kis_packet *in_pack) {
    local_locker lock(&devicelist_mutex);

	if (in_pack->error) {
		// and bail
		num_errorpackets++;
		return 0;
	}

	kis_common_info *pack_common =
        (kis_common_info *) in_pack->fetch(pack_comp_common);

    if (!ram_no_rrd)
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
		_MSG("Invalid phy id " + int_to_string(pack_common->phyid) + " in packet "
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
    device_tracker::update_common_device(kis_common_info *pack_common, 
            mac_addr in_mac, kis_phy_handler *in_phy, kis_packet *in_pack, 
            unsigned int in_flags, std::string in_basic_type) {

    // The device list has to be locked for the duration of the device assignment and
    // update since devices only get added at the end
    local_locker list_locker(&devicelist_mutex);

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

    key = device_key(in_phy->fetch_phyname_hash(), in_mac);

	if ((device = fetch_device(key)) == NULL) {
        if (in_flags & UCD_UPDATE_EXISTING_ONLY)
            return NULL;

        device =
            std::make_shared<kis_tracked_device_base>(device_base_id);
        // Device ID is the size of the vector so a new device always gets put
        // in it's numbered slot
        device->set_kis_internal_id(immutable_tracked_vec->size());

        device->set_key(key);

        device->device_mutex.set_name(fmt::format("kis_tracked_device({})", key));
        device->set_macaddr(in_mac);
        device->set_tracker_phyname(get_cached_phyname(in_phy->fetch_phy_name()));
		device->set_phyid(in_phy->fetch_phy_id());

        device->set_server_uuid(globalreg->server_uuid);

        device->set_first_time(in_pack->ts.tv_sec);

        device->set_tracker_type_string(get_cached_devicetype(in_basic_type));

        if (globalreg->manufdb != NULL) {
            device->set_manuf(globalreg->manufdb->lookup_oui(in_mac));
        }

        load_stored_username(device);
        load_stored_tags(device);

        new_device = true;

    }

    // Lock the device itself for updating, now that it exists
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

    // Raise alerts for new devices or devices which have been
    // idle and re-appeared
    // Also keep them in macdevice_flagged_vec to send devicelost alerts
    auto k = macdevice_alert_conf_map.find(device->get_macaddr());
    if (k != macdevice_alert_conf_map.end()) {
        if (new_device || ((device->get_last_time() < in_pack->ts.tv_sec &&
            in_pack->ts.tv_sec - device->get_last_time() > devicefound_timeout))) {

            if (k->second & 0x1) {
                auto alrt =
                fmt::format("Monitored device {} ({}) has been found.",
                        device->get_macaddr(), device->get_commonname());
                alertracker->raise_alert(alert_macdevice_found_ref,
                        in_pack, device->get_macaddr(), mac_addr{0}, 
                        mac_addr{0}, mac_addr{0}, device->get_channel(), 
                        alrt);
            }
            if (k->second & 0x2) {
                macdevice_flagged_vec.push_back(device);
            }
        }

    }

    if (device->get_last_time() < in_pack->ts.tv_sec)
        device->set_last_time(in_pack->ts.tv_sec);

    if (in_flags & UCD_UPDATE_PACKETS) {
        device->inc_packets();

        if (!ram_no_rrd)
            device->get_packets_rrd()->add_sample(1, globalreg->timestamp.tv_sec);

        if (pack_common != NULL) {
            if (pack_common->error)
                device->inc_error_packets();

            if (pack_common->type == packet_basic_data) {
                // TODO fix directional data
                device->inc_data_packets();
                device->inc_datasize(pack_common->datasize);

                if (!ram_no_rrd) {
                    device->get_data_rrd()->add_sample(pack_common->datasize,
                            globalreg->timestamp.tv_sec);

#if 0
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
#endif
                }

            } else if (pack_common->type == packet_basic_mgmt ||
                    pack_common->type == packet_basic_phy) {
                device->inc_llc_packets();
            }

        }
    }

	if ((in_flags & UCD_UPDATE_FREQUENCIES)) {
        if (pack_l1info != NULL) {
            if (pack_l1info->channel != "0" && pack_l1info->channel != "") {
                device->set_channel(pack_l1info->channel);
            }
            if (pack_l1info->freq_khz != 0)
                device->set_frequency(pack_l1info->freq_khz);

            packinfo_sig_combo *sc = new packinfo_sig_combo(pack_l1info, pack_gpsinfo);
            device->get_signal_data()->append_signal(*sc, !ram_no_rrd, in_pack->ts.tv_sec);

            delete(sc);

            device->inc_frequency_count((int) pack_l1info->freq_khz);
        } else if (pack_common != NULL) {
            if (pack_common->channel != "0" && pack_common->channel != "") {
                device->set_channel(pack_common->channel);
            }
            if (pack_common->freq_khz != 0)
                device->set_frequency(pack_common->freq_khz);
            
            device->inc_frequency_count((int) pack_common->freq_khz);
        }
	}

    if (((in_flags & UCD_UPDATE_LOCATION) ||
                ((in_flags & UCD_UPDATE_EMPTY_LOCATION) && !device->has_location_cloud())) &&
            pack_gpsinfo != NULL &&
            (device_location_signal_threshold == 0 || 
             ( device_location_signal_threshold != 0 && pack_l1info != NULL &&
             pack_l1info->signal_dbm >= device_location_signal_threshold))) {
        device->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                pack_gpsinfo->heading);

        // Throttle history cloud to one update per second to prevent floods of
        // data from swamping the cloud
        if (track_history_cloud && pack_gpsinfo->fix >= 2 &&
                in_pack->ts.tv_sec - device->get_location_cloud()->get_last_sample_ts() >= 1) {
            auto histloc = std::make_shared<kis_historic_location>();

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

        packinfo_sig_combo *sc = NULL;

        if (pack_l1info != NULL)
            f = pack_l1info->freq_khz;

        // Generate a signal record if we're following per-source signal
        if (track_persource_history) {
            sc = new packinfo_sig_combo(pack_l1info, pack_gpsinfo);
        }

        device->inc_seenby_count(pack_datasrc->ref_source, in_pack->ts.tv_sec, f, sc, !ram_no_rrd);

        if (map_seenby_views)
            update_view_device(device);

        if (sc != NULL)
            delete(sc);
	}

    if (pack_common != NULL)
        device->add_basic_crypt(pack_common->basic_crypt_set);

    // Add the new device at the end once we've populated it
    if (new_device) {
        tracked_map[key] = device;

        tracked_vec.push_back(device);
        immutable_tracked_vec->push_back(device);

        auto mm_pair = std::make_pair(in_mac, device);
        tracked_mac_multimap.insert(mm_pair);

        // Unlock the device list before adding it to the device views
        list_locker.unlock();

        // If we have no packet info, add it to the device list immediately,
        // otherwise, flag the packet to trigger a new device event at the
        // end of the packet processing stage of the chain
        if (in_pack == nullptr) {
            new_view_device(device);
            auto evt = eventbus->get_eventbus_event(event_new_device());
            evt->get_event_content()->insert(event_new_device(), device);
            eventbus->publish(evt);
        } else {
            auto evt = eventbus->get_eventbus_event(event_new_device());
            evt->get_event_content()->insert(event_new_device(), device);
            in_pack->process_complete_events.push_back(evt);
        }
    }

    return device;
}

// Sort based on internal kismet ID
bool devicetracker_sort_internal_id(std::shared_ptr<kis_tracked_device_base> a,
	std::shared_ptr<kis_tracked_device_base> b) {
	return a->get_kis_internal_id() < b->get_kis_internal_id();
}

std::shared_ptr<tracker_element_vector> device_tracker::do_readonly_device_work(device_tracker_view_worker& worker, 
        std::shared_ptr<tracker_element_vector> vec) {

    return all_view->do_readonly_device_work(worker, vec);
}

std::shared_ptr<tracker_element_vector> device_tracker::do_device_work(device_tracker_view_worker& worker) {
    return all_view->do_device_work(worker);
}

std::shared_ptr<tracker_element_vector> device_tracker::do_readonly_device_work(device_tracker_view_worker& worker) {
    return all_view->do_readonly_device_work(worker);
}

// Simple std::sort comparison function to order by the least frequently
// seen devices
bool devicetracker_sort_lastseen(std::shared_ptr<kis_tracked_device_base> a,
	std::shared_ptr<kis_tracked_device_base> b) {

	return a->get_last_time() < b->get_last_time();
}

void device_tracker::timetracker_event(int eventid) {
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

                        // Forget it from any views
                        remove_view_device(d);

                        // Forget it from the immutable vec, but keep its 
                        // position; we need to have vecpos = devid
                        auto iti = immutable_tracked_vec->begin() + d->get_kis_internal_id();
                        (*iti).reset();

                        purged = true;

                        return true;
                    }

                    return false;
         
                    }), tracked_vec.end());

        if (purged)
            update_full_refresh();

    } else if (eventid == max_devices_timer) {
		local_locker lock(&devicelist_mutex);

		// Do nothing if we don't care
		if (max_num_devices <= 0)
            return;

		// Do nothing if the number of devices is less than the max
		if (tracked_vec.size() <= max_num_devices)
            return;

        // Do an update since we're trimming something
        update_full_refresh();

		// Now things start getting expensive.  Start by sorting the
		// vector of devices - anything else that has to sort the entire list
        // has to sort it themselves
        std::stable_sort(tracked_vec.begin(), tracked_vec.end(), 
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
}

void device_tracker::usage(const char *name __attribute__((unused))) {
    printf("\n");
	printf(" *** Device Tracking Options ***\n");
	printf("     --device-timeout=n       Expire devices after N seconds\n"
          );
}

void device_tracker::lock_devicelist() {
    local_eol_locker lock(&devicelist_mutex);
}

void device_tracker::unlock_devicelist() {
    local_unlocker unlock(&devicelist_mutex);
}

int device_tracker::database_upgrade_db() {
    local_locker dblock(&ds_mutex);

    unsigned int dbv = database_get_db_version();
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
            _MSG("device_tracker unable to create device_names table in " + ds_dbfile + ": " +
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
            _MSG("device_tracker unable to create device_tags table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            sqlite3_close(db);
            db = NULL;
            return -1;
        }
    }

    database_set_db_version(4);

    return 0;
}

void device_tracker::add_device(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker lock(&devicelist_mutex);

    if (fetch_device(device->get_key()) != NULL) {
        _MSG("device_tracker tried to add device " + device->get_macaddr().mac_to_string() + 
                " which already exists", MSGFLAG_ERROR);
        return;
    }

    // Device ID is the size of the vector so a new device always gets put
    // in it's numbered slot
    device->set_kis_internal_id(immutable_tracked_vec->size());

    tracked_map[device->get_key()] = device;
    tracked_vec.push_back(device);
    immutable_tracked_vec->push_back(device);

    auto mm_pair = std::make_pair(device->get_macaddr(), device);
    tracked_mac_multimap.emplace(mm_pair);
}

bool device_tracker::add_view(std::shared_ptr<device_tracker_view> in_view) {
    local_locker l(&view_mutex);

    for (const auto& i : *view_vec) {
        auto vi = std::static_pointer_cast<device_tracker_view>(i);
        if (vi->get_view_id() == in_view->get_view_id()) 
            return false;
    }

    view_vec->push_back(in_view);

    for (const auto& i : *immutable_tracked_vec) {
        auto di = std::static_pointer_cast<kis_tracked_device_base>(i);
        in_view->new_device(di);
    }

    return true;
}

void device_tracker::remove_view(const std::string& in_id) {
    local_locker l(&view_mutex);
        
    for (auto i = view_vec->begin(); i != view_vec->end(); ++i) {
        auto vi = std::static_pointer_cast<device_tracker_view>(*i);
        if (vi->get_view_id() == in_id) {
            view_vec->erase(i);
            return;
        }
    }
}

void device_tracker::new_view_device(std::shared_ptr<kis_tracked_device_base> in_device) {
    local_shared_locker l(&view_mutex);

    for (const auto& i : *view_vec) {
        auto vi = std::static_pointer_cast<device_tracker_view>(i);
        vi->new_device(in_device);
    }
}

void device_tracker::update_view_device(std::shared_ptr<kis_tracked_device_base> in_device) {
    local_shared_locker l(&view_mutex);

    for (const auto& i : *view_vec) {
        auto vi = std::static_pointer_cast<device_tracker_view>(i);
        vi->update_device(in_device);
    }
}

void device_tracker::remove_view_device(std::shared_ptr<kis_tracked_device_base> in_device) {
    local_shared_locker l(&view_mutex);

    for (const auto& i : *view_vec) {
        auto vi = std::static_pointer_cast<device_tracker_view>(i);
        vi->remove_device(in_device);
    }
}

std::shared_ptr<device_tracker_view> device_tracker::get_phy_view(int in_phyid) {
    local_shared_locker l(&view_mutex);

    auto vk = phy_view_map.find(in_phyid);
    if (vk != phy_view_map.end())
        return vk->second;

    return nullptr;
}

void device_tracker::databaselog_write_devices() {
    auto dbf = Globalreg::fetch_global_as<kis_database_logfile>();
    
    if (dbf == nullptr)
        return;

    device_tracker_view_function_worker worker([this, dbf](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
            if (dev->get_mod_time() >= last_database_logged) {
                dbf->log_device(dev);
            }

            return false;
        });

    // Remember the time BEFORE we spend time looking at all the devices
    auto log_time = time(0);

    do_readonly_device_work(worker);

    // Then update the log; we might catch a few high-change devices twice, but this is
    // safer by far
    last_database_logged = log_time;
}

void device_tracker::load_stored_username(std::shared_ptr<kis_tracked_device_base> in_dev) {
    // Lock the database; we're doing a single query
    local_locker dblock(&ds_mutex);

    if (!database_valid())
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
        _MSG("device_tracker unable to prepare database query for stored devicename in " +
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
            _MSG("device_tracker encountered an error loading stored device username: " + 
                    std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            break;
        }
    }

    sqlite3_finalize(stmt);
}

void device_tracker::load_stored_tags(std::shared_ptr<kis_tracked_device_base> in_dev) {
    // Lock the database; we're doing a single query
    local_locker dblock(&ds_mutex);

    if (!database_valid())
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
        _MSG("device_tracker unable to prepare database query for stored devicetag in " +
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

            auto tagc = std::make_shared<tracker_element_string>();
            tagc->set(std::string((const char *) contentstr));

            in_dev->get_tag_map()->insert(std::string((const char *) tagstr), tagc);
        } else if (r == SQLITE_DONE) {
            break;
        } else {
            _MSG("device_tracker encountered an error loading stored device username: " + 
                    std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            break;
        }
    }

    sqlite3_finalize(stmt);
}

void device_tracker::set_device_user_name(std::shared_ptr<kis_tracked_device_base> in_dev,
        std::string in_username) {

    // Lock the device itself
    local_locker devlocker(&(in_dev->device_mutex));

    in_dev->set_username(in_username);

    if (!database_valid()) {
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
        _MSG("device_tracker unable to prepare database insert for device name in " +
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

void device_tracker::set_device_tag(std::shared_ptr<kis_tracked_device_base> in_dev,
        std::string in_tag, std::string in_content) {

    // Lock the device itself
    local_locker devlocker(&(in_dev->device_mutex));

    auto e = std::make_shared<tracker_element_string>();
    e->set(in_content);

    auto sm = in_dev->get_tag_map();

    auto t = sm->find(in_tag);
    if (t != sm->end()) {
        t->second = e;
    } else {
        sm->insert(in_tag, e);
    }

    if (!database_valid()) {
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
        _MSG("device_tracker unable to prepare database insert for device tags in " +
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

void device_tracker::handle_new_datasource_event(std::shared_ptr<eventbus_event> evt) {
    auto ds_k = evt->get_event_content()->find(datasource_tracker::event_new_datasource());

    if (ds_k == evt->get_event_content()->end())
        return;

    auto datasource = std::static_pointer_cast<kis_datasource>(ds_k->second);

    if (map_seenby_views) {
        auto source_uuid =datasource->get_source_uuid();
        auto source_key = datasource->get_source_key();

        auto k = seenby_view_map.find(source_uuid);

        if (k == seenby_view_map.end()) {
            auto seenby_view =
                std::make_shared<device_tracker_view>(fmt::format("seenby-{}", source_uuid), 
                        fmt::format("Devices seen by datasource {}", source_uuid),
                        std::vector<std::string>{"seenby-uuid", source_uuid.as_string()},
                        [source_key](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                            return dev->get_seenby_map()->find(source_key) != dev->get_seenby_map()->end();
                        },
                        [source_key](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                            return dev->get_seenby_map()->find(source_key) != dev->get_seenby_map()->end();
                        });
            seenby_view_map[source_uuid] = seenby_view;
            add_view(seenby_view);
        }
    }
}

void device_tracker::handle_new_device_event(std::shared_ptr<eventbus_event> evt) {
    auto device_k = evt->get_event_content()->find(device_tracker::event_new_device());

    if (device_k == evt->get_event_content()->end())
        return;

    new_view_device(std::static_pointer_cast<kis_tracked_device_base>(device_k->second));
}

std::shared_ptr<tracker_element_string> device_tracker::get_cached_devicetype(const std::string& type) {
    local_locker l(&device_type_cache_mutex, "device_tracker::get_cached_devicetype");

    auto k = device_type_cache.find(type);

    if (k == device_type_cache.end()) {
        auto r = std::make_shared<tracker_element_string>(type);
        device_type_cache[type] = r;
        return r;
    }

    return k->second;
}

std::shared_ptr<tracker_element_string> device_tracker::get_cached_phyname(const std::string& phyname) {
    local_locker l(&device_phy_name_cache_mutex, "device_tracker::get_cached_phyname");

    auto k = device_phy_name_cache.find(phyname);

    if (k == device_phy_name_cache.end()) {
        auto r = std::make_shared<tracker_element_string>(phyname);
        device_phy_name_cache[phyname] = r;
        return r;
    }

    return k->second;
}

void device_tracker::lock_device_range(std::shared_ptr<tracker_element> devices) {
    switch (devices->get_type()) {
        case tracker_type::tracker_vector:
            lock_device_range(std::static_pointer_cast<tracker_element_vector>(devices));
            break;
        case tracker_type::tracker_map:
            lock_device_range(std::static_pointer_cast<tracker_element_map>(devices));
            break;
        case tracker_type::tracker_key_map:
            lock_device_range(std::static_pointer_cast<tracker_element_device_key_map>(devices));
            break;
        case tracker_type::tracker_mac_map:
            lock_device_range(std::static_pointer_cast<tracker_element_mac_map>(devices));
            break;
        default:
            throw std::runtime_error("tried to lock an unsupported generic tracker element");
    }

}

void device_tracker::lock_device_range(std::shared_ptr<tracker_element_vector> devices) {
    local_eol_locker(&range_mutex, "devicetracker::lock_device_range (element vec)");
    for (auto v : *devices) {
        if (v->get_signature() != kis_tracked_device_base::get_static_signature())
            throw std::runtime_error("tried to lock a device range vec, but not given a map of devices");
        auto d = std::static_pointer_cast<kis_tracked_device_base>(v);
        local_eol_locker l(&d->device_mutex, "device_tracker::lock_range (element vec)");
    }
}

void device_tracker::lock_device_range(const std::vector<std::shared_ptr<kis_tracked_device_base>>& devices) {
    local_eol_locker(&range_mutex, "devicetracker::lock_device_range (std vec)");
    for (auto d : devices) {
        local_eol_locker l(&d->device_mutex, "device_tracker::lock_range (std vec)");
    }
}

void device_tracker::lock_device_range(std::shared_ptr<tracker_element_map> devices) {
    local_eol_locker(&range_mutex, "devicetracker::lock_device_range (element map)");
    for (auto k : *devices) {
        if (k.second->get_signature() != kis_tracked_device_base::get_static_signature())
            throw std::runtime_error("tried to lock a device range map, but not given a map of devices");

        auto d = std::static_pointer_cast<kis_tracked_device_base>(k.second);
        local_eol_locker l(&d->device_mutex, "device_tracker::lock_range (element map)");
    }
}

void device_tracker::lock_device_range(std::shared_ptr<tracker_element_device_key_map> devices) {
    local_eol_locker(&range_mutex, "devicetracker::lock_device_range (element key map)");
    for (auto k : *devices) {
        if (k.second->get_signature() != kis_tracked_device_base::get_static_signature())
            throw std::runtime_error("tried to lock a device range map, but not given a map of devices");

        auto d = std::static_pointer_cast<kis_tracked_device_base>(k.second);
        local_eol_locker l(&d->device_mutex, "device_tracker::lock_range (element key map)");
    }
}

void device_tracker::lock_device_range(std::shared_ptr<tracker_element_mac_map> devices) {
    local_eol_locker(&range_mutex, "devicetracker::lock_device_range (element mac map)");
    for (auto k : *devices) {
        if (k.second->get_signature() != kis_tracked_device_base::get_static_signature())
            throw std::runtime_error("tried to lock a device range map, but not given a map of devices");

        auto d = std::static_pointer_cast<kis_tracked_device_base>(k.second);
        local_eol_locker l(&d->device_mutex, "device_tracker::lock_range (element mac map)");
    }
}

void device_tracker::unlock_device_range(std::shared_ptr<tracker_element> devices) {
    switch (devices->get_type()) {
        case tracker_type::tracker_vector:
            unlock_device_range(std::static_pointer_cast<tracker_element_vector>(devices));
            break;
        case tracker_type::tracker_map:
            unlock_device_range(std::static_pointer_cast<tracker_element_map>(devices));
            break;
        case tracker_type::tracker_key_map:
            unlock_device_range(std::static_pointer_cast<tracker_element_device_key_map>(devices));
            break;
        case tracker_type::tracker_mac_map:
            unlock_device_range(std::static_pointer_cast<tracker_element_mac_map>(devices));
            break;
        default:
            throw std::runtime_error("tried to lock an unsupported generic tracker element");
    }
}

void device_tracker::unlock_device_range(std::shared_ptr<tracker_element_vector> devices) {
    for (auto v : *devices) {
        auto d = std::static_pointer_cast<kis_tracked_device_base>(v);
        local_unlocker l(&d->device_mutex);
    }
    local_unlocker ul(&range_mutex);
}

void device_tracker::unlock_device_range(const std::vector<std::shared_ptr<kis_tracked_device_base>>& devices) {
    for (auto d : devices) {
        local_unlocker l(&d->device_mutex);
    }
    local_unlocker ul(&range_mutex);
}

void device_tracker::unlock_device_range(std::shared_ptr<tracker_element_map> devices) {
    for (auto k : *devices) {
        auto d = std::static_pointer_cast<kis_tracked_device_base>(k.second);
        local_unlocker l(&d->device_mutex);
    }
    local_unlocker ul(&range_mutex);
}

void device_tracker::unlock_device_range(std::shared_ptr<tracker_element_device_key_map> devices) {
    for (auto k : *devices) {
        auto d = std::static_pointer_cast<kis_tracked_device_base>(k.second);
        local_unlocker l(&d->device_mutex);
    }
    local_unlocker ul(&range_mutex);
}

void device_tracker::unlock_device_range(std::shared_ptr<tracker_element_mac_map> devices) {
    for (auto k : *devices) {
        auto d = std::static_pointer_cast<kis_tracked_device_base>(k.second);
        local_unlocker l(&d->device_mutex);
    }
    local_unlocker ul(&range_mutex);
}

