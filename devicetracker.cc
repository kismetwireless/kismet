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

#ifdef HAVE_CPP17_PARALLEL
#include <execution>
#endif

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

device_tracker::device_tracker() :
    lifetime_global(),
    kis_database("devicetracker"),
    deferred_startup() {

    Globalreg::enable_pool_type<kis_historic_location>([](auto *a) { a->reset(); });

    phy_mutex.set_name("device_tracker::phy_mutex");
    devicelist_mutex.set_name("devicetracker::devicelist");

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
    device_builder = std::make_shared<kis_tracked_device_base>(device_base_id);
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

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();

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

    pack_comp_devicetag =
        packetchain->register_packet_component("DEVICETAG");

	// Common tracker, very early in the tracker chain
    packetchain_common_id =
        packetchain->register_handler([](void *auxdata, const std::shared_ptr<kis_packet>& in_packet) -> int {
				auto devicetracker = reinterpret_cast<device_tracker *>(auxdata);
                return devicetracker->common_tracker(in_packet);
            }, this, CHAINPOS_TRACKER, -100);


    // Post any events related to the device generated during tracking mode
    // (like a new device being created) at the very END of tracking, so that
    // the device has as complete a view as possible; if we trigger it at the
    // BEGINNING of the chain, we get only the generic device with none of the
    // phy-specific attachments.
    packetchain_tracking_done_id =
        packetchain->register_handler([](void *auxdata, const std::shared_ptr<kis_packet>& in_packet) -> int {
				auto devicetracker = reinterpret_cast<device_tracker *>(auxdata);
				for (const auto& e : in_packet->process_complete_events)
					devicetracker->eventbus->publish(e);
				return 1;
        }, this, CHAINPOS_TRACKER, 0x7FFFFFFF);

    if (!Globalreg::globalreg->kismet_config->fetch_opt_bool("track_device_rrds", true)) {
        _MSG("Not tracking historical packet data to save RAM", MSGFLAG_INFO);
        ram_no_rrd = true;
    } else {
        ram_no_rrd = false;
    }

    if (!Globalreg::globalreg->kismet_config->fetch_opt_bool("track_device_seenby_views", true)) {
        _MSG("Not building device seenby views to save RAM", MSGFLAG_INFO);
        map_seenby_views = false;
    } else {
        map_seenby_views = true;
    }

    if (!Globalreg::globalreg->kismet_config->fetch_opt_bool("track_device_phy_views", true)) {
        _MSG("Not building device phy views to save RAM", MSGFLAG_INFO);
        map_phy_views = false;
    } else {
        map_phy_views = true;
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_devices", true)) {
        unsigned int lograte =
            Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_device_rate", 30);

        _MSG_INFO("Saving devices to the Kismet database log every {} seconds", lograte);

        databaselog_logging = false;

        databaselog_timer =
            timetracker->register_timer(std::chrono::seconds(lograte), 1,
                [this](int) -> int {
                    if (databaselog_logging) {
                        _MSG("Attempting to log devices, but devices are still being "
                                "saved from the last logging attempt.  It's possible your "
                                "system is slow or you have a very large number of devices "
                                "to log.  Try increasing the delay in 'kis_log_device_rate' "
                                "in kismet_logging.conf", MSGFLAG_ERROR);
                        return 1;
                    }

                    // Don't even attempt to log if we're not logging
                    auto dbf = Globalreg::fetch_global_as<kis_database_logfile>();
                    if (dbf == nullptr)
                        return 1;

                    if (!dbf->is_enabled())
                        return 1;

                    // Run the device storage in its own thread
                    std::thread t([this] {
                        databaselog_write_devices();
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
        Globalreg::globalreg->kismet_config->fetch_opt_uint("tracker_device_presize", 1000);

    immutable_tracked_vec->reserve(preload_sz);

    // Set up the device timeout
    device_idle_expiration =
        Globalreg::globalreg->kismet_config->fetch_opt_int("tracker_device_timeout", 0);

    if (device_idle_expiration != 0) {
        device_idle_min_packets =
            Globalreg::globalreg->kismet_config->fetch_opt_uint("tracker_device_packets", 0);

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
		Globalreg::globalreg->kismet_config->fetch_opt_uint("tracker_max_devices", 0);

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

    full_refresh_time = (time_t) Globalreg::globalreg->last_tv_sec;

    track_persource_history =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("keep_per_datasource_stats", false);

    track_history_cloud =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("keep_location_cloud_history", false);

    if (track_history_cloud)
        _MSG_INFO("Location history cloud tracking enabled; this may use more RAM.  To "
                  "save RAM, set keep_location_cloud_history=false");

    // Initialize the view system
    view_vec = std::make_shared<tracker_element_vector>();

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/devices/views/all_views", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(view_vec, get_devicelist_mutex()));

    httpd->register_route("/devices/multimac/devices", {"POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    return multimac_endp_handler(con);
                }, get_devicelist_mutex()));

    httpd->register_route("/devices/multikey/devices", {"POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    return multikey_endp_handler(con, false);
                }, get_devicelist_mutex()));

    httpd->register_route("/devices/multikey/as-object/devices", {"POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    return multikey_endp_handler(con, true);
                }, get_devicelist_mutex()));

    httpd->register_route("/devices/all_devices", {"GET", "POST"}, httpd->RO_ROLE, {"ekjson", "itjson"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    auto device_ro = std::make_shared<tracker_element_vector>();
                    device_ro->set(immutable_tracked_vec->begin(), immutable_tracked_vec->end());
                    return device_ro;
                }, get_devicelist_mutex()));

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
                }, get_devicelist_mutex()));

    httpd->register_route("/devices/by-mac/:mac/devices", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    auto mac_k = con->uri_params().find(":mac");
                    auto mac = string_to_n<mac_addr>(mac_k->second);

                    if (mac.error())
                        throw std::runtime_error("invalid device MAC");

                    auto devvec = std::make_shared<tracker_element_vector>();

                    const auto mmp = tracked_mac_multimap.equal_range(mac);
                    for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi)
                        devvec->push_back(mmpi->second);

                    return devvec;
                }, get_devicelist_mutex()));

    httpd->register_route("/devices/last-time/:timestamp/devices", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](shared_con con) -> std::shared_ptr<tracker_element> {
                    std::ostream os(&con->response_stream());
                    auto ts_k = con->uri_params().find(":timestamp");
                    auto tv = string_to_n<long>(ts_k->second);

                    auto regex = con->json()["regex"];

                    time_t ts;

                    if (tv < 0) {
                        ts = (time_t) Globalreg::globalreg->last_tv_sec + tv;
                    } else {
                        ts = tv;
                    }

                    auto ts_worker = device_tracker_view_function_worker(
                        [ts](std::shared_ptr<kis_tracked_device_base> d) -> bool {
                            if (d->get_last_time() <= ts)
                                return false;
                            return true;
                        });

                    auto next_work_vec = do_device_work(ts_worker);

                    if (!regex.is_null()) {
                        try {
                            auto worker =
                                device_tracker_view_regex_worker(regex);
                            auto r_vec = do_readonly_device_work(worker, next_work_vec);
                            next_work_vec = r_vec;
                        } catch (const std::exception& e) {
                            con->set_status(400);
                            os << "Invalid regex: " << e.what() << "\n";
                            return nullptr;
                        }
                    }

                    return next_work_vec;
                }, get_devicelist_mutex()));

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

                    std::string name = con->json()["username"];

                    set_device_user_name(dev, name);

                    std::ostream os(&con->response_stream());
                    os << "Device name set\n";
                }, get_devicelist_mutex()));

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

                    std::string tag = con->json()["tagname"];
                    std::string content = con->json()["tagvalue"];

                    set_device_tag(dev, tag, content);

                    std::ostream os(&con->response_stream());
                    os << "Device tag set\n";
                }, get_devicelist_mutex()));

    httpd->register_route("/devices/pcap/by-key/:key/packets", {"GET"}, httpd->RO_ROLE, {"pcapng"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto key_k = con->uri_params().find(":key");
                    auto devkey = string_to_n<device_key>(key_k->second);

                    if (devkey.get_error())
                        throw std::runtime_error("invalid device key");

                    auto pcapng =
						std::make_shared<pcapng_stream_packetchain<pcapng_devicetracker_accept_ftor, pcapng_stream_select_ftor>>(&con->response_stream(),
								pcapng_devicetracker_accept_ftor(devkey), pcapng_stream_select_ftor(), (size_t) 1024*512);

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

    httpd->register_route("/devices/alerts/mac/:type/add", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto type = con->uri_params()[":type"];
                    int type_set = 0;

                    if (type == "found")
                        type_set = 1;
                    else if (type == "lost")
                        type_set = 2;
                    else if (type == "both")
                        type_set = 3;
                    else
                        throw std::runtime_error("Unknown alert type, expected found, lost, or both");

                    std::vector<mac_addr> mac_list;


                    if (!con->json()["mac"].is_null()) {
                        auto mac = mac_addr(con->json()["mac"].get<std::string>());

                        if (mac.error())
                            throw std::runtime_error("invalid MAC address");

                        mac_list.push_back(mac);
                    }

                    if (con->json()["macs"].is_array()) {
                        for (const auto& jv : con->json()["macs"]) {
                            auto mac = mac_addr(jv.get<std::string>());

                            if (mac.error())
                                throw std::runtime_error("invalid MAC address in macs list");

                            mac_list.push_back(mac);
                        }
                    }

                    if (mac_list.size() == 0)
                        throw std::runtime_error("expected MAC address in mac or macs[]");

                    for (auto mi : mac_list) {
                        auto ek = macdevice_alert_conf_map.find(mi);

                        if (ek != macdevice_alert_conf_map.end())
                            ek->second |= type_set;
                        else
                            macdevice_alert_conf_map[mi] = type_set;
                    }
                }, get_devicelist_mutex()));

    httpd->register_route("/devices/alerts/mac/:type/remove", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto type = con->uri_params()[":type"];
                    int type_set = 0;

                    if (type == "found")
                        type_set = 1;
                    else if (type == "lost")
                        type_set = 2;
                    else if (type == "both")
                        type_set = 3;
                    else
                        throw std::runtime_error("Unknown alert type, expected found, lost, or both");

                    std::vector<mac_addr> mac_list;

                    if (!con->json()["mac"].is_null()) {
                        auto mac = mac_addr(con->json()["mac"].get<std::string>());

                        if (mac.error())
                            throw std::runtime_error("invalid MAC address");

                        mac_list.push_back(mac);
                    }

                    if (con->json()["macs"].is_array()) {
                        for (const auto& jv : con->json()["macs"]) {
                            auto mac = mac_addr(jv.get<std::string>());

                            if (mac.error())
                                throw std::runtime_error("invalid MAC address in macs list");

                            mac_list.push_back(mac);
                        }
                    }

                    if (mac_list.size() == 0)
                        throw std::runtime_error("expected MAC address in mac or macs[]");

                    for (auto mi : mac_list) {
                        auto ek = macdevice_alert_conf_map.find(mi);

                        if (ek != macdevice_alert_conf_map.end()) {
                            ek->second &= ~type_set;

                            if (ek->second == 0) {
                                for (unsigned int mi2 = 0; mi2 < macdevice_flagged_vec.size(); mi2++) {
                                    if (mi == macdevice_flagged_vec[mi2]->get_macaddr()) {
                                        macdevice_flagged_vec.erase(macdevice_flagged_vec.begin() + mi2);
                                        break;
                                    }
                                }

                                macdevice_alert_conf_map.erase(ek);
                            }
                        }
                    }
                }, get_devicelist_mutex()));

    httpd->register_route("/devices/alerts/mac/:type/macs", {"GET"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element_vector> {
                    auto type = con->uri_params()[":type"];
                    int type_set = 0;

                    if (type == "found")
                        type_set = 1;
                    else if (type == "lost")
                        type_set = 2;
                    else if (type == "both")
                        type_set = 3;
                    else
                        throw std::runtime_error("Unknown alert type, expected found, lost, or both");

                    auto ret = std::make_shared<tracker_element_vector>();

                    for (auto mi : macdevice_alert_conf_map) {
                        if ((mi.second & type_set))
                            ret->push_back(std::make_shared<tracker_element_mac_addr>(mi.first));
                    }

                    return ret;
                }, get_devicelist_mutex()));

    httpd->register_websocket_route("/devices/monitor", httpd->RO_ROLE, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                // consumer-supplied key# per monitor request, timer id of monitor event
                std::unordered_map<unsigned int, int> key_timer_map;

                auto ws =
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [this, &key_timer_map, con](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf, bool text) {

                        if (!text) {
                            ws->close();
                            return;
                        }

                        std::stringstream ss(boost::beast::buffers_to_string(buf->data()));
                        nlohmann::json json;

                        unsigned int req_id;

                        try {
                            ss >> json;

                            if (!json["cancel"].is_null()) {
                                auto kt_v = key_timer_map.find(json["cancel"]);
                                if (kt_v != key_timer_map.end()) {
                                    timetracker->remove_timer(kt_v->second);
                                    key_timer_map.erase(kt_v);
                                }
                            }

                            if (!json["monitor"].is_null()) {
                                req_id = json["request"];

                                std::string format_t = "json";

                                if (!json["format"].is_null())
                                    format_t = json["format"];

                                auto dev_r = json["monitor"];
                                auto dev_k = device_key(json["monitor"].get<std::string>());
                                auto dev_m = mac_addr(json["monitor"].get<std::string>());

                                if (dev_r != "*" && dev_k.get_error() && dev_m.error())
                                    throw std::runtime_error("invalid device reference");

                                auto rate = json["rate"];

                                // Remove any existing request under this ID
                                auto kt_v = key_timer_map.find(req_id);
                                if (kt_v != key_timer_map.end())
                                    timetracker->remove_timer(kt_v->second);

                                auto rename_map = Globalreg::new_from_pool<tracker_element_serializer::rename_map>();

                                time_t last_tm = 0;

                                // Generate a timer event that goes and looks for the devices and
                                // serializes them with the fields record
                                auto tid =
                                    timetracker->register_timer(std::chrono::seconds(rate), true,
                                            [this, con, dev_r, dev_k, dev_m, json, ws, &last_tm, rename_map, format_t](int) -> int {
                                                if (dev_r == "*") {
                                                    auto worker = device_tracker_view_function_worker([json, last_tm, format_t, this, ws](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                                                        if (dev->get_mod_time() > last_tm) {
                                                            std::stringstream ss;
                                                            entrytracker->serialize_with_json_summary(format_t, ss, dev, json);
                                                            auto data = ss.str();
                                                            ws->write(data);
                                                        }

                                                        return false;
                                                    });

                                                    do_device_work(worker);
                                                } else if (!dev_k.get_error()) {
                                                    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "ws monitor timer serialize lambda");

                                                    auto dev = fetch_device(dev_k);
                                                    if (dev != nullptr) {
                                                        if (dev->get_mod_time() > last_tm) {
                                                            std::stringstream ss;
                                                            entrytracker->serialize_with_json_summary(format_t, ss, dev, json);
                                                            auto data = ss.str();
                                                            ws->write(data);
                                                        }
                                                    }
                                                } else if (!dev_m.error()) {
                                                    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "ws monitor timer serialize lambda");

                                                    const auto mmp = tracked_mac_multimap.equal_range(dev_m);
                                                    for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) {
                                                        if (mmpi->second->get_mod_time() > last_tm) {
                                                            std::stringstream ss;
                                                            entrytracker->serialize_with_json_summary(format_t, ss, mmpi->second, json);
                                                            auto data = ss.str();
                                                            ws->write(data);
                                                        }
                                                    }
                                                }

                                                last_tm = (time_t) Globalreg::globalreg->last_tv_sec;

                                                return 1;
                                            });

                                key_timer_map[req_id] = tid;
                            }

                        } catch (const std::exception& e) {
                            _MSG_ERROR("Invalid device monitor request: {}", e.what());
                            return;
                        }

                    });

                ws->text();

                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ;
                }

                for (const auto t : key_timer_map)
                    timetracker->remove_timer(t.second);
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
                    return all_phys_endp_handler(std::move(con));
            }));

    // Open and upgrade the DB, default path
    database_open("");
    database_upgrade_db();

    new_datasource_evt_id =
        eventbus->register_listener(datasource_tracker::event_new_datasource(),
                [this](std::shared_ptr<eventbus_event> evt) {
                    handle_new_datasource_event(std::move(evt));
                });

    new_device_evt_id =
        eventbus->register_listener(device_tracker::event_new_device(),
                [this](std::shared_ptr<eventbus_event> evt) {
                    handle_new_device_event(std::move(evt));
                });

    devicefound_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("devicefound_timeout", 60);
    devicelost_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("devicelost_timeout", 60);

    alert_macdevice_found_ref =
        alertracker->activate_configured_alert("DEVICEFOUND",
                "SYSTEM", kis_alert_severity::high,
                "A target device has been seen", -1);
    alert_macdevice_lost_ref =
        alertracker->activate_configured_alert("DEVICELOST",
                "SYSTEM", kis_alert_severity::high,
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
                [](const std::shared_ptr<kis_tracked_device_base>&) -> bool {
                    return true;
                },
                [](const std::shared_ptr<kis_tracked_device_base>&) -> bool {
                    return true;
                });
    add_view(all_view);

}

device_tracker::~device_tracker() {
    if (eventbus != nullptr) {
        eventbus->remove_listener(new_datasource_evt_id);
        eventbus->remove_listener(new_device_evt_id);
    }

    Globalreg::globalreg->devicetracker = nullptr;
    Globalreg::globalreg->remove_global(global_name());

    packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    if (packetchain != nullptr) {
        packetchain->remove_handler(packetchain_common_id, CHAINPOS_TRACKER);
        packetchain->remove_handler(packetchain_tracking_done_id, CHAINPOS_TRACKER);
    }

    timetracker = Globalreg::fetch_global_as<time_tracker>();
    if (timetracker != nullptr) {
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

    immutable_tracked_vec->clear();
    tracked_mac_multimap.clear();
}

void device_tracker::macdevice_timer_event() {
    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "device_tracker macdevice_timer_event");

    time_t now = Globalreg::globalreg->last_tv_sec;

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
                    nullptr, mac_addr{0}, k->get_macaddr(),
                    mac_addr{0}, mac_addr{0}, k->get_channel(),
                    alrt);
        } else {
            keep_vec.push_back(k);
        }
    }

    macdevice_flagged_vec = keep_vec;
}

kis_phy_handler *device_tracker::fetch_phy_handler(int in_phy) {
    kis_lock_guard<kis_mutex> lk(phy_mutex, "fetch_phy_handler");

	auto i = phy_handler_map.find(in_phy);

	if (i == phy_handler_map.end())
		return NULL;

	return i->second;
}

kis_phy_handler *device_tracker::fetch_phy_handler_by_name(const std::string& in_name) {
    kis_lock_guard<kis_mutex> lk(phy_mutex, "fetch_phy_handler_by_name");

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
    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "device_tracker fetch_num_devices");

    return tracked_map.size();
}

int device_tracker::fetch_num_packets() {
    return num_packets;
}


int device_tracker::register_phy_handler(kis_phy_handler *in_weak_handler) {
    kis_unique_lock<kis_mutex> lk(phy_mutex, "device_tracker register_phy_handler");

	int num = next_phy_id++;

    lk.unlock();
	kis_phy_handler *strongphy = in_weak_handler->create_phy_handler(num);
    lk.lock();

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

            if (!strongphy->fetch_phy_indexed()) {
                phy_view->set_indexed(false);
            }

            add_view(phy_view);
        }
    }

    auto evt = eventbus->get_eventbus_event(event_new_phy());
    evt->get_event_content()->insert(event_new_phy(),
            std::make_shared<tracker_element_string>(strongphy->fetch_phy_name()));
    eventbus->publish(evt);

    _MSG_INFO("Registered PHY handler '{}' as ID {}", strongphy->fetch_phy_name(), num);

	return num;
}

void device_tracker::update_full_refresh() {
    full_refresh_time = (time_t) Globalreg::globalreg->last_tv_sec;
}

std::shared_ptr<kis_tracked_device_base> device_tracker::fetch_device(const device_key& in_key) {
    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "device_tracker fetch_device");

	device_itr i = tracked_map.find(in_key);

	if (i != tracked_map.end())
		return i->second;

	return NULL;
}

std::shared_ptr<kis_tracked_device_base> device_tracker::fetch_device_nr(const device_key& in_key) {
	device_itr i = tracked_map.find(in_key);

	if (i != tracked_map.end())
		return i->second;

	return NULL;
}

// Fetch one or more devices by mac address or mac mask
std::vector<std::shared_ptr<kis_tracked_device_base>> device_tracker::fetch_devices(const mac_addr& in_mac) {
    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "device_tracker fetch_device mac");
    std::vector<std::shared_ptr<kis_tracked_device_base>> ret;

    const auto mmp = tracked_mac_multimap.equal_range(in_mac);
    for (auto mmpi = mmp.first; mmpi != mmp.second; ++mmpi) {
        ret.push_back(mmpi->second);
    }

    return ret;
}

int device_tracker::common_tracker(const std::shared_ptr<kis_packet>& in_pack) {
    kis_lock_guard<kis_mutex> lk(phy_mutex, "device_tracker common_tracker");

    // All the statistics counters are atomic.
    // Phy specific counters are atomic inside a map protected by the phy mutex
    // RRDs have their own internal locking mechanisms to render them thread-safe
    // We only need to protect the integrity of a phy being added/removed during this

	if (in_pack->error) {
		// and bail
		num_errorpackets++;
		return 0;
	}

    auto pack_common = in_pack->fetch<kis_common_info>(pack_comp_common);

    if (!ram_no_rrd)
        packets_rrd->add_sample(1, Globalreg::globalreg->last_tv_sec);

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
        _MSG_ERROR("Invalid phy id {} in packet: something is wrong", pack_common->phyid);
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
    device_tracker::update_common_device(const std::shared_ptr<kis_common_info>& pack_common,
            const mac_addr& in_mac, kis_phy_handler *in_phy, const std::shared_ptr<kis_packet>& in_pack,
            unsigned int in_flags, const std::string& in_basic_type) {

    // Updating devices can only happen in serial because we don't know that a device is being
    // created & we don't know how to append the data until we get to the end of processing
    // so the entire chain is perforce locked
    kis_lock_guard<kis_mutex> lg(get_devicelist_mutex(), "device_tracker update_common_device");

    std::stringstream sstr;

    bool new_device = false;

    auto pack_l1info = in_pack->fetch<kis_layer1_packinfo>(pack_comp_radiodata);
    auto pack_gpsinfo = in_pack->fetch<kis_gps_packinfo>(pack_comp_gps);
    auto pack_datasrc = in_pack->fetch<packetchain_comp_datasource>(pack_comp_datasrc);
    auto common_info = in_pack->fetch<kis_common_info>(pack_comp_common);
    auto pack_tags = in_pack->fetch<kis_devicetag_packetinfo>(pack_comp_devicetag);

    std::shared_ptr<kis_tracked_device_base> device = NULL;
    device_key key;

    key = device_key(in_phy->fetch_phyname_hash(), in_mac);

	if ((device = fetch_device_nr(key)) == NULL) {
        if (in_flags & UCD_UPDATE_EXISTING_ONLY)
            return NULL;

        device = std::make_shared<kis_tracked_device_base>(device_builder.get());

        // Device ID is the size of the vector so a new device always gets put
        // in it's numbered slot
        device->set_kis_internal_id(immutable_tracked_vec->size());

        device->set_key(key);

        device->set_macaddr(in_mac);
        device->set_tracker_phyname(get_cached_phyname(in_phy->fetch_phy_name()));
		device->set_phyid(in_phy->fetch_phy_id());

        device->set_server_uuid(Globalreg::globalreg->server_uuid);

        device->set_first_time(in_pack->ts.tv_sec);

        device->set_tracker_type_string(get_cached_devicetype(in_basic_type));

        if (Globalreg::globalreg->manufdb != NULL) {
            device->set_manuf(Globalreg::globalreg->manufdb->lookup_oui(in_mac));
        }

        load_stored_username(device);
        load_stored_tags(device);

        new_device = true;
    }

    // Tag the packet with the base device
    auto devinfo = in_pack->fetch<kis_tracked_device_info>(pack_comp_device);

    if (devinfo == nullptr) {
        devinfo = std::make_shared<kis_tracked_device_info>();
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
                mac_addr dstmac, netmac, transmac;

                if (common_info != nullptr) {
                    dstmac = common_info->dest;
                    netmac = common_info->network;
                    transmac = common_info->transmitter;
                }

                auto alrt =
                    fmt::format("Monitored device {} ({}) has been found.",
                            device->get_macaddr(), device->get_commonname());
                   alertracker->raise_alert(alert_macdevice_found_ref,
                           in_pack, netmac, device->get_macaddr(), dstmac, transmac,
                           device->get_channel(), alrt);
            }
            if (k->second & 0x2) {
                macdevice_flagged_vec.push_back(device);
            }
        }

    }

    device->set_if_lt_last_time(in_pack->ts.tv_sec);

    if (in_flags & UCD_UPDATE_PACKETS) {
        device->inc_packets();

        if (pack_common != nullptr) {
            if (pack_common->source == in_mac || pack_common->transmitter == in_mac) {
                device->inc_tx_packets();

                if (!ram_no_rrd)
                    device->get_tx_packets_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);
            } else if (pack_common->dest == in_mac) {
                device->inc_rx_packets();

                if (!ram_no_rrd)
                    device->get_rx_packets_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);
            }
        }

        if (!ram_no_rrd) {
            device->get_packets_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);
        }

        if (pack_common != nullptr) {
            if (pack_common->error)
                device->inc_error_packets();

            if (pack_common->type == packet_basic_data) {
                // TODO fix directional data
                device->inc_data_packets();
                device->inc_datasize(pack_common->datasize);

                if (!ram_no_rrd) {
                    device->get_data_rrd()->add_sample(pack_common->datasize, Globalreg::globalreg->last_tv_sec);
                }

            } else if (pack_common->type == packet_basic_mgmt ||
                    pack_common->type == packet_basic_phy) {
                device->inc_llc_packets();
            }

        }
    }

	if ((in_flags & UCD_UPDATE_FREQUENCIES)) {
        bool set_channel = false;
        bool set_freq = false;

        if (pack_common != nullptr) {
            if (!pack_common->channel.empty() && pack_common->channel != "0") {
                set_channel = true;
                device->set_channel(pack_common->channel);
            }

            if (pack_common->freq_khz != 0) {
                set_freq = true;
                device->set_frequency(pack_common->freq_khz);
                device->inc_frequency_count((int) pack_common->freq_khz);
            }
        }

        if (pack_l1info != nullptr) {
            if (set_channel == false && !pack_l1info->channel.empty() && pack_l1info->channel != "0") {
                device->set_channel(pack_l1info->channel);
            }

            if (set_freq == false && pack_l1info->freq_khz != 0) {
                device->set_frequency(pack_l1info->freq_khz);
                device->inc_frequency_count((int) pack_l1info->freq_khz);
            }

            auto sc = std::make_shared<packinfo_sig_combo>(pack_l1info, pack_gpsinfo);
            device->get_signal_data()->append_signal(*sc, !ram_no_rrd, in_pack->ts.tv_sec);
        }
	}

    if (((in_flags & UCD_UPDATE_LOCATION) ||
         ((in_flags & UCD_UPDATE_EMPTY_LOCATION) && !device->has_location_cloud())) &&
            pack_gpsinfo != NULL && (device_location_signal_threshold == 0 ||
                ( device_location_signal_threshold != 0 && pack_l1info != nullptr &&
                  pack_l1info->signal_dbm >= device_location_signal_threshold))) {

        auto devloc = device->get_location();

        if ((devloc->get_last_location_time() != Globalreg::globalreg->last_tv_sec)) {
            devloc->set_last_location_time(Globalreg::globalreg->last_tv_sec);

            devloc->add_loc_with_avg(pack_gpsinfo->lat, pack_gpsinfo->lon,
                    pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                    pack_gpsinfo->heading);

            // Throttle history cloud to one update per second to prevent floods of
            // data from swamping the cloud
            if (track_history_cloud && pack_gpsinfo->fix >= 2) {
                auto histloc = Globalreg::globalreg->entrytracker->new_from_pool<kis_historic_location>();

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
        } else {
            devloc->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                            pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                            pack_gpsinfo->heading);
        }

    }

	// Update seenby records for time, frequency, packets
	if ((in_flags & UCD_UPDATE_SEENBY) && pack_datasrc != nullptr) {
        double f = -1;

        packinfo_sig_combo *sc = nullptr;

        if (pack_l1info != nullptr)
            f = pack_l1info->freq_khz;

        if (track_persource_history) {
            // Only populate signal, frequency map, etc per-source if we're tracking that
            auto sc = std::make_shared<packinfo_sig_combo>(pack_l1info, pack_gpsinfo);
            device->inc_seenby_count(pack_datasrc->ref_source, in_pack->ts.tv_sec, f,
                    sc.get(), !ram_no_rrd);
        } else {
            device->inc_seenby_count(pack_datasrc->ref_source, in_pack->ts.tv_sec, 0, 0, false);
        }

        if (map_seenby_views)
            update_view_device(device);

        if (sc != nullptr)
            delete(sc);
	}

    if (pack_common != nullptr)
        device->add_basic_crypt(pack_common->basic_crypt_set);

    if (pack_tags != nullptr) {
        for (const auto& i : pack_tags->tagmap) {
            set_device_tag(device, i.first, i.second);
        }
    }

    if (new_device) {
        // Add the new device to the list
        tracked_map[key] = device;

        immutable_tracked_vec->push_back(device);

        auto mm_pair = std::make_pair(in_mac, device);
        tracked_mac_multimap.insert(mm_pair);

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

#if 0
        // Release the devicelist lock before we add it to the views
        ul_list.unlock();
#endif
    }

    return device;
}

// Sort based on internal kismet ID
bool devicetracker_sort_internal_id(const std::shared_ptr<kis_tracked_device_base>& a,
	const std::shared_ptr<kis_tracked_device_base>& b) {
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
bool devicetracker_sort_lastseen(const std::shared_ptr<tracker_element>& a,
    const std::shared_ptr<tracker_element>& b) {

    if (a == nullptr)
        return true;
    if (b == nullptr)
        return true;

    return dynamic_cast<kis_tracked_device_base *>(a.get())->get_last_time() <
        dynamic_cast<kis_tracked_device_base *>(b.get())->get_last_time();
}

void device_tracker::timetracker_event(int eventid) {
    if (eventid == device_idle_timer) {
        kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "device_tracker timetracker_event device_idle_timer");

        time_t ts_now = Globalreg::globalreg->last_tv_sec;
        bool purged = false;

        // Reset the smart pointer of any devices we're dropping from the device list
        for (size_t pi = 0; pi < immutable_tracked_vec->size(); pi++) {
            auto d = std::static_pointer_cast<kis_tracked_device_base>(*(immutable_tracked_vec->begin() + pi));

            if (d == nullptr)
                continue;

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

                // Forget the immutable vec pointer to it
                (immutable_tracked_vec->begin() + pi)->reset();

                purged = true;

            }
        }

        if (purged)
            update_full_refresh();

    } else if (eventid == max_devices_timer) {
        kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "device_tracker timetracker_event max_devices_timer");

		// Do nothing if we don't care
		if (max_num_devices <= 0)
            return;

		// Do nothing if the number of devices is less than the max
		if (tracked_map.size() <= max_num_devices)
            return;

        // Now this gets expensive; clone the immutable vec, sort it, and then we start
        // zeroing out the immutable vec records
        tracker_element_vector sorted_vec(immutable_tracked_vec);

#if defined(HAVE_CPP17_PARALLEL)
        std::stable_sort(std::execution::par_unseq, sorted_vec.begin(), sorted_vec.end(), devicetracker_sort_lastseen);
#else
        std::stable_sort(sorted_vec.begin(), sorted_vec.end(), devicetracker_sort_lastseen);
#endif

        for (auto i = sorted_vec.begin() + max_num_devices; i != sorted_vec.end(); ++i) {
            auto d = std::static_pointer_cast<kis_tracked_device_base>(*i);

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
            (immutable_tracked_vec->begin() + d->get_kis_internal_id())->reset();
        }

        // Do an update since we're trimming something
        update_full_refresh();

	}
}

void device_tracker::usage(const char *name __attribute__((unused))) {
    printf("\n");
	printf(" *** Device Tracking Options ***\n");
	printf("     --device-timeout=n       Expire devices after N seconds\n"
          );
}

int device_tracker::database_upgrade_db() {
    kis_lock_guard<kis_mutex> lk(ds_mutex);

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
    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "device_tracker add_device");

    if (fetch_device_nr(device->get_key()) != NULL) {
        _MSG("device_tracker tried to add device " + device->get_macaddr().mac_to_string() +
                " which already exists", MSGFLAG_ERROR);
        return;
    }

    // Device ID is the size of the vector so a new device always gets put
    // in it's numbered slot
    device->set_kis_internal_id(immutable_tracked_vec->size());

    tracked_map[device->get_key()] = device;
    immutable_tracked_vec->push_back(device);

    auto mm_pair = std::make_pair(device->get_macaddr(), device);
    tracked_mac_multimap.emplace(mm_pair);
}

bool device_tracker::add_view(std::shared_ptr<device_tracker_view> in_view) {
    kis_lock_guard<kis_mutex> lk(devicelist_mutex);

    for (const auto& i : *view_vec) {
        auto vi = static_cast<device_tracker_view *>(i.get());
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
    kis_lock_guard<kis_mutex> lk(devicelist_mutex);

    for (auto i = view_vec->begin(); i != view_vec->end(); ++i) {
        auto vi = static_cast<device_tracker_view *>((*i).get());
        if (vi->get_view_id() == in_id) {
            view_vec->erase(i);
            return;
        }
    }
}

void device_tracker::new_view_device(std::shared_ptr<kis_tracked_device_base> in_device) {
    kis_lock_guard<kis_mutex> lk(devicelist_mutex);

    for (const auto& i : *view_vec) {
        auto vi = dynamic_cast<device_tracker_view *>(i.get());
        vi->new_device(in_device);
    }
}

void device_tracker::update_view_device(std::shared_ptr<kis_tracked_device_base> in_device) {
    kis_lock_guard<kis_mutex> lk(devicelist_mutex);

    for (const auto& i : *view_vec) {
        auto vi = dynamic_cast<device_tracker_view *>(i.get());
        vi->update_device(in_device);
    }
}

void device_tracker::remove_view_device(std::shared_ptr<kis_tracked_device_base> in_device) {
    kis_lock_guard<kis_mutex> lk(devicelist_mutex);

    for (const auto& i : *view_vec) {
        auto vi = dynamic_cast<device_tracker_view *>(i.get());
        vi->remove_device(in_device);
    }
}

std::shared_ptr<device_tracker_view> device_tracker::get_phy_view(int in_phyid) {
    kis_lock_guard<kis_mutex> lk(devicelist_mutex);

    auto vk = phy_view_map.find(in_phyid);
    if (vk != phy_view_map.end())
        return vk->second;

    return nullptr;
}

void device_tracker::databaselog_write_devices() {
    auto dbf = Globalreg::fetch_global_as<kis_database_logfile>();

    if (dbf == nullptr)
        return;

    if (!dbf->is_enabled())
        return;

    device_tracker_view_function_worker worker([this, dbf](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
            if (dev->get_mod_time() >= last_database_logged) {
                dbf->log_device(dev);
            }

            return false;
        });

    // Remember the time BEFORE we spend time looking at all the devices
    uint64_t log_time = Globalreg::globalreg->last_tv_sec;

    databaselog_logging = true;

    // Explicitly use the non-ro worker, because we're phasing out the RO version because of too much contention
    do_device_work(worker);

    databaselog_logging = false;

    // Then update the log; we might catch a few high-change devices twice, but this is
    // safer by far
    last_database_logged = log_time;
}

void device_tracker::load_stored_username(std::shared_ptr<kis_tracked_device_base> in_dev) {
    // Lock the database; we're doing a single query
    kis_lock_guard<kis_mutex> lk(ds_mutex);

    if (!database_valid())
        return;

    // This should only get called inside device creation which should be a safe time, don't lock here
    // Lock the device itself
    // auto devlocker = devicelist_range_scope_locker(shared_from_this(), in_dev);

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
    kis_lock_guard<kis_mutex> lk(ds_mutex);

    if (!database_valid())
        return;

    // This should be safe b/c it's only called inside device creation, don't lock
    // Lock the device itself
    // auto devlocker = devicelist_range_scope_locker(shared_from_this(), in_dev);

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
        const std::string& in_username) {

    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "set_device_user_name");

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
        kis_lock_guard<kis_mutex> lk(ds_mutex);
        sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);

    return;
}

void device_tracker::set_device_tag(std::shared_ptr<kis_tracked_device_base> in_dev,
        const std::string& in_tag, const std::string& in_content) {

    kis_lock_guard<kis_mutex> lk(get_devicelist_mutex(), "set_device_tag");

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
        kis_lock_guard<kis_mutex> lk(ds_mutex);
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
    kis_lock_guard<kis_mutex> lk(device_type_cache_mutex, "device_tracker get_cached_devicetype");

    auto k = device_type_cache.find(type);

    if (k == device_type_cache.end()) {
        auto r = std::make_shared<tracker_element_string>(type);
        device_type_cache[type] = r;
        return r;
    }

    return k->second;
}

std::shared_ptr<tracker_element_string> device_tracker::get_cached_phyname(const std::string& phyname) {
    kis_lock_guard<kis_mutex> lk(device_phy_name_cache_mutex, "device_tracker get_cached_phyname");

    auto k = device_phy_name_cache.find(phyname);

    if (k == device_phy_name_cache.end()) {
        auto r = std::make_shared<tracker_element_string>(phyname);
        device_phy_name_cache[phyname] = r;
        return r;
    }

    return k->second;
}

