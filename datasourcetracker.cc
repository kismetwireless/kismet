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

#include <string.h>
#include <getopt.h>

#include <cmath>

#include <string_view>

#include "alertracker.h"
#include "base64.h"
#include "configfile.h"
#include "datasource_probe_reason.h"
#include "datasourcetracker.h"
#include "endian_magic.h"
#include "globalregistry.h"
#include "kis_databaselogfile.h"
#include "kis_httpd_registry.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "pcapng_stream_futurebuf.h"
#include "streamtracker.h"
#include "timetracker.h"

datasource_tracker_source_probe::datasource_tracker_source_probe(unsigned long probeid,
        std::string in_definition, std::shared_ptr<tracker_element_vector> in_protovec) :
    timetracker {Globalreg::fetch_mandatory_global_as<time_tracker>()},
    proto_vec {in_protovec},
    transaction_id {0},
    definition {in_definition},
    cancelled {false},
    probe_id{probeid} { }

datasource_tracker_source_probe::~datasource_tracker_source_probe() {
    kis_unique_lock<kis_mutex> lk(probe_lock, "~dstprobe");
    probe_cb = nullptr;
    lk.unlock();

    cancel();
}

void datasource_tracker_source_probe::cancel() {
    kis_unique_lock<kis_mutex> lk(probe_lock, "dstprobe cancel");

    if (cancelled)
        return;

    cancelled = true;

    // Cancel any timers; they hold this probe and call cancel(), which needs probe_lock,
    // so don't wait for them
    for (auto i : cancel_timer_vec)
        timetracker->cancel_timer(i);

    if (probe_cb) {
        lk.unlock();
        probe_cb(probe_id, source_builder);
        lk.lock();
    }

    // Cancel any other competing probing sources; this may trigger the callbacks
    // which will call the completion function, but we'll ignore them because
    // we're already cancelled
    for (auto i : ipc_probe_map) {
        i.second->close_source_async([self = shared_from_this(), sid=i.first]() -> void {
                self->probe_cancel_complete(sid);
                });
    }

    ipc_probe_map.clear();
}

void datasource_tracker_source_probe::probe_cancel_complete(unsigned int sid) {
    kis_unique_lock<kis_mutex> lk(probe_lock, "dstprobe cancel complete");

    auto mk = ipc_probe_map.find(sid);
    if (mk != ipc_probe_map.end()) {
        // Move them to the completed vec
        complete_vec.push_back(mk->second);
    }
}

shared_datasource_builder datasource_tracker_source_probe::get_proto() {
    kis_lock_guard<kis_mutex> lk(probe_lock, "dstprobe get_proto");
    return source_builder;
}

std::string datasource_tracker_source_probe::get_decline_reason() {
    kis_lock_guard<kis_mutex> lk(probe_lock, "dstprobe get_decline_reason");
    return decline_reason;
}

void datasource_tracker_source_probe::complete_probe(bool in_success, unsigned int in_transaction,
        std::string in_reason) {

    // If we're already in cancelled state these callbacks mean nothing, ignore them, we're going
    // to be torn down so we don't even need to find our transaction
    if (cancelled)
        return;

    kis_unique_lock<kis_mutex> lk(probe_lock, "dstprobe complete_probe");

    auto v = ipc_probe_map.find(in_transaction);

    if (v != ipc_probe_map.end()) {
        if (in_success) {
            // _MSG_DEBUG("successful probe response");
            source_builder = v->second->get_source_builder();
        } else {
            // Keep the decline reason from a driver that plausibly OWNS this
            // definition.  Otherwise the operator gets only the generic
            // "Unable to find driver" sentence -- identical for a typo, a
            // missing helper package and an unplugged radio.
            //
            // Filtered rather than accumulated. Every builder is probed with
            // every definition and the stock helpers DO write a reason for a
            // foreign one (capture_linux_wifi's "Expected an interface with a
            // standard network API, skipping"), so surfacing them all would
            // turn one bad `-c` into a paragraph. See
            // datasource_probe_reason.h for why the test is ownership and not
            // the reason's content.
            //
            // First writer wins: a second owning driver's reason would be a
            // less-close match by construction, and appending them yields a
            // sentence whose two halves contradict each other.
            auto b = v->second->get_source_builder();
            if (decline_reason.empty() && !in_reason.empty() && b != nullptr &&
                    datasource_reason_is_own_definition(definition, b->get_source_type()))
                decline_reason = in_reason;
        }

        // Move them to the completed vec
        complete_vec.push_back(v->second);

        // Remove them from the map
        ipc_probe_map.erase(v);
    } else {
        // fprintf(stderr, "debug - dstp - complete_probe - couldn't find transaction record for transaction %u\n", in_transaction);
    }

    // If we've succeeded, cancel any others, cancel will take care of our
    // callback for completion
    if (in_success) {
        // _MSG_DEBUG("complete_probe calling cancel() for {}", probe_id);
        lk.unlock();
        cancel();
        return;
    } else {
        // If we've exhausted everything in the map, we're also done
        if (ipc_probe_map.size() == 0) {
            lk.unlock();
            cancel();
            return;
        }
    }
}

void datasource_tracker_source_probe::probe_sources(std::function<void (unsigned long, shared_datasource_builder)> in_cb) {
    kis_unique_lock<kis_mutex> lk(probe_lock, "dst probe_sources");

    probe_cb = in_cb;

    std::vector<shared_datasource_builder> remote_builders;

    unsigned int ncreated = 0;

    // Do some basic validation on the definition
    // If there's a comma in the interface name and no colon, someone probably typoed;
    // if there's a comma before the colon, also probably a typo
    auto comma_pos = definition.find(",");
    auto colon_pos = definition.find(":");

    if ((comma_pos != std::string::npos && colon_pos == std::string::npos) || comma_pos < colon_pos) {
        _MSG_ERROR("Found a ',' in the source definition '{}'.  Sources should be defined as "
                "interface:option1,option2,... this is likely a typo in your 'source=' config "
                "or in your '-c' option on the command line.", definition);
        cancel();
        return;
    }

    // We don't actually need to lock here because the proto vec is only changed at construct

    for (const auto& i : *proto_vec) {
        auto b = std::static_pointer_cast<kis_datasource_builder>(i);

        if (!b->get_probe_capable())
            continue;

        unsigned int transaction = ++transaction_id;

        // Instantiate a local prober datasource
        shared_datasource pds = b->build_datasource(b);

        ipc_probe_map[transaction] = pds;
        ncreated++;

    }

    // Duplicate the launch map so that rapidly terminating sources can't race
    auto build_map = std::map<unsigned int, shared_datasource>(ipc_probe_map);

    for (const auto& i : build_map) {
        // Set up the cancellation timer
        int cancel_timer =
            timetracker->register_timer(std::chrono::seconds(2), false,
                    [self = shared_from_this()] (int) -> int {
                        _MSG_ERROR("Datasource {} cancelling source probe due to timeout", self->definition);
                        self->cancel();
                        return 0;
                    });

        // Log the cancellation timer
        {
            kis_lock_guard<kis_mutex> lk(probe_lock, "dstprobe probe_sources");
            cancel_timer_vec.push_back(cancel_timer);
        }

        i.second->probe_interface(definition, i.first,
                [cancel_timer, self=shared_from_this()](unsigned int transaction, bool success, std::string reason) {
                    self->timetracker->cancel_timer(cancel_timer);
                    self->complete_probe(success, transaction, reason);
                });
    }

    // We've done all we can; if we haven't gotten an answer yet and we
    // have nothing in our transactional map, we've failed
    if (ncreated == 0) {
        cancel();
        return;
    }

}

datasource_tracker_source_list::datasource_tracker_source_list(std::shared_ptr<tracker_element_vector> in_protovec) :
    timetracker {Globalreg::fetch_mandatory_global_as<time_tracker>()},
    proto_vec {in_protovec},
    transaction_id {0},
    cancelled {false},
    cancel_event_id {-1},
    launching {false} { }

datasource_tracker_source_list::~datasource_tracker_source_list() {
    kis_unique_lock<kis_mutex> lk(list_lock, "~dstlist");
    list_cb = nullptr;
    lk.unlock();

    cancel();
}

void datasource_tracker_source_list::cancel() {
    kis_unique_lock<kis_mutex> lk(list_lock, "dstlist cancel");

    if (cancelled)
        return;

    cancelled = true;

    // The timer holds this list and calls cancel(), which needs list_lock
    if (cancel_event_id >= 0)
        timetracker->cancel_timer(cancel_event_id);

    // Answer with whatever HAS arrived.  Answering only when nothing is
    // outstanding is not enough, because nothing answers later: a lister still
    // running at the deadline would leave /datasource/list_interfaces blocked
    // in block_until() for good, and the web UI's Sources panel would read its
    // 30 s ajax timeout as "no interfaces". A slow lister costs its own
    // entries, not everyone's. list_cb is cleared so no path can answer twice.
    if (list_cb) {
        auto cb = list_cb;
        list_cb = nullptr;
        cb(listed_sources);
    }

    // Abort anything already underway
    for (auto i : ipc_list_map) {
        i.second->close_source_async([self = shared_from_this(), sid=i.first]() -> void {
                self->list_cancel_complete(sid);
            });
    }

    ipc_list_map.clear();
}

void datasource_tracker_source_list::list_cancel_complete(unsigned int sid) {
    kis_unique_lock<kis_mutex> lk(list_lock, "dstlist cancel complete");

    auto mk = ipc_list_map.find(sid);
    if (mk != ipc_list_map.end()) {
        complete_vec.push_back(mk->second);
    }
}

void datasource_tracker_source_list::complete_list(std::shared_ptr<kis_datasource> source,
        std::vector<shared_interface> in_list, unsigned int in_transaction) {

    kis_lock_guard<kis_mutex> lk(list_lock, "dstlist complete_list");

    // If we're already in cancelled state these callbacks mean nothing, ignore them
    if (cancelled)
        return;

    for (const auto& i : in_list) {
        listed_sources.push_back(i);
    }

    auto v = ipc_list_map.find(in_transaction);
    if (v != ipc_list_map.end()) {
        complete_vec.push_back(v->second);
        ipc_list_map.erase(v);
    }

    source->close_source_async([]() {});

    // If we've emptied the vec, end -- but never mid-launch, where an empty map
    // means only "the listers after this one are not registered yet".
    if (ipc_list_map.size() == 0 && !launching) {
        cancel();
        return;
    }
}

void datasource_tracker_source_list::list_sources(std::shared_ptr<datasource_tracker_source_list> ref,
        std::function<void (std::vector<shared_interface>)> in_cb) {

    kis_unique_lock<kis_mutex> lk(list_lock, "dst list_sources");

    list_cb = in_cb;

    std::vector<shared_datasource_builder> remote_builders;

    launching = true;

    for (const auto& i : *proto_vec) {
        shared_datasource_builder b = std::static_pointer_cast<kis_datasource_builder>(i);

        if (!b->get_list_capable())
            continue;

        unsigned int transaction = ++transaction_id;

        // Instantiate a local lister
        shared_datasource pds = b->build_datasource(b);

        ipc_list_map[transaction] = pds;
        list_vec.push_back(pds);

        pds->list_interfaces(transaction,
            [self = shared_from_this()] (std::shared_ptr<kis_datasource> src, unsigned int transaction,
                std::vector<shared_interface> interfaces) mutable {
                self->complete_list(src, interfaces, transaction);
            });
    }

    launching = false;

    // Every lister already answered (none launched, or all answered inline).
    if (ipc_list_map.size() == 0) {
        cancel();
        return;
    }

    // The listing deadline. Upstream's fixed 2 s assumes listers that
    // enumerate; the cell helpers (kismet_cap_cell_at / kismet_cap_cell_diag)
    // must TALK to each modem -- AT+CGMR/CGSN/CGMI/CGMM on every AT port --
    // which takes seconds with several modems attached (one unit that never
    // sends a final OK costs seconds on its own). With a 2 s deadline their
    // entries never reach the Sources panel at all. Configurable; a lister still running at
    // the deadline is simply left out of that answer (see cancel()).
    auto list_timeout_s =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("datasource_list_timeout", 10);
    if (list_timeout_s == 0)
        list_timeout_s = 10;

    cancel_event_id =
        timetracker->register_timer(std::chrono::seconds(list_timeout_s), false,
            [self = shared_from_this()] (int) mutable -> int {
                self->cancel();
                return 0;
            });
}


datasource_tracker::datasource_tracker() :
    remotecap_enabled{false},
    remotecap_port{0},
    packet_stats_handler_id{-1} {

    dst_lock.set_name("datasourcetracker");

    timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();
    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();
    streamtracker = Globalreg::fetch_mandatory_global_as<stream_tracker>();

    proto_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.datasourcetracker.driver",
                tracker_element_factory<kis_datasource_builder>(),
                "Datasource driver information");

    source_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.datasourcetracker.datasource",
                tracker_element_factory<kis_datasource>(nullptr),
                "Datasource");

    proto_vec =
        Globalreg::globalreg->entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.datasourcetracker.drivers",
                tracker_element_factory<tracker_element_vector>(), "Known drivers");

    datasource_vec =
        Globalreg::globalreg->entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.datasourcetracker.sources",
                tracker_element_factory<tracker_element_vector>(), "Configured sources");

    auto_masked_types =
        Globalreg::globalreg->kismet_config->fetch_opt_vec("mask_datasource_type");

    masked_ifnames =
        Globalreg::globalreg->kismet_config->fetch_opt_vec("mask_datasource_interface");
}

datasource_tracker::~datasource_tracker() {
    Globalreg::globalreg->remove_global("DATASOURCETRACKER");

    if (completion_cleanup_id >= 0)
        timetracker->remove_timer(completion_cleanup_id);

    if (database_log_timer >= 0) {
        timetracker->remove_timer(database_log_timer);
        databaselog_write_datasources();
    }

    if (packet_stats_handler_id >= 0) {
        auto packetchain = Globalreg::fetch_global_as<packet_chain>();
        if (packetchain != nullptr)
            packetchain->remove_handler(packet_stats_handler_id, CHAINPOS_LOGGING);
    }

    for (auto i : probing_map)
        i.second->cancel();

    for (auto i : listing_map)
        i.second->cancel();
}

void datasource_tracker::databaselog_write_datasources() {
    if (!database_log_enabled)
        return;

    std::shared_ptr<kis_database_logfile> dbf =
        Globalreg::fetch_global_as<kis_database_logfile>("DATABASELOG");

    if (dbf == NULL)
        return;

    // Fire off a database log, using a copy of the datasource vec
    std::shared_ptr<tracker_element_vector> v;

    {
        kis_lock_guard<kis_mutex> lk(dst_lock, "dst databaselog_write_datasources");
        v = std::make_shared<tracker_element_vector>(datasource_vec);
    }

    dbf->log_datasources(v);
}

std::shared_ptr<datasource_tracker_defaults> datasource_tracker::get_config_defaults() {
    return config_defaults;
}

void datasource_tracker::trigger_deferred_startup() {
    completion_cleanup_id = -1;
    next_probe_id = 0;
    next_list_id = 0;

    next_source_num = 0;

    tcp_buffer_sz =
        Globalreg::globalreg->kismet_config->fetch_opt_as<size_t>("tcp_buffer_kb", 512);

    config_defaults =
        Globalreg::globalreg->entrytracker->register_and_get_field_as<datasource_tracker_defaults>("kismet.datasourcetracker.defaults",
                tracker_element_factory<datasource_tracker_defaults>(),
                "Datasource default values");

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("channel_hop", true)) {
        _MSG("Enabling channel hopping by default on sources which support channel "
                "control.", MSGFLAG_INFO);
        config_defaults->set_hop(true);
    }

    std::string optval;
    if ((optval = Globalreg::globalreg->kismet_config->fetch_opt("channel_hop_speed")) != "") {
        try {
            double dv = string_to_rate(optval, 1);
            config_defaults->set_hop_rate(dv);
            _MSG("Setting default channel hop rate to " + optval, MSGFLAG_INFO);
        } catch (const std::exception& e) {
            _MSG_FATAL("Could not parse channel_hop_speed= config: {}", e.what());
            Globalreg::globalreg->fatal_condition = 1;
            return;
        }
    } else {
        _MSG("No channel_hop_speed= in kismet config, setting hop "
                "rate to 1/sec", MSGFLAG_INFO);
        config_defaults->set_hop_rate(1);
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("split_source_hopping", true)) {
        _MSG("Enabling channel list splitting on sources which share the same list "
                "of channels", MSGFLAG_INFO);
        config_defaults->set_split_same_sources(true);
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("randomized_hopping", true)) {
        _MSG("Enabling channel list shuffling to optimize overlaps", MSGFLAG_INFO);
        config_defaults->set_random_channel_order(true);
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("retry_on_source_error", true)) {
        _MSG("Sources will be re-opened if they encounter an error", MSGFLAG_INFO);
        config_defaults->set_retry_on_error(true);
    }

    auto remotecap_enable = Globalreg::globalreg->kismet_config->fetch_opt_bool("remote_capture_enabled", true);

    if (remotecap_enable) {
        remotecap_listen = Globalreg::globalreg->kismet_config->fetch_opt("remote_capture_listen");
        remotecap_port =
            Globalreg::globalreg->kismet_config->fetch_opt_uint("remote_capture_port", 0);

        if (remotecap_listen.length() == 0) {
            _MSG("No remote_capture_listen= found in kismet.conf; no remote "
                    "capture will be enabled.", MSGFLAG_INFO);
            remotecap_enabled = false;
        }

        if (remotecap_port == 0) {
            _MSG("No remote_capture_port= line in kismet.conf; no remote capture will be enabled.", MSGFLAG_INFO);
            remotecap_enabled = false;
        }
    } else {
        _MSG("Remote capture disabled via remote_capture_enabled; no remote capture will be enabled.", MSGFLAG_INFO);
    }

    config_defaults->set_remote_cap_listen(remotecap_listen);
    config_defaults->set_remote_cap_port(remotecap_port);

    config_defaults->set_remote_cap_timestamp(Globalreg::globalreg->kismet_config->fetch_opt_bool("override_remote_timestamp", true));

    // Register js module for UI
    std::shared_ptr<kis_httpd_registry> httpregistry =
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>("WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_datasources",
            "js/kismet.ui.datasources.js");

    database_log_enabled = false;

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_datasources", true)) {
        unsigned int lograte =
            Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_datasource_rate", 30);

        _MSG_INFO("Saving datasources to the Kismet database log every {} seconds", lograte);

        database_log_enabled = true;
        database_logging = false;

        database_log_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * lograte, NULL, 1,
                    [this](int) -> int {
                        if (database_logging) {
                            // _MSG_DEBUG("datasource log failed at {}", std::chrono::system_clock::now());
                            _MSG("Attempting to log datasources, but datasources are still "
                                    "being saved from the last logging attempt.  It's possible "
                                    "your system is extremely over capacity; try increasing the "
                                    "delay in 'kis_log_datasource_rate' in kismet_logging.conf",
                                    MSGFLAG_ERROR);
                            return 1;
                        }

                        // _MSG_DEBUG("datasource logging at {}", std::chrono::system_clock::now());

                        database_logging = true;
                        databaselog_write_datasources();
                        database_logging = false;

                        // _MSG_DEBUG("datasource logging complete at {}", std::chrono::system_clock::now());

                        return 1;
                    });

    } else {
        database_log_timer = -1;
    }


    // Create an alert for source errors
    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");

    alertracker->define_alert("SOURCEERROR", sat_second, 1, sat_second, 10);
    alertracker->activate_configured_alert("SOURCEERROR",
            "SYSTEM", kis_alert_severity::high,
            "A data source encountered an error.  Depending on the source configuration "
            "Kismet may automatically attempt to re-open the source.");

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");

    // Run after everything else so any stage can have flagged the packet; this is where each
    // packet from a source is counted as valid, error or filtered
    packet_stats_handler_id =
        packetchain->register_handler([](void *auxdata, const std::shared_ptr<kis_packet>& packet) -> int {
                auto dst = reinterpret_cast<datasource_tracker *>(auxdata);
                const auto datasrcinfo =
                    packet->fetch<packetchain_comp_datasource>(dst->pack_comp_datasrc);

                if (datasrcinfo == nullptr || datasrcinfo->ref_source == nullptr)
                    return 1;

                // A failed FCS check counts as an error even if nothing flagged it
                const bool error = packet->error || (packet->crc_ok && !packet->checksum_valid);

                if (!error && !packet->filtered) {
                    datasrcinfo->ref_source->inc_source_num_packets(1);
                    return 1;
                }

                if (error)
                    datasrcinfo->ref_source->inc_source_num_error_packets(1);

                if (packet->filtered)
                    datasrcinfo->ref_source->inc_source_num_filtered_packets(1);

                return 1;
            }, this, CHAINPOS_LOGGING, 10000);

    // Activate remote capture
    if (config_defaults->get_remote_cap_listen().length() != 0 &&
            config_defaults->get_remote_cap_port() != 0) {
        _MSG_INFO("Launching remote capture server on {} {}", remotecap_listen, remotecap_port);

        try {
            if (config_defaults->get_remote_cap_listen() == "*" ||
                    config_defaults->get_remote_cap_listen() == "0.0.0.0") {
                auto v4_ep = tcp::endpoint(tcp::v4(), config_defaults->get_remote_cap_port());
                remotecap_v4 = std::make_shared<datasource_tracker_remote_server>(v4_ep);
            } else {
                auto v4_ep =
                    tcp::endpoint(boost::asio::ip::make_address(config_defaults->get_remote_cap_listen()),
                            config_defaults->get_remote_cap_port());
                remotecap_v4 = std::make_shared<datasource_tracker_remote_server>(v4_ep);
            }
        } catch (const std::exception& e) {
            _MSG_FATAL("Failed to create IPV4 remote capture server; check your remote_capture_listen= "
                    "and remote_capture_port= configuration: {}", e.what());
            Globalreg::globalreg->fatal_condition = 1;
            remotecap_enabled = false;
            return;
        }
    }

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/datasource/all_sources", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(datasource_vec, dst_lock));

    httpd->register_route("/datasource/defaults", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(config_defaults, dst_lock));

    httpd->register_route("/datasource/types", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(proto_vec, dst_lock));

    httpd->register_route("/datasource/list_interfaces", {"GET", "POST"}, httpd->LOGON_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    // Locker for waiting for the list callback
                    auto cl = std::make_shared<conditional_locker<std::vector<shared_interface> >>();

                    cl->lock();

                    // Initiate the open
                    list_interfaces(
                        [cl](std::vector<shared_interface> iflist) mutable {
                            cl->unlock(iflist);
                        });

                    // Block until the list cmd unlocks us
                    auto iflist = cl->block_until();

                    auto iv = std::make_shared<tracker_element_vector>();

                    for (auto li : iflist)
                        iv->push_back(li);

                    return iv;
                }));

    httpd->register_route("/datasource/by-uuid/:uuid/source", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) mutable -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    return ds;
                }));


    httpd->register_route("/datasource/add_source", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    shared_datasource r;
                    std::string error_reason;
                    bool success;

                    auto definition = con->json()["definition"].get<std::string>();

                    auto create_promise = std::promise<void>();
                    auto create_ft = create_promise.get_future();

                    open_datasource(definition,
                            [&error_reason, &create_promise, &r, &success](bool cbsuccess, std::string reason,
                                shared_datasource ds) mutable {
                                success = cbsuccess;
                                error_reason = reason;
                                r = ds;
                                create_promise.set_value();
                                });

                    create_ft.wait();

                    if (success)
                        return r;

                    // Say why.  A 500 with an empty map would leave the web
                    // UI's Enable -- the only way to add a cell source without
                    // editing config -- showing nothing but "it went away" for
                    // a missing decode helper, a modem that is not attached, or
                    // a refused option. The endpoint wrapper
                    // turns a throw into 500 + "ERROR: <what>", which the panel
                    // displays on the row the operator clicked.
                    throw std::runtime_error(fmt::format("unable to open '{}': {}",
                                definition, error_reason.empty() ?
                                "the open failed and gave no reason" : error_reason));
                }));

    httpd->register_route("/datasource/by-uuid/:uuid/set_channel", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    bool set_success = false;
                    std::string set_reason;
                    auto set_promise = std::promise<void>();
                    auto set_ft = set_promise.get_future();

                    if (!con->json()["channel"].is_null()) {
                        auto ch = con->json()["channel"].get<std::string>();

                        _MSG_INFO("Source '{}' ({}) setting channel {}",
                                ds->get_source_name(), ds->get_source_uuid(), ch);

                        ds->set_channel(ch, 0,
                                [&set_success, &set_reason, &set_promise](unsigned int t, bool success, std::string e) mutable {
                                set_success = success;
                                set_reason = e;
                                set_promise.set_value();
                                });

                        set_ft.wait();

                        if (set_success) {
                            return ds;
                        } else {
                            _MSG_ERROR("Source '{}' ({}) failed to set channel {}: {}",
                                    ds->get_source_name(), ds->get_source_uuid(), ch,
                                    set_reason.empty() ? "no reason given" : set_reason);
                            con->set_status(500);
                            return std::make_shared<tracker_element_map>();
                        }
                    } else if (!con->json()["channels"].is_null() || !con->json()["rate"].is_null()) {
                        auto converted_channels = std::vector<std::string>();

                        if (!con->json()["channels"].is_null()) {
                            for (const auto& ch : con->json()["channels"])
                                converted_channels.push_back(ch.get<std::string>());
                        } else {
                            for (const auto& c : *(ds->get_source_hop_vec()))
                                converted_channels.push_back(c);
                        }

                        double rate;
                        unsigned int shuffle;

                        if (con->json()["rate"].is_null())
                            rate = ds->get_source_hop_rate();
                        else
                            rate = con->json()["rate"].get<double>();

                        if (con->json()["shuffle"].is_null())
                            shuffle = ds->get_source_hop_shuffle();
                        else
                            shuffle = con->json()["shuffle"].get<unsigned int>();

                        _MSG_INFO("Source '{}' ({}) setting channel list and hopping",
                                ds->get_source_name(), ds->get_source_uuid());

                        ds->set_channel_hop(rate, converted_channels, shuffle,
                                ds->get_source_hop_offset(), 0,
                                [&set_success, &set_reason, &set_promise](unsigned int, bool success, std::string e) mutable {
                                set_success = success;
                                set_reason = e;
                                set_promise.set_value();
                                });

                        set_ft.wait();

                        if (set_success) {
                            return ds;
                        } else {
                            _MSG_ERROR("Source '{}' ({}) failed to set channel list or hopping: {}",
                                    ds->get_source_name(), ds->get_source_uuid(),
                                    set_reason.empty() ? "no reason given" : set_reason);
                            con->set_status(500);
                            return std::make_shared<tracker_element_map>();
                        }
                    } else {
                        throw std::runtime_error("channel control API requires either 'channel' or "
                                "'channels' and 'rate'");
                    }
                }));

    httpd->register_route("/datasource/by-uuid/:uuid/set_hop", {"GET", "POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    bool set_success = false;
                    std::string set_reason;
                    auto set_promise = std::promise<void>();
                    auto set_ft = set_promise.get_future();


                    _MSG_INFO("Source '{}' ({}) enabling channel hop on existing channel list",
                            ds->get_source_name(), ds->get_source_uuid());

                    ds->set_channel_hop(ds->get_source_hop_rate(),
                            ds->get_source_hop_vec(),
                            ds->get_source_hop_shuffle(),
                            ds->get_source_hop_offset(), 0,
                            [&set_success, &set_reason, &set_promise](unsigned int, bool success, std::string e) mutable {
                            set_success = success;
                            set_reason = e;
                            set_promise.set_value();
                            });

                    set_ft.wait();

                    if (set_success) {
                        return ds;
                    } else {
                        _MSG_ERROR("Source '{}' ({}) failed to enable channel hopping: {}",
                                ds->get_source_name(), ds->get_source_uuid(),
                                set_reason.empty() ? "no reason given" : set_reason);
                        con->set_status(500);
                        return std::make_shared<tracker_element_map>();
                    }
                }));

    httpd->register_route("/datasource/by-uuid/:uuid/close_source", {"GET", "POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    _MSG_INFO("Closing source '{}' ({})", ds->get_source_name(), ds->get_source_uuid());
                    ds->stop_source();
                    return(ds);
                }));

    httpd->register_route("/datasource/by-uuid/:uuid/disable_source", {"GET", "POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    _MSG_INFO("Disabling source '{}' ({})", ds->get_source_name(), ds->get_source_uuid());
                    ds->disable_source();
                    return(ds);
                }));

    httpd->register_route("/datasource/by-uuid/:uuid/open_source", {"GET", "POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    bool set_success = false;
                    auto set_promise = std::promise<void>();
                    auto set_ft = set_promise.get_future();

                    if (ds->get_source_running())
                        throw std::runtime_error("source already running");

                    _MSG_INFO("Re-opening source '{}' ({})", ds->get_source_name(), ds->get_source_uuid());

                    ds->clear_source_disabled();

                    ds->open_interface(ds->get_source_definition(), 0,
                            [&set_success, &set_promise](unsigned int, bool success, std::string) mutable {
                            set_success = success;
                            set_promise.set_value();
                            });

                    set_ft.wait();

                    if (set_success) {
                        return ds;
                    } else {
                        con->set_status(500);
                        return std::make_shared<tracker_element_map>();
                    }
                }));

    /* Override source-definition options, to take effect on the NEXT open.
     *
     * Why this route exists: close_source + open_source cannot carry a new
     * definition.  open_source re-opens with `ds->get_source_definition()`,
     * the string the source already had, so close-then-reopen faithfully
     * restores the same options (for example, the same DIAG mask).  Upstream,
     * `update_source_definition()` has no callers outside its own header and
     * `append_source_definition()` is called only from two wifi datasource
     * constructors at build time.
     *
     * The machinery underneath is the existing one, not a new path:
     * parse_source_definition() already folds source_override_opts over the
     * parsed definition (kis_datasource.cc) and then re-synthesises
     * source_definition, so a later open_source picks the override up. This
     * route only supplies the caller that was missing.
     *
     * Refuses while the source is RUNNING rather than silently deferring. A
     * 200 on a request whose effect does not appear until some later reopen is
     * an acknowledgement that is not a measurement; the operator is told to
     * close the source first. */
    httpd->register_route("/datasource/by-uuid/:uuid/update_definition", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    if (ds->get_source_running())
                        throw std::runtime_error("source is running; close_source "
                                "first, then update_definition, then open_source "
                                "-- an option applied at bring-up cannot take "
                                "effect on a live source");

                    if (con->json()["options"].is_null())
                        throw std::runtime_error("expected an 'options' object of "
                                "definition key/value pairs");

                    auto opts = con->json()["options"];

                    if (!opts.is_object())
                        throw std::runtime_error("'options' must be an object");

                    if (opts.size() == 0)
                        throw std::runtime_error("'options' is empty; an update "
                                "that changes nothing would report success");

                    for (auto& kv : opts.items()) {
                        if (!kv.value().is_string())
                            throw std::runtime_error(fmt::format("option '{}' must "
                                        "be a string", kv.key()));

                        _MSG_INFO("Source '{}' ({}) definition override {}={} "
                                "(applies on next open)",
                                ds->get_source_name(), ds->get_source_uuid(),
                                kv.key(), kv.value().get<std::string>());

                        ds->set_source_definition_override(kv.key(),
                                kv.value().get<std::string>());
                    }

                    return ds;
                }));

    httpd->register_route("/datasource/by-uuid/:uuid/pause_source", {"GET", "POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    if (!ds->get_source_paused()) {
                        _MSG_INFO("Pausing source '{}' ({})", ds->get_source_name(), ds->get_source_uuid());
                        ds->pause_source();
                        return(ds);
                    } else {
                        throw std::runtime_error("Source already paused");
                    }
                }));

    httpd->register_route("/datasource/by-uuid/:uuid/resume_source", {"GET", "POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ds_uuid = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (ds_uuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(ds_uuid);

                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    if (ds->get_source_paused()) {
                        _MSG_INFO("Resuming source '{}' ({})", ds->get_source_name(), ds->get_source_uuid());
                        ds->resume_source();
                        return(ds);
                    } else {
                        throw std::runtime_error("Source already running");
                    }
                }));


    httpd->register_route("/pcap/all_packets", {"GET"}, httpd->RO_ROLE, {"pcapng"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    // We use the future stalling function in the pcap future streambuf to hold
                    // this thread in wait until the stream is closed, keeping the http connection
                    // going.  The stream is fed from the packetchain callbacks.
                    auto pcapng =
						std::make_shared<pcapng_stream_packetchain<pcapng_stream_accept_ftor, pcapng_stream_select_ftor>>(&con->response_stream(),
								pcapng_stream_accept_ftor(), pcapng_stream_select_ftor(), (size_t) 1024*512);

                    con->clear_timeout();
                    con->set_target_file("kismet-all-packets.pcapng");
                    con->set_closure_cb([pcapng]() { pcapng->stop_stream("http connection lost"); });

                    auto sid =
                        streamtracker->register_streamer(pcapng, "kismet-all-packets.pcapng",
                            "pcapng", "httpd",
                            fmt::format("pcapng of all packets"));

                    pcapng->start_stream();
                    pcapng->block_until_stream_done();

                    streamtracker->remove_streamer(sid);
                }));

    httpd->register_route("/datasource/pcap/by-uuid/:uuid/packets", {"GET"}, httpd->RO_ROLE, {"pcapng"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto dsuuid = string_to_n<uuid>(con->uri_params()[":uuid"]);
                    if (dsuuid.error)
                        throw std::runtime_error("invalid uuid");

                    auto ds = find_datasource(dsuuid);
                    if (ds == nullptr)
                        throw std::runtime_error("no such datasource");

                    auto dsnum = ds->get_source_number();

                    auto pcapng = std::make_shared<pcapng_stream_packetchain<pcapng_datasourcetracker_accept_ftor, pcapng_stream_select_ftor>>(&con->response_stream(),
							pcapng_datasourcetracker_accept_ftor(dsnum),
							pcapng_stream_select_ftor(), (size_t) 1024*512);

                    con->clear_timeout();
                    con->set_target_file(fmt::format("kismet-datasource-{}-{}.pcapng",
                                ds->get_source_name(), dsuuid));
                    con->set_closure_cb([pcapng]() { pcapng->stop_stream("http connection lost"); });

                    auto sid =
                        streamtracker->register_streamer(pcapng, fmt::format("kismet-datasource-{}-{}.pcapng",
                                ds->get_source_name(), dsuuid),
                            "pcapng", "httpd",
                            fmt::format("pcapng of packets for datasource {} {}", ds->get_source_name(), dsuuid));

                    pcapng->start_stream();
                    pcapng->block_until_stream_done();

                    streamtracker->remove_streamer(sid);
                }));

    httpd->register_websocket_route("/datasource/remote/remotesource", "datasource", {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                std::shared_ptr<kis_net_web_websocket_endpoint> ws;

                auto ds_bridge = std::make_shared<dst_websocket_ds_bridge>();
                ds_bridge->mutex.set_name("incoming remote bridge");

                ws =
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [ds_bridge](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf,bool text) {

                        kis_lock_guard<kis_mutex> lk(ds_bridge->mutex, "dst websocket rx");

                        if (ds_bridge->bridged_ds == nullptr) {
                            ws->close();
                            return;
                        }

                        // All remotecap protocol packets are a complete ws message, so if we didn't get enough to
                        // constitute a full packet, throw an error - we're not going to get to build up a buffer
                        auto cmd_ds = ds_bridge->bridged_ds;
                        auto ret = cmd_ds->handle_packet(buf);

                        if (ret != kis_external_interface::result_handle_packet_ok) {
                            cmd_ds->handle_error(fmt::format("unhandled websocket packet - {}", ret));
                            ws->close();
                            return;
                        }

                        });

                ws->binary();

                ds_bridge->bridged_ds =
                    std::make_shared<dst_incoming_remote>(
                            [this, ds_bridge, ws] (dst_incoming_remote *initiator, std::string in_type,
                                std::string in_def, uuid in_uuid) {

                            kis_lock_guard<kis_mutex> lk(ds_bridge->mutex, "dst websocket completion");

                            // _MSG_DEBUG("Initiating opening full ds");
                            // Retain a reference to it until we exit this loop
                            auto initiatior_ds = ds_bridge->bridged_ds;

                            auto new_ds =
                                datasourcetracker->open_remote_datasource(initiator, in_type, in_def,
                                    in_uuid, false);

                            if (new_ds == nullptr) {
                                ws->close();
                                return;
                            }

                            ds_bridge->bridged_ds = new_ds;

                            if (new_ds == nullptr)
                                _MSG_ERROR("Failed to map incoming websocket remote datasource");

                            if (new_ds == nullptr && ws != nullptr) {
                                // _MSG_DEBUG("remote ds failed, got null");
                                ws->close();
                            }
                        });

                // _MSG_DEBUG("made remote bridge");

                auto write_cb =
                    [ws](const char *data, size_t sz, std::function<void (int, std::size_t)> comp) -> int {
                        ws->write(data, sz);

                        // Shim with both sizes for now since async always accepts all
                        comp(sz, sz);

                        return sz;
                    };

                auto closure_cb =
                    [ws]() {
                        ws->close();
                    };

                auto ws_io = std::make_shared<kis_external_ws>(ds_bridge->bridged_ds, ws, write_cb);

                ds_bridge->bridged_ds->set_closure_cb(closure_cb);

                ds_bridge->bridged_ds->attach_io(ws_io);

                // Blind-catch all errors b/c we must release our listeners at the end
                try {
                    ws->handle_request(con);
                } catch (...) { }

                if (ds_bridge->bridged_ds != nullptr) {
                    kis_lock_guard<kis_mutex> lk(ds_bridge->mutex, "dst websocket bridge teardown");
                    if (ds_bridge->bridged_ds->get_source_running()) {
                        ds_bridge->bridged_ds->handle_error("websocket connection closed");
                    }
                }
                }));
}

// Open the sources from -c or source=.  Called by main() once plugins are active, so sources of a
// type a plugin registers can be opened too.
void datasource_tracker::launch_configured_sources() {
    bool used_args = false;

    std::vector<std::string> src_vec;

    int option_idx = 0;

	static struct option packetsource_long_options[] = {
		{ "capture-source", required_argument, 0, 'c' },
		{ 0, 0, 0, 0 }
	};

    optind = 0;

    while (1) {
        int r = getopt_long(Globalreg::globalreg->argc, Globalreg::globalreg->argv, "-c:",
                packetsource_long_options, &option_idx);

        if (r < 0) break;

        if (r == 'c') {
            used_args = true;
            src_vec.push_back(std::string(optarg));
        }
    }

    if (used_args) {
        _MSG("Data sources passed on the command line (via -c source), ignoring "
                "source= definitions in the Kismet config file.", MSGFLAG_INFO);
    } else {
        src_vec = Globalreg::globalreg->kismet_config->fetch_opt_vec("source");
    }

    if (src_vec.size() == 0) {
        _MSG("No data sources defined; Kismet will not capture anything until "
                "a source is added.", MSGFLAG_INFO);
        return;
    }

    auto stagger_thresh =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("source_stagger_threshold", 16);
    auto simul_open =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("source_launch_group", 10);
    auto simul_open_delay =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("source_launch_delay", 10);

    auto launch_func = [](datasource_tracker *dst, std::string src) {
            // _MSG_DEBUG("launching ds {}", src);
            dst->open_datasource(src,
                    [src](bool success, std::string reason, shared_datasource) {
                if (success) {
                    _MSG_INFO("Data source '{}' launched successfully", src);
                } else {
                    if (reason.length() != 0) {
                        _MSG_ERROR("Data source '{}' failed to launch: {}", src, reason);
                    } else {
                        _MSG_ERROR("Data source '{}' failed to launch, no error provided.", src);
                    }
                }
            });
    };

    if (stagger_thresh == 0 || src_vec.size() <= stagger_thresh) {
        auto source_t = std::thread([launch_func](datasource_tracker *dst,
                    const std::vector<std::string>& src_vec) {
                for (auto i : src_vec) {
                    launch_func(dst, i);
                }
                }, this, src_vec);
        source_t.detach();
    } else {
        std::vector<std::string> work_vec;
        unsigned int group_number = 0;

        for (auto i : src_vec) {
            work_vec.push_back(i);

            if (work_vec.size() > simul_open) {
                // Pass a copy of the work vec so that we can immediately clear it
                auto launch_t = std::thread([launch_func, simul_open_delay](datasource_tracker *dst,
                            const std::vector<std::string> src_vec, unsigned int gn) {

                    // All the threads launch more or less at once, so each thread sleeps for
                    // its allocated amount of time before launching the vector
                    sleep(gn * simul_open_delay);
                    _MSG_INFO("Launching local source group {}", gn + 1);

                    for (auto i : src_vec) {
                        launch_func(dst, i);
                    }
                }, this, work_vec, group_number);
                launch_t.detach();

                work_vec.clear();
                group_number++;
            }
        }

        // Launch the last of the group
        auto launch_t = std::thread([launch_func, simul_open_delay](datasource_tracker *dst,
                    const std::vector<std::string> src_vec, unsigned int gn) {

                    sleep(gn * simul_open_delay);
                    _MSG_INFO("Launching local source group {}", gn);

                    for (auto i : src_vec) {
                        launch_func(dst, i);
                    }
                }, this, work_vec, group_number);
                launch_t.detach();
    }

    return;
}

void datasource_tracker::trigger_deferred_shutdown() {
    std::vector<std::shared_ptr<kis_datasource>> sources;

    {
        kis_lock_guard<kis_mutex> lk(dst_lock, "dst trigger_deferred_shutdown");

        for (auto i : *datasource_vec)
            sources.push_back(std::static_pointer_cast<kis_datasource>(i));
    }

    // Unlocked from here: a source finishing its close reports back through
    // the IO threads, and nothing here may hold what they need.

    unsigned int wait_ms = 0;

    for (const auto& s : sources) {
        s->close_source();
        wait_ms = std::max(wait_ms, s->get_graceful_close_wait_ms());
    }

    // Graceful closes: wait for them here, bounded.  The IO threads are
    // still running, so what a closing source sends now -- its end-of-capture
    // records -- is still received and queued for the packet chain; the log
    // tracker's deferred shutdown runs after this one and drains the chain
    // before it closes the logs.
    if (wait_ms > 0) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);

        while (std::chrono::steady_clock::now() < deadline) {
            bool pending = false;

            for (const auto& s : sources) {
                if (s->get_graceful_close_pending()) {
                    pending = true;
                    break;
                }
            }

            if (!pending)
                break;

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        for (const auto& s : sources)
            s->abort_graceful_close("did not finish closing before Kismet shut down");
    }
}

void datasource_tracker::iterate_datasources(datasource_tracker_worker *in_worker) {
    std::shared_ptr<tracker_element_vector> immutable_copy;

    {
        kis_lock_guard<kis_mutex> lk(dst_lock, "dst iterate_datasources");
        immutable_copy = std::make_shared<tracker_element_vector>(datasource_vec);
    }

    for (auto kds : *immutable_copy) {
        in_worker->handle_datasource(std::static_pointer_cast<kis_datasource>(kds));
    }

    in_worker->finalize();
}

bool datasource_tracker::remove_datasource(const uuid& in_uuid) {
    kis_lock_guard<kis_mutex> lk(dst_lock, "dst remove_datasource");

    // Look for it in the sources vec and fully close it and get rid of it
    for (auto i = datasource_vec->begin(); i != datasource_vec->end(); ++i) {
        shared_datasource kds = std::static_pointer_cast<kis_datasource>(*i);

        if (kds->get_source_uuid() == in_uuid) {
            std::stringstream ss;

            _MSG_INFO("Closing source '{}' and removing it from the list of available "
                    "datasources.", kds->get_source_name());

            // close it
            kds->close_source();

            // Remove it
            datasource_vec->erase(i);

            // Done
            return true;
        }
    }

    return false;
}

shared_datasource datasource_tracker::find_datasource(const uuid& in_uuid) {
    kis_lock_guard<kis_mutex> lk(dst_lock, "dst find_datasource");

    for (auto i : *datasource_vec) {
        shared_datasource kds = std::static_pointer_cast<kis_datasource>(i);

        if (kds->get_source_uuid() == in_uuid)
            return kds;
    }

    return nullptr;
}

bool datasource_tracker::close_datasource(const uuid& in_uuid) {
    kis_lock_guard<kis_mutex> lk(dst_lock, "dst close_datasource");

    for (auto i : *datasource_vec) {
        auto kds = std::static_pointer_cast<kis_datasource>(i);

        if (kds->get_source_uuid() == in_uuid) {
            _MSG_INFO("Closing source '{}'", kds->get_source_name());

            // close it
            kds->close_source();

            // Done
            return true;
        }
    }

    return false;
}

int datasource_tracker::register_datasource(shared_datasource_builder in_builder) {
    kis_lock_guard<kis_mutex> lk(dst_lock, "dst register_datasource");

    for (auto i : *proto_vec) {
        shared_datasource_builder b = std::static_pointer_cast<kis_datasource_builder>(i);

        if (str_lower(b->get_source_type()) == str_lower(in_builder->get_source_type())) {
            _MSG_ERROR("Already registered a data source for type '{}', check that you don't have "
                    "two copies of the same plugin installed in different locations or under "
                    "different names.", b->get_source_type());
            return -1;
        }
    }

    proto_vec->push_back(in_builder);

    return 1;
}

void datasource_tracker::open_datasource(const std::string& in_source,
        const std::function<void (bool, std::string, shared_datasource)>& in_cb) {
    // fprintf(stderr, "debug - DST open source %s\n", in_source.c_str());

    // Open a datasource only from the string definition

    std::string interface;
    std::string options;
    std::vector<opt_pair> opt_vec;
    std::string type;

    size_t cpos = in_source.find(":");

    // Parse basic options and interface, extract type
    if (cpos == std::string::npos) {
        interface = in_source;
        type = "auto";
    } else {
        interface = in_source.substr(0, cpos);
        options = in_source.substr(cpos + 1, in_source.size() - cpos);

        string_to_opts(options, ",", &opt_vec);

        type = str_lower(fetch_opt("type", &opt_vec));

        if (type == "")
            type = "auto";
    }

    // So long as we have a type - that is, an explicitly defined type which
    // is not "auto" - we know what driver is supposed to open it.  We look
    // for that driver in the prototype vector, confirm it can open it, and fire
    // the launch command at it
    if (type != "auto") {
        kis_unique_lock<kis_mutex> lock(dst_lock, std::defer_lock, "dst open_datasource auto");
        lock.lock();

        shared_datasource_builder proto;

        bool proto_found = false;

        for (auto i : *proto_vec) {
            proto = std::static_pointer_cast<kis_datasource_builder>(i);

            if (str_lower(proto->get_source_type()) == str_lower(type)) {
                proto_found = true;
                break;
            }
        }

        if (!proto_found) {
            auto ss = fmt::format("Unable to find datasource for '{}'.  Make sure that any "
                    "required plugins are installed, that the capture interface is available, "
                    "and that you installed all the Kismet helper packages.", type);

            if (in_cb != NULL) {
                lock.unlock();
                in_cb(false, ss, NULL);
                lock.lock();
            }

            return;
        }

        // Open the source with the processed options
        open_datasource(in_source, proto, in_cb);
        return;
    }

    // Otherwise we have to initiate a probe, which is async itself, and
    // tell it to call our CB when it completes.  The probe will find if there
    // is a driver that can claim the source string we were given, and
    // we'll initiate opening it if there is
    _MSG_INFO("Probing interface '{}' to find datasource type", interface);

    // Create a DSTProber to handle the probing
    std::shared_ptr<tracker_element_vector> filtered_proto_vec =
        std::make_shared<tracker_element_vector>();

    for (auto p : *proto_vec) {
        bool accept = true;

        auto pt = std::static_pointer_cast<kis_datasource_builder>(p);

        for (auto f : auto_masked_types) {
            if (pt->get_source_type() == f) {
                accept = false;
                break;
            }
        }

        if (accept)
            filtered_proto_vec->push_back(p);
    }


    // Lock while we initialize the probe
    kis_unique_lock<kis_mutex> lock(dst_lock, "dst probe_sources");
    unsigned int probeid = ++next_probe_id;
    auto dst_probe = std::make_shared<datasource_tracker_source_probe>(probeid, in_source, filtered_proto_vec);
    probing_map[probeid] = dst_probe;
    lock.unlock();

    // Initiate the probe with callback
    dst_probe->probe_sources([this, dst_probe, in_cb](unsigned long probeid, shared_datasource_builder builder) mutable {
        // Lock on completion
        kis_unique_lock<kis_mutex> lock(dst_lock, std::defer_lock, "dst probe_sources lambda");
        lock.lock();

        // fprintf(stderr, "debug - moving probe to completed vec\n");

        auto i = probing_map.find(probeid);

        if (i != probing_map.end()) {
            // Mark this object for completion when the callback triggers
            probing_complete_vec.push_back(i->second);

            auto probe_ref = i->second;

            if (builder == nullptr) {
                // We couldn't find a type, return an error to our initial open CB
                auto ss = fmt::format("Unable to find driver for '{}'.  Make sure that any required plugins "
                        "are loaded, the interface is available, and any required Kismet helper packages are "
                        "installed.", i->second->get_definition());

                // Append the reason from the driver that plausibly owns this
                // definition, if one gave us a reason. Without this the
                // sentence above is definition-agnostic: identical for a typo,
                // a missing helper package and an unplugged radio, even when a
                // helper wrote a sentence naming the exact problem.
                //
                // Concatenated onto the SAME message rather than emitted as a
                // second one: the two are one event, and a separate _MSG would
                // be free to arrive apart from it (or, on a --silent server, to
                // be the half that survives).
                auto reason = i->second->get_decline_reason();
                if (reason.length())
                    ss += fmt::format("  The closest matching driver said: {}", reason);

                _MSG(ss, MSGFLAG_ERROR);
                lock.unlock();
                in_cb(false, ss, NULL);
                lock.lock();
            } else {
                // We got a builder
                _MSG_INFO("Found type '{}' for '{}'", builder->get_source_type(), i->second->get_definition());

                // Let go of the lock
                lock.unlock();

                // Initiate an open w/ a known builder, associate the prototype definition with it
                open_datasource(probe_ref->get_definition(), builder, in_cb);

                lock.lock();
            }

            // _MSG_DEBUG("removing probing event {} from probing map, count {}", probeid, probe_ref.use_count());

            // Remove us from the active vec
            probing_map.erase(i);

            // Schedule a cleanup
            schedule_cleanup();
        } else {
            // _MSG_DEBUG("probe returned unknown probeid {}", probeid);
            // fprintf(stderr, "debug - DST couldn't find response %u\n", probeid);
        }
    });

    return;
}

void datasource_tracker::open_datasource(const std::string& in_source,
        shared_datasource_builder in_proto,
        const std::function<void (bool, std::string, shared_datasource)>& in_cb) {

    // Make a data source from the builder
    shared_datasource ds = in_proto->build_datasource(in_proto);

    ds->open_interface(in_source, 0,
        [this, ds, in_cb] (unsigned int, bool success, std::string reason) mutable {
            // Always merge it so that it gets scheduled for re-opening; when we
            // know the type we know how to keep trying
            merge_source(ds);

            // Whenever we succeed (or fail) at opening a deferred open source,
            // call our callback w/ whatever we know
            if (success) {
                in_cb(true, "", ds);
            } else {
                // It's 'safe' to put them in the broken source vec because all we do is
                // clear that vector on a timer; if the source is in in_sourceerror state but
                // bound elsewhere in the system it won't be removed.
                kis_lock_guard<kis_mutex> lk(dst_lock, "dst open_datasource string open lambda broken");
                broken_source_vec.push_back(ds);
                in_cb(false, reason, ds);
                schedule_cleanup();
            }
        });
}

void datasource_tracker::merge_source(shared_datasource in_source) {
    kis_lock_guard<kis_mutex> lk(dst_lock, "dst merge_source");

    const uuid u = in_source->get_source_uuid();

    // We maintain a persistent map of source uuids to source numbers, which
    // persists even if a source is later removed entirely from the datasource
    // list.

    const auto& i = uuid_source_num_map.find(u);
    if (i != uuid_source_num_map.end()) {
        in_source->set_source_number(i->second);
    } else {
        in_source->set_source_number(++next_source_num);
        uuid_source_num_map[u] = in_source->get_source_number();

        auto evt = eventbus->get_eventbus_event(event_new_datasource());
        evt->get_event_content()->insert(event_new_datasource(), in_source);
        eventbus->publish(evt);
    }

    // Figure out channel hopping
    calculate_source_hopping(in_source);

    if (database_log_enabled) {
        std::shared_ptr<kis_database_logfile> dbf =
            Globalreg::fetch_global_as<kis_database_logfile>("DATABASELOG");

        if (dbf != NULL) {
            dbf->log_datasource(in_source);
        }
    }

    // We should only ever have one copy of a datasource in the datasource vector,
    // unique by UUID.  If there's already a datasource in there that has the same uuid,
    // something has gone wrong, because re-opening an existing datasource doesn't create
    // a new datasource object!
    //
    // A remote ds will make sure an existing ds doesn't exist with the same UUID before
    // merging the incoming remote connection, and a local datasource should never hit
    // merge if it's not unique

    for (const auto& dsi : *datasource_vec) {
        auto ds = std::static_pointer_cast<kis_datasource>(dsi);

        if (ds->get_source_uuid() == u) {
            _MSG_ERROR("Conflict of new datasource {}/{} and existing datasource {} with "
                    "the same UUID.  Datasource UUIDs must be unique, check the Kismet documentation "
                    "for the datasources you are using, and ensure that any manually defined "
                    "UUIDs are unique.",
                    in_source->get_source_name(), u, ds->get_source_name());
            in_source->close_source();
            break;
        }
    }

    datasource_vec->push_back(in_source);
}

void datasource_tracker::list_interfaces(const std::function<void (std::vector<shared_interface>)>& in_cb) {
    kis_unique_lock<kis_mutex> lock(dst_lock, std::defer_lock, "dst list_interfaces");
    lock.lock();

    // Create a DSTProber to handle the probing
    std::shared_ptr<tracker_element_vector> filtered_proto_vec =
        std::make_shared<tracker_element_vector>();

    for (auto p : *proto_vec) {
        bool accept = true;

        auto pt = std::static_pointer_cast<kis_datasource_builder>(p);

        for (auto f : auto_masked_types) {
            if (pt->get_source_type() == f) {
                accept = false;
                break;
            }
        }

        if (accept)
            filtered_proto_vec->push_back(p);
    }

    // Create a DSTProber to handle the probing
    auto dst_list = std::make_shared<datasource_tracker_source_list>(filtered_proto_vec);
    unsigned int listid = ++next_list_id;

    // Record it
    listing_map[listid] = dst_list;

    // Release the mutex before initiating a sources list
    lock.unlock();

    // Initiate the probe
    dst_list->list_sources(dst_list, [this, listid, in_cb, dst_list](std::vector<shared_interface> interfaces) {
        kis_unique_lock<kis_mutex> lock(dst_lock, "dst list_sources cancel lambda");

        // Filter interfaces
        std::vector<shared_interface> f_interfaces;

        for (auto i : interfaces) {
            bool copy = true;

            for (const auto& mi : masked_ifnames) {
                if (i->get_interface() == mi) {
                    copy = false;
                    break;
                }

                if (i->get_cap_interface() == mi) {
                    copy = false;
                    break;
                }
            }

            if (copy) {
                f_interfaces.push_back(i);
            }
        }

        // Figure out what interfaces are in use by active sources and amend their
        // UUID records in the listing
        for (const auto& il : f_interfaces) {
            for (const auto& s : *datasource_vec) {
                shared_datasource sds = std::static_pointer_cast<kis_datasource>(s);

                if (!sds->get_source_remote() && sds->get_source_running() &&
                        (il->get_interface() == sds->get_source_interface() ||
                         il->get_interface() == sds->get_source_cap_interface() ||
                         il->get_cap_interface() == sds->get_source_interface() ||
                         il->get_cap_interface() == sds->get_source_cap_interface())) {
                    il->set_in_use_uuid(sds->get_source_uuid());
                    break;
                }
            }
        }

        lock.unlock();

        in_cb(f_interfaces);

        lock.lock();

        auto i = listing_map.find(listid);

        if (i != listing_map.end()) {
            listing_complete_vec.push_back(i->second);
            listing_map.erase(i);
            schedule_cleanup();
        }
    });
}

void datasource_tracker::schedule_cleanup() {
    kis_lock_guard<kis_mutex> lg(dst_lock);

    if (completion_cleanup_id >= 0)
        return;

    completion_cleanup_id =
        timetracker->register_timer(1, NULL, 0, [this] (int) -> int {
            kis_unique_lock<kis_mutex> lock(dst_lock, std::defer_lock, "dst schedule_cleanup lambda");

            lock.lock();

            // Copy the vectors so we don't actually free the shared ptrs yet
            auto d_pcv = probing_complete_vec;
            auto d_lcv = listing_complete_vec;
            auto d_bsv = broken_source_vec;

            completion_cleanup_id = -1;

            // Clear the tracker level copies
            probing_complete_vec.clear();
            listing_complete_vec.clear();
            broken_source_vec.clear();
            lock.unlock();

            // Actually purge them outside of lockdown
            d_pcv.clear();
            d_lcv.clear();
            d_bsv.clear();

            return 0;
        });

}

std::shared_ptr<kis_datasource> datasource_tracker::open_remote_datasource(dst_incoming_remote *incoming,
        const std::string& in_type, const std::string& in_definition, const uuid& in_uuid,
        bool connect_tcp) {

    shared_datasource merge_target_device;

    kis_unique_lock<kis_mutex> lock(dst_lock, "dst open_remote_datasource");

    // Look for an existing datasource with the same UUID, if the remote announced one
    for (auto p : *datasource_vec) {
        if (in_uuid.error)
            break;

        shared_datasource d = std::static_pointer_cast<kis_datasource>(p);

        if (d->get_source_uuid() == in_uuid) {
            merge_target_device = d;
            break;
        }
    }

    if (merge_target_device != NULL) {
        if (merge_target_device->get_source_builder()->get_source_type() != in_type) {
            _MSG_ERROR("Incoming remote connection for source '{}' matches existing source '{}', "
                    "but has a different source type.  Make sure that multiple remote captures are "
                    "not running for the same device, and that each remote capture source has a "
                    "unique UUID if manually assigned.  For some remote source types such as "
                    "the rtlsdr family, you may need to manually set the uuid= source parameter.",
                    in_uuid.uuid_to_string(), merge_target_device->get_source_name());
            incoming->trigger_error("mismatch device type for this uuid");
            return nullptr;
        }

        if (merge_target_device->get_source_disabled()) {
            _MSG_ERROR("Incoming remote connection for source '{}' matches existing source '{}', "
                    "which has been disabled.  Re-open the source to accept the remote connection.",
                    in_uuid.uuid_to_string(), merge_target_device->get_source_name());
            incoming->trigger_error("source disabled");
            return nullptr;
        }

        if (merge_target_device->get_source_running()) {
            _MSG_ERROR("Incoming remote connection for source '{}' matches existing source '{}', "
                    "which is still running.  The running instance will be closed; make sure "
                    "that multiple remote captures are not running for the same source.  This may "
                    "also indicate multiple remote sources with the same serial number or UUID, "
                    "which may occur with rtlsdr and others.  You may need to set the uuid= "
                    "parameter in your remote source definition.",
                    in_uuid.uuid_to_string(), merge_target_device->get_source_name());
            lock.unlock();
            merge_target_device->close_source();
            lock.lock();
        } else {
            _MSG_INFO("Matching new remote source '{}' with known source with UUID '{}'",
                    in_definition, in_uuid.uuid_to_string());
        }

        // Explicitly unlock our mutex before running a thread
        lock.unlock();

        merge_target_device->connect_remote(in_definition, incoming, in_uuid, connect_tcp,
                [this, merge_target_device](unsigned int, bool success, std::string msg) {
                    if (success) {
                        _MSG_INFO("Remote source {} ({}) reconnected",
                                merge_target_device->get_source_name(),
                                merge_target_device->get_source_uuid());
                        calculate_source_hopping(merge_target_device);
                    } else {
                        _MSG_ERROR("Error reconnecting remote source {} ({}) - {}",
                                merge_target_device->get_source_name(),
                                merge_target_device->get_source_uuid(), msg);
                    }
                });

        return merge_target_device;
    }

    // Otherwise look for a prototype that can handle it
    for (auto p : *proto_vec) {
        shared_datasource_builder b = std::static_pointer_cast<kis_datasource_builder>(p);

        if (!b->get_remote_capable())
            continue;

        if (b->get_source_type() == in_type) {
            // Explicitly unlock the mutex before we fire the connection handler
            lock.unlock();

            // Make a data source from the builder
            shared_datasource ds = b->build_datasource(b);
            ds->connect_remote(in_definition, incoming, in_uuid, connect_tcp,
                [this, ds](unsigned int, bool success, std::string msg) {
                    if (success) {
                        _MSG_INFO("New remote source {} ({}) connected", ds->get_source_name(),
                                ds->get_source_uuid());
                        merge_source(ds);
                    } else {
                        _MSG_ERROR("Error connecting new remote source {} ({}) - {}",
                                ds->get_source_name(), ds->get_source_uuid(), msg);
                        broken_source_vec.push_back(ds);
                    }
                });

            return ds;
        }
    }

    _MSG_ERROR("Kismet could not find a datasource driver for incoming remote source "
            "'{}' defined as '{}'; make sure that Kismet was compiled with all the "
            "data source drivers and that any necessary plugins have been loaded.",
            in_type, in_definition);

    return nullptr;
}

// Basic DST worker for figuring out how many sources of the same type
// exist, and are hopping
class dst_chansplit_worker : public datasource_tracker_worker {
public:
    dst_chansplit_worker(datasource_tracker *in_dst,
            std::shared_ptr<datasource_tracker_defaults> in_defaults,
            shared_datasource in_ds) {
        dst = in_dst;
        defaults = in_defaults;
        target_sources.push_back(in_ds);
        initial_ds = in_ds;
        match_type = in_ds->get_source_builder()->get_source_type();
    }

    virtual void handle_datasource(shared_datasource in_src) {
        // Don't dupe ourselves
        if (in_src == initial_ds)
            return;

        // Don't look at ones we don't care about
        if (in_src->get_source_builder()->get_source_type() != match_type)
            return;

        // Don't look at ones that aren't open yet
        if (!in_src->get_source_running())
            return;

        bool match_list = true;

        auto initial_channels = initial_ds->get_source_channels_vec_copy();
        auto compare_channels = in_src->get_source_channels_vec_copy();

        if (initial_channels.size() != compare_channels.size())
            return;

        for (const auto& first_chan : initial_channels) {
            bool matched_cur_chan = false;

            for (const auto& comp_chan : compare_channels) {
                if (first_chan == comp_chan) {
                    matched_cur_chan = true;
                    break;
                }
            }

            if (!matched_cur_chan) {
                match_list = false;
                break;
            }
        }

        if (match_list)
            target_sources.push_back(in_src);
    }

    virtual void finalize() {
        if (target_sources.size() <= 1) {
            initial_ds->set_channel_hop(dst->definition_hop_rate(initial_ds),
                    initial_ds->get_source_hop_vec(),
                    defaults->get_random_channel_order(),
                    0, 0, NULL);
            return;
        }

        _MSG_INFO("Splitting channels for interfaces using '{}' among {} interfaces",
                match_type, target_sources.size());

        int nintf = 0;
        for (auto ds : target_sources) {
            int offt_count = target_sources.size();

            auto ds_hopchans = (ds)->get_source_hop_vec();

            int ds_offt = (ds_hopchans->size() / offt_count) * nintf;

            ds->set_channel_hop(dst->definition_hop_rate(ds), ds_hopchans, defaults->get_random_channel_order(),
                    ds_offt, 0, NULL);

            nintf++;
        }

    }

protected:
    std::string match_type;

    datasource_tracker *dst;

    shared_datasource initial_ds;
    std::vector<shared_datasource> target_sources;

    std::shared_ptr<datasource_tracker_defaults> defaults;

};

void datasource_tracker::calculate_source_hopping(shared_datasource in_ds) {
    // Failed sources are merged so they can be re-opened, but there's nothing to configure
    if (!in_ds->get_source_running())
        return;

    if (!in_ds->get_definition_opt_bool("channel_hop", true)) {
        // Source doesn't hop regardless of defaults
        return;
    }

    // Turn on channel hopping if we do that
    if (config_defaults->get_hop() && in_ds->get_source_builder()->get_tune_capable() &&
            in_ds->get_source_builder()->get_hop_capable()) {
        // Do we split sources?
        if (config_defaults->get_split_same_sources()) {
            dst_chansplit_worker worker(this, config_defaults, in_ds);
            iterate_datasources(&worker);
        } else {
            in_ds->set_channel_hop(definition_hop_rate(in_ds),
                    in_ds->get_source_hop_vec(),
                    config_defaults->get_random_channel_order(),
                    0, 0, NULL);
        }
    }
}

double datasource_tracker::definition_hop_rate(shared_datasource in_ds) {
    auto opt = in_ds->get_definition_opt("channel_hoprate");

    if (opt == "")
        return config_defaults->get_hop_rate();

    double rate;

    try {
        rate = string_to_rate(opt, -1);
    } catch (const std::exception& e) {
        _MSG_ERROR("Source '{}' could not parse channel_hoprate= option: {}, using default "
                "channel rate.", in_ds->get_source_name(), e.what());
        return config_defaults->get_hop_rate();
    }

    // 0/sec or 0/dwell (infinite) would leave the source not hopping at all
    if (!std::isfinite(rate) || rate <= 0) {
        _MSG_ERROR("Source '{}' channel_hoprate={} is not a usable hop rate, using default "
                "channel rate.", in_ds->get_source_name(), opt);
        return config_defaults->get_hop_rate();
    }

    return rate;
}

double datasource_tracker::string_to_rate(std::string in_str, double in_default) {
    double v, dv;

    std::vector<std::string> toks = str_tokenize(in_str, "/");

    if (toks.size() != 2)
        throw std::runtime_error("Expected [value]/sec or [value]/min or [value]/dwell");

    v = string_to_n<double>(toks[0]);

    if (toks[1] == "sec") {
        return v;
    } else if (toks[1] == "dwell") {
        // Channel dwell is # of *seconds per hop* for very long hop intervals; so to get
        // hops per minute it's dwell seconds.  We convert to a double # of hops per minute,
        // then apply the formula below to turn that into the double value; simplified to:
        dv = 1.0f / v;

        return dv;
    } else if (toks[1] == "min") {
        // Channel hop is # of hops a second, timed in usec, so to get hops per
        // minute we get a minutes worth of usecs (60m), divide by the number
        // of hops per minute, then divide a second by that.
        // dv = (double) 1000000 / (double) ((double) (1000000 * 60) / (double) v);
        // simplified to:
        dv = v / 60.0f;

        return dv;
    } else {
        throw std::runtime_error("Expected [value]/sec or [value]/min");
    }
}



dst_incoming_remote::dst_incoming_remote(callback_t in_cb) :
    kis_datasource() {

    cb = in_cb;

    timerid =
        timetracker->register_timer(std::chrono::seconds(5), 0,
            [this] (int) -> int {
            _MSG_ERROR("Incoming connection on remote capture socket, but remote side did "
                    "not initiate a datasource connection.");
                close_external();
                return 0;
            });
}

dst_incoming_remote::~dst_incoming_remote() {
    // Kill the error timer
    timetracker->remove_timer(timerid);

    close_external();

    // Wait for the thread to finish
    if (handshake_thread.joinable())
        handshake_thread.join();
}

#ifdef HAVE_PROTOBUF_CPP
bool dst_incoming_remote::dispatch_rx_packet(const std::string_view& command,
        uint32_t seqno, const std::string_view& content) {
    // Simple dispatch override, all we do is look for the new source
    if (command.compare("KDSNEWSOURCE") == 0) {
        handle_packet_newsource(seqno, content);
        return true;
    }

    if (kis_external_interface::dispatch_rx_packet(command, seqno, content))
        return true;

    return false;
}

void dst_incoming_remote::handle_packet_newsource(uint32_t in_seqno,
        const std::string_view in_content) {
    KismetDatasource::NewSource c;

    if (!c.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG("Could not process incoming remote datasource announcement", MSGFLAG_ERROR);
        kill();
        return;
    }

    if (cb != NULL) {
        cb(this, c.sourcetype(), c.definition(), c.uuid());
    }

    kill();
}
#endif

bool dst_incoming_remote::dispatch_rx_packet_v3(std::shared_ptr<boost::asio::streambuf> buffer,
        uint16_t command, uint16_t code, uint32_t seqno, const std::string_view& content) {
    // override the new source command
    if (command == KIS_EXTERNAL_V3_KDS_NEWSOURCE) {
        handle_packet_newsource_v3(seqno, code, content);
        return true;
    }

    if (kis_external_interface::dispatch_rx_packet_v3(buffer, command, seqno, code, content)) {
        return true;
    }

    return false;
}

void dst_incoming_remote::handle_packet_newsource_v3(uint32_t in_seqno, uint16_t in_code,
        std::string_view in_packet) {

    mpack_tree_raii tree;
    mpack_node_t root;

    mpack_tree_init_data(&tree, in_packet.data(), in_packet.length());

    if (!mpack_tree_try_parse(&tree)) {
        _MSG_ERROR("Kismet external interface got unparseable v3 PROBEREPORT");
        trigger_error("invalid v3 PROBEREPORT");
        return;
    }

    root = mpack_tree_root(&tree);

    auto definition_n = mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_DEFINITION);
    auto definition_s = mpack_node_str(definition_n);
    auto definition_sz = mpack_node_data_len(definition_n);


    auto type_n = mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_SOURCETYPE);
    auto type_s = mpack_node_str(type_n);
    auto type_sz = mpack_node_data_len(type_n);

    // The UUID is optional; sources which only learn it when opening report it then
    auto uuid_n = mpack_node_map_uint_optional(root, KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_UUID);
    uuid u;

    if (!mpack_node_is_missing(uuid_n)) {
        auto uuid_s = mpack_node_str(uuid_n);
        auto uuid_sz = mpack_node_data_len(uuid_n);

        if (mpack_tree_error(&tree) == mpack_ok)
            u = uuid(std::string(uuid_s, uuid_sz));
    }

    if (mpack_tree_error(&tree)) {
        _MSG_ERROR("Could not process incoming remote datasource announcement");
        kill();
        return;
    }

    auto definition = std::string(definition_s, definition_sz);
    auto srctype = std::string(type_s, type_sz);

    if (cb != NULL) {
        cb(this, srctype, definition, u);
    }

    kill();
}

void dst_incoming_remote::handle_error(const std::string& error) {
    _MSG_ERROR("(DST SETUP REMOTE ERROR) {}", error);

    kill();
}


void dst_incoming_remote::kill() {
    // Kill the error timer
    timetracker->remove_timer(timerid);

    // The tcp socket should be moved away from this connection by now; if not, kill it
    close_external();
}


datasource_tracker_remote_server::~datasource_tracker_remote_server() {
    stop();
}

void datasource_tracker_remote_server::stop() {
    stopped = true;

    if (acceptor.is_open()) {
        try {
            acceptor.cancel();
            acceptor.close();
        } catch (const std::exception& e) {
            ;
        }
    }
}

void datasource_tracker_remote_server::start_accept() {
    if (stopped)
        return;

    acceptor.async_accept(incoming_socket,
            [this](boost::system::error_code ec) {
                if (stopped)
                    return;

                handle_accept(ec, std::move(incoming_socket));

                start_accept();
            });

}

void datasource_tracker_remote_server::handle_accept(const boost::system::error_code& ec, tcp::socket socket) {
    if (!ec) {
        // Bind a new incoming remote which will pivot to the proper data source type
        auto remote =
            std::make_shared<dst_incoming_remote>([this] (dst_incoming_remote *initiator,
                        std::string in_type, std::string in_def, uuid in_uuid) {
                    datasourcetracker->open_remote_datasource(initiator, in_type, in_def, in_uuid, true);
                    });

        remote->attach_tcp_socket(socket);
    }
}

