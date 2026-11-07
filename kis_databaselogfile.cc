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

#include <algorithm>
#include <cmath>
#include <cstring>
#include <optional>

#include <fcntl.h>
#include <unistd.h>

#include "globalregistry.h"
#include "json_adapter.h"
#include "kis_databaselogfile.h"
#include "kis_datasource.h"
#include "messagebus.h"
#include "packetchain.h"
#include "sqlite3_cpp11.h"

namespace {

// Tagged data is stored as snapshots of this type prefix and the tag, so it can't
// collide with Kismet's own GPS, POI, and SYSTEM snapshots
constexpr const char *tagged_data_prefix = "API:";
constexpr size_t tagged_data_max_tag = 64;
constexpr const char *tagged_data_role = "datalog";

constexpr size_t tagged_data_default_size = 8 * 1024 * 1024;
constexpr size_t tagged_data_min_size = 100000;
constexpr size_t tagged_data_max_size = 64 * 1024 * 1024;

constexpr bool tagged_data_tag_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '.' || c == '_' || c == '-';
}

bool tagged_data_valid_tag(const std::string& tag) {
    return !tag.empty() && tag.size() <= tagged_data_max_tag &&
        std::all_of(tag.begin(), tag.end(), tagged_data_tag_char);
}

// Every API:<tag> snaptype sorts strictly between these
constexpr const char *tagged_data_range_lo = "API:";
constexpr const char *tagged_data_range_hi = "API;";

constexpr int64_t tagged_data_default_limit = 100;
constexpr int64_t tagged_data_max_limit = 1000;
// A read stops adding records once they hold this much data; one record is always
// returned, so a single large record can still be read
constexpr size_t tagged_data_read_budget = 32 * 1024 * 1024;

// Read options come from a JSON command, or from URI variables, where numbers are strings
std::optional<double> tagged_data_num_opt(std::shared_ptr<kis_net_beast_httpd_connection> con,
        const std::string& key, bool& bad) {
    const auto& j = con->json();
    if (j.is_object()) {
        auto k = j.find(key);
        if (k != j.end()) {
            if (k->is_number() && std::isfinite(k->get<double>()))
                return k->get<double>();
            bad = true;
            return std::nullopt;
        }
    }

    auto v = con->http_variables().find(key);
    if (v == con->http_variables().end())
        return std::nullopt;

    const auto& str = v->second;
    char *end = nullptr;
    errno = 0;
    double d = str.empty() ? 0 : std::strtod(str.c_str(), &end);
    if (str.empty() || errno != 0 || end != str.c_str() + str.size() || !std::isfinite(d)) {
        bad = true;
        return std::nullopt;
    }
    return d;
}

std::optional<std::string> tagged_data_str_opt(std::shared_ptr<kis_net_beast_httpd_connection> con,
        const std::string& key, bool& bad) {
    const auto& j = con->json();
    if (j.is_object()) {
        auto k = j.find(key);
        if (k != j.end()) {
            if (k->is_string())
                return k->get<std::string>();
            if (k->is_boolean())
                return std::string{k->get<bool>() ? "true" : "false"};
            bad = true;
            return std::nullopt;
        }
    }

    auto v = con->http_variables().find(key);
    if (v == con->http_variables().end())
        return std::nullopt;
    return v->second;
}

}

kis_database_logfile::kis_database_logfile():
    kis_logfile(shared_log_builder(NULL)),
    kis_database("kismetlog"),
    lifetime_global() {

    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();

    transaction_mutex.set_name("kis_database_logfile_transaction");
    packet_stmt_mutex.set_name("kis_database_logfile_packet_stmt");
    data_stmt_mutex.set_name("kis_database_logfile_data_stmt");

    packet_stmt = nullptr;
    data_stmt = nullptr;

    std::shared_ptr<packet_chain> packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");

    pack_comp_device = packetchain->register_packet_component("DEVICE");
    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_datasource = packetchain->register_packet_component("KISDATASRC");
    pack_comp_metablob = packetchain->register_packet_component("METABLOB");
    pack_comp_json = packetchain->register_packet_component("JSON");

    last_device_log = 0;

    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    db_enabled = false;
    close_pending = false;

    message_evt_id = 0;
    alert_evt_id = 0;
}

thread_local kis_database_logfile *kis_database_logfile::current_writer = nullptr;

kis_database_logfile::~kis_database_logfile() {
    eventbus->remove_listener(message_evt_id);
    eventbus->remove_listener(alert_evt_id);

    close_log();
}

void kis_database_logfile::trigger_deferred_startup() {
    gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();
}

void kis_database_logfile::trigger_deferred_shutdown() {

}

bool kis_database_logfile::open_log(const std::string& in_template, const std::string& in_path) {
    // kis_unique_lock<kis_mutex> lk(ds_mutex, "open_log");

    auto timetracker =
        Globalreg::fetch_mandatory_global_as<time_tracker>("TIMETRACKER");

    bool dbr = database_open(in_path, SQLITE_OPEN_FULLMUTEX);

    if (!dbr) {
        _MSG_FATAL("Unable to open KismetDB log at '{}'; check that the directory exists "
                "and that you have write permissions to it.", in_path);
        Globalreg::globalreg->fatal_condition = true;
        return false;
    }

    dbr = database_upgrade_db();

    if (!dbr) {
        _MSG_FATAL("Unable to update existing KismetDB log at {}", in_path);
        Globalreg::globalreg->fatal_condition = true;
        return false;
    }

    sqlite3_exec(db, "PRAGMA journal_mode=PERSIST", NULL, NULL, NULL);

    // Go into transactional mode where we only commit every 10 seconds
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    transaction_timer =
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
            [this](int) -> int {

            db_writer_guard writer_lk(this);
            if (!db_enabled)
                return 1;

            in_transaction_sync = true;

            sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

            in_transaction_sync = false;

            return 1;
        });


    set_int_log_path(in_path);
    set_int_log_template(in_template);

	_MSG("Opened kismetdb log file '" + in_path + "'", MSGFLAG_INFO);

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_ephemeral_dangerous", false)) {
        _MSG_INFO("KISMETDB LOG IS IN EPHEMERAL MODE.  LOG WILL *** NOT *** BE PRESERVED WHEN "
                "KISMET EXITS.");
        unlink(in_path.c_str());
    }

    packet_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_packet_timeout", 0);

    if (packet_timeout != 0) {
        packet_timeout_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * 15, NULL, 1,
                    [this](int) -> int {

                    db_writer_guard writer_lk(this);
                    if (!db_enabled)
                        return 1;

                    auto pkt_delete =
                        fmt::format("DELETE FROM packets WHERE ts_sec < {}",
                                time(0) - packet_timeout);
                    auto data_delete =
                        fmt::format("DELETE FROM data WHERE ts_sec < {}",
                                time(0) - packet_timeout);

                    sqlite3_exec(db, pkt_delete.c_str(), NULL, NULL, NULL);
                    sqlite3_exec(db, data_delete.c_str(), NULL, NULL, NULL);

                    return 1;
                    });
    } else {
        packet_timeout_timer = -1;
    }

    device_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_device_timeout", 0);

    if (device_timeout != 0) {
        device_timeout_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * 60, NULL, 1,
                    [this](int) -> int {

                    db_writer_guard writer_lk(this);
                    if (!db_enabled)
                        return 1;

                    auto pkt_delete =
                        fmt::format("DELETE FROM devices WHERE last_time < {}",
                                time(0) - device_timeout);

                    sqlite3_exec(db, pkt_delete.c_str(), NULL, NULL, NULL);

                    return 1;
                    });
    } else {
        device_timeout_timer = -1;
    }

    message_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_message_timeout", 0);

    if (message_timeout != 0) {
        message_timeout_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * 60, NULL, 1,
                    [this](int) -> int {

                    db_writer_guard writer_lk(this);
                    if (!db_enabled)
                        return 1;

                    auto pkt_delete =
                        fmt::format("DELETE FROM messages WHERE ts_sec < {}",
                                time(0) - message_timeout);

                    sqlite3_exec(db, pkt_delete.c_str(), NULL, NULL, NULL);

                    return 1;
                    });
    } else {
        message_timeout_timer = -1;
    }

    alert_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_alert_timeout", 0);

    if (alert_timeout != 0) {
        alert_timeout_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * 60, NULL, 1,
                    [this](int) -> int {

                    db_writer_guard writer_lk(this);
                    if (!db_enabled)
                        return 1;

                    auto pkt_delete =
                        fmt::format("DELETE FROM alerts WHERE ts_sec < {}",
                                time(0) - alert_timeout);

                    sqlite3_exec(db, pkt_delete.c_str(), NULL, NULL, NULL);

                    return 1;
                    });
    } else {
        alert_timeout_timer = -1;
    }

    snapshot_timeout =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_snapshot_timeout", 0);

    if (snapshot_timeout != 0) {
        snapshot_timeout_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * 60, NULL, 1,
                    [this](int) -> int {

                    db_writer_guard writer_lk(this);
                    if (!db_enabled)
                        return 1;

                    auto pkt_delete =
                        fmt::format("DELETE FROM snapshots WHERE ts_sec < {}",
                                time(0) - snapshot_timeout);

                    sqlite3_exec(db, pkt_delete.c_str(), NULL, NULL, NULL);

                    return 1;
                    });
    } else {
        snapshot_timeout_timer = -1;
    }

    log_duplicate_packets =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_duplicate_packets", true);

    log_data_packets =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_data_packets", true);

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/logging/kismetdb/pcap/drop", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return packet_drop_endpoint_handler(con);
                }));

    httpd->register_route("/poi/create_poi", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return make_poi_endp_handler(con);
                }));

    poi_entry_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.poi",
                tracker_element_factory<tracker_element_map>(),
                "point of interest");
    poi_ts_sec_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.poi.ts_sec",
                tracker_element_factory<tracker_element_uint64>(),
                "point of interest timestamp, seconds");
    poi_ts_usec_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.poi.ts_usec",
                tracker_element_factory<tracker_element_uint64>(),
                "point of interest timestamp, microseconds");
    poi_lat_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.poi.lat",
                tracker_element_factory<tracker_element_double>(),
                "point of interest latitude (0 without a GPS fix)");
    poi_lon_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.poi.lon",
                tracker_element_factory<tracker_element_double>(),
                "point of interest longitude (0 without a GPS fix)");
    poi_note_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.poi.note",
                tracker_element_factory<tracker_element_string>(),
                "point of interest note");

    auto tagged_data_endp =
        std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return tagged_data_endp_handler(con);
                });
    httpd->register_route("/logging/kismetdb/data/push", {"POST"},
            std::list<std::string>{tagged_data_role}, {"cmd"}, tagged_data_endp);

    auto tagged_data_size =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_tagged_data_max_size",
                tagged_data_default_size);
    tagged_data_size = std::clamp<size_t>(tagged_data_size, tagged_data_min_size, tagged_data_max_size);
    httpd->set_route_body_limit(tagged_data_endp, tagged_data_size);

    httpd->register_route("/logging/kismetdb/data/tags", {"GET", "POST"}, httpd->RO_ROLE, {"json"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return tagged_data_tags_endp_handler(con);
                }));

    httpd->register_route("/logging/kismetdb/data/records", {"GET", "POST"}, httpd->RO_ROLE, {"json"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return tagged_data_records_endp_handler(con);
                }));

    httpd->register_route("/logging/kismetdb/data/delete", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return tagged_data_delete_endp_handler(con);
                }));

    httpd->register_route("/poi/list_poi", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return list_poi_endp_handler(con);
                }));

    httpd->register_route("/logging/kismetdb/pcap/:title", {"GET", "POST"}, httpd->RO_ROLE, {"pcapng"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return pcapng_endp_handler(con);
                }));

    device_mac_filter =
        std::make_shared<class_filter_mac_addr>("kismetdb_devices",
                "Kismetdb device MAC filtering");
    packet_mac_filter =
        std::make_shared<packet_filter_mac_addr>("kismetdb_packets",
                "Kismetdb packet MAC filtering");

    auto device_filter_dfl =
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("kis_log_device_filter_default", "pass");

    if (device_filter_dfl == "pass" || device_filter_dfl == "false") {
        device_mac_filter->set_filter_default(false);
    } else if (device_filter_dfl == "block" || device_filter_dfl == "true") {
        device_mac_filter->set_filter_default(true);
    } else {
        _MSG_ERROR("Couldn't parse 'kis_log_device_filter_default', expected 'pass' or 'block', filter "
                "defaulting to 'pass'.");
    }

    auto device_filter_vec =
        Globalreg::globalreg->kismet_config->fetch_opt_vec("kis_log_device_filter");
    for (auto dfi : device_filter_vec) {
        // phy,mac,value
        auto filter_toks = str_tokenize(dfi, ",");

        if (filter_toks.size() != 3) {
            _MSG_ERROR("Skipping invalid kis_log_device_filter option '{}', expected phyname,mac,filtertype.", dfi);
            continue;
        }

        mac_addr m(filter_toks[1]);
        if (m.state.error) {
            _MSG_ERROR("Skipping invalid kis_log_device_filter option '{}', expected phyname,mac,filtertype "
                    "but got error parsing '{}' as a MAC address.", dfi, filter_toks[1]);
            continue;
        }

        bool filter_opt = false;
        if (filter_toks[2] == "pass" || filter_toks[2] == "false") {
            filter_opt = false;
        } else if (filter_toks[2] == "block" || filter_toks[2] == "true") {
            filter_opt = true;
        } else {
            _MSG_ERROR("Skipping invalid kis_log_device_filter option '{}', expected phyname,mac,filtertype "
                    "but got an error parsing '{}' as a filter block or pass.", dfi, filter_toks[2]);
            continue;
        }

        device_mac_filter->set_filter(m, filter_toks[0], filter_opt);
    }

    auto packet_filter_dfl =
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("kis_log_packet_filter_default", "pass");

    if (packet_filter_dfl == "pass" || packet_filter_dfl == "false") {
        packet_mac_filter->set_filter_default(false);
    } else if (packet_filter_dfl == "block" || packet_filter_dfl == "true") {
        packet_mac_filter->set_filter_default(true);
    } else {
        _MSG_ERROR("Couldn't parse 'kis_log_packet_filter_default', expected 'pass' or 'block', filter "
                "defaulting to 'pass'.");
    }

    auto packet_filter_vec =
        Globalreg::globalreg->kismet_config->fetch_opt_vec("kis_log_packet_filter");
    for (auto dfi : packet_filter_vec) {
        // phy,block,mac,value
        auto filter_toks = str_tokenize(dfi, ",");

        if (filter_toks.size() != 4) {
            _MSG_ERROR("Skipping invalid kis_log_packet_filter option '{}', expected phyname,filterblock,mac,filtertype.", dfi);
            continue;
        }

        mac_addr m(filter_toks[2]);
        if (m.state.error) {
            _MSG_ERROR("Skipping invalid kis_log_packet_filter option '{}', expected phyname,filterblock,mac,filtertype "
                    "but got error parsing '{}' as a MAC address.", dfi, filter_toks[2]);
            continue;
        }

        bool filter_opt = false;
        if (filter_toks[3] == "pass" || filter_toks[3] == "false") {
            filter_opt = false;
        } else if (filter_toks[3] == "block" || filter_toks[3] == "true") {
            filter_opt = true;
        } else {
            _MSG_ERROR("Skipping invalid kis_log_packet_filter option '{}', expected phyname,filterblock,mac,filtertype "
                    "but got an error parsing '{}' as a filter block or pass.", dfi, filter_toks[3]);
            continue;
        }

        packet_mac_filter->set_filter(m, filter_toks[0], filter_toks[1], filter_opt);
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_messages", true)) {
        message_evt_id =
            eventbus->register_listener(message_bus::event_message(),
                    [this](std::shared_ptr<eventbus_event> evt) {

                    auto msg_k = evt->get_event_content()->find(message_bus::event_message());
                    if (msg_k == evt->get_event_content()->end())
                        return;

                    auto msg = std::static_pointer_cast<tracked_message>(msg_k->second);

                    handle_message(msg);
                    });
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_alerts", true)) {
        alert_evt_id =
            eventbus->register_listener(alert_tracker::alert_event(),
                    [this](std::shared_ptr<eventbus_event> evt) {

                    auto msg_k = evt->get_event_content()->find(alert_tracker::alert_event());
                    if (msg_k == evt->get_event_content()->end())
                        return;

                    auto al = std::static_pointer_cast<tracked_alert>(msg_k->second);

                    handle_alert(al);
                    });
    }

    // Post that we've got the logfile ready
    auto evt = eventbus->get_eventbus_event(event_log_open());
    eventbus->publish(evt);

    set_int_log_open(true);
    db_enabled = true;

    // lk.unlock();

    // Register the log after we have all the filters set and the mutex unlocked
    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_packets", true)) {
        _MSG("Saving packets to the Kismet database log.", MSGFLAG_INFO);
        std::shared_ptr<packet_chain> packetchain =
            Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");

        // auto this_ref = shared_from_this();
        packet_handler_id =
            packetchain->register_handler([](void *auxdata, const std::shared_ptr<kis_packet>& packet) -> int {
					auto dbl = reinterpret_cast<kis_database_logfile *>(auxdata);
                    return dbl->log_packet(packet.get());
                }, this, CHAINPOS_LOGGING, -100);
    } else {
        packet_handler_id = -1;
        _MSG_INFO("Packets will not be saved to the Kismet database log.");
    }

    return true;
}

void kis_database_logfile::close_log() {
    // Stop new writers first, so a busy packet stream can't starve the close below
    db_enabled = false;

    // Called from a writer (an error path) holding the lifetime lock; waiting for the
    // writers in flight would wait on ourselves, the writer's guard finishes the close
    if (current_writer == this) {
        close_pending = true;
        return;
    }

    // Kill the timers
    auto timetracker =
        Globalreg::fetch_global_as<time_tracker>();

    if (timetracker != NULL) {
        timetracker->remove_timer(transaction_timer);
        timetracker->remove_timer(packet_timeout_timer);
        timetracker->remove_timer(alert_timeout_timer);
        timetracker->remove_timer(device_timeout_timer);
        timetracker->remove_timer(message_timeout_timer);
        timetracker->remove_timer(snapshot_timeout_timer);
    }

    // Kill the eventbus subs
    eventbus->remove_listener(message_evt_id);
    eventbus->remove_listener(alert_evt_id);

    // Kill the hooks
    auto packetchain =
        Globalreg::fetch_global_as<packet_chain>();

    if (packetchain != NULL && packet_handler_id >= 0)
        packetchain->remove_handler(packet_handler_id, CHAINPOS_LOGGING);

    // Wait for anything still using the database, then close it
    std::unique_lock<std::shared_mutex> lifetime_lk(db_lifetime_mutex);

    set_int_log_open(false);

    finalize_cached();

    // Already closed
    if (db == nullptr)
        return;

    // End the transaction
    sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);

    sqlite3_exec(db, "PRAGMA journal_mode=DELETE", NULL, NULL, NULL);
    sqlite3_exec(db, "BEGIN_EXCLUSIVE", NULL, NULL, NULL);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

    database_close();
}

// Packets nearly always come from the same few sources, so keep the last formatted uuid
static std::string cached_uuid_string(const uuid& u) {
    static thread_local uuid last_uuid;
    static thread_local std::string last_str;

    if (last_str.empty() || !(last_uuid == u)) {
        last_uuid = u;
        last_str = u.uuid_to_string();
    }

    return last_str;
}

// Prepare a cached insert on first use; the caller holds the statement's mutex and a
// writer guard, so the database can't close underneath it.  On failure the error is
// returned for the caller to report once it has released the mutex.
sqlite3_stmt *kis_database_logfile::prepare_cached(sqlite3_stmt *& stmt, const char *sql,
        std::string& err) {
    if (stmt != nullptr)
        return stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        err = sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        stmt = nullptr;
    }

    return stmt;
}

// Called with the lifetime lock held exclusively, so no writer is using the statements
void kis_database_logfile::finalize_cached() {
    kis_lock_guard<kis_mutex> plk(packet_stmt_mutex, "kismetdb finalize packet");
    kis_lock_guard<kis_mutex> dlk(data_stmt_mutex, "kismetdb finalize data");

    sqlite3_finalize(packet_stmt);
    packet_stmt = nullptr;
    sqlite3_finalize(data_stmt);
    data_stmt = nullptr;
}

// Bind text or a blob with its full length; sqlite rejects anything over its length limit
// (SQLITE_TOOBIG) instead of the length being truncated to an int
static bool bind_text_checked(sqlite3_stmt *stmt, int pos, std::string_view s,
        sqlite3_destructor_type d) {
    return sqlite3_bind_text64(stmt, pos, s.data(), s.size(), d, SQLITE_UTF8) == SQLITE_OK;
}

static bool bind_blob_checked(sqlite3_stmt *stmt, int pos, std::string_view s,
        sqlite3_destructor_type d) {
    return sqlite3_bind_blob64(stmt, pos, s.data(), s.size(), d) == SQLITE_OK;
}

// Bind a gps record's position, or zeros if there's no usable one
static void bind_gps(sqlite3_stmt *stmt, int& pos, const kis_gps_packinfo *gps) {
    bool ok = gps != nullptr && gps->gps_info_ok;
    sqlite3_bind_double(stmt, pos++, ok ? gps->lat : 0);
    sqlite3_bind_double(stmt, pos++, ok ? gps->lon : 0);
    sqlite3_bind_double(stmt, pos++, ok ? gps->alt : 0);
    sqlite3_bind_double(stmt, pos++, ok ? gps->speed : 0);
    sqlite3_bind_double(stmt, pos++, ok ? gps->heading : 0);
}

int kis_database_logfile::database_upgrade_db() {
    // kis_lock_guard<kis_mutex> lk(ds_mutex, "kismetdb upgrade_db");

    std::string sql;
    int r;
    char *sErrMsg = NULL;

    if (db == NULL)
        return 0;

    sql =
        "CREATE TABLE devices ("

        "first_time INT, " // Time seen
        "last_time INT, "

        "devkey TEXT, " // Device key

        "phyname TEXT, " // Phy records
        "devmac TEXT, "

        "strongest_signal INT, " // Strongest signal

        "min_lat REAL, " // locational bounding rectangle
        "min_lon REAL, "
        "max_lat REAL, "
        "max_lon REAL, "

        "avg_lat REAL, " // Average location
        "avg_lon REAL, "

        "reported_min_lat REAL, " // Bounds and average of the location the device reports
        "reported_min_lon REAL, " // for itself (adsb, ais, remote id...), 0 if it doesn't
        "reported_max_lat REAL, "
        "reported_max_lon REAL, "
        "reported_avg_lat REAL, "
        "reported_avg_lon REAL, "

        "bytes_data INT, " // Amount of data seen on device

        "type TEXT, " // PHY specific type

        "device BLOB, " // Actual device

        "UNIQUE(phyname, devmac) ON CONFLICT REPLACE)";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Kismet log was unable to create devices table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sql =
        "CREATE TABLE packets ("

        "ts_sec INT, " // Timestamps
        "ts_usec INT, "

        "phyname TEXT, " // Packet phy

        "sourcemac TEXT, " // Source, dest, and network addresses
        "destmac TEXT, "
        "transmac TEXT, "

        "frequency REAL, " // Freq in khz

        "devkey TEXT, " // Device key

        "lat REAL, " // location of kismet when the packet was seen
        "lon REAL, "
        "alt REAL, "
        "speed REAL, "
        "heading REAL, "

        "reported_lat REAL, " // location the device reported in the packet, 0 if none
        "reported_lon REAL, "
        "reported_alt REAL, "
        "reported_speed REAL, "
        "reported_heading REAL, "

        "packet_len INT, " // Packet length

        "signal INT, " // Signal level

        "datasource TEXT, " // UUID of data source

        "dlt INT, " // pcap data - datalinktype and packet bin
        "packet BLOB, "

        "error INT, " // Packet was flagged as invalid

        "tags TEXT, "  // Arbitrary packet tags

        "datarate REAL, " // datarate, if known

        "hash INT, " // crc32 hash
        "packetid INT, " // packet id (shared with duplicate packets)

        "packet_full_len INT" // original full length
        ")";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Kismet log was unable to create packet table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sql =
        "CREATE TABLE data ("

        "ts_sec INT, " // Timestamps
        "ts_usec INT, "

        "phyname TEXT, " // Packet name and phy
        "devmac TEXT, "

        "lat REAL, " // Location of kismet
        "lon REAL, "
        "alt REAL, "
        "speed REAL, "
        "heading REAL, "

        "reported_lat REAL, " // Location the device reported, 0 if none
        "reported_lon REAL, "
        "reported_alt REAL, "
        "reported_speed REAL, "
        "reported_heading REAL, "

        "datasource TEXT, " // UUID of data source

        "type TEXT, " // Type of arbitrary record

        "json BLOB, " // Arbitrary JSON record

        "signal INT " // signal
        ")";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Kismet log was unable to create data table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sql =
        "CREATE TABLE datasources ("

        "uuid TEXT, " // Unique ID

        "typestring TEXT, " // Normalized records
        "definition TEXT, "
        "name TEXT, "
        "interface TEXT, "

        "json BLOB, " // Full device dump

        "UNIQUE(uuid) ON CONFLICT REPLACE)";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Kismet log was unable to create datasource table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sql =
        "CREATE TABLE alerts ("

        "ts_sec INT, " // Timestamps
        "ts_usec INT, "

        "phyname TEXT, " // Alert phy
        "devmac TEXT, " // Primary device associated with alert

        "lat REAL, " // Location
        "lon REAL, "

        "header TEXT, " // Alert header/type

        "json BLOB " // Alert JSON record
        ")";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Kismet log was unable to create alerts table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sql =
        "CREATE TABLE messages ("

        "ts_sec INT, " // Timestamps

        "lat REAL, " // Location
        "lon REAL, "

        "msgtype TEXT, " // Message type

        "message TEXT " // message

        ")";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Kismet log was unable to create messages table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sql =
        "CREATE TABLE snapshots ("

        "ts_sec INT, " // Timestamps
        "ts_usec INT, "

        "lat REAL, " // Location
        "lon REAL, "

        "snaptype TEXT, " // Type of snapshot record

        "json BLOB " // Arbitrary record

        ")";

    r = sqlite3_exec(db, sql.c_str(),
            [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

    if (r != SQLITE_OK) {
        _MSG("Kismet log was unable to create messages table in " + ds_dbfile + ": " +
                std::string(sErrMsg), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    database_set_db_version(KISMETDB_LOG_VERSION);

    return 1;
}

void kis_database_logfile::handle_alert(std::shared_ptr<tracked_alert> alert) {
    log_alert(alert);
}

void kis_database_logfile::handle_message(std::shared_ptr<tracked_message> msg) {
    if (!db_enabled)
        return;

    db_writer_guard writer_lk(this);
    if (!db_enabled)
        return;

    int r;
    std::string sql;
    sqlite3_stmt *msg_stmt;
    const char *msg_pz;

    std::shared_ptr<kis_gps_packinfo> loc;

    if (gpstracker != nullptr)
        loc = gpstracker->get_best_location();

    sql =
        "INSERT INTO messages "
        "(ts_sec, "
        "lat, lon, "
        "msgtype, message) "
        "VALUES (?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &msg_stmt, &msg_pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database_logfile unable to prepare database insert for messages in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return;
    }

    unsigned int spos = 1;

    sqlite3_bind_int64(msg_stmt, spos++, time(0));

    if (loc != nullptr && loc->fix >= 2) {
        sqlite3_bind_double(msg_stmt, spos++, loc->lat);
        sqlite3_bind_double(msg_stmt, spos++, loc->lon);
    } else {
        sqlite3_bind_double(msg_stmt, spos++, 0);
        sqlite3_bind_double(msg_stmt, spos++, 0);
    }

    std::string msgtype;

    if (msg->get_flags() & MSGFLAG_INFO)
        msgtype = "INFO";
    else if (msg->get_flags() & MSGFLAG_ERROR)
        msgtype = "ERROR";
    else if (msg->get_flags() & MSGFLAG_DEBUG)
        msgtype = "DEBUG";
    else if (msg->get_flags() & MSGFLAG_FATAL)
        msgtype = "FATAL";

    sqlite3_bind_text(msg_stmt, spos++, msgtype.c_str(), msgtype.length(), SQLITE_TRANSIENT);

    // Reporting an oversized message would come straight back here, so it's dropped
    if (!bind_text_checked(msg_stmt, spos++, msg->get_message(), SQLITE_TRANSIENT)) {
        sqlite3_finalize(msg_stmt);
        return;
    }

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb handle_message");
    db_lock_with_sync_check(dblock, return);
#endif

    r = sqlite3_step(msg_stmt);

    // An oversized message is dropped, as above
    if (r != SQLITE_DONE && r != SQLITE_TOOBIG) {
        close_log();
        _MSG_ERROR("Unable to insert message into {}: {}", ds_dbfile, sqlite3_errmsg(db));
    }

    sqlite3_finalize(msg_stmt);
}

int kis_database_logfile::log_device(const std::shared_ptr<kis_tracked_device_base>& d) {
    if (!db_enabled)
        return 0;

    db_writer_guard writer_lk(this);
    if (!db_enabled)
        return 0;

    std::string sql;

    std::string phystring;
    std::string macstring;
    std::string typestring;
    std::string keystring;

    if (d == nullptr)
        return 0;

    if (device_mac_filter->filter(d->get_macaddr(), d->get_phyid()))
        return 0;

    phystring = d->get_phyname();
    macstring = d->get_macaddr().mac_to_string();
    typestring = d->get_type_string();
    keystring = d->get_key().as_string();

    int spos = 1;

    std::stringstream sstr;

    // We don't have to lock because we're called by a device worker, which locks

#if 0
    {
        kis_lock_guard<kis_mutex> lg_dl(devicetracker->get_devicelist_mutex(), "database_logfile::log_device");
        int r = Globalreg::globalreg->entrytracker->serialize("json", sstr, d, nullptr);

        if (r < 0) {
            _MSG_ERROR("Failure serializing device key {} to the kisdatabaselog", d->get_key());
            return 0;
        }
    }
#endif

    int r = Globalreg::globalreg->entrytracker->serialize("json", sstr, d, nullptr);

    if (r < 0) {
        _MSG_ERROR("Failure serializing device key {} to the kisdatabaselog", d->get_key());
        return 0;
    }

    std::string streamstring = sstr.str();

    sqlite3_stmt *device_stmt;
    const char *device_pz;

    sql =
        "INSERT INTO devices "
        "(first_time, last_time, devkey, phyname, devmac, strongest_signal, "
        "min_lat, min_lon, max_lat, max_lon, "
        "avg_lat, avg_lon, "
        "reported_min_lat, reported_min_lon, reported_max_lat, reported_max_lon, "
        "reported_avg_lat, reported_avg_lon, "
        "bytes_data, type, device) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &device_stmt, &device_pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database_logfile unable to prepare database insert for devices in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_bind_int64(device_stmt, spos++, d->get_first_time());
    sqlite3_bind_int64(device_stmt, spos++, d->get_last_time());
    sqlite3_bind_text(device_stmt, spos++, keystring.c_str(),
            keystring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(device_stmt, spos++, phystring.c_str(),
            phystring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(device_stmt, spos++, macstring.c_str(),
            macstring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_int(device_stmt, spos++, d->get_signal_data()->get_max_signal());

    // Bounds and average of a location set, or zeros if there isn't one
    auto bind_location = [&device_stmt, &spos](const std::shared_ptr<kis_tracked_location>& loc) {
        if (loc != nullptr && loc->has_min_loc() && loc->has_max_loc() && loc->has_avg_loc()) {
            sqlite3_bind_double(device_stmt, spos++, loc->get_min_loc()->get_lat());
            sqlite3_bind_double(device_stmt, spos++, loc->get_min_loc()->get_lon());
            sqlite3_bind_double(device_stmt, spos++, loc->get_max_loc()->get_lat());
            sqlite3_bind_double(device_stmt, spos++, loc->get_max_loc()->get_lon());
            sqlite3_bind_double(device_stmt, spos++, loc->get_avg_loc()->get_lat());
            sqlite3_bind_double(device_stmt, spos++, loc->get_avg_loc()->get_lon());
        } else {
            for (int i = 0; i < 6; i++)
                sqlite3_bind_double(device_stmt, spos++, 0);
        }
    };

    // Where kismet heard the device, then where the device says it is
    bind_location(d->has_location() ? d->get_location() : nullptr);
    bind_location(d->has_reported_location() ? d->get_reported_location() : nullptr);

    sqlite3_bind_int64(device_stmt, spos++, d->get_datasize());
    sqlite3_bind_text(device_stmt, spos++, typestring.c_str(),
            typestring.length(), SQLITE_TRANSIENT);

    if (!bind_blob_checked(device_stmt, spos++, streamstring, SQLITE_TRANSIENT)) {
        sqlite3_finalize(device_stmt);
        _MSG_ERROR("kis_database_logfile skipping device {}, its {} byte record is too large "
                "for the database", macstring, streamstring.length());
        return 0;
    }

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_device");
    db_lock_with_sync_check(dblock, return);
#endif

    auto step_r = sqlite3_step(device_stmt);

    if (step_r == SQLITE_TOOBIG) {
        sqlite3_finalize(device_stmt);
        _MSG_ERROR("kis_database_logfile skipping device {}, its {} byte record is too large for the database", macstring, streamstring.length());
        return 0;
    }

    if (step_r != SQLITE_DONE) {
        _MSG("kis_database_logfile unable to insert device in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_finalize(device_stmt);

    return 1;
}

int kis_database_logfile::log_packet(const kis_packet* in_pack) {
    if (!db_enabled) {
        return 0;
    }

    db_writer_guard writer_lk(this);
    if (!db_enabled)
        return 0;

    std::string phystring;
    std::string macstring;
    std::string deststring;
    std::string transstring;
    std::string keystring;
    std::string sourceuuidstring;
    double frequency;

    if (in_pack->duplicate && !log_duplicate_packets)
        return 0;

    if (in_pack->filtered)
        return 0;

    if (packet_mac_filter->filter_packet(in_pack)) {
        return 0;
    }

    auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_linkframe);
    auto datasrc = in_pack->fetch<packetchain_comp_datasource>(pack_comp_datasource);
    auto metablob = in_pack->fetch<packet_metablob>(pack_comp_metablob);
    auto jsonblob = in_pack->fetch<kis_json_packinfo>(pack_comp_json);

    kis_phy_handler *phyh = NULL;

    // Packets are no longer a 1:1 with a device
    keystring = "0";

    if (in_pack->common_info.common_info_ok) {
        if (in_pack->common_info.type == packet_basic_data && !log_data_packets)
            return 0;

        phyh = devicetracker->fetch_phy_handler(in_pack->common_info.phyid);
        macstring = in_pack->common_info.source.mac_to_string();
        deststring = in_pack->common_info.dest.mac_to_string();
        transstring = in_pack->common_info.transmitter.mac_to_string();
        frequency = in_pack->common_info.freq_khz;
    } else {
        macstring = "00:00:00:00:00:00";
        deststring = "00:00:00:00:00:00";
        transstring = "00:00:00:00:00:00";
        frequency = 0;
    }

    if (phyh == NULL)
        phystring = "Unknown";
    else
        phystring = phyh->fetch_phy_name();


    if (datasrc != NULL) {
        sourceuuidstring = cached_uuid_string(datasrc->ref_source->get_source_uuid());
    } else {
        sourceuuidstring = "00000000-0000-0000-0000-000000000000";
    }

    // Log into the PACKET table if we're a loggable packet (ie, have a link frame)
    if (chunk != nullptr) {
        std::string tagstr;

        for (const auto& tag : in_pack->tag_map) {
            if (!tagstr.empty())
                tagstr += ' ';
            tagstr += tag.first;
        }

        std::string err;
        kis_unique_lock<kis_mutex> stmt_lk(packet_stmt_mutex, "kismetdb log_packet");

        auto stmt = prepare_cached(packet_stmt,
            "INSERT INTO packets "
            "(ts_sec, ts_usec, phyname, "
            "sourcemac, destmac, transmac, devkey, frequency, "
            "lat, lon, alt, speed, heading, "
            "reported_lat, reported_lon, reported_alt, reported_speed, reported_heading, "
            "packet_len, packet_full_len, signal, "
            "datasource, "
            "dlt, packet, "
            "error, tags, datarate, hash, packetid) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            err);

        if (stmt == nullptr) {
            stmt_lk.unlock();
            _MSG_ERROR("kis_database_logfile unable to prepare database insert for packets "
                    "in {}: {}", ds_dbfile, err);
            close_log();
            return -1;
        }

        // Every parameter is bound on every insert, and the bound buffers outlive the
        // step, so they don't need to be copied
        int sql_pos = 1;

        sqlite3_bind_int64(stmt, sql_pos++, in_pack->ts.tv_sec);
        sqlite3_bind_int64(stmt, sql_pos++, in_pack->ts.tv_usec);

        sqlite3_bind_text(stmt, sql_pos++, phystring.c_str(), phystring.length(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, sql_pos++, macstring.c_str(), macstring.length(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, sql_pos++, deststring.c_str(), deststring.length(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, sql_pos++, transstring.c_str(), transstring.length(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, sql_pos++, keystring.c_str(), keystring.length(), SQLITE_STATIC);
        sqlite3_bind_double(stmt, sql_pos++, frequency);

        // Where kismet was, then where the device said it was
        bind_gps(stmt, sql_pos, &in_pack->gps_info);
        bind_gps(stmt, sql_pos, &in_pack->reported_gps);

        sqlite3_bind_int64(stmt, sql_pos++, chunk->length());
        sqlite3_bind_int64(stmt, sql_pos++, in_pack->original_len);

        if (in_pack->signal_info.data_ok) {
            sqlite3_bind_int(stmt, sql_pos++, in_pack->signal_info.signal_dbm);
        } else {
            sqlite3_bind_int(stmt, sql_pos++, 0);
        }

        sqlite3_bind_text(stmt, sql_pos++, sourceuuidstring.c_str(),
                sourceuuidstring.length(), SQLITE_STATIC);

        sqlite3_bind_int(stmt, sql_pos++, chunk->dlt);
        if (!bind_blob_checked(stmt, sql_pos++, *chunk, SQLITE_STATIC)) {
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
            stmt_lk.unlock();
            _MSG_ERROR("kis_database_logfile skipping a {} byte packet, too large for the "
                    "database", chunk->length());
            return 0;
        }

        sqlite3_bind_int(stmt, sql_pos++, in_pack->error);

        sqlite3_bind_text(stmt, sql_pos++, tagstr.c_str(), tagstr.length(), SQLITE_STATIC);

        if (in_pack->signal_info.data_ok)
            sqlite3_bind_double(stmt, sql_pos++, in_pack->signal_info.datarate / 10);
        else
            sqlite3_bind_double(stmt, sql_pos++, 0);

        sqlite3_bind_int(stmt, sql_pos++, in_pack->hash);
        sqlite3_bind_int64(stmt, sql_pos++, in_pack->packet_no);

        auto r = sqlite3_step(stmt);

        if (r != SQLITE_DONE)
            err = sqlite3_errmsg(db);

        // Drop the references to our buffers before they go away
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);

        stmt_lk.unlock();

        if (r == SQLITE_TOOBIG) {
            _MSG_ERROR("kis_database_logfile skipping a {} byte packet, too large for the "
                    "database", chunk->length());
            return 0;
        } else if (r != SQLITE_DONE) {
            _MSG_ERROR("kis_database_logfile unable to insert packet in {}: {}",
                    ds_dbfile, err);
            close_log();
            return -1;
        }
    }

    // If the packet has a metablob record, log that; if the packet ONLY has meta data we should only get a 'data'
    // record; if the packet has both, we'll get both a 'packet' and a 'data' record.
    if (metablob != nullptr) {
        mac_addr smac("00:00:00:00:00:00");
        uuid puuid;

        if (in_pack->common_info.common_info_ok)
            smac = in_pack->common_info.source;

        if (datasrc != nullptr)
            puuid = datasrc->ref_source->get_source_uuid();

        log_data(&in_pack->gps_info, &in_pack->signal_info, in_pack->ts, phystring, smac, puuid,
                metablob->meta_type, metablob->meta_data, &in_pack->reported_gps);
    } else if (jsonblob != nullptr) {
        mac_addr smac("00:00:00:00:00:00");
        uuid puuid;

        if (in_pack->common_info.common_info_ok)
            smac = in_pack->common_info.source;

        if (datasrc != nullptr)
            puuid = datasrc->ref_source->get_source_uuid();

        log_data(&in_pack->gps_info, &in_pack->signal_info, in_pack->ts, phystring, smac, puuid,
                jsonblob->type, jsonblob->json_string, &in_pack->reported_gps);
    }

    return 1;
}

int kis_database_logfile::log_data(const kis_gps_packinfo* gps,
        const kis_layer1_packinfo *l1info,
        const struct timeval& tv, const std::string& phystring, const mac_addr& devmac,
        const uuid& datasource_uuid, const std::string& type, const std::string& json,
        const kis_gps_packinfo *reported_gps) {

    if (!db_enabled)
        return 0;

    db_writer_guard writer_lk(this);
    if (!db_enabled)
        return 0;

    std::string macstring = devmac.mac_to_string();
    std::string uuidstring = cached_uuid_string(datasource_uuid);

    std::string err;
    kis_unique_lock<kis_mutex> stmt_lk(data_stmt_mutex, "kismetdb log_data");

    auto stmt = prepare_cached(data_stmt,
        "INSERT INTO data "
        "(ts_sec, ts_usec, "
        "phyname, devmac, "
        "lat, lon, alt, speed, heading, "
        "reported_lat, reported_lon, reported_alt, reported_speed, reported_heading, "
        "datasource, "
        "type, json, signal) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        err);

    if (stmt == nullptr) {
        stmt_lk.unlock();
        _MSG_ERROR("kis_database_logfile unable to prepare database insert for data "
                "in {}: {}", ds_dbfile, err);
        close_log();
        return -1;
    }

    int sql_pos = 1;

    sqlite3_bind_int64(stmt, sql_pos++, tv.tv_sec);
    sqlite3_bind_int64(stmt, sql_pos++, tv.tv_usec);

    sqlite3_bind_text(stmt, sql_pos++, phystring.c_str(), phystring.length(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, sql_pos++, macstring.c_str(), macstring.length(), SQLITE_STATIC);

    bind_gps(stmt, sql_pos, gps);
    bind_gps(stmt, sql_pos, reported_gps);

    sqlite3_bind_text(stmt, sql_pos++, uuidstring.c_str(), uuidstring.length(), SQLITE_STATIC);

    if (!bind_text_checked(stmt, sql_pos++, type, SQLITE_STATIC) ||
            !bind_text_checked(stmt, sql_pos++, json, SQLITE_STATIC)) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        stmt_lk.unlock();
        _MSG_ERROR("kis_database_logfile skipping a {} byte data record, too large for the "
                "database", type.length() + json.length());
        return 0;
    }

    if (l1info != nullptr && l1info->data_ok) {
        sqlite3_bind_int(stmt, sql_pos++, l1info->signal_dbm);
    } else {
        sqlite3_bind_int(stmt, sql_pos++, 0);
    }

    auto r = sqlite3_step(stmt);

    if (r != SQLITE_DONE)
        err = sqlite3_errmsg(db);

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    stmt_lk.unlock();

    if (r == SQLITE_TOOBIG) {
        _MSG_ERROR("kis_database_logfile skipping a {} byte data record, too large for the "
                "database", type.length() + json.length());
        return 0;
    } else if (r != SQLITE_DONE) {
        _MSG_ERROR("kis_database_logfile unable to insert data in {}: {}", ds_dbfile, err);
        close_log();
        return -1;
    }

    return 1;
}

int kis_database_logfile::log_datasources(const shared_tracker_element& in_datasource_vec) {
    int r;

    if (!db_enabled)
        return 0;

    for (const auto& ds : *(std::static_pointer_cast<tracker_element_vector>(in_datasource_vec))) {
        r = log_datasource(ds);

        if (r < 0)
            return r;
    }

    return 1;
}

int kis_database_logfile::log_datasource(const shared_tracker_element& in_datasource) {
    if (!db_enabled)
        return 0;

    db_writer_guard writer_lk(this);
    if (!db_enabled)
        return 0;

    std::shared_ptr<kis_datasource> ds =
        std::static_pointer_cast<kis_datasource>(in_datasource);

    std::string uuidstring = ds->get_source_uuid().uuid_to_string();
    std::string typestring = ds->get_source_builder()->get_source_type();
    std::string defstring = ds->get_source_definition_redacted();
    std::string namestring = ds->get_source_name();
    std::string intfstring = ds->get_source_interface();

    std::stringstream ss;
    std::string jsonstring;

    json_adapter::pack(ss, in_datasource, NULL);
    jsonstring = ss.str();

    int r;
    std::string sql;
    sqlite3_stmt *datasource_stmt;
    const char *datasource_pz;

    sql =
        "INSERT INTO datasources "
        "(uuid, "
        "typestring, definition, "
        "name, interface, "
        "json) "
        "VALUES (?, ?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &datasource_stmt, &datasource_pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database_logfile unable to prepare database insert for datasources in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_bind_text(datasource_stmt, 1, uuidstring.data(), uuidstring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(datasource_stmt, 2, typestring.data(), typestring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(datasource_stmt, 3, defstring.data(), defstring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(datasource_stmt, 4, namestring.data(), namestring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(datasource_stmt, 5, intfstring.data(), intfstring.length(), SQLITE_TRANSIENT);

    if (!bind_blob_checked(datasource_stmt, 6, jsonstring, SQLITE_TRANSIENT)) {
        sqlite3_finalize(datasource_stmt);
        _MSG_ERROR("kis_database_logfile skipping datasource {}, its {} byte record is too "
                "large for the database", uuidstring, jsonstring.length());
        return 0;
    }

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_datasource");
    db_lock_with_sync_check(dblock, return -1);
#endif

    auto step_r = sqlite3_step(datasource_stmt);

    if (step_r == SQLITE_TOOBIG) {
        sqlite3_finalize(datasource_stmt);
        _MSG_ERROR("kis_database_logfile skipping datasource {}, its {} byte record is too large for the database", uuidstring, jsonstring.length());
        return 0;
    }

    if (step_r != SQLITE_DONE) {
        _MSG("kis_database_logfile unable to insert datasource in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_finalize(datasource_stmt);

    return 1;
}

int kis_database_logfile::log_alert(const std::shared_ptr<tracked_alert>& in_alert) {
    if (!db_enabled)
        return 0;

    db_writer_guard writer_lk(this);
    if (!db_enabled)
        return 0;

    std::string macstring = in_alert->get_transmitter_mac().mac_to_string();
    std::string phystring = devicetracker->fetch_phy_name(in_alert->get_phy());
    std::string headerstring = in_alert->get_header();

    std::stringstream ss;
    std::string jsonstring;

    json_adapter::pack(ss, in_alert, NULL);
    jsonstring = ss.str();

    // Break the double timestamp into two integers
    double intpart, fractpart;
    fractpart = modf(in_alert->get_timestamp(), &intpart);

    int r;
    std::string sql;
    sqlite3_stmt *alert_stmt;
    const char *alert_pz;

    sql =
        "INSERT INTO alerts "
        "(ts_sec, ts_usec, phyname, devmac, "
        "lat, lon, "
        "header, "
        "json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &alert_stmt, &alert_pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database_logfile unable to prepare database insert for alerts in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_bind_int64(alert_stmt, 1, intpart);
    sqlite3_bind_int64(alert_stmt, 2, fractpart * 1000000);

    sqlite3_bind_text(alert_stmt, 3, phystring.c_str(), phystring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(alert_stmt, 4, macstring.c_str(), macstring.length(), SQLITE_TRANSIENT);

    if (in_alert->get_location()->get_valid()) {
        sqlite3_bind_double(alert_stmt, 5, in_alert->get_location()->get_lat());
        sqlite3_bind_double(alert_stmt, 6, in_alert->get_location()->get_lon());
    } else {
        sqlite3_bind_int(alert_stmt, 5, 0);
        sqlite3_bind_int(alert_stmt, 6, 0);
    }

    if (!bind_text_checked(alert_stmt, 7, headerstring, SQLITE_TRANSIENT) ||
            !bind_blob_checked(alert_stmt, 8, jsonstring, SQLITE_TRANSIENT)) {
        sqlite3_finalize(alert_stmt);
        _MSG_ERROR("kis_database_logfile skipping a {} byte alert, too large for the database",
                jsonstring.length());
        return 0;
    }

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_alert");
    db_lock_with_sync_check(dblock, return -1);
#endif

    auto step_r = sqlite3_step(alert_stmt);

    if (step_r == SQLITE_TOOBIG) {
        sqlite3_finalize(alert_stmt);
        _MSG_ERROR("kis_database_logfile skipping a {} byte alert, too large for the database", jsonstring.length());
        return 0;
    }

    if (step_r != SQLITE_DONE) {
        _MSG("kis_database_logfile unable to insert alert in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_finalize(alert_stmt);

    return 1;
}

int kis_database_logfile::log_snapshot(const std::shared_ptr<kis_gps_packinfo>& gps, struct timeval tv,
        const std::string& snaptype, const std::string& json) {

    if (!db_enabled)
        return 0;

    db_writer_guard writer_lk(this);
    if (!db_enabled)
        return 0;

    int r;
    std::string sql;
    sqlite3_stmt *snapshot_stmt;
    const char *snapshot_pz;

    std::shared_ptr<kis_gps_packinfo> loc;

    if (gps == nullptr && gpstracker != nullptr)
        loc = gpstracker->get_best_location();

    sql =
        "INSERT INTO snapshots "
        "(ts_sec, ts_usec, "
        "lat, lon, "
        "snaptype, json) "
        "VALUES (?, ?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &snapshot_stmt, &snapshot_pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database_logfile unable to prepare database insert for snapshots in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_bind_int64(snapshot_stmt, 1, tv.tv_sec);
    sqlite3_bind_int64(snapshot_stmt, 2, tv.tv_usec);

    if (gps != NULL) {
        sqlite3_bind_double(snapshot_stmt, 3, gps->lat);
        sqlite3_bind_double(snapshot_stmt, 4, gps->lon);
    } else {
        if (loc != nullptr && loc->fix >= 2) {
            sqlite3_bind_double(snapshot_stmt, 3, loc->lat);
            sqlite3_bind_double(snapshot_stmt, 4, loc->lon);
        } else {
            sqlite3_bind_int(snapshot_stmt, 3, 0);
            sqlite3_bind_int(snapshot_stmt, 4, 0);
        }
    }

    if (!bind_text_checked(snapshot_stmt, 5, snaptype, SQLITE_TRANSIENT) ||
            !bind_text_checked(snapshot_stmt, 6, json, SQLITE_TRANSIENT)) {
        sqlite3_finalize(snapshot_stmt);
        _MSG_ERROR("kis_database_logfile skipping a {} byte snapshot, too large for the "
                "database", snaptype.length() + json.length());
        return 0;
    }

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_snapshot");
    db_lock_with_sync_check(dblock, return -1);
#endif

    auto step_r = sqlite3_step(snapshot_stmt);

    if (step_r == SQLITE_TOOBIG) {
        sqlite3_finalize(snapshot_stmt);
        _MSG_ERROR("kis_database_logfile skipping a {} byte snapshot, too large for the database", snaptype.length() + json.length());
        return 0;
    }

    if (step_r != SQLITE_DONE) {
        _MSG("kis_database_logfile unable to insert snapshot in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_finalize(snapshot_stmt);

    return 1;
}


void kis_database_logfile::usage(const char *argv0) {

}


void kis_database_logfile::pcapng_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
	using namespace kissqlite3;

	// Hold the database open for the whole stream; a close waits for it
	db_writer_guard writer_lk(this);
	if (!db_enabled) {
		std::ostream ostream(&con->response_stream());
		con->set_status(400);
		ostream << "Illegal request: kismetdb log not enabled\n";
		return;
	}

	auto query = _SELECT(db, "packets", {"ts_sec", "ts_usec", "datasource", "dlt", "packet"});

	auto ts_start_k = con->http_variables().find("timestamp_start");
	if (ts_start_k != con->http_variables().end())
		query.append_where(AND, _WHERE("ts_sec", GE, string_to_n<uint64_t>(ts_start_k->second)));

	auto ts_end_k = con->http_variables().find("timestamp_end");
	if (ts_end_k != con->http_variables().end())
		query.append_where(AND, _WHERE("ts_sec", LE, string_to_n<uint64_t>(ts_end_k->second)));

	auto datasource_k = con->http_variables().find("datasource");
	if (datasource_k != con->http_variables().end())
		query.append_where(AND, _WHERE("datasource", LIKE, datasource_k->second));

	auto deviceid_k = con->http_variables().find("device_id");
	if (deviceid_k != con->http_variables().end())
		query.append_where(AND, _WHERE("devkey", LIKE, deviceid_k->second));

	auto dlt_k = con->http_variables().find("dlt");
	if (dlt_k != con->http_variables().end())
		query.append_where(AND, _WHERE("dlt", EQ, string_to_n<unsigned int>(dlt_k->second)));

	auto frequency_k = con->http_variables().find("frequency");
	if (frequency_k != con->http_variables().end())
		query.append_where(AND, _WHERE("frequency", EQ, string_to_n<unsigned int>(frequency_k->second)));

	auto frequency_min_k = con->http_variables().find("frequency_min");
	if (frequency_min_k != con->http_variables().end())
		query.append_where(AND, _WHERE("frequency", GE, string_to_n<unsigned int>(frequency_min_k->second)));

	auto frequency_max_k = con->http_variables().find("frequency_max");
	if (frequency_max_k != con->http_variables().end())
		query.append_where(AND, _WHERE("frequency", LE, string_to_n<unsigned int>(frequency_max_k->second)));

	auto signal_min_k = con->http_variables().find("signal_min");
	if (signal_min_k != con->http_variables().end())
		query.append_where(AND, _WHERE("signal", GE, string_to_n<int>(signal_min_k->second)));

	auto signal_max_k = con->http_variables().find("signal_max");
	if (signal_max_k != con->http_variables().end())
		query.append_where(AND, _WHERE("signal", LE, string_to_n<int>(signal_max_k->second)));

	auto address_source_k = con->http_variables().find("address_source");
	if (address_source_k != con->http_variables().end())
		query.append_where(AND, _WHERE("sourcemac", LIKE, address_source_k->second));

	auto address_dest_k = con->http_variables().find("address_dest");
	if (address_dest_k != con->http_variables().end())
		query.append_where(AND, _WHERE("destmac", LIKE, address_dest_k->second));

	auto address_trans_k = con->http_variables().find("address_trans");
	if (address_trans_k != con->http_variables().end())
		query.append_where(AND, _WHERE("transmac", LIKE, address_trans_k->second));

	auto location_lat_min_k = con->http_variables().find("location_lat_min");
	if (location_lat_min_k != con->http_variables().end())
		query.append_where(AND, _WHERE("lat", GE, string_to_n<double>(location_lat_min_k->second)));

	auto location_lat_max_k = con->http_variables().find("location_lat_max");
	if (location_lat_max_k != con->http_variables().end())
		query.append_where(AND, _WHERE("lat", LE, string_to_n<double>(location_lat_max_k->second)));

	auto location_lon_min_k = con->http_variables().find("location_lon_min");
	if (location_lon_min_k != con->http_variables().end())
		query.append_where(AND, _WHERE("lon", GE, string_to_n<double>(location_lon_min_k->second)));

	auto location_lon_max_k = con->http_variables().find("location_lon_max");
	if (location_lon_max_k != con->http_variables().end())
		query.append_where(AND, _WHERE("lon", LE, string_to_n<double>(location_lon_max_k->second)));

	auto size_min_k = con->http_variables().find("size_min");
	if (size_min_k != con->http_variables().end())
		query.append_where(AND, _WHERE("packet_len", GE, string_to_n<unsigned long int>(size_min_k->second)));

	auto size_max_k = con->http_variables().find("size_max");
	if (size_max_k != con->http_variables().end())
		query.append_where(AND, _WHERE("packet_len", LE, string_to_n<unsigned long int>(size_max_k->second)));

	auto tag_k = con->http_variables().find("tag");
	if (tag_k != con->http_variables().end())
		query.append_where(AND, _WHERE("tags", LIKE, tag_k->second));

	auto limit_k = con->http_variables().find("limit");
	if (limit_k != con->http_variables().end())
		query.append_clause(LIMIT, string_to_n<unsigned long>(limit_k->second));

	con->clear_timeout();

	auto pcapng = std::make_shared<pcapng_stream_database>(&con->response_stream());

	con->set_target_file(fmt::format("{}.pcapng", con->uri_params()[":title"]));
	con->set_closure_cb([pcapng]() { pcapng->stop_stream("http connection lost"); });

	auto streamtracker = Globalreg::fetch_mandatory_global_as<stream_tracker>();
	scoped_streamer stream_reg(streamtracker, pcapng, fmt::format("kismet-dblog.pcapng"),
				"pcapng", "httpd",
				fmt::format("pcapng of from dblog"));


	pcapng->start_stream();

	// Get the list of all the interfaces we know about in the database and push them into the
	// pcapng handler
	auto datasource_query = _SELECT(db, "datasources", {"uuid", "name", "interface"});

	for (auto ds : datasource_query)  {
		pcapng->add_database_interface(sqlite3_column_as<std::string>(ds, 0),
				sqlite3_column_as<std::string>(ds, 1),
				sqlite3_column_as<std::string>(ds, 2));
	}

	// Database handler registers itself as timing out so this should be OK to just blitz through
	// now, we'll block as necessary
	for (auto p : query) {
		if (pcapng->pcapng_write_database_packet(
					sqlite3_column_as<std::uint64_t>(p, 0),
					sqlite3_column_as<std::uint64_t>(p, 1),
					sqlite3_column_as<std::string>(p, 2),
					sqlite3_column_as<unsigned int>(p, 3),
					sqlite3_column_as<std::string>(p, 4)) < 0) {
			return;
		}
	}

}

void kis_database_logfile::packet_drop_endpoint_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream ostream(&con->response_stream());

    using namespace kissqlite3;

    if (!db_enabled) {
        con->set_status(400);
        ostream << "Illegal request: kismetdb log not enabled\n";
        return;
    }

    db_writer_guard writer_lk(this);
    if (!db_enabled) {
        con->set_status(400);
        ostream << "Illegal request: kismetdb log not enabled\n";
        return;
    }

        auto drop_query =
            _DELETE(db, "packets", _WHERE("ts_sec", LE, con->json()["drop_before"].get<uint64_t>()));

    ostream << "Packets removed\n";
}

void kis_database_logfile::make_poi_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream ostream(&con->response_stream());

    if (!db_enabled)
        throw std::runtime_error("kismetdb log not enabled\n");

    struct timeval tv;
    gettimeofday(&tv, nullptr);
    std::string poi_data;

    std::shared_ptr<kis_gps_packinfo> loc;
    if (gpstracker != nullptr)
        loc = gpstracker->get_best_location();

    if (!con->json()["note"].is_null()) {
        poi_data = "{\"note\": \"" +
            json_adapter::sanitize_string(con->json()["note"]) +
            "\"}";
    }

    log_snapshot(loc, tv, "POI", poi_data);

    ostream << "POI created\n";
}

void kis_database_logfile::tagged_data_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream ostream(&con->response_stream());
    con->set_mime_type("application/json");

    auto fail = [&](int status, const std::string& err) {
        con->set_status(status);
        ostream << nlohmann::json{{"ok", false}, {"error", err}}.dump();
    };

    const auto& j = con->json();
    if (!j.is_object())
        return fail(400, "expected a JSON object with tag and data");

    auto tag_k = j.find("tag");
    if (tag_k == j.end() || !tag_k->is_string())
        return fail(400, "tag has to be a string");

    const auto& tag = tag_k->get_ref<const std::string&>();
    if (!tagged_data_valid_tag(tag))
        return fail(400, fmt::format("tag has to be 1 to {} letters, digits, '.', '_', or '-'",
                    tagged_data_max_tag));

    auto data_k = j.find("data");
    if (data_k == j.end())
        return fail(400, "data is missing");

    if (!db_enabled)
        return fail(400, "kismetdb log not enabled");

    struct timeval tv;
    gettimeofday(&tv, nullptr);

    // The best GPS location, when it has a fix
    if (log_snapshot(nullptr, tv, tagged_data_prefix + tag,
                data_k->dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)) <= 0)
        return fail(500, "the record couldn't be saved to the kismetdb log");

    ostream << nlohmann::json{{"ok", true}, {"tag", tag}, {"ts_sec", tv.tv_sec},
        {"ts_usec", tv.tv_usec}}.dump();
}

void kis_database_logfile::tagged_data_tags_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream ostream(&con->response_stream());
    con->set_mime_type("application/json");

    auto fail = [&](int status, const std::string& err) {
        con->set_status(status);
        ostream << nlohmann::json{{"ok", false}, {"error", err}}.dump();
    };

    auto ret = nlohmann::json::array();

    {
        db_writer_guard writer_lk(this);

        if (!db_enabled)
            return fail(400, "kismetdb log not enabled");

        const std::string sql =
            "SELECT snaptype, count(*), min(ts_sec), max(ts_sec) FROM snapshots "
            "WHERE snaptype > ?1 AND snaptype < ?2 GROUP BY snaptype ORDER BY snaptype";

        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), sql.length(), &stmt, nullptr) != SQLITE_OK) {
            _MSG_ERROR("kis_database_logfile unable to query tagged data in {}: {}", ds_dbfile, sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return fail(500, "the kismetdb log couldn't be read");
        }

        sqlite3_bind_text(stmt, 1, tagged_data_range_lo, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, tagged_data_range_hi, -1, SQLITE_STATIC);

        const auto prefix_len = strlen(tagged_data_prefix);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            auto type = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            if (type == nullptr || strlen(type) <= prefix_len)
                continue;

            ret.push_back({{"tag", type + prefix_len},
                    {"count", sqlite3_column_int64(stmt, 1)},
                    {"first_ts_sec", sqlite3_column_int64(stmt, 2)},
                    {"last_ts_sec", sqlite3_column_int64(stmt, 3)}});
        }

        sqlite3_finalize(stmt);
    }

    ostream << ret.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

void kis_database_logfile::tagged_data_records_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream ostream(&con->response_stream());
    con->set_mime_type("application/json");

    auto fail = [&](int status, const std::string& err) {
        con->set_status(status);
        ostream << nlohmann::json{{"ok", false}, {"error", err}}.dump();
    };

    bool bad = false;

    auto tag = tagged_data_str_opt(con, "tag", bad);
    if (bad || (tag.has_value() && !tagged_data_valid_tag(*tag)))
        return fail(400, fmt::format("tag has to be 1 to {} letters, digits, '.', '_', or '-'",
                    tagged_data_max_tag));

    auto after = tagged_data_num_opt(con, "after", bad);
    if (bad || (after.has_value() && (*after < 0 || *after > 9e15 || *after != std::floor(*after))))
        return fail(400, "after has to be a record id");

    auto limit = tagged_data_num_opt(con, "limit", bad);
    if (bad || (limit.has_value() && (*limit < 1 || *limit > tagged_data_max_limit ||
                    *limit != std::floor(*limit))))
        return fail(400, fmt::format("limit has to be a whole number from 1 to {}", tagged_data_max_limit));

    auto ts_start = tagged_data_num_opt(con, "ts_start", bad);
    auto ts_end = tagged_data_num_opt(con, "ts_end", bad);
    if (bad)
        return fail(400, "ts_start and ts_end have to be times in seconds");

    bool with_data = true;
    auto data_opt = tagged_data_str_opt(con, "data", bad);
    if (data_opt.has_value()) {
        if (*data_opt == "true" || *data_opt == "1")
            with_data = true;
        else if (*data_opt == "false" || *data_opt == "0")
            with_data = false;
        else
            bad = true;
    }
    if (bad)
        return fail(400, "data has to be true or false");

    const int64_t max_rows = limit.has_value() ? static_cast<int64_t>(*limit) : tagged_data_default_limit;

    struct record {
        int64_t id, ts_sec, ts_usec, size;
        double lat, lon;
        std::string tag, json;
    };

    std::vector<record> records;
    bool more = false;

    // Rows are copied out under the log lock and written after it's released, so a slow
    // client never holds up logging
    {
        db_writer_guard writer_lk(this);

        if (!db_enabled)
            return fail(400, "kismetdb log not enabled");

        const std::string sql = fmt::format(
            "SELECT rowid, snaptype, ts_sec, ts_usec, lat, lon, {} FROM snapshots "
            "WHERE rowid > ?1 AND {} "
            "AND ts_sec + ts_usec / 1000000.0 >= ?4 AND ts_sec + ts_usec / 1000000.0 <= ?5 "
            "ORDER BY rowid LIMIT ?6",
            with_data ? "json" : "length(CAST(json AS BLOB))",
            tag.has_value() ? "snaptype = ?2" : "snaptype > ?2 AND snaptype < ?3");

        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), sql.length(), &stmt, nullptr) != SQLITE_OK) {
            _MSG_ERROR("kis_database_logfile unable to query tagged data in {}: {}", ds_dbfile, sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return fail(500, "the kismetdb log couldn't be read");
        }

        const std::string snaptype = tag.has_value() ? tagged_data_prefix + *tag : "";

        sqlite3_bind_int64(stmt, 1, after.has_value() ? static_cast<int64_t>(*after) : 0);
        if (tag.has_value()) {
            sqlite3_bind_text(stmt, 2, snaptype.c_str(), snaptype.length(), SQLITE_STATIC);
        } else {
            sqlite3_bind_text(stmt, 2, tagged_data_range_lo, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, tagged_data_range_hi, -1, SQLITE_STATIC);
        }
        sqlite3_bind_double(stmt, 4, ts_start.has_value() ? *ts_start : -1e18);
        sqlite3_bind_double(stmt, 5, ts_end.has_value() ? *ts_end : 1e18);
        // One more than asked for, to know whether there are more
        sqlite3_bind_int64(stmt, 6, max_rows + 1);

        const auto prefix_len = strlen(tagged_data_prefix);
        size_t total = 0;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (static_cast<int64_t>(records.size()) >= max_rows ||
                    (!records.empty() && total >= tagged_data_read_budget)) {
                more = true;
                break;
            }

            record r;
            r.id = sqlite3_column_int64(stmt, 0);
            auto type = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            if (type != nullptr && strlen(type) > prefix_len)
                r.tag = type + prefix_len;
            r.ts_sec = sqlite3_column_int64(stmt, 2);
            r.ts_usec = sqlite3_column_int64(stmt, 3);
            r.lat = sqlite3_column_double(stmt, 4);
            r.lon = sqlite3_column_double(stmt, 5);

            if (with_data) {
                auto txt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
                auto len = sqlite3_column_bytes(stmt, 6);
                if (txt != nullptr && len > 0)
                    r.json.assign(txt, len);
                r.size = len;
            } else {
                r.size = sqlite3_column_int64(stmt, 6);
            }

            total += r.json.size();
            records.push_back(std::move(r));
        }

        sqlite3_finalize(stmt);
    }

    ostream << "{\"ok\":true,\"records\":[";

    bool first = true;
    for (const auto& r : records) {
        auto head = nlohmann::json{{"id", r.id}, {"tag", r.tag}, {"ts_sec", r.ts_sec},
            {"ts_usec", r.ts_usec}, {"lat", r.lat}, {"lon", r.lon}, {"size", r.size}}.dump(-1, ' ', false,
                    nlohmann::json::error_handler_t::replace);

        ostream << (first ? "" : ",");
        first = false;

        if (!with_data) {
            ostream << head;
            continue;
        }

        // The push API stores compact JSON; it's checked without building the document,
        // then copied as-is
        head.pop_back();
        ostream << head << ",\"data\":";
        if (!r.json.empty() && nlohmann::json::accept(r.json))
            ostream << r.json;
        else
            ostream << "null";
        ostream << "}";
    }

    ostream << "],\"more\":" << (more ? "true" : "false");
    if (!records.empty())
        ostream << ",\"next\":" << records.back().id;
    ostream << "}";
}

void kis_database_logfile::tagged_data_delete_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream ostream(&con->response_stream());
    con->set_mime_type("application/json");

    auto fail = [&](int status, const std::string& err) {
        con->set_status(status);
        ostream << nlohmann::json{{"ok", false}, {"error", err}}.dump();
    };

    bool bad = false;

    auto tag = tagged_data_str_opt(con, "tag", bad);
    if (bad || (tag.has_value() && !tagged_data_valid_tag(*tag)))
        return fail(400, fmt::format("tag has to be 1 to {} letters, digits, '.', '_', or '-'",
                    tagged_data_max_tag));

    auto ts_start = tagged_data_num_opt(con, "ts_start", bad);
    auto ts_end = tagged_data_num_opt(con, "ts_end", bad);
    if (bad)
        return fail(400, "ts_start and ts_end have to be times in seconds");

    bool all = false;
    auto all_opt = tagged_data_str_opt(con, "all", bad);
    if (all_opt.has_value()) {
        if (*all_opt == "true" || *all_opt == "1")
            all = true;
        else if (*all_opt != "false" && *all_opt != "0")
            bad = true;
    }
    if (bad)
        return fail(400, "all has to be true or false");

    const auto ids_err = fmt::format("ids has to be a list of 1 to {} record ids", tagged_data_max_limit);
    std::vector<int64_t> ids;
    bool have_ids = false;

    const auto& j = con->json();
    auto ids_k = j.is_object() ? j.find("ids") : j.end();
    if (j.is_object() && ids_k != j.end()) {
        if (!ids_k->is_array() || ids_k->empty() || ids_k->size() > tagged_data_max_limit)
            return fail(400, ids_err);
        for (const auto& i : *ids_k) {
            if (!i.is_number_integer() || (i.is_number_unsigned() && i.get<uint64_t>() > INT64_MAX) ||
                    i.get<int64_t>() < 1)
                return fail(400, ids_err);
            ids.push_back(i.get<int64_t>());
        }
        have_ids = true;
    } else if (con->http_variables().find("ids") != con->http_variables().end()) {
        return fail(400, ids_err);
    }

    // An empty request never deletes everything by accident
    if (!tag.has_value() && !have_ids && !ts_start.has_value() && !ts_end.has_value() && !all)
        return fail(400, "give a tag, ids, ts_start, or ts_end, or all to delete every tagged record");

    db_writer_guard writer_lk(this);

    if (!db_enabled)
        return fail(400, "kismetdb log not enabled");

    // Only API:<tag> records, whatever else matches
    std::string sql = "DELETE FROM snapshots WHERE snaptype > ? AND snaptype < ?";
    if (tag.has_value())
        sql += " AND snaptype = ?";
    if (ts_start.has_value())
        sql += " AND ts_sec + ts_usec / 1000000.0 >= ?";
    if (ts_end.has_value())
        sql += " AND ts_sec + ts_usec / 1000000.0 <= ?";
    if (have_ids) {
        sql += " AND rowid IN (?";
        for (size_t i = 1; i < ids.size(); i++)
            sql += ",?";
        sql += ")";
    }

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), sql.length(), &stmt, nullptr) != SQLITE_OK) {
        _MSG_ERROR("kis_database_logfile unable to delete tagged data in {}: {}", ds_dbfile, sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return fail(500, "the kismetdb log couldn't be changed");
    }

    const std::string snaptype = tag.has_value() ? tagged_data_prefix + *tag : "";

    int b = 1;
    sqlite3_bind_text(stmt, b++, tagged_data_range_lo, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, b++, tagged_data_range_hi, -1, SQLITE_STATIC);
    if (tag.has_value())
        sqlite3_bind_text(stmt, b++, snaptype.c_str(), snaptype.length(), SQLITE_STATIC);
    if (ts_start.has_value())
        sqlite3_bind_double(stmt, b++, *ts_start);
    if (ts_end.has_value())
        sqlite3_bind_double(stmt, b++, *ts_end);
    for (auto i : ids)
        sqlite3_bind_int64(stmt, b++, i);

    // Other threads log on the same connection; hold it so the count is this delete's
    auto conn_mutex = sqlite3_db_mutex(db);
    sqlite3_mutex_enter(conn_mutex);
    auto r = sqlite3_step(stmt);
    auto deleted = sqlite3_changes(db);
    sqlite3_mutex_leave(conn_mutex);

    sqlite3_finalize(stmt);

    if (r != SQLITE_DONE) {
        _MSG_ERROR("kis_database_logfile unable to delete tagged data in {}: {}", ds_dbfile, sqlite3_errmsg(db));
        return fail(500, "the kismetdb log couldn't be changed");
    }

    ostream << nlohmann::json{{"ok", true}, {"deleted", deleted}}.dump();
}

std::shared_ptr<tracker_element>
kis_database_logfile::list_poi_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    auto ret = std::make_shared<tracker_element_vector>();

    if (!db_enabled)
        return ret;

    db_writer_guard writer_lk(this);
    if (!db_enabled)
        return ret;

    // POIs are stored as snapshots by make_poi_endp_handler(); same connection as the writers,
    // so this also sees POIs in the open transaction
    const std::string sql =
        "SELECT ts_sec, ts_usec, lat, lon, json FROM snapshots "
        "WHERE snaptype = 'POI' ORDER BY ts_sec, ts_usec";

    sqlite3_stmt *poi_stmt;
    const char *poi_pz;

    if (sqlite3_prepare(db, sql.c_str(), sql.length(), &poi_stmt, &poi_pz) != SQLITE_OK) {
        _MSG_ERROR("kis_database_logfile unable to query POIs in {}: {}", ds_dbfile, sqlite3_errmsg(db));
        return ret;
    }

    while (sqlite3_step(poi_stmt) == SQLITE_ROW) {
        auto poi = std::make_shared<tracker_element_map>(poi_entry_id);

        poi->insert(std::make_shared<tracker_element_uint64>(poi_ts_sec_id,
                    sqlite3_column_int64(poi_stmt, 0)));
        poi->insert(std::make_shared<tracker_element_uint64>(poi_ts_usec_id,
                    sqlite3_column_int64(poi_stmt, 1)));
        poi->insert(std::make_shared<tracker_element_double>(poi_lat_id,
                    sqlite3_column_double(poi_stmt, 2)));
        poi->insert(std::make_shared<tracker_element_double>(poi_lon_id,
                    sqlite3_column_double(poi_stmt, 3)));

        // The record is {"note": "..."}, or empty when the POI was created without a note
        std::string note;
        auto json_txt = reinterpret_cast<const char *>(sqlite3_column_text(poi_stmt, 4));
        if (json_txt != nullptr) {
            auto j = nlohmann::json::parse(json_txt, nullptr, false);
            if (j.is_object() && j["note"].is_string())
                note = j["note"].get<std::string>();
        }
        poi->insert(std::make_shared<tracker_element_string>(poi_note_id, note));

        ret->push_back(poi);
    }

    sqlite3_finalize(poi_stmt);

    return ret;
}

pcapng_stream_database::pcapng_stream_database(future_chainbuf* buffer) :
    pcapng_stream_futurebuf(buffer,
			pcapng_stream_accept_ftor(),
			pcapng_stream_select_ftor(),
            1024*512,
            true),
    next_pcap_intf_id{0} {

}

pcapng_stream_database::~pcapng_stream_database() {
    chainbuf->cancel();
}

void pcapng_stream_database::start_stream() {
    pcapng_stream_futurebuf::start_stream();

    // Populate a junk interface
    add_database_interface("0", "lo", "Placeholder for missing interface");
}

void pcapng_stream_database::stop_stream(std::string in_reason) {
    pcapng_stream_futurebuf::stop_stream(in_reason);
}

void pcapng_stream_database::add_database_interface(const std::string& in_uuid, const std::string& in_interface,
        const std::string& in_name) {

    if (db_uuid_intf_map.find(in_uuid) != db_uuid_intf_map.end())
        return;

    auto intf = std::make_shared<db_interface>(in_uuid, in_interface, in_name);
    intf->pcapnum = next_pcap_intf_id;
    next_pcap_intf_id++;

    db_uuid_intf_map[in_uuid] = intf;
}

int pcapng_stream_database::pcapng_write_database_packet(uint64_t time_s, uint64_t time_us,
        const std::string& interface_uuid, unsigned int dlt, const std::string& data) {

    auto pcap_intf_i = db_uuid_intf_map.find(interface_uuid);

    // Shim the junk interface if we can't find it
    if (pcap_intf_i == db_uuid_intf_map.end())
        pcap_intf_i = db_uuid_intf_map.find("0");

    auto pcap_intf = pcap_intf_i->second;
    int ng_interface_id;

    if (pcap_intf->dlt != dlt)
        pcap_intf->dlt = dlt;

    // Same key the interface block was stored under; the bare interface number never
    // matched it, so every packet wrote a new interface block
    auto ds_id_rec =
        datasource_id_map.find(idb_key{pcap_intf->pcapnum, static_cast<int>(pcap_intf->dlt)});

    if (ds_id_rec == datasource_id_map.end()) {
        ng_interface_id = pcapng_make_idb(pcap_intf->pcapnum, pcap_intf->interface,
                fmt::format("kismetdb stored interface {} {}", pcap_intf->interface,
                    pcap_intf->uuid), pcap_intf->dlt);

        if (ng_interface_id < 0)
            return -1;

    } else {
        ng_interface_id = ds_id_rec->second;
    }

    struct timeval ts;
    ts.tv_sec = time_s;
    ts.tv_usec = time_us;

    return pcapng_write_packet(ng_interface_id, ts, data, data.length());
}

