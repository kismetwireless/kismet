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

#include <fcntl.h>
#include <unistd.h>

#include "globalregistry.h"
#include "json_adapter.h"
#include "kis_databaselogfile.h"
#include "kis_datasource.h"
#include "messagebus.h"
#include "packetchain.h"
#include "sqlite3_cpp11.h"

kis_database_logfile::kis_database_logfile():
    kis_logfile(shared_log_builder(NULL)),
    kis_database("kismetlog"),
    lifetime_global() {

    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();

    transaction_mutex.set_name("kis_database_logfile_transaction");

    std::shared_ptr<packet_chain> packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");

    pack_comp_device = packetchain->register_packet_component("DEVICE");
    pack_comp_radiodata = packetchain->register_packet_component("RADIODATA");
    pack_comp_gps = packetchain->register_packet_component("GPS");
    pack_comp_no_gps = packetchain->register_packet_component("NOGPS");
    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_datasource = packetchain->register_packet_component("KISDATASRC");
    pack_comp_common = packetchain->register_packet_component("COMMON");
    pack_comp_metablob = packetchain->register_packet_component("METABLOB");

    last_device_log = 0;

    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    db_enabled = false;

    message_evt_id = 0;
    alert_evt_id = 0;
}

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

            // local_locker dblock(&ds_mutex, "kismetdb transaction_timer");

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

    alert_evt_id =
        eventbus->register_listener(alert_tracker::alert_event(),
                [this](std::shared_ptr<eventbus_event> evt) {

                auto msg_k = evt->get_event_content()->find(alert_tracker::alert_event());
                if (msg_k == evt->get_event_content()->end())
                    return;

                auto al = std::static_pointer_cast<tracked_alert>(msg_k->second);

                handle_alert(al);
                });

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
                    return dbl->log_packet(packet);
                }, this, CHAINPOS_LOGGING, -100);
    } else {
        packet_handler_id = -1;
        _MSG_INFO("Packets will not be saved to the Kismet database log.");
    }

    return true;
}

void kis_database_logfile::close_log() {
#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb close_log");
    db_lock_with_sync_check(dblock, return);
#endif

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

    set_int_log_open(false);
    db_enabled = false;

    // End the transaction
    sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);

    sqlite3_exec(db, "PRAGMA journal_mode=DELETE", NULL, NULL, NULL);
    sqlite3_exec(db, "BEGIN_EXCLUSIVE", NULL, NULL, NULL);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

    database_close();
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

        "lat REAL, " // location
        "lon REAL, "
        "alt REAL, "
        "speed REAL, "
        "heading REAL, "

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

        "lat REAL, " // Location
        "lon REAL, "
        "alt REAL, "
        "speed REAL, "
        "heading REAL, "

        "datasource TEXT, " // UUID of data source

        "type TEXT, " // Type of arbitrary record

        "json BLOB " // Arbitrary JSON record
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
    sqlite3_bind_text(msg_stmt, spos++, msg->get_message().c_str(), msg->get_message().length(), SQLITE_TRANSIENT);

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb handle_message");
    db_lock_with_sync_check(dblock, return);
#endif

    if (sqlite3_step(msg_stmt) != SQLITE_DONE) {
        close_log();
        _MSG_ERROR("Unable to insert message into {}: {}", ds_dbfile, sqlite3_errmsg(db));
    }

    sqlite3_finalize(msg_stmt);
}

int kis_database_logfile::log_device(const std::shared_ptr<kis_tracked_device_base>& d) {
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
        "bytes_data, type, device) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

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

    if (d->has_location() && (d->get_location()->has_min_loc() &&
                              d->get_location()->has_max_loc() &&
                              d->get_location()->has_avg_loc())) {
        sqlite3_bind_double(device_stmt, spos++,
                            d->get_location()->get_min_loc()->get_lat());
        sqlite3_bind_double(device_stmt, spos++,
                            d->get_location()->get_min_loc()->get_lon());
        sqlite3_bind_double(device_stmt, spos++,
                            d->get_location()->get_max_loc()->get_lat());
        sqlite3_bind_double(device_stmt, spos++,
                            d->get_location()->get_max_loc()->get_lon());
        sqlite3_bind_double(device_stmt, spos++,
                            d->get_location()->get_avg_loc()->get_lat());
        sqlite3_bind_double(device_stmt, spos++,
                            d->get_location()->get_avg_loc()->get_lon());
    } else {
        // Empty location
        sqlite3_bind_double(device_stmt, spos++, 0);
        sqlite3_bind_double(device_stmt, spos++, 0);
        sqlite3_bind_double(device_stmt, spos++, 0);
        sqlite3_bind_double(device_stmt, spos++, 0);
        sqlite3_bind_double(device_stmt, spos++, 0);
        sqlite3_bind_double(device_stmt, spos++, 0);
    }

    sqlite3_bind_int64(device_stmt, spos++, d->get_datasize());
    sqlite3_bind_text(device_stmt, spos++, typestring.c_str(),
            typestring.length(), SQLITE_TRANSIENT);

    sqlite3_bind_blob(device_stmt, spos++, streamstring.c_str(),
            streamstring.length(), SQLITE_TRANSIENT);

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_device");
    db_lock_with_sync_check(dblock, return);
#endif

    if (sqlite3_step(device_stmt) != SQLITE_DONE) {
        _MSG("kis_database_logfile unable to insert device in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_finalize(device_stmt);

    return 1;
}

int kis_database_logfile::log_packet(const std::shared_ptr<kis_packet>& in_pack) {
    if (!db_enabled) {
        return 0;
    }

    std::string phystring;
    std::string macstring;
    std::string deststring;
    std::string transstring;
    std::string keystring;
    std::string sourceuuidstring;
    double frequency;

    if (!log_data_packets)
        return 0;

    if (in_pack->duplicate && !log_duplicate_packets)
        return 0;

    if (in_pack->filtered)
        return 0;

    if (packet_mac_filter->filter_packet(in_pack)) {
        return 0;
    }

    auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_linkframe);
    auto radioinfo = in_pack->fetch<kis_layer1_packinfo>(pack_comp_radiodata);
    auto gpsdata = in_pack->fetch<kis_gps_packinfo>(pack_comp_gps);
    auto commoninfo = in_pack->fetch<kis_common_info>(pack_comp_common);
    auto datasrc = in_pack->fetch<packetchain_comp_datasource>(pack_comp_datasource);
    auto metablob = in_pack->fetch<packet_metablob>(pack_comp_metablob);

    kis_phy_handler *phyh = NULL;

    // Packets are no longer a 1:1 with a device
    keystring = "0";

    if (commoninfo != NULL) {
        phyh = devicetracker->fetch_phy_handler(commoninfo->phyid);
        macstring = commoninfo->source.mac_to_string();
        deststring = commoninfo->dest.mac_to_string();
        transstring = commoninfo->transmitter.mac_to_string();
        frequency = commoninfo->freq_khz;
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
        sourceuuidstring = datasrc->ref_source->get_source_uuid().uuid_to_string();
    } else {
        sourceuuidstring = "00000000-0000-0000-0000-000000000000";
    }

    // Log into the PACKET table if we're a loggable packet (ie, have a link frame)
    if (chunk != nullptr) {
        int r;
        std::string sql;
        sqlite3_stmt *packet_stmt;
        const char *packet_pz;

        sql =
            "INSERT INTO packets "
            "(ts_sec, ts_usec, phyname, "
            "sourcemac, destmac, transmac, devkey, frequency, "
            "lat, lon, alt, speed, heading, "
            "packet_len, packet_full_len, signal, "
            "datasource, "
            "dlt, packet, "
            "error, tags, datarate, hash, packetid) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        r = sqlite3_prepare(db, sql.c_str(), sql.length(), &packet_stmt, &packet_pz);

        if (r != SQLITE_OK) {
            _MSG("kis_database_logfile unable to prepare database insert for packets in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            close_log();
            return -1;
        }

        int sql_pos = 1;

        sqlite3_bind_int64(packet_stmt, sql_pos++, in_pack->ts.tv_sec);
        sqlite3_bind_int64(packet_stmt, sql_pos++, in_pack->ts.tv_usec);

        sqlite3_bind_text(packet_stmt, sql_pos++, phystring.c_str(), phystring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(packet_stmt, sql_pos++, macstring.c_str(), macstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(packet_stmt, sql_pos++, deststring.c_str(), deststring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(packet_stmt, sql_pos++, transstring.c_str(), transstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(packet_stmt, sql_pos++, keystring.c_str(), keystring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_double(packet_stmt, sql_pos++, frequency);

        if (gpsdata != NULL) {
            sqlite3_bind_double(packet_stmt, sql_pos++, gpsdata->lat);
            sqlite3_bind_double(packet_stmt, sql_pos++, gpsdata->lon);
            sqlite3_bind_double(packet_stmt, sql_pos++, gpsdata->alt);
            sqlite3_bind_double(packet_stmt, sql_pos++, gpsdata->speed);
            sqlite3_bind_double(packet_stmt, sql_pos++, gpsdata->heading);
        } else {
            sqlite3_bind_double(packet_stmt, sql_pos++, 0);
            sqlite3_bind_double(packet_stmt, sql_pos++, 0);
            sqlite3_bind_double(packet_stmt, sql_pos++, 0);
            sqlite3_bind_double(packet_stmt, sql_pos++, 0);
            sqlite3_bind_double(packet_stmt, sql_pos++, 0);
        }

        sqlite3_bind_int64(packet_stmt, sql_pos++, chunk->length());
        sqlite3_bind_int64(packet_stmt, sql_pos++, in_pack->original_len);

        if (radioinfo != nullptr) {
            sqlite3_bind_int(packet_stmt, sql_pos++, radioinfo->signal_dbm);
        } else {
            sqlite3_bind_int(packet_stmt, sql_pos++, 0);
        }

        sqlite3_bind_text(packet_stmt, sql_pos++, sourceuuidstring.c_str(),
                sourceuuidstring.length(), SQLITE_TRANSIENT);

        sqlite3_bind_int(packet_stmt, sql_pos++, chunk->dlt);
        sqlite3_bind_blob(packet_stmt, sql_pos++, (const char *) chunk->data(), chunk->length(), 0);

        sqlite3_bind_int(packet_stmt, sql_pos++, in_pack->error);

        std::stringstream tagstream;
        bool space_needed = false;

        for (auto tag : in_pack->tag_map) {
            if (space_needed)
                tagstream << " ";
            space_needed = true;
            tagstream << tag.first;
        }

        auto str = tagstream.str();
        sqlite3_bind_text(packet_stmt, sql_pos++, str.c_str(), tagstream.str().length(), SQLITE_TRANSIENT);

        if (radioinfo != nullptr)
            sqlite3_bind_double(packet_stmt, sql_pos++, radioinfo->datarate / 10);
        else
            sqlite3_bind_double(packet_stmt, sql_pos++, 0);

        sqlite3_bind_int(packet_stmt, sql_pos++, in_pack->hash);
        sqlite3_bind_int64(packet_stmt, sql_pos++, in_pack->packet_no);

#if 0
        kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_packet");
        db_lock_with_sync_check(dblock, return -1);
#endif

        if (sqlite3_step(packet_stmt) != SQLITE_DONE) {
            _MSG("kis_database_logfile unable to insert packet in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            close_log();
            return -1;
        }

        sqlite3_finalize(packet_stmt);
    }

    // If the packet has a metablob record, log that; if the packet ONLY has meta data we should only get a 'data'
    // record; if the packet has both, we'll get both a 'packet' and a 'data' record.
    if (metablob != nullptr) {
        mac_addr smac("00:00:00:00:00:00");
        uuid puuid;

        if (commoninfo != nullptr)
            smac = commoninfo->source;

        if (datasrc != nullptr)
            puuid = datasrc->ref_source->get_source_uuid();

        log_data(gpsdata, in_pack->ts, phystring, smac, puuid,
                metablob->meta_type, metablob->meta_data);
    }

    return 1;
}

int kis_database_logfile::log_data(const std::shared_ptr<kis_gps_packinfo>& gps,
        const struct timeval& tv, const std::string& phystring, const mac_addr& devmac,
        const uuid& datasource_uuid, const std::string& type, const std::string& json) {

    if (!db_enabled)
        return 0;

    std::string macstring = devmac.mac_to_string();
    std::string uuidstring = datasource_uuid.uuid_to_string();

    int r;
    std::string sql;
    sqlite3_stmt *data_stmt;
    const char *data_pz;

    sql =
        "INSERT INTO data "
        "(ts_sec, ts_usec, "
        "phyname, devmac, "
        "lat, lon, alt, speed, heading, "
        "datasource, "
        "type, json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &data_stmt, &data_pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database_logfile unable to prepare database insert for data in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_reset(data_stmt);
    sqlite3_clear_bindings(data_stmt);

    int sql_pos = 1;

    sqlite3_bind_int64(data_stmt, sql_pos++, tv.tv_sec);
    sqlite3_bind_int64(data_stmt, sql_pos++, tv.tv_usec);

    sqlite3_bind_text(data_stmt, sql_pos++, phystring.c_str(), phystring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(data_stmt, sql_pos++, macstring.c_str(), macstring.length(), SQLITE_TRANSIENT);

    if (gps != NULL) {
        sqlite3_bind_double(data_stmt, sql_pos++, gps->lat);
        sqlite3_bind_double(data_stmt, sql_pos++, gps->lon);
        sqlite3_bind_double(data_stmt, sql_pos++, gps->alt);
        sqlite3_bind_double(data_stmt, sql_pos++, gps->speed);
        sqlite3_bind_double(data_stmt, sql_pos++, gps->heading);
    } else {
        sqlite3_bind_double(data_stmt, sql_pos++, 0);
        sqlite3_bind_double(data_stmt, sql_pos++, 0);
        sqlite3_bind_double(data_stmt, sql_pos++, 0);
        sqlite3_bind_double(data_stmt, sql_pos++, 0);
        sqlite3_bind_double(data_stmt, sql_pos++, 0);
    }

    sqlite3_bind_text(data_stmt, sql_pos++, uuidstring.c_str(), uuidstring.length(), SQLITE_TRANSIENT);

    sqlite3_bind_text(data_stmt, sql_pos++, type.data(), type.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(data_stmt, sql_pos++, json.data(), json.length(), SQLITE_TRANSIENT);

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_data");
    db_lock_with_sync_check(dblock, return -1);
#endif

    if (sqlite3_step(data_stmt) != SQLITE_DONE) {
        _MSG("kis_database_logfile unable to insert data in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    sqlite3_finalize(data_stmt);

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

    std::shared_ptr<kis_datasource> ds =
        std::static_pointer_cast<kis_datasource>(in_datasource);

    std::string uuidstring = ds->get_source_uuid().uuid_to_string();
    std::string typestring = ds->get_source_builder()->get_source_type();
    std::string defstring = ds->get_source_definition();
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

    sqlite3_bind_blob(datasource_stmt, 6, jsonstring.data(), jsonstring.length(), SQLITE_TRANSIENT);

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_datasource");
    db_lock_with_sync_check(dblock, return -1);
#endif

    if (sqlite3_step(datasource_stmt) != SQLITE_DONE) {
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

    sqlite3_bind_text(alert_stmt, 7, headerstring.c_str(), headerstring.length(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(alert_stmt, 8, jsonstring.data(), jsonstring.length(), SQLITE_TRANSIENT);

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_alert");
    db_lock_with_sync_check(dblock, return -1);
#endif

    if (sqlite3_step(alert_stmt) != SQLITE_DONE) {
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

    sqlite3_bind_text(snapshot_stmt, 5, snaptype.c_str(), snaptype.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(snapshot_stmt, 6, json.data(), json.length(), SQLITE_TRANSIENT);

#if 0
    kis_unique_lock<kis_mutex> dblock(ds_mutex, std::defer_lock, "kismetdb log_snapshot");
    db_lock_with_sync_check(dblock, return -1);
#endif

    if (sqlite3_step(snapshot_stmt) != SQLITE_DONE) {
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
	auto sid =
		streamtracker->register_streamer(pcapng, fmt::format("kismet-dblog.pcapng"),
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

	streamtracker->remove_streamer(sid);
}

void kis_database_logfile::packet_drop_endpoint_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream ostream(&con->response_stream());

    using namespace kissqlite3;

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

std::shared_ptr<tracker_element>
kis_database_logfile::list_poi_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    return std::make_shared<tracker_element_vector>();
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

    auto ds_id_rec =
        datasource_id_map.find(pcap_intf->pcapnum);

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

