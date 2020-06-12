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
#include "kismet_json.h"
#include "messagebus.h"
#include "packetchain.h"
#include "structured.h"
#include "sqlite3_cpp11.h"

kis_database_logfile::kis_database_logfile():
    kis_logfile(shared_log_builder(NULL)), 
    kis_database(Globalreg::globalreg, "kismetlog"),
    lifetime_global(),
    kis_net_httpd_ringbuf_stream_handler(),
    message_client(Globalreg::globalreg, nullptr) {

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

    device_stmt = NULL;
    device_pz = NULL;

    packet_stmt = NULL;
    packet_pz = NULL;

    datasource_stmt = NULL;
    datasource_pz = NULL;

    data_stmt = NULL;
    data_pz = NULL;

    alert_stmt = NULL;
    alert_pz = NULL;

    msg_stmt = NULL;
    msg_pz = NULL;

    snapshot_stmt = NULL;
    snapshot_pz = NULL;

    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    db_enabled = false;

    bind_httpd_server();
}

kis_database_logfile::~kis_database_logfile() {
    auto messagebus = Globalreg::FetchGlobalAs<message_bus>();
    if (messagebus != nullptr)
        messagebus->remove_client(this);

    close_log();
}

void kis_database_logfile::trigger_deferred_startup() {
    gpstracker = 
        Globalreg::fetch_mandatory_global_as<gps_tracker>();
}

void kis_database_logfile::trigger_deferred_shutdown() {

}

bool kis_database_logfile::open_log(std::string in_path) {
    local_locker dbl(&ds_mutex);

    auto timetracker = 
        Globalreg::fetch_mandatory_global_as<time_tracker>("TIMETRACKER");

    bool dbr = database_open(in_path);

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

    set_int_log_path(in_path);
    set_int_log_open(true);

	_MSG("Opened kismetdb log file '" + in_path + "'", MSGFLAG_INFO);

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_ephemeral_dangerous", false)) {
        _MSG_INFO("KISMETDB LOG IS IN EPHEMERAL MODE.  LOG WILL *** NOT *** BE PRESERVED WHEN "
                "KISMET EXITS.");
        unlink(in_path.c_str());
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_packets", true)) {
        _MSG("Saving packets to the Kismet database log.", MSGFLAG_INFO);
        std::shared_ptr<packet_chain> packetchain =
            Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");

        packetchain->register_handler(&kis_database_logfile::packet_handler, this, 
                CHAINPOS_LOGGING, -100);
    } else {
        _MSG_INFO("Packets will not be saved to the Kismet database log.");
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

    packet_drop_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>("/logging/kismetdb/pcap/drop", 
                [this](std::ostream& stream, const std::string& uri,
                    shared_structured post_structured, 
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return packet_drop_endpoint_handler(stream, uri, post_structured, variable_cache);
                }, nullptr);

    make_poi_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>("/poi/create_poi", 
                [this](std::ostream& stream, const std::string& uri,
                    shared_structured post_structured,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return make_poi_endp_handler(stream, uri, post_structured, variable_cache);
                });

    list_poi_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>("/poi/list_poi", 
                [this]() -> std::shared_ptr<tracker_element> {
                    return list_poi_endp_handler();
                });

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
        if (m.error) {
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
        if (m.error) {
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
        auto messagebus = 
            Globalreg::fetch_mandatory_global_as<message_bus>();
        messagebus->register_client(this, MSGFLAG_ALL);
    }


    db_enabled = true;

    sqlite3_exec(db, "PRAGMA journal_mode=PERSIST", NULL, NULL, NULL);
    
    // Go into transactional mode where we only commit every 10 seconds
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    transaction_timer = 
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
            [this](int) -> int {

            local_locker dblock(&ds_mutex);

            in_transaction_sync = true;

            sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

            in_transaction_sync = false;

            return 1;
        });

    // Post that we've got the logfile ready
    auto eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();
    eventbus->publish(std::make_shared<event_dblog_opened>());

    return true;
}

void kis_database_logfile::close_log() {
    local_demand_locker dblock(&ds_mutex);

    db_lock_with_sync_check(dblock, return);

    set_int_log_open(false);

    // Kill the timers
    auto timetracker = 
        Globalreg::FetchGlobalAs<time_tracker>();
    if (timetracker != NULL) {
        timetracker->remove_timer(transaction_timer);
        timetracker->remove_timer(packet_timeout_timer);
        timetracker->remove_timer(alert_timeout_timer);
        timetracker->remove_timer(device_timeout_timer);
        timetracker->remove_timer(message_timeout_timer);
        timetracker->remove_timer(snapshot_timeout_timer);
    }

    // End the transaction
    {
        sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);
    }

    db_enabled = false;

    auto packetchain =
        Globalreg::FetchGlobalAs<packet_chain>();
    if (packetchain != NULL) 
        packetchain->remove_handler(&kis_database_logfile::packet_handler, CHAINPOS_LOGGING);

    {
        if (device_stmt != NULL)
            sqlite3_finalize(device_stmt);
        device_stmt = NULL;
    }

    {
        if (packet_stmt != NULL)
            sqlite3_finalize(packet_stmt);
        packet_stmt = NULL;
    }

    {
        if (datasource_stmt != NULL)
            sqlite3_finalize(datasource_stmt);
        datasource_stmt = NULL;
    }

    {
        if (data_stmt != NULL)
            sqlite3_finalize(data_stmt);
        data_stmt = NULL;
    }

    { 
        if (alert_stmt != NULL)
            sqlite3_finalize(alert_stmt);
        alert_stmt = NULL;
    }

    {
        if (msg_stmt != NULL)
            sqlite3_finalize(msg_stmt);
        msg_stmt = NULL;
    }

    {
        if (snapshot_stmt != NULL)
            sqlite3_finalize(snapshot_stmt);
        snapshot_stmt = NULL;
    }

    sqlite3_exec(db, "PRAGMA journal_mode=DELETE", NULL, NULL, NULL);
    sqlite3_exec(db, "BEGIN_EXCLUSIVE", NULL, NULL, NULL);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

    database_close();
}

int kis_database_logfile::database_upgrade_db() {
    local_locker dblock(&ds_mutex);

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

        "tags TEXT" // Arbitrary packet tags
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

    database_set_db_version(6);

    // Prepare the statements we'll need later
    //
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

    sql =
        "INSERT INTO packets "
        "(ts_sec, ts_usec, phyname, "
        "sourcemac, destmac, transmac, devkey, frequency, " 
        "lat, lon, alt, speed, heading, "
        "packet_len, signal, "
        "datasource, "
        "dlt, packet, "
        "error, tags) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &packet_stmt, &packet_pz);

    if (r != SQLITE_OK) {
        _MSG("kis_database_logfile unable to prepare database insert for packets in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

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
        return -1;
    }

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

    return 1;
}

void kis_database_logfile::process_message(std::string in_msg, int in_flags) {
    if (!db_enabled)
        return;

    local_demand_locker dblock(&ds_mutex);
    db_lock_with_sync_check(dblock, return);

    sqlite3_reset(msg_stmt);

    unsigned int spos = 1;

    sqlite3_bind_int64(msg_stmt, spos++, time(0));

    if (gpstracker != nullptr) {
        auto loc = std::shared_ptr<kis_gps_packinfo>(gpstracker->get_best_location());

        if (loc != nullptr && loc->fix >= 2) {
            sqlite3_bind_double(msg_stmt, spos++, loc->lat);
            sqlite3_bind_double(msg_stmt, spos++, loc->lon);
        } else {
            sqlite3_bind_double(msg_stmt, spos++, 0);
            sqlite3_bind_double(msg_stmt, spos++, 0);
        }
    } else {
        sqlite3_bind_double(msg_stmt, spos++, 0);
        sqlite3_bind_double(msg_stmt, spos++, 0);
    }

    std::string msgtype;

    if (in_flags & MSGFLAG_INFO)
        msgtype = "INFO";
    else if (in_flags & MSGFLAG_ERROR)
        msgtype = "ERROR";
    else if (in_flags & MSGFLAG_DEBUG)
        msgtype = "DEBUG";
    else if (in_flags & MSGFLAG_FATAL)
        msgtype = "FATAL";

    sqlite3_bind_text(msg_stmt, spos++, msgtype.c_str(), msgtype.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(msg_stmt, spos++, in_msg.c_str(), in_msg.length(), SQLITE_TRANSIENT);

    if (sqlite3_step(msg_stmt) != SQLITE_DONE) {
        close_log();
        _MSG_ERROR("Unable to insert message into {}: {}", ds_dbfile, sqlite3_errmsg(db));
    }
}

int kis_database_logfile::log_device(std::shared_ptr<kis_tracked_device_base> d) {
    // We avoid using external mutexes here and try to let sqlite3 handle its own
    // internal locking state; we don't want a huge device list write to block packet
    // writes for instance
    
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

    // serialize the device
    int r = Globalreg::globalreg->entrytracker->serialize("json", sstr, d, nullptr);
   
    if (r < 0) {
        _MSG_ERROR("Failure serializing device key {} to the kisdatabaselog", d->get_key());
        return 0;
    }


    std::string streamstring = sstr.str();

    {
        local_demand_locker dblock(&ds_mutex);
        db_lock_with_sync_check(dblock, return -1);

        sqlite3_reset(device_stmt);

        sqlite3_bind_int64(device_stmt, spos++, d->get_first_time());
        sqlite3_bind_int64(device_stmt, spos++, d->get_last_time());
        sqlite3_bind_text(device_stmt, spos++, keystring.c_str(), 
                keystring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(device_stmt, spos++, phystring.c_str(), 
                phystring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(device_stmt, spos++, macstring.c_str(), 
                macstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_int(device_stmt, spos++, d->get_signal_data()->get_max_signal());

        if (d->get_tracker_location() != NULL) {
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

        if (sqlite3_step(device_stmt) != SQLITE_DONE) {
            _MSG("kis_database_logfile unable to insert device in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            close_log();
            return -1;
        }
    }

    return 1;
}

int kis_database_logfile::log_packet(kis_packet *in_pack) {
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

    if (packet_mac_filter->filter_packet(in_pack)) {
        return 0;
    }

    kis_datachunk *chunk = 
        (kis_datachunk *) in_pack->fetch(pack_comp_linkframe);

    kis_layer1_packinfo *radioinfo = 
        (kis_layer1_packinfo *) in_pack->fetch(pack_comp_radiodata);

    kis_gps_packinfo *gpsdata =
        (kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);

    kis_common_info *commoninfo =
        (kis_common_info *) in_pack->fetch(pack_comp_common);

    packetchain_comp_datasource *datasrc =
        (packetchain_comp_datasource *) in_pack->fetch(pack_comp_datasource);

    packet_metablob *metablob =
        (packet_metablob *) in_pack->fetch(pack_comp_metablob);

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
        local_demand_locker dblock(&ds_mutex);
        db_lock_with_sync_check(dblock, return -1);

        sqlite3_reset(packet_stmt);

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

        sqlite3_bind_int64(packet_stmt, sql_pos++, chunk->length);

        if (radioinfo != nullptr) {
            sqlite3_bind_int(packet_stmt, sql_pos++, radioinfo->signal_dbm);
        } else {
            sqlite3_bind_int(packet_stmt, sql_pos++, 0);
        }

        sqlite3_bind_text(packet_stmt, sql_pos++, sourceuuidstring.c_str(), 
                sourceuuidstring.length(), SQLITE_TRANSIENT);

        sqlite3_bind_int(packet_stmt, sql_pos++, chunk->dlt);
        sqlite3_bind_blob(packet_stmt, sql_pos++, (const char *) chunk->data, chunk->length, 0);

        sqlite3_bind_int(packet_stmt, sql_pos++, in_pack->error);

        std::stringstream tagstream;
        bool space_needed = false;

        for (auto tag : in_pack->tag_vec) {
            if (space_needed)
                tagstream << " ";
            space_needed = true;
            tagstream << tag;
        }

        auto str = tagstream.str();
        sqlite3_bind_text(packet_stmt, sql_pos++, str.c_str(), tagstream.str().length(), SQLITE_TRANSIENT);

        if (sqlite3_step(packet_stmt) != SQLITE_DONE) {
            _MSG("kis_database_logfile unable to insert packet in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            close_log();
            return -1;
        }
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

int kis_database_logfile::log_data(kis_gps_packinfo *gps, struct timeval tv, 
        std::string phystring, mac_addr devmac, uuid datasource_uuid, 
        std::string type, std::string json) {

    if (!db_enabled)
        return 0;

    std::string macstring = devmac.mac_to_string();
    std::string uuidstring = datasource_uuid.uuid_to_string();

    {
        local_demand_locker dblock(&ds_mutex);
        db_lock_with_sync_check(dblock, return -1);

        sqlite3_reset(data_stmt);

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

        if (sqlite3_step(data_stmt) != SQLITE_DONE) {
            _MSG("kis_database_logfile unable to insert data in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            close_log();
            return -1;
        }
    }

    return 1;
}

int kis_database_logfile::log_datasources(shared_tracker_element in_datasource_vec) {
    int r;

    if (!db_enabled)
        return 0;

    for (auto ds : *(std::static_pointer_cast<tracker_element_vector>(in_datasource_vec))) {
        r = log_datasource(ds);

        if (r < 0)
            return r;
    }

    return 1;
}

int kis_database_logfile::log_datasource(shared_tracker_element in_datasource) {

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

    {
        local_demand_locker dblock(&ds_mutex);
        db_lock_with_sync_check(dblock, return -1);

        sqlite3_reset(datasource_stmt);

        sqlite3_bind_text(datasource_stmt, 1, uuidstring.data(), uuidstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(datasource_stmt, 2, typestring.data(), typestring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(datasource_stmt, 3, defstring.data(), defstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(datasource_stmt, 4, namestring.data(), namestring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(datasource_stmt, 5, intfstring.data(), intfstring.length(), SQLITE_TRANSIENT);

        sqlite3_bind_blob(datasource_stmt, 6, jsonstring.data(), jsonstring.length(), SQLITE_TRANSIENT);

        if (sqlite3_step(datasource_stmt) != SQLITE_DONE) {
            _MSG("kis_database_logfile unable to insert datasource in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            close_log();
            return -1;
        }
    }

    return 1;
}

int kis_database_logfile::log_alert(std::shared_ptr<tracked_alert> in_alert) {
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

    {
        local_demand_locker dblock(&ds_mutex);
        db_lock_with_sync_check(dblock, return -1);

        sqlite3_reset(alert_stmt);

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

        if (sqlite3_step(alert_stmt) != SQLITE_DONE) {
            _MSG("kis_database_logfile unable to insert alert in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            close_log();
            return -1;
        }
    }

    return 1;
}

int kis_database_logfile::log_snapshot(kis_gps_packinfo *gps, struct timeval tv,
        std::string snaptype, std::string json) {

    if (!db_enabled)
        return 0;

    local_demand_locker dblock(&ds_mutex);
    db_lock_with_sync_check(dblock, return -1);

    sqlite3_reset(snapshot_stmt);

    sqlite3_bind_int64(snapshot_stmt, 1, tv.tv_sec);
    sqlite3_bind_int64(snapshot_stmt, 2, tv.tv_usec);

    if (gps != NULL) {
        sqlite3_bind_double(snapshot_stmt, 3, gps->lat);
        sqlite3_bind_double(snapshot_stmt, 4, gps->lon);
    } else {
        if (gpstracker != nullptr) {
            auto loc = std::shared_ptr<kis_gps_packinfo>(gpstracker->get_best_location());

            if (loc != nullptr && loc->fix >= 2) {
                sqlite3_bind_double(snapshot_stmt, 3, loc->lat);
                sqlite3_bind_double(snapshot_stmt, 4, loc->lon);
            } else {
                sqlite3_bind_int(snapshot_stmt, 3, 0);
                sqlite3_bind_int(snapshot_stmt, 4, 0);
            }
        } else {
            sqlite3_bind_int(snapshot_stmt, 3, 0);
            sqlite3_bind_int(snapshot_stmt, 4, 0);
        }
    }

    sqlite3_bind_text(snapshot_stmt, 5, snaptype.c_str(), snaptype.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(snapshot_stmt, 6, json.data(), json.length(), SQLITE_TRANSIENT);

    if (sqlite3_step(snapshot_stmt) != SQLITE_DONE) {
        _MSG("kis_database_logfile unable to insert snapshot in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        close_log();
        return -1;
    }

    return 1;
}

int kis_database_logfile::packet_handler(CHAINCALL_PARMS) {
    // Extremely basic shim to our built-in logging
    kis_database_logfile *logfile = (kis_database_logfile *) auxdata;

    return logfile->log_packet(in_pack);
}

void kis_database_logfile::usage(const char *argv0) {

}

bool kis_database_logfile::httpd_verify_path(const char *path, const char *method) {
    std::string stripped = httpd_strip_suffix(path);
    std::string suffix = httpd_get_suffix(path);

    if (stripped.find("/logging/kismetdb/pcap/") == 0 && suffix == "pcapng" && db_enabled)
        return true;

    return false;
}

int kis_database_logfile::httpd_create_stream_response(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) {

    using namespace kissqlite3;

    std::string stripped = httpd_strip_suffix(connection->url);
    std::string suffix = httpd_get_suffix(connection->url);

    if (!httpd->has_valid_session(connection, true)) {
        connection->httpcode = 503;
        return MHD_YES;
    }

    if (stripped.find("/logging/kismetdb/pcap/") == 0 && suffix == "pcapng") {
        if (db == nullptr || !db_enabled) {
            connection->httpcode = 500;
            return MHD_YES;
        }

        using namespace kissqlite3;
        auto query = _SELECT(db, "packets", {"ts_sec", "ts_usec", "datasource", "dlt", "packet"});

        try {
            if (connection->has_cached_variable("timestamp_start")) {
                // Break the double timestamp into two integers
                double intpart, fractpart;
                fractpart = modf(connection->variable_cache_as<double>("timestamp_start"), &intpart);
                query.append_where(AND, _WHERE("ts_sec", GT, intpart, OR,
                           "ts_sec", EQ, intpart, AND, "ts_usec", GE, fractpart * 1000000));
            }

            if (connection->has_cached_variable("timestamp_end")) {
                // Break the double timestamp into two integers
                double intpart, fractpart;
                fractpart = modf(connection->variable_cache_as<double>("timestamp_end"), &intpart);
                query.append_where(AND, _WHERE("ts_sec", LT, intpart, OR,
                            "ts_sec", EQ, intpart, AND, "ts_usec", LE, fractpart * 1000000));
            }

            if (connection->has_cached_variable("datasource"))
                query.append_where(AND, _WHERE("datasource", LIKE,
                            connection->variable_cache_as<std::string>("datasource")));

            if (connection->has_cached_variable("device_id"))
                query.append_where(AND, _WHERE("devkey", LIKE,
                            connection->variable_cache_as<std::string>("device_id")));

            if (connection->has_cached_variable("dlt"))
                query.append_where(AND, _WHERE("dlt", EQ,
                            connection->variable_cache_as<unsigned int>("dlt")));

            if (connection->has_cached_variable("frequency"))
                query.append_where(AND, _WHERE("frequency", EQ,
                            connection->variable_cache_as<unsigned long int>("frequency")));

            if (connection->has_cached_variable("frequency_min"))
                query.append_where(AND, _WHERE("frequency", GE,
                            connection->variable_cache_as<unsigned long int>("frequency_min")));

            if (connection->has_cached_variable("frequency_max"))
                query.append_where(AND, _WHERE("frequency", LE,
                            connection->variable_cache_as<unsigned long int>("frequency_max")));

            /*
            if (connection->has_cached_variable("channel")) {
                fprintf(stderr, "debug - channel %s\n", connection->variable_cache_as<std::string>("chnnel").c_str());
                query.append_where(AND, _WHERE("channel", LIKE,
                            connection->variable_cache_as<std::string>("channel")));
            }
            */

            if (connection->has_cached_variable("signal_min"))
                query.append_where(AND, _WHERE("signal", GE,
                            connection->variable_cache_as<unsigned int>("signal_min")));

            if (connection->has_cached_variable("signal_max"))
                query.append_where(AND, _WHERE("signal", LE, 
                            connection->variable_cache_as<unsigned int>("signal_max")));

            if (connection->has_cached_variable("address_source")) 
                query.append_where(AND, _WHERE("sourcemac", LIKE, 
                            connection->variable_cache_as<std::string>("address_source")));

            if (connection->has_cached_variable("address_dest")) 
                query.append_where(AND, _WHERE("destmac", LIKE, 
                            connection->variable_cache_as<std::string>("address_dest")));

            if (connection->has_cached_variable("address_trans")) 
                query.append_where(AND, _WHERE("transmac", LIKE, 
                            connection->variable_cache_as<std::string>("address_trans")));

            if (connection->has_cached_variable("location_lat_min"))
                query.append_where(AND, _WHERE("lat", GE, 
                            connection->variable_cache_as<double>("location_lat_min")));

            if (connection->has_cached_variable("location_lon_min"))
                query.append_where(AND, _WHERE("lon", GE, 
                            connection->variable_cache_as<double>("location_lon_min")));

            if (connection->has_cached_variable("location_lat_max"))
                query.append_where(AND, _WHERE("lat", LE, 
                            connection->variable_cache_as<double>("location_lat_max")));

            if (connection->has_cached_variable("location_lon_max"))
                query.append_where(AND, _WHERE("lon", LE, 
                            connection->variable_cache_as<double>("location_lon_max")));

            if (connection->has_cached_variable("size_min"))
                query.append_where(AND, _WHERE("packet_len", GE, 
                            connection->variable_cache_as<long int>("size_min")));

            if (connection->has_cached_variable("size_max"))
                query.append_where(AND, _WHERE("packet_len", LE, 
                            connection->variable_cache_as<long int>("size_max")));

            if (connection->has_cached_variable("limit"))
                query.append_clause(LIMIT, connection->variable_cache_as<unsigned long>("limit"));

        } catch (const std::exception& e) {
            connection->httpcode = 500;
            return MHD_YES;
        }

        kis_net_httpd_buffer_stream_aux *saux = (kis_net_httpd_buffer_stream_aux *) connection->custom_extension;
        auto streamtracker = Globalreg::fetch_mandatory_global_as<stream_tracker>();

        auto *dbrb = new pcap_stream_database(Globalreg::globalreg, saux->get_rbhandler());

        saux->set_aux(dbrb,
                [dbrb,streamtracker](kis_net_httpd_buffer_stream_aux *aux) {
                streamtracker->remove_streamer(dbrb->get_stream_id());
                if (aux->aux != NULL) {
                delete (pcap_stream_database *) (aux->aux);
                }
                });

        streamtracker->register_streamer(dbrb, "kismetdb.pcapng",
                "pcapng", "httpd", "filtered pcapng from kismetdb");

        // Get the list of all the interfaces we know about in the database and push them into the
        // pcapng handler
        auto datasource_query = _SELECT(db, "datasources", {"uuid", "name", "interface"});

        for (auto ds : datasource_query)  {
            dbrb->add_database_interface(sqlite3_column_as<std::string>(ds, 0),
                    sqlite3_column_as<std::string>(ds, 1),
                    sqlite3_column_as<std::string>(ds, 2));
        }

        // Database handler registers itself as timing out so this should be OK to just blitz through
        // now, we'll block as necessary
        for (auto p : query) {
            if (dbrb->pcapng_write_database_packet(
                        sqlite3_column_as<std::uint64_t>(p, 0),
                        sqlite3_column_as<std::uint64_t>(p, 1),
                        sqlite3_column_as<std::string>(p, 2),
                        sqlite3_column_as<unsigned int>(p, 3),
                        sqlite3_column_as<std::string>(p, 4)) < 0) {
                return MHD_YES;
            }
        }
    }

    return MHD_YES;
}

int kis_database_logfile::httpd_post_complete(kis_net_httpd_connection *concls) {
    std::string stripped = httpd_strip_suffix(concls->url);
    std::string suffix = httpd_get_suffix(concls->url);

    shared_structured structdata;
    shared_structured filterdata;

    if (!httpd->has_valid_session(concls, true)) {
        concls->httpcode = 503;
        return MHD_YES;
    }

    if (stripped.find("/logging/kismetdb/pcap/") == 0 && suffix == "pcapng") {
        if (db == nullptr || !db_enabled) {
            concls->httpcode = 500;
            return MHD_YES;
        }

        try {
            if (concls->variable_cache.find("json") != 
                    concls->variable_cache.end()) {
                structdata =
                    std::make_shared<structured_json>(concls->variable_cache["json"]->str());

                if (structdata != nullptr) {
                    if (structdata->has_key("filter")) {
                        filterdata = structdata->get_structured_by_key("filter");

                        if (!filterdata->is_dictionary()) 
                            throw structured_data_exception("expected filter to be a dictionary");
                    }
                }
            }
        } catch(const structured_data_exception& e) {
            auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
            auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

            std::ostream stream(streambuf);

            saux->set_aux(streambuf, 
                    [](kis_net_httpd_buffer_stream_aux *aux) {
                    if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
                    });

            // Set our sync function which is called by the webserver side before we
            // clean up...
            saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
                    if (aux->aux != NULL) {
                    ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                    }
                    });

            stream << "Invalid request: ";
            stream << e.what();
            concls->httpcode = 400;
            return MHD_YES;
        }
    }

    using namespace kissqlite3;
    auto query = _SELECT(db, "packets", {"ts_sec", "ts_usec", "datasource", "dlt", "packet"});

    if (filterdata != nullptr) {
        try {
            if (filterdata->has_key("timestamp_start")) {
                // Break the double timestamp into two integers
                double intpart, fractpart;
                fractpart = modf(filterdata->key_as_number("timestamp_start"), &intpart);
                query.append_where(AND, _WHERE("ts_sec", GT, intpart, OR,
                           "ts_sec", EQ, intpart, AND, "ts_usec", GE, fractpart * 1000000));
            }

            if (filterdata->has_key("timestamp_end")) {
                // Break the double timestamp into two integers
                double intpart, fractpart;
                fractpart = modf(filterdata->key_as_number("timestamp_end"), &intpart);
                query.append_where(AND, _WHERE("ts_sec", LT, intpart, OR,
                           "ts_sec", EQ, intpart, AND, "ts_usec", LE, fractpart * 1000000));
            }

            if (filterdata->has_key("datasource")) 
                query.append_where(AND, 
                        _WHERE("datasource", LIKE, filterdata->key_as_string("datasource")));

            if (filterdata->has_key("device_id")) 
                query.append_where(AND, _WHERE("devkey", LIKE, filterdata->key_as_string("device_id")));

            if (filterdata->has_key("dlt")) 
                query.append_where(AND, _WHERE("dlt", EQ, filterdata->key_as_number("dlt")));

            if (filterdata->has_key("frequency")) 
                query.append_where(AND, 
                        _WHERE("frequency", EQ, filterdata->key_as_number("frequency")));

            if (filterdata->has_key("frequency_min")) 
                query.append_where(AND, 
                        _WHERE("frequency", GE, filterdata->key_as_number("frequency_min")));

            if (filterdata->has_key("frequency_max")) 
                query.append_where(AND, 
                        _WHERE("frequency", LE, filterdata->key_as_number("frequency_max")));

            /*
            if (filterdata->has_key("channel")) 
                query.append_where(AND, _WHERE("CHANNEL", LIKE, filterdata->key_as_number("channel")));
                */

            if (filterdata->has_key("signal_min"))
                query.append_where(AND, _WHERE("signal", GE, filterdata->key_as_number("signal_min")));

            if (filterdata->has_key("signal_max"))
                query.append_where(AND, _WHERE("signal", LE, filterdata->key_as_number("signal_max")));

            if (filterdata->has_key("address_source")) 
                query.append_where(AND, 
                        _WHERE("sourcemac", LIKE, filterdata->key_as_string("address_source")));

            if (filterdata->has_key("address_dest")) 
                query.append_where(AND, 
                        _WHERE("destmac", LIKE, filterdata->key_as_string("address_dest")));

            if (filterdata->has_key("address_trans")) 
                query.append_where(AND, 
                        _WHERE("transmac", LIKE, filterdata->key_as_string("address_trans")));

            if (filterdata->has_key("location_lat_min"))
                query.append_where(AND, 
                        _WHERE("lat", GE, filterdata->key_as_number("location_lat_min")));

            if (filterdata->has_key("location_lon_min"))
                query.append_where(AND, 
                        _WHERE("lon", GE, filterdata->key_as_number("location_lon_min")));

            if (filterdata->has_key("location_lat_max"))
                query.append_where(AND, 
                        _WHERE("lat", LE, filterdata->key_as_number("location_lat_max")));

            if (filterdata->has_key("location_lon_max"))
                query.append_where(AND, 
                        _WHERE("lon", LE, filterdata->key_as_number("location_lon_max")));

            if (filterdata->has_key("size_min"))
                query.append_where(AND, _WHERE("packet_len", GE, filterdata->key_as_number("size_min")));

            if (filterdata->has_key("size_max"))
                query.append_where(AND, _WHERE("packet_len", LE, filterdata->key_as_number("size_max")));

            if (filterdata->has_key("limit"))
                query.append_clause(LIMIT, filterdata->key_as_number("limit"));

        } catch (const structured_data_exception& e) {
            auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
            auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

            std::ostream stream(streambuf);

            saux->set_aux(streambuf, 
                    [](kis_net_httpd_buffer_stream_aux *aux) {
                    if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
                    });

            // Set our sync function which is called by the webserver side before we
            // clean up...
            saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
                    if (aux->aux != NULL) {
                    ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                    }
                    });

            stream << "Invalid request: ";
            stream << e.what();
            concls->httpcode = 400;
            return MHD_YES;
        }
    }

    // std::cout << query << std::endl;

    kis_net_httpd_buffer_stream_aux *saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streamtracker = Globalreg::fetch_mandatory_global_as<stream_tracker>();

    auto *dbrb = new pcap_stream_database(Globalreg::globalreg, saux->get_rbhandler());

    saux->set_aux(dbrb,
            [dbrb,streamtracker](kis_net_httpd_buffer_stream_aux *aux) {
                streamtracker->remove_streamer(dbrb->get_stream_id());
                if (aux->aux != NULL) {
                    delete (pcap_stream_database *) (aux->aux);
                }
            });

    streamtracker->register_streamer(dbrb, "kismetdb.pcapng",
            "pcapng", "httpd", "filtered pcapng from kismetdb");

    // Get the list of all the interfaces we know about in the database and push them into the
    // pcapng handler
    auto datasource_query = _SELECT(db, "datasources", {"uuid", "name", "interface"});

    for (auto ds : datasource_query)  {
        dbrb->add_database_interface(sqlite3_column_as<std::string>(ds, 0),
                sqlite3_column_as<std::string>(ds, 1),
                sqlite3_column_as<std::string>(ds, 2));
    }

    // Database handler registers itself as timing out so this should be OK to just blitz through
    // now, we'll block as necessary
    for (auto p : query) {
        if (dbrb->pcapng_write_database_packet(
                    sqlite3_column_as<std::uint64_t>(p, 0),
                    sqlite3_column_as<std::uint64_t>(p, 1),
                    sqlite3_column_as<std::string>(p, 2),
                    sqlite3_column_as<unsigned int>(p, 3),
                    sqlite3_column_as<std::string>(p, 4)) < 0) {
            return MHD_YES;
        }
    }

    return MHD_YES;
}

unsigned int kis_database_logfile::packet_drop_endpoint_handler(std::ostream& ostream,
        const std::string& uri,
        shared_structured structured, kis_net_httpd_connection::variable_cache_map& postvars) {

    using namespace kissqlite3;

    if (!db_enabled) {
        ostream << "Illegal request: kismetdb log not enabled\n";
        return 400;
    }

    if (structured == nullptr) {
        ostream << "Expected 'drop_before' in command dictionary\n";
        return 400;
    }

    try {
        if (structured->has_key("drop_before")) {
            auto drop_query = 
                _DELETE(db, "packets", _WHERE("ts_sec", LE, 
                            structured->key_as_number("drop_before")));

        } else {
            throw std::runtime_error("Expected 'drop_before' in command dictionary");
        }
    } catch (const std::exception& e) {
        ostream << e.what() << "\n";
        return 400;
    }

    ostream << "Packets removed\n";
    return 200;
}

unsigned int kis_database_logfile::make_poi_endp_handler(std::ostream& ostream, 
        const std::string& uri, shared_structured structured,
        kis_net_httpd_connection::variable_cache_map& postvars) {

    if (!db_enabled) {
        ostream << "Illegal request: kismetdb log not enabled\n";
        return 400;
    }

    struct timeval tv;
    gettimeofday(&tv, nullptr);
    std::string poi_data;

    if (structured != nullptr) {
        if (structured->has_key("note")) {
            poi_data = "{\"note\": \"" +
                json_adapter::sanitize_string(structured->key_as_string("note")) +
                        "\"}";
        }
    }

    std::shared_ptr<kis_gps_packinfo> loc;

    if (gpstracker != nullptr) 
        loc = std::shared_ptr<kis_gps_packinfo>(gpstracker->get_best_location());

    log_snapshot(loc.get(), tv, "POI", poi_data);

    ostream << "POI created\n";
    return 200;
}

std::shared_ptr<tracker_element> kis_database_logfile::list_poi_endp_handler() {
    return std::make_shared<tracker_element_vector>();
}

pcap_stream_database::pcap_stream_database(global_registry *in_globalreg,
        std::shared_ptr<buffer_handler_generic> in_handler) :
        pcap_stream_ringbuf(Globalreg::globalreg, in_handler, nullptr, nullptr, true),
        next_pcap_intf_id {0} {

    // Populate a junk interface
    add_database_interface("0", "lo", "Placeholder for missing interface");
}

pcap_stream_database::~pcap_stream_database() {
}

void pcap_stream_database::stop_stream(std::string in_reason) {
    handler->protocol_error();
}

void pcap_stream_database::add_database_interface(const std::string& in_uuid, const std::string& in_interface,
        const std::string& in_name) {
    
    if (db_uuid_intf_map.find(in_uuid) != db_uuid_intf_map.end())
        return;

    auto intf = std::make_shared<db_interface>(in_uuid, in_interface, in_name);
    intf->pcapnum = next_pcap_intf_id;
    next_pcap_intf_id++;

    db_uuid_intf_map[in_uuid] = intf;
}

int pcap_stream_database::pcapng_write_database_packet(uint64_t time_s, uint64_t time_us,
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

    auto blocks = std::vector<data_block>{};
    blocks.push_back(data_block((uint8_t *) data.data(), data.length()));

    struct timeval ts;
    ts.tv_sec = time_s;
    ts.tv_usec = time_us;

    return pcapng_write_packet(ng_interface_id, &ts, blocks);
}

