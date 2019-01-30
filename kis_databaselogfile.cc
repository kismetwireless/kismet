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

#include "globalregistry.h"
#include "messagebus.h"

#include "json_adapter.h"
#include "packetchain.h"
#include "kis_datasource.h"

#include "kis_databaselogfile.h"

#include "structured.h"
#include "kismet_json.h"

#include "sqlite3_cpp11.h"

KisDatabaseLogfile::KisDatabaseLogfile():
    KisLogfile(SharedLogBuilder(NULL)), 
    KisDatabase(Globalreg::globalreg, "kismetlog"),
    LifetimeGlobal(),
    Kis_Net_Httpd_Ringbuf_Stream_Handler() {

    std::shared_ptr<Packetchain> packetchain =
        Globalreg::FetchMandatoryGlobalAs<Packetchain>("PACKETCHAIN");

    pack_comp_device = packetchain->RegisterPacketComponent("DEVICE");
    pack_comp_radiodata = packetchain->RegisterPacketComponent("RADIODATA");
    pack_comp_gps = packetchain->RegisterPacketComponent("GPS");
    pack_comp_linkframe = packetchain->RegisterPacketComponent("LINKFRAME");
    pack_comp_datasource = packetchain->RegisterPacketComponent("KISDATASRC");
    pack_comp_common = packetchain->RegisterPacketComponent("COMMON");
    pack_comp_metablob = packetchain->RegisterPacketComponent("METABLOB");

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
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER");

    db_enabled = false;

    packet_drop_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Post_Endpoint>("/logging/kismetdb/pcap/drop", true,
                [this](std::ostream& stream, const std::string& uri,
                    SharedStructured post_structured, 
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return packet_drop_endpoint_handler(stream, uri, post_structured, variable_cache);
                }, nullptr);

    Bind_Httpd_Server();
}

KisDatabaseLogfile::~KisDatabaseLogfile() {
    Log_Close();
}

bool KisDatabaseLogfile::Log_Open(std::string in_path) {
    local_locker dbl(&ds_mutex);

    bool dbr = Database_Open(in_path);

    if (!dbr) {
        _MSG_FATAL("Unable to open KismetDB log at {}", in_path);
        globalreg->fatal_condition = true;
        return false;
    }

    dbr = Database_UpgradeDB();

    if (!dbr) {
        _MSG_FATAL("Unable to update existing KismetDB log at {}", in_path);
        globalreg->fatal_condition = true;
        return false;
    }

    set_int_log_path(in_path);
    set_int_log_open(true);

	_MSG("Opened kismetdb log file '" + in_path + "'", MSGFLAG_INFO);

    if (Globalreg::globalreg->kismet_config->FetchOptBoolean("kis_log_packets", true)) {
        _MSG("Saving packets to the Kismet database log.", MSGFLAG_INFO);
        std::shared_ptr<Packetchain> packetchain =
            Globalreg::FetchMandatoryGlobalAs<Packetchain>("PACKETCHAIN");

        packetchain->RegisterHandler(&KisDatabaseLogfile::packet_handler, this, 
                CHAINPOS_LOGGING, -100);
    }

    db_enabled = true;

    sqlite3_exec(db, "PRAGMA journal_mode=PERSIST", NULL, NULL, NULL);
    
    // Go into transactional mode where we only commit every 10 seconds
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    std::shared_ptr<Timetracker> timetracker = 
        Globalreg::FetchMandatoryGlobalAs<Timetracker>("TIMETRACKER");
    transaction_timer = 
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
            [this](int) -> int {

            local_locker dblock(&ds_mutex);

            sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

            return 1;
        });

    return true;
}

void KisDatabaseLogfile::Log_Close() {
    local_locker dblock(&ds_mutex);

    set_int_log_open(false);

    // Kill the timer
    std::shared_ptr<Timetracker> timetracker = 
        Globalreg::FetchMandatoryGlobalAs<Timetracker>("TIMETRACKER");
    if (timetracker != NULL)
        timetracker->RemoveTimer(transaction_timer);

    // End the transaction
    {
        sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);
    }

    db_enabled = false;

    auto packetchain =
        Globalreg::FetchGlobalAs<Packetchain>("PACKETCHAIN");
    if (packetchain != NULL) 
        packetchain->RemoveHandler(&KisDatabaseLogfile::packet_handler, CHAINPOS_LOGGING);

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

    Database_Close();
}

int KisDatabaseLogfile::Database_UpgradeDB() {
    local_locker dblock(&ds_mutex);

    unsigned int dbv = Database_GetDBVersion();
    std::string sql;
    int r;
    char *sErrMsg = NULL;

    if (db == NULL)
        return 0;

    if (dbv < 1) {
        sql =
            "CREATE TABLE devices ("
            
            "first_time INT, " // Time seen
            "last_time INT, "

            "devkey TEXT, " // Device key

            "phyname TEXT, " // Phy records
            "devmac TEXT, "

            "strongest_signal INT, " // Strongest signal

            "min_lat INT, " // Normalized locational bounding rectangle
            "min_lon INT, "
            "max_lat INT, "
            "max_lon INT, "

            "avg_lat INT, " // Average location
            "avg_lon INT, "

            "bytes_data INT, " // Amount of data seen on device

            "type TEXT, " // PHY specific type

            "device BLOB, " // Actual device
            
            "UNIQUE(phyname, devmac) ON CONFLICT REPLACE)";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Kismet log was unable to create devices table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            Log_Close();
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

            "lat INT, " // Normalized location
            "lon INT, "

            "packet_len INT, " // Packet length

            "signal INT, " // Signal level

            "datasource TEXT, " // UUID of data source

            "dlt INT, " // pcap data - datalinktype and packet bin
            "packet BLOB, "

            "error INT" // Packet was flagged as invalid
            ")";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Kismet log was unable to create packet table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            Log_Close();
            return -1;
        }

        sql =
            "CREATE TABLE data ("

            "ts_sec INT, " // Timestamps
            "ts_usec INT, "

            "phyname TEXT, " // Packet name and phy
            "devmac TEXT, "

            "lat INT, " // Normalized location
            "lon INT, "

            "datasource TEXT, " // UUID of data source

            "type TEXT, " // Type of arbitrary record

            "json BLOB " // Arbitrary JSON record
            ")";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Kismet log was unable to create data table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            Log_Close();
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
            Log_Close();
            return -1;
        }

        sql =
            "CREATE TABLE alerts ("

            "ts_sec INT, " // Timestamps
            "ts_usec INT, "

            "phyname TEXT, " // Alert phy
            "devmac TEXT, " // Primary device associated with alert

            "lat INT, " // Normalized location
            "lon INT, "

            "header TEXT, " // Alert header/type

            "json BLOB " // Alert JSON record
            ")";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Kismet log was unable to create alerts table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            Log_Close();
            return -1;
        }

        sql =
            "CREATE TABLE messages ("

            "ts_sec INT, " // Timestamps

            "lat INT, " // Normalized location
            "lon INT, "

            "msgtype TEXT, " // Message type
            
            "message TEXT " // message

            ")";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Kismet log was unable to create messages table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            Log_Close();
            return -1;
        }

        sql =
            "CREATE TABLE snapshots ("

            "ts_sec INT, " // Timestamps
            "ts_usec INT, "

            "lat INT, " // Normalized location
            "lon INT, "

            "snaptype TEXT, " // Type of snapshot record

            "json BLOB " // Arbitrary record

            ")";

        r = sqlite3_exec(db, sql.c_str(),
                [] (void *, int, char **, char **) -> int { return 0; }, NULL, &sErrMsg);

        if (r != SQLITE_OK) {
            _MSG("Kismet log was unable to create messages table in " + ds_dbfile + ": " +
                    std::string(sErrMsg), MSGFLAG_ERROR);
            Log_Close();
            return -1;
        }


    }

    Database_SetDBVersion(4);

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
        _MSG("KisDatabaseLogfile unable to prepare database insert for devices in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        Log_Close();
        return -1;
    }

    sql =
        "INSERT INTO packets "
        "(ts_sec, ts_usec, phyname, "
        "sourcemac, destmac, transmac, devkey, frequency, " 
        "lat, lon, "
        "packet_len, signal, "
        "datasource, "
        "dlt, packet, "
        "error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &packet_stmt, &packet_pz);

    if (r != SQLITE_OK) {
        _MSG("KisDatabaseLogfile unable to prepare database insert for packets in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        Log_Close();
        return -1;
    }

    sql =
        "INSERT INTO data "
        "(ts_sec, ts_usec, "
        "phyname, devmac, "
        "lat, lon, "
        "datasource, "
        "type, json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    r = sqlite3_prepare(db, sql.c_str(), sql.length(), &data_stmt, &data_pz);

    if (r != SQLITE_OK) {
        _MSG("KisDatabaseLogfile unable to prepare database insert for data in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        Log_Close();
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
        _MSG("KisDatabaseLogfile unable to prepare database insert for datasources in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        Log_Close();
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
        _MSG("KisDatabaseLogfile unable to prepare database insert for alerts in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        Log_Close();
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
        _MSG("KisDatabaseLogfile unable to prepare database insert for messages in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        Log_Close();
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
        _MSG("KisDatabaseLogfile unable to prepare database insert for snapshots in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        Log_Close();
        return -1;
    }

    return 1;
}

int KisDatabaseLogfile::log_devices(std::shared_ptr<TrackerElementVector> in_devices) {
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

    for (auto i : *in_devices) {
        if (i == NULL)
            continue;

        auto d = std::static_pointer_cast<kis_tracked_device_base>(i);

        phystring = d->get_phyname();
        macstring = d->get_macaddr().Mac2String();
        typestring = d->get_type_string();
        keystring = d->get_key().as_string();

        int spos = 1;

        std::stringstream sstr;

        // Serialize the device
        JsonAdapter::Pack(sstr, d, NULL);
        std::string streamstring = sstr.str();

        {
            local_locker dblock(&ds_mutex);
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
                sqlite3_bind_int64(device_stmt, spos++, 
                        d->get_location()->get_min_loc()->get_lat() * 100000);
                sqlite3_bind_int64(device_stmt, spos++,
                        d->get_location()->get_min_loc()->get_lon() * 100000);
                sqlite3_bind_int64(device_stmt, spos++,
                        d->get_location()->get_max_loc()->get_lat() * 100000);
                sqlite3_bind_int64(device_stmt, spos++,
                        d->get_location()->get_max_loc()->get_lon() * 100000);
                sqlite3_bind_int64(device_stmt, spos++,
                        d->get_location()->get_avg_loc()->get_lat() * 100000);
                sqlite3_bind_int64(device_stmt, spos++,
                        d->get_location()->get_avg_loc()->get_lon() * 100000);
            } else {
                // Empty location
                sqlite3_bind_int(device_stmt, spos++, 0);
                sqlite3_bind_int(device_stmt, spos++, 0);
                sqlite3_bind_int(device_stmt, spos++, 0);
                sqlite3_bind_int(device_stmt, spos++, 0);
                sqlite3_bind_int(device_stmt, spos++, 0);
                sqlite3_bind_int(device_stmt, spos++, 0);
            }

            sqlite3_bind_int64(device_stmt, spos++, d->get_datasize());
            sqlite3_bind_text(device_stmt, spos++, typestring.c_str(), 
                    typestring.length(), SQLITE_TRANSIENT);

            sqlite3_bind_blob(device_stmt, spos++, streamstring.c_str(), 
                    streamstring.length(), SQLITE_TRANSIENT);

            if (sqlite3_step(device_stmt) != SQLITE_DONE) {
                _MSG("KisDatabaseLogfile unable to insert device in " +
                        ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
                Log_Close();
                return -1;
            }
        }
    }

    return 1;
}

int KisDatabaseLogfile::log_packet(kis_packet *in_pack) {
    if (!db_enabled)
        return 0;

    std::string phystring;
    std::string macstring;
    std::string deststring;
    std::string transstring;
    std::string keystring;
    std::string sourceuuidstring;
    double frequency;

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

    Kis_Phy_Handler *phyh = NULL;

    // Packets are no longer a 1:1 with a device
    keystring = "0";

    if (commoninfo != NULL) {
        phyh = devicetracker->FetchPhyHandler(commoninfo->phyid);
        macstring = commoninfo->source.Mac2String();
        deststring = commoninfo->dest.Mac2String();
        transstring = commoninfo->transmitter.Mac2String();
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
        phystring = phyh->FetchPhyName();


    if (datasrc != NULL) {
        sourceuuidstring = datasrc->ref_source->get_source_uuid().UUID2String();
    } else {
        sourceuuidstring = "00000000-0000-0000-0000-000000000000";
    }

    {
        local_locker dblock(&ds_mutex);
        sqlite3_reset(packet_stmt);

        sqlite3_bind_int64(packet_stmt, 1, in_pack->ts.tv_sec);
        sqlite3_bind_int64(packet_stmt, 2, in_pack->ts.tv_usec);

        sqlite3_bind_text(packet_stmt, 3, phystring.c_str(), phystring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(packet_stmt, 4, macstring.c_str(), macstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(packet_stmt, 5, deststring.c_str(), deststring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(packet_stmt, 6, transstring.c_str(), transstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(packet_stmt, 7, keystring.c_str(), keystring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_double(packet_stmt, 8, frequency);

        if (gpsdata != NULL) {
            sqlite3_bind_int64(packet_stmt, 9, gpsdata->lat * 100000);
            sqlite3_bind_int64(packet_stmt, 10, gpsdata->lon * 100000);
        } else {
            sqlite3_bind_int(packet_stmt, 9, 0);
            sqlite3_bind_int(packet_stmt, 10, 0);
        }

        if (chunk != NULL) {
            sqlite3_bind_int64(packet_stmt, 11, chunk->length);
        } else {
            sqlite3_bind_int(packet_stmt, 11, 0);
        }

        if (radioinfo != NULL) {
            sqlite3_bind_int(packet_stmt, 12, radioinfo->signal_dbm);
        } else {
            sqlite3_bind_int(packet_stmt, 12, 0);
        }

        sqlite3_bind_text(packet_stmt, 13, sourceuuidstring.c_str(), 
                sourceuuidstring.length(), SQLITE_TRANSIENT);

        if (chunk != NULL) {
            sqlite3_bind_int(packet_stmt, 14, chunk->dlt);
            sqlite3_bind_blob(packet_stmt, 15, (const char *) chunk->data, chunk->length, 0);
        } else {
            sqlite3_bind_int(packet_stmt, 14, -1);
            sqlite3_bind_text(packet_stmt, 15, "", 0, SQLITE_TRANSIENT);
        }

        sqlite3_bind_int(packet_stmt, 16, in_pack->error);

        if (sqlite3_step(packet_stmt) != SQLITE_DONE) {
            _MSG("KisDatabaseLogfile unable to insert packet in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            Log_Close();
            return -1;
        }
    }

    // If the packet has a metablob record, log that
    if (metablob != NULL) {
        mac_addr smac("00:00:00:00:00:00");
        uuid puuid;

        if (commoninfo != NULL)
            smac = commoninfo->source;

        if (datasrc != NULL) 
            puuid = datasrc->ref_source->get_source_uuid();

        log_data(gpsdata, in_pack->ts, phystring, smac, puuid,
                metablob->meta_type, metablob->meta_data);
    }

    return 1;
}

int KisDatabaseLogfile::log_data(kis_gps_packinfo *gps, struct timeval tv, 
        std::string phystring, mac_addr devmac, uuid datasource_uuid, 
        std::string type, std::string json) {

    if (!db_enabled)
        return 0;

    std::string macstring = devmac.Mac2String();
    std::string uuidstring = datasource_uuid.UUID2String();

    {
        local_locker dblock(&ds_mutex);
        sqlite3_reset(data_stmt);

        sqlite3_bind_int64(data_stmt, 1, tv.tv_sec);
        sqlite3_bind_int64(data_stmt, 2, tv.tv_usec);

        sqlite3_bind_text(data_stmt, 3, phystring.c_str(), phystring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(data_stmt, 4, macstring.c_str(), macstring.length(), SQLITE_TRANSIENT);

        if (gps != NULL) {
            sqlite3_bind_int64(data_stmt, 5, gps->lat * 100000);
            sqlite3_bind_int64(data_stmt, 6, gps->lon * 100000);
        } else {
            sqlite3_bind_int(data_stmt, 5, 0);
            sqlite3_bind_int(data_stmt, 6, 0);
        }

        sqlite3_bind_text(data_stmt, 7, uuidstring.c_str(), uuidstring.length(), SQLITE_TRANSIENT);

        sqlite3_bind_text(data_stmt, 8, type.data(), type.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(data_stmt, 9, json.data(), json.length(), SQLITE_TRANSIENT);

        if (sqlite3_step(data_stmt) != SQLITE_DONE) {
            _MSG("KisDatabaseLogfile unable to insert data in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            Log_Close();
            return -1;
        }
    }

    return 1;
}

int KisDatabaseLogfile::log_datasources(SharedTrackerElement in_datasource_vec) {
    int r;

    if (!db_enabled)
        return 0;

    for (auto ds : *(std::static_pointer_cast<TrackerElementVector>(in_datasource_vec))) {
        r = log_datasource(ds);

        if (r < 0)
            return r;
    }

    return 1;
}

int KisDatabaseLogfile::log_datasource(SharedTrackerElement in_datasource) {

    if (!db_enabled)
        return 0;

    std::shared_ptr<KisDatasource> ds =
        std::static_pointer_cast<KisDatasource>(in_datasource);

    std::string uuidstring = ds->get_source_uuid().UUID2String();
    std::string typestring = ds->get_source_builder()->get_source_type();
    std::string defstring = ds->get_source_definition();
    std::string namestring = ds->get_source_name();
    std::string intfstring = ds->get_source_interface();

    std::stringstream ss;
    std::string jsonstring;

    JsonAdapter::Pack(ss, in_datasource, NULL);
    jsonstring = ss.str();

    {
        local_locker dblock(&ds_mutex);
        sqlite3_reset(datasource_stmt);

        sqlite3_bind_text(datasource_stmt, 1, uuidstring.data(), uuidstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(datasource_stmt, 2, typestring.data(), typestring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(datasource_stmt, 3, defstring.data(), defstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(datasource_stmt, 4, namestring.data(), namestring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(datasource_stmt, 5, intfstring.data(), intfstring.length(), SQLITE_TRANSIENT);

        sqlite3_bind_blob(datasource_stmt, 6, jsonstring.data(), jsonstring.length(), SQLITE_TRANSIENT);

        if (sqlite3_step(datasource_stmt) != SQLITE_DONE) {
            _MSG("KisDatabaseLogfile unable to insert datasource in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            Log_Close();
            return -1;
        }
    }

    return 1;
}

int KisDatabaseLogfile::log_alert(std::shared_ptr<tracked_alert> in_alert) {
    if (!db_enabled)
        return 0;

    std::string macstring = in_alert->get_transmitter_mac().Mac2String();
    std::string phystring = devicetracker->FetchPhyName(in_alert->get_phy());
    std::string headerstring = in_alert->get_header();

    std::stringstream ss;
    std::string jsonstring;

    JsonAdapter::Pack(ss, in_alert, NULL);
    jsonstring = ss.str();

    // Break the double timestamp into two integers
    double intpart, fractpart;
    fractpart = modf(in_alert->get_timestamp(), &intpart);

    {
        local_locker dblock(&ds_mutex);
        sqlite3_reset(alert_stmt);

        sqlite3_bind_int64(alert_stmt, 1, intpart);
        sqlite3_bind_int64(alert_stmt, 2, fractpart * 1000000);

        sqlite3_bind_text(alert_stmt, 3, phystring.c_str(), phystring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(alert_stmt, 4, macstring.c_str(), macstring.length(), SQLITE_TRANSIENT);

        if (in_alert->get_location()->get_valid()) {
            sqlite3_bind_int64(alert_stmt, 5, in_alert->get_location()->get_lat() * 100000);
            sqlite3_bind_int64(alert_stmt, 6, in_alert->get_location()->get_lon() * 100000);
        } else {
            sqlite3_bind_int(alert_stmt, 5, 0);
            sqlite3_bind_int(alert_stmt, 6, 0);
        }

        sqlite3_bind_text(alert_stmt, 7, headerstring.c_str(), headerstring.length(), SQLITE_TRANSIENT);
        sqlite3_bind_blob(alert_stmt, 8, jsonstring.data(), jsonstring.length(), SQLITE_TRANSIENT);

        if (sqlite3_step(alert_stmt) != SQLITE_DONE) {
            _MSG("KisDatabaseLogfile unable to insert alert in " +
                    ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
            Log_Close();
            return -1;
        }
    }

    return 1;
}

int KisDatabaseLogfile::log_snapshot(kis_gps_packinfo *gps, struct timeval tv,
        std::string snaptype, std::string json) {

    if (!db_enabled)
        return 0;

    local_locker dblock(&ds_mutex);
    sqlite3_reset(snapshot_stmt);

    sqlite3_bind_int64(snapshot_stmt, 1, tv.tv_sec);
    sqlite3_bind_int64(snapshot_stmt, 2, tv.tv_usec);

    if (gps != NULL) {
        sqlite3_bind_int64(snapshot_stmt, 3, gps->lat * 100000);
        sqlite3_bind_int64(snapshot_stmt, 4, gps->lon * 100000);
    } else {
        sqlite3_bind_int(snapshot_stmt, 3, 0);
        sqlite3_bind_int(snapshot_stmt, 4, 0);
    }

    sqlite3_bind_text(snapshot_stmt, 5, snaptype.c_str(), snaptype.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(snapshot_stmt, 6, json.data(), json.length(), SQLITE_TRANSIENT);

    if (sqlite3_step(snapshot_stmt) != SQLITE_DONE) {
        _MSG("KisDatabaseLogfile unable to insert snapshot in " +
                ds_dbfile + ":" + std::string(sqlite3_errmsg(db)), MSGFLAG_ERROR);
        Log_Close();
        return -1;
    }

    return 1;
}

int KisDatabaseLogfile::packet_handler(CHAINCALL_PARMS) {
    // Extremely basic shim to our built-in logging
    KisDatabaseLogfile *logfile = (KisDatabaseLogfile *) auxdata;

    return logfile->log_packet(in_pack);
}

void KisDatabaseLogfile::Usage(const char *argv0) {

}

bool KisDatabaseLogfile::Httpd_VerifyPath(const char *path, const char *method) {
    std::string stripped = Httpd_StripSuffix(path);
    std::string suffix = Httpd_GetSuffix(path);

    if (stripped.find("/logging/kismetdb/pcap/") == 0 && suffix == "pcapng" && db_enabled)
        return true;

    return false;
}

int KisDatabaseLogfile::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) {

    using namespace kissqlite3;

    std::string stripped = Httpd_StripSuffix(connection->url);
    std::string suffix = Httpd_GetSuffix(connection->url);

    if (!httpd->HasValidSession(connection, true)) {
        connection->httpcode = 503;
        return MHD_YES;
    }

    if (stripped.find("/logging/kismetdb/pcap/") == 0 && suffix == "pcapng") {
        if (db == nullptr || db_enabled) {
            connection->httpcode = 500;
            return MHD_YES;
        }

        using namespace kissqlite3;
        auto query = _SELECT(db, "packets", {"ts_sec", "ts_usec", "datasource", "dlt", "packet"});

        try {
            if (connection->has_cached_variable("timestamp_start"))
                query.append_where(AND, _WHERE("ts_sec", GE, 
                            connection->variable_cache_as<uint64_t>("timestamp_start")));

            if (connection->has_cached_variable("timestamp_end"))
                query.append_where(AND, _WHERE("ts_sec", LE,
                            connection->variable_cache_as<uint64_t>("timestamp_end")));

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
                            connection->variable_cache_as<long int>("location_lat_min") * 100000));

            if (connection->has_cached_variable("location_lon_min"))
                query.append_where(AND, _WHERE("lon", GE, 
                            connection->variable_cache_as<long int>("location_lon_min") * 100000));

            if (connection->has_cached_variable("location_lat_max"))
                query.append_where(AND, _WHERE("lat", LE, 
                            connection->variable_cache_as<long int>("location_lat_max") * 100000));

            if (connection->has_cached_variable("location_lon_max"))
                query.append_where(AND, _WHERE("lon", LE, 
                            connection->variable_cache_as<long int>("location_lon_max") * 100000));

            if (connection->has_cached_variable("size_min"))
                query.append_where(AND, _WHERE("size", GE, 
                            connection->variable_cache_as<long int>("size_min")));

            if (connection->has_cached_variable("size_max"))
                query.append_where(AND, _WHERE("size_max", LE, 
                            connection->variable_cache_as<long int>("size_max")));

            if (connection->has_cached_variable("limit"))
                query.append_clause(LIMIT, connection->variable_cache_as<unsigned long>("limit"));

        } catch (const std::exception& e) {
            connection->httpcode = 500;
            return MHD_YES;
        }

        Kis_Net_Httpd_Buffer_Stream_Aux *saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;
        auto streamtracker = Globalreg::FetchMandatoryGlobalAs<StreamTracker>();

        auto *dbrb = new Pcap_Stream_Database(Globalreg::globalreg, saux->get_rbhandler());

        saux->set_aux(dbrb,
                [dbrb,streamtracker](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                streamtracker->remove_streamer(dbrb->get_stream_id());
                if (aux->aux != NULL) {
                delete (Pcap_Stream_Database *) (aux->aux);
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

int KisDatabaseLogfile::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    std::string stripped = Httpd_StripSuffix(concls->url);
    std::string suffix = Httpd_GetSuffix(concls->url);

    SharedStructured structdata;
    SharedStructured filterdata;

    if (!httpd->HasValidSession(concls, true)) {
        concls->httpcode = 503;
        return MHD_YES;
    }

    if (stripped.find("/logging/kismetdb/pcap/") == 0 && suffix == "pcapng") {
        if (db == nullptr || db_enabled) {
            concls->httpcode = 500;
            return MHD_YES;
        }

        try {
            if (concls->variable_cache.find("json") != 
                    concls->variable_cache.end()) {
                structdata =
                    std::make_shared<StructuredJson>(concls->variable_cache["json"]->str());

                if (structdata != nullptr) {
                    if (structdata->hasKey("filter")) {
                        filterdata = structdata->getStructuredByKey("filter");

                        if (!filterdata->isDictionary()) 
                            throw StructuredDataException("expected filter to be a dictionary");
                    }
                }
            }
        } catch(const StructuredDataException& e) {
            auto saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;
            auto streambuf = new BufferHandlerOStringStreambuf(saux->get_rbhandler());

            std::ostream stream(streambuf);

            saux->set_aux(streambuf, 
                    [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                    if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
                    });

            // Set our sync function which is called by the webserver side before we
            // clean up...
            saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                    if (aux->aux != NULL) {
                    ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
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
            if (filterdata->hasKey("timestamp_start")) 
                query.append_where(AND, 
                        _WHERE("ts_sec", GE, filterdata->getKeyAsNumber("timestamp_start")));

            if (filterdata->hasKey("timestamp_end")) 
                query.append_where(AND, 
                        _WHERE("ts_sec", LE, filterdata->getKeyAsNumber("timestamp_end")));

            if (filterdata->hasKey("datasource")) 
                query.append_where(AND, 
                        _WHERE("datasource", LIKE, filterdata->getKeyAsString("datasource")));

            if (filterdata->hasKey("device_id")) 
                query.append_where(AND, _WHERE("devkey", LIKE, filterdata->getKeyAsString("device_id")));

            if (filterdata->hasKey("dlt")) 
                query.append_where(AND, _WHERE("dlt", EQ, filterdata->getKeyAsNumber("dlt")));

            if (filterdata->hasKey("frequency")) 
                query.append_where(AND, 
                        _WHERE("frequency", EQ, filterdata->getKeyAsNumber("frequency")));

            if (filterdata->hasKey("frequency_min")) 
                query.append_where(AND, 
                        _WHERE("frequency", GE, filterdata->getKeyAsNumber("frequency_min")));

            if (filterdata->hasKey("frequency_max")) 
                query.append_where(AND, 
                        _WHERE("frequency", LE, filterdata->getKeyAsNumber("frequency_max")));

            /*
            if (filterdata->hasKey("channel")) 
                query.append_where(AND, _WHERE("CHANNEL", LIKE, filterdata->getKeyAsNumber("channel")));
                */

            if (filterdata->hasKey("signal_min"))
                query.append_where(AND, _WHERE("signal", GE, filterdata->getKeyAsNumber("signal_min")));

            if (filterdata->hasKey("signal_max"))
                query.append_where(AND, _WHERE("signal", LE, filterdata->getKeyAsNumber("signal_max")));

            if (filterdata->hasKey("address_source")) 
                query.append_where(AND, 
                        _WHERE("sourcemac", LIKE, filterdata->getKeyAsString("address_source")));

            if (filterdata->hasKey("address_dest")) 
                query.append_where(AND, 
                        _WHERE("destmac", LIKE, filterdata->getKeyAsString("address_dest")));

            if (filterdata->hasKey("address_trans")) 
                query.append_where(AND, 
                        _WHERE("transmac", LIKE, filterdata->getKeyAsString("address_trans")));

            if (filterdata->hasKey("location_lat_min"))
                query.append_where(AND, 
                        _WHERE("lat", GE, filterdata->getKeyAsNumber("location_lat_min") * 100000));

            if (filterdata->hasKey("location_lon_min"))
                query.append_where(AND, 
                        _WHERE("lon", GE, filterdata->getKeyAsNumber("location_lon_min") * 100000));

            if (filterdata->hasKey("location_lat_max"))
                query.append_where(AND, 
                        _WHERE("lat", LE, filterdata->getKeyAsNumber("location_lat_max") * 100000));

            if (filterdata->hasKey("location_lon_max"))
                query.append_where(AND, 
                        _WHERE("lon", LE, filterdata->getKeyAsNumber("location_lon_max") * 100000));

            if (filterdata->hasKey("size_min"))
                query.append_where(AND, _WHERE("size", GE, filterdata->getKeyAsNumber("size_min")));

            if (filterdata->hasKey("size_max"))
                query.append_where(AND, _WHERE("size_max", LE, filterdata->getKeyAsNumber("size_max")));

            if (filterdata->hasKey("limit"))
                query.append_clause(LIMIT, filterdata->getKeyAsNumber("limit"));

        } catch (const StructuredDataException& e) {
            auto saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;
            auto streambuf = new BufferHandlerOStringStreambuf(saux->get_rbhandler());

            std::ostream stream(streambuf);

            saux->set_aux(streambuf, 
                    [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                    if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
                    });

            // Set our sync function which is called by the webserver side before we
            // clean up...
            saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                    if (aux->aux != NULL) {
                    ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                    }
                    });

            stream << "Invalid request: ";
            stream << e.what();
            concls->httpcode = 400;
            return MHD_YES;
        }
    }

    // std::cout << query << std::endl;

    Kis_Net_Httpd_Buffer_Stream_Aux *saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;
    auto streamtracker = Globalreg::FetchMandatoryGlobalAs<StreamTracker>();

    auto *dbrb = new Pcap_Stream_Database(Globalreg::globalreg, saux->get_rbhandler());

    saux->set_aux(dbrb,
            [dbrb,streamtracker](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                streamtracker->remove_streamer(dbrb->get_stream_id());
                if (aux->aux != NULL) {
                    delete (Pcap_Stream_Database *) (aux->aux);
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

unsigned int KisDatabaseLogfile::packet_drop_endpoint_handler(std::ostream& ostream,
        const std::string& uri,
        SharedStructured structured, Kis_Net_Httpd_Connection::variable_cache_map& postvars) {

    using namespace kissqlite3;

    if (structured == nullptr) {
        ostream << "Expected 'drop_before' in command dictionary\n";
        return 400;
    }

    try {
        if (structured->hasKey("drop_before")) {
            auto drop_query = 
                _DELETE(db, "packets", _WHERE("ts_sec", LE, 
                            structured->getKeyAsNumber("drop_before")));

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


Pcap_Stream_Database::Pcap_Stream_Database(GlobalRegistry *in_globalreg,
        std::shared_ptr<BufferHandlerGeneric> in_handler) :
        Pcap_Stream_Ringbuf(Globalreg::globalreg, in_handler, nullptr, nullptr, true),
        next_pcap_intf_id {0} {

    // Populate a junk interface
    add_database_interface("0", "lo", "Placeholder for missing interface");
}

Pcap_Stream_Database::~Pcap_Stream_Database() {
}

void Pcap_Stream_Database::stop_stream(std::string in_reason) {
    handler->ProtocolError();
}

void Pcap_Stream_Database::add_database_interface(const std::string& in_uuid, const std::string& in_interface,
        const std::string& in_name) {
    
    if (db_uuid_intf_map.find(in_uuid) != db_uuid_intf_map.end())
        return;

    auto intf = std::make_shared<db_interface>(in_uuid, in_interface, in_name);
    intf->pcapnum = next_pcap_intf_id;
    next_pcap_intf_id++;

    db_uuid_intf_map[in_uuid] = intf;
}

int Pcap_Stream_Database::pcapng_write_database_packet(uint64_t time_s, uint64_t time_us,
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

