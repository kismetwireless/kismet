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

/* The new grand, unified Kismet logging system.
 *
 * The new logfile system combines all the previous Kismet logs into a single entity
 * which can later be extrapolated into the original data types (or all new data types).
 *
 * The new log is based on sqlite3 and is, itself, a database.  It borrows from the nosql
 * methodology by, in general, defining the minimum number of normalized fields and 
 * storing data in traditional JSON format whenever possible.
 *
 * The new log format synergizes with the REST UI to provide dynamic access to 
 * historical data.
 *
 * Docs in docs/dev/log_kismet.md
 *
 */

#ifndef __KISLOGFILE_H__
#define __KISLOGFILE_H__

#include "config.h"

#include <atomic>
#include <memory>
#include <string>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_database.h"
#include "devicetracker.h"
#include "alertracker.h"
#include "logtracker.h"
#include "packetchain.h"
#include "pcapng_stream_ringbuf.h"
#include "sqlite3_cpp11.h"
#include "class_filter.h"
#include "packet_filter.h"
#include "messagebus.h"

// This is a bit of a unique case - because so many things plug into this, it has
// to exist as a global record; we build it like we do any other global record;
// then the builder hooks it, sets the internal builder record, and passed it to
// the logtracker
class KisDatabaseLogfile : public KisLogfile, public KisDatabase, public LifetimeGlobal,
    public Kis_Net_Httpd_Ringbuf_Stream_Handler, public MessageClient, public DeferredStartup {
public:
    static std::string global_name() { return "DATABASELOG"; }

    static std::shared_ptr<KisDatabaseLogfile> 
        create_kisdatabaselog() {
            std::shared_ptr<KisDatabaseLogfile> mon(new KisDatabaseLogfile());
            Globalreg::globalreg->RegisterDeferredGlobal(mon);
            Globalreg::globalreg->RegisterLifetimeGlobal(mon);
            Globalreg::globalreg->InsertGlobal(global_name(), mon);
            return mon;
    }

    KisDatabaseLogfile();
    virtual ~KisDatabaseLogfile();

    virtual void Deferred_Startup() override;
    virtual void Deferred_Shutdown() override;

    void SetDatabaseBuilder(SharedLogBuilder in_builder) {
        builder = in_builder;

        if (builder != nullptr)
            insert(builder);
    }

    virtual bool Log_Open(std::string in_path) override;
    virtual void Log_Close() override;

    virtual int Database_UpgradeDB() override;

    // Log a vector of multiple devices, replacing any old device records
    virtual int log_devices(std::shared_ptr<TrackerElementVector> in_devices);

    // Device logs are non-streaming; we need to know the last time we generated
    // device logs so that we can update just the logs we need.
    virtual time_t get_last_device_log_ts() { return last_device_log; }

    // Log a packet
    virtual int log_packet(kis_packet *in_packet);

    // Log data that isn't a packet; this is a slightly more clunky API because we 
    // can't derive the data from the simple packet interface.  GPS may be null,
    // and other attributes may be empty, if that data is not available
    virtual int log_data(kis_gps_packinfo *gps, struct timeval tv, 
            std::string phystring, mac_addr devmac, uuid datasource_uuid, 
            std::string type, std::string json);

    // Log datasources
    virtual int log_datasources(SharedTrackerElement in_datasource_vec);
    // Log a single datasource
    virtual int log_datasource(SharedTrackerElement in_datasource);

    // Log an alert; takes a standard tracked_alert element
    virtual int log_alert(std::shared_ptr<tracked_alert> in_alert);

    // Log snapshotted data; Slightly clunkier API since it has to allow for
    // entirely generic data
    virtual int log_snapshot(kis_gps_packinfo *gps, struct timeval tv,
            std::string snaptype, std::string json);

    static void Usage(const char *argv0);

    // HTTP handlers
    virtual bool Httpd_VerifyPath(const char *path, const char *method) override;

    virtual int Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) override;

    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) override;

    // Messagebus API
    virtual void ProcessMessage(std::string in_msg, int in_flags) override;

    // Direct access to the filters for setting programatically
    std::shared_ptr<PacketfilterMacaddr> GetPacketFilter() { 
        return packet_mac_filter;
    }

    std::shared_ptr<ClassfilterMacaddr> GetDeviceFilter() {
        return device_mac_filter;
    }

    // Eventbus event we inject when the log is opened
    class EventDblogOpened : public EventbusEvent {
    public:
        static std::string log_type() { return "KISMETDB_LOG_OPEN"; }
        EventDblogOpened() :
            EventbusEvent("KISMETDB_LOG_OPEN") { }
        virtual ~EventDblogOpened() {}
    };

protected:
    // Is the database even enabled?
    std::atomic<bool> db_enabled;

    std::shared_ptr<Devicetracker> devicetracker;
    std::shared_ptr<GpsTracker> gpstracker;

    int pack_comp_linkframe, pack_comp_gps, pack_comp_radiodata,
        pack_comp_device, pack_comp_datasource, pack_comp_common,
        pack_comp_metablob;

    std::atomic<time_t> last_device_log;

    // Prebaked parameterized statements
    sqlite3_stmt *device_stmt;
    const char *device_pz;

    sqlite3_stmt *packet_stmt;
    const char *packet_pz;

    sqlite3_stmt *datasource_stmt;
    const char *datasource_pz;

    sqlite3_stmt *data_stmt;
    const char *data_pz;
    
    sqlite3_stmt *alert_stmt;
    const char *alert_pz;

    sqlite3_stmt *msg_stmt;
    const char *msg_pz;
    
    sqlite3_stmt *snapshot_stmt;
    const char *snapshot_pz;

    static int packet_handler(CHAINCALL_PARMS);

    // Keep track of our commit cycles; to avoid thrashing the filesystem with
    // commit state we run a 10 second tranasction commit loop
    kis_recursive_timed_mutex transaction_mutex;
    int transaction_timer;

    // Packet time limit
    unsigned int packet_timeout;
    int packet_timeout_timer;

    // Device time limit
    unsigned int device_timeout;
    int device_timeout_timer;

    // Snapshot time limit
    unsigned int snapshot_timeout;
    int snapshot_timeout_timer;

    // Message time limit
    unsigned int message_timeout;
    int message_timeout_timer;

    // Alert time limit
    unsigned int alert_timeout;
    int alert_timeout_timer;

    // Packet clearing API
    std::shared_ptr<Kis_Net_Httpd_Simple_Post_Endpoint> packet_drop_endp;
    unsigned int packet_drop_endpoint_handler(std::ostream& stream, const std::string& uri,
            SharedStructured structured, Kis_Net_Httpd_Connection::variable_cache_map& postvars);

    // POI API
    std::shared_ptr<Kis_Net_Httpd_Simple_Post_Endpoint> make_poi_endp;
    unsigned int make_poi_endp_handler(std::ostream& stream, const std::string& uri,
            SharedStructured structured, Kis_Net_Httpd_Connection::variable_cache_map& postvars);

    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> list_poi_endp;
    std::shared_ptr<TrackerElement> list_poi_endp_handler();

    // Device log filter
    std::shared_ptr<ClassfilterMacaddr> device_mac_filter;

    // Packet log filter
    std::shared_ptr<PacketfilterMacaddr> packet_mac_filter;
};

class KisDatabaseLogfileBuilder : public KisLogfileBuilder {
public:
    KisDatabaseLogfileBuilder() :
        KisLogfileBuilder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    KisDatabaseLogfileBuilder(int in_id) :
        KisLogfileBuilder(in_id) {
           
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    KisDatabaseLogfileBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisLogfileBuilder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~KisDatabaseLogfileBuilder() { }

    // Custom builder that fetches the global copy and shoves it back down to the 
    // logfile system instead
    virtual SharedLogfile build_logfile(SharedLogBuilder builder) {
        std::shared_ptr<KisDatabaseLogfile> logfile =
            Globalreg::FetchMandatoryGlobalAs<KisDatabaseLogfile>("DATABASELOG");
        logfile->SetDatabaseBuilder(builder);
        return logfile;
    }

    virtual void initialize() {
        set_log_class("kismet");
        set_log_name("Kismet Unified Log");
        set_stream(true);
        set_singleton(true);
        set_log_description("Unified Kismet log containing device, data source, packet, "
                "alert, and other runtime data");
    }
};

class Pcap_Stream_Database : public Pcap_Stream_Ringbuf {
public:
    Pcap_Stream_Database(GlobalRegistry *in_globalreg, 
            std::shared_ptr<BufferHandlerGeneric> in_handler);

    virtual ~Pcap_Stream_Database();

    virtual void stop_stream(std::string in_reason);

    // Write packet using database metadata, doing a lookup on the interface UUID.  This is more expensive
    // than the numerical lookup but we need to search by UUID regardless and for many single-source feeds
    // the lookup will be a single compare
    virtual int pcapng_write_database_packet(uint64_t time_s, uint64_t time_us,
            const std::string& interface_uuid, unsigned int dlt, const std::string& data);

    // Populate the interface list with all the interfaces from the database, we'll
    // assign pcapng IDs to them as they get used so only included interfaces will show up
    // in the pcapng idb list
    virtual void add_database_interface(const std::string& in_uuid, const std::string& in_interface,
            const std::string& in_namet);

protected:
    // Record of all interfaces from the database, assign them pcapng idb indexes and DLT types from the
    // first packet we see from them.
    struct db_interface {
    public:
        db_interface(const std::string& uuid, const std::string& interface, const std::string& name) :
            uuid {uuid},
            interface {interface},
            name {name},
            dlt {0},
            pcapnum {-1} { }

        std::string uuid;
        std::string interface;
        std::string name;
        unsigned int dlt;
        int pcapnum;
    };

    std::map<std::string, std::shared_ptr<db_interface>> db_uuid_intf_map;
    int next_pcap_intf_id;

};


#endif

