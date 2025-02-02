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
#include "pcapng_stream_futurebuf.h"
#include "sqlite3_cpp11.h"
#include "class_filter.h"
#include "packet_filter.h"
#include "messagebus.h"

// Kismetdb version

#define KISMETDB_LOG_VERSION        9

// This is a bit of a unique case - because so many things plug into this, it has
// to exist as a global record; we build it like we do any other global record;
// then the builder hooks it, sets the internal builder record, and passed it to
// the logtracker
class kis_database_logfile : public kis_logfile, public kis_database, public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "DATABASELOG"; }

    static std::shared_ptr<kis_database_logfile>
        create_kisdatabaselog() {
            std::shared_ptr<kis_database_logfile> mon(new kis_database_logfile());
            Globalreg::globalreg->register_deferred_global(mon);
            Globalreg::globalreg->register_lifetime_global(mon);
            Globalreg::globalreg->insert_global(global_name(), mon);
            return mon;
    }

    kis_database_logfile();
    virtual ~kis_database_logfile();

    virtual void trigger_deferred_startup() override;
    virtual void trigger_deferred_shutdown() override;

    void set_database_builder(shared_log_builder in_builder) {
        builder = in_builder;

        if (builder != nullptr)
            insert(builder);
    }

    virtual bool open_log(const std::string& in_template, const std::string& in_path) override;
    virtual void close_log() override;

    virtual int database_upgrade_db() override;

    bool is_enabled() {
        return db_enabled;
    }

    // Log a vector of multiple devices, replacing any old device records
    virtual int log_device(const std::shared_ptr<kis_tracked_device_base>& in_device);

    // Device logs are non-streaming; we need to know the last time we generated
    // device logs so that we can update just the logs we need.
    virtual time_t get_last_device_log_ts() { return last_device_log; }

    // Log a packet
    virtual int log_packet(const std::shared_ptr<kis_packet>& in_packet);

    // Log data that isn't a packet; this is a slightly more clunky API because we
    // can't derive the data from the simple packet interface.  GPS may be null,
    // and other attributes may be empty, if that data is not available
    virtual int log_data(const std::shared_ptr<kis_gps_packinfo>& gps, const struct timeval& tv,
            const std::string& phystring, const mac_addr& devmac, const uuid& datasource_uuid,
            const std::string& type, const std::string& json);

    // Log datasources
    virtual int log_datasources(const shared_tracker_element& in_datasource_vec);
    // Log a single datasource
    virtual int log_datasource(const shared_tracker_element& in_datasource);

    // Log an alert; takes a standard tracked_alert element
    virtual int log_alert(const std::shared_ptr<tracked_alert>& in_alert);

    // Log snapshotted data; Slightly clunkier API since it has to allow for
    // entirely generic data
    virtual int log_snapshot(const std::shared_ptr<kis_gps_packinfo>& gps, struct timeval tv,
            const std::string& snaptype, const std::string& json);

    static void usage(const char *argv0);

    // Direct access to the filters for setting programmatically
    std::shared_ptr<packet_filter_mac_addr> get_packet_filter() {
        return packet_mac_filter;
    }

    std::shared_ptr<class_filter_mac_addr> get_device_filter() {
        return device_mac_filter;
    }

    static std::string event_log_open() {
        return "KISMETDB_LOG_OPEN";
    }

protected:
    // Is the database even enabled?
    std::atomic<bool> db_enabled;

    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<gps_tracker> gpstracker;

    int pack_comp_linkframe, pack_comp_gps, pack_comp_no_gps, pack_comp_radiodata,
        pack_comp_device, pack_comp_datasource, pack_comp_common, pack_comp_metablob;

    std::atomic<time_t> last_device_log;

    std::atomic<bool> in_transaction_sync;

    // Nasty define hack for checking if we're blocked on a really slow
    // device by comparing the transaction sync
#define db_lock_with_sync_check(locker, errcode) \
    try { \
        locker.lock(); \
    } catch (const std::runtime_error& e) { \
        if (in_transaction_sync) { \
            fmt::print(stderr, "FATAL: kismetdb log couldn't finish a database transaction within the " \
                    "timeout window for threads ({} seconds).  Usually this happens when " \
                    "the disk you are logging to can not perform adequately, such as a " \
                    "micro SD.  Try moving logging to a USB device.", KIS_THREAD_TIMEOUT); \
            Globalreg::globalreg->fatal_condition = 1; \
            throw; \
        } else { \
            throw; \
        } \
    }

    int packet_handler_id;

    // Keep track of our commit cycles; to avoid thrashing the filesystem with
    // commit state we run a 10 second tranasction commit loop
    kis_mutex transaction_mutex;
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
    void packet_drop_endpoint_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);

    // POI API
    void make_poi_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);
    std::shared_ptr<tracker_element> list_poi_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);

    // Pcap streaming api
    void pcapng_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);

    // Device log filter
    std::shared_ptr<class_filter_mac_addr> device_mac_filter;

    // Packet log filter
    std::shared_ptr<packet_filter_mac_addr> packet_mac_filter;

    // Eventbus listeners
    std::shared_ptr<event_bus> eventbus;
    void handle_message(std::shared_ptr<tracked_message> msg);
    unsigned long message_evt_id;

    void handle_alert(std::shared_ptr<tracked_alert> msg);
    unsigned long alert_evt_id;

    bool log_duplicate_packets;
    bool log_data_packets;
};

class kis_database_logfile_builder : public kis_logfile_builder {
public:
    kis_database_logfile_builder() :
        kis_logfile_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    kis_database_logfile_builder(int in_id) :
        kis_logfile_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    kis_database_logfile_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_logfile_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~kis_database_logfile_builder() { }

    // Custom builder that fetches the global copy and shoves it back down to the
    // logfile system instead
    virtual shared_logfile build_logfile(shared_log_builder builder) {
        std::shared_ptr<kis_database_logfile> logfile =
            Globalreg::fetch_mandatory_global_as<kis_database_logfile>("DATABASELOG");
        logfile->set_database_builder(builder);
        return std::static_pointer_cast<kis_logfile>(logfile);
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

class pcapng_stream_database : public pcapng_stream_futurebuf<pcapng_stream_accept_ftor, pcapng_stream_select_ftor> {
public:
    pcapng_stream_database(future_chainbuf* buffer);

    virtual ~pcapng_stream_database();

    virtual void start_stream() override;
    virtual void stop_stream(std::string in_reason) override;

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

