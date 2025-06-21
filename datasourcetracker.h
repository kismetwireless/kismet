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

#ifndef __DATASOURCETRACKER_H__
#define __DATASOURCETRACKER_H__

#include "config.h"

#include <atomic>
#include <string>
#include <vector>
#include <map>
#include <functional>

#include "globalregistry.h"
#include "util.h"
#include "kis_datasource.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "kis_net_beast_httpd.h"
#include "entrytracker.h"
#include "timetracker.h"
#include "trackedrrd.h"
#include "kis_mutex.h"
#include "eventbus.h"
#include "messagebus.h"
#include "streamtracker.h"

/* Data source tracker
 *
 * Core of the new capture management system.
 *
 * This code replaces the old packetsource tracker.
 *
 * Data sources are registered passing a builder instance which is used to
 * instantiate the final versions of the data sources.
 *
 * Data sources communicate via the protocol defined in simple_cap_proto.h
 * and may communicate packets or complete device objects.
 *
 * 'Auto' type sources (sources with type=auto or no type given) are
 * probed automatically via all the registered datasource drivers.
 * Datasource drivers may require starting a process in order to perform the
 * probe, or they may be able to perform the probe in C++ native code.
 *
 * Once a source driver is found, it is instantiated as an active source and
 * put in the list of sources.  Opening the source may result in an error,
 * but as the source is actually assigned, it will remain in the source list.
 * This is to allow defining sources that may not be plugged in yet, etc.
 *
 * Devices which encounter errors are placed in the error vector and
 * periodically re-tried
 *
 */

class datasource_tracker;
class kis_datasource;
class datasource_tracker_worker;

// Worker class used to perform work on the list of packet-sources in a thread
// safe / continuity safe context.
class datasource_tracker_worker {
public:
    datasource_tracker_worker() { };

    // Handle a data source when working on iterate_datasources
    virtual void handle_datasource(std::shared_ptr<kis_datasource> in_src __attribute__((unused))) { };

    // All data sources have been processed in iterate_datasources
    virtual void finalize() { };
};

// Probe resolution for auto type sources
//
// Scans drivers which don't need IPC for probing first and returns immediately
// if one of them is able to handle the probe without an IPC.
//
// Spawns IPC sources for all prototype sources concurrently.
// The first source to answer a probe with an affirmative wins; the rest of the
// probes are cancelled.
//
// After 5 seconds, probing is cancelled.
class datasource_tracker_source_probe : public std::enable_shared_from_this<datasource_tracker_source_probe> {
public:
    datasource_tracker_source_probe(unsigned long probeid, std::string in_definition, std::shared_ptr<tracker_element_vector> in_protovec);
    virtual ~datasource_tracker_source_probe();

    void probe_sources(std::function<void (unsigned long, shared_datasource_builder)> in_cb);

    std::string get_definition() { return definition; }

    shared_datasource_builder get_proto();

    // Complete a probe - when the last one completes we're done
    void complete_probe(bool in_success, unsigned int in_transaction, std::string in_reason);

    // Cancel all pending probes, ultimately calls the callback from
    // probe_sources when complete
    void cancel();

protected:
    kis_mutex probe_lock;

    std::shared_ptr<time_tracker> timetracker;

    // Probing instances
    std::map<unsigned int, shared_datasource> ipc_probe_map;

    std::shared_ptr<tracker_element_vector> proto_vec;

    // Vector of sources which are complete and waiting for cleanup
    std::vector<shared_datasource> complete_vec;

    // Vector of timer events to make sure are dead before we destruct
    std::vector<int> cancel_timer_vec;

    // Prototype we found
    shared_datasource_builder source_builder;

    // Transaction ID
    std::atomic<unsigned int> transaction_id;

    // Finish cancelling a source
    void probe_cancel_complete(unsigned int sid);

    std::string definition;

    std::function<void (unsigned long, shared_datasource_builder)> probe_cb;
    std::atomic<bool> cancelled;

    unsigned long probe_id;
};

typedef std::shared_ptr<datasource_tracker_source_probe> shared_dst_source_probe;

// List all interface supported by a phy
//
// Handles listing interfaces supported by kismet
//
// Populated with a list transaction ID, and the prototype sources,
//
// Scans drivers which don't need IPC launching first, then launches all
// IPC sources capable of doing an interface list and sends a query.
//
// IPC sources spawned concurrently, and results aggregated.
//
// List requests cancelled after 5 seconds
class datasource_tracker_source_list : public std::enable_shared_from_this<datasource_tracker_source_list> {
public:
    datasource_tracker_source_list(std::shared_ptr<tracker_element_vector> in_protovec);
    virtual ~datasource_tracker_source_list();

    void list_sources(std::shared_ptr<datasource_tracker_source_list> ref, std::function<void (std::vector<shared_interface>)> in_cb);

    std::string get_definition() { return definition; }

    // Complete a list - when the last one completes we're done
    void complete_list(std::shared_ptr<kis_datasource> source,
            std::vector<shared_interface> interfaces, unsigned int in_transaction);

    void cancel();

protected:
    kis_mutex list_lock;
    std::shared_ptr<time_tracker> timetracker;

    // Probing instances
    std::map<unsigned int, shared_datasource> ipc_list_map;

    std::shared_ptr<tracker_element_vector> proto_vec;

    // Vector of sources we're still waiting to return from listing
    std::vector<shared_datasource> list_vec;

    // Vector of sources which are complete and waiting for cleanup
    std::vector<shared_datasource> complete_vec;

    // Transaction ID
    unsigned int transaction_id;

    // Finish completing a source
    void list_cancel_complete(unsigned int sid);

    std::string definition;

    std::function<void (std::vector<shared_interface>)> list_cb;
    std::atomic<bool> cancelled;

    std::atomic<int> cancel_event_id;

    std::vector<shared_interface> listed_sources;
};

typedef std::shared_ptr<datasource_tracker_source_list> shared_dst_source_list;

// Tracker/serializable record of default values used for all datasources
class datasource_tracker_defaults : public tracker_component {
public:
    datasource_tracker_defaults() :
        tracker_component(0) {
        register_fields();
        reserve_fields(NULL);
    }

    datasource_tracker_defaults(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    datasource_tracker_defaults(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("datasource_tracker_defaults");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(hop_rate, double, double, double, hop_rate);
    __Proxy(hop, uint8_t, bool, bool, hop);
    __Proxy(split_same_sources, uint8_t, bool, bool, split_same_sources);
    __Proxy(random_channel_order, uint8_t, bool, bool, random_channel_order);
    __Proxy(retry_on_error, uint8_t, bool, bool, retry_on_error);

    __Proxy(remote_cap_listen, std::string, std::string, std::string, remote_cap_listen);
    __Proxy(remote_cap_port, uint32_t, uint32_t, uint32_t, remote_cap_port);

    __Proxy(remote_cap_timestamp, uint8_t, bool, bool, remote_cap_timestamp);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.datasourcetracker.default.hop_rate",
                "default hop rate for sources", &hop_rate);
        register_field("kismet.datasourcetracker.default.hop",
                "do sources hop by default", &hop);
        register_field("kismet.datasourcetracker.default.split",
                "split channels among sources with the same type",
                &split_same_sources);
        register_field("kismet.datasourcetracker.default.random_order",
                "scramble channel order to maximize use of overlap",
                &random_channel_order);
        register_field("kismet.datasourcetracker.default.retry_on_error",
                "re-open sources if an error occurs", &retry_on_error);

        register_field("kismet.datasourcetracker.default.remote_cap_listen",
                "listen address for remote capture",
                &remote_cap_listen);
        register_field("kismet.datasourcetracker.default.remote_cap_port",
                "listen port for remote capture",
                &remote_cap_port);

        register_field("kismet.datasourcetracker.default.remote_cap_timestamp",
                "overwrite remote capture timestamp with server timestamp",
                &remote_cap_timestamp);
    }

    // Double hoprate per second
    std::shared_ptr<tracker_element_double> hop_rate;

    // Boolean, do we hop at all
    std::shared_ptr<tracker_element_uint8> hop;

    // Boolean, do we try to split channels up among the same driver?
    std::shared_ptr<tracker_element_uint8> split_same_sources;

    // Boolean, do we scramble the hop pattern?
    std::shared_ptr<tracker_element_uint8> random_channel_order;

    // Boolean, do we retry on errors?
    std::shared_ptr<tracker_element_uint8> retry_on_error;

    // Remote listen
    std::shared_ptr<tracker_element_string> remote_cap_listen;
    std::shared_ptr<tracker_element_uint32> remote_cap_port;
    std::shared_ptr<tracker_element_uint8> remote_cap_timestamp;

};

class datasource_tracker_remote_server;
class dst_incoming_remote;

class datasource_tracker : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "DATASOURCETRACKER"; }
    static std::shared_ptr<datasource_tracker> create_dst() {
        auto mon = std::shared_ptr<datasource_tracker>(new datasource_tracker());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        Globalreg::globalreg->register_deferred_global(mon);
        mon->datasourcetracker = mon;
		Globalreg::globalreg->datasourcetracker = mon.get();
        return mon;
    }

private:
    datasource_tracker();

public:
    virtual ~datasource_tracker();

    // Start up the system once kismet is up and running; this happens just before
    // the main select loop in kismet
    virtual void trigger_deferred_startup() override;

    // Shut down all sources, this happens as kismet is terminating
    virtual void trigger_deferred_shutdown() override;

    static std::string event_new_datasource() {
        return "NEW_DATASOURCE";
    }

    // Add a driver
    int register_datasource(shared_datasource_builder in_builder);

    // Handle everything about launching a source, given a basic source line
    //
    // If there is no type defined or the type is 'auto', attempt to find the
    // driver via local probe.
    //
    // Optional completion function will be called, asynchronously,
    // on completion.
    void open_datasource(const std::string& in_source,
            const std::function<void (bool, std::string, shared_datasource)>& in_cb);

    // Launch a source with a known prototype, given a basic source line
    // and a prototype.
    //
    // Optional completion function will be called on error or success
    void open_datasource(const std::string& in_source, shared_datasource_builder in_proto,
            const std::function<void (bool, std::string, shared_datasource)>& in_cb);

    // close a datasource - stop it if necessary, and place it into a closed state
    // without automatic reconnection.
    bool close_datasource(const uuid& in_uuid);

    // Remove a data source by UUID; stop it if necessary
    bool remove_datasource(const uuid& in_uuid);

    // Try to instantiate a remote data source
    std::shared_ptr<kis_datasource> open_remote_datasource(dst_incoming_remote *incoming,
            const std::string& in_type, const std::string& in_definition, const uuid& in_uuid,
            bool connect_tcp);

    // Find a datasource
    shared_datasource find_datasource(const uuid& in_uuid);

    // List potential sources
    //
    // Optional completion function will be called with list of possible sources.
    void list_interfaces(const std::function<void (std::vector<shared_interface>)>& in_cb);

    // Operate on all data sources currently defined.  The datasource tracker is locked
    // during this operation, making it thread safe.
    void iterate_datasources(datasource_tracker_worker *in_worker);

    // Parse a rate string
    double string_to_rate(std::string in_str, double in_default);

    // Access the defaults
    std::shared_ptr<datasource_tracker_defaults> get_config_defaults();

    // Merge a source into the source list, preserving UUID and source number
    virtual void merge_source(shared_datasource in_source);

    // Remote capture info
    bool remote_enabled() const {
        return remotecap_enabled;
    }

    unsigned int remote_port() const {
        return remotecap_port;
    }

    std::string remote_listen() const {
        return remotecap_listen;
    }

protected:
    // Log the datasources
    virtual void databaselog_write_datasources();

    bool remotecap_enabled;
    unsigned int remotecap_port;
    std::string remotecap_listen;

    std::shared_ptr<datasource_tracker_remote_server> remotecap_v4;

    std::shared_ptr<datasource_tracker> datasourcetracker;
    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<event_bus> eventbus;
    std::shared_ptr<stream_tracker> streamtracker;

    kis_mutex dst_lock;

    int pack_comp_datasrc;

    int proto_id;
    int source_id;

    // Available prototypes
    std::shared_ptr<tracker_element_vector> proto_vec;

    // Active data sources
    std::shared_ptr<tracker_element_vector> datasource_vec;

    // Sub-workers probing for a source definition
    std::map<unsigned int, shared_dst_source_probe> probing_map;
    std::atomic<unsigned int> next_probe_id;

    // Masked datasource types that won't be used for scan or autoprobing,
    // for systems where python takes so long to load it causes problems
    std::vector<std::string> auto_masked_types;

    // Masked interface names we don't return
    std::vector<std::string> masked_ifnames;

    // Sub-workers slated for being removed
    std::vector<shared_dst_source_probe> probing_complete_vec;

    // Sub-workers listing interfaces
    std::map<unsigned int, shared_dst_source_list> listing_map;
    std::atomic<unsigned int> next_list_id;

    // Sub-workers slated for being removed
    std::vector<shared_dst_source_list> listing_complete_vec;

    // Sources which could not be opened in any way and which do not have a UUID
    // assignment (mis-defined startup sources, for instance)
    std::vector<shared_datasource> broken_source_vec;

    // Cleanup task
    std::atomic<int> completion_cleanup_id;
    void schedule_cleanup();

    // UUIDs to source numbers
    unsigned int next_source_num;
    std::map<uuid, unsigned int> uuid_source_num_map;

    std::shared_ptr<datasource_tracker_defaults> config_defaults;

    // Re-assign channel hopping because we've opened a new source
    // and want to do channel split
    void calculate_source_hopping(shared_datasource in_ds);

    // Datasource logging
    int database_log_timer;
    bool database_log_enabled;
    std::atomic<bool> database_logging;

    // Buffer sizes
    size_t tcp_buffer_sz;

    friend class datasource_tracker_remote_server;
};

// Intermediary holder for bridging websockets and dataources so that the websockets can transition from
// an incoming remote to a full datasource
struct dst_websocket_ds_bridge {
    std::shared_ptr<kis_datasource> bridged_ds;
    kis_mutex mutex;
};

// Intermediary buffer handler which is responsible for parsing the incoming
// simple packet protocol enough to get a NEWSOURCE command; The resulting source
// type, definition, uuid, and rbufhandler is passed to the callback function; the cb
// is responsible for looking up the type, closing the connection if it is invalid, etc.
class dst_incoming_remote : public kis_datasource {
public:
    using callback_t = std::function<void (dst_incoming_remote *, std::string, std::string, uuid)>;

    dst_incoming_remote(callback_t in_cb);
    ~dst_incoming_remote();

#ifdef HAVE_PROTOBUF_CPP
    // Override the dispatch commands to handle the new source
    virtual bool dispatch_rx_packet(const nonstd::string_view& command,
            uint32_t seqno, const nonstd::string_view& content) override;
    virtual void handle_packet_newsource(uint32_t in_seqno, nonstd::string_view in_packet);
#endif

    virtual bool dispatch_rx_packet_v3(std::shared_ptr<boost::asio::streambuf> buffer,
            uint16_t command, uint16_t code, uint32_t seqno,
            const nonstd::string_view& content) override;
    virtual void handle_packet_newsource_v3(uint32_t in_seqno, uint16_t in_code, nonstd::string_view in_packet);

    virtual void handle_msg_proxy(const std::string& msg, const int msgtype) override {
        _MSG(fmt::format("(Remote) - {}", msg), msgtype);
    }

    virtual void kill();

    virtual void handshake_rb(std::thread t) {
        std::swap(handshake_thread, t);
    }

protected:
    virtual void handle_error(const std::string& error) override;

    // Timeout for killing this connection
    int timerid;

    callback_t cb;

    std::thread handshake_thread;
};


// Remote capture server helper, we need to instantiate this outside of the main dst instance, and we
// may make multiple copies of it for different types of endpoint
class datasource_tracker_remote_server {
public:
    datasource_tracker_remote_server(const tcp::endpoint& endpoint) :
        stopped{false},
        acceptor{Globalreg::globalreg->io, endpoint},
        incoming_socket{Globalreg::globalreg->io} {
        acceptor.set_option(boost::asio::socket_base::reuse_address(true));
        datasourcetracker = Globalreg::fetch_mandatory_global_as<datasource_tracker>();
        start_accept();
    }

    virtual ~datasource_tracker_remote_server();

    void stop();

    void start_accept();
    void handle_accept(const boost::system::error_code& ec, tcp::socket socket);

protected:
    std::atomic<bool> stopped;
    tcp::acceptor acceptor;
    tcp::socket incoming_socket;
    std::shared_ptr<datasource_tracker> datasourcetracker;
};

struct pcapng_datasourcetracker_accept_ftor {
    pcapng_datasourcetracker_accept_ftor(uint64_t in_dsnum) :
		dsnum{in_dsnum} {
            auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
			pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");
        }

    bool operator()(std::shared_ptr<kis_packet> in_pack) {
		const auto datasrcinfo = in_pack->fetch<packetchain_comp_datasource>(pack_comp_datasrc);

		if (datasrcinfo == nullptr) {
			return false;
		}

		if (datasrcinfo->ref_source->get_source_number() == dsnum) {
			return true;
		}

        return false;
    }

	int pack_comp_datasrc;
	uint64_t dsnum;
};


#endif

