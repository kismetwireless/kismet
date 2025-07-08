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

#ifndef __DATASOURCE_H__
#define __DATASOURCE_H__

#include "config.h"

#include <functional>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "uuid.h"
#include "gpstracker.h"
#include "packet.h"
#include "devicetracker_component.h"
#include "packetchain.h"
#include "entrytracker.h"
#include "kis_external.h"
#include "timetracker.h"

#ifdef HAVE_PROTOBUF_CPP
#include "protobuf_cpp/kismet.pb.h"
#include "protobuf_cpp/datasource.pb.h"
#endif

#include "mpack/mpack.h"
#include "mpack/mpack_cpp.h"

// Builder class responsible for making an instance of this datasource
class kis_datasource_builder;
typedef std::shared_ptr<kis_datasource_builder> shared_datasource_builder;

// Auto-discovered interface
class kis_datasource_interface;
typedef std::shared_ptr<kis_datasource_interface> shared_interface;

// Simple keyed object derived from the low-level C protocol
class kis_datasource_cap_keyed_object;

class datasource_tracker;
class kis_datasource;

class kis_gps;

class kis_datasource_builder : public tracker_component {
public:
    kis_datasource_builder() :
        tracker_component(0) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    kis_datasource_builder(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    kis_datasource_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_datasource_builder");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual ~kis_datasource_builder() { };

    virtual void initialize() { };

    // Build the actual data source; when subclassing this MUST fill in the prototype!
    // Due to semantics of shared_pointers we can't simply pass a 'this' sharedptr
    // to the instantiated datasource, so we need to take a pointer to ourselves
    // in the input.
    // Typical implementation:
    // return shared_datasource(new SomeKismetDatasource(globalreg, in_shared_builder));
    virtual std::shared_ptr<kis_datasource>
        build_datasource(std::shared_ptr<kis_datasource_builder> in_shared_builder) { return nullptr; };

    __Proxy(source_type, std::string, std::string, std::string, source_type);
    __Proxy(source_description, std::string, std::string, std::string, source_description);

    __Proxy(probe_capable, uint8_t, bool, bool, probe_capable);

    __Proxy(list_capable, uint8_t, bool, bool, list_capable);

    __Proxy(local_capable, uint8_t, bool, bool, local_capable);

    __Proxy(remote_capable, uint8_t, bool, bool, remote_capable);

    __Proxy(passive_capable, uint8_t, bool, bool, passive_capable);

    __Proxy(tune_capable, uint8_t, bool, bool, tune_capable);

    __Proxy(hop_capable, uint8_t, bool, bool, hop_capable);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.datasource.driver.type", "Type", &source_type);
        register_field("kismet.datasource.driver.description", "Description", &source_description);

        register_field("kismet.datasource.driver.probe_capable",
                "Datasource can automatically probe", &probe_capable);

        register_field("kismet.datasource.driver.probe_ipc",
                "Datasource requires IPC to probe", &probe_ipc);

        register_field("kismet.datasource.driver.list_capable",
                "Datasource can list interfaces", &list_capable);

        register_field("kismet.datasource.driver.list_ipc",
                "Datasource requires IPC to list interfaces", &list_ipc);

        register_field("kismet.datasource.driver.local_capable",
                "Datasource can support local interfaces", &local_capable);

        register_field("kismet.datasource.driver.local_ipc",
                "Datasource requires IPC for local interfaces", &local_ipc);

        register_field("kismet.datasource.driver.remote_capable",
                "Datasource can support remote interfaces", &remote_capable);

        register_field("kismet.datasource.driver.passive_capable",
                "Datasource can support passive interface-less data", &passive_capable);

        register_field("kismet.datasource.driver.tuning_capable",
                "Datasource can control channels", &tune_capable);

        register_field("kismet.datasource_driver.hop_capable",
                "Datasource can channel hop", &hop_capable);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        tracked_id = Globalreg::globalreg->entrytracker->register_field("kismet.datasource.type_driver",
                tracker_element_factory<tracker_element_map>(),
                "datasource driver handler");
    }

    int datasource_entity_id;

    std::shared_ptr<tracker_element_string> source_type;
    std::shared_ptr<tracker_element_string> source_description;
    std::shared_ptr<tracker_element_uint8> probe_capable;
    std::shared_ptr<tracker_element_uint8> probe_ipc;
    std::shared_ptr<tracker_element_uint8> list_capable;
    std::shared_ptr<tracker_element_uint8> list_ipc;
    std::shared_ptr<tracker_element_uint8> local_capable;
    std::shared_ptr<tracker_element_uint8> local_ipc;
    std::shared_ptr<tracker_element_uint8> remote_capable;
    std::shared_ptr<tracker_element_uint8> passive_capable;
    std::shared_ptr<tracker_element_uint8> tune_capable;
    std::shared_ptr<tracker_element_uint8> hop_capable;
};


class kis_datasource : public tracker_component, public kis_external_interface {
public:
    kis_datasource(shared_datasource_builder in_builder);

    kis_datasource() :
        tracker_component(0),
        kis_external_interface() {
        error_timer_id = -1;
        ping_timer_id = -1;
        register_fields();
        reserve_fields(NULL);
    }

    kis_datasource(int in_id) :
        tracker_component(in_id),
        kis_external_interface() {
        error_timer_id = -1;
        ping_timer_id = -1;
        register_fields();
        reserve_fields(NULL);
    }

    kis_datasource(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id),
        kis_external_interface() {
        error_timer_id = -1;
        ping_timer_id = -1;
        register_fields();
        reserve_fields(e);
    }

    virtual ~kis_datasource();

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_datasource");
    }

    // Fetch default per-source options.  These override the global defaults,
    // but are overridden by specific commands inside the definition.
    //
    // To override a default, return a string for that option; to ignore an
    // opportunity to override, return an empty string.
    virtual std::string override_default_option(std::string in_opt __attribute__((unused))) {
        return "";
    }

    // Async command API
    // All commands to change non-local state are asynchronous.  Failure, success,
    // and state change will not be known until the command completes.
    // To marshal this, all commands take a transaction id (arbitrary number provided
    // by the caller) and a callback function.  If the function exists, it is called
    // when the command completes.

    // 'List' callback - called with caller-supplied transaction id and contents,
    // if any, of the interface list command
    typedef std::function<void (std::shared_ptr<kis_datasource> src,
            unsigned int, std::vector<shared_interface>)> list_callback_t;

    // List all interfaces this source can support
    virtual void list_interfaces(unsigned int in_transaction, list_callback_t in_cb);

    // 'Probe' callback - called with caller-supplied transaction id and success
    // or failure of the probe command and string message of any additional
    // information if there was a MESSAGE key in the PROBERESP or if there was a
    // local communications error.
    typedef std::function<void (unsigned int, bool, std::string)> probe_callback_t;

    // Probe to determine if a specific interface is supported by this source
    virtual void probe_interface(std::string in_definition, unsigned int in_transaction,
            probe_callback_t in_cb);

    // 'Open' callback - called with the caller-supplied transaction id,
    // success (or not) of open command, and a string message of any failure
    // data if there was a MESSAGE key in the OPENRESP or there was a
    // local communications error.
    typedef std::function<void (unsigned int, bool, std::string)> open_callback_t;

    // Open an interface defined by in_definition
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb);

    // 'Configure' callback - called when a configure-related command such as
    // channel set, hop set, etc is performed.  Returns the caller-supplied
    // transaction id, success, std::string message (if any) related to a failure
    typedef std::function<void (unsigned int, bool, std::string)> configure_callback_t;

    // Lock to a specific channel and stop hopping
    virtual void set_channel(std::string in_channel, unsigned int in_transaction,
            configure_callback_t in_cb);

    // Set the channel hop rate and list of channels to hop on, using a string vector
    virtual void set_channel_hop(double in_rate, std::vector<std::string> in_chans,
            bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
            configure_callback_t in_cb);
    // Set the channel hop rate using a tracker_element vector object
    virtual void set_channel_hop(double in_rate,
            std::shared_ptr<tracker_element_vector_string> in_chans,
            bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
            configure_callback_t in_cb);
    // Set just the channel hop rate; internally this is the same as setting a
    // hop+vector but we simplify the API for callers
    virtual void set_channel_hop_rate(double in_rate, unsigned int in_transaction,
            configure_callback_t in_cb);
    // Set just the hop channels; internally this is the same as setting a
    // hop+vector but we simplify the API for callers
    virtual void set_channel_hop_list(std::vector<std::string> in_chans,
            unsigned int in_transaction, configure_callback_t in_cb);


    // Instantiate from an incoming remote; caller must then assign tcpsocket or callbacks and trigger
    // a datasource open
    virtual void connect_remote(std::string in_definition, kis_datasource* in_remote,
            const uuid& uuid, bool in_tcp, configure_callback_t in_cb);

    // close the source
    // This must be called from either our own strand async functions, or fully
    // outside of ANY strand.
    //
    // See close_source_async for closing a source safely from another strand, like
    // datasourcetracker probing
    //
    // Cancels any current activity (probe, open, pending commands) and sends a
    // terminate command to the capture binary.
    // Closing sends a failure result to any pending async commands
    // Closes an active source, and is called during the normal source shutdown
    // process in case of an error.  Closed sources may automatically re-open if
    // the retry option is configured.
    virtual void close_source();

    // Perform an adync close of a source and perform a callback when done.  This can be
    // called from another strand, it will not block & will initiate a stranded event
    // which calls the provided cb at completion.
    virtual void close_source_async(std::function<void (void)> cb);


    // Disables a source
    // Cancels any current activity, and sends a terminate to the capture binary.
    // Disables any error state and disables the error retry.
    virtual void disable_source();


    // Pauses a source
    // Paused sources remain open, but discard any packts
    virtual void pause_source();

    // Resumes a source
    virtual void resume_source();


    // Get an option from the definition
    virtual bool has_definition_opt(const std::string& in_opt);
    virtual std::string get_definition_opt(std::string in_opt);
    virtual bool get_definition_opt_bool(std::string in_opt, bool in_default);
    virtual double get_definition_opt_double(std::string in_opt, double in_default);


    // Kismet-only variables can be set realtime, they have no capture-binary
    // equivalents and are only used for tracking purposes in the Kismet server
    __ProxyM(source_name, std::string, std::string, std::string, source_name, data_mutex);
    __ProxyM(source_uuid, uuid, uuid, uuid, source_uuid, data_mutex);

    // Source key is a checksum of the uuid for us to do fast indexing
    __ProxyM(source_key, uint32_t, uint32_t, uint32_t, source_key, data_mutex);

    // Prototype/driver definition
    __ProxyTrackable(source_builder, kis_datasource_builder, source_builder);

    // Read-only access to the source state; this mirrors the state in the capture
    // binary. Set commands queue a command to the binary and then update as
    // they complete.
    __ProxyGetM(source_definition, std::string, std::string, source_definition, data_mutex);
    __ProxyGetM(source_interface, std::string, std::string, source_interface, data_mutex);
    __ProxyGetM(source_cap_interface, std::string, std::string, source_cap_interface, data_mutex);
    __ProxyGetM(source_hardware, std::string, std::string, source_hardware, data_mutex);

    __ProxyGetM(source_dlt, uint32_t, uint32_t, source_dlt, data_mutex);

    // Don't allow raw access to the vec, we have to copy it under ext_mutex
    // __ProxyTrackableM(source_channels_vec, tracker_element_vector_string, source_channels_vec, data_mutex);
    std::vector<std::string> get_source_channels_vec_copy();


    // Any alert state passed from the driver we want to be able to consistently
    // report to the user
    __ProxyGetM(source_warning, std::string, std::string, source_warning, data_mutex);

    __ProxyGetM(source_hopping, uint8_t, bool, source_hopping, data_mutex);
    __ProxyGetM(source_channel, std::string, std::string, source_channel, data_mutex);
    __ProxyGetM(source_hop_rate, double, double, source_hop_rate, data_mutex);
    __ProxyGetM(source_split_hop, uint8_t, bool, source_hop_split, data_mutex);
    __ProxyGetM(source_hop_offset, uint32_t, uint32_t, source_hop_offset, data_mutex);
    __ProxyGetM(source_hop_shuffle, uint8_t, bool, source_hop_shuffle, data_mutex);
    __ProxyGetM(source_hop_shuffle_skip, uint32_t, uint32_t, source_hop_shuffle_skip, data_mutex);
    __ProxyTrackableM(source_hop_vec, tracker_element_vector_string, source_hop_vec, data_mutex);

    __ProxyGetM(source_running, uint8_t, bool, source_running, data_mutex);

    __ProxyGetM(source_remote, uint8_t, bool, source_remote, data_mutex);
    __ProxyGetM(source_passive, uint8_t, bool, source_passive, data_mutex);

    __ProxyM(source_num_packets, uint64_t, uint64_t, uint64_t, source_num_packets, data_mutex);
    __ProxyIncDecM(source_num_packets, uint64_t, uint64_t, source_num_packets, data_mutex);

    __ProxyM(source_num_error_packets, uint64_t, uint64_t, uint64_t, source_num_error_packets, data_mutex);
    __ProxyIncDecM(Msource_num_error_packets, uint64_t, uint64_t, source_num_error_packets, data_mutex);

    __ProxyDynamicTrackableM(source_packet_rrd, kis_tracked_rrd<>,
            packet_rate_rrd, packet_rate_rrd_id, data_mutex);

    __ProxyDynamicTrackableM(source_packet_size_rrd, kis_tracked_rrd<>,
            packet_size_rrd, packet_size_rrd_id, data_mutex);

    // IPC binary name, if any
    __ProxyGetM(source_ipc_binary, std::string, std::string, source_ipc_binary, data_mutex);
    // IPC channel pid, if any
    __ProxyGetM(source_ipc_pid, int64_t, pid_t, source_ipc_pid, data_mutex);

    // Retry API - do we try to re-open when there's a problem?
    __ProxyGetM(source_error, uint8_t, bool, source_error, data_mutex);
    __ProxyM(source_retry, uint8_t, bool, bool, source_retry, data_mutex);
    __ProxyGetM(source_retry_attempts, uint32_t, uint32_t, source_retry_attempts, data_mutex);

    __Proxy(source_number, uint64_t, uint64_t, uint64_t, source_number);

    __ProxyM(source_paused, uint8_t, bool, bool, source_paused, data_mutex);


    // Random metadata
    __ProxyM(source_info_antenna_type, std::string, std::string, std::string, source_info_antenna_type, data_mutex);
    __ProxyM(source_info_antenna_gain, double, double, double, source_info_antenna_gain, data_mutex);
    __ProxyM(source_info_antenna_orientation, double, double, double, source_info_antenna_orientation, data_mutex);
    __ProxyM(source_info_antenna_beamwidth, double, double, double, source_info_antenna_beamwidth, data_mutex);
    __ProxyM(source_info_amp_type, std::string, std::string, std::string, source_info_amp_type, data_mutex);
    __ProxyM(source_info_amp_gain, double, double, double, source_info_amp_gain, data_mutex);

    // Overridden linktype
    __ProxyPrivSplitM(source_override_linktype, unsigned int, unsigned int, uint32_t,
            source_override_linktype, data_mutex);

    __ProxyGetM(source_error_reason, std::string, std::string, source_error_reason, data_mutex);


    // Perform a checksum on a packet after it's decapsulated; this is always
    // called; a source should override it and check flags in the source
    // definition to see if it should be checksummed
    //
    // Additional checksum data (like FCS frames) will be in the packet
    // from the DLT decoders.
    //
    // Checksum functions should flag the packet as invalid directly via some
    // method recognized by the device categorization stage
    virtual void checksum_packet(std::shared_ptr<kis_packet> in_pack __attribute__((unused))) { return; }

    virtual void pre_serialize() override {
        kis_lock_guard<kis_mutex> lk(data_mutex, kismet::retain_lock, "datasource preserialize");
    }

    virtual void post_serialize() override {
        kis_lock_guard<kis_mutex> lk(data_mutex, std::adopt_lock);
    }

    static std::string event_datasource_error() { return "DATASOURCE_ERROR"; }
    static std::string event_datasource_opened() { return "DATASOURCE_OPENED"; }
    static std::string event_datasource_closed() { return "DATASOURCE_CLOSED"; }
    static std::string event_datasource_paused() { return "DATASOURCE_PAUSED"; }
    static std::string event_datasource_resumed() { return "DATASOURCE_RESUMED"; }

#ifdef HAVE_PROTOBUF_CPP
    // Manipulate incoming packet data before it is inserted into the base packet; Subclasses can use
    // this to modify the data before it hits the linkframe to minimize copy overhead.  When replacing
    // this function, replacements MUST implement the full timestamp, RRD update, etc found in the
    // base function.
    virtual void handle_rx_datalayer_v2(std::shared_ptr<kis_packet> packet,
            const KismetDatasource::SubPacket& report);

    // Manipulate incoming packet json before it is inserted into the base packet; Subclasses can use
    // this to modify the json before it hits the jsoninfo buffer
    virtual void handle_rx_jsonlayer_v2(std::shared_ptr<kis_packet> packet,
            const KismetDatasource::SubJson& report);
#endif

    // Manipulate incoming packet data before it is inserted into the base packet; Subclasses can use
    // this to modify the data before it hits the linkframe to minimize copy overhead.  When replacing
    // this function, replacements MUST implement the full timestamp, RRD update, etc found in the
    // base function.
    virtual void handle_rx_datalayer_v3(std::shared_ptr<kis_packet> packet,
            mpack_node_t& root, mpack_tree_t *tree);

    // Manipulate incoming packet json before it is inserted into the base packet; Subclasses can use
    // this to modify the json before it hits the jsoninfo buffer
    virtual void handle_rx_jsonlayer_v3(std::shared_ptr<kis_packet> packet,
            mpack_node_t& root, mpack_tree_t *tree);

    // Manipulate and insert the decapsulated data into a packet
    virtual int handle_rx_data_content(kis_packet *packet,
            kis_datachunk *datachunk, const uint8_t *content, size_t content_sz);

    // Handle injecting packets into the packet chain after the data report has been received
    // and processed.  Subclasses can override this to manipulate packet content.
    virtual void handle_rx_packet(std::shared_ptr<kis_packet> packet);

    // Source error; sets error state, fails all pending function callbacks,
    // shuts down the buffer and ipc, and initiates retry if we retry errors
    virtual void handle_error(const std::string& in_reason) override;

    // Manage a specific GPS linked to this datasource (metagps, etc)
    virtual void set_device_gps(std::shared_ptr<kis_gps> in_gps);
    virtual void clear_device_gps();

protected:
    std::shared_ptr<gps_tracker> gpstracker;

    // Mutex for data elements
    kis_mutex data_mutex;


    virtual void close_external() override;
    virtual void close_external_impl() override;


    // Common interface parsing to set our name/uuid/interface and interface
    // config pairs.  Once this is done it will have automatically set any
    // local variables like name, uuid, etc that needed to get set.
    virtual bool parse_source_definition(std::string in_definition);

    // Split out local var-key pairs for the source definition
    std::map<std::string, std::string> source_definition_opts;
    std::map<std::string, std::string> source_append_opts;
    std::map<std::string, std::string> source_override_opts;

    // Append a new key pair to a definition; do not replace existing values
    virtual bool append_source_definition(const std::string& in_key,
            const std::string& in_data);

    // Append or replace a key pair on a definition
    virtual void update_source_definition(const std::string& in_key,
            const std::string& in_data);

    // Re-synthesize an interface definition
    virtual std::string generate_source_definition();

    // Grab overrides per key
    virtual std::map<std::string, std::string> get_config_overrides(const std::string& in_key);

    // Async command API
    // Commands have to be sent over the IPC channel or the network connection, making
    // all commands fundamentally asynchronous.
    // Any set / open / probe / list command takes an optional callback
    // which will be called on completion of the command

    // Tracker object for our map of commands which haven't finished
    class tracked_command {
    public:
        tracked_command(unsigned int in_trans, uint32_t in_seq, kis_datasource *in_src) {
            transaction = in_trans;
            command_seq = in_seq;
            command_time = Globalreg::globalreg->last_tv_sec;

            timetracker =
                Globalreg::fetch_mandatory_global_as<time_tracker>();

            // Generate a timeout for 5 seconds from now
            auto src_alias = in_src;
            timer_id = timetracker->register_timer(SERVER_TIMESLICES_SEC * 30,
                    NULL, 0, [src_alias, this](int) -> int {
                    src_alias->cancel_command(command_seq, "Command did not complete");
                    return 0;
                });

        }

        ~tracked_command() {
            if (timer_id > -1) {
                timetracker->remove_timer(timer_id);
                timer_id = -1;
            }
        }

        std::shared_ptr<time_tracker> timetracker;

        unsigned int transaction;
        uint32_t command_seq;
        time_t command_time;
        std::atomic<int> timer_id;

        // Callbacks
        list_callback_t list_cb;
        probe_callback_t probe_cb;
        open_callback_t open_cb;
        configure_callback_t configure_cb;
    };

    // Tracked commands we need to ack
    std::atomic<unsigned int> next_transaction;
    std::map<uint32_t, std::shared_ptr<kis_datasource::tracked_command> > command_ack_map;

    // Get a command
    virtual std::shared_ptr<kis_datasource::tracked_command> get_command(uint32_t in_transaction);

    // Cancel a specific command; exposed as a function for easy callbacks
    virtual void cancel_command(uint32_t in_transaction, std::string in_reason);

    // Kill any pending commands - we're entering error state or closing, so
    // any pending callbacks get cleared out
    virtual void cancel_all_commands(std::string in_error);

    // common send functions that pick based on protocol version and compile time options
    virtual unsigned int send_configure_channel(const std::string& in_channel, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_configure_channel_hop(double in_rate,
            std::shared_ptr<tracker_element_vector_string> in_chans,
            bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_list_interfaces(unsigned int in_transaction, list_callback_t in_cb);
    virtual unsigned int send_open_source(const std::string& in_definition, unsigned int in_transaction,
            open_callback_t in_cb);
    virtual unsigned int send_probe_source(const std::string& in_defintion, unsigned int in_transaction,
            probe_callback_t in_cb);

    // new v3 protocol dispatch and handlers, always built

    virtual bool dispatch_rx_packet_v3(std::shared_ptr<boost::asio::streambuf> buffer,
            uint16_t command, uint16_t code, uint32_t seqno,
            const nonstd::string_view& content) override;

    // V3 Packet handlers
    virtual void handle_configsource_report_v3_callback(uint32_t in_seqno, uint16_t code,
            kis_unique_lock<kis_mutex>& lock, const std::string& msg);
    virtual void handle_packet_configure_report_v3(uint32_t in_seqno, uint16_t code,
            const nonstd::string_view& in_packet);
    virtual void handle_packet_data_report_v3(uint32_t in_seqno, uint16_t code,
            const nonstd::string_view& in_packet,
            std::shared_ptr<boost::asio::streambuf> buffer);

	virtual void handle_interfaces_report_v3_callback(uint32_t in_seqno, uint16_t code,
			kis_unique_lock<kis_mutex>& lock, std::vector<shared_interface>& interfaces);
    virtual void handle_packet_interfaces_report_v3(uint32_t in_seqno, uint16_t code,
            const nonstd::string_view& in_packet);

    virtual void handle_opensource_report_v3_callback(uint32_t in_seqno, uint16_t code,
            kis_unique_lock<kis_mutex>& lock, const std::string& msg);
    virtual void handle_packet_opensource_report_v3(uint32_t in_seqno, uint16_t code,
            const nonstd::string_view& in_packet);

    virtual void handle_probesource_report_v3_callback(uint32_t in_seqno, uint16_t code,
            kis_unique_lock<kis_mutex>& lock, const std::string& msg);
    virtual void handle_packet_probesource_report_v3(uint32_t in_seqno, uint16_t code,
            const nonstd::string_view& in_packet);

    virtual unsigned int send_configure_channel_v3(const std::string& in_channel,
            unsigned int in_transaction, configure_callback_t in_cb);
    virtual unsigned int send_configure_channel_hop_v3(double in_rate,
            std::shared_ptr<tracker_element_vector_string> in_chans,
            bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_list_interfaces_v3(unsigned int in_transaction,
            list_callback_t in_cb);
    virtual unsigned int send_open_source_v3(const std::string& in_definition,
            unsigned int in_transaction, open_callback_t in_cb);
    virtual unsigned int send_probe_source_v3(const std::string& in_defintion,
            unsigned int in_transaction, probe_callback_t in_cb);

    virtual void handle_msg_proxy(const std::string& msg, const int type) override;

    // specific decoders to break out signal and gps extraction for derivitive classes; to be passed the
    // decoded packet mpack tree.  most child classes shouldn't ever need to touch this since it also
    // implies handling the whole raw packet.
    virtual std::shared_ptr<kis_gps_packinfo> handle_sub_gps(mpack_node_t& root,
            mpack_tree_t *tree);
    virtual std::shared_ptr<kis_layer1_packinfo> handle_sub_signal(mpack_node_t& root,
            mpack_tree_t *tree);

#ifdef HAVE_PROTOBUF_CPP
    // legacy v2 protocol handlers, to be phased out.  these are all optional, and require Kismet to be
    // compiled with protobufs support.

    // central packet dispatch override to add the datasource commands
    virtual bool dispatch_rx_packet(const nonstd::string_view& command,
            uint32_t seqno, const nonstd::string_view& content) override;

    virtual void handle_packet_configure_report_v2(uint32_t in_seqno, const nonstd::string_view& in_packet);
    virtual void handle_packet_data_report_v2(uint32_t in_seqno, const nonstd::string_view& in_packet);
    virtual void handle_packet_error_report_v2(uint32_t in_seqno, const nonstd::string_view& in_packet);
    virtual void handle_packet_interfaces_report_v2(uint32_t in_seqno, const nonstd::string_view& in_packet);
    virtual void handle_packet_opensource_report_v2(uint32_t in_seqno, const nonstd::string_view& in_packet);
    virtual void handle_packet_probesource_report_v2(uint32_t in_seqno, const nonstd::string_view& in_packet);
    virtual void handle_packet_warning_report_v2(uint32_t in_seqno, const nonstd::string_view& in_packet);

    virtual unsigned int send_configure_channel_v2(std::string in_channel, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_configure_channel_hop_v2(double in_rate,
            std::shared_ptr<tracker_element_vector_string> in_chans,
            bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_list_interfaces_v2(unsigned int in_transaction, list_callback_t in_cb);
    virtual unsigned int send_open_source_v2(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb);
    virtual unsigned int send_probe_source_v2(std::string in_defintion, unsigned int in_transaction,
            probe_callback_t in_cb);

    // specific decoders broken out for derivitive classes to access signal and gps easily
    virtual std::shared_ptr<kis_gps_packinfo> handle_sub_gps(KismetDatasource::SubGps in_gps);
    virtual std::shared_ptr<kis_layer1_packinfo> handle_sub_signal(KismetDatasource::SubSignal in_signal);
#endif


    // Launch the IPC binary
    virtual bool launch_ipc();


    // TrackerComponent API, we can't ever get instantiated from a saved element
    // so we always initialize as if we're a new object
    virtual void register_fields() override;

    // We don't build quite like a normal object so just remember what our
    // element ID is - it's a generic tracker_map which holds our serializable
    // presentation data for indexing sources
    int datasource_entity_id;

    __ProxyM(source_cmd_pending, uint8_t, uint8_t, uint8_t, source_cmd_pending, data_mutex);

    // We define internal proxies for the set_ commands because we don't present
    // a writeable trackercomponent interface - these are just mirrors of the state
    // given to us by the capture binary itself.  We use the ProxySet macros with
    // a modified function name so that we can easily set our tracker components
    // from the KV handlers
    __ProxySetM(int_source_definition, std::string, std::string, source_definition, data_mutex);
    __ProxySetM(int_source_interface, std::string, std::string, source_interface, data_mutex);
    __ProxySetM(int_source_cap_interface, std::string, std::string, source_cap_interface, data_mutex);
    __ProxySetM(int_source_hardware, std::string, std::string, source_hardware, data_mutex);
    __ProxySetM(int_source_dlt, uint32_t, uint32_t, source_dlt, data_mutex);
    __ProxyTrackableM(int_source_channels_vec, tracker_element_vector_string, source_channels_vec, data_mutex);

    __ProxySetM(int_source_warning, std::string, std::string, source_warning, data_mutex);

    __ProxySetM(int_source_hopping, uint8_t, bool, source_hopping, data_mutex);
    __ProxySetM(int_source_channel, std::string, std::string, source_channel, data_mutex);
    __ProxySetM(int_source_hop_rate, double, double, source_hop_rate, data_mutex);
    __ProxySetM(int_source_hop_split, uint8_t, bool, source_hop_split, data_mutex);
    __ProxySetM(int_source_hop_shuffle, uint8_t, bool, source_hop_shuffle, data_mutex);
    __ProxySetM(int_source_hop_shuffle_skip, uint32_t, uint32_t, source_hop_shuffle_skip, data_mutex);
    __ProxySetM(int_source_hop_offset, uint32_t, uint32_t, source_hop_offset, data_mutex);
    __ProxyTrackableM(int_source_hop_vec, tracker_element_vector_string, source_hop_vec, data_mutex);

    // Prototype object which created us, defines our overall capabilities
    std::shared_ptr<kis_datasource_builder> source_builder;

    // command pending completion
    std::shared_ptr<tracker_element_uint8> source_cmd_pending;

    // RW fields, they're relevant only to Kismet
    std::shared_ptr<tracker_element_string> source_name;
    std::shared_ptr<tracker_element_uuid> source_uuid;
    bool local_uuid;
    std::shared_ptr<tracker_element_uint32> source_key;

    // Read-only tracked element states

    // Raw definition
    std::shared_ptr<tracker_element_string> source_definition;

    // Network interface / filename
    std::shared_ptr<tracker_element_string> source_interface;
    // Optional interface we actually capture from - ie, linux wifi VIFs or resolved USB device paths
    std::shared_ptr<tracker_element_string> source_cap_interface;
    // Optional hardware
    std::shared_ptr<tracker_element_string> source_hardware;

    // Interface DLT
    std::shared_ptr<tracker_element_uint32> source_dlt;

    int channel_entry_id;

    // Possible channels supported by this source
    std::shared_ptr<tracker_element_vector_string> source_channels_vec;

    // Warning to the user if something is funny in the source
    std::shared_ptr<tracker_element_string> source_warning;

    // Are we channel hopping?
    std::shared_ptr<tracker_element_uint8> source_hopping;

    // Current channel if we're not hopping
    std::shared_ptr<tracker_element_string> source_channel;

    // Current hop rate and vector of channels we hop through, if we're hopping
    std::shared_ptr<tracker_element_double> source_hop_rate;
    std::shared_ptr<tracker_element_vector_string> source_hop_vec;
    int source_hop_vec_id;

    std::shared_ptr<tracker_element_uint8> source_hop_split;
    std::shared_ptr<tracker_element_uint32> source_hop_offset;
    std::shared_ptr<tracker_element_uint8> source_hop_shuffle;
    std::shared_ptr<tracker_element_uint32> source_hop_shuffle_skip;

    std::shared_ptr<tracker_element_uint64> source_num_packets;
    std::shared_ptr<tracker_element_uint64> source_num_error_packets;

    int packet_rate_rrd_id;
    std::shared_ptr<kis_tracked_rrd<>> packet_rate_rrd;

    int packet_size_rrd_id;
    std::shared_ptr<kis_tracked_rrd<>> packet_size_rrd;


    // Local ID number is an increasing number assigned to each
    // unique UUID; it's used inside Kismet for fast mapping for seenby,
    // etc.  DST maps this to unique UUIDs after an Open
    std::shared_ptr<tracker_element_uint64> source_number;

    // Is the source paused?  If so, we throw out packets from it for now
    std::shared_ptr<tracker_element_uint8> source_paused;


    // Retry API
    // Try to re-open sources in error automatically

    // Are we in error state?
    __ProxySetM(int_source_error, uint8_t, bool, source_error, data_mutex);
    std::shared_ptr<tracker_element_uint8> source_error;

    // Why are we in error state?
    __ProxySetM(int_source_error_reason, std::string, std::string, source_error_reason, data_mutex);
    std::shared_ptr<tracker_element_string> source_error_reason;

    // Do we want to try to re-open automatically?
    __ProxySetM(int_source_retry, uint8_t, bool, source_retry, data_mutex);
    std::shared_ptr<tracker_element_uint8> source_retry;

    // How many consecutive errors have we had?
    __ProxySetM(int_source_retry_attempts, uint32_t, uint32_t, source_retry_attempts, data_mutex);
    __ProxyIncDecM(int_source_retry_attempts, uint32_t, uint32_t, source_retry_attempts, data_mutex);
    std::shared_ptr<tracker_element_uint32> source_retry_attempts;

    // How many total errors?
    __ProxySetM(int_source_total_retry_attempts, uint32_t, uint32_t, source_total_retry_attempts, data_mutex);
    __ProxyIncDecM(int_source_total_retry_attempts, uint32_t, uint32_t, source_total_retry_attempts, data_mutex);
    std::shared_ptr<tracker_element_uint32> source_total_retry_attempts;

    // Timer ID for trying to recover from an error
    int error_timer_id;

    // Function that gets called when we encounter an error; allows for scheduling
    // bringup, etc
    virtual void handle_source_error();


    // Arbitrary data stored about the source, entered by the user
    std::shared_ptr<tracker_element_string> source_info_antenna_type;
    std::shared_ptr<tracker_element_double> source_info_antenna_gain;
    std::shared_ptr<tracker_element_double> source_info_antenna_orientation;
    std::shared_ptr<tracker_element_double> source_info_antenna_beamwidth;

    std::shared_ptr<tracker_element_string> source_info_amp_type;
    std::shared_ptr<tracker_element_double> source_info_amp_gain;

    std::shared_ptr<tracker_element_uint32> source_override_linktype;


    // Do we clobber the remote timestamp?
    bool clobber_timestamp;

    __ProxySetM(int_source_remote, uint8_t, bool, source_remote, data_mutex);
    std::shared_ptr<tracker_element_uint8> source_remote;

    __ProxySetM(int_source_passive, uint8_t, bool, source_passive, data_mutex);
    std::shared_ptr<tracker_element_uint8> source_passive;

    __ProxySetM(int_source_running, uint8_t, bool, source_running, data_mutex);
    std::shared_ptr<tracker_element_uint8> source_running;

    __ProxySetM(int_source_ipc_binary, std::string, std::string, source_ipc_binary, data_mutex);
    std::shared_ptr<tracker_element_string> source_ipc_binary;

    __ProxySetM(int_source_ipc_pid, int64_t, pid_t, source_ipc_pid, data_mutex);
    std::shared_ptr<tracker_element_int64> source_ipc_pid;


    // Interfaces we found via list
    std::vector<shared_interface> listed_interfaces;
    int listed_interface_entry_id;

    // Special modes which suppress error output and retry handling
    bool mode_probing;
    bool mode_listing;

    // We've gotten our response from an operation, don't report additional errors
    bool quiet_errors;

    // We suppress automatically adding GPS to packets from this source
    bool suppress_gps;

    // packet_chain
    std::shared_ptr<packet_chain> packetchain;

    // gps, if a specific gps is bound to this interface
    std::shared_ptr<kis_gps> device_gps;

    // Packet components we inject
    int pack_comp_report, pack_comp_linkframe, pack_comp_l1info, pack_comp_l1_agg,
        pack_comp_gps, pack_comp_no_gps,
        pack_comp_datasrc, pack_comp_json, pack_comp_protobuf;

    virtual void handle_v2_pong_event() override;
    std::function<void ()> deferred_event;

};

typedef std::shared_ptr<kis_datasource> shared_datasource;

// kis_datasource_interface
// An automatically discovered interface, and any parameters needed to instantiate
// it; returned by the probe API

class kis_datasource_interface : public tracker_component {
public:
    kis_datasource_interface() :
        tracker_component(0) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_datasource_interface(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_datasource_interface(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual ~kis_datasource_interface() { };

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_datasource_interface");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(interface, std::string, std::string, std::string, interface);
    __ProxyTrackable(options_vec, tracker_element_vector, options_vec);

    __ProxyTrackable(prototype, kis_datasource_builder, prototype);
    __Proxy(in_use_uuid, uuid, uuid, uuid, in_use_uuid);
    __Proxy(hardware, std::string, std::string, std::string, hardware);
    __Proxy(cap_interface, std::string, std::string, std::string, cap_interface);

    void populate(std::string in_interface, std::string in_options) {
        std::vector<std::string> optvec = str_tokenize(in_options, ",");
        populate(in_interface, optvec);
    }

    void populate(std::string in_interface, std::vector<std::string> in_options) {
        set_interface(in_interface);

        if (in_options.size() != 0) {
            for (auto i : *options_vec) {
                auto o = std::make_shared<tracker_element_string>(options_entry_id,
                        get_tracker_value<std::string>(i));
                options_vec->push_back(o);
            }
        }
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.datasource.probed.interface", "Interface name", &interface);
        register_field("kismet.datasource.probed.capture_interface", "Capture interface name", &cap_interface);
        register_field("kismet.datasource.probed.options_vec",
                "Interface options", &options_vec);

        options_entry_id =
            register_field("kismet.datasource.probed.option",
                    tracker_element_factory<tracker_element_string>(),
                    "Interface option");

        register_field("kismet.datasource.probed.in_use_uuid",
                "Active source using this interface", &in_use_uuid);

        register_field("kismet.datasource.probed.hardware",
                "Hardware / chipset", &hardware);

    }

    std::shared_ptr<tracker_element_string> interface;
    std::shared_ptr<tracker_element_string> cap_interface;
    std::shared_ptr<tracker_element_vector> options_vec;

    std::shared_ptr<kis_datasource_builder> prototype;

    std::shared_ptr<tracker_element_uuid> in_use_uuid;
    std::shared_ptr<tracker_element_string> hardware;

    int options_entry_id;
};

// Packet chain component; we need to use a raw pointer here but it only exists
// for the lifetime of the packet being processed
class packetchain_comp_datasource : public packet_component {
public:
    kis_datasource *ref_source;

    packetchain_comp_datasource() {
        ref_source = nullptr;
    }

    virtual ~packetchain_comp_datasource() { }

    virtual bool unique() override { return true; }

    void reset() {
        ref_source = nullptr;
    }
};

#endif

