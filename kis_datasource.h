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
#include "ipc_remote2.h"
#include "buffer_handler.h"
#include "uuid.h"
#include "gpstracker.h"
#include "packet.h"
#include "devicetracker_component.h"
#include "packetchain.h"
#include "entrytracker.h"
#include "kis_external.h"

#include "protobuf_cpp/kismet.pb.h"
#include "protobuf_cpp/datasource.pb.h"

// Builder class responsible for making an instance of this datasource
class KisDatasourceBuilder;
typedef std::shared_ptr<KisDatasourceBuilder> SharedDatasourceBuilder;

// Auto-discovered interface
class KisDatasourceInterface;
typedef std::shared_ptr<KisDatasourceInterface> SharedInterface;

// Simple keyed object derived from the low-level C protocol
class KisDatasourceCapKeyedObject;

class Datasourcetracker;
class KisDatasource;

class KisDatasourceBuilder : public tracker_component {
public:
    KisDatasourceBuilder() :
        tracker_component(0) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    KisDatasourceBuilder(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    KisDatasourceBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("KisDatasourceBuilder");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    virtual ~KisDatasourceBuilder() { };

    virtual void initialize() { };

    // Build the actual data source; when subclassing this MUST fill in the prototype!
    // Due to semantics of shared_pointers we can't simply pass a 'this' sharedptr 
    // to the instantiated datasource, so we need to take a pointer to ourselves 
    // in the input.
    // Typical implementation:
    // return SharedDatasource(new SomeKismetDatasource(globalreg, in_shared_builder));
    virtual std::shared_ptr<KisDatasource> build_datasource(std::shared_ptr<KisDatasourceBuilder>
            in_shared_builder __attribute__((unused))) { return NULL; };

    __Proxy(source_type, std::string, std::string, std::string, source_type);
    __Proxy(source_description, std::string, std::string, std::string, source_description);

    __Proxy(probe_capable, uint8_t, bool, bool, probe_capable);

    __Proxy(list_capable, uint8_t, bool, bool, list_capable);

    __Proxy(local_capable, uint8_t, bool, bool, local_capable);

    __Proxy(remote_capable, uint8_t, bool, bool, remote_capable);

    __Proxy(passive_capable, uint8_t, bool, bool, passive_capable);

    __Proxy(tune_capable, uint8_t, bool, bool, tune_capable);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        set_local_name("kismet.datasource.type_driver");

        RegisterField("kismet.datasource.driver.type", "Type", &source_type);
        RegisterField("kismet.datasource.driver.description", "Description", &source_description);

        RegisterField("kismet.datasource.driver.probe_capable", 
                "Datasource can automatically probe", &probe_capable);

        RegisterField("kismet.datasource.driver.probe_ipc", 
                "Datasource requires IPC to probe", &probe_ipc);

        RegisterField("kismet.datasource.driver.list_capable",
                "Datasource can list interfaces", &list_capable);

        RegisterField("kismet.datasource.driver.list_ipc", 
                "Datasource requires IPC to list interfaces", &list_ipc);

        RegisterField("kismet.datasource.driver.local_capable", 
                "Datasource can support local interfaces", &local_capable);

        RegisterField("kismet.datasource.driver.local_ipc", 
                "Datasource requires IPC for local interfaces", &local_ipc);

        RegisterField("kismet.datasource.driver.remote_capable",
                "Datasource can support remote interfaces", &remote_capable);

        RegisterField("kismet.datasource.driver.passive_capable", 
                "Datasource can support passive interface-less data", &passive_capable);

        RegisterField("kismet.datasource.driver.tuning_capable",
                "Datasource can control channels", &tune_capable);
    }

    int datasource_entity_id;

    std::shared_ptr<TrackerElementString> source_type;
    std::shared_ptr<TrackerElementString> source_description;
    std::shared_ptr<TrackerElementUInt8> probe_capable;
    std::shared_ptr<TrackerElementUInt8> probe_ipc;
    std::shared_ptr<TrackerElementUInt8> list_capable;
    std::shared_ptr<TrackerElementUInt8> list_ipc;
    std::shared_ptr<TrackerElementUInt8> local_capable;
    std::shared_ptr<TrackerElementUInt8> local_ipc;
    std::shared_ptr<TrackerElementUInt8> remote_capable;
    std::shared_ptr<TrackerElementUInt8> passive_capable;
    std::shared_ptr<TrackerElementUInt8> tune_capable;
};


class KisDatasource : public tracker_component, public KisExternalInterface {
public:
    // Initialize and tell us what sort of builder
    KisDatasource(SharedDatasourceBuilder in_builder);

    KisDatasource() :
        tracker_component(0),
        KisExternalInterface() {
        register_fields();
        reserve_fields(NULL);
    }

    KisDatasource(int in_id) :
        tracker_component(in_id),
        KisExternalInterface() {
        register_fields();
        reserve_fields(NULL);
    }

    KisDatasource(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id),
        KisExternalInterface() {
        register_fields();
        reserve_fields(e);
    }

    virtual ~KisDatasource();

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("KisDatasource");
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
    typedef std::function<void (unsigned int, std::vector<SharedInterface>)> list_callback_t;

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
    // Set the channel hop rate using a TrackerElement vector object
    virtual void set_channel_hop(double in_rate, 
            std::shared_ptr<TrackerElementVector> in_chans,
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


    // Connect an interface to a pre-existing buffer (such as from a TCP server
    // connection); This doesn't require async because we're just binding the
    // interface; anything we do with the buffer is itself async in the
    // future however
    virtual void connect_remote(std::shared_ptr<BufferHandlerGeneric> in_ringbuf,
            std::string in_definition, open_callback_t in_cb);


    // Close the source
    // Cancels any current activity (probe, open, pending commands) and sends a
    // terminate command to the capture binary.
    // Closing sends a failure result to any pending async commands
    // Closes an active source, and is called during the normal source shutdown
    // process in case of an error.  Closed sources may automatically re-open if
    // the retry option is configured.
    virtual void close_source();


    // Disables a source
    // Cancels any current activity, and sends a terminate to the capture binary.
    // Disables any error state and disables the error retry.
    virtual void disable_source();


    // Get an option from the definition
    virtual std::string get_definition_opt(std::string in_opt);
    virtual bool get_definition_opt_bool(std::string in_opt, bool in_default);
    virtual double get_definition_opt_double(std::string in_opt, double in_default);


    // Kismet-only variables can be set realtime, they have no capture-binary
    // equivalents and are only used for tracking purposes in the Kismet server
    __ProxyMS(source_name, std::string, std::string, std::string, source_name, ext_mutex);
    __ProxyMS(source_uuid, uuid, uuid, uuid, source_uuid, ext_mutex);

    // Source key is a checksum of the uuid for us to do fast indexing
    __ProxyMS(source_key, uint32_t, uint32_t, uint32_t, source_key, ext_mutex);

    // Prototype/driver definition
    __ProxyTrackableMS(source_builder, KisDatasourceBuilder, source_builder, ext_mutex);

    // Read-only access to the source state; this mirrors the state in the capture
    // binary. Set commands queue a command to the binary and then update as
    // they complete.
    __ProxyGetMS(source_definition, std::string, std::string, source_definition, ext_mutex);
    __ProxyGetMS(source_interface, std::string, std::string, source_interface, ext_mutex);
    __ProxyGetMS(source_cap_interface, std::string, std::string, source_cap_interface, ext_mutex);
    __ProxyGetMS(source_hardware, std::string, std::string, source_hardware, ext_mutex);

    __ProxyGetMS(source_dlt, uint32_t, uint32_t, source_dlt, ext_mutex);

    __ProxyTrackableMS(source_channels_vec, TrackerElementVector, source_channels_vec, ext_mutex);

    // Any alert state passed from the driver we want to be able to consistently
    // report to the user
    __ProxyGetMS(source_warning, std::string, std::string, source_warning, ext_mutex);

    __ProxyGetMS(source_hopping, uint8_t, bool, source_hopping, ext_mutex);
    __ProxyGetMS(source_channel, std::string, std::string, source_channel, ext_mutex);
    __ProxyGetMS(source_hop_rate, double, double, source_hop_rate, ext_mutex);
    __ProxyGetMS(source_split_hop, uint8_t, bool, source_hop_split, ext_mutex);
    __ProxyGetMS(source_hop_offset, uint32_t, uint32_t, source_hop_offset, ext_mutex);
    __ProxyGetMS(source_hop_shuffle, uint8_t, bool, source_hop_shuffle, ext_mutex);
    __ProxyGetMS(source_hop_shuffle_skip, uint32_t, uint32_t, source_hop_shuffle_skip, ext_mutex);
    __ProxyTrackableMS(source_hop_vec, TrackerElementVector, source_hop_vec, ext_mutex);

    __ProxyGetMS(source_running, uint8_t, bool, source_running, ext_mutex);

    __ProxyGetMS(source_remote, uint8_t, bool, source_remote, ext_mutex);
    __ProxyGetMS(source_passive, uint8_t, bool, source_passive, ext_mutex);

    __ProxyMS(source_num_packets, uint64_t, uint64_t, uint64_t, source_num_packets, ext_mutex);
    __ProxyIncDecMS(source_num_packets, uint64_t, uint64_t, source_num_packets, ext_mutex);

    __ProxyMS(source_num_error_packets, uint64_t, uint64_t, uint64_t, source_num_error_packets, ext_mutex);
    __ProxyIncDecMS(Msource_num_error_packets, uint64_t, uint64_t, source_num_error_packets, ext_mutex);

    __ProxyDynamicTrackableMS(source_packet_rrd, kis_tracked_minute_rrd<>, 
            packet_rate_rrd, packet_rate_rrd_id, ext_mutex);

    // IPC binary name, if any
    __ProxyGetMS(source_ipc_binary, std::string, std::string, source_ipc_binary, ext_mutex);
    // IPC channel pid, if any
    __ProxyGetMS(source_ipc_pid, int64_t, pid_t, source_ipc_pid, ext_mutex);

    // Retry API - do we try to re-open when there's a problem?
    __ProxyGetMS(source_error, uint8_t, bool, source_error, ext_mutex);
    __ProxyMS(source_retry, uint8_t, bool, bool, source_retry, ext_mutex);
    __ProxyGetMS(source_retry_attempts, uint32_t, uint32_t, source_retry_attempts, ext_mutex);

    __ProxyMS(source_number, uint64_t, uint64_t, uint64_t, source_number, ext_mutex);

    __ProxyMS(source_paused, uint8_t, bool, bool, source_paused, ext_mutex);


    // Random metadata
    __ProxyMS(source_info_antenna_type, std::string, std::string, std::string, source_info_antenna_type, ext_mutex);
    __ProxyMS(source_info_antenna_gain, double, double, double, source_info_antenna_gain, ext_mutex);
    __ProxyMS(source_info_antenna_orientation, double, double, double, source_info_antenna_orientation, ext_mutex);
    __ProxyMS(source_info_antenna_beamwidth, double, double, double, source_info_antenna_beamwidth, ext_mutex);
    __ProxyMS(source_info_amp_type, std::string, std::string, std::string, source_info_amp_type, ext_mutex);
    __ProxyMS(source_info_amp_gain, double, double, double, source_info_amp_gain, ext_mutex);

    // Overridden linktype
    __ProxyPrivSplitMS(source_override_linktype, unsigned int, unsigned int, uint32_t, 
            source_override_linktype, ext_mutex);

    
    // Perform a checksum on a packet after it's decapsulated; this is always
    // called; a source should override it and check flags in the source
    // definition to see if it should be checksummed
    //
    // Additional checksum data (like FCS frames) will be in the packet
    // from the DLT decoders.
    //
    // Checksum functions should flag the packet as invalid directly via some
    // method recognized by the device categorization stage
    virtual void checksum_packet(kis_packet *in_pack __attribute__((unused))) { return; }

    // IPC error
    virtual void BufferError(std::string in_error) override;

    virtual void pre_serialize() override {
        local_eol_shared_locker l(ext_mutex);
    }

    virtual void post_serialize() override {
        local_shared_unlocker ul(ext_mutex);
    }

protected:
    // Source error; sets error state, fails all pending function callbacks,
    // shuts down the buffer and ipc, and initiates retry if we retry errors
    virtual void trigger_error(std::string in_reason) override;


    // Common interface parsing to set our name/uuid/interface and interface
    // config pairs.  Once this is done it will have automatically set any 
    // local variables like name, uuid, etc that needed to get set.
    virtual bool parse_interface_definition(std::string in_definition);

    // Split out local var-key pairs for the source definition
    std::map<std::string, std::string> source_definition_opts;


    // Async command API
    // Commands have to be sent over the IPC channel or the network connection, making
    // all commands fundamentally asynchronous.
    // Any set / open / probe / list command takes an optional callback
    // which will be called on completion of the command

    // Tracker object for our map of commands which haven't finished
    class tracked_command {
    public:
        tracked_command(unsigned int in_trans, uint32_t in_seq, KisDatasource *in_src) {
            transaction = in_trans;
            command_seq = in_seq;
            command_time = time(0);

            timetracker = 
                Globalreg::FetchMandatoryGlobalAs<Timetracker>();

            // Generate a timeout for 5 seconds from now
            auto src_alias = in_src;
            timer_id = timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 15,
                    NULL, 0, [src_alias, this](int) -> int {
                    src_alias->cancel_command(command_seq, "Command did not complete");
                    return 0;
                });

        }

        ~tracked_command() {
            if (timer_id > -1) {
                timetracker->RemoveTimer(timer_id);
                timer_id = -1;
            }
        }

        std::shared_ptr<Timetracker> timetracker;

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
    std::map<uint32_t, std::shared_ptr<KisDatasource::tracked_command> > command_ack_map;

    // Get a command
    virtual std::shared_ptr<KisDatasource::tracked_command> get_command(uint32_t in_transaction);

    // Cancel a specific command; exposed as a function for easy callbacks
    virtual void cancel_command(uint32_t in_transaction, std::string in_reason);

    // Kill any pending commands - we're entering error state or closing, so 
    // any pending callbacks get cleared out
    virtual void cancel_all_commands(std::string in_error);


    // Central packet dispatch override to add the datasource commands
    virtual bool dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) override;

    virtual void handle_msg_proxy(const std::string& msg, const int type) override;

    virtual void handle_packet_configure_report(uint32_t in_seqno, const std::string& in_packet);
    virtual void handle_packet_data_report(uint32_t in_seqno, const std::string& in_packet);
    virtual void handle_packet_error_report(uint32_t in_seqno, const std::string& in_packet);
    virtual void handle_packet_interfaces_report(uint32_t in_seqno, const std::string& in_packet);
    virtual void handle_packet_opensource_report(uint32_t in_seqno, const std::string& in_packet);
    virtual void handle_packet_probesource_report(uint32_t in_seqno, const std::string& in_packet);
    virtual void handle_packet_warning_report(uint32_t in_seqno, const std::string& in_packet);

    virtual unsigned int send_configure_channel(std::string in_channel, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_configure_channel_hop(double in_rate,
            std::shared_ptr<TrackerElementVector> in_chans,
            bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_list_interfaces(unsigned int in_transaction, list_callback_t in_cb);
    virtual unsigned int send_open_source(std::string in_definition, unsigned int in_transaction, 
            open_callback_t in_cb);
    virtual unsigned int send_probe_source(std::string in_defintion, unsigned int in_transaction,
            probe_callback_t in_cb);

    // Break out packet generation sub-functions so that custom datasources can easily
    // piggyback onto the decoders
    virtual kis_gps_packinfo *handle_sub_gps(KismetDatasource::SubGps in_gps);
    virtual kis_layer1_packinfo *handle_sub_signal(KismetDatasource::SubSignal in_signal);


    // Launch the IPC binary
    virtual bool launch_ipc();


    // TrackerComponent API, we can't ever get instantiated from a saved element
    // so we always initialize as if we're a new object
    virtual void register_fields() override;

    // We don't build quite like a normal object so just remember what our
    // element ID is - it's a generic TrackerMap which holds our serializable
    // presentation data for indexing sources
    int datasource_entity_id;

    // We define internal proxies for the set_ commands because we don't present
    // a writeable trackercomponent interface - these are just mirrors of the state
    // given to us by the capture binary itself.  We use the ProxySet macros with
    // a modified function name so that we can easily set our tracker components
    // from the KV handlers
    __ProxySetMS(int_source_definition, std::string, std::string, source_definition, ext_mutex);
    __ProxySetMS(int_source_interface, std::string, std::string, source_interface, ext_mutex);
    __ProxySetMS(int_source_cap_interface, std::string, std::string, source_cap_interface, ext_mutex);
    __ProxySetMS(int_source_hardware, std::string, std::string, source_hardware, ext_mutex);
    __ProxySetMS(int_source_dlt, uint32_t, uint32_t, source_dlt, ext_mutex);
    __ProxyTrackableMS(int_source_channels_vec, TrackerElementVector, source_channels_vec, ext_mutex);

    __ProxySetMS(int_source_warning, std::string, std::string, source_warning, ext_mutex);

    __ProxySetMS(int_source_hopping, uint8_t, bool, source_hopping, ext_mutex);
    __ProxySetMS(int_source_channel, std::string, std::string, source_channel, ext_mutex);
    __ProxySetMS(int_source_hop_rate, double, double, source_hop_rate, ext_mutex);
    __ProxySetMS(int_source_hop_split, uint8_t, bool, source_hop_split, ext_mutex);
    __ProxySetMS(int_source_hop_shuffle, uint8_t, bool, source_hop_shuffle, ext_mutex);
    __ProxySetMS(int_source_hop_shuffle_skip, uint32_t, uint32_t, source_hop_shuffle_skip, ext_mutex);
    __ProxySetMS(int_source_hop_offset, uint32_t, uint32_t, source_hop_offset, ext_mutex);
    __ProxyTrackableMS(int_source_hop_vec, TrackerElementVector, source_hop_vec, ext_mutex);

    // Prototype object which created us, defines our overall capabilities
    std::shared_ptr<KisDatasourceBuilder> source_builder;

    // RW fields, they're relevant only to Kismet
    std::shared_ptr<TrackerElementString> source_name;
    std::shared_ptr<TrackerElementUUID> source_uuid;
    bool local_uuid;
    std::shared_ptr<TrackerElementUInt32> source_key;

    // Read-only tracked element states
    
    // Raw definition
    std::shared_ptr<TrackerElementString> source_definition;

    // Network interface / filename
    std::shared_ptr<TrackerElementString> source_interface;
    // Optional interface we actually capture from - ie, linux wifi VIFs or resolved USB device paths
    std::shared_ptr<TrackerElementString> source_cap_interface;
    // Optional hardware
    std::shared_ptr<TrackerElementString> source_hardware;

    // Interface DLT
    std::shared_ptr<TrackerElementUInt32> source_dlt;

    int channel_entry_id;

    // Possible channels supported by this source
    std::shared_ptr<TrackerElementVector> source_channels_vec;

    // Warning to the user if something is funny in the source
    std::shared_ptr<TrackerElementString> source_warning;

    // Are we channel hopping?
    std::shared_ptr<TrackerElementUInt8> source_hopping;

    // Current channel if we're not hopping
    std::shared_ptr<TrackerElementString> source_channel;

    // Current hop rate and vector of channels we hop through, if we're hopping
    std::shared_ptr<TrackerElementDouble> source_hop_rate;
    std::shared_ptr<TrackerElementVector> source_hop_vec;
    int source_hop_vec_id;

    std::shared_ptr<TrackerElementUInt8> source_hop_split;
    std::shared_ptr<TrackerElementUInt32> source_hop_offset;
    std::shared_ptr<TrackerElementUInt8> source_hop_shuffle;
    std::shared_ptr<TrackerElementUInt32> source_hop_shuffle_skip;

    std::shared_ptr<TrackerElementUInt32> source_num_packets;
    std::shared_ptr<TrackerElementUInt32> source_num_error_packets;

    int packet_rate_rrd_id;
    std::shared_ptr<kis_tracked_minute_rrd<>> packet_rate_rrd;


    // Local ID number is an increasing number assigned to each 
    // unique UUID; it's used inside Kismet for fast mapping for seenby, 
    // etc.  DST maps this to unique UUIDs after an Open
    std::shared_ptr<TrackerElementUInt64> source_number;

    // Is the source paused?  If so, we throw out packets from it for now
    std::shared_ptr<TrackerElementUInt8> source_paused;


    // Retry API
    // Try to re-open sources in error automatically
    
    // Are we in error state?
    __ProxySetMS(int_source_error, uint8_t, bool, source_error, ext_mutex);
    std::shared_ptr<TrackerElementUInt8> source_error;

    // Why are we in error state?
    __ProxySetMS(int_source_error_reason, std::string, std::string, source_error_reason, ext_mutex);
    std::shared_ptr<TrackerElementString> source_error_reason;

    // Do we want to try to re-open automatically?
    __ProxySetMS(int_source_retry, uint8_t, bool, source_retry, ext_mutex);
    std::shared_ptr<TrackerElementUInt8> source_retry;

    // How many consecutive errors have we had?
    __ProxySetMS(int_source_retry_attempts, uint32_t, uint32_t, source_retry_attempts, ext_mutex);
    __ProxyIncDecMS(int_source_retry_attempts, uint32_t, uint32_t, source_retry_attempts, ext_mutex);
    std::shared_ptr<TrackerElementUInt32> source_retry_attempts;

    // How many total errors?
    __ProxySetMS(int_source_total_retry_attempts, uint32_t, uint32_t, source_total_retry_attempts, ext_mutex);
    __ProxyIncDecMS(int_source_total_retry_attempts, uint32_t, uint32_t, source_total_retry_attempts, ext_mutex);
    std::shared_ptr<TrackerElementUInt32> source_total_retry_attempts;

    // Timer ID for trying to recover from an error
    int error_timer_id;

    // Timer ID for sending a PING
    int ping_timer_id;

    // Function that gets called when we encounter an error; allows for scheduling
    // bringup, etc
    virtual void handle_source_error();


    // Arbitrary data stored about the source, entered by the user
    std::shared_ptr<TrackerElementString> source_info_antenna_type;
    std::shared_ptr<TrackerElementDouble> source_info_antenna_gain;
    std::shared_ptr<TrackerElementDouble> source_info_antenna_orientation;
    std::shared_ptr<TrackerElementDouble> source_info_antenna_beamwidth;

    std::shared_ptr<TrackerElementString> source_info_amp_type;
    std::shared_ptr<TrackerElementDouble> source_info_amp_gain;

    std::shared_ptr<TrackerElementUInt32> source_override_linktype;
    

    // Do we clobber the remote timestamp?
    bool clobber_timestamp;

    __ProxySetMS(int_source_remote, uint8_t, bool, source_remote, ext_mutex);
    std::shared_ptr<TrackerElementUInt8> source_remote;

    __ProxySetMS(int_source_passive, uint8_t, bool, source_passive, ext_mutex);
    std::shared_ptr<TrackerElementUInt8> source_passive;

    __ProxySetMS(int_source_running, uint8_t, bool, source_running, ext_mutex);
    std::shared_ptr<TrackerElementUInt8> source_running;

    __ProxySetMS(int_source_ipc_binary, std::string, std::string, source_ipc_binary, ext_mutex);
    std::shared_ptr<TrackerElementString> source_ipc_binary;

    __ProxySetMS(int_source_ipc_pid, int64_t, pid_t, source_ipc_pid, ext_mutex);
    std::shared_ptr<TrackerElementInt64> source_ipc_pid;


    // Interfaces we found via list
    std::vector<SharedInterface> listed_interfaces;
    int listed_interface_entry_id;

    // Special modes which suppress error output and retry handling
    bool mode_probing;
    bool mode_listing;

    // We've gotten our response from an operation, don't report additional errors
    bool quiet_errors;

    // Last time we saw a PONG
    time_t last_pong;

    // Packetchain
    std::shared_ptr<Packetchain> packetchain;

    // Packet components we inject
    int pack_comp_linkframe, pack_comp_l1info, pack_comp_gps, pack_comp_datasrc,
        pack_comp_json, pack_comp_protobuf;

};

typedef std::shared_ptr<KisDatasource> SharedDatasource;

// KisDatasourceInterface
// An automatically discovered interface, and any parameters needed to instantiate
// it; returned by the probe API

class KisDatasourceInterface : public tracker_component {
public:
    KisDatasourceInterface() :
        tracker_component(0) {
        register_fields();
        reserve_fields(NULL);
    }

    KisDatasourceInterface(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    KisDatasourceInterface(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual ~KisDatasourceInterface() { };

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("KisDatasourceInterface");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(interface, std::string, std::string, std::string, interface);
    __ProxyTrackable(options_vec, TrackerElementVector, options_vec);

    __ProxyTrackable(prototype, KisDatasourceBuilder, prototype);

    __Proxy(in_use_uuid, uuid, uuid, uuid, in_use_uuid);

    __Proxy(hardware, std::string, std::string, std::string, hardware);

    void populate(std::string in_interface, std::string in_options) {
        std::vector<std::string> optvec = StrTokenize(in_options, ",");
        populate(in_interface, optvec);
    }

    void populate(std::string in_interface, std::vector<std::string> in_options) {
        set_interface(in_interface);

        if (in_options.size() != 0) {
            for (auto i : *options_vec) {
                auto o = std::make_shared<TrackerElementString>(options_entry_id, 
                        GetTrackerValue<std::string>(i));
                options_vec->push_back(o);
            }
        }
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.datasource.probed.interface", "Interface name", &interface);
        RegisterField("kismet.datasource.probed.options_vec",
                "Interface options", &options_vec);

        options_entry_id =
            RegisterField("kismet.datasource.probed.option",
                    TrackerElementFactory<TrackerElementString>(),
                    "Interface option");

        RegisterField("kismet.datasource.probed.in_use_uuid",
                "Active source using this interface", &in_use_uuid);

        RegisterField("kismet.datasource.probed.hardware",
                "Hardware / chipset", &hardware);

    }

    std::shared_ptr<TrackerElementString> interface;
    std::shared_ptr<TrackerElementVector> options_vec;

    std::shared_ptr<KisDatasourceBuilder> prototype;

    std::shared_ptr<TrackerElementUUID> in_use_uuid;
    std::shared_ptr<TrackerElementString> hardware;

    int options_entry_id;

};

// Packet chain component; we need to use a raw pointer here but it only exists
// for the lifetime of the packet being processed
class packetchain_comp_datasource : public packet_component {
public:
    KisDatasource *ref_source;

    packetchain_comp_datasource() {
        self_destruct = 1;
        ref_source = NULL;
    }

    virtual ~packetchain_comp_datasource() { }
};

#endif

