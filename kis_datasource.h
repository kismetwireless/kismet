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

// Fwd def for DST
class Datasourcetracker;

class KisDatasource : public tracker_component, public KisExternalInterface {
public:
    // Initialize and tell us what sort of builder
    KisDatasource(GlobalRegistry *in_globalreg, SharedDatasourceBuilder in_builder);

    virtual ~KisDatasource();

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
    virtual void set_channel_hop(double in_rate, SharedTrackerElement in_chans,
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
    __Proxy(source_name, std::string, std::string, std::string, source_name);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);

    // Source key is a checksum of the uuid for us to do fast indexing
    __Proxy(source_key, uint32_t, uint32_t, uint32_t, source_key);

    // Prototype/driver definition
    __ProxyTrackable(source_builder, KisDatasourceBuilder, source_builder);

    // Read-only access to the source state; this mirrors the state in the capture
    // binary. Set commands queue a command to the binary and then update as
    // they complete.
    __ProxyGet(source_definition, std::string, std::string, source_definition);
    __ProxyGet(source_interface, std::string, std::string, source_interface);
    __ProxyGet(source_cap_interface, std::string, std::string, source_cap_interface);
    __ProxyGet(source_hardware, std::string, std::string, source_hardware);

    __ProxyGet(source_dlt, uint32_t, uint32_t, source_dlt);

    __ProxyTrackable(source_channels_vec, TrackerElement, source_channels_vec);

    // Any alert state passed from the driver we want to be able to consistently
    // report to the user
    __ProxyGet(source_warning, std::string, std::string, source_warning);

    __ProxyGet(source_hopping, uint8_t, bool, source_hopping);
    __ProxyGet(source_channel, std::string, std::string, source_channel);
    __ProxyGet(source_hop_rate, double, double, source_hop_rate);
    __ProxyGet(source_split_hop, uint8_t, bool, source_hop_split);
    __ProxyGet(source_hop_offset, uint32_t, uint32_t, source_hop_offset);
    __ProxyGet(source_hop_shuffle, uint8_t, bool, source_hop_shuffle);
    __ProxyGet(source_hop_shuffle_skip, uint32_t, uint32_t, source_hop_shuffle_skip);
    __ProxyTrackable(source_hop_vec, TrackerElement, source_hop_vec);

    __ProxyGet(source_running, uint8_t, bool, source_running);

    __ProxyGet(source_remote, uint8_t, bool, source_remote);
    __ProxyGet(source_passive, uint8_t, bool, source_passive);

    __Proxy(source_num_packets, uint64_t, uint64_t, uint64_t, source_num_packets);
    __ProxyIncDec(source_num_packets, uint64_t, uint64_t, source_num_packets);

    __Proxy(source_num_error_packets, uint64_t, uint64_t, uint64_t, 
            source_num_error_packets);
    __ProxyIncDec(source_num_error_packets, uint64_t, uint64_t, 
            source_num_error_packets);

    __ProxyDynamicTrackable(source_packet_rrd, kis_tracked_minute_rrd<>, 
            packet_rate_rrd, packet_rate_rrd_id);

    // IPC binary name, if any
    __ProxyGet(source_ipc_binary, std::string, std::string, source_ipc_binary);
    // IPC channel pid, if any
    __ProxyGet(source_ipc_pid, int64_t, pid_t, source_ipc_pid);

    // Retry API - do we try to re-open when there's a problem?
    __ProxyGet(source_error, uint8_t, bool, source_error);
    __Proxy(source_retry, uint8_t, bool, bool, source_retry);
    __ProxyGet(source_retry_attempts, uint32_t, uint32_t, source_retry_attempts);

    __Proxy(source_number, uint64_t, uint64_t, uint64_t, source_number);

    __Proxy(source_paused, uint8_t, bool, bool, source_paused);


    // Random metadata
    __Proxy(source_info_antenna_type, std::string, std::string, std::string, source_info_antenna_type);
    __Proxy(source_info_antenna_gain, double, double, double, source_info_antenna_gain);
    __Proxy(source_info_antenna_orientation, double, double, double, source_info_antenna_orientation);
    __Proxy(source_info_antenna_beamwidth, double, double, double, source_info_antenna_beamwidth);
    __Proxy(source_info_amp_type, std::string, std::string, std::string, source_info_amp_type);
    __Proxy(source_info_amp_gain, double, double, double, source_info_amp_gain);


    
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


protected:
    // Source error; sets error state, fails all pending function callbacks,
    // shuts down the buffer and ipc, and initiates retry if we retry errors
    virtual void trigger_error(std::string in_reason);


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

            timetracker = in_src->timetracker;

            // Generate a timeout for 5 seconds from now
            timer_id = timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5,
                    NULL, 0, [in_src, this](int) -> int {
                    in_src->cancel_command(command_seq, "Command did not complete");
                    return 0;
                });

        }

        ~tracked_command() {
            if (timer_id > -1) {
                timetracker->RemoveTimer(timer_id);
            }
        }

        std::shared_ptr<Timetracker> timetracker;

        unsigned int transaction;
        uint32_t command_seq;
        time_t command_time;
        int timer_id;

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
    virtual bool dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c);

    virtual void handle_packet_configure_report(uint32_t in_seqno, std::string in_packet);
    virtual void handle_packet_data_report(uint32_t in_seqno, std::string in_packet);
    virtual void handle_packet_error_report(uint32_t in_seqno, std::string in_packet);
    virtual void handle_packet_interfaces_report(uint32_t in_seqno, std::string in_packet);
    virtual void handle_packet_opensource_report(uint32_t in_seqno, std::string in_packet);
    virtual void handle_packet_probesource_report(uint32_t in_seqno, std::string in_packet);

    virtual unsigned int send_configure_channel(std::string in_channel, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_configure_channel_hop(double in_rate, SharedTrackerElement in_chans,
            bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
            configure_callback_t in_cb);
    virtual unsigned int send_list_interfaces(unsigned int in_transaction, list_callback_t in_cb);
    virtual unsigned int send_open_source(std::string in_definition, unsigned int in_transaction, 
            open_callback_t in_cb);
    virtual unsigned int send_probe_source(std::string in_defintion, unsigned int in_transaction,
            probe_callback_t in_cb);

    // Break out packet generation sub-functions so that custom datasources can easily
    // piggyback onto the decoders
    virtual kis_packet *handle_sub_packet(KismetDatasource::SubPacket in_packet);
    virtual kis_gps_packinfo *handle_sub_gps(KismetDatasource::SubGps in_gps);
    virtual kis_layer1_packinfo *handle_sub_signal(KismetDatasource::SubSignal in_signal);


    // Launch the IPC binary
    virtual bool launch_ipc();


    // TrackerComponent API, we can't ever get instantiated from a saved element
    // so we always initialize as if we're a new object
    virtual void register_fields();
    virtual void reserve_fields(SharedTrackerElement e);

    // We don't build quite like a normal object so just remember what our
    // element ID is - it's a generic TrackerMap which holds our serializable
    // presentation data for indexing sources
    int datasource_entity_id;

    // We define internal proxies for the set_ commands because we don't present
    // a writeable trackercomponent interface - these are just mirrors of the state
    // given to us by the capture binary itself.  We use the ProxySet macros with
    // a modified function name so that we can easily set our tracker components
    // from the KV handlers
    __ProxySet(int_source_definition, std::string, std::string, source_definition);
    __ProxySet(int_source_interface, std::string, std::string, source_interface);
    __ProxySet(int_source_cap_interface, std::string, std::string, source_cap_interface);
    __ProxySet(int_source_hardware, std::string, std::string, source_hardware);
    __ProxySet(int_source_dlt, uint32_t, uint32_t, source_dlt);
    __ProxyTrackable(int_source_channels_vec, TrackerElement, source_channels_vec);

    __ProxySet(int_source_warning, std::string, std::string, source_warning);

    __ProxySet(int_source_hopping, uint8_t, bool, source_hopping);
    __ProxySet(int_source_channel, std::string, std::string, source_channel);
    __ProxySet(int_source_hop_rate, double, double, source_hop_rate);
    __ProxySet(int_source_hop_split, uint8_t, bool, source_hop_split);
    __ProxySet(int_source_hop_shuffle, uint8_t, bool, source_hop_shuffle);
    __ProxySet(int_source_hop_shuffle_skip, uint32_t, uint32_t, source_hop_shuffle_skip);
    __ProxySet(int_source_hop_offset, uint32_t, uint32_t, source_hop_offset);
    __ProxyTrackable(int_source_hop_vec, TrackerElement, source_hop_vec);

    // Prototype object which created us, defines our overall capabilities
    SharedDatasourceBuilder source_builder;

    // RW fields, they're relevant only to Kismet
    SharedTrackerElement source_name;
    SharedTrackerElement source_uuid;
    bool local_uuid;
    SharedTrackerElement source_key;

    // Read-only tracked element states
    
    // Raw definition
    SharedTrackerElement source_definition;

    // Network interface / filename
    SharedTrackerElement source_interface;
    // Optional interface we actually capture from - ie, linux wifi VIFs or resolved
    // USB device paths
    SharedTrackerElement source_cap_interface;
    // Optional hardware
    SharedTrackerElement source_hardware;

    // Interface DLT
    SharedTrackerElement source_dlt;

    // Builder for channel string elements
    SharedTrackerElement channel_entry_builder;

    // Possible channels supported by this source
    SharedTrackerElement source_channels_vec;

    // Warning to the user if something is funny in the source
    SharedTrackerElement source_warning;

    // Are we channel hopping?
    SharedTrackerElement source_hopping;

    // Current channel if we're not hopping
    SharedTrackerElement source_channel;

    // Current hop rate and vector of channels we hop through, if we're hopping
    SharedTrackerElement source_hop_rate;
    SharedTrackerElement source_hop_vec;

    SharedTrackerElement source_hop_split;
    SharedTrackerElement source_hop_offset;
    SharedTrackerElement source_hop_shuffle;
    SharedTrackerElement source_hop_shuffle_skip;

    SharedTrackerElement source_num_packets;
    SharedTrackerElement source_num_error_packets;

    int packet_rate_rrd_id;
    std::shared_ptr<kis_tracked_minute_rrd<> > packet_rate_rrd;


    // Local ID number is an increasing number assigned to each 
    // unique UUID; it's used inside Kismet for fast mapping for seenby, 
    // etc.  DST maps this to unique UUIDs after an Open
    SharedTrackerElement source_number;

    // Is the source paused?  If so, we throw out packets from it for now
    SharedTrackerElement source_paused;


    // Global registry all objects have for coordination
    GlobalRegistry *globalreg;



    // Retry API
    // Try to re-open sources in error automatically
    
    // Are we in error state?
    __ProxySet(int_source_error, uint8_t, bool, source_error);
    SharedTrackerElement source_error;

    // Why are we in error state?
    __ProxySet(int_source_error_reason, std::string, std::string, source_error_reason);
    SharedTrackerElement source_error_reason;

    // Do we want to try to re-open automatically?
    __ProxySet(int_source_retry, uint8_t, bool, source_retry);
    SharedTrackerElement source_retry;

    // How many consecutive errors have we had?
    __ProxySet(int_source_retry_attempts, uint32_t, uint32_t, source_retry_attempts);
    __ProxyIncDec(int_source_retry_attempts, uint32_t, uint32_t, source_retry_attempts);
    SharedTrackerElement source_retry_attempts;

    // How many total errors?
    __ProxySet(int_source_total_retry_attempts, uint32_t, uint32_t, 
            source_total_retry_attempts);
    __ProxyIncDec(int_source_total_retry_attempts, uint32_t, uint32_t, 
            source_total_retry_attempts);
    SharedTrackerElement source_total_retry_attempts;

    // Timer ID for trying to recover from an error
    int error_timer_id;

    // Timer ID for sending a PING
    int ping_timer_id;

    // Function that gets called when we encounter an error; allows for scheduling
    // bringup, etc
    virtual void handle_source_error();


    // Arbitrary data stored about the source, entered by the user
    SharedTrackerElement source_info_antenna_type;
    SharedTrackerElement source_info_antenna_gain;
    SharedTrackerElement source_info_antenna_orientation;
    SharedTrackerElement source_info_antenna_beamwidth;

    SharedTrackerElement source_info_amp_type;
    SharedTrackerElement source_info_amp_gain;
    


    // Communications API.  We implement a buffer interface and listen to the
    // incoming read buffer, we're agnostic if it's a network or IPC buffer.
    std::shared_ptr<BufferHandlerGeneric> ringbuf_handler;

    // If we're an IPC instance, the IPC control.  The ringbuf_handler is associated
    // with the IPC instance.
    std::shared_ptr<IPCRemoteV2> ipc_remote;

    // Do we clobber the remote timestamp?
    bool clobber_timestamp;

    SharedTrackerElement source_remote;
    __ProxySet(int_source_remote, uint8_t, bool, source_remote);

    SharedTrackerElement source_passive;
    __ProxySet(int_source_passive, uint8_t, bool, source_passive);

    SharedTrackerElement source_running;
    __ProxySet(int_source_running, uint8_t, bool, source_running);

    SharedTrackerElement source_ipc_binary;
    __ProxySet(int_source_ipc_binary, std::string, std::string, source_ipc_binary);

    SharedTrackerElement source_ipc_pid;
    __ProxySet(int_source_ipc_pid, int64_t, pid_t, source_ipc_pid);

    // Local list of additional arguments we pass to the IPC binary - could
    // be derived from the source line, could just be stuff we know
    std::vector<std::string> ipc_binary_args;


    // Interfaces we found via list
    std::vector<SharedInterface> listed_interfaces;
    SharedTrackerElement listed_interface_builder;


    // Thread
    std::shared_ptr<Timetracker> timetracker;


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
    int pack_comp_linkframe, pack_comp_l1info, pack_comp_gps, pack_comp_datasrc;

    // Reference to the DST
    std::shared_ptr<Datasourcetracker> datasourcetracker;

};

typedef std::shared_ptr<KisDatasource> SharedDatasource;

class KisDatasourceBuilder : public tracker_component {
public:
    KisDatasourceBuilder(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();

        if (in_id == 0) {
            tracked_id = entrytracker->RegisterField("kismet.datasource.type_driver",
                    TrackerMap, "Datasource type definition / driver");
        }
    }

    KisDatasourceBuilder(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
        initialize();

        if (in_id == 0) {
            tracked_id = entrytracker->RegisterField("kismet.datasource.type_driver",
                    TrackerMap, "Datasource type definition / driver");
        }
    }


    virtual ~KisDatasourceBuilder() { };

    virtual void initialize() { };

    // Build the actual data source; when subclassing this MUST fill in the prototype!
    // Due to semantics of shared_pointers we can't simply pass a 'this' sharedptr 
    // to the instantiated datasource, so we need to take a pointer to ourselves 
    // in the input.
    // Typical implementation:
    // return SharedDatasource(new SomeKismetDatasource(globalreg, in_shared_builder));
    virtual SharedDatasource build_datasource(SharedDatasourceBuilder 
            in_shared_builder __attribute__((unused))) { return NULL; };

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisDatasourceBuilder(globalreg, get_id()));
    }

    __Proxy(source_type, std::string, std::string, std::string, source_type);
    __Proxy(source_description, std::string, std::string, std::string, source_description);

    __Proxy(probe_capable, uint8_t, bool, bool, probe_capable);

    __Proxy(list_capable, uint8_t, bool, bool, list_capable);

    __Proxy(local_capable, uint8_t, bool, bool, local_capable);

    __Proxy(remote_capable, uint8_t, bool, bool, remote_capable);

    __Proxy(passive_capable, uint8_t, bool, bool, passive_capable);

    __Proxy(tune_capable, uint8_t, bool, bool, tune_capable);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.datasource.driver.type", TrackerString, 
                "Datasource type", &source_type);

        RegisterField("kismet.datasource.driver.description", TrackerString,
                "Datasource description", &source_description);

        RegisterField("kismet.datasource.driver.probe_capable", TrackerUInt8,
                "Datasource can automatically probe", &probe_capable);

        RegisterField("kismet.datasource.driver.probe_ipc", TrackerUInt8,
                "Datasource requires IPC to probe", &probe_capable);

        RegisterField("kismet.datasource.driver.list_capable", TrackerUInt8,
                "Datasource can list interfaces", &list_capable);

        RegisterField("kismet.datasource.driver.list_ipc", TrackerUInt8,
                "Datasource requires IPC to list interfaces", &list_capable);

        RegisterField("kismet.datasource.driver.local_capable", TrackerUInt8,
                "Datasource can support local interfaces", &local_capable);

        RegisterField("kismet.datasource.driver.local_ipc", TrackerUInt8,
                "Datasource requires IPC for local interfaces", &local_ipc);

        RegisterField("kismet.datasource.driver.remote_capable", TrackerUInt8,
                "Datasource can support remote interfaces", &remote_capable);

        RegisterField("kismet.datasource.driver.passive_capable", TrackerUInt8,
                "Datasource can support passive interface-less data", &passive_capable);

        RegisterField("kismet.datasource.driver.tuning_capable", TrackerUInt8,
                "Datasource can control channels", &tune_capable);
    }

    int datasource_entity_id;

    SharedTrackerElement source_type;
    SharedTrackerElement source_description;

    SharedTrackerElement probe_capable;
    SharedTrackerElement probe_ipc;

    SharedTrackerElement list_capable;
    SharedTrackerElement list_ipc;

    SharedTrackerElement local_capable;
    SharedTrackerElement local_ipc;

    SharedTrackerElement remote_capable;
    SharedTrackerElement passive_capable;

    SharedTrackerElement tune_capable;

};


// KisDatasourceInterface
// An automatically discovered interface, and any parameters needed to instantiate
// it; returned by the probe API

class KisDatasourceInterface : public tracker_component {
public:
    KisDatasourceInterface(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    KisDatasourceInterface(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual ~KisDatasourceInterface() { };

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisDatasourceInterface(globalreg, get_id()));
    }

    __Proxy(interface, std::string, std::string, std::string, interface);
    __ProxyTrackable(options_vec, TrackerElement, options_vec);

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
            TrackerElementVector v(get_options_vec());

            for (auto i = in_options.begin(); i != in_options.end(); ++i) {
                SharedTrackerElement o(new TrackerElement(TrackerString, 
                            options_entry_id));
                o->set(*i);
                v.push_back(o);
            }
        }
    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.datasource.probed.interface", TrackerString,
                "Interface name", &interface);
        RegisterField("kismet.datasource.probed.options_vec", TrackerVector,
                "Interface options", &options_vec);

        options_entry_id =
            RegisterField("kismet.datasource.probed.option", TrackerString,
                    "Interface option");

        RegisterField("kismet.datasource.probed.in_use_uuid", TrackerUuid,
                "Active source using this interface", &in_use_uuid);

        RegisterField("kismet.datasource.probed.hardware", TrackerString,
                "Hardware / chipset", &hardware);

    }

    SharedTrackerElement interface;
    SharedTrackerElement options_vec;

    SharedDatasourceBuilder prototype;

    SharedTrackerElement in_use_uuid;

    SharedTrackerElement hardware;

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

