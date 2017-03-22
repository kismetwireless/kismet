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
#include "ipc_remote2.h"
#include "ringbuf_handler.h"
#include "uuid.h"
#include "gps_manager.h"
#include "packet.h"
#include "devicetracker_component.h"
#include "packetchain.h"
#include "simple_datasource_proto.h"
#include "entrytracker.h"

// Builder class responsible for making an instance of this datasource
class KisDatasourceBuilder;
typedef shared_ptr<KisDatasourceBuilder> SharedDatasourceBuilder;

// Auto-discovered interface
class KisDatasourceInterface;
typedef shared_ptr<KisDatasourceInterface> SharedInterface;

// Simple keyed object derived from the low-level C protocol
class KisDatasourceCapKeyedObject;

class KisDatasource : public tracker_component, public RingbufferInterface {
public:
    // Initialize and tell us what sort of builder
    KisDatasource(GlobalRegistry *in_globalreg, SharedDatasourceBuilder in_builder);

    // Async command API
    // All commands to change non-local state are asynchronous.  Failure, success,
    // and state change will not be known until the command completes.
    // To marshal this, all commands take a transaction id (arbitrary number provided
    // by the caller) and a callback function.  If the function exists, it is called
    // when the command completes.
    
    // 'List' callback - called with caller-supplied transaction id and contents,
    // if any, of the interface list command
    typedef function<void (unsigned int, vector<SharedInterface>)> list_callback_t;

    // List all interfaces this source can support
    virtual void list_interfaces(unsigned int in_transaction, list_callback_t in_cb);

    // 'Probe' callback - called with caller-supplied transaction id and success
    // or failure of the probe command and string message of any additional 
    // information if there was a MESSAGE key in the PROBERESP or if there was a
    // local communications error.
    typedef function<void (unsigned int, bool, string)> probe_callback_t;

    // Probe to determine if a specific interface is supported by this source
    virtual void probe_interface(string in_definition, unsigned int in_transaction,
            probe_callback_t in_cb);

    // 'Open' callback - called with the caller-supplied transaction id,
    // success (or not) of open command, and a string message of any failure
    // data if there was a MESSAGE key in the OPENRESP or there was a
    // local communications error.
    typedef function<void (unsigned int, bool, string)> open_callback_t;

    // Open an interface defined by in_definition
    virtual void open_interface(string in_definition, unsigned int in_transaction,
            open_callback_t in_cb);

    // 'Configure' callback - called when a configure-related command such as
    // channel set, hop set, etc is performed.  Returns the caller-supplied
    // transaction id, success, string message (if any) related to a failure
    typedef function<void (unsigned int, bool, string)> configure_callback_t;

    // Lock to a specific channel and stop hopping
    virtual void set_channel(string in_channel, unsigned int in_transaction,
            configure_callback_t in_cb);

    // Set the channel hop rate and list of channels to hop on, using a string vector
    virtual void set_channel_hop(double in_rate, std::vector<std::string> in_chans,
            unsigned int in_transaction, configure_callback_t in_cb);
    // Set the channel hop rate using a TrackerElement vector object
    virtual void set_channel_hop(double in_rate, SharedTrackerElement in_chans,
            unsigned int in_transaction, configure_callback_t in_cb);
    // Set just the channel hop rate; internally this is the same as setting a 
    // hop+vector but we simplify the API for callers
    virtual void set_channel_hop_rate(double in_rate, unsigned int in_transaction,
            configure_callback_t in_cb);
    // Set just the hop channels; internally this is the same as setting a
    // hop+vector but we simplify the API for callers
    virtual void set_channel_hop_list(std::vector<std::string> in_chans, 
            unsigned int in_transaction, configure_callback_t in_cb);

    // Connect an interface to a pre-existing ringbuffer (such as from a TCP server
    // connection); This doesn't require async because we're just binding the
    // interface; anything we do with the ringbuffer is itself async in the
    // future however
    virtual void connect_ringbuffer(shared_ptr<RingbufferHandler> in_ringbuf);


    // Close the source
    // Cancels any current activity (probe, open, pending commands) and sends a
    // terminate command to the capture binary.
    // Closing sends a failure result to any pending async commands
    virtual void close_source();




    // Ringbuffer interface - called when the attached ringbuffer has data available.
    // Datasources only bind to the read side of the buffer handler.  This connection
    // may be made to IPC or network, and speaks the kismet datasource simplified
    // protocol.  This function does basic framing and then calls the private 
    // hierarchy of key-value parsers.
    virtual void BufferAvailable(size_t in_amt);

    // Ringbuffer interface - handles error on IPC or TCP, called when there is a 
    // low-level error on the communications stack (process death, etc).
    // Passes error to the the internal source_error function
    virtual void BufferError(string in_error);

    // Kismet-only variables can be set realtime, they have no capture-binary
    // equivalents and are only used for tracking purposes in the Kismet server
    __Proxy(source_name, string, string, string, source_name);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);

    // Prototype/driver definition
    __ProxyTrackable(source_builder, KisDatasourceBuilder, source_builder);

    // Read-only access to the source state; this mirrors the state in the capture
    // binary. Set commands queue a command to the binary and then update as
    // they complete.
    __ProxyGet(source_definition, string, string, source_definition);
    __ProxyGet(source_interface, string, string, source_interface);
    __ProxyTrackable(source_channels_vec, TrackerElement, source_channels_vec);
    __ProxyGet(source_hopping, uint8_t, bool, source_hopping);
    __ProxyGet(source_channel, string, string, source_channel);
    __ProxyGet(source_hop_rate, double, double, source_hop_rate);
    __ProxyTrackable(source_hop_vec, TrackerElement, source_hop_vec);



    // Retry API - do we try to re-open when there's a problem?
    __ProxyGet(source_error, uint8_t, bool, source_error);
    __Proxy(source_retry, uint8_t, bool, bool, source_retry);
    __ProxyGet(source_retry_attempts, uint32_t, uint32_t, source_retry_attempts);



protected:

    // Source error; sets error state, fails all pending function callbacks,
    // shuts down the ringbuffer and ipc, and initiates retry if we retry errors
    virtual void trigger_error(string in_reason);


    // Common interface parsing to set our name/uuid/interface and interface
    // config pairs
    virtual bool parse_interface_definition(string in_definition);


    // Async command API
    // Commands have to be sent over the IPC channel or the network connection, making
    // all commands fundamentally asynchronous.
    // Any set / open / probe / list command takes an optional callback
    // which will be called on completion of the command
    
    // Tracker object for our map of commands which haven't finished
    class tracked_command {
    public:
        tracked_command(unsigned int in_trans, uint32_t in_seq) {
            transaction = in_trans;
            command_seq = in_seq;
            command_time = time(0);
        }

        unsigned int transaction;
        uint32_t command_seq;
        time_t command_time;

        // Callbacks
        list_callback_t list_cb;
        probe_callback_t probe_cb;
        open_callback_t open_cb;
        configure_callback_t configure_cb;
    };

    // Tracked commands we need to ack
    std::map<uint32_t, KisDatasource::tracked_command *> command_ack_map;




    // Datasource protocol - each datasource is responsible for processing incoming
    // data, which may come from IPC or may come from the network.  Handling is
    // dispatched by packet type, then kv pairs.  Packets and kv pair handling
    // can be overridden to add additional handlers.  When overriding, make sure
    // to call the parent implementation to get the default packet handling.
    typedef map<string, KisDatasourceCapKeyedObject *> KVmap;

    // Datasource protocol - dispatch handler.  Handles dispatching top-level
    // packet types to helper functions.  Automatically handles the default
    // packet types, and can be overridden to handle additional types.
    virtual void proto_dispatch_packet(string in_type, KVmap in_kvmap);

    // Top-level default packet type handlers for the datasource simplified protocol
    virtual void proto_packet_status(KVmap in_kvpairs);
    virtual void proto_packet_probe_resp(KVmap in_kvpairs);
    virtual void proto_packet_open_resp(KVmap in_kvpairs);
    virtual void proto_packet_error(KVmap in_kvpairs);
    virtual void proto_packet_message(KVmap in_kvpairs);
    virtual void proto_packet_configure(KVmap in_kvpairs);
    virtual void proto_packet_data(KVmap in_kvpairs);

    // Common K-V pair handlers that are likely to be found in multiple types
    // of packets; these can be used by custom packet handlers to implement automatic
    // "proper" behavior for existing pairs, or overridden and extended.  In general,
    // datasources will want to extend proto_dispatch_packet and add their own
    // packet types, and generally should not override the core pair handlers.
    //
    // Default KV handlers have some hidden complexities: they are responsible for
    // maintaining the async events, filling in the packet responses, etc.
    virtual bool handle_kv_success(KisDatasourceCapKeyedObject *in_obj);
    virtual bool handle_kv_message(KisDatasourceCapKeyedObject *in_obj);
    virtual bool handle_kv_channels(KisDatasourceCapKeyedObject *in_obj);
    virtual bool handle_kv_config_channel(KisDatasourceCapKeyedObject *in_obj);
    virtual bool handle_kv_config_hop(KisDatasourceCapKeyedObject *in_obj);
    virtual kis_gps_packinfo *handle_kv_gps(KisDatasourceCapKeyedObject *in_obj);
    virtual kis_layer1_packinfo *handle_kv_signal(KisDatasourceCapKeyedObject *in_obj);
    virtual kis_packet *handle_kv_packet(KisDatasourceCapKeyedObject *in_obj);


    // Assemble a packet it write it out the ringbuffer, returning a command 
    // sequence number in ret_seqno.  Returns false on low-level failure such as
    // inability to write to the ringbuffer
    virtual bool write_packet(string in_cmd, KVmap in_kvpairs, uint32_t &ret_seqno);


    // Form basic commands; call the callback with failure if we're unable to
    // form the low-level command
    virtual bool send_command_list_interfaces(unsigned int in_transaction,
            list_callback_t in_cb);
    virtual bool send_command_probe_interface(string in_definition, 
            unsigned int in_transaction, probe_callback_t in_cb);
    virtual bool send_command_open_interface(string in_definition,
            unsigned int in_transaction, open_callback_t in_cb);
    virtual bool send_command_set_channel(string in_channel,
            unsigned int in_transaction, configure_callback_t in_cb);
    virtual bool send_command_set_channel_hop(double in_rate,
            SharedTrackerElement in_chans, unsigned int in_transaction,
            configure_callback_t in_cb);


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
    __ProxySet(int_source_definition, string, string, source_definition);
    __ProxySet(int_source_interface, string, string, source_interface);
    __ProxyTrackable(int_source_channels_vec, TrackerElement, source_channels_vec);
    __ProxySet(int_source_hopping, uint8_t, bool, source_hopping);
    __ProxySet(int_source_channel, string, string, source_channel);
    __ProxySet(int_source_hop_rate, double, double, source_hop_rate);
    __ProxyTrackable(int_source_hop_vec, TrackerElement, source_hop_vec);

    // Prototype object which created us, defines our overall capabilities
    SharedDatasourceBuilder source_builder;

    // RW fields, they're relevant only to Kismet
    SharedTrackerElement source_name;
    SharedTrackerElement source_uuid;

    // Read-only tracked element states
    
    // Raw definition
    SharedTrackerElement source_definition;
   
    // Network interface / filename
    SharedTrackerElement source_interface;

    // Builder for channel string elements
    SharedTrackerElement channel_entry_builder;

    // Possible channels supported by this source
    SharedTrackerElement source_channels_vec;

    // Are we channel hopping?
    SharedTrackerElement source_hopping;

    // Current channel if we're not hopping
    SharedTrackerElement source_channel;

    // Current hop rate and vector of channels we hop through, if we're hopping
    SharedTrackerElement source_hop_rate;
    SharedTrackerElement source_hop_vec;


    // Global registry all objects have for coordination
    GlobalRegistry *globalreg;



    // Retry API
    // Try to re-open sources in error automatically
    
    // Are we in error state?
    __ProxySet(int_source_error, uint8_t, bool, source_error);
    SharedTrackerElement source_error;

    // Do we want to try to re-open automatically?
    SharedTrackerElement source_retry;

    // How many consecutive errors have we had?
    __ProxySet(int_source_retry_attempts, uint32_t, uint32_t, source_retry_attempts);
    SharedTrackerElement source_retry_attempts;

    // Timer ID for trying to recover from an error
    int error_timer_id;

    // Function that gets called when we encounter an error
    virtual void handle_source_error();




    // Communications API.  We implement a ringbuffer interface and listen to the
    // incoming read buffer, we're agnostic if it's a network or IPC buffer.
    shared_ptr<RingbufferHandler> ringbuf_handler;

    // If we're an IPC instance, the IPC control.  The ringbuf_handler is associated
    // with the IPC instance.
    IPCRemoteV2 *ipc_remote;

};

typedef shared_ptr<KisDatasource> SharedDatasource;

class KisDatasourceBuilder : public tracker_component {
public:
    KisDatasourceBuilder(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
        Initialize();
    }

    KisDatasourceBuilder(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
        Initialize();
    }

    virtual ~KisDatasourceBuilder() { };

    virtual void Initialize() { };

    // Build the actual data source; when subclassing this MUST fill in the prototype!
    // Due to semantics of shared_pointers we can't simply pass a 'this' sharedptr 
    // to the instantiated datasource, so we need to take a pointer to ourselves 
    // in the input.
    // Typical implementation:
    // return SharedDatasource(new SomeKismetDatasource(globalreg, in_shared_builder));
    virtual SharedDatasource build_datasource(SharedDatasourceBuilder 
            in_shared_builder) = 0;

    __Proxy(source_type, string, string, string, source_type);
    __Proxy(source_description, string, string, string, source_description);

    __Proxy(probe_capable, uint8_t, bool, bool, probe_capable);
    __Proxy(probe_ipc, uint8_t, bool, bool, probe_ipc);

    __Proxy(list_capable, uint8_t, bool, bool, list_capable);
    __Proxy(list_ipc, uint8_t, bool, bool, list_ipc);

    __Proxy(local_capable, uint8_t, bool, bool, local_capable);
    __Proxy(local_ipc, uint8_t, bool, bool, local_ipc);

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

    shared_ptr<EntryTracker> entrytracker;

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

    virtual ~KisDatasourceInterface();

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisDatasourceInterface(globalreg, get_id()));
    }

    __Proxy(interface, string, string, string, interface);
    __ProxyTrackable(options_vec, TrackerElement, options_vec);

    __ProxyTrackable(prototype, KisDatasourceBuilder, prototype);

    void populate(string in_interface, vector<string> in_options) {
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

        __RegisterComplexField(KisDataSourceBuilder, prototype_id,
                "kismet.datasource.probed.driver", "Autoprobed driver");

    }

    SharedTrackerElement interface;
    SharedTrackerElement options_vec;

    int prototype_id;
    SharedDatasourceBuilder prototype;

    int options_entry_id;

};

class KisDataSource_CapKeyedObject {
public:
    KisDataSource_CapKeyedObject(simple_cap_proto_kv *in_kp);
    KisDataSource_CapKeyedObject(string in_key, const char *in_object, ssize_t in_len);
    ~KisDataSource_CapKeyedObject();

    string key;
    size_t size;
    char *object;
};

#if 0
/*
 * Kismet Data Source
 *
 * Data sources replace packetsources in the new Kismet code model.
 * A data source is the kismet_server side of a capture engine:  It accepts
 * data frames from a capture binary over network or IPC and injects them to the
 * packet tracker.  Additionally, datasources can accept complex network objects
 * and interact directly with the device tracker system for non-packet-based
 * captures.
 *
 * A small number of capture sources will not need any capture driver code; 
 * All others will need to launch their capture binary and communicate with it,
 * or communicate with a network instance supplied by the datasourcetracker.
 * Datasource code should be as agnostic as possible and work with the RBI 
 * so that it will interface automatically with the IPC management and network 
 * connections.
 *
 * The same common protocol is used for local ipc and remote network sources.
 *
 * Data frames are defined in simple_datasource_proto.h.  A frame consists of an
 * overall type and multiple objects indexed by name.  Each object may
 * contain additional data.
 *
 * Objects are packed using the msgpack library as dictionaries of named values.
 *
 * Msgpack abstracts endian and byte issues and has implementations in nearly
 * every language, hopefully allowing the capture binary code to be highly
 * agnostic & writeable in any suitable language.  The key:value nomenclature 
 * allows for arbitrary changes to the protocol without breaking a rigid framing
 * structure.
 *
 * A datasource builder defines the capabilities and describes the functionality
 * of the datasource; it is used to instantiate an actual datasource object, 
 * which is used for performing interface lists, auto type probing, or actually
 * driving the capture.
 *
 */

/* DST forward ref */
class Datasourcetracker;
typedef shared_ptr<Datasourcetracker> SharedDatasourcetracker;

/* Keypair object from cap proto */
class KisDataSource_CapKeyedObject;

// Supported source
class KisDataSource_SupportedSource;

// Forward definition of data sources
class KisDataSource;
typedef shared_ptr<KisDataSource> SharedDataSource;

/* KisDataSourceBuilder
 *
 * A 'prototype' of the data source which tells the tracking system it's 
 * capabilities and knows how to build a full data source
 *
 * It is stored as a tracker_component so that the tracker can directly
 * serialize the data for displaying what sources are possible.
 */
class KisDataSourceBuilder;
typedef shared_ptr<KisDataSourceBuilder> SharedDataSourceBuilder;


class KisDataSource : public tracker_component, public RingbufferInterface {
public:
    KisDataSource(GlobalRegistry *in_globalreg, int in_id); 
    KisDataSource(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e);

    KisDataSource(GlobalRegistry *in_globalreg, int in_id,
            SharedDataSourceBuilder in_builder);

    virtual ~KisDataSource();

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisDataSource(globalreg, get_id()));
    }

    virtual void set_datasource_tracker(SharedDatasourcetracker in_tracker) {
        datasourcetracker = in_tracker;
    };

    typedef map<string, KisDataSource_CapKeyedObject *> KVmap;
    typedef pair<string, KisDataSource_CapKeyedObject *> KVpair;

    // List locally supported interfaces for sources.
    //
    // Called on a dynamically allocated datasource object.
    //
    // Returns a list immediately if it is possible to probe for them without
    // special privileges, otherwise spawns an IPC interface and performs an async
    // IPC probe, returning the values in the callback function
    virtual vector<SharedListInterface> list_interfaces(unsigned int in_transaction,
            function<void (unsigned int, vector<SharedListInterface>)> in_cb);

    // Determine if an interface spec is supported locally by this driver.
    //
    // Called on a dynamically allocated datasource object.
    //
    // Returns:
    //  1 - This source is handled by this driver, stop looking
    //  0 - This source is not handled by this driver, keep looking
    // -1 - Asynchronous probe via IPC required and will be reported via the
    //      callback function, which takes the result and the transaction id
    virtual int probe_source(string srcdef, unsigned int in_transaction,
            function<void (bool, unsigned int)> in_cb);

    // Open a local data source
    //
    // Configure from a given spec and populate the ring buffer interface.
    // Typically this means creating a ringbuffer bound to an ipcremote2
    //
    // Returns:
    //
    //  1 - This source is completely configured and is ready for use
    //  0 - This source has encountered a fatal error during setup
    // -1 - This source has initiated IPC bringup and success or failure will
    //      be reported via the callback function
    virtual int open_ipc_source(string srcdef, unsigned int in_transaction,
            function<void (bool, unsigned int)> in_cb);

    // Allocate the local side of a network capture.
    //
    // The TCP server in datasourcetracker has already received a connection,
    // established a ringbufferhandler for it, and the DST has identified that
    // we handle that type of interface from the HELLO packet.
    // 
    // Returns:
    //
    //  true - successful open
    //  false - failed to configure source to receive network events
    virtual bool open_network_source(shared_ptr<RingbufferHandler> in_handler);

    // Allocate the local side of a passive source
    //
    // A passive source doesn't take packets from a specific physical interface.
    // It may be a web interface accepting events, etc.  This gives it a 
    // local interface to associate packets with.
    //
    // Passive sources should provide a source definition for each unique
    // input and allocate a source for tracking.  For instance, each RTL433
    // receiver should transmit a record and have a corresponding passive
    // source entry.
    //
    // Returns:
    //
    //  true - successful establishment of passive source
    //  false - failed to establish passive source somehow
    virtual bool open_passive_source(string srcdef);

    // Close any active operation
    //
    // Cancels probing if a probe is underway
    // Cancels opening if opening is underway
    // Closes an open source and terminates IPC if necessary
    // Stops accepting packets on a passive source
    virtual void close_source();

    // Ringbuffer interface, called when new data arrives from IPC or network
    virtual void BufferAvailable(size_t in_amt);
    virtual void BufferError(string in_error);

    __Proxy(source_running, uint8_t, bool, bool, source_running);

    __ProxyTrackable(prototype, KisDataSourceBuilder, prototype);

    __Proxy(sourceline, string, string, string, sourceline);
    __Proxy(source_interface, string, string, string, source_interface);

    __Proxy(source_name, string, string, string, source_name);

    __ProxyL(source_channel, string, string, string, source_channel, src_set_channel);

    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);
    __Proxy(source_id, uint64_t, uint64_t, uint64_t, source_id);

    __Proxy(child_pid, int64_t, int64_t, int64_t, child_pid);
    __Proxy(source_ipc_bin, string, string, string, source_ipc_bin);

    __ProxyTrackable(source_channels_vec, TrackerElement, source_channels_vec);

    // Get-only interfaces
    __ProxyGet(source_hopping, uint8_t, bool, source_hopping);
    __ProxyGet(source_hop_rate, double, double, source_hop_rate);

    // Combined set function because we want to push both as one event usually
    virtual bool set_channel_hop(vector<string> in_list, double in_rate);
    virtual bool set_channel_hop(SharedTrackerElement in_list, double in_rate);

    // We can independently set the hop vector
    __ProxyTrackableL(source_hop_vec, TrackerElement, source_hop_vec,
            src_set_source_hop_vec);

    virtual string get_response_message() { 
        local_locker lock(&source_lock);
        return response_message;
    }

protected:
    // Proxy set commands that just update the tracked element
    __ProxySet(int_source_hopping, uint8_t, bool, source_hopping);
    __ProxySet(int_source_hop_rate, double, double, source_hop_rate);
    __ProxySet(int_source_channel, string, string, source_channel);

    virtual void initialize();

    GlobalRegistry *globalreg;

    uint32_t next_cmd_sequence;

    string response_message;

    SharedDatasourcetracker datasourcetracker;

    shared_ptr<Packetchain> packetchain;

    // IPC remote, if we have one
    IPCRemoteV2 *ipc_remote;

    // Ringbuffer handler, either we launched it via IPC or DST provided it to
    // us via a network source connecting
    shared_ptr<RingbufferHandler> ringbuf_handler;

    int pack_comp_linkframe, pack_comp_l1info, pack_comp_gps;

    pthread_mutex_t source_lock;

    virtual void register_fields();

    // Human name
    SharedTrackerElement source_name;

    // Prototype that built us
    int prototype_id;
    SharedDataSourceBuilder prototype;

    // Source line that created us
    SharedTrackerElement sourceline;

    // Interface name
    SharedTrackerElement source_interface;

    // Channel
    SharedTrackerElement source_channel;

    // Source UUID, automatically derived or provided by user
    SharedTrackerElement source_uuid;

    // Runtime source index
    SharedTrackerElement source_id;

    // PID, if an IPC local source
    SharedTrackerElement child_pid;

    // Path to helper binary, if in IPC mode
    SharedTrackerElement source_ipc_bin;

    // Supported channels, as vector of strings
    SharedTrackerElement source_channels_vec;
    SharedTrackerElement source_channel_entry_builder;

    // Currently running to the best of our knowledge
    SharedTrackerElement source_running;

    // Hopping and hop rate
    SharedTrackerElement source_hopping;
    SharedTrackerElement source_hop_rate;
    // Vector of channels we hop across, as vector of strings
    SharedTrackerElement source_hop_vec;

    // Callbacks for list and probe modes
    function<void (bool, unsigned int)> probe_cb;
    unsigned int probe_transaction;

    function<void (unsigned int, vector<SharedListInterface>)> list_cb;
    unsigned int list_transaction;

    function<void (bool, unsigned int)> open_cb;
    unsigned int open_transaction;

    // Internal commands; called to send the command frames to an IPC/network
    // driver, and linked to the tracked element proxy functions
    virtual bool src_send_probe(string in_srcdef);
    virtual bool src_send_open(string in_srcdef);
    virtual bool src_set_channel(string in_channel);

    virtual bool src_set_source_hop_vec(SharedTrackerElement in_vec);
    virtual bool src_set_source_hop_rate(double in_rate);

    // Assemble a packet and write it to the buffer; returns false if the buffer
    // could not accept more commands
    virtual bool write_packet(string in_cmd, KVmap in_kvpairs);

    // Top-level packet handler called by DST
    virtual void handle_packet(string in_type, KVmap in_kvmap);

    // Standard packet types
    virtual void handle_packet_status(KVmap in_kvpairs);
    virtual void handle_packet_probe_resp(KVmap in_kvpairs);
    virtual void handle_packet_open_resp(KVmap in_kvpairs);
    virtual void handle_packet_error(KVmap in_kvpairs);
    virtual void handle_packet_message(KVmap in_kvpairs);
    virtual void handle_packet_data(KVmap in_kvpairs);

    // Common message kv pair
    virtual bool handle_kv_success(KisDataSource_CapKeyedObject *in_obj);
    virtual bool handle_kv_message(KisDataSource_CapKeyedObject *in_obj);
    virtual bool handle_kv_channels(KisDataSource_CapKeyedObject *in_obj);
    virtual kis_gps_packinfo *handle_kv_gps(KisDataSource_CapKeyedObject *in_obj);
    virtual kis_layer1_packinfo *handle_kv_signal(KisDataSource_CapKeyedObject *in_obj);
    virtual kis_packet *handle_kv_packet(KisDataSource_CapKeyedObject *in_obj);

    // Spawn an IPC process, using the source_ipc_bin.  If the IPC system is running
    // already, issue a kill
    virtual bool spawn_ipc();

};

class KisDataSource_CapKeyedObject {
public:
    KisDataSource_CapKeyedObject(simple_cap_proto_kv *in_kp);
    KisDataSource_CapKeyedObject(string in_key, const char *in_object, ssize_t in_len);
    ~KisDataSource_CapKeyedObject();

    string key;
    size_t size;
    char *object;
};
#endif

#endif

