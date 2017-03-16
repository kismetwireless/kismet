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
#include "datasourcetracker.h"
#include "ipc_remote2.h"
#include "ringbuf_handler.h"
#include "uuid.h"
#include "gps_manager.h"
#include "packet.h"
#include "devicetracker_component.h"
#include "packetchain.h"
#include "simple_datasource_proto.h"

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
class DatasourceTracker;
typedef shared_ptr<DatasourceTracker> SharedDatasourceTracker;

/* Keypair object from cap proto */
class KisDataSource_CapKeyedObject;

// Queued command/data
class KisDataSource_QueuedCommand;

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

class KisDataSourceBuilder : public tracker_component {
public:
    KisDataSourceBuilder(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    KisDataSourceBuilder(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual ~KisDataSourceBuilder();

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisDataSourceBuilder(globalreg, get_id()));
    }

    // Build the actual data source
    virtual SharedDataSource build_datasource() { return NULL; }

    __Proxy(source_type, string, string, string, source_type);
    __Proxy(source_description, string, string, string, source_description);

    __Proxy(phyname, string, string, string, phyname);

    __Proxy(probe_capable, uint8_t, bool, bool, probe_capable);
    __Proxy(probe_ipc, uint8_t, bool, bool, probe_ipc);

    __Proxy(list_capable, uint8_t, bool, bool, list_capable);
    __Proxy(list_ipc, uint8_t, bool, bool, list_ipc);

    __Proxy(local_capable, uint8_t, bool, bool, local_capable);
    __Proxy(remote_capable, uint8_t, bool, bool, remote_capable);
    __Proxy(passive_capable, uint8_t, bool, bool, passive_capable);
    __Proxy(tune_capable, uint8_t, bool, bool, tune_capable);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.datasource.def.type", TrackerString, 
                "Datasource type", &source_type);

        RegisterField("kismet.datasource.def.description", TrackerString,
                "Datasource description", &source_description);

        RegisterField("kismet.datasource.def.phyname", TrackerString,
                "Datasource phy layer name", &phyname);

        RegisterField("kismet.datasource.def.probe_capable", TrackerUInt8,
                "Datasource can automatically probe", &probe_capable);

        RegisterField("kismet.datasource.def.probe_ipc", TrackerUInt8,
                "Datasource requires IPC to probe", &probe_capable);

        RegisterField("kismet.datasource.def.list_capable", TrackerUInt8,
                "Datasource can list interfaces", &list_capable);

        RegisterField("kismet.datasource.def.list_ipc", TrackerUInt8,
                "Datasource requires IPC to list interfaces", &list_capable);

        RegisterField("kismet.datasource.def.local_capable", TrackerUInt8,
                "Datasource can support local interfaces", &local_capable);

        RegisterField("kismet.datasource.def.remote_capable", TrackerUInt8,
                "Datasource can support remote interfaces", &remote_capable);

        RegisterField("kismet.datasource.def.passive_capable", TrackerUInt8,
                "Datasource can support passive interface-less data", &passive_capable);

        RegisterField("kismet.datasource.def.tuning_capable", TrackerUInt8,
                "Datasource can control channels", &tune_capable);
    }

    SharedTrackerElement source_type;
    SharedTrackerElement source_description;

    SharedTrackerElement phyname;

    SharedTrackerElement probe_capable;
    SharedTrackerElement probe_ipc;

    SharedTrackerElement list_capable;
    SharedTrackerElement list_ipc;

    SharedTrackerElement local_capable;
    SharedTrackerElement remote_capable;
    SharedTrackerElement passive_capable;

    SharedTrackerElement tune_capable;

};

/* List results
 *
 * Tracked element of list results, consisting of the interface and any parameters
 * required to make the interface unique
 */
class KisDataSourceListInterface;
typedef shared_ptr<KisDataSourceListInterface> SharedListInterface;

class KisDataSourceListInterface : public tracker_component {
public:
    KisDataSourceListInterface(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    KisDataSourceListInterface(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual ~KisDataSourceListInterface();

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisDataSourceListInterface(globalreg, get_id()));
    }

    __Proxy(interface, string, string, string, interface);
    __ProxyTrackable(options_vec, TrackerElement, options_vec);

    __ProxyTrackable(prototype, KisDataSourceBuilder, prototype);

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

    }

    SharedTrackerElement interface;
    SharedTrackerElement options_vec;

    SharedDataSourceBuilder prototype;

    int options_entry_id;

};

class KisDataSource : public tracker_component, public RingbufferInterface {
public:
    KisDataSource(GlobalRegistry *in_globalreg, int in_id); 
    KisDataSource(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e);
    virtual ~KisDataSource();

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisDataSource(globalreg, get_id()));
    }

    virtual void set_proto(SharedDataSourceBuilder in_proto);
    virtual void set_datasource_tracker(SharedDatasourceTracker in_tracker);

    typedef map<string, KisDataSource_CapKeyedObject *> KVmap;
    typedef pair<string, KisDataSource_CapKeyedObject *> KVpair;

    // List locally supported interfaces for sources.
    //
    // Called on a dynamically allocated datasource object.
    //
    // Returns a list immediately if it is possible to probe for them without
    // special privileges, otherwise spawns an IPC interface and performs an async
    // IPC probe, returning the values in the callback function
    vector<SharedListInterface> list_interfaces(unsigned int in_transaction,
            function<void (vector<SharedListInterface>)> in_cb);

    // Determine if an interface spec is supported locally by this driver.
    //
    // Called on a dynamically allocated datasource object.
    //
    // Returns:
    //  1 - This source is handled by this driver, stop looking
    //  0 - This source is not handled by this driver, keep looking
    // -1 - Asynchronous probe via IPC required and will be reported via the
    //      callback function
    int probe_source(string srcdef, unsigned int in_transaction,
            function<void (bool)> in_cb);

    // Open a local data source
    //
    // Configure from a given spec and populate the ring buffer interface.
    // Typically this means connecting the ring buffer to an IPCRemoteV2 instance
    // and launching our control binary, but could also use a non-IPC non-privileged
    // mechanism and write directly into the handler.
    //
    // Returns:
    //
    //  1 - This source is completely configured and is ready for use
    //  0 - This source has encountered a fatal error during setup
    // -1 - This source has initiated IPC bringup and success or failure will
    //      be reported to the DST
    int open_local_source(string srcdef, RingbufferHandler *in_handler, 
            unsigned int in_transaction);

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
    bool open_network_source(RingbufferHandler *in_handler);

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
    bool open_passive_source(string srcdef);

    // Close any active operation
    //
    // Cancels probing if a probe is underway
    // Cancels opening if opening is underway
    // Closes an open source and terminates IPC if necessary
    // Stops accepting packets on a passive source
    void close_source();

    // Ringbuffer interface, called when new data arrives from IPC or 
    virtual void BufferAvailable(size_t in_amt);

    __Proxy(source_running, bool, uint8_t, uint8_t, source_running);
    __ProxyTrackable(prototype, KisDataSourceBuilder, prototype);
    __Proxy(sourceline, string, string, string, sourceline);
    __Proxy(source_interface, string, string, string, source_interface);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);
    __Proxy(source_id, uint64_t, uint64_t, uint64_t, source_id);

    __Proxy(child_pid, int64_t, int64_t, int64_t, child_pid);
    __Proxy(source_ipc_bin, string, string, string, source_ipc_bin);

    __ProxyTrackable(source_channels_vec, TrackerElement, source_channels_vec);
    __ProxyL(source_hopping, bool, uint8_t, uint8_t, 
            source_hopping, src_set_source_hopping);
    __ProxyL(source_hop_rate, double, double, double, source_hop_rate,
            src_set_source_hop_rate);
    __ProxyTrackableL(source_hop_vec, TrackerElement, source_hop_vec,
            src_set_source_hop_vec);

protected:
    void initialize();

    GlobalRegistry *globalreg;

    SharedDatasourceTracker datasourcetracker;

    shared_ptr<Packetchain> packetchain;

    // IPC remote, if we have one
    IPCRemoteV2 *ipc_remote;

    // Ringbuffer handler, either we launched it via IPC or DST provided it to
    // us via a network source connecting
    RingbufferHandler *ringbuf_handler;

    int pack_comp_linkframe, pack_comp_l1info, pack_comp_gps;

    pthread_mutex_t source_lock;

    virtual void register_fields();

    // Human name
    SharedTrackerElement source_name;

    // Prototype that built us
    SharedDataSourceBuilder prototype;

    // Source line that created us
    SharedTrackerElement sourceline;

    // Interface name
    SharedTrackerElemnt source_interface;

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
    int source_channel_entry_id;

    // Currently running to the best of our knowledge
    SharedTrackerElement source_running;

    // Hopping and hop rate
    SharedTrackerElement source_hopping;
    SharedTrackerElement source_hop_rate;
    // Vector of channels we hop across, as vector of strings
    SharedTrackerElement source_hop_vec;

    // Callbacks for list and probe modes
    function<void (bool)> probe_cb;
    function<void (vector<SharedListInterface>)> list_cb;

    // Commands waiting to be sent
    vector<KisDataSource_QueuedCommand *> pending_commands;

    // Internal commands called when we set the tracked types
    virtual bool src_set_source_hopping(bool in_hop);
    virtual bool src_set_source_hop_vec(SharedTrackerElement in_vec);
    virtual bool src_set_source_hop_rate(double in_rate);

    // Queue commands to be sent over ipc or tcp
    virtual bool queue_ipc_command(string in_cmd, KVmap *in_kvpairs);

    // IPC protocol assembly & send to driver
    virtual bool write_packet(string in_type, KVmap *in_kvpairs);

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

class KisDataSource_QueuedCommand {
public:
    KisDataSource_QueuedCommand(string in_cmd, KisDataSource::KVmap *in_kv, 
            time_t in_time);

    string command;
    KisDataSource::KVmap *kv;
    time_t insert_time;
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

