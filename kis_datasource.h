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
 * data frames from a capture engine and will create kis_packet structures
 * from them.
 *
 * Capture sources communicate via the supplied RingbufferInterface, which
 * will most likely be an IPC channel or a TCP socket.
 *
 * Data sources consume from the read buffer and send commands to the
 * write buffer of the ringbuf handler
 *
 * Data frames are defined in simple_datasource_proto.h.  A frame consists of an
 * overall type and multiple objects indexed by name.  Each object may
 * contain additional data.
 *
 * By default, objects are packed using the msgpack library, as dictionaries
 * of named values.  This abstracts problems with endian, complex types such
 * as float and double, and changes in the protocol over time.
 *
 * Data sources derive from trackable elements so they can be easily 
 * serialized for status
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
    __Proxy(list_capable, uint8_t, bool, bool, list_capable);
    __Proxy(local_capable, uint8_t, bool, bool, local_capable);
    __Proxy(remote_capable, uint8_t, bool, bool, remote_capable);
    __Proxy(passive_capable, uint8_t, bool, bool, passive_capable);
    __Proxy(hop_capable, uint8_t, bool, bool, hop_capable);

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

        RegisterField("kismet.datasource.def.list_capable", TrackerUInt8,
                "Datasource can list local interfaces", &list_capable);

        RegisterField("kismet.datasource.def.local_capable", TrackerUInt8,
                "Datasource can support local interfaces", &local_capable);

        RegisterField("kismet.datasource.def.remote_capable", TrackerUInt8,
                "Datasource can support remote interfaces", &remote_capable);

        RegisterField("kismet.datasource.def.passive_capable", TrackerUInt8,
                "Datasource can support passive interface-less data", &passive_capable);

        RegisterField("kismet.datasource.def.hop_capable", TrackerUInt8,
                "Datasource can control channels", &hop_capable);
    }

    SharedTrackerElement source_type;
    SharedTrackerElement source_description;

    SharedTrackerElement phyname;

    SharedTrackerElement probe_capable;
    SharedTrackerElement list_capable;
    SharedTrackerElement local_capable;
    SharedTrackerElement remote_capable;
    SharedTrackerElement passive_capable;
    SharedTrackerElement hop_capable;

};

/* Probe results
 *
 * Tracked element of probe results, consisting of the interface and any parameters
 * required to make the interface unique
 */
class KisDataSourceProbeInterface;
typedef shared_ptr<KisDataSourceProbeInterface> SharedProbeInterface;

class KisDataSourceProbeInterface : public tracker_component {
public:
    KisDataSourceProbeInterface(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    KisDataSourceProbeInterface(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual ~KisDataSourceProbeInterface();

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisDataSourceProbeInterface(globalreg, get_id()));
    }

    __Proxy(interface, string, string, string, interface);
    __ProxyTrackable(options_vec, TrackerElement, options_vec);

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
    int options_entry_id;

};

class KisDataSource : public tracker_component {
public:
    KisDataSource(GlobalRegistry *in_globalreg, SharedDataSourceBuilder in_proto,
            SharedDatasourceTracker in_dst);
    virtual ~KisDataSource();

    // List locally supported interfaces for sources.
    //
    // Called on a dynamically allocated datasource object.
    //
    // Returns a list immediately if it is possible to probe for them without
    // special privileges, otherwise spawns an IPC interface and performs an async
    // IPC probe and then reports back to the DST
    vector<SharedProbeInterface> list_interfaces(unsigned int in_transaction);

    // Determine if an interface spec is supported locally by this driver.
    //
    // Called on a dynamically allocated datasource object.
    //
    // Returns:
    //  1 - This source is handled by this driver, stop looking
    //  0 - This source is not handled by this driver, keep looking
    // -1 - Asynchronous probe via IPC required and will be reported back to the
    //      DST
    int probe_source(string srcdef, unsigned int in_transaction);

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

protected:
    GlobalRegistry *globalreg;

    SharedDatasourceTracker datasourcetracker;

    shared_ptr<Packetchain> packetchain;

    // IPC remote, if we have one
    IPCRemoteV2 *ipc_remote;

    // Ringbuffer handler, we always have one when we're instantiated
    RingbufferHandler *ringbuf_handler;

    int pack_comp_linkframe, pack_comp_l1info, pack_comp_gps;

    pthread_mutex_t source_lock;

    virtual void register_fields();

    // Human name
    SharedTrackerElement source_name;

    // Prototype that built us
    SharedDataSourceBuilder prototype;

    // Type
    int source_type_id;
    SharedTrackerElement source_type;

    // Definition used to create interface
    int source_definition_id;
    SharedTrackerElement source_definition;

    // Source interface as string
    int source_interface_id;
    SharedTrackerElement source_interface;

    // UUID of source (expensive to resolve but good for logs)
    int source_uuid_id;
    SharedTrackerElement source_uuid;

    // Runtime source id
    int source_id_id;
    SharedTrackerElement source_id;

    // Can this source change channel/frequency?
    int source_channel_capable_id;
    SharedTrackerElement source_channel_capable;

    // Description of the source
    int source_description_id;
    SharedTrackerElement source_description;

    // PID
    int child_pid_id;
    SharedTrackerElement child_pid;

    // Channels
    int source_channels_vec_id;
    SharedTrackerElement source_channels_vec;
    int source_channel_entry_id;

    // IPC errors
    int ipc_errors_id;
    SharedTrackerElement ipc_errors;

    // Currently running to the best of our knowledge
    int source_running_id;
    SharedTrackerElement source_running;

    // Hopping and hop rate
    int source_hopping_id;
    SharedTrackerElement source_hopping;

    int source_hop_rate_id;
    SharedTrackerElement source_hop_rate;

    int source_hop_vec_id;
    SharedTrackerElement source_hop_vec;

    int source_ipc_bin_id;
    SharedTrackerElement source_ipc_bin;

    int last_report_time_id;
    SharedTrackerElement last_report_time;

    int num_reports_id;
    SharedTrackerElement num_reports;

    IPCRemoteV2 *source_ipc;
    RingbufferHandler *ipchandler;

    // Commands waiting to be sent
    vector<KisDataSource_QueuedCommand *> pending_commands;

    // Queue a command to be sent when the IPC is up and running.  The queue
    // system will be responsible for freeing kvpairs, etc
    virtual bool queue_ipc_command(string in_cmd, KVmap *in_kvpairs);

    // IPC protocol assembly & send to driver
    virtual bool write_ipc_packet(string in_type, KVmap *in_kvpairs);

    // Top-level packet handler
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

