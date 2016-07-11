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
#include "devicetracker_component.h"
#include "simple_datasource_proto.h"

/*
 * Kismet Data Source
 *
 * Data sources replace packetsources in the new Kismet code model.
 * A data source is the kismet_server side of a capture engine:  It accepts
 * data frames from a capture engine and will create kis_packet structures
 * from them.
 *
 * The capture engine will, locally, be over IPC channels as defined in
 * IpcRemoteV2.  Data may also come from TCP sockets, or in the future,
 * other sources - anything which can plug into in a ringbufferhandler
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
 * inspected by client interfaces.
 *
 */

/* DST forward ref */
class DatasourceTracker;

/* Keypair object from cap proto */
class KisDataSource_CapKeyedObject;

/* Queued command when IPC is open proto */
class KisDataSource_QueuedCommand;

class KisDataSource : public RingbufferInterface, public tracker_component {
public:
    // Create a builder instance which only knows enough to be able to
    // build a complete version of itself
    KisDataSource(GlobalRegistry *in_globalreg);
    virtual ~KisDataSource();

    // Build a new instance of the class, used for opening and probing
    virtual KisDataSource *build_data_source() { return NULL; }

    // Error handler callback, called when something goes wrong in the source
    // and it has to close
    typedef void (*error_handler)(KisDataSource *, void *);
    virtual void set_error_handler(error_handler in_cb, void *in_aux);
    virtual void cancel_error_handler();

    // Can we handle this type?
    virtual bool probe_type(string in_type) { return false; }

    // Can we handle this source?  May require launching the external binary
    // to probe.  Since this is an async operation, provide a callback.
    // Returns false if unable to launch probe, or true if probe is underway.
    typedef void (*probe_handler)(KisDataSource *, void *, bool);
    virtual bool probe_source(string in_source, probe_handler in_cb, void *in_aux);

    // Cancel the callbacks
    virtual void cancel_probe_source();

    // Launch IPC and open source.  This is an async operation, the callback
    // will be notified when complete.
    // Returns false if unable to initiate opening, or true if opening is underway
    typedef void (*open_handler)(KisDataSource *, void *, bool);
    virtual bool open_source(string in_source, open_handler in_cb, void *in_aux);
    // Cancel the callbacks
    virtual void cancel_open_source();

    // Close and kill a source
    virtual void close_source();

    // Set channel or frequency, string-based definition.  Specifics of channel
    // and frequency definition are determined by the source phy.  Does not return,
    // source will go into error state instead because of async
    virtual void set_channel(string in_channel);

    // Set a channel and hopping rate.  Hopping rate is units per second, and now
    // processed as a double.  Values less than 1.0 result in multiple seconds 
    // per channel
    virtual void set_channel_hop(vector<string> in_channel_list, double in_rate);

    __Proxy(source_name, string, string, string, source_name);
    __Proxy(source_type, string, string, string, source_type);
    __Proxy(source_interface, string, string, string, source_interface);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);
    __Proxy(source_id, int32_t, int, int, source_id);
    __Proxy(source_channel_capable, uint8_t, bool, bool, source_channel_capable);
    __Proxy(source_definition, string, string, string, source_definition);
    __Proxy(child_pid, int64_t, pid_t, pid_t, child_pid);
    __Proxy(source_description, string, string, string, source_description);

    __ProxyTrackable(source_channels_vec, TrackerElement, source_channels_vec);

    __Proxy(ipc_errors, uint64_t, uint64_t, uint64_t, ipc_errors);
    __ProxyIncDec(ipc_errors, uint64_t, uint64_t, ipc_errors);

    __Proxy(source_running, uint8_t, bool, bool, source_running);

    __Proxy(source_ipc_bin, string, string, string, source_ipc_bin);

    // Only proxy get, because setting these is a complex operation
    __ProxyGet(source_hopping, uint8_t, bool, source_hopping);
    __ProxyGet(source_hop_rate, double, double, source_hop_rate);

    __ProxyTrackable(source_hop_vec, TrackerElement, source_hop_vec);

    // Ringbuffer API
    virtual void BufferAvailable(size_t in_amt);
    virtual void BufferError(string in_error);

    // KV pair map
    typedef map<string, KisDataSource_CapKeyedObject *> KVmap;
    typedef pair<string, KisDataSource_CapKeyedObject *> KVpair;

protected:
    GlobalRegistry *in_globalreg;

    pthread_mutex_t source_lock;

    error_handler error_callback;
    void *error_aux;

    probe_handler probe_callback;
    void *probe_aux;

    open_handler open_callback;
    void *open_aux;

    virtual void register_fields();

    // Human name
    int source_name_id;
    TrackerElement *source_name;

    // Type
    int source_type_id;
    TrackerElement *source_type;

    // Definition used to create interface
    int source_definition_id;
    TrackerElement *source_definition;

    // Source interface as string
    int source_interface_id;
    TrackerElement *source_interface;

    // UUID of source (expensive to resolve but good for logs)
    int source_uuid_id;
    TrackerElement *source_uuid;

    // Runtime source id
    int source_id_id;
    TrackerElement *source_id;

    // Can this source change channel/frequency?
    int source_channel_capable_id;
    TrackerElement *source_channel_capable;

    // Description of the source
    int source_description_id;
    TrackerElement *source_description;

    // PID
    int child_pid_id;
    TrackerElement *child_pid;

    // Channels
    int source_channels_vec_id;
    TrackerElement *source_channels_vec;
    int source_channel_entry_id;

    // IPC errors
    int ipc_errors_id;
    TrackerElement *ipc_errors;

    // Currently running to the best of our knowledge
    int source_running_id;
    TrackerElement *source_running;

    // Hopping and hop rate
    int source_hopping_id;
    TrackerElement *source_hopping;

    int source_hop_rate_id;
    TrackerElement *source_hop_rate;

    int source_hop_vec_id;
    TrackerElement *source_hop_vec;

    int source_ipc_bin_id;
    TrackerElement *source_ipc_bin;

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

