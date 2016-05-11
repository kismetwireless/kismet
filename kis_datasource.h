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

/* Keypair object from cap proto */
class KisDataSource_CapKeyedObject;

class KisDataSource : public RingbufferInterface, public tracker_component {
public:
    // Create a builder instance which only knows enough to be able to
    // build a complete version of itself
    KisDataSource(GlobalRegistry *in_globalreg);
    ~KisDataSource();

    // Register the source and any sub-sources (builder)
    virtual int register_sources() = 0;

    // Build a source
    virtual KisDataSource *build_data_source(string in_definition) = 0;

    // Can we handle this source?  May require launching the external binary
    // to probe.  Since this may be an async operation, provide a callback
    typedef void (*probe_handler)(KisDataSource *, void *, bool);
    virtual bool probe_source(string in_source, probe_handler in_cb, void *in_aux) = 0;
    // Cancel the callbacks
    virtual void cancel_probe_source();

    // Launch IPC and open source
    typedef void (*open_handler)(KisDataSource *, void *, bool);
    virtual bool open_source(string in_source, open_handler in_cb, void *in_aux);
    // Cancel the callbacks
    virtual void cancel_open_source();

    // Set channel or frequency, string-based definition.  Specifics of channel
    // and frequency definition are determined by the source phy
    virtual bool set_channel(string in_channel);

    __Proxy(source_name, string, string, string, source_name);
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

    // Ringbuffer API
    virtual void BufferAvailable(size_t in_amt);

protected:
    GlobalRegistry *in_globalreg;

    pthread_mutex_t source_lock;

    probe_handler probe_callback;
    void *probe_aux;

    open_handler open_callback;
    void *open_aux;

    virtual void register_fields();

    // Human name
    int source_name_id;
    TrackerElement *source_name;

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

    IPCRemoteV2 *source_ipc;
    RingbufferHandler *ipchandler;

    typedef map<string, KisDataSource_CapKeyedObject *> KVmap;

    // Top-level packet handler
    virtual void handle_packet(string in_type, KVmap in_kvmap);

    // Standard packet types
    virtual void handle_packet_hello(KVmap in_kvpairs);
    virtual void handle_packet_probe_resp(KVmap in_kvpairs);
    virtual void handle_packet_open_resp(KVmap in_kvpairs);
    virtual void handle_packet_error(KVmap in_kvpairs);
    virtual void handle_packet_message(KVmap in_kvpairs);
    virtual void handle_packet_data(KVmap in_kvpairs);

    // Common message kv pair
    virtual bool handle_kv_success(KisDataSource_CapKeyedObject *in_obj);
    virtual bool handle_kv_message(KisDataSource_CapKeyedObject *in_obj);
    virtual bool handle_kv_channels(KisDataSource_CapKeyedObject *in_obj);

};

class KisDataSource_CapKeyedObject {
public:
    KisDataSource_CapKeyedObject(simple_cap_proto_kv *in_kp);
    ~KisDataSource_CapKeyedObject();

    string key;
    uint32_t size;
    char *object;
};

#endif

