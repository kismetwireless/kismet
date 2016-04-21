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
 * Data frames are defined in simple_cap_proto.h.  A frame consists of an
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

    // Build a strong instance
    virtual KisDataSource *BuildDataSource(string in_definition) = 0;

    // Register the source and any sub-sources
    virtual int RegisterSources() = 0;

    // Launch and try to open a source
    virtual int OpenSource(string in_definition);

    __Proxy(source_name, string, string, string, source_name);
    __Proxy(source_interface, string, string, string, source_interface);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);
    __Proxy(source_id, int, int, int, source_id);
    __Proxy(source_channel_capable, uint8_t, bool, bool, source_channel_capable);
    __Proxy(source_definition, string, string, string, source_definition);
    __Proxy(child_pid, int64_t, pid_t, pid_t, child_pid);

    // Ringbuffer API
    virtual void BufferAvailable(size_t in_amt);

    // Top-level packet handler
    virtual void HandlePacket(string in_type, 
            vector<KisDataSource_CapKeyedObject *> in_kvpairs);

protected:
    GlobalRegistry *in_globalreg;

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

    // PID
    int child_pid_id;
    TrackerElement *child_pid;

    IPCRemoteV2 *source_ipc;
    RingbufferHandler *ipchandler;

};

class KisDataSource_CapKeyedObject {
public:
    KisDataSource_CapKeyedObject(simple_cap_proto_kv *in_kp);
    ~KisDataSource_CapKeyedObject();

    string key;
    uint32_t size;
    uint8_t *object;
};

#endif

