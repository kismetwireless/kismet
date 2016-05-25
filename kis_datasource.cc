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

#include "config.h"

#include "kis_datasource.h"
#include "simple_datasource_proto.h"
#include "endian_magic.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

KisDataSource::KisDataSource(GlobalRegistry *in_globalreg) :
    tracker_component(in_globalreg, 0) {
    globalreg = in_globalreg;

    pthread_mutex_init(&source_lock, NULL);

    probe_callback = NULL;
    probe_aux = NULL;

    error_callback = NULL;
    error_aux = NULL;

    open_callback = NULL;
    open_aux = NULL;

    register_fields();
    reserve_fields(NULL);

    set_source_running(false);

    ipchandler = NULL;
    source_ipc = NULL;
}

KisDataSource::~KisDataSource() {
    {
        // Make sure no-one is holding a reference to us
        local_locker lock(&source_lock);
    }

    pthread_mutex_destroy(&source_lock);

    if (source_ipc != NULL) {
        source_ipc->hard_kill();
    }
}

void KisDataSource::register_fields() {
    source_name_id =
        RegisterField("kismet.datasource.source_name", TrackerString,
                "Human name of data source", (void **) &source_name);
    source_type_id =
        RegisterField("kismet.datasource.source_type", TrackerString,
                "Type of data source", (void **) &source_type);
    source_interface_id =
        RegisterField("kismet.datasource.source_interface", TrackerString,
                "Primary capture interface", (void **) &source_interface);
    source_uuid_id =
        RegisterField("kismet.datasource.source_uuid", TrackerUuid,
                "UUID", (void **) &source_uuid);
    source_id_id =
        RegisterField("kismet.datasource.source_id", TrackerInt32,
                "Run-time ID", (void **) &source_id);
    source_channel_capable_id =
        RegisterField("kismet.datasource.source_channel_capable", TrackerUInt8,
                "(bool) source capable of channel change", 
                (void **) &source_channel_capable);
    child_pid_id =
        RegisterField("kismet.datasource.child_pid", TrackerInt64,
                "PID of data capture process", (void **) &child_pid);
    source_definition_id =
        RegisterField("kismet.datasource.definition", TrackerString,
                "original source definition", (void **) &source_definition);
    source_description_id =
        RegisterField("kismet.datasource.description", TrackerString,
                "human-readable description", (void **) &source_description);

    source_channel_entry_id =
        globalreg->entrytracker->RegisterField("kismet.device.base.channel", 
                TrackerString, "channel (phy specific)");
    source_channels_vec_id =
        RegisterField("kismet.datasource.channels", TrackerVector,
                "valid channels for this device", (void **) &source_channels_vec);

    ipc_errors_id =
        RegisterField("kismet.datasource.ipc_errors", TrackerUInt64,
                "number of errors in IPC protocol", (void **) &ipc_errors);
    source_running_id =
        RegisterField("kismet.datasource.running", TrackerUInt8,
                "source is currently operational", (void **) &source_running);
    source_hopping_id = 
        RegisterField("kismet.datasource.hopping", TrackerUInt8,
                "source is channel hopping (bool)", (void **) &source_hopping);
    source_hop_rate_id =
        RegisterField("kismet.datasource.hop_rate", TrackerDouble,
                "channel hopping rate", (void **) &source_hop_rate);
    source_hop_vec_id =
        RegisterField("kismet.datasource.hop_channels", TrackerVector,
                "hopping channels", (void **) &source_hop_vec);
    source_ipc_bin_id =
        RegisterField("kismet.datasource.ipc_bin", TrackerString,
                "driver binary", (void **) &source_ipc_bin);

}

void KisDataSource::BufferAvailable(size_t in_amt) {
    simple_cap_proto_t *frame_header;
    uint8_t *buf;
    uint32_t frame_sz;
    uint32_t frame_checksum, calc_checksum;

    if (in_amt < sizeof(simple_cap_proto_t)) {
        return;
    }

    // Peek the buffer
    buf = new uint8_t[in_amt];
    ipchandler->PeekReadBufferData(buf, in_amt);

    frame_header = (simple_cap_proto_t *) buf;

    if (kis_ntoh32(frame_header->signature) != KIS_CAP_SIMPLE_PROTO_SIG) {
        // TODO kill connection or seek for valid
        delete[] buf;
        return;
    }

    frame_sz = kis_ntoh32(frame_header->packet_sz);

    if (frame_sz > in_amt) {
        // Nothing we can do right now, not enough data to make up a
        // complete packet.
        delete[] buf;
        return;
    }

    // Get the checksum
    frame_checksum = kis_ntoh32(frame_header->checksum);

    // Zero the checksum field in the packet
    frame_header->checksum = 0x00000000;

    // Calc the checksum of the rest
    calc_checksum = Adler32Checksum((const char *) buf, frame_sz);

    // Compare to the saved checksum
    if (calc_checksum != frame_checksum) {
        // TODO report invalid checksum and disconnect
        delete[] buf;
        return;
    }

    // Consume the packet in the ringbuf 
    ipchandler->GetReadBufferData(NULL, frame_sz);

    // Extract the kv pairs
    KVmap kv_map;

    ssize_t data_offt = 0;
    for (unsigned int kvn = 0; kvn < kis_ntoh32(frame_header->num_kv_pairs); kvn++) {
        simple_cap_proto_kv *pkv =
            (simple_cap_proto_kv *) &((frame_header->data)[data_offt]);

        data_offt = 
            sizeof(simple_cap_proto_kv_h_t) +
            kis_ntoh32(pkv->header.obj_sz);

        KisDataSource_CapKeyedObject *kv =
            new KisDataSource_CapKeyedObject(pkv);

        kv_map[StrLower(kv->key)] = kv;
    }

    char ctype[17];
    snprintf(ctype, 17, "%s", frame_header->type);
    handle_packet(ctype, kv_map);

    for (KVmap::iterator i = kv_map.begin(); i != kv_map.end(); ++i) {
        delete i->second;
    }

    delete[] buf;

}

bool KisDataSource::queue_ipc_command(string in_cmd, KVmap *in_kvpairs) {

    // If IPC is running just write it straight out
    if (source_ipc != NULL && source_ipc->get_pid() > 0) {
        bool ret = false;

        ret = write_ipc_packet(in_cmd, in_kvpairs);

        if (ret) {
            for (KVmap::iterator i = in_kvpairs->begin(); i != in_kvpairs->end(); ++i) {
                delete i->second;
            }
            delete in_kvpairs;

            return ret;
        }
    }

    // If we didn't succeed in writing the packet for some reason

    // Queue the command
    KisDataSource_QueuedCommand *cmd = 
        new KisDataSource_QueuedCommand(in_cmd, in_kvpairs, 
                globalreg->timestamp.tv_sec);

    {
        local_locker lock(&source_lock);
        pending_commands.push_back(cmd);
    }

    return true;
}

bool KisDataSource::write_ipc_packet(string in_type, KVmap *in_kvpairs) {
    simple_cap_proto_t *ret = NULL;
    vector<simple_cap_proto_kv_t *> proto_kvpairs;
    size_t kvpair_len = 0;
    size_t kvpair_offt = 0;
    size_t pack_len;

    for (KVmap::iterator i = in_kvpairs->begin(); i != in_kvpairs->end(); ++i) {
        // Size of header + size of object
        simple_cap_proto_kv_t *kvt = (simple_cap_proto_kv_t *) 
            new char[sizeof(simple_cap_proto_kv_h_t) + i->second->size];

        // Set up the header, network endian
        snprintf(kvt->header.key, 16, "%s", i->second->key.c_str());
        kvt->header.obj_sz = kis_hton32(i->second->size);

        // Copy the content
        memcpy(kvt->object, i->second->object, i->second->size);

        // Add the total size
        kvpair_len += sizeof(simple_cap_proto_kv_h_t) + i->second->size;
    }

    // Make the container packet
    pack_len = sizeof(simple_cap_proto_t) + kvpair_len;

    ret = (simple_cap_proto_t *) new char[pack_len];

    ret->signature = kis_hton32(KIS_CAP_SIMPLE_PROTO_SIG);
   
    // Prep the checksum with 0
    ret->checksum = 0;

    ret->packet_sz = kis_hton32(pack_len);

    snprintf(ret->type, 16, "%s", in_type.c_str());

    ret->num_kv_pairs = kis_hton32(proto_kvpairs.size());

    // Progress through the kv pairs and pack them 
    for (unsigned int i = 0; i < proto_kvpairs.size(); i++) {
        // Annoying to have to do it this way
        size_t len = kis_ntoh32(proto_kvpairs[i]->header.obj_sz) +
            sizeof(simple_cap_proto_kv_h_t);

        memcpy(&(ret->data[kvpair_offt]), proto_kvpairs[i], len);

        kvpair_offt += len;

        // Delete it as we go
        delete(proto_kvpairs[i]);
    }

    // Calculate the checksum with it pre-populated as 0x0
    uint32_t calc_checksum;
    calc_checksum = Adler32Checksum((const char *) ret, pack_len);

    ret->checksum = kis_hton32(calc_checksum);

    size_t ret_sz;

    {
        // Lock & send to the IPC ringbuffer
        local_locker lock(&source_lock);
        ret_sz = ipchandler->PutWriteBufferData(ret, pack_len, true);

        delete ret;
    }

    if (ret_sz != pack_len)
        return false;

    return true;
}

void KisDataSource::set_error_handler(error_handler in_cb, void *in_aux) {
    local_locker lock(&source_lock);

    error_callback = in_cb;
    error_aux = in_aux;
}

void KisDataSource::cancel_error_handler() {
    local_locker lock(&source_lock);

    error_callback = NULL;
    error_aux = NULL;
}

bool KisDataSource::open_source(string in_definition, open_handler in_cb, void *in_aux) {
    local_locker lock(&source_lock);

    open_callback = in_cb;
    open_aux = in_aux;

    set_source_definition(in_definition);

    return 0;
}

void KisDataSource::cancel_probe_source() {
    local_locker lock(&source_lock);

    probe_callback = NULL;
    probe_aux = NULL;
}

void KisDataSource::cancel_open_source() {
    local_locker lock(&source_lock);

    open_callback = NULL;
    open_aux = NULL;
}

void KisDataSource::set_channel(string in_channel) {

}

void KisDataSource::set_channel_hop(vector<string> in_channel_list, 
        double in_rate) {

}

void KisDataSource::handle_packet(string in_type, KVmap in_kvmap) {
    string ltype = StrLower(in_type);

    if (ltype == "status")
        handle_packet_status(in_kvmap);
    else if (ltype == "proberesp")
        handle_packet_probe_resp(in_kvmap);
    else if (ltype == "openresp")
        handle_packet_open_resp(in_kvmap);
    else if (ltype == "error")
        handle_packet_error(in_kvmap);
    else if (ltype == "message")
        handle_packet_message(in_kvmap);
    else if (ltype == "data")
        handle_packet_data(in_kvmap);
}

void KisDataSource::handle_packet_status(KVmap in_kvpairs) {
    KVmap::iterator i;
    
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    // If we just launched, this lets us know we're awake and can 
    // send any queued commands

}

void KisDataSource::handle_packet_probe_resp(KVmap in_kvpairs) {
    KVmap::iterator i;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    // Process channels list if we got one
    if ((i = in_kvpairs.find("channels")) != in_kvpairs.end()) {
        if (!handle_kv_channels(i->second))
            return;
    }

    // Process success value and callback
    if ((i = in_kvpairs.find("success")) != in_kvpairs.end()) {
        local_locker lock(&source_lock);

        if (probe_callback != NULL) {
            (*probe_callback)(this, probe_aux, handle_kv_success(i->second));
        }
    } else {
        // ProbeResp with no success value?  ehh.
        local_locker lock(&source_lock);
        inc_ipc_errors(1);
        return;
    }

    // Close the source since probe is done
    source_ipc->close_ipc();
}

void KisDataSource::handle_packet_open_resp(KVmap in_kvpairs) {
    KVmap::iterator i;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    // Process channels list if we got one
    if ((i = in_kvpairs.find("channels")) != in_kvpairs.end()) {
        if (!handle_kv_channels(i->second))
            return;
    }

    // Process success value and callback
    if ((i = in_kvpairs.find("success")) != in_kvpairs.end()) {
        local_locker lock(&source_lock);

        if (open_callback != NULL) {
            (*open_callback)(this, open_aux, handle_kv_success(i->second));
        }
    } else {
        // OpenResp with no success value?  ehh.
        local_locker lock(&source_lock);
        inc_ipc_errors(1);
        return;
    }

}

void KisDataSource::handle_packet_error(KVmap in_kvpairs) {
    KVmap::iterator i;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    // Lock only after handling messages
    {
        local_locker lock(&source_lock);

        // Kill the IPC
        source_ipc->soft_kill();
    }
}


void KisDataSource::handle_packet_message(KVmap in_kvpairs) {
    KVmap::iterator i;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }
}

void KisDataSource::handle_packet_data(KVmap in_kvpairs) {
    KVmap::iterator i;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

}

bool KisDataSource::handle_kv_success(KisDataSource_CapKeyedObject *in_obj) {
    // Not a msgpacked object, just a single byte
    if (in_obj->size != 1) {
        local_locker lock(&source_lock);
        inc_ipc_errors(1);
        return false;
    }

    return in_obj->object[0];
}

bool KisDataSource::handle_kv_message(KisDataSource_CapKeyedObject *in_obj) {
    // Unpack the dictionary
    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;
    vector<string> channel_vec;

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size); 
        msgpack::object deserialized = result.get();
        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        string msg;
        unsigned int flags;

        if ((obj_iter = dict.find("msg")) != dict.end()) {
            msg = obj_iter->second.as<string>();
        } else {
            throw std::runtime_error("missing 'msg' entry");
        }

        if ((obj_iter = dict.find("flags")) != dict.end()) {
            flags = obj_iter->second.as<unsigned int>();
        } else {
            throw std::runtime_error("missing 'flags' entry");
        }

        _MSG(msg, flags);

    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        stringstream ss;
        ss << "Source " << get_source_name() << " failed to unpack message " <<
            "bundle: " << e.what();
        _MSG(ss.str(), MSGFLAG_ERROR);

        local_locker lock(&source_lock);
        inc_ipc_errors(1);

        return false;
    }

    return true;

}

bool KisDataSource::handle_kv_channels(KisDataSource_CapKeyedObject *in_obj) {
    // Unpack the dictionary
    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;
    vector<string> channel_vec;

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size);
        msgpack::object deserialized = result.get();
        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        if ((obj_iter = dict.find("channels")) != dict.end()) {
            MsgpackAdapter::AsStringVector(obj_iter->second, channel_vec);

            // We now have a string vector of channels, dupe it into our 
            // tracked channels vec
            local_locker lock(&source_lock);

            source_channels_vec->clear_vector();
            for (unsigned int x = 0; x < channel_vec.size(); x++) {
                TrackerElement *chanstr =
                    globalreg->entrytracker->GetTrackedInstance(source_channel_entry_id);
                chanstr->set(channel_vec[x]);
                source_channels_vec->add_vector(chanstr);
            }
        }
    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        stringstream ss;
        ss << "Source " << get_source_name() << " failed to unpack proberesp " <<
            "channels bundle: " << e.what();
        _MSG(ss.str(), MSGFLAG_ERROR);

        local_locker lock(&source_lock);
        inc_ipc_errors(1);

        return false;
    }

    return true;
}

bool KisDataSource::spawn_ipc() {
    stringstream ss;

    local_locker lock(&source_lock);

    if (get_source_ipc_bin() == "") {
        ss << "Datasource '" << get_source_name() << "' missing IPC binary, cannot "
            "launch binary";
        _MSG(ss.str(), MSGFLAG_ERROR);

        // Call the handler if we have one
        if (error_callback != NULL)
            (*error_callback)(this, error_aux);

        return false;
    }

    // Deregister from the handler if we have one
    if (ipchandler != NULL) {
        ipchandler->RemoveReadBufferInterface();
    }

    // Kill the running process if we have one
    if (source_ipc != NULL) {
        ss.str("");
        ss << "Datasource '" << get_source_name() << "' launching IPC with a running "
            "process, killing existing process pid " << get_child_pid();
        _MSG(ss.str(), MSGFLAG_INFO);

        source_ipc->soft_kill();
    }

    // Make a new handler and new ipc.  Give a generous buffer.
    ipchandler = new RingbufferHandler((32 * 1024), (32 * 1024));
    ipchandler->SetReadBufferInterface(this);

    source_ipc = new IPCRemoteV2(globalreg, ipchandler);
    
    // TODO set binary paths from config

    vector<string> args;

    int ret = source_ipc->launch_kis_binary(get_source_ipc_bin(), args);

    if (ret < 0) {
        ss.str("");
        ss << "Datasource '" << get_source_name() << 
            "' failed to launch IPC binary '" <<
            get_source_ipc_bin() << "'";
        _MSG(ss.str(), MSGFLAG_ERROR);

        // Call the handler if we have one
        if (error_callback != NULL)
            (*error_callback)(this, error_aux);

        return false;
    }

    return true;
}

KisDataSource_QueuedCommand::KisDataSource_QueuedCommand(string in_cmd,
        KisDataSource::KVmap *in_kv, time_t in_time) {
    command = in_cmd;
    kv = in_kv;
    insert_time = in_time;
}

KisDataSource_CapKeyedObject::KisDataSource_CapKeyedObject(simple_cap_proto_kv *in_kp) {
    char ckey[17];

    snprintf(ckey, 17, "%s", in_kp->header.key);
    key = string(ckey);

    size = kis_ntoh32(in_kp->header.obj_sz);
    object = new char[size];
    memcpy(object, in_kp->object, size);
}

KisDataSource_CapKeyedObject::KisDataSource_CapKeyedObject(string in_key,
        char *in_object, ssize_t in_len) {

    key = in_key.substr(0, 16);
    object = new char[in_len];
    memcpy(object, in_object, in_len);
}

KisDataSource_CapKeyedObject::~KisDataSource_CapKeyedObject() {
    delete[] object;
}

