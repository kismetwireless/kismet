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
#include "datasourcetracker.h"
#include "simple_datasource_proto.h"
#include "endian_magic.h"
#include "configfile.h"
#include "msgpack_adapter.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

KisDataSource::KisDataSource(GlobalRegistry *in_globalreg, int in_id,
        SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
    globalreg = in_globalreg;

    register_fields();
    reserve_fields(e);

    initialize();
}

KisDataSource::KisDataSource(GlobalRegistry *in_globalreg, int in_id) :
    tracker_component(in_globalreg, in_id) {
    globalreg = in_globalreg;
        
    register_fields();
    reserve_fields(NULL);

    initialize();
}

void KisDataSource::initialize() {
    packetchain = 
        static_pointer_cast<Packetchain>(globalreg->FetchGlobal("PACKETCHAIN"));

	pack_comp_linkframe = packetchain->RegisterPacketComponent("LINKFRAME");
    pack_comp_l1info = packetchain->RegisterPacketComponent("RADIODATA");
    pack_comp_gps = packetchain->RegisterPacketComponent("GPS");

    pthread_mutex_init(&source_lock, NULL);

    ringbuf_handler = NULL;
    ipc_remote = NULL;

    next_cmd_sequence = 1;
}

KisDataSource::~KisDataSource() {
    // Make sure no-one is holding a reference to us
    local_eol_locker lock(&source_lock);

    close_source();

    pthread_mutex_destroy(&source_lock);
}

void KisDataSource::close_source() {

    if (ipc_remote != NULL) {
        ipc_remote->close_ipc();
        ipc_remote->soft_kill();
    } else {
        // Try killing the connection with the DST TCPserver
    }

    set_source_running(false);
    set_child_pid(-1);
}

void KisDataSource::register_fields() {
    RegisterField("kismet.datasource.source_name", TrackerString,
            "Human name of data source", &source_name);
    RegisterField("kismet.datasource.source_interface", TrackerString,
            "Primary capture interface", &source_interface);
    RegisterField("kismet.datasource.source_uuid", TrackerUuid,
            "UUID", &source_uuid);
    RegisterField("kismet.datasource.source_id", TrackerInt32,
            "Run-time ID", &source_id);

    __RegisterComplexField(KisDataSourceBuilder, prototype_id, 
            "kismet.datasource.driver", "Datasource driver definition");

    RegisterField("kismet.datasource.child_pid", TrackerInt64,
            "PID of data capture process", &child_pid);
    RegisterField("kismet.datasource.ipc_bin", TrackerString,
            "driver binary", &source_ipc_bin);

    RegisterField("kismet.datasource.sourceline", TrackerString,
            "original source definition", &sourceline);

    RegisterField("kismet.datasource.channel", TrackerString,
            "channel (if not hopping)", &source_channel);

    source_channel_entry_builder =
        globalreg->entrytracker->RegisterAndGetField("kismet.device.base.channel", 
                TrackerString, "channel (phy specific)");

    RegisterField("kismet.datasource.channels", TrackerVector,
            "Supported channels for this device", &source_channels_vec);

    RegisterField("kismet.datasource.running", TrackerUInt8,
            "source is currently operational", &source_running);

    RegisterField("kismet.datasource.hopping", TrackerUInt8,
            "source is channel hopping (bool)", &source_hopping);
    RegisterField("kismet.datasource.hop_rate", TrackerDouble,
            "channel hopping rate", &source_hop_rate);
    RegisterField("kismet.datasource.hop_channels", TrackerVector,
            "channel hop list", &source_hop_vec);
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
    ringbuf_handler->PeekReadBufferData(buf, in_amt);

    frame_header = (simple_cap_proto_t *) buf;

    if (kis_ntoh32(frame_header->signature) != KIS_CAP_SIMPLE_PROTO_SIG) {
        _MSG("Kismet data source " + get_source_name() + " got an invalid "
                "control from on IPC/Network, closing.", MSGFLAG_ERROR);
        delete[] buf;
        close_source();
        return;
    }

    frame_sz = kis_ntoh32(frame_header->packet_sz);

    if (frame_sz > in_amt) {
        // Nothing we can do right now, not enough data to make up a complete packet.
        delete[] buf;
        return;
    }

    // Get the checksum & save it
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
    ringbuf_handler->GetReadBufferData(NULL, frame_sz);

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

void KisDataSource::BufferError(string in_error) {
    _MSG(in_error, MSGFLAG_ERROR);
    
    {
        local_locker lock(&source_lock);

        if (probe_cb != NULL) {
            probe_cb(false, probe_transaction);
        }

        if (list_cb != NULL) {
            list_cb(vector<SharedListInterface>());
        }

        if (ipc_remote != NULL) {
            // Kill the IPC
            ipc_remote->soft_kill();

            set_source_running(false);
            set_child_pid(-1);
        } else if (ringbuf_handler != NULL) {
            datasourcetracker->KillConnection(ringbuf_handler);
        }

    }
}

bool KisDataSource::write_packet(string in_cmd, KVmap in_kvmap) {
    simple_cap_proto_t *ret = NULL;
    vector<simple_cap_proto_kv_t *> proto_kvpairs;
    size_t kvpair_len = 0;
    size_t kvpair_offt = 0;
    size_t pack_len;

    for (auto i = in_kvmap.begin(); i != in_kvmap.end(); ++i) {
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

    snprintf(ret->type, 16, "%s", in_cmd.c_str());

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
        // Lock & send to the ringbuffer
        local_locker lock(&source_lock);
        ret_sz = ringbuf_handler->PutWriteBufferData(ret, pack_len, true);

        delete ret;
    }

    if (ret_sz != pack_len) {
        return false;
    }

    return true;
}


int KisDataSource::probe_source(string in_source, unsigned int in_transaction,
        function<void (bool, unsigned int)> in_cb) {
    local_locker lock(&source_lock);

    /* Inherited functions must fill this in.
     *
     * Non-ipc probing should be handled immediately, ipc probe should
     * launch ipc and queue a probe command, returning the results to the
     * callback when the probe command completes
     */

    probe_cb = in_cb;
    probe_transaction = in_transaction;

    set_sourceline(in_source);

    return 0;
}

int KisDataSource::open_local_source(string in_source, unsigned int in_transaction,
        function<void (bool, unsigned int)> in_cb) {
    local_locker lock(&source_lock);

    /* Inherited functions must fill this in.
     *
     * Non-IPC sources can perform an open directly
     * IPC sources should use src_send_open
     *
     */

    open_cb = in_cb;
    open_transaction = in_transaction;
    set_sourceline(in_source);

    return 0;
}

bool KisDataSource::src_send_probe(string srcdef) {
    if (!get_prototype()->get_tracker_local_capable())
        return false;

    if (!get_prototype()->get_local_ipc()) 
        return false;

    if (ringbuf_handler == NULL && ipc_remote == NULL) {
        if (!spawn_ipc()) {
            if (open_cb != NULL) {
                open_cb(false, open_transaction);
            }

            return false;
        }
    }

    KisDataSource_CapKeyedObject *definition =
        new KisDataSource_CapKeyedObject("DEFINITION", srcdef.data(), srcdef.length());

    KVmap kvmap;

    kvmap.insert(KVpair("DEFINITION", definition));

    return write_packet("PROBEDEVICE", kvmap);
}

bool KisDataSource::src_send_open(string srcdef) {
    if (!get_prototype()->get_tracker_local_capable())
        return false;

    if (!get_prototype()->get_local_ipc()) 
        return false;

    if (ringbuf_handler == NULL && ipc_remote == NULL) {
        if (!spawn_ipc()) {
            if (open_cb != NULL) {
                open_cb(false, open_transaction);
            }

            return false;
        }
    }

    KisDataSource_CapKeyedObject *definition =
        new KisDataSource_CapKeyedObject("DEFINITION", srcdef.data(), srcdef.length());

    KVmap kvmap;

    kvmap.insert(KVpair("DEFINITION", definition));

    return write_packet("OPENDEVICE", kvmap);
}

bool KisDataSource::src_set_channel(string in_channel) {
    // Blow up if we can't set a channel
    if (!get_prototype()->get_tune_capable()) {
        _MSG("Attempt to set channel on source " + get_source_name() + " which is "
                "not capable of tuning", MSGFLAG_ERROR);
        return false;
    }

    if (ringbuf_handler == NULL) {
        _MSG("Attempt to set channel on source '" + get_source_name() + "' which "
                "is closed", MSGFLAG_ERROR);
        return false;
    }

    KisDataSource_CapKeyedObject *chanset =
        new KisDataSource_CapKeyedObject("CHANSET", in_channel.data(),
                in_channel.length());
    KVmap kvmap;

    kvmap.insert(KVpair("CHANSET", chanset));

    return write_packet("CONFIGURE", kvmap);
}

bool KisDataSource::set_channel_hop(vector<string> in_channel_list, double in_rate) {
    if (!get_prototype()->get_tune_capable()) {
        _MSG("Attempt to set channel hop on source " + get_source_name() + " which is "
                "not capable of tuning", MSGFLAG_ERROR);
        return false;
    }

    if (ringbuf_handler == NULL) {
        _MSG("Attempt to set channel hop on source " + get_source_name() + " which is "
                "closed", MSGFLAG_ERROR);
        return false;
    }

    // Build a new element of the channels
    SharedTrackerElement newchans = get_source_hop_vec()->clone_type();
    TrackerElementVector hv(newchans);

    for (auto i = in_channel_list.begin(); i != in_channel_list.end(); ++i) {
        SharedTrackerElement c = source_channel_entry_builder->clone_type();
        c->set(*i);
        hv.push_back(c);
    }

    // Call the element-based set
    return set_channel_hop(newchans, in_rate);
}

bool KisDataSource::set_channel_hop(SharedTrackerElement in_channel_list, 
        double in_rate) {

    if (!get_prototype()->get_tune_capable()) {
        _MSG("Attempt to set channel hop on source " + get_source_name() + " which is "
                "not capable of tuning", MSGFLAG_ERROR);
        return false;
    }

    if (ringbuf_handler == NULL) {
        _MSG("Attempt to set channel hop on source " + get_source_name() + " which is "
                "closed", MSGFLAG_ERROR);
        return false;
    }

    TrackerElementVector in_vec(in_channel_list);

    stringstream stream;
    msgpack::packer<std::stringstream> packer(&stream);

    // 2-element dictionary
    packer.pack_map(2);

    // Pack the rate dictionary entry
    packer.pack(string("rate"));
    packer.pack(in_rate);

    // Pack the vector of channels
    packer.pack(string("channels"));
    packer.pack_array(in_vec.size());

    for (auto i = in_vec.begin(); i != in_vec.end(); ++i) {
        packer.pack((*i)->get_string());
    }

    KisDataSource_CapKeyedObject *chanhop =
        new KisDataSource_CapKeyedObject("CHANHOP", stream.str().data(),
                stream.str().length());
    KVmap kvmap;

    kvmap.insert(KVpair("CHANHOP", chanhop));

    // Set the local variables
    set_int_source_hop_rate(in_rate);

    // Only dupe the hop vec if it's not the one we already have set, since
    // we can get called w/ our existing vector when just setting the hop rate
    if (in_channel_list != get_source_hop_vec()) {
        TrackerElementVector hv(get_source_hop_vec());
        hv.clear();
        for (auto i = in_vec.begin(); i != in_vec.end(); ++i) {
            hv.push_back(*i);
        }
    }

    return write_packet("CONFIGURE", kvmap);
}

bool KisDataSource::src_set_source_hop_vec(SharedTrackerElement in_vec) {
    return set_channel_hop(in_vec, get_source_hop_rate());
}

bool KisDataSource::src_set_source_hop_rate(double in_rate) {
    return set_channel_hop(get_source_hop_vec(), in_rate);
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

        if (probe_cb != NULL) {
            probe_cb(handle_kv_success(i->second), probe_transaction);
        }

    } else {
        // ProbeResp with no success value?  ehh.
        BufferError("Invalid interface probe response");
        return;
    }

    if (ipc_remote != NULL)
        ipc_remote->close_ipc();
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

        if (open_cb != NULL) {
            open_cb(handle_kv_success(i->second), open_transaction);
        }
    } else {
        // OpenResp with no success value?  ehh.
        BufferError("Invalid interface open response");
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

        if (ipc_remote != NULL) {
            ipc_remote->soft_kill();

            set_source_running(false);
            set_child_pid(0);
        } else if (ringbuf_handler != NULL) {
            datasourcetracker->KillConnection(ringbuf_handler);
        }
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

    kis_packet *packet = NULL;
    kis_layer1_packinfo *siginfo = NULL;
    kis_gps_packinfo *gpsinfo = NULL;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    // Do we have a packet?
    if ((i = in_kvpairs.find("packet")) != in_kvpairs.end()) {
        packet = handle_kv_packet(i->second);
    }

    if (packet == NULL)
        return;

    // Gather signal data
    if ((i = in_kvpairs.find("signal")) != in_kvpairs.end()) {
        siginfo = handle_kv_signal(i->second);
    }
    
    // Gather GPS data
    if ((i = in_kvpairs.find("gps")) != in_kvpairs.end()) {
        gpsinfo = handle_kv_gps(i->second);
    }

    // Add them to the packet
    if (siginfo != NULL) {
        packet->insert(pack_comp_l1info, siginfo);
    }

    if (gpsinfo != NULL) {
        packet->insert(pack_comp_gps, gpsinfo);
    }

    // Inject the packet into the packetchain if we have one
    packetchain->ProcessPacket(packet);

}

bool KisDataSource::handle_kv_success(KisDataSource_CapKeyedObject *in_obj) {
    // Not a msgpacked object, just a single byte
    if (in_obj->size != 1) {
        BufferError("Invalid kv_success object");
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

        BufferError(ss.str());

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

            TrackerElementVector chan_vec(get_source_channels_vec());
            chan_vec.clear();

            for (unsigned int x = 0; x < channel_vec.size(); x++) {
                SharedTrackerElement chanstr = 
                    source_channel_entry_builder->clone_type();
                chanstr->set(channel_vec[x]);
                chan_vec.push_back(chanstr);
            }
        }
    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        stringstream ss;
        ss << "Source " << get_source_name() << " failed to unpack proberesp " <<
            "channels bundle: " << e.what();

        BufferError(ss.str());

        return false;
    }

    return true;
}

kis_layer1_packinfo *KisDataSource::handle_kv_signal(KisDataSource_CapKeyedObject *in_obj) {
    kis_layer1_packinfo *siginfo = new kis_layer1_packinfo();

    // Unpack the dictionary
    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size);
        msgpack::object deserialized = result.get();
        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        if ((obj_iter = dict.find("signal_dbm")) != dict.end()) {
            siginfo->signal_type = kis_l1_signal_type_dbm;
            siginfo->signal_dbm = obj_iter->second.as<int32_t>();
        }

        if ((obj_iter = dict.find("noise_dbm")) != dict.end()) {
            siginfo->signal_type = kis_l1_signal_type_dbm;
            siginfo->noise_dbm = obj_iter->second.as<int32_t>();
        }

        if ((obj_iter = dict.find("signal_rssi")) != dict.end()) {
            siginfo->signal_type = kis_l1_signal_type_rssi;
            siginfo->signal_rssi = obj_iter->second.as<int32_t>();
        }

        if ((obj_iter = dict.find("noise_rssi")) != dict.end()) {
            siginfo->signal_type = kis_l1_signal_type_rssi;
            siginfo->noise_rssi = obj_iter->second.as<int32_t>();
        }

        if ((obj_iter = dict.find("freq_khz")) != dict.end()) {
            siginfo->freq_khz = obj_iter->second.as<double>();
        }

        if ((obj_iter = dict.find("channel")) != dict.end()) {
            siginfo->channel = obj_iter->second.as<string>();
        }

        if ((obj_iter = dict.find("datarate")) != dict.end()) {
            siginfo->datarate = obj_iter->second.as<double>();
        }

    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        stringstream ss;
        ss << "Source " << get_source_name() << " failed to unpack gps bundle: " <<
            e.what();

        BufferError(ss.str());

        delete(siginfo);

        return NULL;
    }


    return siginfo;
}

kis_gps_packinfo *KisDataSource::handle_kv_gps(KisDataSource_CapKeyedObject *in_obj) {
    kis_gps_packinfo *gpsinfo = new kis_gps_packinfo();

    // Unpack the dictionary
    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size);
        msgpack::object deserialized = result.get();
        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        if ((obj_iter = dict.find("lat")) != dict.end()) {
            gpsinfo->lat = obj_iter->second.as<double>();
        }

        if ((obj_iter = dict.find("lon")) != dict.end()) {
            gpsinfo->lon = obj_iter->second.as<double>();
        }

        if ((obj_iter = dict.find("alt")) != dict.end()) {
            gpsinfo->alt = obj_iter->second.as<double>();
        }

        if ((obj_iter = dict.find("speed")) != dict.end()) {
            gpsinfo->speed = obj_iter->second.as<double>();
        }

        if ((obj_iter = dict.find("heading")) != dict.end()) {
            gpsinfo->heading = obj_iter->second.as<double>();
        }

        if ((obj_iter = dict.find("precision")) != dict.end()) {
            gpsinfo->precision = obj_iter->second.as<double>();
        }

        if ((obj_iter = dict.find("fix")) != dict.end()) {
            gpsinfo->precision = obj_iter->second.as<int32_t>();
        }

        if ((obj_iter = dict.find("time")) != dict.end()) {
            gpsinfo->time = (time_t) obj_iter->second.as<uint64_t>();
        }

        if ((obj_iter = dict.find("name")) != dict.end()) {
            gpsinfo->gpsname = obj_iter->second.as<string>();
        }

    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        stringstream ss;
        ss << "Source " << get_source_name() << " failed to unpack gps bundle: " <<
            e.what();

        BufferError(ss.str());

        delete(gpsinfo);
        return NULL;
    }

    return gpsinfo;

}

kis_packet *KisDataSource::handle_kv_packet(KisDataSource_CapKeyedObject *in_obj) {
    kis_packet *packet = packetchain->GeneratePacket();
    kis_datachunk *datachunk = new kis_datachunk();

    // Unpack the dictionary
    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size);
        msgpack::object deserialized = result.get();
        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        if ((obj_iter = dict.find("tv_sec")) != dict.end()) {
            packet->ts.tv_sec = (time_t) obj_iter->second.as<uint64_t>();
        } else {
            throw std::runtime_error(string("tv_sec timestamp missing"));
        }

        if ((obj_iter = dict.find("tv_usec")) != dict.end()) {
            packet->ts.tv_usec = (time_t) obj_iter->second.as<uint64_t>();
        } else {
            throw std::runtime_error(string("tv_usec timestamp missing"));
        }

        if ((obj_iter = dict.find("dlt")) != dict.end()) {
            datachunk->dlt = obj_iter->second.as<uint64_t>();
        } else {
            throw std::runtime_error(string("DLT missing"));
        }

        // Record the size
        uint64_t size = 0;
        if ((obj_iter = dict.find("size")) != dict.end()) {
            size = obj_iter->second.as<uint64_t>();
        } else {
            throw std::runtime_error(string("size field missing or zero"));
        }

        msgpack::object rawdata;
        if ((obj_iter = dict.find("packet")) != dict.end()) {
            rawdata = obj_iter->second;
        } else {
            throw std::runtime_error(string("packet data missing"));
        }

        if (rawdata.via.bin.size != size) {
            throw std::runtime_error(string("packet size did not match data size"));
        }

        datachunk->copy_data((const uint8_t *) rawdata.via.bin.ptr, size);

    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        stringstream ss;
        ss << "Source " << get_source_name() << " failed to unpack packet bundle: " <<
            e.what();

        BufferError(ss.str());

        // Destroy the packet appropriately
        packetchain->DestroyPacket(packet);
        // Always delete the datachunk, we don't insert it into the packet
        // until later
        delete(datachunk);

        return NULL;
    }

    packet->insert(pack_comp_linkframe, datachunk);

    return packet;

}

bool KisDataSource::spawn_ipc() {
    stringstream ss;

    // Do not lock thread, we can only be called when we're inside a locked
    // context.
    
    set_source_running(false);
    set_child_pid(0);

    if (get_source_ipc_bin() == "") {
        ss << "Datasource '" << get_source_name() << "' missing IPC binary, cannot "
            "launch binary";
        
        _MSG(ss.str(), MSGFLAG_ERROR);

        return false;
    }

    // Kill the running process if we have one
    if (ipc_remote != NULL) {
        ss.str("");
        ss << "Datasource '" << get_source_name() << "' launching IPC with a running "
            "process, killing existing process pid " << get_child_pid();
        _MSG(ss.str(), MSGFLAG_INFO);

        ipc_remote->soft_kill();
    }

    // Make a new handler and new ipc.  Give a generous buffer.
    ringbuf_handler.reset(new RingbufferHandler((32 * 1024), (32 * 1024)));
    ringbuf_handler->SetReadBufferInterface(this);

    ipc_remote = new IPCRemoteV2(globalreg, ringbuf_handler);

    // Get allowed paths for binaries
    vector<string> bin_paths = globalreg->kismet_config->FetchOptVec("bin_paths");

    for (vector<string>::iterator i = bin_paths.begin(); i != bin_paths.end(); ++i) {
        ipc_remote->add_path(*i);
    }

    vector<string> args;

    int ret = ipc_remote->launch_kis_binary(get_source_ipc_bin(), args);

    if (ret < 0) {
        ss.str("");
        ss << "Datasource '" << get_source_name() << "' failed to launch IPC " <<
            "binary '" << get_source_ipc_bin() << "'";
        _MSG(ss.str(), MSGFLAG_ERROR);

        return false;
    }

    set_source_running(true);
    set_child_pid(ipc_remote->get_pid());

    return true;
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
        const char *in_object, ssize_t in_len) {

    key = in_key.substr(0, 16);
    object = new char[in_len];
    memcpy(object, in_object, in_len);
}

KisDataSource_CapKeyedObject::~KisDataSource_CapKeyedObject() {
    delete[] object;
}

