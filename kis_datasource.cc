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
#include "configfile.h"
#include "msgpack_adapter.h"
#include "datasourcetracker.h"
#include "entrytracker.h"
#include "alertracker.h"

// We never instantiate from a generic tracker component or from a stored
// record so we always re-allocate ourselves
KisDatasource::KisDatasource(GlobalRegistry *in_globalreg, 
        SharedDatasourceBuilder in_builder) :
    tracker_component(in_globalreg, 0) {

    globalreg = in_globalreg;
    
    register_fields();
    reserve_fields(NULL);

    set_source_builder(in_builder);

    if (in_builder != NULL)
        add_map(in_builder);

    timetracker = 
        Globalreg::FetchGlobalAs<Timetracker>(globalreg, "TIMETRACKER");

    packetchain =
        Globalreg::FetchGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");

    datasourcetracker =
        Globalreg::FetchGlobalAs<Datasourcetracker>(globalreg, "DATASOURCETRACKER");

	pack_comp_linkframe = packetchain->RegisterPacketComponent("LINKFRAME");
    pack_comp_l1info = packetchain->RegisterPacketComponent("RADIODATA");
    pack_comp_gps = packetchain->RegisterPacketComponent("GPS");
	pack_comp_datasrc = packetchain->RegisterPacketComponent("KISDATASRC");

    next_cmd_sequence = rand(); 

    error_timer_id = -1;
    ping_timer_id = -1;

    mode_probing = false;
    mode_listing = false;

    shared_ptr<EntryTracker> entrytracker = 
        Globalreg::FetchGlobalAs<EntryTracker>(globalreg, "ENTRY_TRACKER");
    listed_interface_builder =
        entrytracker->RegisterAndGetField("kismet.datasourcetracker.listed_interface", 
                SharedInterface(new KisDatasourceInterface(globalreg, 0)), 
                    "auto-discovered interface");

    last_pong = time(0);

    quiet_errors = 0;

    set_int_source_running(false);
}

KisDatasource::~KisDatasource() {
    local_eol_locker lock(&source_lock);

    // fprintf(stderr, "debug - ~KisDatasource\n");

    // Cancel any timer
    if (error_timer_id > 0)
        timetracker->RemoveTimer(error_timer_id);

    if (ping_timer_id > 0)
        timetracker->RemoveTimer(ping_timer_id);

    // Delete the ringbuf handler
    if (ringbuf_handler != NULL) {
        // Remove ourself from getting notifications from the rb
        ringbuf_handler->RemoveReadBufferInterface();
        // We're shutting down, issue a protocol error to kill any line-drivers
        // attached to this buffer
        ringbuf_handler->ProtocolError();
        // Lose our local ref
        ringbuf_handler.reset();
    } else {
        // fprintf(stderr, "debug - ~kds null ringbuf\n");
    }

    ipc_remote.reset();

    command_ack_map.empty();

    // We don't call a normal close here because we can't risk double-free
    // or going through commands again - if the source is being deleted, it should
    // be completed!
}

void KisDatasource::list_interfaces(unsigned int in_transaction, 
        list_callback_t in_cb) {
    local_locker lock(&source_lock);

    mode_listing = true;

    // If we can't list interfaces according to our prototype, die 
    // and call the cb instantly
    if (!get_source_builder()->get_list_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, std::vector<SharedInterface>());
        }

        return;
    }

    // Launch the IPC
    launch_ipc();

    // Otherwise create and send a list command
    send_command_list_interfaces(in_transaction, in_cb);
}

void KisDatasource::probe_interface(std::string in_definition, unsigned int in_transaction,
        probe_callback_t in_cb) {
    local_locker lock(&source_lock);

    mode_probing = true;

    set_int_source_definition(in_definition);
    
    // If we can't probe interfaces according to our prototype, die
    // and call the cb instantly
    if (!get_source_builder()->get_probe_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver not capable of probing");
        }

        return;
    }

    // Populate our local info about the interface
    if (!parse_interface_definition(in_definition)) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Malformed source config");
        }

        return;
    }

    // Launch the IPC
    launch_ipc();

    // Create and send list command
    send_command_probe_interface(in_definition, in_transaction, in_cb);
}

void KisDatasource::open_interface(std::string in_definition, unsigned int in_transaction, 
        open_callback_t in_cb) {
    local_locker lock(&source_lock);

    set_int_source_definition(in_definition);

    // Populate our local info about the interface
    if (!parse_interface_definition(in_definition)) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Malformed source config");
        }

        return;
    }

    if (get_source_builder()->get_passive_capable()) {
        if (get_source_uuid().error && !local_uuid) {
            uuid nuuid;

            nuuid.GenerateTimeUUID((uint8_t *) "\x00\x00\x00\x00\x00\x00");

            set_source_uuid(nuuid);
            set_source_key(Adler32Checksum(nuuid.UUID2String()));
        }

        set_int_source_retry_attempts(0);

        set_int_source_running(1);
        set_int_source_error(0);

        if (in_cb != NULL)
            in_cb(in_transaction, true, "Source opened");

        return;
    }
    
    // If we can't open local interfaces, die
    if (!get_source_builder()->get_local_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver does not support direct capture");
        }
        
        return;
    }

    // If we have an error callback that's going to try to re-open us, cancel it
    if (error_timer_id > 0)
        timetracker->RemoveTimer(error_timer_id);

    // Launch the IPC
    launch_ipc();

    // Create and send open command
    send_command_open_interface(in_definition, in_transaction, in_cb);
}

void KisDatasource::set_channel(std::string in_channel, unsigned int in_transaction,
        configure_callback_t in_cb) {
    local_locker lock(&source_lock);

    if (!get_source_builder()->get_tune_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver not capable of changing channel");
        }
        return;
    }

    send_command_set_channel(in_channel, in_transaction, in_cb);
}

void KisDatasource::set_channel_hop(double in_rate, std::vector<std::string> in_chans,
        bool in_shuffle, unsigned int in_offt, unsigned int in_transaction, 
        configure_callback_t in_cb) {
    local_locker lock(&source_lock);

    if (!get_source_builder()->get_tune_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver not capable of changing channel");
        }
        return;
    }

    // Convert the std::vector to a channel vector
    SharedTrackerElement elem(get_source_hop_vec()->clone_type());
    TrackerElementVector vec(elem);

    for (auto i = in_chans.begin(); i != in_chans.end(); ++i) {
        SharedTrackerElement c(channel_entry_builder->clone_type());
        c->set(*i);
        vec.push_back(c);
    }

    // Call the tracker element variation
    set_channel_hop(in_rate, elem, in_shuffle, in_offt, in_transaction, in_cb);
}

void KisDatasource::set_channel_hop(double in_rate, SharedTrackerElement in_chans,
        bool in_shuffle, unsigned int in_offt, unsigned int in_transaction, 
        configure_callback_t in_cb) {
    local_locker lock(&source_lock);

    if (!get_source_builder()->get_tune_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver not capable of changing channel");
        }
        return;
    }

    // Generate the command and send it
    send_command_set_channel_hop(in_rate, in_chans, in_shuffle, in_offt, 
            in_transaction, in_cb);
}

void KisDatasource::set_channel_hop_rate(double in_rate, unsigned int in_transaction,
        configure_callback_t in_cb) {
    // Don't bother checking if we can set channel since we're just calling a function
    // that already checks that
    set_channel_hop(in_rate, get_source_hop_vec(), get_source_hop_shuffle(),
            get_source_hop_offset(), in_transaction, in_cb);
}

void KisDatasource::set_channel_hop_list(std::vector<std::string> in_chans,
        unsigned int in_transaction, configure_callback_t in_cb) {
    // Again don't bother, we're just an API shim
    set_channel_hop(get_source_hop_rate(), in_chans, get_source_hop_shuffle(),
            get_source_hop_offset(), in_transaction, in_cb);
}

void KisDatasource::connect_buffer(shared_ptr<BufferHandlerGeneric> in_ringbuf,
        std::string in_definition, open_callback_t in_cb) {
    local_locker lock(&source_lock);

    set_int_source_running(true);

    if (ringbuf_handler != NULL && ringbuf_handler != in_ringbuf) {
        // printf("debug - disconnecting existing ringbuffer from new remote source\n");
        // ringbuf_handler->RemoveReadBufferInterface();
        // ringbuf_handler->ProtocolError();
        ringbuf_handler = NULL;
    }

    // Assign the ringbuffer & set us as the wakeup interface
    ringbuf_handler = in_ringbuf;
    ringbuf_handler->SetReadBufferInterface(this);

    set_int_source_definition(in_definition);
    
    // Populate our local info about the interface
    if (!parse_interface_definition(in_definition)) {
        set_int_source_running(false);
        _MSG("Unable to parse interface definition", MSGFLAG_ERROR);
        return;
    }

    // We can't reconnect failed interfaces that are remote
    set_int_source_retry(false);
    
    // We're remote
    set_int_source_remote(true);

    // Send an opensource
    send_command_open_interface(in_definition, 0, in_cb);
}

void KisDatasource::close_source() {
    local_locker lock(&source_lock);

    if (get_source_error())
        return;

    if (!get_source_running())
        return;

    if (ping_timer_id > 0) {
        timetracker->RemoveTimer(ping_timer_id);
        ping_timer_id = -1;
    }

    if (ringbuf_handler != NULL) {
        ringbuf_handler->RemoveReadBufferInterface();
        uint32_t seqno = 0;
        write_packet("CLOSEDEVICE", KVmap(), seqno);
    }

    if (ipc_remote != NULL) {
        ipc_remote->soft_kill();
    }

    quiet_errors = true;

    cancel_all_commands("Closing source");

    set_int_source_running(false);
}

void KisDatasource::disable_source() {
    local_locker lock(&source_lock);

    close_source();

    set_int_source_error(false);
    set_int_source_error_reason("Source disabled");

    // cancel any timers
    if (error_timer_id > 0)
        timetracker->RemoveTimer(error_timer_id);

    error_timer_id = -1;
}

void KisDatasource::BufferAvailable(size_t in_amt __attribute__((unused))) {
    // Handle reading raw frames off the incoming buffer and validate their
    // framing, then break them into KVMap records and dispatch them.
    //
    // We can survive unknown frame types, but we can't survive invalid ones -
    // if we get an invalid frame, throw an error and drop into the error
    // processing.
    
    local_locker lock(&source_lock);
    
    simple_cap_proto_frame_t *frame;
    uint8_t *buf = NULL;
    uint32_t frame_sz;
    uint32_t header_checksum, data_checksum, calc_checksum;

    // Loop until we drain the buffer
    while (1) {
        if (ringbuf_handler == NULL)
            return;

        size_t buffamt = ringbuf_handler->GetReadBufferUsed();
        if (buffamt < sizeof(simple_cap_proto_t)) {
            return;
        }

        // Allocate as much as we can and peek it from the buffer
        buffamt = ringbuf_handler->PeekReadBufferData((void **) &buf, buffamt);

        if (buffamt < sizeof(simple_cap_proto_t)) {
            ringbuf_handler->PeekFreeReadBufferData(buf);
            return;
        }

        // fprintf(stderr, "debug - sig %x header %u data %u sequence %u\n", frame->header.signature, kis_ntoh32(frame->header.header_checksum), kis_ntoh32(frame->header.data_checksum), kis_ntoh32(frame->header.sequence_number));


        // Turn it into a frame header
        frame = (simple_cap_proto_frame_t *) buf;

        if (kis_ntoh32(frame->header.signature) != KIS_CAP_SIMPLE_PROTO_SIG) {
            ringbuf_handler->PeekFreeReadBufferData(buf);

            _MSG("Kismet data source " + get_source_name() + " got an invalid "
                    "control from on IPC/Network, closing.", MSGFLAG_ERROR);
            trigger_error("Source got invalid control frame");

            return;
        }

        // Get the frame header checksum and validate it; to validate we need to clear
        // both the frame and the data checksum fields so remember them both now
        header_checksum = kis_ntoh32(frame->header.header_checksum);
        data_checksum = kis_ntoh32(frame->header.data_checksum);

        // fprintf(stderr, "debug - sig %x header %u data %u sequence %u\n", frame->header.signature, header_checksum, data_checksum, kis_ntoh32(frame->header.sequence_number));

        // Zero the checksum field in the packet
        frame->header.header_checksum = 0;
        frame->header.data_checksum = 0;

        // Calc the checksum of the header
        calc_checksum = Adler32Checksum((const char *) frame, 
                sizeof(simple_cap_proto_t));

        // fprintf(stderr, "debug - frame type... %s len %u?\n", string(frame->header.type, 16).c_str(), kis_ntoh32(frame->header.packet_sz));

        // Compare to the saved checksum
        if (calc_checksum != header_checksum) {
            // Restore the headers in case
            frame->header.header_checksum = kis_hton32(header_checksum);
            frame->header.data_checksum = kis_hton32(data_checksum);

            ringbuf_handler->PeekFreeReadBufferData(buf);

#if 0
            fprintf(stderr, "debug - calc %X header %X\n", calc_checksum, header_checksum);

            for (unsigned int x = 0; x < 100; x++) {
                fprintf(stderr, "%02X ", ((uint8_t *) frame)[x] & 0xFF);
            }
            fprintf(stderr, "\n");
#endif

            _MSG("Kismet data source " + get_source_name() + " got an invalid hdr " +
                    "checksum on control from IPC/Network, closing.", MSGFLAG_ERROR);
            trigger_error("Source got invalid control frame");

            return;
        }

        // Get the size of the frame
        frame_sz = kis_ntoh32(frame->header.packet_sz);

        // fprintf(stderr, "debug - got frame sz %u\n", frame_sz);

        if (frame_sz > buffamt) {
            // fprintf(stderr, "debug - got frame sz %u too big for current buffer %lu\n", frame_sz, buffamt);
            // Restore the headers in case
            frame->header.header_checksum = kis_hton32(header_checksum);
            frame->header.data_checksum = kis_hton32(data_checksum);

#if 0
            for (unsigned int x = 0; x < buffamt; x++) {
                fprintf(stderr, "%02X ", buf[x] & 0xFF);
            }
            fprintf(stderr, "\n");
#endif

            // Nothing we can do right now, not enough data to 
            // make up a complete packet.
            ringbuf_handler->PeekFreeReadBufferData(buf);
            return;
        }

        // Calc the checksum of the rest
        calc_checksum = Adler32Checksum((const char *) buf, frame_sz);

        // Compare to the saved checksum
        if (calc_checksum != data_checksum) {
            ringbuf_handler->PeekFreeReadBufferData(buf);

            _MSG("Kismet data source " + get_source_name() + " got an invalid checksum "
                    "on control from IPC/Network, closing.", MSGFLAG_ERROR);
            trigger_error("Source got invalid control frame");

            return;
        }

        // Extract the kv pairs
        KVmap kv_map;

        size_t data_offt = 0;
        for (unsigned int kvn = 0; 
                kvn < kis_ntoh32(frame->header.num_kv_pairs); kvn++) {

            if (frame_sz < sizeof(simple_cap_proto_t) + 
                    sizeof(simple_cap_proto_kv_t) + data_offt) {

                // Consume the packet in the ringbuf 
                ringbuf_handler->PeekFreeReadBufferData(buf);
                ringbuf_handler->ConsumeReadBufferData(frame_sz);

                _MSG("Kismet data source " + get_source_name() + " got an invalid "
                        "frame (KV too long for frame) from IPC/Network, closing.",
                        MSGFLAG_ERROR);
                trigger_error("Source got invalid control frame");

                return;
            }

            simple_cap_proto_kv_t *pkv =
                (simple_cap_proto_kv_t *) &((frame->data)[data_offt]);

            data_offt += 
                sizeof(simple_cap_proto_kv_h_t) +
                kis_ntoh32(pkv->header.obj_sz);

            KisDatasourceCapKeyedObject *kv =
                new KisDatasourceCapKeyedObject(pkv);

            kv_map[StrLower(kv->key)] = kv;
        }

        char ctype[17];
        snprintf(ctype, 17, "%s", frame->header.type);

        proto_dispatch_packet(ctype, kv_map);

        for (auto i = kv_map.begin(); i != kv_map.end(); ++i) {
            delete i->second;
        }

        // Consume the packet in the ringbuf 
        ringbuf_handler->PeekFreeReadBufferData(buf);
        ringbuf_handler->ConsumeReadBufferData(frame_sz);
    }
}

void KisDatasource::BufferError(std::string in_error) {
    // Simple passthrough to crash the source out from an error at the buffer level
    trigger_error(in_error);
}

void KisDatasource::trigger_error(std::string in_error) {
    local_locker lock(&source_lock);

    // fprintf(stderr, "DEBUG - trigger error %s\n", in_error.c_str());

    std::stringstream ss;

    if (!quiet_errors) {
        ss << "Data source " << get_source_name() << " (" <<
            get_source_interface() << ") encountered an error: " <<
            in_error;
        _MSG(ss.str(), MSGFLAG_ERROR);
        set_int_source_error(true);
        set_int_source_error_reason(in_error);
    }

    // Kill any interaction w/ the source
    close_source();

    /* Set errors as quiet after the first one */
    quiet_errors = 1;

    set_int_source_running(false);

    handle_source_error();
    cancel_all_commands(in_error);
}

std::string KisDatasource::get_definition_opt(std::string in_opt) {
    auto i = source_definition_opts.find(StrLower(in_opt));

    if (i == source_definition_opts.end())
        return override_default_option(in_opt);

    return i->second;
}

bool KisDatasource::get_definition_opt_bool(std::string in_opt, bool in_def) {
    auto i = source_definition_opts.find(StrLower(in_opt));
    std::string opt;

    if (i != source_definition_opts.end())
        opt = i->second;
    else
        opt = override_default_option(in_opt);

    return StringToBool(opt, in_def);
}

bool KisDatasource::parse_interface_definition(std::string in_definition) {
    local_locker lock(&source_lock);

    local_uuid = false;

    std::string interface;

    size_t cpos = in_definition.find(":");

    // Turn the rest into an opt vector
    std::vector<opt_pair> options;

    // If there's no ':' then there are no options
    if (cpos == std::string::npos) {
        set_int_source_interface(in_definition);
        set_source_name(in_definition);
    } else {
        // Slice the interface
        set_int_source_interface(in_definition.substr(0, cpos));

        // Blow up if we fail parsing
        if (StringToOpts(in_definition.substr(cpos + 1, 
                        in_definition.size() - cpos - 1), ",", &options) < 0) {
            return false;
        }

        // Throw into a nice keyed dictionary so other elements of the DS can use it
        for (auto i = options.begin(); i != options.end(); ++i) {
            source_definition_opts[StrLower((*i).opt)] = (*i).val;
        }
    }

    // Set some basic options
   
    std::string namestr = get_definition_opt("name");

    if (namestr != "") {
        set_source_name(namestr);
    } else {
        set_source_name(get_source_interface());
    }

    std::string uuidstr = get_definition_opt("uuid");

    if (uuidstr != "") {
        uuid u(uuidstr);

        if (u.error) {
            _MSG("Invalid UUID for data source " + get_source_name() + "/" + 
                    get_source_interface(), MSGFLAG_ERROR);
            return false;
        }

        set_source_uuid(u);
        local_uuid = true;
        set_source_key(Adler32Checksum(u.UUID2String()));
    }

    set_int_source_retry(get_definition_opt_bool("retry", 
                datasourcetracker->get_config_defaults()->get_retry_on_error()));

    clobber_timestamp = get_definition_opt_bool("timestamp", 
            datasourcetracker->get_config_defaults()->get_remote_cap_timestamp());
   
    return true;
}

shared_ptr<KisDatasource::tracked_command> KisDatasource::get_command(uint32_t in_transaction) {
    auto i = command_ack_map.find(in_transaction);

    if (i == command_ack_map.end())
        return NULL;

    return i->second;
}

void KisDatasource::cancel_command(uint32_t in_transaction, std::string in_error) {
    local_locker lock(&source_lock);

    auto i = command_ack_map.find(in_transaction);
    if (i != command_ack_map.end()) {
        shared_ptr<tracked_command> cmd = i->second;

        // Cancel any timers
        if (cmd->timer_id > -1) {
            timetracker->RemoveTimer(cmd->timer_id);
        }

        // fprintf(stderr, "debug - erasing from command ack via cancel %u\n", in_transaction);
        command_ack_map.erase(i);

        // Cancel any callbacks, zeroing them out as we call them so they
        // can't recurse through
        if (cmd->list_cb != NULL) {
            list_callback_t cb = cmd->list_cb;
            cmd->list_cb = NULL;
            cb(cmd->transaction, std::vector<SharedInterface>());
        } else if (cmd->probe_cb != NULL) {
            probe_callback_t cb = cmd->probe_cb;
            cmd->probe_cb = NULL;
            cb(cmd->transaction, false, in_error);
        } else if (cmd->open_cb != NULL) {
            open_callback_t cb = cmd->open_cb;
            cmd->open_cb = NULL;
            cb(cmd->transaction, false, in_error);
        } else if (cmd->configure_cb != NULL) {
            configure_callback_t cb = cmd->configure_cb;
            cmd->configure_cb = NULL;
            cb(cmd->transaction, false, in_error);
        }

        cmd.reset();
    }
}

void KisDatasource::cancel_all_commands(std::string in_error) {
    local_locker lock(&source_lock);

    // fprintf(stderr, "debug - cancel all commands\n");

    while (1) {
        auto i = command_ack_map.begin();

        if (i == command_ack_map.end())
            break;

        cancel_command(i->first, in_error);
    }

    command_ack_map.empty();
}

void KisDatasource::proto_dispatch_packet(std::string in_type, KVmap in_kvmap) {
    local_locker lock(&source_lock);

    std::string ltype = StrLower(in_type);

    if (ltype == "proberesp") {
        proto_packet_probe_resp(in_kvmap);
    } else if (ltype == "openresp") {
        proto_packet_open_resp(in_kvmap);
    } else if (ltype == "listresp") {
        proto_packet_list_resp(in_kvmap);
    } else if (ltype == "error") {
        proto_packet_error(in_kvmap);
    } else if (ltype == "message") {
        proto_packet_message(in_kvmap);
    } else if (ltype == "configresp") {
        proto_packet_configresp(in_kvmap);
    } else if (ltype == "ping") {
        send_command_pong();
    } else if (ltype == "pong") {
        last_pong = time(0);
        // fprintf(stderr, "debug - ping - got pong %lu\n", last_pong);
    } else if (ltype == "data") {
        proto_packet_data(in_kvmap);
    }

    // We don't care about types we don't understand
}

void KisDatasource::proto_packet_probe_resp(KVmap in_kvpairs) {
    KVmap::iterator i;
    std::string msg;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        msg = handle_kv_message(i->second);
    }

    // Process channels list if we got one; this will populate our
    // channels fields automatically
    if ((i = in_kvpairs.find("channels")) != in_kvpairs.end()) {
        handle_kv_channels(i->second);
    }

    // Process single channel if we got one
    if ((i = in_kvpairs.find("chanset")) != in_kvpairs.end()) {
        handle_kv_config_channel(i->second);
    }

    // If we don't have a success record we're flat out invalid
    if ((i = in_kvpairs.find("success")) == in_kvpairs.end()) {
        trigger_error("No valid response found for probe request");
        return;
    }

    // Quiet errors display for shutdown of pipe
    quiet_errors = true;

    // Get the sequence number and look up our command
    uint32_t seq = get_kv_success_sequence(i->second);
    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        if (ci->second->probe_cb != NULL)
            ci->second->probe_cb(ci->second->transaction, 
                    get_kv_success(i->second), msg);
        // fprintf(stderr, "debug - probe resp removing command %u\n", seq);
        command_ack_map.erase(ci);
    }

}

void KisDatasource::proto_packet_open_resp(KVmap in_kvpairs) {
    KVmap::iterator i;
    KVmap::iterator successitr;
    std::string msg;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        msg = handle_kv_message(i->second);
    }

    // If we don't have a success record we're flat out invalid
    if ((successitr = in_kvpairs.find("success")) == in_kvpairs.end()) {
        trigger_error("No valid response found for open request");
        return;
    }

    // Process channels list if we got one
    if ((i = in_kvpairs.find("channels")) != in_kvpairs.end()) {
        handle_kv_channels(i->second);
    }

    // Process config list
    if ((i = in_kvpairs.find("chanset")) != in_kvpairs.end()) {
        handle_kv_config_channel(i->second);
    }

    if ((i = in_kvpairs.find("chanhop")) != in_kvpairs.end()) {
        handle_kv_config_hop(i->second);
    }

    if ((i = in_kvpairs.find("uuid")) != in_kvpairs.end()) {
        handle_kv_uuid(i->second);
    }

    if ((i = in_kvpairs.find("capif")) != in_kvpairs.end()) {
        handle_kv_capif(i->second);
    }

    if ((i = in_kvpairs.find("hardware")) != in_kvpairs.end()) {
        handle_kv_hardware(i->second);
    }

    if ((i = in_kvpairs.find("dlt")) != in_kvpairs.end()) {
        handle_kv_dlt(i->second);
    } else {
        trigger_error("No DLT found for interface");
        return;
    }

    // If we didn't get a uuid and we don't have one, make up a timestamp-based one
    if (get_source_uuid().error && !local_uuid) {
        uuid nuuid;

        nuuid.GenerateTimeUUID((uint8_t *) "\x00\x00\x00\x00\x00\x00");

        set_source_uuid(nuuid);
        set_source_key(Adler32Checksum(nuuid.UUID2String()));
    }

    // If we have a channels= option in the definition, override the
    // channels list, merge the custom channels list and the supplied channels
    // list.  Otherwise, copy the source list to the hop list.
    //
    // If we have a 'channel=' in the source definition that isn't in the list,
    // add it.
    //
    // If we have a 'add_channels=' in the source, use the provided list + that
    // for hop, 

    TrackerElementVector source_chan_vec(get_int_source_channels_vec());
    TrackerElementVector hop_chan_vec(get_int_source_hop_vec());

    hop_chan_vec.clear();

    std::string def_chan = get_definition_opt("channel");
    if (def_chan != "") {
        bool append = true;
        for (auto sci : source_chan_vec) {
            if (strcasecmp(GetTrackerValue<std::string>(sci).c_str(), def_chan.c_str()) == 0) {
                append = false;
                break;
            }
        }

        if (append) {
            SharedTrackerElement dce(new TrackerElement(TrackerString));
            dce->set(def_chan);
            source_chan_vec.push_back(dce);
        }
    }

    std::vector<std::string> def_vec = StrTokenize(get_definition_opt("channels"), ",");
    std::vector<std::string> add_vec = StrTokenize(get_definition_opt("add_channels"), ",");

    if (def_vec.size() != 0) {
        for (auto dc : def_vec) {
            SharedTrackerElement dce(new TrackerElement(TrackerString));
            dce->set(dc);

            hop_chan_vec.push_back(dce);

            bool append = true;
            for (auto sci : source_chan_vec) {
                if (strcasecmp(GetTrackerValue<std::string>(sci).c_str(), dc.c_str()) == 0) {
                    append = false;
                    break;
                }
            }
            
            if (append) {
                source_chan_vec.push_back(dce);
            }
        }
    } else if (add_vec.size() != 0) {
        // Add all our existing channels
        for (auto c = source_chan_vec.begin(); c != source_chan_vec.end(); ++c) {
            hop_chan_vec.push_back(*c);
        }

        for (auto ac : add_vec) {
            // Add any new channels from the add_vec
            bool append = true;
            for (auto sci : source_chan_vec) {
                if (strcasecmp(GetTrackerValue<std::string>(sci).c_str(), ac.c_str()) == 0) {
                    append = false;
                    break;
                }
            }
            
            if (append) {
                SharedTrackerElement ace(new TrackerElement(TrackerString));
                ace->set(ac);

                hop_chan_vec.push_back(ace);

                source_chan_vec.push_back(ace);
            }
        }

    } else {
        for (auto c = source_chan_vec.begin(); c != source_chan_vec.end(); ++c) {
            hop_chan_vec.push_back(*c);
        }
    }

    if (get_kv_success(i->second)) {
        set_int_source_retry_attempts(0);
    }

    set_int_source_running(get_kv_success(successitr->second));
    set_int_source_error(get_kv_success(successitr->second) == 0);

    // Get the sequence number and look up our command
    uint32_t seq = get_kv_success_sequence(successitr->second);
    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        if (ci->second->open_cb != NULL)
            ci->second->open_cb(ci->second->transaction, get_source_running(), msg);
        command_ack_map.erase(ci);
    }

    // If the open failed, kill the source
    if (!get_source_running()) {
        trigger_error(msg);
        set_int_source_error_reason(msg);
        return;
    }

    last_pong = time(0);

    // If we got here we're valid; start a PING timer
    if (ping_timer_id <= 0) {
        ping_timer_id = timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL,
                1, [this](int) -> int {
            local_locker lock(&source_lock);
            
            if (!get_source_running()) {
                ping_timer_id = -1;
                return 0;
            }
           
            send_command_ping();
            return 1;
        });
    }
}

void KisDatasource::proto_packet_list_resp(KVmap in_kvpairs) {
    KVmap::iterator i;
    std::string msg;

    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        msg = handle_kv_message(i->second);
    }

    if ((i = in_kvpairs.find("interfacelist")) != in_kvpairs.end()) {
        handle_kv_interfacelist(i->second);
    }

    // If we don't have a success record we're flat out invalid
    if ((i = in_kvpairs.find("success")) == in_kvpairs.end()) {
        trigger_error("No valid response found for list request");
        return;
    }

    // Quiet errors display for shutdown of pipe
    quiet_errors = true;

    // Get the sequence number and look up our command
    uint32_t seq = get_kv_success_sequence(i->second);
    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        // fprintf(stderr, "debug - erasingcommand ack from list %u\n", seq);
        if (ci->second->list_cb != NULL)
            ci->second->list_cb(ci->second->transaction, listed_interfaces);
        command_ack_map.erase(ci);
    }
}

void KisDatasource::proto_packet_error(KVmap in_kvpairs) {
    KVmap::iterator i;

    std::string fail_reason = "Received error frame on data source";

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        fail_reason = handle_kv_message(i->second);
    }

    trigger_error(fail_reason);
}

void KisDatasource::proto_packet_message(KVmap in_kvpairs) {
    KVmap::iterator i;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    if ((i = in_kvpairs.find("warning")) != in_kvpairs.end()) {
        handle_kv_warning(i->second);
    }
}

void KisDatasource::proto_packet_configresp(KVmap in_kvpairs) {
    KVmap::iterator i;
    std::string msg;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        msg = handle_kv_message(i->second);
    }

    if ((i = in_kvpairs.find("warning")) != in_kvpairs.end()) {
        handle_kv_warning(i->second);
    }

    // Process config list
    if ((i = in_kvpairs.find("chanset")) != in_kvpairs.end()) {
        handle_kv_config_channel(i->second);
    }

    if ((i = in_kvpairs.find("chanhop")) != in_kvpairs.end()) {
        handle_kv_config_hop(i->second);
    }

    // If we don't have a success record we're flat out invalid
    if ((i = in_kvpairs.find("success")) == in_kvpairs.end()) {
        trigger_error("No valid response found for config request");
        return;
    }

    // Get the sequence number and look up our command
    uint32_t seq = get_kv_success_sequence(i->second);
    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        // fprintf(stderr, "debug - erasing command ack from configure %u\n", seq);
        if (ci->second->configure_cb != NULL)
            ci->second->configure_cb(seq, get_kv_success(i->second), msg);
        command_ack_map.erase(ci);
    }

    if (!get_kv_success(i->second)) {
        trigger_error(msg);
        set_int_source_error_reason(msg);
    }
}

void KisDatasource::proto_packet_data(KVmap in_kvpairs) {
    // If we're paused, do nothing
    {
        local_locker lock(&source_lock);

        if (get_source_paused())
            return;
    }

    KVmap::iterator i;

    kis_packet *packet = NULL;
    kis_layer1_packinfo *siginfo = NULL;
    kis_gps_packinfo *gpsinfo = NULL;

    // Process any messages
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    if ((i = in_kvpairs.find("warning")) != in_kvpairs.end()) {
        handle_kv_warning(i->second);
    }

    // Do we have a packet?
    if ((i = in_kvpairs.find("packet")) != in_kvpairs.end()) {
        packet = handle_kv_packet(i->second);
    }

    if (packet == NULL) {
        return;
    }

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

    packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
    datasrcinfo->ref_source = this;

    packet->insert(pack_comp_datasrc, datasrcinfo);

    inc_source_num_packets(1);
    get_source_packet_rrd()->add_sample(1, time(0));

    // Inject the packet into the packetchain if we have one
    packetchain->ProcessPacket(packet);

}

bool KisDatasource::get_kv_success(KisDatasourceCapKeyedObject *in_obj) {
    if (in_obj->size != sizeof(simple_cap_proto_success_value)) {
        return false;
    }

    simple_cap_proto_success_t *status = (simple_cap_proto_success_t *) in_obj->object;

    return status->success;
}

uint32_t KisDatasource::get_kv_success_sequence(KisDatasourceCapKeyedObject *in_obj) {
    if (in_obj->size != sizeof(simple_cap_proto_success_value)) {
        return 0;
    }

    simple_cap_proto_success_t *status = (simple_cap_proto_success_t *) in_obj->object;
    uint32_t seqno = kis_ntoh32(status->sequence_number);

    return seqno;
}

std::string KisDatasource::handle_kv_message(KisDatasourceCapKeyedObject *in_obj) {
    // Unpack the dictionary
    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;
    std::vector<std::string> channel_vec;
    std::string msg;

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size); 
        msgpack::object deserialized = result.get();
        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        unsigned int flags;

        if ((obj_iter = dict.find("msg")) != dict.end()) {
            msg = obj_iter->second.as<std::string>();
        } else {
            throw std::runtime_error("missing 'msg' entry");
        }

        if ((obj_iter = dict.find("flags")) != dict.end()) {
            flags = obj_iter->second.as<unsigned int>();
        } else {
            throw std::runtime_error("missing 'flags' entry");
        }

        _MSG(get_source_name() + " - " + msg, flags);

    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        std::stringstream ss;
        ss << "failed to unpack message bundle: " << e.what();

        trigger_error(ss.str());

        return ss.str();
    }

    return msg;
}

void KisDatasource::handle_kv_channels(KisDatasourceCapKeyedObject *in_obj) {
    // Extracts the keyed value from a msgpack dictionary, turns it into
    // a string vector, then clears our local channel list and populates it with
    // the new data sent to us; this lets us inherit the channel list
    // as a whole

    // Unpack the dictionary
    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;
    std::vector<std::string> channel_vec;

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size);
        msgpack::object deserialized = result.get();
        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        if ((obj_iter = dict.find("channels")) != dict.end()) {
            MsgpackAdapter::AsStringVector(obj_iter->second, channel_vec);

            // We now have a string vector of channels, dupe it into our 
            // tracked channels vec
            local_locker lock(&source_lock);

            TrackerElementVector chan_vec(get_int_source_channels_vec());
            chan_vec.clear();

            for (unsigned int x = 0; x < channel_vec.size(); x++) {
                SharedTrackerElement chanstr = 
                    channel_entry_builder->clone_type();
                chanstr->set(channel_vec[x]);
                chan_vec.push_back(chanstr);
            }
        }
    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        std::stringstream ss;
        ss << "failed to unpack proberesp channels bundle: " << e.what();

        trigger_error(ss.str());

        return;
    }

    return;
}

kis_layer1_packinfo *KisDatasource::handle_kv_signal(KisDatasourceCapKeyedObject *in_obj) {
    // Extract l1 info from a KV pair so we can add it to a packet
    
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
            siginfo->channel = obj_iter->second.as<std::string>();
        }

        if ((obj_iter = dict.find("datarate")) != dict.end()) {
            siginfo->datarate = obj_iter->second.as<double>();
        }

    } catch (const std::exception& e) {
        delete(siginfo);

        // Something went wrong with msgpack unpacking
        std::stringstream ss;
        ss << "failed to unpack gps bundle: " << e.what();

        trigger_error(ss.str());
        return NULL;
    }

    return siginfo;
}

kis_gps_packinfo *KisDatasource::handle_kv_gps(KisDatasourceCapKeyedObject *in_obj) {
    // Extract a GPS record from a packet and turn it into a packinfo gps log
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
            gpsinfo->tv.tv_sec = (time_t) obj_iter->second.as<uint64_t>();
            gpsinfo->tv.tv_usec = 0;
        }

        /*
        if ((obj_iter = dict.find("name")) != dict.end()) {
            gpsinfo->gpsname = obj_iter->second.as<string>();
        }
        */

    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        delete(gpsinfo);
        std::stringstream ss;
        ss << "failed to unpack gps bundle: " << e.what();

        trigger_error(ss.str());

        return NULL;
    }

    return gpsinfo;
}

kis_packet *KisDatasource::handle_kv_packet(KisDatasourceCapKeyedObject *in_obj) {
    // Extract a packet record
    
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

        if (clobber_timestamp && get_source_remote()) {
            gettimeofday(&(packet->ts), NULL);
        } else {
            if ((obj_iter = dict.find("tv_sec")) != dict.end()) {
                packet->ts.tv_sec = (time_t) obj_iter->second.as<uint64_t>();
            } else {
                throw std::runtime_error(std::string("tv_sec timestamp missing"));
            }

            if ((obj_iter = dict.find("tv_usec")) != dict.end()) {
                packet->ts.tv_usec = (time_t) obj_iter->second.as<uint64_t>();
            } else {
                throw std::runtime_error(std::string("tv_usec timestamp missing"));
            }
        }

        // Record the size
        uint64_t size = 0;
        if ((obj_iter = dict.find("size")) != dict.end()) {
            size = obj_iter->second.as<uint64_t>();
        } else {
            throw std::runtime_error(std::string("size field missing or zero"));
        }

        msgpack::object rawdata;
        if ((obj_iter = dict.find("packet")) != dict.end()) {
            rawdata = obj_iter->second;
        } else {
            throw std::runtime_error(std::string("packet data missing"));
        }

        if (rawdata.via.bin.size != size) {
            throw std::runtime_error(std::string("packet size did not match data size"));
        }

        datachunk->copy_data((const uint8_t *) rawdata.via.bin.ptr, size);

    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        //
        // Destroy the packet appropriately
        packetchain->DestroyPacket(packet);
        // Always delete the datachunk, we don't insert it into the packet
        // until later
        delete(datachunk);

        std::stringstream ss;
        ss << "failed to unpack packet bundle: " << e.what();

        trigger_error(ss.str());

        return NULL;
    }

    datachunk->dlt = get_source_dlt();

    packet->insert(pack_comp_linkframe, datachunk);

    return packet;
}

void KisDatasource::handle_kv_uuid(KisDatasourceCapKeyedObject *in_obj) {
    uuid parsed_uuid(std::string(in_obj->object, in_obj->size));

    if (parsed_uuid.error) {
        trigger_error("unable to parse UUID");
        return;
    }

    // Only set the local UUID if we don't define one in the sourceline
    if (!local_uuid) {
        set_source_uuid(parsed_uuid);
        set_source_key(Adler32Checksum(parsed_uuid.UUID2String()));
    }
}

void KisDatasource::handle_kv_capif(KisDatasourceCapKeyedObject *in_obj) {
    set_int_source_cap_interface(std::string(in_obj->object, in_obj->size));
}

std::string KisDatasource::handle_kv_warning(KisDatasourceCapKeyedObject *in_obj) {
    // Stupid simple
    set_int_source_warning(MungeToPrintable(std::string(in_obj->object, in_obj->size)));
    return (std::string(in_obj->object, in_obj->size));
}

void KisDatasource::handle_kv_config_channel(KisDatasourceCapKeyedObject *in_obj) {
    // Very simple - we just copy the channel string over
    set_int_source_hopping(false);
    set_int_source_channel(std::string(in_obj->object, in_obj->size));
}

void KisDatasource::handle_kv_hardware(KisDatasourceCapKeyedObject *in_obj) {
    set_int_source_hardware(MungeToPrintable(std::string(in_obj->object, in_obj->size)));
}

void KisDatasource::handle_kv_config_hop(KisDatasourceCapKeyedObject *in_obj) {
    // Unpack the dictionary
    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;
    std::vector<std::string> channel_vec;

    std::vector<std::string> blocked_channel_vec;

    // Get any channels we mask out from the source definition
    blocked_channel_vec = StrTokenize(get_definition_opt("blockedchannels"), ",");

    std::string blocked_msg_list = "";

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size);
        msgpack::object deserialized = result.get();
        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        if ((obj_iter = dict.find("channels")) != dict.end()) {
            MsgpackAdapter::AsStringVector(obj_iter->second, channel_vec);

            // We now have a string vector of channels, dupe it into our 
            // tracked channels vec
            local_locker lock(&source_lock);

            TrackerElementVector hop_chan_vec(get_int_source_hop_vec());
            hop_chan_vec.clear();

            for (unsigned int x = 0; x < channel_vec.size(); x++) {
                // Skip blocked channels - we know they cause the source
                // problems for some reason
                bool skip = false;
                for (unsigned int z = 0; z < blocked_channel_vec.size(); z++) {
                    if (StrLower(channel_vec[x]) == StrLower(blocked_channel_vec[z])) {
                        if (blocked_msg_list.length() != 0)
                            blocked_msg_list += ",";
                        blocked_msg_list += channel_vec[x];

                        skip = true;
                        break;
                    }
                }

                if (skip)
                    continue;
                
                SharedTrackerElement chanstr = 
                    channel_entry_builder->clone_type();
                chanstr->set(channel_vec[x]);
                hop_chan_vec.push_back(chanstr);
            }

            if (blocked_msg_list.length() != 0) {
                _MSG("Source '" + get_source_name() + "' ignoring channels '" +
                        blocked_msg_list + "'", MSGFLAG_INFO);
            }
        } else {
            throw std::runtime_error(std::string("channel list missing in hop config"));
        }

        if ((obj_iter = dict.find("rate")) != dict.end()) {
            set_int_source_hop_rate(obj_iter->second.as<double>());
        } else {
            throw std::runtime_error(std::string("rate missing in hop config"));
        }

        set_int_source_hopping(true);

        // Grab the shuffle and offset if we have them
        if ((obj_iter = dict.find("shuffle")) != dict.end()) {
            set_int_source_hop_shuffle(obj_iter->second.as<uint8_t>());
        }

        if ((obj_iter = dict.find("offset")) != dict.end()) {
            set_int_source_hop_offset(obj_iter->second.as<uint32_t>());
        }

        if ((obj_iter = dict.find("shuffle_skip")) != dict.end()) {
            set_int_source_hop_shuffle_skip(obj_iter->second.as<uint32_t>());
        }

    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        std::stringstream ss;
        ss << "failed to unpack hop config bundle: " << e.what();
        trigger_error(ss.str());

        return;
    }
}

void KisDatasource::handle_kv_interfacelist(KisDatasourceCapKeyedObject *in_obj) {
    // Clears the list of interfaces, then extracts the array of new interfaces
    // from the packet
   
    listed_interfaces.clear();

    // Unpack the dictionary
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap dict;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;
    std::vector<std::string> channel_vec;

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size);
        msgpack::object deserialized = result.get();

        // we expect an array of msgpack dicts, so turn it into an array
        for (unsigned int i = 0; i < deserialized.via.array.size; i++) {
            // Then turn it into a string map
            dict = deserialized.via.array.ptr[i].as<MsgpackAdapter::MsgpackStrMap>();

            // Our extracted values
            std::string interface;
            std::string opts;

            // Interface is mandatory, flags are not
            if ((obj_iter = dict.find("interface")) != dict.end()) {
                interface = obj_iter->second.as<std::string>();
            } else {
                throw std::runtime_error(std::string("interface missing in list response"));
            }

            if ((obj_iter = dict.find("flags")) != dict.end()) {
                opts = obj_iter->second.as<std::string>();
            }

            SharedInterface intf = static_pointer_cast<KisDatasourceInterface>(listed_interface_builder->clone_type());
            intf->populate(interface, opts);
            intf->set_prototype(get_source_builder());

            if ((obj_iter = dict.find("hardware")) != dict.end()) {
                intf->set_hardware(obj_iter->second.as<std::string>());
            }

            {
                local_locker lock(&source_lock);
                listed_interfaces.push_back(intf);
            }

        }
    } catch (const std::exception& e) {
        // Something went wrong with msgpack unpacking
        std::stringstream ss;
        ss << "failed to unpack interface list bundle: " << e.what();

        trigger_error(ss.str());

        return;
    }

    return;
}

unsigned int KisDatasource::handle_kv_dlt(KisDatasourceCapKeyedObject *in_obj) {
    uint32_t *dlt;

    if (in_obj->size != sizeof(uint32_t)) {
        trigger_error("Invalid DLT object in response");
        return 0;
    }

    dlt = (uint32_t *) in_obj->object;

    set_int_source_dlt(kis_ntoh32(*dlt));

    return *dlt;
}

bool KisDatasource::write_packet(std::string in_cmd, KVmap in_kvpairs,
        uint32_t &ret_seqno) {
    local_locker lock(&source_lock);
    // Generate a packet and put it in the buffer
    
    if (ringbuf_handler == NULL)
        return false;

    simple_cap_proto_t proto_hdr;

    uint32_t hcsum, dcsum = 0, csum_s1 = 0, csum_s2 = 0;

    size_t total_len = sizeof(simple_cap_proto_t);

    // Add up the length of all of the kv pairs
    for (auto i = in_kvpairs.begin(); i != in_kvpairs.end(); ++i) {
        total_len += sizeof(simple_cap_proto_kv_h_t) + i->second->size;
    }

    proto_hdr.signature = kis_hton32(KIS_CAP_SIMPLE_PROTO_SIG);
    proto_hdr.header_checksum = 0;
    proto_hdr.data_checksum = 0;
    proto_hdr.packet_sz = kis_hton32(total_len);

    proto_hdr.sequence_number = kis_hton32(next_cmd_sequence);
    ret_seqno = next_cmd_sequence;
    next_cmd_sequence++;

    snprintf(proto_hdr.type, 16, "%s", in_cmd.c_str());

    proto_hdr.num_kv_pairs = kis_hton32(in_kvpairs.size());

    // Start calculating the checksum on just the header
    hcsum = Adler32IncrementalChecksum((const char *) &proto_hdr, 
            sizeof(simple_cap_proto_t), &csum_s1, &csum_s2);
    

    // Calc the checksum of all the kv pairs
    for (auto i = in_kvpairs.begin(); i != in_kvpairs.end(); ++i) {
        dcsum = Adler32IncrementalChecksum((const char *) i->second->kv,
                sizeof(simple_cap_proto_kv_h_t) + i->second->size,
                &csum_s1, &csum_s2);
    }

    if (in_kvpairs.size() == 0)
        dcsum = hcsum;

    proto_hdr.header_checksum = kis_hton32(hcsum);
    proto_hdr.data_checksum = kis_hton32(dcsum);

    if (ringbuf_handler->PutWriteBufferData(&proto_hdr, 
                sizeof(simple_cap_proto_t), true) == 0)
        return false;

    for (auto i = in_kvpairs.begin(); i != in_kvpairs.end(); ++i) {
        if (ringbuf_handler->PutWriteBufferData(i->second->kv,
                    sizeof(simple_cap_proto_kv_h_t) + i->second->size, true) == 0)
            return false;
    }

    return true;
}

void KisDatasource::send_command_list_interfaces(unsigned int in_transaction,
        list_callback_t in_cb) {
    local_locker lock(&source_lock);

    KVmap kvmap;

    // Nothing to fill in for the kvmap for a list request

    uint32_t seqno;
    bool success;
    shared_ptr<tracked_command> cmd;

    success = write_packet("LISTINTERFACES", kvmap, seqno);

    if (!success) {
        if (in_cb != NULL) {
            in_cb(in_transaction, std::vector<SharedInterface>());
        }

        return;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->list_cb = in_cb;
    
    command_ack_map.emplace(seqno, cmd);
}

void KisDatasource::send_command_probe_interface(std::string in_definition, 
        unsigned int in_transaction, probe_callback_t in_cb) {
    local_locker lock(&source_lock);

    KVmap kvmap;

    KisDatasourceCapKeyedObject *definition =
        new KisDatasourceCapKeyedObject("DEFINITION", in_definition.data(), 
                in_definition.length());
    kvmap.emplace("DEFINITION", definition);

    uint32_t seqno;
    bool success;
    shared_ptr<tracked_command> cmd;

    success = write_packet("PROBEDEVICE", kvmap, seqno);

    delete(definition);

    if (!success) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "unable to generate command frame");
        }

        return;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->probe_cb = in_cb;

    command_ack_map.emplace(seqno, cmd);
}


void KisDatasource::send_command_open_interface(std::string in_definition,
        unsigned int in_transaction, open_callback_t in_cb) {
    local_locker lock(&source_lock);

    KisDatasourceCapKeyedObject *definition =
        new KisDatasourceCapKeyedObject("DEFINITION", in_definition.data(), 
                in_definition.length());

    KVmap kvmap;
    kvmap.emplace("DEFINITION", definition);

    uint32_t seqno;
    bool success;
    shared_ptr<tracked_command> cmd;

    success = write_packet("OPENDEVICE", kvmap, seqno);

    delete(definition);

    if (!success) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "unable to generate command frame");
        }

        return;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->open_cb = in_cb;

    command_ack_map.emplace(seqno, cmd);
}

void KisDatasource::send_command_set_channel(std::string in_channel, 
        unsigned int in_transaction, configure_callback_t in_cb) {
    local_locker lock(&source_lock);

    KisDatasourceCapKeyedObject *chanset =
        new KisDatasourceCapKeyedObject("CHANSET", in_channel.data(),
                in_channel.length());
    KVmap kvmap;

    kvmap.emplace("CHANSET", chanset);

    uint32_t seqno;
    bool success;
    shared_ptr<tracked_command> cmd;

    success = write_packet("CONFIGURE", kvmap, seqno);

    delete(chanset);

    if (!success) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "unable to generate command frame");
        }

        return;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->configure_cb = in_cb;

    command_ack_map.emplace(seqno, cmd);
}

void KisDatasource::send_command_set_channel_hop(double in_rate, 
        SharedTrackerElement in_chans, bool in_shuffle, unsigned int in_offt,
        unsigned int in_transaction,
        configure_callback_t in_cb) {

    // This is one of the more complex commands - we have to generate a 
    // command dictionary containing a rate:double and a channels:vector
    // structure; fortunately msgpack makes this easy for us.

    local_locker lock(&source_lock);

    TrackerElementVector in_vec(in_chans);

    // Pack the vector into a string stream using the msgpack api
    std::stringstream stream;
    msgpack::packer<std::stringstream> packer(&stream);

    // 4-element dictionary
    packer.pack_map(4);

    // Pack the rate dictionary entry
    packer.pack(std::string("rate"));
    packer.pack(in_rate);

    // Pack the shuffle
    packer.pack(std::string("shuffle"));
    packer.pack((uint8_t) in_shuffle);

    // Pack the offset
    packer.pack(std::string("offset"));
    packer.pack((uint32_t) in_offt);

    // Pack the vector of channels
    packer.pack(std::string("channels"));
    packer.pack_array(in_vec.size());

    for (auto i = in_vec.begin(); i != in_vec.end(); ++i) {
        packer.pack((*i)->get_string());
    }

    KisDatasourceCapKeyedObject *chanhop =
        new KisDatasourceCapKeyedObject("CHANHOP", stream.str().data(),
                stream.str().length());
    KVmap kvmap;

    kvmap.emplace("CHANHOP", chanhop);

    uint32_t seqno;
    bool success;
    shared_ptr<tracked_command> cmd;

    success = write_packet("CONFIGURE", kvmap, seqno);

    delete(chanhop);

    if (!success) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "unable to generate command frame");
        }

        return;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->configure_cb = in_cb;

    command_ack_map.emplace(seqno, cmd);
}

void KisDatasource::send_command_ping() {
    local_locker lock(&source_lock);

    KVmap kvmap;

    // Nothing to fill in for the kvmap for a list request

    uint32_t seqno;
    write_packet("PING", kvmap, seqno);
}

void KisDatasource::send_command_pong() {
    local_locker lock(&source_lock);

    KVmap kvmap;

    // Nothing to fill in for the kvmap for a list request

    uint32_t seqno;
    write_packet("PONG", kvmap, seqno);
}

void KisDatasource::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.datasource.source_number", TrackerUInt64,
            "internal source number per Kismet instance",
            &source_number);
    RegisterField("kismet.datasource.source_key", TrackerUInt32,
            "hashed UUID key", &source_key);

    RegisterField("kismet.datasource.paused", TrackerUInt8,
            "capture is paused (no packets will be processed from this source)", &source_paused);

    RegisterField("kismet.datasource.ipc_binary", TrackerString,
            "capture command", &source_ipc_binary);
    RegisterField("kismet.datasource.ipc_pid", TrackerInt64,
            "capture process", &source_ipc_pid);

    RegisterField("kismet.datasource.running", TrackerUInt8,
            "capture is running", &source_running);

    RegisterField("kismet.datasource.remote", TrackerUInt8,
            "capture is connected from a remote server", &source_remote);

    RegisterField("kismet.datasource.passive", TrackerUInt8,
            "capture is a post-able passive capture", &source_passive);

    RegisterField("kismet.datasource.name", TrackerString,
            "Human-readable name", &source_name);
    RegisterField("kismet.datasource.uuid", TrackerUuid,
            "UUID", &source_uuid);

    RegisterField("kismet.datasource.definition", TrackerString,
            "Original source= definition", &source_definition);
    RegisterField("kismet.datasource.interface", TrackerString,
            "Interface", &source_interface);
    RegisterField("kismet.datasource.capture_interface", TrackerString,
            "Interface", &source_cap_interface);
    RegisterField("kismet.datasource.hardware", TrackerString,
            "Hardware / chipset", &source_hardware);

    RegisterField("kismet.datasource.dlt", TrackerUInt32,
            "DLT (link type)", &source_dlt);

    RegisterField("kismet.datasource.warning", TrackerString,
            "Warning or unusual interface state", &source_warning);

    channel_entry_builder.reset(new TrackerElement(TrackerString, 0));
    RegisterComplexField("kismet.datasource.channel_entry",
            channel_entry_builder, "Channel");

    RegisterField("kismet.datasource.channels", TrackerVector,
            "Supported channels", &source_channels_vec);
    RegisterField("kismet.datasource.hopping", TrackerUInt8,
            "Source is channel hopping", &source_hopping);
    RegisterField("kismet.datasource.channel", TrackerString,
            "Current channel", &source_channel);
    RegisterField("kismet.datasource.hop_rate", TrackerDouble,
            "Hop rate if channel hopping", &source_hop_rate);
    RegisterField("kismet.datasource.hop_channels", TrackerVector,
            "Hop pattern if hopping", &source_hop_vec);
    RegisterField("kismet.datasource.hop_split", TrackerUInt8,
            "Split hopping among same type interfaces", &source_hop_split);
    RegisterField("kismet.datasource.hop_offset", TrackerUInt32,
            "Offset into hopping list for multiple sources", &source_hop_offset);
    RegisterField("kismet.datasource.hop_shuffle", TrackerUInt8,
            "Shuffle channels while hopping", &source_hop_shuffle);
    RegisterField("kismet.datasource.hop_shuffle_skip", TrackerUInt32,
            "Number of channels skipped by source during hop shuffling", 
            &source_hop_shuffle_skip);

    RegisterField("kismet.datasource.error", TrackerUInt8,
            "Source is in error state", &source_error);
    RegisterField("kismet.datasource.error_reason", TrackerString,
            "Last known reason for error state", &source_error_reason);

    RegisterField("kismet.datasource.num_packets", TrackerUInt64,
            "Number of packets seen by source", &source_num_packets);
    RegisterField("kismet.datasource.num_error_packets", TrackerUInt64,
            "Number of invalid/error packets seen by source",
            &source_num_error_packets);

    packet_rate_rrd_id = RegisterComplexField("kismet.datasource.packets_rrd", 
            shared_ptr<kis_tracked_minute_rrd<> >(new kis_tracked_minute_rrd<>(globalreg, 0)), 
            "packet rate over past minute");

    RegisterField("kismet.datasource.retry", TrackerUInt8,
            "Source will try to re-open after failure", &source_retry);
    RegisterField("kismet.datasource.retry_attempts", TrackerUInt32,
            "Consecutive unsuccessful retry attempts", &source_retry_attempts);
    RegisterField("kismet.datasource.total_retry_attempts", TrackerUInt32,
            "Total unsuccessful retry attempts", &source_total_retry_attempts);
}

void KisDatasource::reserve_fields(SharedTrackerElement e) {
    tracker_component::reserve_fields(e);

    // We don't ever instantiate from an existing object so we don't do anything
}

void KisDatasource::handle_source_error() {
    local_locker lock(&source_lock);

    // If we're probing or listing we don't do any special handling
    if (mode_listing || mode_probing)
        return;

    std::stringstream ss;

    // Do nothing if we don't handle retry
    if (get_source_remote()) {
        if (get_source_running()) {
            ss << "Source " << get_source_name() << " has encountered an error.  "
                "Remote sources are not locally reconnected; waiting for the remote source "
                "to reconnect to resume capture.";

            shared_ptr<Alertracker> alertracker =
                Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
            alertracker->RaiseOneShot("SOURCEERROR", ss.str(), -1);

            _MSG(ss.str(), MSGFLAG_ERROR);
        }

        if (ping_timer_id > 0) {
            timetracker->RemoveTimer(ping_timer_id);
            ping_timer_id = -1;
        }

        set_int_source_running(false);
        return;
    }

    if (!get_source_retry()) {
        if (get_source_running()) {
            ss << "Source " << get_source_name() << " has encountered an error but "
                "is not configured to automatically re-try opening; it will remain "
                "closed.";

            shared_ptr<Alertracker> alertracker =
                Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
            alertracker->RaiseOneShot("SOURCEERROR", ss.str(), -1);

            _MSG(ss.str(), MSGFLAG_ERROR);
        }

        if (ping_timer_id > 0) {
            timetracker->RemoveTimer(ping_timer_id);
            ping_timer_id = -1;
        }

        set_int_source_running(false);

        return;
    }
    
    if (ping_timer_id > 0) {
        timetracker->RemoveTimer(ping_timer_id);
        ping_timer_id = -1;
    }

    set_int_source_running(false);

    // If we already have an error timer, we're thinking about restarting, 
    // be quiet about things; otherwise, talk about restarting, increment the
    // count, and set a timer
    if (error_timer_id <= 0) {

        // Increment our failures
        inc_int_source_retry_attempts(1);
        inc_int_source_total_retry_attempts(1);

        // Notify about it
        ss << "Source " << get_source_name() << " has encountered an error. "
            "Kismet will attempt to re-open the source in 5 seconds.  (" <<
            get_source_retry_attempts() << " failures)";

        shared_ptr<Alertracker> alertracker =
            Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
        alertracker->RaiseOneShot("SOURCEERROR", ss.str(), -1);

        _MSG(ss.str(), MSGFLAG_ERROR);

        // Set a new event to try to re-open the interface
        error_timer_id = timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5,
                NULL, 0, [this](int) -> int {
                local_locker lock(&source_lock);

                error_timer_id = 0;

                _MSG("Attempting to re-open source " + get_source_name(), MSGFLAG_INFO);

                // Call open on the same sourceline, no transaction, no cb
                open_interface(get_source_definition(), 0, 
                        [this](int, bool success, std::string) {
                            if (!success)
                                return;

                            std::stringstream ss;

                            ss << "Source " << get_source_name() << " successfully "
                                "re-opened";

                            shared_ptr<Alertracker> alertracker =
                                Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
                            alertracker->RaiseOneShot("SOURCEOPEN", ss.str(), -1);

                            if (get_source_hopping()) {
                                // Reset the channel hop if we're hopping
                                set_channel_hop(get_source_hop_rate(),
                                        get_source_hop_vec(),
                                        get_source_hop_shuffle(),
                                        get_source_hop_offset(),
                                        0, NULL);
                            } else if (get_source_channel() != "") {
                                // Reset the fixed channel if we have one
                                set_channel(get_source_channel(), 0, NULL);
                            }
                        });

                    return 0;
                });
    } else {
        // fprintf(stderr, "debug - source error but we think a timer is already running\n");
    }
}

void KisDatasource::launch_ipc() {
    local_locker lock(&source_lock);

    std::stringstream ss;

    if (get_source_ipc_binary() == "") {
        ss << "missing IPC binary name, cannot launch capture tool";
        trigger_error(ss.str());
        return;
    }

    // Kill the running process if we have one
    if (ipc_remote != NULL) {
        ss.str("");
        ss << "Datasource '" << get_source_name() << "' launching IPC with a running "
            "process, killing existing process pid " << get_source_ipc_pid();
        _MSG(ss.str(), MSGFLAG_INFO);

        ipc_remote->soft_kill();
    }

    set_int_source_ipc_pid(-1);

    // Make a new handler and new ipc.  Give a generous buffer.
    ringbuf_handler.reset(new BufferHandler<RingbufV2>((1024 * 1024), (1024 * 1024)));
    ringbuf_handler->SetReadBufferInterface(this);

    ipc_remote.reset(new IPCRemoteV2(globalreg, ringbuf_handler));

    // Get allowed paths for binaries
    std::vector<std::string> bin_paths = 
        globalreg->kismet_config->FetchOptVec("capture_binary_path");

    // Explode any expansion macros in the path and add it to the list we search
    for (auto i = bin_paths.begin(); i != bin_paths.end(); ++i) {
        ipc_remote->add_path(globalreg->kismet_config->ExpandLogPath(*i, "", "", 0, 1));
    }

    int ret = ipc_remote->launch_kis_binary(get_source_ipc_binary(), ipc_binary_args);

    if (ret < 0) {
        ss.str("");
        ss << "failed to launch IPC binary '" << get_source_ipc_binary() << "'";
        trigger_error(ss.str());
        return;
    }

    set_int_source_ipc_pid(ipc_remote->get_pid());

    return;
}

KisDatasourceCapKeyedObject::KisDatasourceCapKeyedObject(simple_cap_proto_kv *in_kp) {
    char ckey[16];

    kv = in_kp;

    snprintf(ckey, 16, "%s", in_kp->header.key);
    key = std::string(ckey);

    size = kis_ntoh32(in_kp->header.obj_sz);
    object = (char *) kv->object;

    allocated = false;
}

KisDatasourceCapKeyedObject::KisDatasourceCapKeyedObject(std::string in_key,
        const char *in_object, ssize_t in_len) {
    // Clone the object into a kv header for easier transmission assembly
    
    allocated = true;
    kv = (simple_cap_proto_kv_t *) 
        new uint8_t[in_len + sizeof(simple_cap_proto_kv_h_t)];

    kv->header.obj_sz = kis_hton32(in_len);
    size = in_len;

    snprintf(kv->header.key, 16, "%s", in_key.c_str());
    key = in_key.substr(0, 16);

    memcpy(kv->object, in_object, in_len);
    object = (char *) kv->object;

}

KisDatasourceCapKeyedObject::~KisDatasourceCapKeyedObject() {
    if (allocated)
        delete[] kv;
}


