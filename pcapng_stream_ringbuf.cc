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

#include "pcapng_stream_ringbuf.h"

Pcap_Stream_Ringbuf::Pcap_Stream_Ringbuf(GlobalRegistry *in_globalreg,
        std::shared_ptr<BufferHandlerGeneric> in_handler,
        std::function<bool (kis_packet *)> accept_filter,
        std::function<kis_datachunk * (kis_packet *)> data_selector,
        bool block_for_buffer) : 
    streaming_agent(),
    globalreg {in_globalreg},
    handler {in_handler},
    accept_cb {accept_filter},
    selector_cb {data_selector},
    block_for_buffer {block_for_buffer},
    locker_required_bytes {0} {

    packetchain = 
        std::static_pointer_cast<Packetchain>(globalreg->FetchGlobal("PACKETCHAIN"));

    pack_comp_linkframe = packetchain->RegisterPacketComponent("LINKFRAME");
    pack_comp_datasrc = packetchain->RegisterPacketComponent("KISDATASRC");

    // Set the buffer locker
    if (block_for_buffer) {
        handler->SetReadBufferDrainCb([this](size_t) {
            local_locker l(&required_bytes_mutex);
            if (locker_required_bytes != 0 && handler->GetWriteBufferAvailable() > locker_required_bytes) {
                buffer_available_locker.unlock(1);
                locker_required_bytes = 0;
            }
        });
    }

    // Write the initial headers
    if (pcapng_make_shb("", "", "Kismet") < 0)
        return;

}

Pcap_Stream_Ringbuf::~Pcap_Stream_Ringbuf() {
    handler->ProtocolError();
}

int Pcap_Stream_Ringbuf::lock_until_writeable(ssize_t req_bytes) {
    // Got the space already?  We're fine.
    if (handler->GetWriteBufferAvailable() >= req_bytes) {
        return 1;
    }

    // Don't block and don't have the space?  error.
    if (!block_for_buffer) {
        return -1;
    }

    // Update the required amount and lock the conditional
    {
        local_locker l(&required_bytes_mutex);
        locker_required_bytes = req_bytes;
        buffer_available_locker.lock();
    }

    // Wait for it to unlock; if it gets unlocked because the stream is stopped, it will return a negative
    // in the conditional future
    if (buffer_available_locker.block_until() < 0) 
        return -1;

    return 1;
}

void Pcap_Stream_Ringbuf::stop_stream(std::string in_reason) {
    // Unlock the conditional with an error
    buffer_available_locker.unlock(-1);

    // Trigger an error in the handler
    handler->ProtocolError();
}

ssize_t Pcap_Stream_Ringbuf::buffer_available() {
    if (handler != nullptr) 
        return handler->GetWriteBufferAvailable();

    return 0;
}

int Pcap_Stream_Ringbuf::pcapng_make_shb(std::string in_hw, std::string in_os, std::string in_app) {
    uint8_t *buf = NULL;
    pcapng_shb *shb;

    pcapng_option *opt;
    size_t opt_offt = 0;

    size_t buf_sz;
    size_t write_sz;

    uint32_t *end_sz = (uint32_t *) &buf_sz;

    buf_sz = sizeof(pcapng_shb);
    // Allocate an end-of-options entry
    buf_sz += sizeof(pcapng_option);

    // Allocate for all entries
    if (in_hw.length() > 0) 
        buf_sz += sizeof(pcapng_option) + PAD_TO_32BIT(in_hw.length());

    if (in_os.length() > 0) 
        buf_sz += sizeof(pcapng_option) + PAD_TO_32BIT(in_os.length());

    if (in_app.length() > 0) 
        buf_sz += sizeof(pcapng_option) + PAD_TO_32BIT(in_app.length());

    if (lock_until_writeable((ssize_t) buf_sz + 4) < 0) {
        return -1;
    }

    buf = new uint8_t[buf_sz];

    if (buf == NULL) {
        delete[] buf;
        return -1;
    }

    shb = (pcapng_shb *) buf;

    // Host-endian data; fill in the default info
    shb->block_type = PCAPNG_SHB_TYPE_MAGIC;
    shb->block_length = buf_sz + 4;
    shb->block_endian_magic = PCAPNG_SHB_ENDIAN_MAGIC;
    shb->version_major = PCAPNG_SHB_VERSION_MAJOR;
    shb->version_minor = PCAPNG_SHB_VERSION_MINOR;

    // Unspecified section length
    shb->section_length = -1;

    if (in_hw.length() > 0) {
        opt = (pcapng_option_t *) &(shb->options[opt_offt]);

        opt->option_code = PCAPNG_OPT_SHB_HW;
        opt->option_length = in_hw.length();
        memcpy(opt->option_data, in_hw.data(), in_hw.length());

        opt_offt += sizeof(pcapng_option) + PAD_TO_32BIT(in_hw.length());
    }

    if (in_os.length() > 0) {
        opt = (pcapng_option_t *) &(shb->options[opt_offt]);

        opt->option_code = PCAPNG_OPT_SHB_OS;
        opt->option_length = in_os.length();
        memcpy(opt->option_data, in_os.data(), in_os.length());

        opt_offt += sizeof(pcapng_option) + PAD_TO_32BIT(in_os.length());
    }

    if (in_app.length() > 0) {
        opt = (pcapng_option_t *) &(shb->options[opt_offt]);

        opt->option_code = PCAPNG_OPT_SHB_USERAPPL;
        opt->option_length = in_app.length();
        memcpy(opt->option_data, in_app.data(), in_app.length());

        opt_offt += sizeof(pcapng_option) + PAD_TO_32BIT(in_app.length());
    }

    // Put the end-of-options entry in
    opt = (pcapng_option_t *) &(shb->options[opt_offt]);
    opt->option_code = PCAPNG_OPT_ENDOFOPT;
    opt->option_length = 0;

    write_sz = handler->PutWriteBufferData(buf, buf_sz, true);

    if (write_sz != buf_sz) {
        handler->ProtocolError();
        delete[] buf;
        return -1;
    }

    log_size += write_sz;

    // Put the trailing size
    *end_sz += 4;
    
    write_sz = handler->PutWriteBufferData(end_sz, 4, true);

    if (write_sz != 4) {
        handler->ProtocolError();
        delete[] buf;
        return -1;
    }

    log_size += write_sz;

    delete[] buf;

    return 1;
}

int Pcap_Stream_Ringbuf::pcapng_make_idb(KisDatasource *in_datasource) {
    
    std::string ifname;
    ifname = in_datasource->get_source_name();

    std::string ifdesc;
    if (in_datasource->get_source_cap_interface() != in_datasource->get_source_interface()) {
        ifdesc = "capture interface for " + in_datasource->get_source_interface();
    }

    return pcapng_make_idb(in_datasource->get_source_number(), ifname, ifdesc,
            in_datasource->get_source_dlt());
}

int Pcap_Stream_Ringbuf::pcapng_make_idb(unsigned int in_sourcenumber, std::string in_interface, 
        std::string in_desc, int in_dlt) {
    // Put it in the map of datasource IDs to local log IDs.  The sequential 
    // position in the list of IDBs is the size of the map because we never
    // remove from the number map
    unsigned int logid = datasource_id_map.size();
    datasource_id_map[in_sourcenumber] = logid;

    uint8_t *retbuf;

    pcapng_idb *idb;

    pcapng_option *opt;
    size_t opt_offt = 0;

    size_t buf_sz;
    size_t write_sz;

    uint32_t *end_sz = (uint32_t *) &buf_sz;
    
    buf_sz = sizeof(pcapng_idb);

    // Allocate an end-of-options entry
    buf_sz += sizeof(pcapng_option);

    // Allocate for all entries
    if (in_interface.length() > 0)
        buf_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(in_interface.length());

    if (in_desc.length() > 0) {
        buf_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(in_desc.length());
    }

    if (lock_until_writeable((ssize_t) buf_sz + 4) < 0) {
        return -1;
    }

    retbuf = new uint8_t[buf_sz];

    if (retbuf == NULL) {
        return -1;
    }

    idb = (pcapng_idb *) retbuf;

    idb->block_type = PCAPNG_IDB_BLOCK_TYPE;
    idb->block_length = buf_sz + 4;
    idb->dlt = in_dlt;
    idb->reserved = 0;
    idb->snaplen = 65535;

    // Put our options, if any
    if (in_interface.length() > 0) {
        opt = (pcapng_option_t *) &(idb->options[opt_offt]);
        opt->option_code = PCAPNG_OPT_IDB_IFNAME;
        opt->option_length = in_interface.length();
        memcpy(opt->option_data, in_interface.data(), in_interface.length());
        opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(in_interface.length());
    }

    if (in_desc.length() > 0) {
        opt = (pcapng_option_t *) &(idb->options[opt_offt]);
        opt->option_code = PCAPNG_OPT_IDB_IFDESC;
        opt->option_length = in_desc.length();
        memcpy(opt->option_data, in_desc.data(), in_desc.length());
        opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(in_desc.length());
    }

    // Put the end-of-options
    opt = (pcapng_option_t *) &(idb->options[opt_offt]);
    opt->option_code = PCAPNG_OPT_ENDOFOPT;
    opt->option_length = 0;

    write_sz = handler->PutWriteBufferData(retbuf, buf_sz, true);

    if (write_sz != buf_sz) {
        handler->ProtocolError();
        delete[] retbuf;
        return -1;
    }

    log_size += write_sz;

    // Put the trailing size
    *end_sz += 4;
    
    write_sz = handler->PutWriteBufferData(end_sz, 4, true);

    if (write_sz != 4) {
        handler->ProtocolError();
        delete[] retbuf;
        return -1;
    }

    log_size += write_sz;

    delete[] retbuf;

    return logid;
}

int Pcap_Stream_Ringbuf::pcapng_write_packet(unsigned int in_sourcenumber, 
        struct timeval *in_tv, std::vector<data_block> in_blocks) {
    local_locker lg(&packet_mutex);

    uint8_t *retbuf;

    // Interface ID for multiple interfaces per file
    int ng_interface_id = in_sourcenumber;

    pcapng_epb *epb;
    pcapng_option *opt;

    // Buffer contains just the header
    size_t buf_sz = sizeof(pcapng_epb);

    // Data contains header + data + options
    size_t data_sz = buf_sz;

    // End reference size
    uint32_t *end_sz = (uint32_t *) &data_sz;

    size_t write_sz;

    size_t aggregate_block_sz = 0;

    for (auto db : in_blocks) {
        aggregate_block_sz += db.len;
    }

    // Pad to 32
    data_sz += PAD_TO_32BIT(aggregate_block_sz);

    // Allocate an end-of-options entry
    data_sz += sizeof(pcapng_option);

    if (lock_until_writeable((ssize_t) data_sz + 4) < 0) {
        return 0;
    }

    ssize_t r = handler->ReserveWriteBufferData((void **) &retbuf, buf_sz);

    if (r != (ssize_t) buf_sz) {
        handler->CommitWriteBufferData(NULL, 0);
        handler->ProtocolError();
        return -1;
    }

    epb = (pcapng_epb *) retbuf;

    epb->block_type = PCAPNG_EPB_BLOCK_TYPE;
    epb->block_length = data_sz + 4;
    epb->interface_id = ng_interface_id;

    // Convert timestamp to 10e6 usec precision
    uint64_t conv_ts;
    conv_ts = (uint64_t) in_tv->tv_sec * 1000000L;
    conv_ts += in_tv->tv_usec;

    // Split high and low ts
    epb->timestamp_high = (conv_ts >> 32);
    epb->timestamp_low = conv_ts;

    epb->captured_length = aggregate_block_sz;
    epb->original_length = aggregate_block_sz;

    // Write the header to the ringbuf
    write_sz = handler->CommitWriteBufferData(retbuf, buf_sz);

    if (!write_sz) {
        handler->ProtocolError();
        return -1;
    }

    log_size += write_sz;

    // Write all the incoming blocks sequentially
    for (auto db : in_blocks) {
        // Write the data to the ringbuf
        write_sz = handler->PutWriteBufferData(db.data, db.len, true);

        if (write_sz != db.len) {
            handler->ProtocolError();
            return -1;
        }

        log_size += write_sz;
    }

    // Pad data to 32bit
    uint32_t pad = 0;
    size_t pad_sz = 0;

    pad_sz = PAD_TO_32BIT(aggregate_block_sz) - aggregate_block_sz;

    if (pad_sz > 0) {
        write_sz = handler->PutWriteBufferData(&pad, pad_sz, true);

        if (write_sz != pad_sz) {
            handler->ProtocolError();
            return -1;
        }

        log_size += write_sz;
    }

    // Allocate the options
    retbuf = new uint8_t[sizeof(pcapng_option_t)];

    if (retbuf == NULL) {
        handler->ProtocolError();
        return -1;
    }

    // Put the end-of-options
    opt = (pcapng_option_t *) retbuf;
    opt->option_code = PCAPNG_OPT_ENDOFOPT;
    opt->option_length = 0;

    write_sz = handler->PutWriteBufferData(retbuf, sizeof(pcapng_option_t), true);

    if (write_sz != sizeof(pcapng_option_t)) {
        handler->ProtocolError();
        delete[] retbuf;
        return -1;
    }

    log_size += write_sz;

    delete[] retbuf;

    // Put the trailing size
    *end_sz += 4;
    
    write_sz = handler->PutWriteBufferData(end_sz, 4, true);

    if (write_sz != 4) {
        handler->ProtocolError();
        return -1;
    }

    log_size += write_sz;

    return 1;
}

int Pcap_Stream_Ringbuf::pcapng_write_packet(kis_packet *in_packet, kis_datachunk *in_data) {
    local_locker lg(&packet_mutex);

    SharedDatasource kis_datasource;

    packetchain_comp_datasource *datasrcinfo = 
        (packetchain_comp_datasource *) in_packet->fetch(pack_comp_datasrc);

    // We can't log packets w/ no info b/c we don't know what source in the
    // pcapng to associate them with
    if (datasrcinfo == NULL)
        return 0;

    auto ds_id_rec = 
        datasource_id_map.find(datasrcinfo->ref_source->get_source_number());

    // Interface ID for multiple interfaces per file
    int ng_interface_id;

    if (ds_id_rec == datasource_id_map.end()) {
        if ((ng_interface_id = pcapng_make_idb(datasrcinfo->ref_source)) < 0) {
            return -1;
        }
    } else {
        ng_interface_id = ds_id_rec->second;
    }

    std::vector<data_block> blocks;
    blocks.push_back(data_block(in_data->data, in_data->length));

    return pcapng_write_packet(ng_interface_id, &(in_packet->ts), blocks);
}

// Handle a packet from the chain; given the accept_cb and selector_cb we
// should be able to generically handle any sort of filtering - an advanced
// filter can be applied by the caller function to filter to a specific device
// or source.
//
// Interface descriptors are automatically created during packet insertion, and
// packets linked to the proper interface.
void Pcap_Stream_Ringbuf::handle_packet(kis_packet *in_packet) {
    kis_datachunk *target_datachunk;

    // If we have an accept filter and it rejects, we're done
    if (accept_cb != NULL && accept_cb(in_packet) == false)
        return;

    // If we're paused, ignore packets
    if (get_stream_paused())
        return;

    // If we have a selector filter, use it to get the data chunk, otherwise
    // use the linkframe
    if (selector_cb != NULL) {
        target_datachunk = selector_cb(in_packet);
    } else {
        target_datachunk = (kis_datachunk *) in_packet->fetch(pack_comp_linkframe);
    }

    // If we didn't get a data chunk from the selector or there isn't a linkframe,
    // silently ignore this packet
    if (target_datachunk == NULL)
        return;

    pcapng_write_packet(in_packet, target_datachunk);

    log_packets++;

    // Bail if this pushes us over the max
    if (check_over_size() || check_over_packets()) {
        handler->ProtocolError();
    }
}

Pcap_Stream_Packetchain::Pcap_Stream_Packetchain(GlobalRegistry *in_globalreg,
        std::shared_ptr<BufferHandlerGeneric> in_handler,
        std::function<bool (kis_packet *)> accept_filter,
        std::function<kis_datachunk * (kis_packet *)> data_selector) :
    Pcap_Stream_Ringbuf(in_globalreg, in_handler, accept_filter, data_selector, false) {

    packethandler_id = packetchain->RegisterHandler([this](kis_packet *packet) {
            handle_packet(packet);
            return 1;
        }, CHAINPOS_LOGGING, -100);
}

Pcap_Stream_Packetchain::~Pcap_Stream_Packetchain() {
    handler->ProtocolError();
    packetchain->RemoveHandler(packethandler_id, CHAINPOS_LOGGING);
}

void Pcap_Stream_Packetchain::stop_stream(std::string in_reason) {
    packetchain->RemoveHandler(packethandler_id, CHAINPOS_LOGGING);
    Pcap_Stream_Ringbuf::stop_stream(in_reason);
}

