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
        shared_ptr<RingbufferHandler> in_handler,
        function<bool (kis_packet *)> accept_filter,
        function<kis_datachunk * (kis_packet *)> data_selector) : streaming_agent() {

    globalreg = in_globalreg;
    
    packetchain = 
        static_pointer_cast<Packetchain>(globalreg->FetchGlobal("PACKETCHAIN"));

    handler = in_handler;

    accept_cb = accept_filter;
    selector_cb = data_selector;

    packethandler_id = packetchain->RegisterHandler([this](kis_packet *packet) {
            handle_chain_packet(packet);
            return 1;
        }, CHAINPOS_LOGGING, -100);

    pack_comp_linkframe = packetchain->RegisterPacketComponent("LINKFRAME");
    pack_comp_datasrc = packetchain->RegisterPacketComponent("KISDATASRC");

    // Write the initial headers
    if (pcapng_make_shb("", "", "Kismet") < 0)
        return;

}

Pcap_Stream_Ringbuf::~Pcap_Stream_Ringbuf() {
    handler->ProtocolError();
    packetchain->RemoveHandler(packethandler_id, CHAINPOS_LOGGING);
}

void Pcap_Stream_Ringbuf::stop_stream(string in_reason) {
    packetchain->RemoveHandler(packethandler_id, CHAINPOS_LOGGING);
    handler->ProtocolError();
}

int Pcap_Stream_Ringbuf::pcapng_make_shb(string in_hw, string in_os, string in_app) {
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

    if (handler->GetWriteBufferFree() < buf_sz + 4) {
        handler->ProtocolError();
        return -1;
    }

    buf = new uint8_t[buf_sz];

    if (buf == NULL) {
        handler->ProtocolError();
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

    return 1;
}

int Pcap_Stream_Ringbuf::pcapng_make_idb(KisDatasource *in_datasource) {
    // Put it in the map of datasource IDs to local log IDs.  The sequential 
    // position in the list of IDBs is the size of the map because we never
    // remove from the number map
    unsigned int logid = datasource_id_map.size();
    datasource_id_map.emplace(in_datasource->get_source_number(), logid);

    // fprintf(stderr, "debug - making idb for datasource %s %s number %u log number %u\n", in_datasource->get_source_interface().c_str(), in_datasource->get_source_uuid().UUID2String().c_str(), in_datasource->get_source_number(), logid);


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

    string ifname;
    if (in_datasource->get_source_cap_interface().length() > 0) {
        ifname = in_datasource->get_source_cap_interface();
    } else {
        ifname = in_datasource->get_source_interface();
    }

    string ifdesc;
    if (in_datasource->get_source_cap_interface() !=
            in_datasource->get_source_interface()) {
        ifdesc = "capture interface for " + in_datasource->get_source_interface();
    }

    // Allocate for all entries
    if (ifname.length() > 0)
        buf_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(ifname.length());

    if (ifdesc.length() > 0) {
        buf_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(ifdesc.length());
    }

    if (handler->GetWriteBufferFree() < buf_sz + 4) {
        handler->ProtocolError();
        return -1;
    }

    retbuf = new uint8_t[buf_sz];

    if (retbuf == NULL) {
        handler->ProtocolError();
        return -1;
    }

    idb = (pcapng_idb *) retbuf;

    idb->block_type = PCAPNG_IDB_BLOCK_TYPE;
    idb->block_length = buf_sz + 4;
    idb->dlt = in_datasource->get_source_dlt();
    idb->reserved = 0;
    idb->snaplen = 65535;

    // Put our options, if any
    if (ifname.length() > 0) {
        opt = (pcapng_option_t *) &(idb->options[opt_offt]);
        opt->option_code = PCAPNG_OPT_IDB_IFNAME;
        opt->option_length = ifname.length();
        memcpy(opt->option_data, ifname.data(), ifname.length());
        opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(ifname.length());
    }

    if (ifdesc.length() > 0) {
        opt = (pcapng_option_t *) &(idb->options[opt_offt]);
        opt->option_code = PCAPNG_OPT_IDB_IFDESC;
        opt->option_length = ifdesc.length();
        memcpy(opt->option_data, ifdesc.data(), ifdesc.length());
        opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(ifdesc.length());
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

    return logid;
}

int Pcap_Stream_Ringbuf::pcapng_write_packet(kis_packet *in_packet,
        kis_datachunk *in_data) {
    uint8_t *retbuf;
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

    pcapng_epb *epb;

    pcapng_option *opt;

    // Buffer contains just the header
    size_t buf_sz = sizeof(pcapng_epb);

    // Data contains header + data + options
    size_t data_sz = buf_sz;

    // End reference size
    uint32_t *end_sz = (uint32_t *) &data_sz;

    size_t write_sz;

    // Pad to 32
    data_sz += PAD_TO_32BIT(in_data->length);

    // Allocate an end-of-options entry
    data_sz += sizeof(pcapng_option);

    // Drop packet if we can't put it in the buffer
    if (handler->GetWriteBufferFree() < buf_sz + 4) {
        return 0;
    }

    retbuf = new uint8_t[buf_sz];

    if (retbuf == NULL) {
        handler->ProtocolError();
        return -1;
    }

    epb = (pcapng_epb *) retbuf;

    epb->block_type = PCAPNG_EPB_BLOCK_TYPE;
    epb->block_length = data_sz + 4;
    epb->interface_id = ng_interface_id;

    // Convert timestamp to 10e6 usec precision
    uint64_t conv_ts;
    conv_ts = (uint64_t) in_packet->ts.tv_sec * 1000000L;
    conv_ts += in_packet->ts.tv_usec;

    // Split high and low ts
    epb->timestamp_high = (conv_ts >> 32);
    epb->timestamp_low = conv_ts;

    epb->captured_length = in_data->length;
    epb->original_length = in_data->length;

    // Write the header to the ringbuf
    write_sz = handler->PutWriteBufferData(retbuf, buf_sz, true);

    if (write_sz != buf_sz) {
        handler->ProtocolError();
        delete[] retbuf;
        return -1;
    }

    log_size += write_sz;

    delete[] retbuf;

    // Write the data to the ringbuf
    write_sz = handler->PutWriteBufferData(in_data->data, in_data->length, true);

    if (write_sz != in_data->length) {
        handler->ProtocolError();
        return -1;
    }

    log_size += write_sz;

    // Pad data to 32bit
    uint32_t pad = 0;
    size_t pad_sz = 0;

    pad_sz = PAD_TO_32BIT(in_data->length) - in_data->length;

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

// Handle a packet from the chain; given the accept_cb and selector_cb we
// should be able to generically handle any sort of filtering - an advanced
// filter can be applied by the caller function to filter to a specific device
// or source.
//
// Interface descriptors are automatically created during packet insertion, and
// packets linked to the proper interface.
void Pcap_Stream_Ringbuf::handle_chain_packet(kis_packet *in_packet) {
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


