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

#include "pcapng_stream_futurebuf.h"

pcapng_stream_futurebuf::pcapng_stream_futurebuf(future_chainbuf& buffer,
        std::function<bool (kis_packet *)> accept_filter,
        std::function<kis_datachunk *(kis_packet *)> data_selector,
        size_t backlog_sz,
        bool block_for_write) :
    streaming_agent{},
    chainbuf{buffer},
    max_backlog{backlog_sz},
    block_for_buffer{block_for_write}, 
    accept_cb{accept_filter},
    selector_cb{data_selector} {

    pcap_mutex.set_name("pcapng_stream_futurebuf");

    // Kick us out of stream mode into packet mode
    chainbuf.set_packetmode();

    packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");
}

pcapng_stream_futurebuf::~pcapng_stream_futurebuf() {
    try {
        total_lifetime_promise.set_value();
    } catch (const std::future_error& e) {
        ;
    }

    chainbuf.cancel();
}

void pcapng_stream_futurebuf::start_stream() {
    pcapng_make_shb("", "", "Kismet");
}

bool pcapng_stream_futurebuf::block_until(size_t req_bytes) {
    if (!block_for_buffer)
        return chainbuf.size() + req_bytes < max_backlog;

    while (chainbuf.size() + req_bytes > max_backlog) {
        if (!chainbuf.running())
            return false;

        chainbuf.wait_write();
    }

    return true;
}

void pcapng_stream_futurebuf::stop_stream(std::string reason) {
    try {
        total_lifetime_promise.set_value();
    } catch (const std::future_error& e) {
        ;
    }

    chainbuf.cancel();
}

void pcapng_stream_futurebuf::block_until_stream_done() {
    total_lifetime_ft = total_lifetime_promise.get_future();
    total_lifetime_ft.wait();
}

int pcapng_stream_futurebuf::pcapng_make_shb(const std::string& in_hw, const std::string& in_os, 
        const std::string& in_app) {
    std::shared_ptr<char> buf;

    pcapng_shb *shb;
    pcapng_option *opt;

    size_t opt_offt = 0;
    size_t buf_sz = 0;

    // Start with a header and end-of-options
    buf_sz = sizeof(pcapng_shb) + sizeof(pcapng_option);

    // Allocate for all entities
    if (in_hw.length() > 0)
        buf_sz += sizeof(pcapng_option) + PAD_TO_32BIT(in_hw.length());

    if (in_os.length() > 0)
        buf_sz += sizeof(pcapng_option) + PAD_TO_32BIT(in_os.length());

    if (in_app.length() > 0)
        buf_sz += sizeof(pcapng_option) + PAD_TO_32BIT(in_app.length());

    if (!block_until(buf_sz + 4))
        return -1;

    buf = std::shared_ptr<char>(new char[buf_sz + 4], std::default_delete<char[]>());
    if (buf == nullptr) {
        return -1;
    }

    memset(buf.get(), 0, buf_sz + 4);

    shb = reinterpret_cast<pcapng_shb *>(buf.get());

    // Host-endian data
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

    // Alias the last 4 bytes of the buffer for the completion size
    auto end_sz = reinterpret_cast<uint32_t *>(buf.get() + buf_sz);
    *end_sz = buf_sz + 4;

    // Drop it into the buffer
    chainbuf.put_data(buf, buf_sz + 4);

    log_size += buf_sz + 4;

    return 1;
}

int pcapng_stream_futurebuf::pcapng_make_idb(kis_datasource *in_datasource, int in_dlt) {
    std::string ifname;
    ifname = in_datasource->get_source_name();

    std::string ifdesc;
    if (in_datasource->get_source_cap_interface() != in_datasource->get_source_interface())
        ifdesc = fmt::format("capture interface for {}", in_datasource->get_source_interface());

    return pcapng_make_idb(in_datasource->get_source_number(), ifname, ifdesc, in_dlt);
}

int pcapng_stream_futurebuf::pcapng_make_idb(unsigned int in_sourcenumber, const std::string& in_interface,
        const std::string& in_ifdesc, int in_dlt) {
    // Calculate the size and if we're going to wait to insert it before we put it into the key map
    // because if we don't have room and aren't waiting, we need to generate it next time
    size_t buf_sz;

    buf_sz = sizeof(pcapng_idb);

    // Allocate an end-of-options entry
    buf_sz += sizeof(pcapng_option);

    // Allocate for all entries
    if (in_interface.length() > 0)
        buf_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(in_interface.length());

    if (in_ifdesc.length() > 0) {
        buf_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(in_ifdesc.length());
    }

    if (!block_until(buf_sz + 4))
        return 0;

    // Put it in the map of datasource IDs to local log IDs.  The sequential 
    // position in the list of IDBs is the size of the map because we never
    // remove from the number map.
    //
    // Index ID is a hash of the source number and DLT
    unsigned int logid = datasource_id_map.size();

    auto h1 = std::hash<unsigned int>{}(in_sourcenumber);
    auto h2 = std::hash<unsigned int>{}(in_dlt);
    auto index = h1 ^ (h2 << 1);

    datasource_id_map[index] = logid;

    std::shared_ptr<char> buf;

    pcapng_idb *idb;

    pcapng_option *opt;
    size_t opt_offt = 0;

    buf = std::shared_ptr<char>(new char[buf_sz + 4], std::default_delete<char[]>());

    idb = reinterpret_cast<pcapng_idb *>(buf.get());

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

    if (in_ifdesc.length() > 0) {
        opt = (pcapng_option_t *) &(idb->options[opt_offt]);
        opt->option_code = PCAPNG_OPT_IDB_IFDESC;
        opt->option_length = in_ifdesc.length();
        memcpy(opt->option_data, in_ifdesc.data(), in_ifdesc.length());
        opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(in_ifdesc.length());
    }

    // Put the end-of-options
    opt = (pcapng_option_t *) &(idb->options[opt_offt]);
    opt->option_code = PCAPNG_OPT_ENDOFOPT;
    opt->option_length = 0;

    uint32_t *end_sz = reinterpret_cast<uint32_t *>(buf.get() + buf_sz);
    *end_sz = buf_sz + 4;

    chainbuf.put_data(buf, buf_sz + 4);

    log_size += buf_sz + 4;

    return logid;
}

int pcapng_stream_futurebuf::pcapng_write_packet(kis_packet *in_packet, kis_datachunk *in_data) {
    local_locker l(&pcap_mutex, "pcapng_write_packet");

    auto datasrcinfo = in_packet->fetch<packetchain_comp_datasource>(pack_comp_datasrc);

    if (datasrcinfo == nullptr)
        return 0;

    auto h1 = std::hash<unsigned int>{}(datasrcinfo->ref_source->get_source_number());
    auto h2 = std::hash<unsigned int>{}(in_data->dlt);
    auto ds_index = h1 ^ (h2 << 1);

    auto ds_id_rec = datasource_id_map.find(ds_index);

    // Interface ID for multiple interfaces per file
    int ng_interface_id;

    if (ds_id_rec == datasource_id_map.end()) {
        if ((ng_interface_id = pcapng_make_idb(datasrcinfo->ref_source, in_data->dlt)) < 0) {
            return -1;
        }
    } else {
        ng_interface_id = ds_id_rec->second;
    }

    std::shared_ptr<char> buf;

    // Total buffer size is header + data + options
    size_t buf_sz = sizeof(pcapng_epb) + PAD_TO_32BIT(in_data->length) + sizeof(pcapng_option);

    if (!block_until(buf_sz + 4))
        return 0;

    pcapng_epb *epb;
    pcapng_option *opt;

    buf = std::shared_ptr<char>(new char[buf_sz + 4], std::default_delete<char[]>());
    memset(buf.get(), 0, buf_sz + 4);

    epb = reinterpret_cast<pcapng_epb *>(buf.get());

    epb->block_type = PCAPNG_EPB_BLOCK_TYPE;
    epb->block_length = buf_sz + 4;
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

    // Copy the data after the epb header
    memcpy(buf.get() + sizeof(pcapng_epb), in_data->data, in_data->length);

    // Place an end option after the data - header + pad32(data)
    opt = reinterpret_cast<pcapng_option *>(buf.get() + sizeof(pcapng_epb) + PAD_TO_32BIT(in_data->length));
    opt->option_code = PCAPNG_OPT_ENDOFOPT;
    opt->option_length = 0;

    // Final size
    auto end_sz = reinterpret_cast<uint32_t *>(buf.get() + buf_sz);
    *end_sz = buf_sz + 4;

    chainbuf.put_data(buf, buf_sz + 4);

    log_size += buf_sz + 4;

    return 1;
}

void pcapng_stream_futurebuf::handle_packet(kis_packet *in_packet) {
    kis_datachunk *target_datachunk;

    if (get_stream_paused())
        return;

    if (accept_cb != nullptr && accept_cb(in_packet) == false)
        return;

    if (selector_cb != nullptr)
        target_datachunk = selector_cb(in_packet);
    else
        target_datachunk = in_packet->fetch<kis_datachunk>(pack_comp_linkframe);

    if (target_datachunk == nullptr)
        return;

    if (target_datachunk->dlt == 0)
        return;

    pcapng_write_packet(in_packet, target_datachunk);

    log_packets++;

    if (check_over_size() || check_over_packets()) {
        chainbuf.cancel();
    }

}



pcapng_stream_packetchain::pcapng_stream_packetchain(future_chainbuf& buffer,
            std::function<bool (kis_packet *)> accept_filter,
            std::function<kis_datachunk *(kis_packet *)> data_selector,
            size_t backlog_sz) :
    pcapng_stream_futurebuf{buffer, accept_filter, data_selector, backlog_sz, true} {

}

pcapng_stream_packetchain::~pcapng_stream_packetchain() {
    packetchain->remove_handler(packethandler_id, CHAINPOS_LOGGING);
    chainbuf.cancel();
}

void pcapng_stream_packetchain::start_stream() {
    pcapng_stream_futurebuf::start_stream();

    packethandler_id = 
        packetchain->register_handler([this](kis_packet *packet) {
            handle_packet(packet);
            return 1;
        }, CHAINPOS_LOGGING, -100);
}

void pcapng_stream_packetchain::stop_stream(std::string in_reason) {
    // We have to spawn a thread to deal with this because we're inside the locking
    // chain of the buffer handler when we get a stream stop event, sometimes
    std::thread t([this]() {
            packetchain->remove_handler(packethandler_id, CHAINPOS_LOGGING);
            });

    pcapng_stream_futurebuf::stop_stream(in_reason);
    t.join();
}

