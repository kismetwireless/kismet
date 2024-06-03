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

#ifndef __PCAPNG_STREAM_FUTUREBUF__
#define __PCAPNG_STREAM_FUTUREBUF__ 

#include "config.h"

#include <functional>
#include <unordered_map>
#include <vector>

#include "future_chainbuf.h"
#include "globalregistry.h"
#include "packetchain.h"
#include "kis_datasource.h"
#include "pcapng.h"
#include "streamtracker.h"

// A streaming pcap generator that connects the packetchain to a buffer defined by the
// future_chainbuf; registers as a stream handler in the streaming subsystem.
//
// Can be configured to have a maximum pending buffer size, with discard or stall behavior.
//
// Can be stalled until the lifetime of the stream completes, for easy inclusion in http request
// threads

struct pcapng_stream_accept_ftor {
    bool operator()(const std::shared_ptr<kis_packet>&) {
        return true;
    }
};

struct pcapng_stream_select_ftor {
    pcapng_stream_select_ftor() {
        auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
        pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    }

    std::shared_ptr<kis_datachunk> operator()(const std::shared_ptr<kis_packet>& in_packet) {
        return in_packet->fetch<kis_datachunk>(pack_comp_linkframe);
    }

    int pack_comp_linkframe;
};

template<typename fn_accept = pcapng_stream_accept_ftor, typename fn_selector = pcapng_stream_select_ftor>
class pcapng_stream_futurebuf : public streaming_agent, public std::enable_shared_from_this<pcapng_stream_futurebuf<fn_accept, fn_selector>> {
public:
    pcapng_stream_futurebuf(future_chainbuf *buffer, 
            fn_accept accept_filter,
            fn_selector data_selector,
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
            chainbuf->set_packetmode();

            packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
            pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
            pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");
            pack_comp_gpsinfo = packetchain->register_packet_component("GPS");
            pack_comp_meta = packetchain->register_packet_component("JSON");

        }

    virtual ~pcapng_stream_futurebuf() {
        try {
            total_lifetime_promise.set_value();
        } catch (const std::future_error& e) {
            ;
        }

        chainbuf->cancel();
    }

    virtual void start_stream() {
        pcapng_make_shb("", "", "Kismet");
    }

    // Restart the chain on a new buffer; return that buffer once it is assigned
    virtual future_chainbuf *restart_stream(future_chainbuf *new_buffer) {
        // Restart a stream on the current buffer
        kis_lock_guard<kis_mutex> lk(pcap_mutex, "pcapng_futurebuf restart_stream");

        // Swap to the new buffer; the caller should finish dealing with the old
        // buffer somehow (such as flushing it out to file)
        chainbuf = new_buffer;

        log_packets = 0;
        datasource_id_map.clear();
        pcapng_make_shb("", "", "Kismet");

        return chainbuf;
    }

    virtual void stop_stream(std::string in_reason) override {
        try {
            total_lifetime_promise.set_value();
        } catch (const std::future_error& e) {
            ;
        }

        chainbuf->cancel();
    }

    virtual void block_until_stream_done() {
        total_lifetime_ft = total_lifetime_promise.get_future();
        total_lifetime_ft.wait();
    }

protected:
    kis_mutex pcap_mutex;

    future_chainbuf *chainbuf;

    std::promise<void> total_lifetime_promise;
    std::future<void> total_lifetime_ft;

    size_t max_backlog;
    bool block_for_buffer;

    fn_accept accept_cb;
    fn_selector selector_cb;

    std::shared_ptr<packet_chain> packetchain;
    int pack_comp_linkframe, pack_comp_datasrc, pack_comp_gpsinfo, pack_comp_meta;

    // Map kismet internal interface ID + DLT hash to log interface ID
    std::unordered_map<unsigned int, unsigned int> datasource_id_map;

    virtual bool block_until(size_t req_bytes) {
        if (!block_for_buffer)
            return chainbuf->size() + req_bytes < max_backlog;

        while (chainbuf->size() + req_bytes > max_backlog) {
            if (!chainbuf->running())
                return false;

            chainbuf->wait_write();
        }

        return true;
    }

    virtual int pcapng_make_shb(const std::string& in_hw, const std::string& in_os, const std::string& in_app) {
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
        chainbuf->put_data(buf, buf_sz + 4);

        log_size += buf_sz + 4;

        return 1;
    }

    virtual int pcapng_make_idb(kis_datasource *in_datasource, int in_dlt) {
        kis_lock_guard<kis_mutex> kl(pcap_mutex, "make idb");

        auto h1 = std::hash<unsigned int>{}(in_datasource->get_source_number());
        auto h2 = std::hash<unsigned int>{}(in_dlt);
        auto ds_index = h1 ^ (h2 << 1);

        auto ds_id_rec = datasource_id_map.find(ds_index);

        // Interface ID for multiple interfaces per file
        int ng_interface_id;

        if (ds_id_rec != datasource_id_map.end()) {
            ng_interface_id = ds_id_rec->second;
            return ng_interface_id;
        }

        std::string ifname;
        ifname = in_datasource->get_source_name();

        std::string ifdesc;
        if (in_datasource->get_source_cap_interface() != in_datasource->get_source_interface())
            ifdesc = fmt::format("capture interface for {}", in_datasource->get_source_interface());

        return pcapng_make_idb(in_datasource->get_source_number(), ifname, ifdesc, in_dlt);
    }

    virtual int pcapng_make_idb(unsigned int in_sourcenumber, const std::string& in_interface,
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

        chainbuf->put_data(buf, buf_sz + 4);

        log_size += buf_sz + 4;

        return logid;

    }

    virtual int pcapng_write_packet(const std::shared_ptr<kis_packet>& in_packet,
            std::shared_ptr<kis_datachunk> in_data) {
        kis_lock_guard<kis_mutex> lk(pcap_mutex, "pcapng_futurebuf pcapng_write_packet");

        auto datasrcinfo = in_packet->fetch<packetchain_comp_datasource>(pack_comp_datasrc);
        auto gpsinfo = in_packet->fetch<kis_gps_packinfo>(pack_comp_gpsinfo);
        auto metablob = in_packet->fetch<packet_metablob>(pack_comp_meta);

        if (datasrcinfo == nullptr) {
            return 0;
        }

        int ng_interface_id;

        if (in_data != nullptr) {
            ng_interface_id = pcapng_make_idb(datasrcinfo->ref_source, in_data->dlt);
        } else {
            ng_interface_id = pcapng_make_idb(datasrcinfo->ref_source, 0);
        }

        // Bundle the json info into a single keyed entry including the type; do this with 
        // basic strings because we don't want to waste time re-parsing the JSON data
        std::string formatted_json;
        if (metablob != nullptr) {
            formatted_json = fmt::format("\"{}\": {}", metablob->meta_type, metablob->meta_data);
        }

        std::shared_ptr<char> buf;

        // Total buffer size starts header + data + options + end of option
        size_t buf_sz = sizeof(pcapng_epb_t) + sizeof(pcapng_option_t);

        if (in_data != nullptr) {
            buf_sz += PAD_TO_32BIT(in_data->length());
        }

        // Optionally we add the GPS option into the total length
        size_t gps_len = 0;

        if (gpsinfo != nullptr && gpsinfo->fix >= 2) {
            // GPS header
            gps_len = sizeof(kismet_pcapng_gps_chunk_t);

            // Always lat/lon, optionally alt
            gps_len += 8;

            if (gpsinfo->fix > 2 && gpsinfo->alt != 0)
                gps_len += 4;

            // Total additional size is custom option block including PEN, and padded custom data
            buf_sz += sizeof(pcapng_custom_option_t) + PAD_TO_32BIT(gps_len);
        }

        size_t json_len = 0;
        if (formatted_json.length() > 0) {
            json_len = sizeof(kismet_pcapng_json_chunk_t) + formatted_json.length();
            buf_sz += sizeof(pcapng_custom_option_t) + PAD_TO_32BIT(json_len);
        }

        if (in_packet->hash != 0) {
            // CRC32 hash, 1 octet identifier, 4 octet hash
            buf_sz += PAD_TO_32BIT(sizeof(pcapng_epb_hash_option_t));
        }

        if (in_packet->packet_no != 0) {
            // Unique packet number, 8 bytes
            buf_sz += PAD_TO_32BIT(sizeof(pcapng_epb_packetid_option_t));
        }

        // Allocate 4 bytes larger to hold the final length
        if (!block_until(buf_sz + 4))
            return 0;

        pcapng_epb *epb;
        pcapng_option *opt;

        buf = std::shared_ptr<char>(new char[buf_sz + 4], std::default_delete<char[]>());
        memset(buf.get(), 0x00, buf_sz + 4);

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

        size_t opt_offt = sizeof(pcapng_epb_t);

        if (in_data != nullptr) {
            epb->captured_length = in_data->length();
            epb->original_length = in_packet->original_len;
            // epb->original_length = in_data->length();

            // Copy the data after the epb header
            memcpy(buf.get() + sizeof(pcapng_epb_t), in_data->data(), in_data->length());

            // Offset to the end of the epb header + data + pad
            opt_offt += PAD_TO_32BIT(in_data->length());
        } else {
            epb->captured_length = 0;
            epb->original_length = 0;
        }

        if (in_packet->hash != 0) {
            auto hopt = reinterpret_cast<pcapng_epb_hash_option_t *>(buf.get() + opt_offt);

            hopt->option_code = PCAPNG_OPT_EPB_HASH;
            hopt->option_length = 5;
            hopt->hash_type = PCAPNG_OPT_EPB_HASH_CRC32;
            hopt->hash = in_packet->hash;

            opt_offt += PAD_TO_32BIT(sizeof(pcapng_epb_hash_option_t));
        }

        if (in_packet->packet_no != 0) {
            auto popt = reinterpret_cast<pcapng_epb_packetid_option_t *>(buf.get() + opt_offt);

            popt->option_code = PCAPNG_OPT_EPB_PACKETID;
            popt->option_length = 8;
            popt->packetid = in_packet->packet_no;

            opt_offt += PAD_TO_32BIT(sizeof(pcapng_epb_packetid_option_t));
        }

        if (formatted_json.length() > 0) {
            auto gopt = reinterpret_cast<pcapng_custom_option_t *>(buf.get() + opt_offt);

            gopt->option_code = PCAPNG_OPT_CUSTOM_UTF8;
            gopt->option_pen = KISMET_IANA_PEN;
            // PEN + data, without padding
            gopt->option_length = 4 + sizeof(kismet_pcapng_json_chunk_t) + formatted_json.length();

            auto json = reinterpret_cast<kismet_pcapng_json_chunk_t *>(gopt->option_data);
            json->json_magic = PCAPNG_JSON_MAGIC;
            json->json_version = PCAPNG_JSON_VERSION;
            json->json_len = (uint16_t) formatted_json.length();

            memcpy(json->json_data, formatted_json.data(), formatted_json.length());

            // Move the offset by option length + padded content length
            opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(gopt->option_length);
        }

        if (gpsinfo != nullptr && gpsinfo->fix >= 2) {
            auto gopt = reinterpret_cast<pcapng_custom_option_t *>(buf.get() + opt_offt);

            // Always lon and lat
            uint32_t gps_fields = PCAPNG_GPS_FLAG_LAT | PCAPNG_GPS_FLAG_LON;

            // lon/lat
            gps_len = 8;

            if (gpsinfo->fix > 2 && gpsinfo->alt != 0) {
                gps_len += 4;
                gps_fields |= PCAPNG_GPS_FLAG_ALT;
            }

            gopt->option_code = PCAPNG_OPT_CUSTOM_BINARY;
            gopt->option_pen = KISMET_IANA_PEN;

            // PEN + data, without padding
            gopt->option_length = 4 + sizeof(kismet_pcapng_gps_chunk_t) + gps_len;

            auto gps = reinterpret_cast<kismet_pcapng_gps_chunk_t *>(gopt->option_data);

            gps->gps_magic = PCAPNG_GPS_MAGIC;
            gps->gps_verison = PCAPNG_GPS_VERSION;
            gps->gps_len = gps_len;
            gps->gps_fields_present = gps_fields;

            size_t field_data_offt = 0;

            auto f = reinterpret_cast<uint32_t *>(gps->gps_data + field_data_offt);
            *f = double_to_fixed3_7(gpsinfo->lon);
            field_data_offt += 4;

            f = reinterpret_cast<uint32_t *>(gps->gps_data + field_data_offt);
            *f = double_to_fixed3_7(gpsinfo->lat);
            field_data_offt += 4;

            if (gpsinfo->fix > 2 && gpsinfo->alt != 0) {
                f = reinterpret_cast<uint32_t *>(gps->gps_data + field_data_offt);
                *f = double_to_fixed6_4(gpsinfo->alt);
                field_data_offt += 4;
            }

            // Move the offset by option length + padded content length
            opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(gopt->option_length);
        }

        // Place an end option after the data - header + pad32(data)
        opt = reinterpret_cast<pcapng_option *>(buf.get() + opt_offt);
        opt->option_code = PCAPNG_OPT_ENDOFOPT;
        opt->option_length = 0;

        // Final size
        auto end_sz = reinterpret_cast<uint32_t *>(buf.get() + buf_sz);
        *end_sz = buf_sz + 4;

        chainbuf->put_data(buf, buf_sz + 4);

        log_size += buf_sz + 4;

        return 1;
    }

    virtual int pcapng_write_packet(int ng_interface_id, const struct timeval& ts, const std::string& in_data, size_t original_len) {
        kis_lock_guard<kis_mutex> lk(pcap_mutex, "pcapng_futurebuf pcapng_write_packet");

        std::shared_ptr<char> buf;

        // Total buffer size is header + data + options
        size_t buf_sz = sizeof(pcapng_epb) + PAD_TO_32BIT(in_data.size()) + sizeof(pcapng_option);

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
        conv_ts = (uint64_t) ts.tv_sec * 1000000L;
        conv_ts += ts.tv_usec;

        // Split high and low ts
        epb->timestamp_high = (conv_ts >> 32);
        epb->timestamp_low = conv_ts;

        epb->captured_length = in_data.size();
        epb->original_length = original_len;

        // Copy the data after the epb header
        memcpy(buf.get() + sizeof(pcapng_epb), in_data.data(), in_data.size());

        // Place an end option after the data - header + pad32(data)
        opt = reinterpret_cast<pcapng_option *>(buf.get() + sizeof(pcapng_epb) + PAD_TO_32BIT(in_data.size()));
        opt->option_code = PCAPNG_OPT_ENDOFOPT;
        opt->option_length = 0;

        // Final size
        auto end_sz = reinterpret_cast<uint32_t *>(buf.get() + buf_sz);
        *end_sz = buf_sz + 4;

        chainbuf->put_data(buf, buf_sz + 4);

        log_size += buf_sz + 4;

        return 1;

    }

    virtual void handle_packet(const std::shared_ptr<kis_packet>& in_packet) {
        std::shared_ptr<kis_datachunk> target_datachunk;

        if (get_stream_paused())
            return;

        if (accept_cb(in_packet) == false) {
            return;
        }

        target_datachunk = selector_cb(in_packet);

        // Allow null data chunks if we have json, otherwise skip this packet
        if (target_datachunk == nullptr && !in_packet->has(pack_comp_meta)) {
            return;
        }

        if (target_datachunk != nullptr && target_datachunk->dlt == 0 && !in_packet->has(pack_comp_meta)) {
            return;
        }

        kis_lock_guard<kis_mutex> lk(pcap_mutex, "pcapng_futurebuf handle_packet");

        pcapng_write_packet(in_packet, target_datachunk);

        log_packets++;

        if (check_over_size() || check_over_packets()) {
            chainbuf->cancel();
        }
    }

    static size_t PAD_TO_32BIT(size_t in) {
        while (in % 4) in++;
        return in;
    }
};

template<typename fn_accept, typename fn_selector>
class pcapng_stream_packetchain : public pcapng_stream_futurebuf<fn_accept, fn_selector> {
public:
    pcapng_stream_packetchain(future_chainbuf *buffer, 
            fn_accept accept_filter,
            fn_selector data_selector,
            size_t backlog_sz) :
        pcapng_stream_futurebuf<fn_accept, fn_selector>{buffer, accept_filter, data_selector, backlog_sz, false} { }

    virtual ~pcapng_stream_packetchain() {
        this->packetchain->remove_handler(packethandler_id, CHAINPOS_LOGGING);
        this->chainbuf->cancel();
    }

    virtual void start_stream() override {
        pcapng_stream_futurebuf<fn_accept, fn_selector>::start_stream();

        packethandler_id = 
            this->packetchain->register_handler([](void *auxdata, const std::shared_ptr<kis_packet>& packet) {
					auto pcapng = reinterpret_cast<pcapng_stream_packetchain *>(auxdata);
                    pcapng->handle_packet(packet);
                    return 1;
				}, this, CHAINPOS_LOGGING, -100);

    }

    virtual void stop_stream(std::string in_reason) override {
        // We have to spawn a thread to deal with this because we're inside the locking
        // chain of the buffer handler when we get a stream stop event, sometimes
        std::thread t([this]() {
                this->packetchain->remove_handler(packethandler_id, CHAINPOS_LOGGING);
                });

        pcapng_stream_futurebuf<fn_accept, fn_selector>::stop_stream(in_reason);
        t.join();
    }

protected:
    int packethandler_id;
};


#endif /* ifndef PCAPNG_STREAM_FUTUREBUF */
