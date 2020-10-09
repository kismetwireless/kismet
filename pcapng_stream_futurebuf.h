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

class pcapng_stream_futurebuf : public streaming_agent, public std::enable_shared_from_this<pcapng_stream_futurebuf> {
public:
    pcapng_stream_futurebuf(future_chainbuf& buffer, 
            std::function<bool (kis_packet *)> accept_filter,
            std::function<kis_datachunk *(kis_packet *)> data_selector,
            size_t backlog_sz,
            bool block_for_write);

    virtual ~pcapng_stream_futurebuf();

    virtual void stop_stream(std::string in_reason) override;

    virtual void block_until_stream_done();
protected:
    kis_recursive_timed_mutex pcap_mutex;

    future_chainbuf& chainbuf;

    std::promise<void> total_lifetime_promise;
    std::future<void> total_lifetime_ft;

    size_t max_backlog;
    bool block_for_buffer;

    std::function<bool (kis_packet *)> accept_cb;
    std::function<kis_datachunk *(kis_packet *)> selector_cb;

    std::shared_ptr<packet_chain> packetchain;
    int pack_comp_linkframe, pack_comp_datasrc;

    // Map kismet internal interface ID + DLT hash to log interface ID
    std::unordered_map<unsigned int, unsigned int> datasource_id_map;

    virtual size_t block_until(size_t req_bytes);

    virtual int pcapng_make_shb(const std::string& in_hw, const std::string& in_os, const std::string& in_app);

    virtual int pcapng_make_idb(kis_datasource *in_datasource, int in_dlt);
    virtual int pcapng_make_idb(unsigned int in_sourcenumber, const std::string& in_interface,
            const std::string& in_description, int in_dlt);
    virtual int pcapng_write_packet(kis_packet *in_packet, kis_datachunk *in_data);

    virtual void handle_packet(kis_packet *in_packet);

    static size_t PAD_TO_32BIT(size_t in) {
        while (in % 4) in++;
        return in;
    }
};

class pcapng_stream_packetchain : public pcapng_stream_futurebuf {
public:
    pcapng_stream_packetchain(future_chainbuf& buffer, 
            std::function<bool (kis_packet *)> accept_filter,
            std::function<kis_datachunk *(kis_packet *)> data_selector,
            size_t backlog_sz);
    virtual ~pcapng_stream_packetchain();

    virtual void stop_stream(std::string in_reason) override;

protected:
    int packethandler_id;
};


#endif /* ifndef PCAPNG_STREAM_FUTUREBUF */
