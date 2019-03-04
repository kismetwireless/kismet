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

#ifndef __PCAP_STREAM_RINGBUF__
#define __PCAP_STREAM_RINGBUF__

/* A streaming pcap generator that writes to the ringbuf contained in a 
 * Kis_Net_Httpd_Ringbuf_Stream_Handler.
 *
 * Designed to be initiated from a stream handler sub-class to feed
 * pcap data from the packetchain into the ringbuffer.
 */

#include "config.h"

#include <algorithm>
#include <functional>

#include "ringbuf2.h"
#include "buffer_handler.h"
#include "globalregistry.h"
#include "packetchain.h"
#include "kis_datasource.h"
#include "streamtracker.h"
#include "pcapng.h"

/* Instantiate a stream that attaches to the packetchain, outputs packets 
 * of type dlt, and optionally, apply an accept filter function;
 *
 * The filter function, if present, should return true to include the packet in 
 * the stream, false to exclude it.
 *
 * The data selector function, if present, should return the kis_datachunk component
 * of the packet destined for export.
 *
 */
class Pcap_Stream_Ringbuf : public streaming_agent {
public:
    Pcap_Stream_Ringbuf(GlobalRegistry *in_globalreg, 
            std::shared_ptr<BufferHandlerGeneric> in_handler,
            std::function<bool (kis_packet *)> accept_filter,
            std::function<kis_datachunk * (kis_packet *)> data_selector,
            bool block_for_buffer);
    virtual ~Pcap_Stream_Ringbuf();

    virtual void set_blocking(bool in_block) {
        block_for_buffer = in_block;
    }

    virtual void stop_stream(std::string in_reason);

    struct data_block {
        data_block(uint8_t *in_d, size_t in_l) {
            data = in_d;
            len = in_l;
        }

        uint8_t *data;
        size_t len;
    };

    ssize_t buffer_available();

protected:
    virtual int lock_until_writeable(ssize_t req_bytes);

    virtual int pcapng_make_shb(std::string in_hw, std::string in_os, std::string in_app);

    // Create a new interface record from an existing datasource
    virtual int pcapng_make_idb(KisDatasource *in_datasource);

    // Low-level datasource creation
    virtual int pcapng_make_idb(unsigned int in_sourcenumber, std::string in_interface, 
            std::string in_description, int in_dlt);

    // Write a complete block using native headers
    virtual int pcapng_write_packet(kis_packet *in_packet, kis_datachunk *in_data);

    // Low-level packet logging; accepts a vector of blocks to minimize the copying
    // needed to append custom headers
    virtual int pcapng_write_packet(unsigned int in_sourcenumber, struct timeval *in_tv,
            std::vector<data_block> in_blocks);

    virtual void handle_packet(kis_packet *in_packet);

    size_t PAD_TO_32BIT(size_t in) {
        while (in % 4) in++;
        return in;
    }

    GlobalRegistry *globalreg;

    std::shared_ptr<BufferHandlerGeneric> handler;

    std::shared_ptr<Packetchain> packetchain;

    int pack_comp_linkframe, pack_comp_datasrc;

    std::function<bool (kis_packet *)> accept_cb;
    std::function<kis_datachunk * (kis_packet *)> selector_cb;

    // Map kismet internal interface ID to log interface ID
    std::map<unsigned int, unsigned int> datasource_id_map;

    kis_recursive_timed_mutex packet_mutex;

    // Optional blocking operations until the required space is available in the buffer
    bool block_for_buffer;
    conditional_locker<int> buffer_available_locker;
    ssize_t locker_required_bytes;
    kis_recursive_timed_mutex required_bytes_mutex;
};

class Pcap_Stream_Packetchain : public Pcap_Stream_Ringbuf {
public:
    Pcap_Stream_Packetchain(GlobalRegistry *in_globalreg, 
            std::shared_ptr<BufferHandlerGeneric> in_handler,
            std::function<bool (kis_packet *)> accept_filter,
            std::function<kis_datachunk * (kis_packet *)> data_selector);

    virtual ~Pcap_Stream_Packetchain();

    virtual void stop_stream(std::string in_reason) override;

protected:
    int packethandler_id;

};

#endif

