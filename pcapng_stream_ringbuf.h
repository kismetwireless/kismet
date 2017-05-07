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

#include "config.hpp"

#include <algorithm>
#include <functional>

#include "ringbuf2.h"
#include "ringbuf_handler.h"
#include "globalregistry.h"
#include "packetchain.h"
#include "kis_datasource.h"

/* PCAP-NG basic structs, as defined in:
 * http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#section_shb
 */

/* Generic option block */
struct pcapng_option {
    uint16_t option_code;
    // Length of actual option data
    uint16_t option_length;
    // Must be padded to 32 bit
    uint8_t option_data[0];
} __attribute__((packed));
typedef struct pcapng_option pcapng_option_t;
#define PCAPNG_OPT_ENDOFOPT     0
#define PCAPNG_OPT_COMMENT      1

/* Header block found at start of file */
struct pcapng_shb {
    uint32_t block_type;
    uint32_t block_length;
    uint32_t block_endian_magic;
    uint16_t version_major;
    uint16_t version_minor;
    int64_t section_length;
    uint8_t options[0];
} __attribute__((packed));
typedef struct pcapng_shb pcapng_shb_t;
#define PCAPNG_SHB_TYPE_MAGIC       0x0A0D0D0A
#define PCAPNG_SHB_ENDIAN_MAGIC     0x1A2B3C4D
#define PCAPNG_SHB_VERSION_MAJOR    1
#define PCAPNG_SHB_VERSION_MINOR    0

#define PCAPNG_OPT_SHB_HW           2
#define PCAPNG_OPT_SHB_OS           3
#define PCAPNG_OPT_SHB_USERAPPL     4


/* Interface definition */
struct pcapng_idb {
    uint32_t block_type;
    uint32_t block_length;
    uint16_t dlt;
    uint16_t reserved;
    uint32_t snaplen;
    uint8_t options[0];
} __attribute__((packed));
typedef struct pcapng_idb pcapng_idb_t;
#define PCAPNG_IDB_BLOCK_TYPE       1

#define PCAPNG_OPT_IDB_IFNAME       2
#define PCAPNG_OPT_IDB_IFDESC       3
#define PCAPNG_OPT_IDB_FCSLEN       13


/* Capture frame 
 * Enhanced packet blocks have 2 dynamic length fields; the uint32_t aligned data 
 * field, and the options.  Outputting this must adjust the size accordingly then
 * output an options array field after it
 */
struct pcapng_epb {
    uint32_t block_type;
    uint32_t block_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;

    // Length of actual packet
    uint32_t captured_length;
    uint32_t original_length;

    // Data must be padded to 32bit
    uint8_t data[0];
    /* Options go here and must be dynamically calculated */
} __attribute__((packed));
typedef struct pcapng_epb pcapng_epb_t;
#define PCAPNG_EPB_BLOCK_TYPE       6

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
class Pcap_Stream_Ringbuf {
public:
    Pcap_Stream_Ringbuf(GlobalRegistry *in_globalreg, 
            shared_ptr<RingbufferHandler> in_handler,
            function<bool (kis_packet *)> accept_filter,
            function<kis_datachunk * (kis_packet *)> data_selector);

    virtual ~Pcap_Stream_Ringbuf();

protected:
    virtual int pcapng_make_shb(string in_hw, string in_os, string in_app);
    virtual int pcapng_make_idb(KisDatasource *in_datasource);
    virtual int pcapng_write_packet(kis_packet *in_packet, kis_datachunk *in_data);

    virtual void handle_chain_packet(kis_packet *in_packet);

    size_t PAD_TO_32BIT(size_t in) {
        while (in % 4) in++;
        return in;
    }

    GlobalRegistry *globalreg;

    shared_ptr<Packetchain> packetchain;

    shared_ptr<RingbufferHandler> handler;

    int packethandler_id;
    int pack_comp_linkframe, pack_comp_datasrc;

    function<bool (kis_packet *)> accept_cb;
    function<kis_datachunk * (kis_packet *)> selector_cb;

    // Map kismet internal interface ID to log interface ID
    map<unsigned int, unsigned int> datasource_id_map;
    
};

#endif

