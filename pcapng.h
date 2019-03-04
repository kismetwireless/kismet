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

#ifndef __PCAPNG_H__
#define __PCAPNG_H__

#include <stdint.h>

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

#endif
