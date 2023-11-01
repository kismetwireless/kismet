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

/*
 * Original basic pcap header 
 */
struct pcap_hdr {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t dlt;
} __attribute__((packed));
typedef struct pcap_hdr pcap_hdr_t;
#define PCAP_MAGIC          0xA1B2C3D4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define PCAP_MAX_SNAPLEN    8192

struct pcap_packet_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed));
typedef struct pcap_packet_hdr pcap_packet_hdr_t;

/* PCAP-NG basic structs, as defined in:
 * http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#section_shb
 */

/* Generic option block */
struct pcapng_option {
    uint16_t option_code;
    /* Length of actual option data */
    uint16_t option_length;
    /* Must be padded to 32 bit */
    uint8_t option_data[0];
} __attribute__((packed));
typedef struct pcapng_option pcapng_option_t;
#define PCAPNG_OPT_ENDOFOPT     0
#define PCAPNG_OPT_COMMENT      1

/* pcapng custom block */
struct pcapng_custom_option {
    uint16_t option_code;
    uint16_t option_length;
    uint32_t option_pen;
    uint8_t option_data[0];
} __attribute__((packed));
typedef struct pcapng_custom_option pcapng_custom_option_t;

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

#define PCAPNG_OPT_CUSTOM_UTF8          2988
#define PCAPNG_OPT_CUSTOM_BINARY        2989
#define PCAPNG_OPT_CUSTOM_UTF8_NOCOPY   19372
#define PCAPNG_OPT_CUSTOM_BINARY_NOCOPY 19373


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

    /* Length of actual packet */
    uint32_t captured_length;
    uint32_t original_length;

    /* Data must be padded to 32bit */
    uint8_t data[0];

    /* Options go here and must be dynamically calculated */
} __attribute__((packed));
typedef struct pcapng_epb pcapng_epb_t;
#define PCAPNG_EPB_BLOCK_TYPE       6

struct pcapng_epb_hash_option {
    uint16_t option_code;
    uint16_t option_length;
    uint8_t hash_type;
    uint32_t hash;
} __attribute__((packed));
typedef struct pcapng_epb_hash_option pcapng_epb_hash_option_t;

struct pcapng_epb_packetid_option {
    uint16_t option_code;
    uint16_t option_length;
    uint64_t packetid;
} __attribute__((packed));
typedef struct pcapng_epb_packetid_option pcapng_epb_packetid_option_t;

#define PCAPNG_OPT_EPB_HASH         3
#define PCAPNG_OPT_EPB_PACKETID     5

#define PCAPNG_OPT_EPB_HASH_CRC32   2

/* Custom pcapng block */
struct pcapng_custom_block {
    uint32_t block_type;
    uint32_t block_length;
    uint32_t custom_pen;
    
    /* Data must be padded to 32bit */
    uint8_t data[0];

    /* Options must be dynamically calculated */

} __attribute__((packed));
typedef struct pcapng_custom_block pcapng_custom_block_t;
#define PCAPNG_CB_BLOCK_TYPE        0xBAD

/* Kismet IANA PEN */
#define KISMET_IANA_PEN 55922

/* Kismet GPS record, matches PPI GPS definition */
struct kismet_pcapng_gps_chunk {
    uint8_t gps_magic;
    uint8_t gps_verison;
    uint16_t gps_len;
    uint32_t gps_fields_present;
    uint8_t gps_data[0];
} __attribute__((packed));
typedef struct kismet_pcapng_gps_chunk kismet_pcapng_gps_chunk_t;

/* Magic identifier to ID this custom sub chunk */
#define PCAPNG_GPS_MAGIC            0x47
#define PCAPNG_GPS_VERSION          0x1

#define PCAPNG_GPS_FLAG_LON         0x2
#define PCAPNG_GPS_FLAG_LAT	    	0x4
#define PCAPNG_GPS_FLAG_ALT		    0x8
#define PCAPNG_GPS_FLAG_ALT_G		0x10
#define PCAPNG_GPS_FLAG_GPSTIME		0x20
#define PCAPNG_GPS_FLAG_FRACTIME	0x40
#define PCAPNG_GPS_FLAG_EPH         0x80
#define PCAPNG_GPS_FLAG_EPV         0x100
#define PCAPNG_GPS_FLAG_EPT         0x200
#define PCAPNG_GPS_TS_HIGH          0x400
#define PCAPNG_GPS_TS_LOW           0x800

/* Kismet JSON record, encapsulates a JSON event instead of a binary packet event for 
 * things like rtlsdr, bluetooth hci, etc */
struct kismet_pcapng_json_chunk {
	uint8_t json_magic;
	uint8_t json_version;
	uint16_t json_len;
	char json_data[0];
} __attribute__((packed));
typedef struct kismet_pcapng_json_chunk kismet_pcapng_json_chunk_t;

/* Magic identifier for this custom sub chunk */
#define PCAPNG_JSON_MAGIC 			0x48
#define PCAPNG_JSON_VERSION 		0x1

#endif
