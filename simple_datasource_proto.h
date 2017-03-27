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

#ifndef __SIMPLE_CAP_PROTO_H__
#define __SIMPLE_CAP_PROTO_H__

#include "config.h"

#include <stdint.h>
#include <time.h>

/*
 * Simple capture protocol
 *
 * A simple and expandable protocol to communicate between a data 
 * source & the kismet server. 
 *
 * This protocol is used by kismet datasources and by remote drones, it's 
 * designed to be as generic as possible.
 *
 * To minimize requirements on data sources and on drones, we don't use any
 * c++ structures in the protocol, however it does rely on msgpack to encode
 * the data stored in keyed values.
 *
 * All multibyte values are stored in network endian.  Data encoded in msgpack
 * blobs is encoded by msgpack and not pre-converted to a fixed endian format.
 *
 * msgpack encoded objects are encouraged to pack as maps with string keys to 
 * make future flexibility simpler.
 */

#define KIS_CAP_SIMPLE_PROTO_SIG    0xDECAFBAD

/* Multiple key-value pairs can be nested inside a kismet proto packet. */

/* Object field header */
struct simple_cap_proto_kv_h {
    /* Named key for this kv pair */
    char key[16];
    /* Length of value object */
    uint32_t obj_sz;
} __attribute__((packed));
typedef struct simple_cap_proto_kv_h simple_cap_proto_kv_h_t;

struct simple_cap_proto_kv {
    simple_cap_proto_kv_h_t header;
    /* Packed binary representation of value */
    uint8_t *object;
} __attribute__((packed));
typedef struct simple_cap_proto_kv simple_cap_proto_kv_t;

/* Basic proto header/wrapper */
struct simple_cap_proto {
    /* Fixed Start-of-packet signature */
    uint32_t signature;
    /* Basic crc32 checksum of packet data, calculated with checksum set to zero */
    uint32_t checksum;
    /* Total size of packet including signature and checksum */
    uint32_t packet_sz;
    /* Sequence number (sender) */
    uint32_t sequence_number;
    /* Type of packet */
    char type[16];
    /* Number of KV pairs */
    uint32_t num_kv_pairs;
    /* List of kv pairs */
    uint8_t *data;
} __attribute__((packed));
typedef struct simple_cap_proto simple_cap_proto_t;

/* Basic success object */
struct simple_cap_proto_success_value {
    /* Success bool */
    uint8_t success;
    /* 3 byte padding */
    uint8_t pad1;
    uint16_t pad2;
    /* Sequence number of command */
    uint32_t sequence_number;
} __attribute__((packed));
typedef struct simple_cap_proto_success_value simple_cap_proto_success_t;

/* Encode a KV list */
simple_cap_proto_t *encode_simple_cap_proto(char *in_type, uint32_t in_seqno,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len);

/* Encode raw data into a kv pair */
simple_cap_proto_kv_t *encode_simple_cap_proto_kv(char *in_key, uint8_t *in_obj,
        unsigned int in_obj_len);

/* Encode a packet into a raw KV value suitable for being sent in a PACKET frame.
 * Buffer is returned in ret_buffer, length in ret_sz
 *
 * Returns:
 * -1   Failure
 *  1   Success
 *
 */
int pack_kv_capdata(uint8_t **ret_buffer, uint32_t *ret_sz,
        struct timeval in_ts, int in_dlt, uint32_t in_pack_sz, uint8_t *in_pack);

/* Encode a GPS frame into a raw KV suitable for being sent in a PACKET frame 
 * Buffer is returned in ret_buffer, length in ret_sz
 *
 * Returns:
 * -1   Failure
 *  1   Success
 */
int pack_kv_gps(uint8_t **ret_buffer, uint32_t *ret_sz,
        double in_lat, double in_lon, double in_alt, double in_speed, double in_heading,
        double in_precision, int in_fix, time_t in_time, 
        char *in_gps_type, char *in_gps_name);

/* Encode a list response frame into a raw KV suitable for being set int a 
 * LISTRESP frame.  
 * Buffer is returned in ret_buffer, length in ret_sz
 *
 * Interfaces and Options are expected to be of identical lengths; if an 
 * interface has no corresponding OPTIONS element, it should have a NULL in
 * that slot.
 *
 * Returns:
 * -1   Failure
 *  1   Success
 *
 */
int pack_kv_interfacelist(uint8_t **ret_buffer, uint32_t *ret_sz,
        const char **interfaces, const char **options, size_t len);

#endif

