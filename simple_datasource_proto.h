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
    /* Type of packet */
    char type[16];
    /* Number of KV pairs */
    uint32_t num_kv_pairs;
    /* List of kv pairs */
    uint8_t *data;
} __attribute__((packed));
typedef struct simple_cap_proto simple_cap_proto_t;

/* Encode a KV list */
simple_cap_proto_t *encode_simple_cap_proto(char *in_type, 
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len);

/* Encode data into a kb pair */
simple_cap_proto_kv_t *encode_simple_cap_proto_kv(char *in_key, uint8_t *in_obj,
        unsigned int in_obj_len);

#endif

