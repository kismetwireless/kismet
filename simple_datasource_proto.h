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

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

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
    uint8_t object[0];
} __attribute__((packed));
typedef struct simple_cap_proto_kv simple_cap_proto_kv_t;

/* Basic proto header/wrapper */
struct simple_cap_proto {
    /* Fixed Start-of-packet signature */
    uint32_t signature;
    /* Basic adler32 checksum of header data, calculated with both header and data
     * checksum set to zero */
    uint32_t header_checksum;
    /* Basic adler32 checksum of packet data, calculated with checksum set to zero */
    uint32_t data_checksum;
    /* Total size of packet including signature and checksum */
    uint32_t packet_sz;
    /* Sequence number (sender) */
    uint32_t sequence_number;
    /* Type of packet */
    char type[16];
    /* Number of KV pairs */
    uint32_t num_kv_pairs;
} __attribute__((packed));
typedef struct simple_cap_proto simple_cap_proto_t;

struct simple_cap_proto_frame {
    simple_cap_proto_t header;
    /* List of kv pairs */
    uint8_t data[0];
} __attribute__((packed));
typedef struct simple_cap_proto_frame simple_cap_proto_frame_t;

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

/* Adler32 checksum */
uint32_t adler32_csum(uint8_t *in_buffer, size_t in_len);

/* Incremental adler32; to compute a checksum over multiple chunks, the caller
 * must preserve s1 and s2 and provide them to each incremental call.
 * The first call must set s1 and s2 to 0.
 */
uint32_t adler32_partial_csum(uint8_t *in_buf, size_t in_len,
        uint32_t *s1, uint32_t *s2); 

/* Encode a KV list into a packet; DOES NOT free any supplied data, and performs a
 * memcpy of all the data into a single record.
 *
 * For more efficient methods with fewer memcpy operations, look at
 * encode_simple_cap_proto_header(..)
 *
 * Returns:
 * Pointer to data
 * NULL on failure
 */
simple_cap_proto_frame_t *encode_simple_cap_proto(const char *in_type, uint32_t in_seqno,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len);

/* Encode a KV list into a packet *header*.  This allocates *only a buffer for the
 * packet header*, and does not memcpy any data.
 *
 * The total size of the packet is returned in ret_sz.  The returned buffer is the
 * size of *a header only*
 *
 * This function should be used to prepare a packet for writing to a streaming
 * buffer - the caller can prepare the packet header and then write the streaming
 * content out itself rather than cause a full memcpy of the entire frame.
 *
 * Returns:
 * Pointer to data
 * NULL on failure
 */
simple_cap_proto_t *encode_simple_cap_proto_hdr(size_t *ret_sz, 
        const char *in_type, uint32_t in_seqno,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len);

/* Encode raw data into a kv pair.  Copies provided data, and DOES NOT free or
 * modify the original buffers.
 *
 * Returns:
 * Pointer on success
 * NULL on failure
 */
simple_cap_proto_kv_t *encode_simple_cap_proto_kv(const char *in_key, uint8_t *in_obj,
        size_t in_obj_len);

/* Encode a simple success response
 *
 * Returns:
 * Pointer on success
 * NULL on failure
 */
simple_cap_proto_kv_t *encode_kv_success(unsigned int success, uint32_t sequence);

/* Encode a simple warning KV
 *
 * Returns:
 * Pointer on success
 * NULL on failure
 */
simple_cap_proto_kv_t *encode_kv_warning(const char *warning);

/* Encode source type KV
 *
 * Returns:
 * Pointer on success
 * NULL on failure
 */
simple_cap_proto_kv_t *encode_kv_sourcetype(const char *sourcetype);

/* Encode source definition KV
 *
 * Returns:
 * Pointer on success
 * NULL on failure
 */
simple_cap_proto_kv_t *encode_kv_definition(const char *definition);

/* Encode a source hardware KV
 *
 * Returns:
 * Pointer on success
 * NULL on failure 
 */
simple_cap_proto_kv_t *encode_kv_hardware(const char *hardware);

/* Encode a chanset response
 *
 * Returns:
 * Pointer on success
 * NULL on failure 
 */
simple_cap_proto_kv_t *encode_kv_chanset(const char *channel);

/* Encode a uuid response
 *
 * Returns:
 * Pointer on success
 * NULL on failure 
 */
simple_cap_proto_kv_t *encode_kv_uuid(const char *uuid);

/* Encode a capif response
 *
 * Returns:
 * Pointer on success
 * NULL on failure
 */
simple_cap_proto_kv_t *encode_kv_capif(const char *capif);

/* Encode a packet into a PACKET KV
 *
 * Returns:
 * Pointer on success
 * Null on failure
 *
 */
simple_cap_proto_kv_t *encode_kv_capdata(struct timeval in_ts, 
        uint32_t in_pack_sz, uint8_t *in_pack);

/* Encode a GPS KV
 *
 * This should only be needed when the GPS data is not encoded in the DLT already.
 * For instance, it's not recommended to parse a PPI header and extract embedded
 * GPS data, then encode as a GPS KV pair; instead, pass the entire radiotap packet
 * to Kismet.
 *
 * This is best used for remote capture drivers with independent GPS or a fixed GPS
 * location.
 *
 * Returns:
 * Pointer on success
 * Null on failure
 */
simple_cap_proto_kv_t *encode_kv_gps(double in_lat, double in_lon, double in_alt, 
        double in_speed, double in_heading,
        double in_precision, int in_fix, time_t in_time, 
        char *in_gps_type, char *in_gps_name);

/* Encode a SIGNAL KV
 *
 * This should only be needed when the signal data is not encoded in the DLT already.
 * For instance, it's not recommended to parse a radiotap header from a capture and
 * encode the signal information here - simply pass the radiotap packet with the 
 * proper DLT to Kismet.
 *
 * This is best used in situations where there is no embedded signal data in the packet
 * record.
 *
 * returns:
 * Pointer on success
 * Null on failure
 *
 */
simple_cap_proto_kv_t *encode_kv_signal(int32_t signal_dbm, uint32_t signal_rssi, 
        int32_t noise_dbm, uint32_t noise_rssi, double freq_khz, char *channel, 
        double datarate);

/* Encode an arbitrary complex KV field list
 *
 * Expects:
 *
 * The KV key in 'key'
 * A list of fields, of length len_fields
 * A two-dimensional array of data, indexed by data[row][field]
 *
 * Produces:
 *
 * A KV pair consisting of an array of name:value string pairs, for
 * use with KV pairs such as the interface list
 *
 * Returns:
 * Pointer on success
 * Null on failure
 *
 */
simple_cap_proto_kv_t *encode_kv_arraylist(const char *key, const char **fields, size_t len_fields,
        char ***data, size_t len_data);

/* Encode a DLT KV
 *
 * Returns:
 * Pointer on success
 * Null on failure
 *
 */
simple_cap_proto_kv_t *encode_kv_dlt(unsigned int dlt);

/* Encode a single channel into a kv 
 *
 * Channel is an arbitrary string
 *
 * Returns:
 * Pointer on success
 * Null on failure
 */
simple_cap_proto_kv_t *encode_kv_channel(const char *channel);

/* Encode a list of channels into a raw KV
 *
 * Channels are arbitrary strings.
 *
 * Returns:
 * Pointer on success
 * Null on failure
 *
 */
simple_cap_proto_kv_t *encode_kv_channels(char **channels, size_t len);

/* Encode a CHANHOP KV pair
 *
 * Channels are arbitrary strings
 *
 * Returns:
 * Pointer on success
 * Null on failure
 *
 */
simple_cap_proto_kv_t *encode_kv_chanhop(double rate, char **channels, size_t len);

/* Encode a complex CHANHOP KV pair
 *
 * Channels are arbitrary strings.
 *
 * Returns:
 * Pointer on success
 * NULL on failure
 */
simple_cap_proto_kv_t *encode_kv_chanhop_complex(double rate, char **channels,
        size_t len, int shuffle, int shuffle_skip, int offset);

/* Encode a SPECSET KV pair
 *
 * Returns:
 * Pointer on success
 * NULL on failure
 */
simple_cap_proto_kv_t *encode_kv_specset(uint64_t start_mhz, uint64_t end_mhz, 
        uint64_t samples_per_freq, uint64_t bin_width, uint8_t amp,
        uint64_t if_amp, uint64_t baseband_amp);

#define MSGFLAG_NONE    0
#define MSGFLAG_DEBUG   1
#define MSGFLAG_INFO    2
#define MSGFLAG_ERROR   4
#define MSGFLAG_ALERT   8
#define MSGFLAG_FATAL   16
/* Encode a MESSAGE KV pair
 * Buffer is returned in ret_buffer, length in ret_sz
 *
 * Returns:
 * Pointer on success
 * Null on failure
 *
 */
simple_cap_proto_kv_t *encode_kv_message(const char *message, unsigned int flags);


/* Validate if a header passes checksum
 *
 * Returns:
 * -1   Failure
 *  1   Success
 */
int validate_simple_cap_proto_header(simple_cap_proto_t *in_packet);

/* Validate if a complete frame passes checksum
 *
 * Returns:
 * -1   Failure
 *  1   Success
 */
int validate_simple_cap_proto(simple_cap_proto_t *in_packet);

/* Get the next KV from a simple cap proto frame.
 * If *last_kv is NULL, returns the first KV and populates *last_kv.  If
 * *last_kv is not NULL, returns the next KV pair.
 *
 * Returns pointer to key in *key or NULL in *key if no more KV pairs.
 *
 * Upon return, *last_kv points to the KV pair matching *key
 *
 * Return values:
 * -1   Failure
 *  0   No additional keys found
 *  1+  Length of the KV data object
 */
int get_simple_cap_proto_next_kv(simple_cap_proto_frame_t *in_packet, char **key,
        simple_cap_proto_kv_t **last_kv);

/* Find a KV in a simple cap proto frame.
 *
 * Returns pointer to the KV structure in *kv, or NULL if the value can't be
 * found.
 *
 * Returns values:
 * -1   Failure
 *  0   Key not found
 *  1+  Length of KV data object
 */
int find_simple_cap_proto_kv(simple_cap_proto_frame_t *in_packet, const char *key,
        simple_cap_proto_kv_t **kv);

#endif

