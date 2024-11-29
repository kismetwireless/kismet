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

#ifndef __KIS_EXTERNAL_PACKET_H__
#define __KIS_EXTERNAL_PACKET_H__

/* Kismet external API packets are wrapped in a simple framing system to 
 * transmit them over TCP or IPC channels.  For the complete interface, see:
 *
 * docs/dev/helper_interface.md
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>

#ifndef KIS_EXTERNAL_PROTO_SIG
#define KIS_EXTERNAL_PROTO_SIG    0xDECAFBAD
#endif

/* Basic proto header/wrapper */
struct kismet_external_frame {
    /* Fixed Start-of-packet signature, big endian */
    uint32_t signature;
    /* Basic adler32 checksum of packet data */
    uint32_t data_checksum;
    /* Size of data payload */
    uint32_t data_sz;
    /* Packet content, defined as a protobuf in protobuf_definitions/kismet.proto */
    uint8_t data[0];
} __attribute__((packed));
typedef struct kismet_external_frame kismet_external_frame_t;

/* v2 protocol - a more efficient representation of the protobuf stacking
 * that optimizes serialization and prevents double-serialization, enabling
 * direct serialization into a zero-copy buffer */
#define KIS_EXTERNAL_V2_SIG         0xABCD
struct kismet_external_frame_v2 {
    /* Fixed Start-of-packet signature, big endian */
    uint32_t signature;

    /* Fixed v2 sentinel 0xABCD, taking the place of the original checksum */
    uint16_t v2_sentinel;
    /* v2+ version code */
    uint16_t frame_version;

    /* Size of data payload encoded in data[0], retained in this position for 
     * compatibility with previous frame */
    uint32_t data_sz;

    /* Frame type (previously encoded in the external command) */
    char command[32];

    /* Sequence number */
    uint32_t seqno;

    /* Encoded payload */
    uint8_t data[0];
} __attribute__((packed));
typedef struct kismet_external_frame_v2 kismet_external_frame_v2_t;

/* all v3 multi-byte fields are sent as network endian */

#define KIS_EXTERNAL_V3_SIG         0xA9A9
typedef struct kismet_external_frame_v3 {
    /* Common Kismet signature */
    uint32_t signature;

    /* V3 signature and version */
    uint16_t v3_sentinel;
    uint16_t v3_version;

    /* V3 content */
    uint16_t pkt_type;
    uint16_t pad0;

    /* sequence, if applicable */
    uint32_t seqno;

    /* Success/fail code, if relevant; otherwise 0 and padding */
    uint16_t code;
    /* Length of packet, *including this header length* to account for 
     * repeated fieldset blocks expanding the header. */
    uint16_t length;

    /* Primary field set (for this packet type).  
     * Sub blocks may contain additional field sets.
     * 
     * If an overflow is indicated, additional field sets will be placed immediately
     * following the first fieldset, before the data fields.
     */
    uint32_t fieldset;

    /* Blob containing fields; fields are encoded in the order they are defined, and aligned to 32bits */
    uint8_t data[0];
} __attribute__((packed)) kismet_external_frame_v3_t;

/* Sub-block header.  Sub-blocks are repeated groups of fields
 * used in multiple messages.  Sub blocks are treated as a complete
 * field at the top level. */
typedef struct _kismet_v3_sub_block {
    /* If the field set indicates an overflow, additional field sets will
     * follow this primary field set, before any additional fields. */
    uint32_t fieldset;

    /* sub-block length for validation */
    uint16_t length;
    uint16_t padding;

    uint8_t data[0];
} kismet_v3_sub_block;

/* strings are always represented as a u16 length aligned to 32 bit, followed by the string content,
 * also aligned to 32 bit.  Strings are always truncated to the specified length, so null termination is
 * optional. */
typedef struct _kismet_v3_sub_string {
    uint16_t length;
    uint16_t pad0;
    char data[0];
} kismet_v3_sub_string;

/* Double to fixed precision converters; the proper converter is picked for the data type used, and will be
 * documented in the field name.  Fixed representations are all 4 bytes. */

/* FIXED_3_6:  Error estimates, angular rotation, beamwidth, gain */
#define FLOAT_TO_FIXED3_6(flt)      ((uint32_t) (flt * 1000000))
#define FLOAT_FROM_FIXED3_6(fxd)    ((double) (fxd / (double) 1000000))

/* FIXED_3_7: Latitude and longitude */
#define FLOAT_TO_FIXED3_7(flt)      (((int32_t) ((flt) * (double) 10000000)) + ((int32_t) 180 * 10000000))
#define FLOAT_FROM_FIXED3_7(fxd)    ((double) ((double) (fxd - (180 * 10000000)) / 10000000))

/* Altitude, offsets, velocity, acceleration */
#define FLOAT_TO_FIXED6_4(flt)      ((uint32_t) (((int32_t) ((flt) * (double) 10000)) + ((int32_t) 180000 * 10000)))
#define FLOAT_FROM_FIXED6_4(fxd)    ((double) ((double) (fxd - (180000 * 10000)) / 10000))

/* core commands */
#define KIS_EXTERNAL_V3_CMD_REGISTER            1
#define KIS_EXTERNAL_V3_CMD_PING                2
#define KIS_EXTERNAL_V3 CMD_PONG                3
#define KIS_EXTERNAL_V3_CMD_SHUTDOWN            4
#define KIS_EXTERNAL_V3_CMD_MESSAGE             5

/* datasource commands */
#define KIS_EXTERNAL_V3_KDS_PROBEREQ        10
#define KIS_EXTERNAL_V3_KDS_PROBEREPORT     11
#define KIS_EXTERNAL_V3_KDS_OPENREQ         12
#define KIS_EXTERNAL_V3_KDS_OPENREPORT      13
#define KIS_EXTERNAL_V3_KDS_LISTREQ         14
#define KIS_EXTERNAL_V3_KDS_LISTREPORT      15
#define KIS_EXTERNAL_V3_KDS_PACKET          16

/* Overflow field flag common to all blocks */
#define KIS_EXTERNAL_V3_FIELD_OVERFLOW      (1 << 31)


/* string block */
#define KIS_EXTERNAL_V3_SHUTDOWN_STRING     (1 << 0)

/*
 *  Example command frame:
 *
 *  - Common frame
 *    uint32_t signature;
 *    uint16_t v3_sentinel;
 *    uint16_t v3_version;
 *    uint16_t pkt_type = 11; - PROBE_REPORT
 *    uint16_t pad0;
 *    uint32_t seqno;
 *    uint16_t code;
 *    uint16_t length; - total length 
 *
 *    uint32_t fieldset; - PROBE_REPORT fields =
 *      KIS_EXTERNAL_V3_KDS_PROBE_REPORT_SUB_MSG |
 *      KIS_EXTERNAL_V3_KDS_PROBE_REPORT_SUB_CHANNELS |
 *      ...
 *
 *    - data
 *      - KIS_EXTERNAL_V3_KDS_PROBE_REPORT_SUB_MSG sub-block
 *      | uint32_t fieldset; - MSG subblock fields =
 *      |   KIS_EXTERNAL_V3_SUB_MESSAGE_TYPE |
 *      |   KIS_EXTERNAL_V3_SUB_MESSAGE_STRING
 *      | uint16_t length; - length of subblock
 *      | uint16_t padding;
 *      | - sub_data
 *      |   - uint32_t sub_msg_type; - MSG_INFO etc
 *      |   - uint16_t msg_str_len;
 *      |   - uint16_t msg_str_pad;
 *      |   - uint8_t msg[...];
 *      | - padding (allocated and zeroed to 4-byte boundary
 *      - KIS_EXTERNAL_V3_KDS_PROBE_REPORT_SUB_CHANNELS block
 *      | - uint32_t fieldset; SUB_CHANNELS fieldset =
 *      |   KIS_EXTERNAL_V3_SUB_CHANLIST_STRING
 *      | - uint16_t length; - length of sub
 *      | - uint16_t padding;
 *      | - sub data
 *      |   - uint16_t stringlen
 *      |   - uint16_t pad
 *      |   - uint8_t msg[...];
 *      |   - padding (allocated and zeroed to 4-byte boundary)
 */

/* Generic sub-blocks */

/* Message sub block */
/* u8, aligned to u32 */
#define KIS_EXTERNAL_V3_SUB_MESSAGE_FIELD_TYPE        (1 << 0)
/* string block */
#define KIS_EXTERNAL_V3_SUB_MESSAGE_FIELD_STRING      (1 << 1)

/* Sub-blocks used in datasources
 *
 * Sub blocks are defined as a set of fields and are used as
 * building blocks of larger reports.
 *
 * This prevents large repeated lists of field types.
 *
 * A sub-block is always aligned to the nearest 4 byte value.
 *
 * Sub blocks are encoded as kismet_v3_sub_block structs
 */


/* message types */
#define KIS_EXTERNAL_V3_MSG_DEBUG           1
#define KIS_EXTERNAL_V3_MSG_INFO            2
#define KIS_EXTERNAL_V3_MSG_ERROR           4
#define KIS_EXTERNAL_V3_MSG_ALERT           8
#define KIS_EXTERNAL_V3_MSG_FATAL           16

/* KIS_EXTERNAL_V3_CMD_REGISTER
 *
 * Register a helper
 */
/* string block */
#define KIS_EXTERNAL_V3_REGISTER_FIELD_SUBSYSTEM    (1 << 0)

/* KIS_EXTERNAL_V3_CMD_PING - no content required */
/* KIS_EXTERNAL_V3_CMD_PONG - no content required */

/* KIS_EXTERNAL_V3_CMD_SHUTDOWN
 *
 * Shut down the connection (KS->DS or DS->KS)
 */
/* string block */
#define KIS_EXTERNAL_V3_SHUTDOWN_FIELD_REASON       (1 << 0)

/* KIS_EXTERNAL_V3_CMD_MESSAGE
 *
 * Wrap the message subblock as a single frame
*/
/* u8, aligned to u32 */
#define KIS_EXTERNAL_V3_MESSAGE_FIELD_TYPE        (1 << 0)
/* string block */
#define KIS_EXTERNAL_V3_MESSAGE_FIELD_STRING      (1 << 1)

/* KDS_CHANNEL_HOP_BLOCK
 *
 * Channel hop directive
 */
/* string block */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHANNEL       (1 << 0)
/* float6_4, u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE          (1 << 1)
/* u8, aligned as u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE       (1 << 2)
/* u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP          (1 << 3)
/* u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET        (1 << 4)

/* KIDS_CHANNEL_GPS_BLOCK */
/* float3_7, u32 lat, float3_t, u32 lon, u64 total */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_2D                (1 << 0)
/* float6_4 u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT               (1 << 1)
/* float6_4 u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_SPEED             (1 << 2)
/* float3_6 u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_HEADING           (1 << 3)
/* float3_6 u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_PRECISION         (1 << 4)
/* u64+u64 time_sec time_usec */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TIMESTAMP         (1 << 5)
/* string block */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE              (1 << 6)
/* string block */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_NAME              (1 << 7)

/* KDS_INTERFACE_BLOCK */
/* string block */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_IFACE       (1 << 0)
/* string block */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_FLAGS       (1 << 1)
/* string block */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_HW          (1 << 2)
/* string block */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_CAPIFACE    (1 << 3)

/* Spectrum sub block TBD */

/* KDS_SIGNAL_BLOCK  */
/* u32 signal dbm */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_DBM     (1 << 0)
/* u32 noise dbm */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_DBM      (1 << 1)
/* u32 signal rssi */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_RSSI    (1 << 2)
/* u32 noise rssi */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE RSSI     (1 << 3)
/* u64 frequency in khz */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_FREQ_KHZ       (1 << 4)
/* u64 data rate, in whatever the datasource thinks data rat */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_DATARATE       (1 << 5)
/* string block, channel as defined by the source */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_CHANNEL        (1 << 6)

/* KDS_PACKET_BLOCK */
/* u32 DLT */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_DLT            (1 << 0)
/* u64+u64 sec:usec timestamp */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS             (1 << 1)
/* u32 reported length */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_LENGTH         (1 << 2)
/* u32 captured length */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_CAPLENGTH      (1 << 3)
/* *u8 padded to 32 boundary */
#define KIS_EXTERNA_V3_KDS_SUB_PACKET_FIELD_CONTENT         (1 << 4)

/* KDS_JSON_BLOCK */
/* string block, type/identifier */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TYPE             (1 << 0)
/* u64+u64 sec:usec timestamp */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TS               (1 << 1)
/* string block, json blob */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON             (1 << 2)


/* KIS_EXTERNAL_V3_KDS_PACKET
 *
 * datasource data report
 *
 * datasource -> KS
 * sends packet or packet-like data to the Kismet server
 */
/* gps sub-block */
#define KIS_EXTERNAL_V3_KDS_DATA_REPORT_FIELD_GPSBLOCK      (1 << 0)
/* signal sub-block */
#define KIS_EXTERNAL_V3_KDS_DATA_REPORT_FIELD_SIGNALBLOCK   (1 << 1)
/* spectrum sub-block (currently not defined or implemented) */
#define KIS_EXTERNAL_V3_KDS_DATA_REPORT_FIELD_SPECTRUMBLOCK (1 << 2)
/* packet sub-block */
#define KIS_EXTERNAL_V3_KDS_DATA_REPORT_FIELD_PACKETBLOCK   (1 << 3)
/* json sub-block */
#define KIS_EXTERNAL_V3_KDS_DATA_REPORT_FIELD_JSONBLOCK     (1 << 4)



/* KIS_EXTERNAL_V3_KDS_PROBEREQ
 *
 * KS -> Datasource
 *
 * Does this datasource handle this source definition?
 * */
/* string block */
#define KIS_EXTERNAL_V3_KDS_PROBEREQ_FIELD_DEFINITON        (1 << 0)


/* KIS_EXTERNAL_V3_KDS_PROBEREPORT
 *
 * Datasource -> KS
 * Sequence and success code set in top-level header
 * */
/* message sub-block */
#define KIS_EXTERNAL_V3_KDS_PROBE_REPORT_FIELD_MSGBLOCK     (1 << 0)
/* channels as string */
#define KIS_EXTERNAL_V3_KDS_PROBE_REPORT_FIELD_CHANNELS     (1 << 1)
/* single channel as string */
#define KIS_EXTERNAL_V3_KDS_PROBE_REPORT_FIELD_CHANNEL      (1 << 2)
/* channel hop sub-block */
#define KIS_EXTERNAL_V3_KDS_PROBE_REPORT_FIELD_CHANHOPBLOCK (1 << 3)


/* KIS_EXTERNAL_V3_KDS_OPENREQ
 *
 * KS -> Datasource
 * Open the defined datasource
 * */
/* source definition, as string */
#define KIS_EXTERNAL_V3_KDS_OPENREQ_FIELD_SOURCEDEFINITION  (1 << 0)


/* KIS_EXTERNAL_V3_KDS_OPENREPORT
 *
 * Datasource -> KS
 * Sequence and success code set in top-level header
 * */
/* uint32, dlt if opened as a single type */
#define KIS_EXTERNAL_V3_KDS_OPEN_REPORT_FIELD_DLT                 (1 << 0)
/* string, capture interface resolved */
#define KIS_EXTERNAL_V3_KDS_OPEN_REPORT_FIELD_CAPIF               (1 << 1)
/* configured channels, as comma string */
#define KIS_EXTERNAL_V3_KDS_OPEN_REPORT_FIELD_CHANNELS            (1 << 2)
/* single channel as string */
#define KIS_EXTERNAL_V3_KDS_OPEN_REPORT_FIELD_CHANNEL             (1 << 3)
/* channel hop sub-block */
#define KIS_EXTERNAL_V3_KDS_OPEN_REPORT_FIELD_CHANHOPBLOCK        (1 << 4)
/* string */
#define KIS_EXTERNAL_V3_KDS_OPEN_REPORT_FIELD_HARDWARE            (1 << 5)
/* string */
#define KIS_EXTERNAL_V3_KDS_OPEN_REPORT_FIELD_UUID                (1 << 6)


/* KIS_EXTERNAL_V3_KDS_LISTREQ
 *
 * KS -> Datasource
 *
 * Request a list of all interfaces supported by this datasource.
 *
 * No content.
 */


/* KIS_EXTERNAL_V3_KDS_LISTREPORT
 *
 * Datasource -> KS
 *
 * Contains multiple (as defined by the number of results field) interface
 * report sub-blocks
 * */

/* uint32 */
#define KIS_EXTERNAL_V3_KDS_LIST_REPORT_FIELD_NUMIFS        (1 << 0)
/* Array of [N] instances of interface sub blocks */
#define KDS_INTERNAL_V3_KDS_LIST_REPORT_FIELD_IFLIST        (1 << 1)



/* Generic padding calculator */
#define ks_proto_v3_pad(x)  (x + (x % 4))

/* Calculate the size of a string block */
size_t ks_proto_v3_strblock_padlen(size_t str_length);


/* Error codes from capture binaries */
#define KIS_EXTERNAL_RETCODE_OK             0
#define KIS_EXTERNAL_RETCODE_GENERIC        1
#define KIS_EXTERNAL_RETCODE_ARGUMENTS      2
#define KIS_EXTERNAL_RETCODE_FORK           3
#define KIS_EXTERNAL_RETCODE_TCP            4
#define KIS_EXTERNAL_RETCODE_WEBSOCKET      5
#define KIS_EXTERNAL_RETCODE_WSCOMPILE      6

#endif

