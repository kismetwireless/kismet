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

#define KIS_EXTERNAL_V3_SIG         0xA9A9
typedef struct kismet_external_frame_v3 {
    /* v3 fields sent as network endian. 
     * v3 content sent as a msgpack blob.
     */

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
    /* Length of data component of frame, not including this header */
    uint16_t length;

    /* msgpack content */
    uint8_t data[0];
} __attribute__((packed)) kismet_external_frame_v3_t;


/* 
 * v3 replaces protobufs with msgpack for a simpler mechanism serializing 
 * and deserializing, and to remove the compile time requirements from 
 * protobufs. 
 *
 * v3 header 
 *
 *    The v3 header is compatible with the v2 header in the first bytes, so that 
 *    a v2 processor will be able to detect that this is not a protocol for it 
 *    to handle. 
 *
 *    The packet type is converted to an integer to optimize comparisons and 
 *    transmission size. 
 *
 *    The header is aligned to 32bits for quicker extraction.
 *
 *    The error code is moved into the packet header, as room was available in 
 *    the padding regardless.
 *
 * v3 data content 
 *
 *    The v3 data blob is a msgpack packed element.  
 *    
 *    The first value in the data blob is a uint32 field set which indicates 
 *    what fields are being used. 
 *
 *    If more than 32 fields are required, the field overflow bit is set. 
 *    Additional field sets are then packed immediately after the current 
 *    field set. 
 *
 * v3 sub-blocks 
 *
 *    Some fields are defined as sub-blocks; a sub block is serialized in-line 
 *    at the field location.
 *
 *    A sub-block starts with a uint32 field set, with the same rules as the 
 *    top level field set.
 *
 *    The second field of a sub block is a uint32 length field so that parsers 
 *    can skip the remainder if they are unable to process it.
 *
 */

/* Example frame: 
 *
 *  uint32_t signature = 0xdecafbad;
 *  uint16_t v3_sentinel = 0xa9a9;
 *  uint16_t v3_version = 3;
 *  uint16_t pkt_type = CMD_MESSAGE;
 *  uint16_t pad0 = 0;
 *  uint32_t seqno = 0;
 *  uint16_t code = 0;
 *  uint16_t length = <length of msgpack stream>;
 *  data = [msgpack] 
 *      uint32 fieldset = MSG_FIELD_TYPE | MSG_FIELD_MESSAGE
 *      uint8 type 
 *      string message
 *
 *
 * Example data with sub-blocks: 
 * 
 * pkt_type = KDS_PACKET
 * data = [msgpack]
 *      uint32 fieldset = DATA_REPORT_FIELD_SIGNALBLOCK | DATA_REPORT_FIELD_PACKETBLOCK
 *      -- Start of signal sub block.  Each block gets a fieldset denoting the inner fields  -- 
 *      uint32 fieldset = SIGNAL_FIELD_DBM | SIGNAL_FIELD_FREQ_KHZ 
 *      uint32 signal 
 *      uint32 frequency 
 *      -- End of signal sub block --
 *      -- Start of packet sub block -- 
 *      uint32 fieldset = PACKET_FIELD_DLT | PACKET_FIELD_TS | PACKET_FIELD_LENGTH ...
 *      uint32 dlt 
 *      uint64 ts 
 *      uint32 Length 
 *      ...
 *      -- End of packet sub block --
 *
 */


/* core commands */
#define KIS_EXTERNAL_V3_CMD_REGISTER            1
#define KIS_EXTERNAL_V3_CMD_PING                2
#define KIS_EXTERNAL_V3_CMD_PONG                3
#define KIS_EXTERNAL_V3_CMD_SHUTDOWN            4
#define KIS_EXTERNAL_V3_CMD_MESSAGE             5
#define KIS_EXTERNAL_V3_CMD_ERROR               6


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
 */

/* Generic sub-blocks */

/* Message sub block */
/* u8 */
#define KIS_EXTERNAL_V3_SUB_MESSAGE_FIELD_TYPE        (1 << 0)
/* string */
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
/* string */
#define KIS_EXTERNAL_V3_REGISTER_FIELD_SUBSYSTEM    (1 << 0)

/* KIS_EXTERNAL_V3_CMD_PING - no content required */
/* KIS_EXTERNAL_V3_CMD_PONG - no content required */


/* KIS_EXTERNAL_V3_CMD_SHUTDOWN
 *
 * Shut down the connection (KS->DS or DS->KS)
 */
/* string */
#define KIS_EXTERNAL_V3_SHUTDOWN_FIELD_REASON       (1 << 0)


/* KIS_EXTERNAL_V3_CMD_MESSAGE
 *
 * Wrap the message subblock as a single frame
*/
/* u8 */
#define KIS_EXTERNAL_V3_MESSAGE_FIELD_TYPE          (1 << 0)
/* string */
#define KIS_EXTERNAL_V3_MESSAGE_FIELD_STRING        (1 << 1)


/* KIS_EXTERNAL_V3_CMD_ERROR 
 *
 * sequence number in frame header references the request which 
 * failed, or 0 
 *
 * error code in frame header contains the error result 
 */ 
/* string */
#define KIS_EXTERNAL_V3_ERROR_FIELD_STRING                  (1 << 0)


/* KDS_CHANNEL_HOP_BLOCK
 *
 * Channel hop directive
 */
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHANNEL       (1 << 0)
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE          (1 << 1)
/* bool */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE       (1 << 2)
/* uint16 */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP          (1 << 3)
/* uint16 */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET        (1 << 4)
/* array[string] */ 
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHANLIST      (1 << 5)


/* KIDS_CHANNEL_GPS_BLOCK */
/* double */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LAT               (1 << 0)
/* double */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LON               (1 << 1)
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT               (1 << 2)
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_SPEED             (1 << 3)
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_HEADING           (1 << 4)
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_PRECISION         (1 << 5)
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TIMESTAMP_S       (1 << 6)
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TIMESTAMP_US      (1 << 7)
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE              (1 << 8)
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_NAME              (1 << 9)


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
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_RSSI     (1 << 3)
/* u64 frequency in khz */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_FREQ_KHZ       (1 << 4)
/* u64 data rate, in whatever the datasource thinks data rat */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_DATARATE       (1 << 5)
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_CHANNEL        (1 << 6)


/* KDS_PACKET_BLOCK */
/* u32 DLT */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_DLT            (1 << 0)
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_S           (1 << 1)
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_US          (1 << 2)
/* u32 reported length */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_LENGTH         (1 << 3)
/* u32 captured length */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_CAPLENGTH      (1 << 4)
/* string/binary */
#define KIS_EXTERNA_V3_KDS_SUB_PACKET_FIELD_CONTENT         (1 << 5)


/* KDS_JSON_BLOCK */
/* string, type/identifier */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TYPE             (1 << 0)
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_S           (1 << 1)
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_US          (1 << 2)
/* string, json blob */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON             (1 << 3)


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
/* string */
#define KIS_EXTERNAL_V3_KDS_PROBEREQ_FIELD_DEFINITON        (1 << 0)



/* KIS_EXTERNAL_V3_KDS_PROBEREPORT
 *
 * Datasource -> KS
 * Sequence and success code set in top-level header
 * */
/* message sub-block */
#define KIS_EXTERNAL_V3_KDS_PROBE_REPORT_FIELD_MSGBLOCK     (1 << 0)
/* array[string] */
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

/* uint16, padded to 32 */
#define KIS_EXTERNAL_V3_KDS_LIST_REPORT_FIELD_NUMIFS        (1 << 0)
/* Array of [N] instances of interface sub blocks */
#define KIS_EXTERNAL_V3_KDS_LIST_REPORT_FIELD_IFLIST        (1 << 1)




/* Error codes from capture binaries */
#define KIS_EXTERNAL_RETCODE_OK             0
#define KIS_EXTERNAL_RETCODE_GENERIC        1
#define KIS_EXTERNAL_RETCODE_ARGUMENTS      2
#define KIS_EXTERNAL_RETCODE_FORK           3
#define KIS_EXTERNAL_RETCODE_TCP            4
#define KIS_EXTERNAL_RETCODE_WEBSOCKET      5
#define KIS_EXTERNAL_RETCODE_WSCOMPILE      6

#endif

