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

/* Minimal common protocol header to derive version */
struct kismet_external_frame_stub {
    uint32_t signature;
    uint16_t proto_sentinel;
    uint16_t proto_version;
    uint32_t data_sz;
} __attribute__((packed));
typedef struct kismet_external_frame_stub kismet_external_frame_stub_t;

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

    /* Length of data component of frame, not including this header */
    uint32_t length;

    /* V3 content */
    uint16_t pkt_type;
    /* Success/fail code, if relevant; otherwise 0 and padding */
    uint16_t code;

    /* sequence, if applicable */
    uint32_t seqno;

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
 *    The v3 data blob is a msgpack packed map of integer field IDs mapped
 *    to msgpacked data.
 *
 *    Fields are keyed by number, as defined below, for optimization of
 *    the packing and comparison steps.
 *
 *    Field numbers must never be reused, but can be retired in future
 *    revisions.
 *
 *    Field numbers are grouped by block and sub-block, and are determined
 *    by the packet type or sub-block type.
 *
 * v3 sub-blocks
 *
 *    Some fields are defined as sub-blocks; a sub block is serialzied as
 *    a msgpack map of integer field IDs to msgpack values.
 *
 *    Sub-block field IDs are determined by the sub-block type.
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
 *  data = [msgpack map]
 *      MSG_FIELD_TYPE = uint8
 *      MSG_FIELD_MESSAGE = string
 *
 *
 * Example data with sub-blocks:
 *
 * pkt_type = KDS_PACKET
 * data = [msgpack map]
 *      FIELD_SIGNALBLOCK = [msgpack map]
 *          SIGNAL_FIELD_DBM = uint8
 *          SIGNAL_FIELD_FREQ_KHZ = uint32
 *      FIELD_PACKETBLOCK = [msgpack map ]
 *          PACKET_FIELD_DLT = uint32
 *          PACKET_FIELD_TS = uint64
 *          PACKET_FIELD_LENGTH = uint32
 *          ...
 *      ...
 *      -- End of packet sub block --
 *
 */


/* core commands */
#define KIS_EXTERNAL_V3_CMD_REGISTER                            1
#define KIS_EXTERNAL_V3_CMD_PING                                2
#define KIS_EXTERNAL_V3_CMD_PONG                                3
#define KIS_EXTERNAL_V3_CMD_SHUTDOWN                            4
#define KIS_EXTERNAL_V3_CMD_MESSAGE                             5
#define KIS_EXTERNAL_V3_CMD_ERROR                               6


/* datasource commands */
#define KIS_EXTERNAL_V3_KDS_PROBEREQ                            10
#define KIS_EXTERNAL_V3_KDS_PROBEREPORT                         11
#define KIS_EXTERNAL_V3_KDS_OPENREQ                             12
#define KIS_EXTERNAL_V3_KDS_OPENREPORT                          13
#define KIS_EXTERNAL_V3_KDS_LISTREQ                             14
#define KIS_EXTERNAL_V3_KDS_LISTREPORT                          15
#define KIS_EXTERNAL_V3_KDS_PACKET                              16
#define KIS_EXTERNAL_V3_KDS_CONFIGREQ                           17
#define KIS_EXTERNAL_V3_KDS_CONFIGREPORT                        18
#define KIS_EXTERNAL_V3_KDS_NEWSOURCE                           19

/* eventbus commands */
#define KIS_EXTERNAL_V3_EVT_REGISTER                            32
#define KIS_EXTERNAL_V3_EVT_EVENT                               33
#define KIS_EXTERNAL_V3_EVT_PUBLISH                             34

/* web proxy commands */
#define KIS_EXTERNAL_V3_WEB_REGISTERURI                         64
#define KIS_EXTERNAL_V3_WEB_REQUEST                             65
#define KIS_EXTERNAL_v3_WEB_REQUEST_CANCEL                      66
#define KIS_EXTERNAL_V3_WEB_RESPONSE                            67
#define KIS_EXTERNAL_V3_WEB_AUTHREQ                             68
#define KIS_EXTERNAL_V3_WEB_AUTHRESP                            69

/* Generic sub-blocks used in external and datasources */

/* Message sub block */
/* u8 */
#define KIS_EXTERNAL_V3_SUB_MESSAGE_FIELD_TYPE                  1
/* string */
#define KIS_EXTERNAL_V3_SUB_MESSAGE_FIELD_STRING                2

/* message types */
#define KIS_EXTERNAL_V3_MSG_DEBUG                               1
#define KIS_EXTERNAL_V3_MSG_INFO                                2
#define KIS_EXTERNAL_V3_MSG_ERROR                               4
#define KIS_EXTERNAL_V3_MSG_ALERT                               8
#define KIS_EXTERNAL_V3_MSG_FATAL                               16


/* Shutdown command
 * KS <-> External
 * Initiate a shutdown of this connection, with optional message
 */
/* string */
#define KIS_EXTERNAL_V3_SHUTDOWN_FIELD_REASON                   1


/* KIS_EXTERNAL_V3_CMD_REGISTER
 * External -> KS
 *
 * Register a helper/datasource/etc
 */
/* string */
#define KIS_EXTERNAL_V3_REGISTER_FIELD_SUBSYSTEM                1


/* KIS_EXTERNAL_V3_CMD_PING - no content required */
/* KIS_EXTERNAL_V3_CMD_PONG - no content required */


/* KIS_EXTERNAL_V3_CMD_MESSAGE
 * KS <-> External
 *
 * Wrap the message subblock as a single frame
*/
/* u8 */
#define KIS_EXTERNAL_V3_MESSAGE_FIELD_TYPE                      1
/* string */
#define KIS_EXTERNAL_V3_MESSAGE_FIELD_STRING                    2


/* KIS_EXTERNAL_V3_CMD_ERROR
 * KS <-> External
 *
 * sequence number in frame header references the request which
 * failed, or 0
 *
 * error code in frame header contains the error result
 */
/* string */
#define KIS_EXTERNAL_V3_ERROR_FIELD_STRING                      1


/* Datasource specific commands and sub-blocks */


/* KDS_CHANNEL_HOP_BLOCK
 *
 * Channel hop directive
 */
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE              1
/* bool */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE           2
/* uint16 */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP              3
/* uint16 */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET            4
/* array[string] */
#define KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHAN_LIST         5


/* KDS_CHANNEL_GPS_BLOCK */
/* double */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LAT                   1
/* double */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LON                   2
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT                   3
/* u8 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_FIX                   4
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_SPEED                 5
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_HEADING               6
/* float */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_PRECISION             7
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_S                  8
/* u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_US                 9
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE                  10
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_NAME                  11
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_UUID                  12

/* Estimate length from gps record */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN(l, g) \
    { \
        l += 8 + 8 + 4 + 1 + 4 + 4 + 4 + 8 + 4; \
        if (g->gps_name != NULL) l += strlen(g->gps_name); \
        if (g->gps_type != NULL) l += strlen(g->gps_type); \
    }

/* Estimate length with specific names */
#define KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN2(l, t, n) \
    { \
        l += 8 + 8 + 4 + 4 + 4 + 4 + 8 + 4; \
        if (n != NULL) l += strlen(n); \
        if (t != NULL) l += strlen(t); \
    }

/* KDS_INTERFACE_BLOCK */
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_IFACE           1
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_FLAGS           2
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_HW              3
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_CAPIFACE        4
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_CHANNEL         5
/* array[string] */
#define KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_CHAN_LIST       6


/* Spectrum sub block TBD */


/* KDS_SIGNAL_BLOCK  */
/* u32 signal dbm */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_DBM         1
/* u32 noise dbm */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_DBM          2
/* u32 signal rssi */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_RSSI        3
/* u32 noise rssi */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_RSSI         4
/* u64 frequency in khz */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_FREQ_KHZ           5
/* u64 data rate, in whatever the datasource thinks data rat */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_DATARATE           6
/* string */
#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_CHANNEL            7

#define KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_EST_LEN(v, s)      \
    { \
        v += 4 + 4 + 4 + 4 + 8 + 8; \
        if (s->channel != NULL) v += strlen(s->channel); \
    }


/* KDS_PACKET_BLOCK */
/* u32 DLT */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_DLT                1
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_S               2
/* u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_US              3
/* u32 original reported length of full packet, may be
 * longer than the captured length */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_LENGTH             4
/* string/binary */
#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_CONTENT             6

#define KIS_EXTERNAL_V3_KDS_SUB_PACKET_EST_LEN(v, cl) \
    { \
        v += 4 + 8 + 4 + cl; \
    }


/* KDS_JSON_BLOCK */
/* string, type/identifier */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TYPE                 1
/* u64 */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TS_S                 2
/* u32 */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TS_US                3
/* string, json blob */
#define KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON                 4

#define KIS_EXTERNAL_V3_KDS_SUB_JSON_EST_LEN(v, t, j) \
    { \
        v += 8 + 4 + strlen(t) + strlen(j); \
    }


/* KIS_EXTERNAL_V3_KDS_PACKET
 *
 * datasource data report
 *
 * datasource -> KS
 * sends packet or packet-like data to the Kismet server
 */
/* gps sub-block */
#define KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_GPSBLOCK          1
/* signal sub-block */
#define KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_SIGNALBLOCK       2
/* spectrum sub-block (currently not defined or implemented) */
#define KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_SPECTRUMBLOCK     3
/* packet sub-block */
#define KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_PACKETBLOCK       4
/* json sub-block */
#define KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK         5



/* KIS_EXTERNAL_V3_KDS_PROBEREQ
 *
 * KS -> Datasource
 *
 * Does this datasource handle this source definition?
 * */
/* string */
#define KIS_EXTERNAL_V3_KDS_PROBEREQ_FIELD_DEFINITION           1



/* KIS_EXTERNAL_V3_KDS_PROBEREPORT
 *
 * Datasource -> KS
 * Sequence and success code set in top-level header
 * */
/* u32 */
#define KIS_EXTERNAL_V3_KDS_PROBEREPORT_FIELD_SEQNO             1
/* interface sub-block */
#define KIS_EXTERNAL_V3_KDS_PROBEREPORT_FIELD_INTERFACE         2
/* stirng */
#define KIS_EXTERNAL_V3_KDS_PROBEREPORT_FIELD_MSG               3



/* KIS_EXTERNAL_V3_KDS_OPENREQ
 *
 * KS -> Datasource
 * Open the defined datasource
 * */
/* source definition, as string */
#define KIS_EXTERNAL_V3_KDS_OPENREQ_FIELD_DEFINITION            1



/* KIS_EXTERNAL_V3_KDS_OPENREPORT
 *
 * Datasource -> KS
 * Sequence and success code set in top-level header
 * */
/* uint32 */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_SEQNO              1
/* uint32, dlt if opened as a single type */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_DLT                2
/* string, capture interface resolved */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CAPIF              3
/* configured channels, as array[string] */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CHAN_LIST          4
/* single channel as string */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CHANNEL            5
/* channel hop sub-block */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CHANHOPBLOCK       6
/* string */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_HARDWARE           7
/* string */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_UUID               8
/* string */
#define KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_MSG                9



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
 */

/* uint32 */
#define KIS_EXTERNAL_V3_KDS_LISTREPORT_FIELD_SEQNO              1
/* Array of instances of interface sub blocks */
#define KIS_EXTERNAL_V3_KDS_LISTREPORT_FIELD_IFLIST             2
/* string */
#define KIS_EXTERNAL_V3_KDS_LISTREPORT_FIELD_MSG                3


/* KIS_EXTERNAL_V3_KDS_CONFIGURE
 *
 * KS -> Datasource
 *
 * Configure channel behavior
 */

/* string */
#define KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANNEL             1
/* hopping sub-block */
#define KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANHOPBLOCK        2
/* todo: spectrum */


/* KIS_EXTERNAL_V3_KDS_CONFIGREPORT
 *
 * Datasource -> KS
 */
/* uin32 */
#define KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_SEQNO            1
/* string */
#define KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_CHANNEL          2
/* channel hop block */
#define KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_CHANHOPBLOCK     3
/* string */
#define KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_MSG              4


/* KIS_EXTERNAL_V3_KDS_NEWSOURCE
 *
 * Datasource -> KS
 */
/* string */
#define KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_DEFINITION          1
/* string */
#define KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_SOURCETYPE          2
/* string */
#define KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_UUID                3


/* KIS_EXTERNAL_V3_EVT_REGISTER
 *
 * remote -> KS
 */
/* array[string] */
#define KIS_EXTERNAL_V3_EVT_EVENTREGISTER_FIELD_EVENT           1

/* KIS_EXTERNAL_V3_EVT_EVENT
 *
 * KS -> remote
 */
#define KIS_EXTERNAL_V3_EVT_EVENT_FIELD_EVENT                   1

/* KIS_EXTERNAL_V3_EVT_EVTPUBLISH
 *
 * remote -> KS
 */
/* string */
#define KIS_EXTERNAL_V3_EVT_EVENTPUBLISH_FIELD_TYPE             1
/* string */
#define KIS_EXTERNAL_V3_EVT_EVENTPUBLISH_FIELD_EVENT            2


/* KIS_EXTERNAL_V3_WEB_REGISTERURI
 *
 * remote -> KS
 */
/* string */
#define KIS_EXTERNAL_V3_WEB_REGISTERURI_FIELD_URI               1
/* string */
#define KIS_EXTERNAL_V3_WEB_REGISTERURI_FIELD_METHOD            2

/* KIS_EXTERNAL_V3_WEB_REQUEST
 *
 * ks -> remote
 */
/* uint32 */
#define KIS_EXTERNAL_V3_WEB_REQUEST_FIELD_REQID                 1
/* string */
#define KIS_EXTERNAL_V3_WEB_REQUEST_FIELD_URI                   2
/* string */
#define KIS_EXTERNAL_V3_WEB_REQUEST_FIELD_METHOD                3
/* map[string,string] */
#define KIS_EXTERNAL_V3_WEB_REQUEST_FIELD_VARIABLES             4

/* KIS_EXTERNAL_V3_WEB_REQUEST_CANCEL
 *
 * ks -> remote
 */
/* uint32 */
#define KIS_EXTERNAL_V3_WEB_REQUEST_CANCEL_FIELD_REQID          1

/* KIS_EXTERNAL_V3_WEB_RESPONSE
 *
 * remote -> ks
 */
/* uint32 */
#define KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_REQID                1
/* map[string, string] */
#define KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_HEADERS              2
/* string */
#define KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_CONTENT              3
/* uint32 */
#define KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_RESULTCODE           4
/* bool */
#define KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_CLOSE                5

/* KIS_EXTERNAL_V3_WEB_AUTHREQ
 *
 * remote -> ks
 *
 * no content
 *
 */

/* KIS_EXTERNAL_V3_WEB_AUTHRESP
 *
 * ks -> remote
 */
/* string */
#define KIS_EXTERNAL_V3_WEB_AUTHRESP_FIELD_TOKEN                1



/* Error codes from capture binaries */
#define KIS_EXTERNAL_RETCODE_OK             0
#define KIS_EXTERNAL_RETCODE_GENERIC        1
#define KIS_EXTERNAL_RETCODE_ARGUMENTS      2
#define KIS_EXTERNAL_RETCODE_FORK           3
#define KIS_EXTERNAL_RETCODE_TCP            4
#define KIS_EXTERNAL_RETCODE_WEBSOCKET      5
#define KIS_EXTERNAL_RETCODE_WSCOMPILE      6

#endif

