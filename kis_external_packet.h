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

#define KIS_EXTERNAL_PROTO_SIG    0xDECAFBAD

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

#define KIS_EXTERNAL_V2_SIG         0xABCD
/* v2 wrapper that makes for much more efficient serialization */
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

/* Error codes from capture binaries */
#define KIS_EXTERNAL_RETCODE_OK             0
#define KIS_EXTERNAL_RETCODE_GENERIC        1
#define KIS_EXTERNAL_RETCODE_ARGUMENTS      2
#define KIS_EXTERNAL_RETCODE_FORK           3
#define KIS_EXTERNAL_RETCODE_TCP            4
#define KIS_EXTERNAL_RETCODE_WEBSOCKET      5
#define KIS_EXTERNAL_RETCODE_WSCOMPILE      6

#endif

