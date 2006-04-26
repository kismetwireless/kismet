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

#ifndef __PACKETSTREAM_H__
#define __PACKETSTREAM_H__

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define STREAM_DRONE_VERSION 9

#define STREAM_SENTINEL      0xDECAFBAD

#define STREAM_FTYPE_VERSION 1
#define STREAM_FTYPE_PACKET  2

#define STREAM_COMMAND_FLUSH -1

typedef struct stream_frame_header {
    uint32_t frame_sentinel;
    uint8_t frame_type;
    uint32_t frame_len;
} __attribute__((__packed__));

typedef struct stream_version_packet {
    uint16_t drone_version;
	uint8_t gps_enabled;
};

typedef struct stream_packet_header {
    uint32_t header_len;
    uint16_t drone_version;
    uint32_t len;
    uint32_t caplen;
    uint64_t tv_sec;
    uint64_t tv_usec;
    uint16_t quality;
    uint16_t signal;
    uint16_t noise;
    uint8_t error;
    uint8_t channel;
    uint8_t carrier;
    uint8_t encoding;
    uint32_t datarate;

    int16_t gps_lat;
    int64_t gps_lat_mant;
    int16_t gps_lon;
    int64_t gps_lon_mant;
    int16_t gps_alt;
    int64_t gps_alt_mant;
    int16_t gps_spd;
    int64_t gps_spd_mant;
    int16_t gps_heading;
    int64_t gps_heading_mant;
    int8_t gps_fix;

    uint8_t sourcename[32];
} __attribute__((__packed__));

#endif
