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

#define STREAM_DRONE_VERSION 6

#define STREAM_SENTINEL      0xDECAFBAD

#define STREAM_FTYPE_VERSION 1
#define STREAM_FTYPE_PACKET  2

#define STREAM_COMMAND_FLUSH -1

typedef struct stream_frame_header {
    uint32_t frame_sentinel __attribute__ ((packed));
    uint8_t frame_type __attribute__ ((packed));
    uint32_t frame_len __attribute__ ((packed));
};

typedef struct stream_version_packet {
    uint16_t drone_version;
};

typedef struct stream_packet_header {
    uint32_t header_len __attribute__ ((packed));
    uint16_t drone_version __attribute__ ((packed));
    uint32_t len __attribute__ ((packed));
    uint32_t caplen __attribute__ ((packed));
    uint64_t tv_sec __attribute__ ((packed));
    uint64_t tv_usec __attribute__ ((packed));
    uint16_t quality __attribute__ ((packed));
    uint16_t signal __attribute__ ((packed));
    uint16_t noise __attribute__ ((packed));
    uint8_t error __attribute__ ((packed));
    uint8_t channel __attribute__ ((packed));
    uint8_t carrier __attribute__ ((packed));
    uint8_t encoding __attribute__ ((packed));
    uint32_t datarate __attribute__ ((packed));

    int16_t gps_lat __attribute__ ((packed));
    int64_t gps_lat_mant __attribute__ ((packed));
    int16_t gps_lon __attribute__ ((packed));
    int64_t gps_lon_mant __attribute__ ((packed));
    int16_t gps_alt __attribute__ ((packed));
    int64_t gps_alt_mant __attribute__ ((packed));
    int16_t gps_spd __attribute__ ((packed));
    int64_t gps_spd_mant __attribute__ ((packed));
    int8_t gps_fix __attribute__ ((packed));
};

#endif
