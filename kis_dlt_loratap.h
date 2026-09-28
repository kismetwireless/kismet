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

    Reconstructed from Wireshark packet-loratap.c for GPL2 clean-ness
*/

#ifndef __KIS_DLT_LORATAP__
#define __KIS_DLT_LORATAP__

#include "config.h"

#include <stdint.h>

#ifndef KDLT_LORATAP
#define KDLT_LORATAP             270
#endif

namespace kis_dlt_loratap {

enum class channel_bandwidth {
    bw_125 = 1,
    bw_250 = 2,
    bw_500 = 3,
};

enum class syncwords {
    sync_private = 0x12,
    sync_lorawan = 0x34,
    sync_meshtastic = 0x2b,
};

enum class codingrate {
    coderate_none = 0,
    coderate_4_5 = 5,
    coderate_4_6 = 6,
    corerate_4_7 = 7,
    coderate_4_8 = 8,
};

enum class crcstate {
    crc_ok = 1,
    crc_bad = 2,
    crc_none = 4,
};

const uint8_t flag_fsk = 0x1;
const uint8_t flag_iq_inverted = 0x2;
const uint8_t flag_implicit_hdr_type = 0x4;
const uint8_t flag_crc_type = 0x38;

typedef struct {
    uint8_t version;
    uint16_t padding;
    uint16_t length;
} __attribute__((packed)) loratap_header_prefix_t;

typedef struct {
    uint8_t version;
    uint8_t padding;
    uint16_t length;
    uint32_t frequency;
    uint8_t bandwidth;
    uint8_t spread_factor;
    uint8_t rssi;
    uint8_t max_rssi;
    uint8_t current_rssi;
    uint8_t snr;
    uint8_t sync_word;
} __attribute__((packed)) loratap_header_v0_t;

typedef struct {
    loratap_header_v0_t v0_common;
    uint64_t gateway;
    uint32_t timestamp;
    uint8_t flags;
    uint8_t code_rate;
    uint16_t data_rate;
    uint8_t if_channel;
    uint8_t rf_chain;
    uint16_t tag;
} __attribute__((packed)) loratap_header_v1_t;

}

#endif /* __KIS_DLT_LORATAP__ */
