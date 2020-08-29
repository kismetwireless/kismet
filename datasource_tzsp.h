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

#ifndef __DATASOURCE_TZSP_H__
#define __DATASOURCE_TZSP_H__ 

#include "config.h"

#include "globalregistry.h"
#include "kis_datasource.h"
#include "udpserver.h"

// TZSP per-frame header
typedef struct {
    uint8_t tzsp_version;
    uint8_t tzsp_type;
    uint8_t tzsp_encapsulation;
} __attribute__((packed)) tzsp_header;

#define TZSP_PACKET_RECEIVED        0x00
#define TZSP_PACKET_TRANSMIT        0x01
#define TZSP_PACKET_RESERVED        0x02
#define TZSP_PACKET_CONFIGURATION   0x03
#define TZSP_PACKET_KEEPALIVE       0x04
#define TZSP_PACKET_PORTOPENER      0x05

#define TZSP_DLT_ETHERNET           0x01
#define TZSP_DLT_IEEE80211          0x12
#define TZSP_DLT_PRISM              0x77
#define TZSP_DLT_AVS                0x7F

// TZSP tagged records
typedef struct {
    uint8_t tagno;
    uint8_t taglen;
    char *data;
} __attribute__((packed)) tzsp_tag_t;

#define TZSP_TAG_PADDING            0x00
#define TZSP_TAG_END                0x01
#define TZSP_TAG_RSSI               0x0A
#define TZSP_TAG_SNR                0x0B
#define TZSP_TAG_DATARATE           0x0C
#define TZSP_TAG_TIMESTAMP          0x0D
#define TZSP_TAG_CONTENTIONFREE     0x0F
#define TZSP_TAG_DECRYPTED          0x10
#define TZSP_TAG_FCS_ERROR          0x11
#define TZSP_TAG_RX_CHANNEL         0x12
#define TZSP_TAG_PACKET_COUNT       0x28
#define TZSP_TAG_RX_FRAMELEN        0x29
#define TZSP_TAG_RX_RADIO_SERIAL    0x3C

class tzsp_source : public lifetime_global {
public:
    static std::string global_name() { return "tzsp_source"; }

    static std::shared_ptr<tzsp_source> create_tzsp_source() {
        std::shared_ptr<tzsp_source> tsrc(new tzsp_source());
        Globalreg::globalreg->register_lifetime_global(tsrc);
        Globalreg::globalreg->insert_global(global_name(), tsrc);
        return tsrc;
    }

private:
    tzsp_source();

public:
    virtual ~tzsp_source();

protected:
    std::shared_ptr<udp_dgram_server> tzsp_listener;

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<datasource_tracker> datasourcetracker;
    std::shared_ptr<pollable_tracker> pollabletracker;

    int pack_comp_common, pack_comp_linkframe, pack_comp_l1info, pack_comp_datasrc;

    // datagram callback for new data; auto-allocates a source for a new remote sensor
    void udp_datagram(const struct sockaddr_storage *sockaddr, size_t addrsize,
            uint32_t hash, const char *data, size_t len);

    // datagram callback for a closed or timed-out remote tzsp sensor, flags the virtual source as closed
    void udp_cancel(uint32_t hash, bool timeout, const std::string& reason);

    std::map<uint32_t, std::shared_ptr<kis_datasource>> tzsp_source_map;

};

#endif /* ifndef DATASOURCE_TZSP_H */
