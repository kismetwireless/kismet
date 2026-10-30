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

#include <algorithm>
#include <stdexcept>

#include "btle.h"

void bluetooth_btle::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_advertised_data = std::make_shared<shared_advdata_vector>();
    m_has_advertising_address = false;
    m_has_peer_address = false;
    m_has_connect_params = false;
    m_has_adv_sid = false;

    m_access_address = p_io->read_u4le();
    m_packet_header = p_io->read_u1();
    m_length = p_io->read_u1();

    // The PDU length bounds the payload; the CRC follows it
    std::string payload = p_io->read_bytes(m_length);
    size_t adv_off = 0;

    switch (pdu_type()) {
        case 0x0:   // ADV_IND
        case 0x2:   // ADV_NONCONN_IND
        case 0x4:   // SCAN_RSP
        case 0x6:   // ADV_SCAN_IND
            set_address(payload, 0);
            adv_off = 6;
            break;

        case 0x1:   // ADV_DIRECT_IND: AdvA, TargetA
        case 0x3:   // SCAN_REQ: ScanA, AdvA
        case 0x5:   // CONNECT_IND: InitA, AdvA, LLData
            // The transmitter address is first; there's no advertising data
            set_address(payload, 0);

            if (payload.length() >= 12) {
                m_peer_address = kaitai::kstream::reverse(payload.substr(6, 6));
                m_has_peer_address = true;
            }

            // LLData: access address, CRC init, window size and offset, interval,
            // latency, timeout, channel map, hop and SCA
            if (pdu_type() == 0x5 && payload.length() >= 34) {
                const auto ll = reinterpret_cast<const uint8_t *>(payload.data()) + 12;
                m_connect_params.access_address = ll[0] | ((uint32_t) ll[1] << 8) |
                    ((uint32_t) ll[2] << 16) | ((uint32_t) ll[3] << 24);
                m_connect_params.interval = ll[10] | ((uint16_t) ll[11] << 8);
                m_connect_params.latency = ll[12] | ((uint16_t) ll[13] << 8);
                m_connect_params.timeout = ll[14] | ((uint16_t) ll[15] << 8);
                m_connect_params.hop = ll[21] & 0x1F;
                m_has_connect_params = true;
            }

            return;

        case 0x7:   // ADV_EXT_IND, AUX_ADV_IND, AUX_SCAN_RSP, AUX_SYNC_IND, AUX_CHAIN_IND
        case 0x8:   // AUX_CONNECT_RSP
            adv_off = parse_extended_header(payload);
            break;

        default:
            return;
    }

    parse_advdata(payload, adv_off);
}

void bluetooth_btle::from_report(const mac_addr& address, bool random, uint8_t pdu_type,
        bool extended, const std::string& advdata) {
    m_advertised_data = std::make_shared<shared_advdata_vector>();
    m_has_peer_address = false;
    m_has_connect_params = false;
    m_has_adv_sid = false;
    m_has_aux_ptr = false;

    m_access_address = 0x8E89BED6;
    m_packet_header = (pdu_type & 0x0F) | (random ? 0x40 : 0);
    m_length = (uint8_t) std::min<size_t>(6 + advdata.length(), 255);
    m_extended = extended;

    m_advertising_address.resize(6);
    for (unsigned int i = 0; i < 6; i++)
        m_advertising_address[i] = (char) address[i];
    m_has_advertising_address = true;

    parse_advdata(advdata, 0);
}

void bluetooth_btle::parse_advdata(const std::string& payload, size_t adv_off) {
    // Advertising data runs to the end of the payload; a zero length entry is padding
    while (adv_off + 2 <= payload.length()) {
        uint8_t ad_len = (uint8_t) payload[adv_off];

        if (ad_len == 0 || adv_off + 1 + ad_len > payload.length())
            break;

        auto adv_datum = std::make_shared<bluetooth_btle_advdata>();
        adv_datum->parse(payload.substr(adv_off, 1 + ad_len));
        m_advertised_data->push_back(adv_datum);

        adv_off += 1 + ad_len;
    }
}

void bluetooth_btle::set_address(const std::string& payload, size_t offt) {
    if (offt + 6 > payload.length())
        throw std::runtime_error("btle address past end of pdu");

    // BTLE stores the MAC address backwards
    m_advertising_address = kaitai::kstream::reverse(payload.substr(offt, 6));
    m_has_advertising_address = true;
}

size_t bluetooth_btle::parse_extended_header(const std::string& payload) {
    // Common extended advertising payload: header length and mode, then flags and
    // the optional fields in flag order
    if (payload.length() < 1)
        throw std::runtime_error("btle extended pdu too short");

    size_t hdr_len = (uint8_t) payload[0] & 0x3F;
    size_t end = 1 + hdr_len;

    if (end > payload.length())
        throw std::runtime_error("btle extended header past end of pdu");

    m_extended = true;

    if (hdr_len == 0)
        return end;

    uint8_t flags = payload[1];
    size_t offt = 2;

    // AdvA, TargetA, CTEInfo, ADI, AuxPtr, SyncInfo, TxPower
    static const size_t field_len[] = { 6, 6, 1, 2, 3, 18, 1 };

    for (unsigned int f = 0; f < 7; f++) {
        if (!(flags & (1 << f)))
            continue;

        if (offt + field_len[f] > end)
            throw std::runtime_error("btle extended header field past end of header");

        if (f == 0) {
            set_address(payload, offt);
        } else if (f == 3) {
            // DID in the low 12 bits, SID in the top 4
            m_adv_sid = (uint8_t) payload[offt + 1] >> 4;
            m_has_adv_sid = true;
        } else if (f == 4) {
            m_has_aux_ptr = true;
        }

        offt += field_len[f];
    }

    return end;
}

void bluetooth_btle::bluetooth_btle_advdata::parse(const std::string& record) {
    m_length = (uint8_t) record[0];
    m_type = (uint8_t) record[1];

    m_data = record.substr(2);
    m_data_stream = std::make_shared<kaitai::kstream>(m_data);
}

void bluetooth_btle::bluetooth_btle_advdata::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_length = p_io->read_u1();

    if (m_length == 0)
        throw std::runtime_error("btle zero length advertising data");

    m_type = p_io->read_u1();

    m_data = p_io->read_bytes(length() - 1);
    m_data_stream = std::make_shared<kaitai::kstream>(m_data);
}

