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

#include "datasource_sniffle_ble.h"

#include "endian_magic.h"

// content is Sniffle's own raw 0x10 (PacketMessage) message body, forwarded
// close to verbatim by capture_sniffle_ble.c after base64/CRLF deframing. Layout
// confirmed directly from Sniffle's own python_cli/sniffle/packet_decoder.py
// (PacketMessage.__init__: `unpack("<LHHbB", raw_msg[:10])`):
//
//   offset 0-3: ts     (uint32 LE)  -- not used here, capture-time gettimeofday() is close enough
//   offset 4-5: l      (uint16 LE)  -- bit15 = packet direction, bit14 = crc_err, bits13-0 = body length
//   offset 6-7: event  (uint16 LE)  -- not used here
//   offset 8:   rssi   (int8)
//   offset 9:   chan   (uint8)      -- bits7-6 = PHY, bits5-0 = BLE channel (0-39)
//   offset 10+: body                -- the actual PDU, no access address or CRC (Sniffle's firmware
//                                       already validated/stripped both; crc_err above reports the result)
int kis_datasource_sniffle_ble::handle_rx_data_content(kis_packet *packet,
        kis_datachunk *datachunk, const uint8_t *content, size_t content_sz) {

    typedef struct {
        uint8_t monitor_channel;
        int8_t signal;
        int8_t noise;
        uint8_t access_offenses;
        uint8_t reference_access_address[4];
        uint16_t flags_le;
        uint8_t payload[0];
    } __attribute__((packed)) btle_rf;

    typedef struct {
        uint32_t ts;
        uint16_t l;
        uint16_t event;
        int8_t rssi;
        uint8_t chan;
        uint8_t body[0];
    } __attribute__((packed)) sniffle_hdr;

    const uint16_t btle_rf_flag_signalvalid = (1 << 1);
    const uint16_t btle_rf_crc_checked = (1 << 10);
    const uint16_t btle_rf_crc_valid = (1 << 11);

    // BLE advertising channel access address (0x8E89BED6), little-endian on
    // the wire - same standard constant Sniffle's own sniffle_hw.py uses as
    // BLE_ADV_AA. Sniffle's firmware only ever hands us advertising-channel
    // (37/38/39) packets in our PASSIVE_SCAN usage, so this is always correct
    // here; it would need to come from the actual connection instead if this
    // datasource ever grew connection-following support.
    static const uint8_t adv_aa_le[4] = {0xD6, 0xBE, 0x89, 0x8E};

    if (content == nullptr || content_sz < sizeof(sniffle_hdr)) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    const sniffle_hdr *hdr = reinterpret_cast<const sniffle_hdr *>(content);

    uint16_t l_raw = kis_letoh16(hdr->l);
    bool crc_err = (l_raw & 0x4000) != 0;
    uint16_t body_len = l_raw & 0x3FFF;

    if (content_sz - sizeof(sniffle_hdr) < body_len) {
        // Truncated/malformed - preserve for logging, same as the size guard above
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    int8_t rssi = hdr->rssi;
    uint8_t chan = hdr->chan & 0x3F;
    // uint8_t phy = hdr->chan >> 6; - PHY_1M only in our current PASSIVE_SCAN
    // usage (setup_sniffer never enables coded_phy), not currently surfaced

    uint8_t monitor_channel;
    uint64_t freq_khz = 0;
    switch (chan) {
        case 37:
            monitor_channel = 0;
            freq_khz = 2402 * 1000;
            break;
        case 38:
            monitor_channel = 12;
            freq_khz = 2426 * 1000;
            break;
        case 39:
            monitor_channel = 39;
            freq_khz = 2480 * 1000;
            break;
        default:
            // Shouldn't happen - this datasource only configures Sniffle to
            // listen on a primary advertising channel - but don't silently
            // mis-map into another valid-looking channel if it ever does.
            packet->error = 1;
            packet->set_data((const char *) content, content_sz);
            datachunk->set_data(packet->data);
            return 1;
    }

    // Decap payload = access address (4) + PDU (body_len) + dummy CRC (3).
    size_t decap_len = 4 + body_len + 3;
    size_t conv_buf_len = sizeof(btle_rf) + decap_len;

    char conv_buf[conv_buf_len];
    memset(conv_buf, 0, conv_buf_len);
    btle_rf *conv_header = reinterpret_cast<btle_rf *>(conv_buf);

    conv_header->monitor_channel = monitor_channel;
    conv_header->signal = rssi;
    conv_header->noise = -128; // not measured by Sniffle's firmware
    conv_header->access_offenses = 0;
    memcpy(conv_header->reference_access_address, adv_aa_le, 4);

    uint16_t bits = btle_rf_flag_signalvalid | btle_rf_crc_checked;
    if (!crc_err)
        bits |= btle_rf_crc_valid;
    conv_header->flags_le = kis_htole16(bits);

    memcpy(conv_header->payload, adv_aa_le, 4);
    memcpy(conv_header->payload + 4, hdr->body, body_len);
    // trailing 3 bytes already zeroed by the memset above (dummy CRC)

    datachunk->dlt = KDLT_BTLE_RADIO;
    packet->set_data(conv_buf, conv_buf_len);
    datachunk->set_data(packet->data);

    packet->signal_info.data_ok = true;
    packet->signal_info.signal_type = kis_l1_signal_type_dbm;
    packet->signal_info.signal_dbm = rssi;
    packet->signal_info.freq_khz = freq_khz;
    packet->signal_info.channel = fmt::format("{}", chan);

    if (!crc_err) {
        packet->crc_ok = true;
        packet->checksum_valid = true;
    } else {
        packet->crc_ok = true;
        packet->checksum_valid = false;
        packet->filtered = true;
    }

    auto decapchunk = packetchain->new_packet_component<kis_datachunk>();
    decapchunk->dlt = KDLT_BLUETOOTH_LE_LL;
    decapchunk->set_data(packet->data.substr(sizeof(btle_rf), decap_len));
    packet->insert(pack_comp_decap, decapchunk);

    return 1;
}
