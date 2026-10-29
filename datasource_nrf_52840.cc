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

#include "datasource_nrf_52840.h"

#include <charconv>
#include <string_view>

kis_datasource_nrf52840::rx_content kis_datasource_nrf52840::handle_rx_data_content(kis_packet *packet, kis_datachunk *datachunk,
            const uint8_t *content, size_t content_sz) {

    // The largest 802.15.4 frame
    constexpr size_t max_payload = 127;

    if (content_sz == 0) {
        packet->error = 1;
        return rx_content::frame;
    }

    // Frames from the nRF52840 BTLE firmware can't be decoded by this source
    if (content[0] == 0xAB && content[content_sz - 1] == 0xBC)
        return rx_content::error;

    // error, but preserve the packet for logging
    auto corrupt = [&]() {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return rx_content::frame;
    };

    // Records are ascii 'received: <hex> power: <rssi> lqi: <lqi> time:', with the channel
    // written over the third byte by the capture tool
    const std::string_view rec((const char *) content, content_sz);
    constexpr std::string_view power_label{" power: "};
    constexpr std::string_view lqi_label{" lqi: "};
    constexpr size_t hex_start = 10;

    if (rec.size() < hex_start || rec.substr(8, 2) != ": ")
        return corrupt();

    auto power_pos = rec.find(power_label, hex_start);
    if (power_pos == std::string_view::npos)
        return corrupt();

    auto hex = rec.substr(hex_start, power_pos - hex_start);
    if (hex.empty() || hex.size() % 2 != 0 || hex.size() > max_payload * 2)
        return corrupt();

    auto rssi_start = power_pos + power_label.size();
    auto lqi_pos = rec.find(lqi_label, rssi_start);
    if (lqi_pos == std::string_view::npos)
        return corrupt();

    auto rssi_str = rec.substr(rssi_start, lqi_pos - rssi_start);
    int rssi = 0;
    auto [rssi_end, rssi_ec] = std::from_chars(rssi_str.data(), rssi_str.data() + rssi_str.size(), rssi);
    if (rssi_ec != std::errc() || rssi_end != rssi_str.data() + rssi_str.size() ||
            rssi < -255 || rssi > 255)
        return corrupt();

    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        return -1;
    };

    // Build the TAP header and payload
    alignas(_802_15_4_tap) char conv_buf[sizeof(_802_15_4_tap) + max_payload];
    _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(conv_buf);
    // The payload follows the header in conv_buf; payload[] itself is zero-length
    uint8_t *payload = reinterpret_cast<uint8_t *>(conv_buf + sizeof(_802_15_4_tap));
    size_t nrf_payload_len = hex.size() / 2;

    for (size_t i = 0; i < nrf_payload_len; i++) {
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0)
            return corrupt();

        payload[i] = (uint8_t) ((hi << 4) | lo);
    }

    uint8_t channel = content[2];

    // no FCS, the RSSI in dBm, the channel
    tap_802_15_4_fill(conv_header, 0, 1, (float) rssi, 0, channel);

    datachunk->dlt = KDLT_IEEE802_15_4_TAP;

    packet->set_data(conv_buf, sizeof(_802_15_4_tap) + nrf_payload_len);
    datachunk->set_data(packet->data);

    packet->signal_info.data_ok = true;
    packet->signal_info.signal_type = kis_l1_signal_type_dbm;
    packet->signal_info.signal_dbm = rssi;
    if (channel >= 11 && channel <= 26)
        packet->signal_info.freq_khz = (2405 + ((channel - 11) * 5)) * 1000;
    packet->signal_info.channel = fmt::format("{}", (channel));

    return rx_content::frame;
}
