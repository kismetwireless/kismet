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

#include "datasource_rz_killerbee.h"

kis_datasource_rzkillerbee::rx_content kis_datasource_rzkillerbee::handle_rx_data_content(kis_packet *packet,
        kis_datachunk *datachunk, const uint8_t *content, size_t content_sz) {

    if (content_sz < 9) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return rx_content::frame;
    }

    if (content[7]) {
        const unsigned int rz_payload_len = content[8];

        if (content_sz < rz_payload_len + 9) {
            packet->error = 1;
            // error, but preserve the packet for logging
            packet->set_data((const char *) content, content_sz);
            datachunk->set_data(packet->data);
            return rx_content::frame;
        }


        int rssi = content[6];
        uint8_t channel = content[5];

	    // We can make a valid payload from this much
        const size_t conv_buf_len = sizeof(_802_15_4_tap) + rz_payload_len;
        char conv_buf[sizeof(_802_15_4_tap) + 255];

        _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(conv_buf);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &content[9], rz_payload_len);

        // the KillerBee frame includes its FCS; the RSSI in dBm, the channel
        tap_802_15_4_fill(conv_header, 1, 1, (float) rssi, 0, channel);

        packet->original_len = conv_buf_len;

        packet->set_data(conv_buf, conv_buf_len);
        datachunk->set_data(packet->data);

        datachunk->dlt = KDLT_IEEE802_15_4_TAP;

		packet->signal_info.data_ok = true;
        packet->signal_info.signal_type = kis_l1_signal_type_dbm;
        packet->signal_info.signal_dbm = rssi;
        packet->signal_info.freq_khz = (2405 + ((channel - 11) * 5)) * 1000;
        packet->signal_info.channel = fmt::format("{}", (channel));

        return rx_content::frame;
    } else {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return rx_content::frame;
    }
}
