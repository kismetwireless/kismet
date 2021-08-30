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

#include "endian_magic.h"

#include "datasource_ti_cc_2540.h"

void kis_datasource_ticc2540::handle_rx_datalayer(std::shared_ptr<kis_packet> packet, 
        const KismetDatasource::SubPacket& report) {

    typedef struct {
        uint8_t monitor_channel;
        int8_t signal;
        int8_t noise;
        uint8_t access_offenses;
        uint8_t reference_access_address[4];
        uint16_t flags_le;
        uint8_t payload[0];
    } __attribute__((packed)) btle_rf;

    // Subset of flags we set
    const uint16_t btle_rf_flag_dewhitened = (1 << 0);
    const uint16_t btle_rf_flag_signalvalid = (1 << 1);
    const uint16_t btle_rf_flag_reference_access_valid = (1 << 5);
    const uint16_t btle_rf_crc_checked = (1 << 10);
    const uint16_t btle_rf_crc_valid = (1 << 11);

    auto& rxdata = report.data();

    // If we can't validate the basics of the packet at the phy capture level, throw it out.
    // We don't get rid of invalid btle contents, but we do get rid of invalid USB frames that
    // we can't decipher - we can't even log them sanely!
   
    if (rxdata.length() < 8) {
        packet->error = 1;
        return;
    }

    unsigned int cc_len = rxdata[1];
    if (cc_len != rxdata.length() - 3) {
        packet->error = 1;
        return;
    }

    unsigned int cc_payload_len = rxdata[7] - 0x02;
    if (cc_payload_len + 8 != rxdata.length() - 2) {
        packet->error = 1;
        return;
    }

    uint8_t fcs1 = rxdata[rxdata.length() - 2];
    uint8_t fcs2 = rxdata[rxdata.length() - 1];

    // Convert the channel for the btlell header
    auto bt_channel = fcs2 & 0x7F;
    switch (bt_channel) {
        case 37:
            bt_channel = 0;
            break;
        case 38:
            bt_channel = 12;
            break;
        case 39:
            bt_channel = 39;
            break;
        default:
            bt_channel = bt_channel - 2;
    };

    // We can make a valid payload from this much
    auto conv_buf_len = sizeof(btle_rf) + cc_payload_len;
    std::string conv_buf;
    conv_buf.resize(conv_buf_len, 0);

    btle_rf *conv_header = reinterpret_cast<btle_rf *>(conv_buf.data());

    // Copy the actual packet payload into the header
    memcpy(conv_header->payload, &rxdata.data()[8], cc_payload_len);

    // Set the converted channel
    conv_header->monitor_channel = bt_channel;

    // RSSI is a signed value at fcs1; convert it from the CC value to signed dbm
    conv_header->signal = (fcs1 + (int) pow(2, 7)) % (int) pow(2, 8) - (int) pow(2, 7) - 73;

    uint16_t bits = btle_rf_crc_checked;
    if (fcs2 & (1 << 7))
        bits += btle_rf_crc_valid;

    if (cc_payload_len >= 4) {
        memcpy(conv_header->reference_access_address, conv_header->payload, 4);
        bits += btle_rf_flag_reference_access_valid;
    }

    conv_header->flags_le = 
        kis_htole16(bits + btle_rf_flag_signalvalid + btle_rf_flag_dewhitened);


    // Put the modified data into the packet & fill in the rest of the base data info
    auto datachunk = packetchain->new_packet_component<kis_datachunk>();

    if (clobber_timestamp && get_source_remote()) {
        gettimeofday(&(packet->ts), NULL);
    } else {
        packet->ts.tv_sec = report.time_sec();
        packet->ts.tv_usec = report.time_usec();
    }

    packet->set_data(conv_buf);
    datachunk->set_data(packet->data);
    datachunk->dlt = KDLT_BTLE_RADIO;

    get_source_packet_size_rrd()->add_sample(conv_buf.length(), time(0));

    packet->insert(pack_comp_linkframe, datachunk);


    // Generate a l1 radio header and a decap header since we have it computed already
    auto radioheader = packetchain->new_packet_component<kis_layer1_packinfo>();
    radioheader->signal_type = kis_l1_signal_type_dbm;
    radioheader->signal_dbm = conv_header->signal;
    radioheader->freq_khz = (2400 + (fcs2 & 0x7F)) * 1000;
    radioheader->channel = fmt::format("{}", (fcs2 & 0x7F));
    packet->insert(pack_comp_radiodata, radioheader);

    auto decapchunk = packetchain->new_packet_component<kis_datachunk>();
    decapchunk->dlt = KDLT_BLUETOOTH_LE_LL;
    decapchunk->set_data(packet->data.substr(sizeof(btle_rf), cc_payload_len));
    packet->insert(pack_comp_decap, decapchunk);
}

