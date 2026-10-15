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

#include <cctype>
#include <cmath>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>

#include "datasource_lorapipe.h"

#include "util.h"

#include "kis_endian.h"
#include "kis_dlt_loratap.h"

// <charconv> isn't available, or lacks floating point, on older compilers.  Tokens are
// copied to a terminated buffer and must be consumed completely.
namespace {
    constexpr size_t lorapipe_num_max = 32;

    bool lorapipe_copy_num(const std::string_view& sv, char (&buf)[lorapipe_num_max]) {
        if (sv.empty() || sv.length() >= lorapipe_num_max)
            return false;

        // strto* skip leading whitespace and accept '+', which from_chars did not
        if (sv[0] == '+' || isspace((unsigned char) sv[0]))
            return false;

        memcpy(buf, sv.data(), sv.length());
        buf[sv.length()] = 0;
        return true;
    }

    bool lorapipe_parse(const std::string_view& sv, double& out) {
        char buf[lorapipe_num_max];

        if (!lorapipe_copy_num(sv, buf))
            return false;

        char *end;
        errno = 0;
        out = strtod(buf, &end);

        return errno == 0 && end == buf + sv.length() && std::isfinite(out);
    }

    bool lorapipe_parse(const std::string_view& sv, unsigned int& out, int base = 10) {
        char buf[lorapipe_num_max];

        if (!lorapipe_copy_num(sv, buf) || buf[0] == '-')
            return false;

        char *end;
        errno = 0;
        const auto v = strtoul(buf, &end, base);

        if (errno != 0 || end != buf + sv.length() || v > UINT_MAX)
            return false;

        out = static_cast<unsigned int>(v);
        return true;
    }
}

int kis_datasource_lorapipe::handle_rx_data_content(kis_packet *packet,
        kis_datachunk *datachunk, const uint8_t *content, size_t content_sz) {

    // Raw lorapipe
    // 1715770553,RXLOG,-31.00,5.75,FFFFFFFF084A3C43A25D0C2800080008FC383FF6194371FE2B6C
    // Kismet prepended raw radio data:
    // 906.875,250,11,5,2b,1715770553,RXLOG,-31.00,5.75,FFFFFFFF084A3C43A25D0C2800080008FC383FF6194371FE2B6C

    // Errors and frames both return 1; errors keep the raw line for logging
    auto fail = [&]() {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    };

    const auto toks = base_sv_tokenize({(const char *) content, content_sz}, ",", "");

    if (toks.size() != 10 || toks[6] != "RXLOG") {
        return fail();
    }

    // Bandwidth may be fractional (62.5, or 812.5 for 2.4GHz)
    double freq, bandwidth, signal, snr;
    unsigned int spreading, coding, syncword;

    if (!lorapipe_parse(toks[0], freq)) {
        return fail();
    }

    if (!lorapipe_parse(toks[1], bandwidth)) {
        return fail();
    }

    if (!lorapipe_parse(toks[2], spreading)) {
        return fail();
    }

    if (!lorapipe_parse(toks[3], coding)) {
        return fail();
    }

    if (!lorapipe_parse(toks[4], syncword, 16) || syncword > 0xFF) {
        return fail();
    }

    if (!lorapipe_parse(toks[7], signal)) {
        return fail();
    }

    if (!lorapipe_parse(toks[8], snr)) {
        return fail();
    }

    const size_t payload_sz = (toks[9].length() / 2) + 1;

    std::string convbuf(sizeof(kis_dlt_loratap::loratap_header_v1_t) + payload_sz, (char) 0x0);
    auto loratap = reinterpret_cast<kis_dlt_loratap::loratap_header_v1_t *>(convbuf.data());

    if (freq <= 0 || freq * 1000000 > UINT32_MAX || spreading > 0xFF || coding > 0xFF) {
        return fail();
    }

    loratap->v0_common.version = 1;
    loratap->v0_common.padding = 0;
    loratap->v0_common.length = kis_hton16(sizeof(kis_dlt_loratap::loratap_header_v1_t));
    loratap->v0_common.frequency = kis_hton32((uint32_t) std::lround(freq * 1000000));
    loratap->v0_common.bandwidth = kis_dlt_loratap::bandwidth_to_loratap(bandwidth);
    loratap->v0_common.spread_factor = (uint8_t) spreading;
    loratap->v0_common.rssi = kis_dlt_loratap::rssi_to_loratap(signal);
    loratap->v0_common.current_rssi = kis_dlt_loratap::rssi_to_loratap(signal);
    loratap->v0_common.snr = kis_dlt_loratap::snr_to_loratap(snr);
    loratap->v0_common.sync_word = (uint8_t) syncword;
    loratap->code_rate = (uint8_t) coding;

    size_t data_sz;
    try {
        data_sz = hex_to_bytes(toks[9], (uint8_t *) convbuf.data() + sizeof(kis_dlt_loratap::loratap_header_v1_t),
                convbuf.length() - sizeof(kis_dlt_loratap::loratap_header_v1_t));
    } catch (...) {
        return fail();
    }

    packet->set_data(convbuf.data(), sizeof(kis_dlt_loratap::loratap_header_v1_t) + data_sz);
    packet->original_len = packet->data.length();

    datachunk->dlt = KDLT_LORATAP;
    datachunk->set_data(packet->data);

    // propogate the signal data
    packet->signal_info.data_ok = true;
    packet->signal_info.signal_type = kis_l1_signal_type_dbm;
    packet->signal_info.signal_dbm = signal;
    packet->signal_info.freq_khz = freq * 1000;
    packet->signal_info.channel = fmt::format("{}-{}-{}-{}-{:02x}",
            freq, bandwidth, spreading, coding, syncword);

    // slice the decoded data off the synthetic header
    auto decapchunk = packetchain->new_packet_component<kis_datachunk>();

    decapchunk->set_data(packet->data.substr(sizeof(kis_dlt_loratap::loratap_header_v1_t), data_sz));

    switch (syncword) {
        case kis_dlt_loratap::sync_meshtastic:
            decapchunk->dlt = dlt_meshtastic;
            break;
        case kis_dlt_loratap::sync_meshcore:
            decapchunk->dlt = dlt_meshcore;
            break;
        default:
            decapchunk->dlt = dlt_lora_generic;
            break;
    }

    packet->insert(pack_comp_decap, decapchunk);

    return 1;
}

