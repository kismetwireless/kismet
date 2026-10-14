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

    bool lorapipe_parse(const std::string_view& sv, float& out) {
        char buf[lorapipe_num_max];

        if (!lorapipe_copy_num(sv, buf))
            return false;

        char *end;
        errno = 0;
        out = strtof(buf, &end);

        return errno == 0 && end == buf + sv.length();
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

    const auto toks = base_sv_tokenize({(const char *) content, content_sz}, ",", "");

    if (toks.size() != 10) {
        packet->error = 1;
        return 1;
    }

    if (toks[6] != "RXLOG") {
        packet->error = 1;
        return 1;
    }

    float freq, signal, snr;
    unsigned int bandwidth, spreading, coding, syncword;

    if (!lorapipe_parse(toks[0], freq)) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        return 1;
    }

    if (!lorapipe_parse(toks[1], bandwidth)) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        return 1;
    }

    if (!lorapipe_parse(toks[2], spreading)) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        return 1;
    }

    if (!lorapipe_parse(toks[3], coding)) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        return 1;
    }

    if (!lorapipe_parse(toks[4], syncword, 16)) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        return 1;
    }

    if (!lorapipe_parse(toks[7], signal)) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        return 1;
    }

    if (!lorapipe_parse(toks[8], snr)) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        return 1;
    }

    content_sz = (toks[9].length() / 2) + 1;

    // _MSG_DEBUG("toks[9] {} len {} content sz {}", toks[9], toks[9].length(), content_sz);

    std::string convbuf(sizeof(kis_dlt_loratap::loratap_header_v1_t) + content_sz, (char) 0x0);
    auto loratap = reinterpret_cast<kis_dlt_loratap::loratap_header_v1_t *>(convbuf.data());

    loratap->v0_common.version = 0;
    loratap->v0_common.padding = 0;
    loratap->v0_common.length = kis_hton16(sizeof(kis_dlt_loratap::loratap_header_v1_t));
    loratap->v0_common.frequency = kis_hton32(freq * 1024 * 1024);
    loratap->v0_common.bandwidth = bandwidth;
    loratap->v0_common.spread_factor = spreading;
    loratap->v0_common.rssi = (uint8_t) signal + 139;
    loratap->v0_common.current_rssi = (uint8_t) signal;
    loratap->v0_common.snr = (uint8_t) snr * 4;
    loratap->v0_common.sync_word = (uint8_t) syncword;
    loratap->code_rate = (uint8_t) coding;

    size_t data_sz;
    try {
        data_sz = hex_to_bytes(toks[9], (uint8_t *) convbuf.data() + sizeof(kis_dlt_loratap::loratap_header_v1_t),
                convbuf.length() - sizeof(kis_dlt_loratap::loratap_header_v1_t));
    } catch (...) {
        packet->error = 1;
        packet->set_data((const char *) content, content_sz);
        return 1;
    }

    packet->set_data(convbuf.data(), sizeof(kis_dlt_loratap::loratap_header_v1_t) + data_sz);

    datachunk->dlt = KDLT_LORATAP;
    datachunk->set_data(packet->data);

    // propogate the signal data
    packet->signal_info.data_ok = true;
    packet->signal_info.signal_type = kis_l1_signal_type_dbm;
    packet->signal_info.signal_dbm = signal;
    packet->signal_info.freq_khz = freq * 1024;
    packet->signal_info.channel = fmt::format("{}-{}-{}-{}-{:2x}",
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


    return 0;
}

