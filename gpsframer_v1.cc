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

#include "config.h"

#include <algorithm>

#include "gpsframer_v1.h"

void gps_framer_v1::feed(const uint8_t *data, size_t len, const frame_cb& cb) {
    pending.append(reinterpret_cast<const char *>(data), len);

    size_t pos = 0;

    while (pos < pending.size()) {
        const auto c = static_cast<uint8_t>(pending[pos]);
        size_t used = std::string::npos;

        if (c == '$' || c == '!')
            used = scan_nmea(pos, cb);
        else if (c == gps_ubx_decoder_v1::sync_1)
            used = scan_ubx(pos, cb);
        else if (c == gps_sirf_decoder_v1::start_1)
            used = scan_sirf(pos, cb);

        // Partial frame; wait for more data
        if (used == 0)
            break;

        if (used == std::string::npos) {
            pos++;
            discarded++;
            continue;
        }

        frames++;
        pos += used;
    }

    pending.erase(0, pos);
}

size_t gps_framer_v1::scan_nmea(size_t pos, const frame_cb& cb) {
    // NMEA runs to LF; anything non-printable first means this wasn't a sentence start
    const size_t limit = std::min(pending.size(), pos + max_nmea_len);

    for (size_t end = pos + 1; end < limit; end++) {
        const char d = pending[end];

        if (d == '\n') {
            cb(frame{frame_type::nmea, std::string_view(pending).substr(pos, end + 1 - pos)});
            return end + 1 - pos;
        }

        if ((d < 0x20 && d != '\r') || d > 0x7E)
            return std::string::npos;
    }

    // Too long to be a sentence
    if (limit - pos >= max_nmea_len)
        return std::string::npos;

    return 0;
}

size_t gps_framer_v1::scan_ubx(size_t pos, const frame_cb& cb) {
    using ubx = gps_ubx_decoder_v1;

    const size_t avail = pending.size() - pos;
    const auto *p = reinterpret_cast<const uint8_t *>(pending.data() + pos);

    if (avail < 2)
        return 0;

    if (p[1] != ubx::sync_2)
        return std::string::npos;

    if (avail < ubx::header_len)
        return 0;

    const size_t payload_len = static_cast<size_t>(p[4] | (p[5] << 8));

    if (payload_len > ubx::max_payload_for(p[2], p[3]))
        return std::string::npos;

    const size_t total = ubx::header_len + payload_len + ubx::checksum_len;

    if (avail < total)
        return 0;

    const auto ck = ubx::checksum(p + 2, ubx::header_len - 2 + payload_len);

    if (p[total - 2] != ck.first || p[total - 1] != ck.second)
        return std::string::npos;

    cb(frame{frame_type::ubx, std::string_view(pending).substr(pos, total)});
    return total;
}

size_t gps_framer_v1::scan_sirf(size_t pos, const frame_cb& cb) {
    using sirf = gps_sirf_decoder_v1;

    const size_t avail = pending.size() - pos;
    const auto *p = reinterpret_cast<const uint8_t *>(pending.data() + pos);

    if (avail < 2)
        return 0;

    if (p[1] != sirf::start_2)
        return std::string::npos;

    if (avail < sirf::header_len)
        return 0;

    // 15 bit big endian length
    const size_t payload_len = static_cast<size_t>(((p[2] & 0x7F) << 8) | p[3]);

    if (payload_len == 0 || payload_len > sirf::max_payload || (p[2] & 0x80) != 0)
        return std::string::npos;

    const size_t total = sirf::header_len + payload_len + sirf::trailer_len;

    if (avail < total)
        return 0;

    const auto *t = p + sirf::header_len + payload_len;
    const uint16_t ck = sirf::checksum(p + sirf::header_len, payload_len);

    if (t[0] != ((ck >> 8) & 0xFF) || t[1] != (ck & 0xFF) || t[2] != sirf::end_1 || t[3] != sirf::end_2)
        return std::string::npos;

    cb(frame{frame_type::sirf, std::string_view(pending).substr(pos, total)});
    return total;
}
