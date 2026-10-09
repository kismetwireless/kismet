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

#ifndef __GPSFRAMER_V1_H__
#define __GPSFRAMER_V1_H__

#include "config.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "gpssirf_v1.h"
#include "gpsubx_v1.h"

// Splits a raw GPS byte stream into protocol frames.  Bytes which aren't part of a frame
// are counted and dropped, so the held data never grows past one partial frame.  Binary
// frames are only emitted with a valid checksum.
class gps_framer_v1 {
public:
    enum class frame_type {
        nmea,
        ubx,
        sirf,
    };

    struct frame {
        frame_type type;
        // Only valid during the callback
        std::string_view data;
    };

    using frame_cb = std::function<void (const frame&)>;

    // Longest NMEA sentence held while waiting for the rest of it, plus CR/LF
    static constexpr size_t max_nmea_len = 130;

    static constexpr size_t max_ubx_len = gps_ubx_decoder_v1::header_len +
        gps_ubx_decoder_v1::max_payload + gps_ubx_decoder_v1::checksum_len;

    static constexpr size_t max_sirf_len = gps_sirf_decoder_v1::header_len +
        gps_sirf_decoder_v1::max_payload + gps_sirf_decoder_v1::trailer_len;

    gps_framer_v1() {
        pending.reserve(std::max(max_ubx_len, max_sirf_len) * 2);
    }

    void feed(const uint8_t *data, size_t len, const frame_cb& cb);

    void reset() {
        pending.clear();
    }

    uint64_t get_frames() const {
        return frames;
    }

    uint64_t get_discarded() const {
        return discarded;
    }

protected:
    // Bytes used by a frame at pos, 0 if it needs more data, or npos if it isn't one
    size_t scan_nmea(size_t pos, const frame_cb& cb);
    size_t scan_ubx(size_t pos, const frame_cb& cb);
    size_t scan_sirf(size_t pos, const frame_cb& cb);

    std::string pending;

    uint64_t frames = 0;
    uint64_t discarded = 0;
};

#endif
