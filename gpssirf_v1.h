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

#ifndef __GPSSIRF_V1_H__
#define __GPSSIRF_V1_H__

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "gps_proto.h"

// SiRF binary protocol decoder (SiRFstar III and similar); no I/O, and Kismet never sends
// SiRF commands: switching a receiver's protocol is kept in its battery backed memory,
// which outlives a power cycle.  Frames come from gps_framer_v1 with the start and end
// sequences, length, and checksum already checked.
//
// MID 41 (geodetic navigation data) is a complete report.  Firmware without it reports
// MID 2 (ECEF position and velocity), which is converted and used until MID 41 shows up.
class gps_sirf_decoder_v1 {
public:
    static constexpr uint8_t start_1 = 0xA0;
    static constexpr uint8_t start_2 = 0xA2;
    static constexpr uint8_t end_1 = 0xB0;
    static constexpr uint8_t end_2 = 0xB3;

    // Start sequence and payload length
    static constexpr size_t header_len = 4;
    // Checksum and end sequence
    static constexpr size_t trailer_len = 4;

    // Largest payload the protocol allows
    static constexpr size_t max_payload = 1023;

    static constexpr uint8_t mid_measured_nav = 2;
    static constexpr uint8_t mid_geodetic_nav = 41;

    enum class result {
        // Location, or a no fix report (fix 1 only)
        update,
        // Valid message which carries nothing to apply (an unhandled message)
        ignored,
        malformed,
    };

    // 15-bit sum of the payload bytes
    static constexpr uint16_t checksum(const uint8_t *payload, size_t len) {
        uint32_t sum = 0;

        for (size_t i = 0; i < len; i++)
            sum = (sum + payload[i]) & 0x7FFF;

        return static_cast<uint16_t>(sum);
    }

    // Decode one complete frame, from the start sequence through the end sequence
    result decode(std::string_view frame, gps_fix_update& update);

    void reset() {
        have_geodetic = false;
    }

protected:
    // Once MID 41 has been seen, MID 2 is ignored
    bool have_geodetic = false;
};

#endif
