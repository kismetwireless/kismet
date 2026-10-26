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

#include "btle_tracker.h"

namespace btle_tracker {

bool decode_samsung_smarttag(const uint8_t *data, size_t len, smarttag_info& out) {
    if (data == nullptr || len < 2 + smarttag_min_len)
        return false;

    uint16_t uuid = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    if (uuid != samsung_service_uuid)
        return false;

    const uint8_t *p = data + 2;

    if ((p[0] & smarttag_frame_mask) != smarttag_frame_id)
        return false;

    out.state = p[0] & 0x07;
    out.aging_counter = (uint32_t) p[1] | ((uint32_t) p[2] << 8) | ((uint32_t) p[3] << 16);
    out.privacy_id.assign(reinterpret_cast<const char *>(p + 4), smarttag_privacy_id_len);
    out.flags = p[12];

    return true;
}

const char *tracker_type_str(tracker_type type) {
    switch (type) {
        case tracker_type::samsung_smarttag:
            return "samsung_smarttag";
        default:
            return "unknown";
    }
}

const char *battery_level_str(battery_level level) {
    switch (level) {
        case battery_level::full:
            return "full";
        case battery_level::medium:
            return "medium";
        case battery_level::low:
            return "low";
        case battery_level::very_low:
            return "very_low";
    }

    return "unknown";
}

const char *smarttag_state_str(uint8_t state) {
    switch (state) {
        case 1:
            return "premature_offline";
        case 2:
            return "offline";
        case 3:
            return "overmature_offline";
        case 4:
        case 5:
        case 6:
            return "connected";
        default:
            return "unknown";
    }
}

}
