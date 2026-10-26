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

bool decode_apple_findmy(const uint8_t *data, size_t len, findmy_info& out) {
    /* Company ID, type, length and status are the shortest frame */
    if (data == nullptr || len < 2 + 3)
        return false;

    uint16_t company = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    if (company != apple_company_id)
        return false;

    const uint8_t *p = data + 2;

    if (p[0] != findmy_type)
        return false;

    if (p[1] != findmy_len_separated && p[1] != findmy_len_near_owner)
        return false;

    /* The length byte counts the bytes after it */
    if (len < 2 + 2 + (size_t) p[1])
        return false;

    out.status = p[2];
    out.separated_frame = p[1] == findmy_len_separated;

    return true;
}

bool decode_google_fmdn(const uint8_t *data, size_t len, fmdn_info& out) {
    if (data == nullptr || len < 2 + 1)
        return false;

    uint16_t uuid = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    if (uuid != google_fmdn_service_uuid)
        return false;

    const uint8_t *p = data + 2;
    size_t plen = len - 2;

    if (p[0] != fmdn_frame && p[0] != fmdn_frame_utp)
        return false;

    /* Frame type, the ephemeral identifier, and the optional hashed flags */
    size_t eid_len;
    if (plen == 1 + fmdn_eid_len_160 || plen == 1 + fmdn_eid_len_160 + 1)
        eid_len = fmdn_eid_len_160;
    else if (plen == 1 + fmdn_eid_len_256 || plen == 1 + fmdn_eid_len_256 + 1)
        eid_len = fmdn_eid_len_256;
    else
        return false;

    out.frame_type = p[0];
    out.ephemeral_id.assign(reinterpret_cast<const char *>(p + 1), eid_len);
    out.hashed_flags = plen == 1 + eid_len + 1;

    return true;
}

bool decode_dult(const uint8_t *data, size_t len, dult_info& out) {
    if (data == nullptr || len < 2 + dult_min_len)
        return false;

    uint16_t uuid = (uint16_t) data[0] | ((uint16_t) data[1] << 8);
    if (uuid != dult_service_uuid)
        return false;

    out.network_id = data[2];
    out.status = data[3];

    return true;
}

const char *tracker_type_str(tracker_type type) {
    switch (type) {
        case tracker_type::samsung_smarttag:
            return "samsung_smarttag";
        case tracker_type::apple_findmy:
            return "apple_findmy";
        case tracker_type::google_fmdn:
            return "google_fmdn";
        case tracker_type::dult:
            return "dult";
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

const char *findmy_device_type_str(uint8_t device_type) {
    switch (device_type) {
        case findmy_device_apple:
            return "apple_device";
        case findmy_device_airtag:
            return "airtag";
        case findmy_device_accessory:
            return "findmy_accessory";
        case findmy_device_airpods:
            return "airpods";
        default:
            return "unknown";
    }
}

const char *separated_state_str(bool separated) {
    return separated ? "separated" : "near_owner";
}

const char *fmdn_state_str(const fmdn_info& info) {
    return info.unwanted_tracking_protection() ? "unwanted_tracking_protection" : "normal";
}

}
