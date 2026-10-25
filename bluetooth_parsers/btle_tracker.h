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

#ifndef __BTLE_TRACKER_H__
#define __BTLE_TRACKER_H__

/* Bluetooth LE location trackers (item finders) which advertise their state in
 * the clear.  Only the public, unencrypted parts of the advertisement are decoded:
 * nothing here identifies the owner or talks to the vendor network.
 *
 * Samsung Galaxy SmartTag / SmartTag2 (SmartThings Find), 16-bit service data
 * with the Samsung UUID 0xFD5A.  Layout of the payload after the UUID:
 *
 *   0       frame id (upper 5 bits) and operating state (lower 3 bits)
 *   1-3     aging counter, 24 bit little endian
 *   4-11    privacy ID; rotates, not a permanent identity
 *   12      flags: battery level in bits 0-1, UWB support in bit 2; the region and
 *           encryption bits are not publicly documented
 *   13-     not publicly documented; not decoded
 *
 * Observed on a separated SmartTag over an hour: the random address changed about every
 * 15 minutes, the aging counter went up by one about as often, and the privacy ID, the
 * flags and bytes 13-15 (zero) stayed the same, so while separated the privacy ID links
 * the advertisements across address changes.  Bytes 16-19 changed with the aging
 * counter, a signature by the look of it.
 *
 * Operating states: 1 premature offline, 2 offline, 3 overmature offline (away from
 * the owner for more than 24 hours), 4-6 connected to one or more owner devices.
 *
 * Sources: T. Yu, J. Henderson, A. Tiu, T. Haines, "Security and Privacy Analysis of
 * Samsung's Crowd-Sourced Bluetooth Location Tracking System", USENIX Security 2024;
 * the field offsets match the SamsungTracker decoder of SEEMOO's AirGuard
 * (github.com/seemoo-lab/AirGuard).  This is an independent implementation.
 *
 * The decoder only depends on the standard library and bounds checks everything.
 */

#include <cstddef>
#include <cstdint>
#include <string>

namespace btle_tracker {

enum class tracker_type : uint8_t {
    none = 0,
    samsung_smarttag = 1,
};

enum class battery_level : uint8_t {
    very_low = 0,
    low = 1,
    medium = 2,
    full = 3,
};

/* Samsung's 16-bit service UUID */
constexpr uint16_t samsung_service_uuid = 0xFD5A;

/* SmartTag frame id, matched under smarttag_frame_mask against byte 0 */
constexpr uint8_t smarttag_frame_id = 0x10;
constexpr uint8_t smarttag_frame_mask = 0xF8;

/* Payload bytes up to and including the flags byte */
constexpr size_t smarttag_min_len = 13;
constexpr size_t smarttag_privacy_id_len = 8;

struct smarttag_info {
    uint8_t state = 0;
    uint32_t aging_counter = 0;
    /* Raw bytes, smarttag_privacy_id_len long */
    std::string privacy_id;
    uint8_t flags = 0;

    /* Premature, regular, or overmature offline: not near any of the owner's devices */
    bool separated() const {
        return state >= 1 && state <= 3;
    }

    battery_level battery() const {
        return static_cast<battery_level>(flags & 0x03);
    }

    bool uwb() const {
        return (flags & 0x04) != 0;
    }
};

/* 16-bit service data (the AD record after the 0x16 type byte: UUID, then payload).
 * Returns false unless it is a SmartTag frame of at least the documented length. */
bool decode_samsung_smarttag(const uint8_t *data, size_t len, smarttag_info& out);

const char *tracker_type_str(tracker_type type);
const char *battery_level_str(battery_level level);

/* premature_offline, offline, overmature_offline, connected, or unknown */
const char *smarttag_state_str(uint8_t state);

}

#endif
